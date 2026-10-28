package fleet

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

var (
	reSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	reKid    = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
	reCode   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// SourceInfo is the source block of an enrollment request.
type SourceInfo struct {
	Kind        string       `json:"kind"`
	Version     string       `json:"version"`
	ServiceName string       `json:"service_name"`
	Instance    string       `json:"instance,omitempty"`
	Runtime     *RuntimeInfo `json:"runtime,omitempty"`
	HMACKids    []string     `json:"hmac_kids,omitempty"`
}

// RuntimeInfo describes the runtime of a source.
type RuntimeInfo struct {
	Lang        string `json:"lang,omitempty"`
	LangVersion string `json:"lang_version,omitempty"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
}

func (s *SourceInfo) validate() error {
	bad := func(msg string) error { return invalid("invalid_source", msg) }
	if !validKind(s.Kind) {
		return bad("unknown source kind")
	}
	if len(s.Version) > 64 || !reSemver.MatchString(s.Version) {
		return bad("version must be a semantic version")
	}
	if !reServiceName.MatchString(s.ServiceName) {
		return bad("service_name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}
	if len(s.Instance) > 128 {
		return bad("instance is longer than 128 characters")
	}
	if r := s.Runtime; r != nil && (len(r.Lang) > 32 || len(r.LangVersion) > 64 || len(r.OS) > 32 || len(r.Arch) > 32) {
		return bad("runtime field too long")
	}
	if len(s.HMACKids) > 8 {
		return bad("at most 8 hmac_kids")
	}
	for _, k := range s.HMACKids {
		if !reKid.MatchString(k) {
			return bad("hmac_kids must match ^[a-z0-9]{1,8}$")
		}
	}
	return nil
}

// enrollResult is what Enroll returns to the handler.
type enrollResult struct {
	SourceID, Group, Service string
	Cert                     issuedCert
}

// Enroll exchanges a token for a client certificate (fleet-api enroll).
// csrPEM may be empty: tt-core then generates the key, returns it once and
// never stores it.
func (f *Fleet) Enroll(ctx context.Context, token, csrPEM string, src SourceInfo) (*enrollResult, error) {
	m := reToken.FindStringSubmatch(token)
	if m == nil {
		return nil, invalid("invalid_token", "malformed enrollment token")
	}
	if m[2] != f.ca.pin {
		// A token minted by another tt-core (or for a rotated CA).
		return nil, tokenProblem("token_unknown")
	}
	if err := src.validate(); err != nil {
		return nil, err
	}
	var pub crypto.PublicKey
	if csrPEM != "" {
		k, err := clientPublicKey(csrPEM)
		if err != nil {
			return nil, invalid("invalid_csr", "the CSR is invalid or uses an unsupported key type")
		}
		pub = k
	}
	pinned := f.signingKids() // what the source pins (initial signing_kids)
	if len(pinned) == 0 {
		return nil, apiErr(503, "no_signing_keys", "policy signing keys are not available yet")
	}
	now := f.now()
	id := httpx.NewID("src-")
	var res *enrollResult
	var tok *TokenInfo
	adopted := false
	err := f.db.InTx(ctx, func(tx *sql.Tx) error {
		adopted = false
		var err error
		tok, err = f.consumeToken(ctx, tx, m[1], now)
		if err != nil {
			return err
		}
		if !tokenAdmits(tok.Kind, src.Kind) {
			return invalid("kind_mismatch", "the source kind differs from the kind of the enrollment token")
		}
		var allowedJSON string
		if err := tx.QueryRowContext(ctx, `SELECT allowed_service_names FROM fleet_groups WHERE name = ?`, tok.Group).Scan(&allowedJSON); err != nil {
			return err
		}
		var allowed []string
		if err := json.Unmarshal([]byte(allowedJSON), &allowed); err != nil {
			return err
		}
		switch {
		case len(allowed) == 0:
			// A group created without service names takes the name of its
			// first source (TT_SERVICE_NAME); from then on only that name
			// is allowed, like a name given at creation.
			allowed = []string{src.ServiceName}
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_groups SET allowed_service_names = ?, updated_at = ? WHERE name = ?`,
				mustJSON(allowed), now.Unix(), tok.Group); err != nil {
				return err
			}
			adopted = true
		case !slices.Contains(allowed, src.ServiceName):
			return apiErr(403, "service_not_allowed", "service_name is not allowed for the token's group")
		}
		cert, err := f.ca.issueClient(id, pub, f.opts.ClientCertTTL)
		if err != nil {
			return err
		}
		rt := "{}"
		if src.Runtime != nil {
			rt = mustJSON(src.Runtime)
		}
		kids := src.HMACKids
		if kids == nil {
			kids = []string{}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_sources(id, token_id, grp, kind, version, service_name, instance, runtime, hmac_kids, enrolled_at, cert_not_after, signing_kids)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, tok.TokenID, tok.Group, src.Kind, src.Version, src.ServiceName, src.Instance, rt, mustJSON(kids),
			now.Unix(), cert.NotAfter.Unix(), mustJSON(pinned)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_certs(serial, source_id, issued_at, not_after) VALUES(?,?,?,?)`,
			cert.Serial, id, now.Unix(), cert.NotAfter.Unix()); err != nil {
			return err
		}
		res = &enrollResult{SourceID: id, Group: tok.Group, Service: src.ServiceName, Cert: cert}
		return nil
	})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			tid := ""
			if tok != nil {
				tid = tok.TokenID
				f.mu.Lock()
				f.enrollFail[tid] = ae.Code
				f.mu.Unlock()
			}
			f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorAnonymous}, Action: "fleet.enroll",
				Target: audit.Target{Type: "enrollment_token", ID: tid}, Outcome: audit.Denied, Reason: ae.Code})
		}
		return nil, err
	}
	f.mu.Lock()
	if g := f.groups[res.Group]; adopted && g != nil {
		g.allowed = []string{res.Service}
	}
	f.sources[id] = &memSource{id: id, group: res.Group, service: res.Service, tokenID: tok.TokenID, certNotAfter: res.Cert.NotAfter}
	f.certs[res.Cert.Serial] = memCert{source: id, notAfter: res.Cert.NotAfter}
	delete(f.enrollFail, tok.TokenID)
	f.mu.Unlock()
	f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSource, ID: id}, Action: "fleet.enroll",
		Target: audit.Target{Type: "source", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"token_id": tok.TokenID, "group": res.Group, "service": res.Service, "kind": src.Kind,
			"csr": strconv.FormatBool(csrPEM != ""), "cert_serial": res.Cert.Serial}})
	if adopted {
		f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSource, ID: id}, Action: "fleet.group_update",
			Target: audit.Target{Type: "group", ID: res.Group}, Outcome: audit.Success,
			Details: map[string]string{"allowed_service_names": res.Service, "reason": "first_enrollment"}})
	}
	return res, nil
}

// RenewCert issues a new certificate for an enrolled, non-revoked source.
func (f *Fleet) RenewCert(ctx context.Context, sourceID, csrPEM string) (issuedCert, error) {
	var pub crypto.PublicKey
	if csrPEM != "" {
		k, err := clientPublicKey(csrPEM)
		if err != nil {
			return issuedCert{}, invalid("invalid_csr", "the CSR is invalid or uses an unsupported key type")
		}
		pub = k
	}
	f.mu.RLock()
	s := f.sources[sourceID]
	revoked := s == nil || s.revoked
	f.mu.RUnlock()
	if revoked {
		return issuedCert{}, apiErr(403, "source_revoked", "source revoked")
	}
	cert, err := f.ca.issueClient(sourceID, pub, f.opts.ClientCertTTL)
	if err != nil {
		return issuedCert{}, err
	}
	now := f.now()
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_certs(serial, source_id, issued_at, not_after) VALUES(?,?,?,?)`, cert.Serial, sourceID, now.Unix(), cert.NotAfter.Unix()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE fleet_sources SET cert_not_after = ? WHERE id = ?`, cert.NotAfter.Unix(), sourceID)
		return err
	})
	if err != nil {
		return issuedCert{}, err
	}
	f.mu.Lock()
	f.certs[cert.Serial] = memCert{source: sourceID, notAfter: cert.NotAfter}
	if s := f.sources[sourceID]; s != nil {
		s.certNotAfter = cert.NotAfter
	}
	f.mu.Unlock()
	f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSource, ID: sourceID}, Action: "fleet.cert_renew",
		Target: audit.Target{Type: "source", ID: sourceID}, Outcome: audit.Success,
		Details: map[string]string{"cert_serial": cert.Serial, "csr": strconv.FormatBool(csrPEM != "")}})
	return cert, nil
}

// RevokeSource revokes a source and all its certificates: the intake TLS
// hook refuses it from the next handshake, Fleet endpoints answer 403.
func (f *Fleet) RevokeSource(ctx context.Context, p *auth.Principal, id string) error {
	if !ValidSourceID(id) {
		return errNotFound
	}
	err := f.db.InTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE fleet_sources SET revoked = 1 WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
		_, err = tx.ExecContext(ctx, `UPDATE fleet_certs SET revoked = 1 WHERE source_id = ?`, id)
		return err
	})
	if err != nil {
		return err
	}
	f.mu.Lock()
	if s := f.sources[id]; s != nil {
		s.revoked = true
	}
	for serial, c := range f.certs {
		if c.source == id {
			c.revoked = true
			f.certs[serial] = c
		}
	}
	f.mu.Unlock()
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.source_revoke", Target: audit.Target{Type: "source", ID: id}, Outcome: audit.Success})
	return nil
}

// SetSourceSampling sets (or with nil removes) the sampling override of a
// source. Values at or above the policy rate are kept but never sent: an
// override can only lower the rate.
func (f *Fleet) SetSourceSampling(ctx context.Context, p *auth.Principal, id string, bp *int) error {
	if bp != nil && (*bp < 0 || *bp > 10000) {
		return invalid("invalid_sampling", "sampling_override_bp must be between 0 and 10000")
	}
	if !ValidSourceID(id) {
		return errNotFound
	}
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_sources SET sampling_override_bp = ? WHERE id = ?`, nullInt(bp), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	f.mu.Lock()
	if s := f.sources[id]; s != nil {
		s.overrideBP = bp
	}
	f.mu.Unlock()
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.sampling_override", Target: audit.Target{Type: "source", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"sampling_override_bp": optInt(bp)}})
	return nil
}

// KillScope selects what the kill switch applies to: exactly one field.
type KillScope struct {
	All      *bool   `json:"all,omitempty"`
	Group    *string `json:"group,omitempty"`
	SourceID *string `json:"source_id,omitempty"`
}

// SetKill turns the kill switch on or off for all sources, a group or one
// source. The state is persisted and delivered at the next heartbeat;
// turning it off is audited like turning it on (and alerted).
func (f *Fleet) SetKill(ctx context.Context, p *auth.Principal, active bool, sc KillScope) error {
	n := 0
	for _, set := range []bool{sc.All != nil, sc.Group != nil, sc.SourceID != nil} {
		if set {
			n++
		}
	}
	if n != 1 || (sc.All != nil && !*sc.All) {
		return invalid("invalid_scope", "scope must be exactly one of {all: true}, {group}, {source_id}")
	}
	var target audit.Target
	switch {
	case sc.All != nil:
		target = audit.Target{Type: "fleet", ID: "all"}
		err := f.db.InTx(ctx, func(tx *sql.Tx) error {
			return setMeta(ctx, tx, metaGlobalKill, map[bool]string{true: "1", false: "0"}[active])
		})
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.killAll = active
		f.mu.Unlock()
	case sc.Group != nil:
		target = audit.Target{Type: "group", ID: audit.SafeValue(*sc.Group)}
		res, err := f.db.ExecContext(ctx, `UPDATE fleet_groups SET killed = ?, updated_at = ? WHERE name = ?`, boolInt(active), f.now().Unix(), *sc.Group)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return errNotFound
		}
		f.mu.Lock()
		if g := f.groups[*sc.Group]; g != nil {
			g.killed = active
		}
		f.mu.Unlock()
	default:
		target = audit.Target{Type: "source", ID: audit.SafeValue(*sc.SourceID)}
		res, err := f.db.ExecContext(ctx, `UPDATE fleet_sources SET killed = ? WHERE id = ?`, boolInt(active), *sc.SourceID)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return errNotFound
		}
		f.mu.Lock()
		if s := f.sources[*sc.SourceID]; s != nil {
			s.killed = active
		}
		f.mu.Unlock()
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.kill", Target: target, Outcome: audit.Success,
		Details: map[string]string{"active": strconv.FormatBool(active)}})
	if f.alerts != nil {
		f.alerts.Alert(ctx, "fleet.kill", map[string]string{"active": strconv.FormatBool(active), "scope": target.Type, "id": target.ID})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Heartbeat

// Heartbeat is the body of POST /fleet/v1/heartbeat.
type Heartbeat struct {
	SourceID   string           `json:"source_id"`
	State      string           `json:"state"`
	Policy     *HeartbeatPolicy `json:"policy,omitempty"`
	Counters   *Counters        `json:"counters"`
	OverheadUS *Overhead        `json:"overhead_us,omitempty"`
	Queue      *struct {
		Events int64 `json:"events"`
		Bytes  int64 `json:"bytes"`
	} `json:"queue,omitempty"`
	LastErrors []LastError  `json:"last_errors,omitempty"`
	Runtime    *RuntimeInfo `json:"runtime,omitempty"`
	// SigningKids are the policy signing kids the source trusts (pinned,
	// not revoked). Absent in older sources: the stored value is kept.
	SigningKids []string `json:"signing_kids,omitempty"`
}

// maxSigningKids bounds Heartbeat.SigningKids.
const maxSigningKids = 32

// HeartbeatPolicy is the policy a source reports running.
type HeartbeatPolicy struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	IssuedSeq int64  `json:"issued_seq"`
	Hash      string `json:"hash"`
}

// Counters are the monotonic counters of a source since process start.
type Counters struct {
	ExchangesSeen      *int64 `json:"exchanges_seen"`
	ExchangesSampled   *int64 `json:"exchanges_sampled"`
	EventsSent         *int64 `json:"events_sent"`
	EventsDroppedQueue *int64 `json:"events_dropped_queue"`
	EventsRejected     *int64 `json:"events_rejected"`
	SendErrors         *int64 `json:"send_errors"`
	SanitizerErrors    *int64 `json:"sanitizer_errors"`
}

// Overhead is the time spent in tt per exchange (microseconds).
type Overhead struct {
	P50 *int64 `json:"p50,omitempty"`
	P99 *int64 `json:"p99,omitempty"`
}

// LastError is an error code reported by a source (never a value).
type LastError struct {
	Code string `json:"code"`
	// At is the time of the last occurrence (as reported by the source;
	// in a SourceStatus, equal to LastSeen).
	At time.Time `json:"at"`
	// FirstSeen, LastSeen and Count are filled in the SourceStatus view: the
	// occurrences of the code within the last-errors window.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Count     int        `json:"count,omitempty"`
}

// PolicyRef identifies a policy version.
type PolicyRef struct {
	PolicyID  string `json:"policy_id"`
	Version   int64  `json:"version"`
	IssuedSeq int64  `json:"issued_seq"`
	Hash      string `json:"hash"`
}

// HeartbeatResponse carries the commands for a source.
type HeartbeatResponse struct {
	NextHeartbeatS     int64         `json:"next_heartbeat_s"`
	Kill               bool          `json:"kill"`
	MinIssuedSeq       int64         `json:"min_issued_seq"`
	PolicyCurrent      *PolicyRef    `json:"policy_current"`
	SamplingOverrideBP *int          `json:"sampling_override_bp"`
	RenewBefore        *time.Time    `json:"renew_before"`
	AddSigningKeys     []EndorsedKey `json:"add_signing_keys"`
	RevokeSigningKeys  []string      `json:"revoke_signing_keys"`
}

// EndorsedKey is a new signing key endorsed by an already pinned one.
type EndorsedKey struct {
	Kid         string `json:"kid"`
	Alg         string `json:"alg"`
	PublicKey   string `json:"public_key"`
	EndorsedBy  string `json:"endorsed_by"`
	Endorsement string `json:"endorsement"`
}

var heartbeatStates = []string{"starting", "capturing", "no_policy", "policy_rejected", "expired_policy", "key_missing", "key_mismatch", "killed"}

func (h *Heartbeat) validate() error {
	bad := func(msg string) error { return invalid("invalid_heartbeat", msg) }
	if !slices.Contains(heartbeatStates, h.State) {
		return bad("unknown state")
	}
	c := h.Counters
	if c == nil || c.ExchangesSeen == nil || c.ExchangesSampled == nil || c.EventsSent == nil || c.EventsDroppedQueue == nil ||
		c.EventsRejected == nil || c.SendErrors == nil || c.SanitizerErrors == nil {
		return bad("counters are incomplete")
	}
	for _, v := range []*int64{c.ExchangesSeen, c.ExchangesSampled, c.EventsSent, c.EventsDroppedQueue, c.EventsRejected, c.SendErrors, c.SanitizerErrors} {
		if *v < 0 {
			return bad("counters must not be negative")
		}
	}
	if len(h.LastErrors) > 20 {
		return bad("at most 20 last_errors")
	}
	for _, e := range h.LastErrors {
		if !reCode.MatchString(e.Code) {
			return bad("last_errors codes must be short identifiers")
		}
	}
	if len(h.SigningKids) > maxSigningKids {
		return bad("too many signing_kids")
	}
	for _, k := range h.SigningKids {
		if !policy.ValidSigningKid(k) {
			return bad("signing_kids must be valid kids")
		}
	}
	if p := h.Policy; p != nil && (len(p.ID) > 63 || len(p.Hash) > 71) {
		return bad("policy reference too long")
	}
	return nil
}

type storedCounters struct {
	Counters
	At int64 `json:"at"`
}

// HandleHeartbeat records a heartbeat of an authenticated source and
// returns its commands. sourceID is the identity of the client
// certificate; the body must name the same source.
func (f *Fleet) HandleHeartbeat(ctx context.Context, sourceID string, h *Heartbeat) (*HeartbeatResponse, error) {
	if h.SourceID != sourceID {
		return nil, apiErr(403, "source_mismatch", "source_id differs from the client certificate")
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	f.mu.RLock()
	s := f.sources[sourceID]
	if s == nil || s.revoked {
		f.mu.RUnlock()
		return nil, apiErr(403, "source_revoked", "source revoked")
	}
	resp := &HeartbeatResponse{
		NextHeartbeatS:    int64(f.opts.HeartbeatInterval / time.Second),
		Kill:              f.killedLocked(s),
		AddSigningKeys:    []EndorsedKey{},
		RevokeSigningKeys: slices.Clone(f.revoked),
	}
	if resp.RevokeSigningKeys == nil {
		resp.RevokeSigningKeys = []string{}
	}
	if cur := f.currentFor(s.group); cur != nil {
		resp.MinIssuedSeq = cur.seq
		resp.PolicyCurrent = &PolicyRef{PolicyID: cur.policyID, Version: cur.version, IssuedSeq: cur.seq, Hash: cur.hash}
		eff := s.overrideBP
		if g := f.groups[s.group]; g != nil && g.overrideBP != nil && (eff == nil || *g.overrideBP < *eff) {
			eff = g.overrideBP
		}
		if eff != nil && *eff < cur.rateBP {
			v := *eff
			resp.SamplingOverrideBP = &v
		}
	} else if m := f.maxActiveSeqLocked(); m > 0 {
		// No policy is assigned to the group (never bound, or unbound): tell
		// the source that every policy signed so far is superseded for good,
		// so it stops using the one it has cached. Any policy issued later
		// has a higher issued_seq and is still accepted.
		resp.MinIssuedSeq = m + 1
	}
	rb := s.certNotAfter.Add(-f.opts.ClientCertTTL / 3).UTC()
	resp.RenewBefore = &rb
	for _, k := range endorsedInOrder(f.keys) {
		resp.AddSigningKeys = append(resp.AddSigningKeys, EndorsedKey{
			Kid: k.Kid, Alg: "Ed25519", PublicKey: b64.EncodeToString(k.PublicKey), EndorsedBy: k.EndorsedBy, Endorsement: k.Endorsement,
		})
	}
	f.mu.RUnlock()

	if err := f.storeHealth(ctx, sourceID, h); err != nil {
		return nil, err
	}
	return resp, nil
}

func (f *Fleet) storeHealth(ctx context.Context, id string, h *Heartbeat) error {
	now := f.now()
	return f.db.InTx(ctx, func(tx *sql.Tx) error {
		var prevJSON string
		var prevEPM float64
		if err := tx.QueryRowContext(ctx, `SELECT counters, events_per_min FROM fleet_sources WHERE id = ?`, id).Scan(&prevJSON, &prevEPM); err != nil {
			return err
		}
		var prev storedCounters
		_ = json.Unmarshal([]byte(prevJSON), &prev)
		c := h.Counters
		epm := prevEPM
		if prev.EventsSent != nil && prev.At > 0 {
			if dt := now.Sub(time.Unix(prev.At, 0)).Minutes(); dt > 0 {
				delta := *c.EventsSent - *prev.EventsSent
				if delta < 0 { // process restarted: counters reset
					delta = *c.EventsSent
				}
				epm = float64(delta) / dt
			}
		}
		drop := 0.0
		if tot := *c.EventsSent + *c.EventsDroppedQueue; tot > 0 {
			drop = float64(*c.EventsDroppedQueue) / float64(tot)
		}
		var p50, p99 any
		if o := h.OverheadUS; o != nil {
			if o.P50 != nil {
				p50 = *o.P50
			}
			if o.P99 != nil {
				p99 = *o.P99
			}
		}
		pid, pver, pseq, phash := "", int64(0), int64(0), ""
		if p := h.Policy; p != nil {
			pid, pver, pseq, phash = p.ID, p.Version, p.IssuedSeq, p.Hash
		}
		errs := h.LastErrors
		if errs == nil {
			errs = []LastError{}
		}
		q := `UPDATE fleet_sources SET last_seen = ?, state = ?, policy_id = ?, policy_version = ?, policy_seq = ?, policy_hash = ?,
			counters = ?, events_per_min = ?, drop_ratio = ?, overhead_p50 = ?, overhead_p99 = ?, last_errors = ?`
		args := []any{now.Unix(), h.State, pid, pver, pseq, phash, mustJSON(storedCounters{Counters: *c, At: now.Unix()}), epm, drop, p50, p99, mustJSON(errs)}
		if h.SigningKids != nil {
			kids := slices.Clone(h.SigningKids)
			slices.Sort(kids)
			q += `, signing_kids = ?`
			args = append(args, mustJSON(slices.Compact(kids)))
		}
		if r := h.Runtime; r != nil && len(r.Lang) <= 32 && len(r.LangVersion) <= 64 {
			q += `, runtime = ?`
			args = append(args, mustJSON(r))
		}
		q += ` WHERE id = ?`
		_, err := tx.ExecContext(ctx, q, append(args, id)...)
		return err
	})
}

// ---------------------------------------------------------------------------
// Status views

// CodeInboundNotCaptured is the last_errors code (and problem code) of a source that
// reported seeing no inbound traffic of its process: the zero-code start found no web app
// to wrap (sdk/python autocapture).
const CodeInboundNotCaptured = "inbound_not_captured"

// Problem is an onboarding or source problem (admin-api Problem).
type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

var problemText = map[string][2]string{
	"token_expired":       {"the enrollment token expired", "create a new token"},
	"token_revoked":       {"the enrollment token was revoked", "create a new token"},
	"token_exhausted":     {"the one-time token was already used", "create a new token, or a group token for replicated deployments"},
	"service_not_allowed": {"the source declared a service name not allowed for the group", "add the name to the group's allowed_service_names or fix TT_SERVICE_NAME"},
	"kind_mismatch":       {"the source kind differs from the token kind", "create a token for this kind of source"},
	"invalid_csr":         {"the source sent an invalid CSR", "use an Ed25519 or ECDSA P-256 key"},
	"no_policy":           {"the source has no policy and does not capture", "assign a policy to the group and approve it"},
	"policy_rejected":     {"the source rejected the policy", "check the source logs and the policy signing keys"},
	"expired_policy":      {"the source's policy expired", "check that tt-core renews policies through keyguard"},
	"key_missing": {"the source has no HMAC key and does not capture",
		"set TT_HMAC_KEY_FILE to the installation-wide HMAC key file from your platform team (same kid as the policy hmac.kid)"},
	"key_mismatch": {"the source's HMAC key id is not accepted by the policy", "align hmac.kid / accept_kids with the source key"},
	"inbound_not_captured": {"the source sees only outgoing calls: no web application of the process was wrapped, so the service itself does not appear",
		"start the service with `python -m traffic_twin run -- <server>` (Flask, FastAPI, Django, uvicorn and gunicorn are wrapped by themselves) or add `app = traffic_twin.install(app)` where the app is created"},
	"double_capture": {"an outbound call was captured both by an SDK and by tt-egress (the SDK also records the hop to the proxy)",
		"use either the SDK or tt-egress for a given outbound call: do not list the tt-egress address in the SDK policy's hosts_allow, or send the call directly"},
}

func problem(code string) Problem {
	t := problemText[code]
	return Problem{Code: code, Message: t[0], Hint: t[1]}
}

// SourceStatus is the admin view of a source (admin-api SourceStatus).
type SourceStatus struct {
	SourceID    string `json:"source_id"`
	Kind        string `json:"kind"`
	Version     string `json:"version"`
	ServiceName string `json:"service_name"`
	Group       string `json:"group"`
	Instance    string `json:"instance,omitempty"`
	State       string `json:"state"`
	Killed      bool   `json:"killed"`
	Revoked     bool   `json:"revoked"`
	Policy      *struct {
		ID        string `json:"id"`
		Version   int64  `json:"version"`
		IssuedSeq int64  `json:"issued_seq"`
	} `json:"policy,omitempty"`
	LastSeen           *time.Time  `json:"last_seen"`
	EventsPerMin       float64     `json:"events_per_min"`
	DropRatio          float64     `json:"drop_ratio"`
	SanitizerErrors    int64       `json:"sanitizer_errors"`
	SamplingOverrideBP *int        `json:"sampling_override_bp"`
	OverheadUS         *Overhead   `json:"overhead_us,omitempty"`
	LastErrors         []LastError `json:"last_errors"`
	Problems           []Problem   `json:"problems"`
	tokenID            string
	eventsSent         int64
	policyHash         string
}

const sourceCols = `id, kind, version, service_name, grp, instance, state, killed, revoked, policy_id, policy_version, policy_seq, policy_hash,
	last_seen, events_per_min, drop_ratio, sampling_override_bp, overhead_p50, overhead_p99, last_errors, counters, token_id`

func (f *Fleet) scanSource(sc interface{ Scan(...any) error }) (*SourceStatus, error) {
	s := &SourceStatus{}
	var killed, revoked int
	var pid, phash, lastErrs, counters string
	var pver, pseq, lastSeen int64
	var ov, p50, p99 sql.NullInt64
	if err := sc.Scan(&s.SourceID, &s.Kind, &s.Version, &s.ServiceName, &s.Group, &s.Instance, &s.State, &killed, &revoked,
		&pid, &pver, &pseq, &phash, &lastSeen, &s.EventsPerMin, &s.DropRatio, &ov, &p50, &p99, &lastErrs, &counters, &s.tokenID); err != nil {
		return nil, err
	}
	s.Revoked, s.SamplingOverrideBP, s.policyHash = revoked == 1, intPtr(ov), phash
	f.mu.RLock()
	if m := f.sources[s.SourceID]; m != nil {
		s.Killed = f.killedLocked(m)
	}
	rc, _ := f.events.(RejectCounter)
	dc, _ := f.events.(DoubleCaptureReporter)
	f.mu.RUnlock()
	if pid != "" {
		s.Policy = &struct {
			ID        string `json:"id"`
			Version   int64  `json:"version"`
			IssuedSeq int64  `json:"issued_seq"`
		}{pid, pver, pseq}
	}
	if lastSeen > 0 {
		t := time.Unix(lastSeen, 0).UTC()
		s.LastSeen = &t
	}
	if p50.Valid || p99.Valid {
		s.OverheadUS = &Overhead{}
		if p50.Valid {
			s.OverheadUS.P50 = &p50.Int64
		}
		if p99.Valid {
			s.OverheadUS.P99 = &p99.Int64
		}
	}
	_ = json.Unmarshal([]byte(lastErrs), &s.LastErrors)
	now := f.now()
	s.LastErrors = windowedErrors(s.LastErrors, now, f.opts.LastErrorsWindow)
	if rc != nil {
		s.LastErrors = appendIntakeRejections(s.LastErrors, rc.RecentRejections(s.SourceID, f.opts.LastErrorsWindow))
	}
	var c storedCounters
	if json.Unmarshal([]byte(counters), &c) == nil {
		if c.SanitizerErrors != nil {
			s.SanitizerErrors = *c.SanitizerErrors
		}
		if c.EventsSent != nil {
			s.eventsSent = *c.EventsSent
		}
	}
	s.Problems = []Problem{}
	if _, ok := problemText[s.State]; ok {
		s.Problems = append(s.Problems, problem(s.State))
	}
	for _, le := range s.LastErrors {
		if le.Code == CodeInboundNotCaptured {
			s.Problems = append(s.Problems, problem(CodeInboundNotCaptured))
			break
		}
	}
	if dc != nil && dc.DoubleCaptured(s.SourceID) {
		s.Problems = append(s.Problems, problem("double_capture"))
	}
	return s, nil
}

// ListSources returns the enrolled sources, optionally of one group.
func (f *Fleet) ListSources(ctx context.Context, group string) ([]*SourceStatus, error) {
	q, args := `SELECT `+sourceCols+` FROM fleet_sources`, []any{}
	if group != "" {
		q += ` WHERE grp = ?`
		args = append(args, group)
	}
	rows, err := f.db.QueryContext(ctx, q+` ORDER BY enrolled_at, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SourceStatus{}
	for rows.Next() {
		s, err := f.scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetSource returns one source.
func (f *Fleet) GetSource(ctx context.Context, id string) (*SourceStatus, error) {
	s, err := f.scanSource(f.db.QueryRowContext(ctx, `SELECT `+sourceCols+` FROM fleet_sources WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return s, err
}

// OnboardingStatus is the live status of the sources enrolled with a token.
type OnboardingStatus struct {
	Steps struct {
		Enrolled       bool  `json:"enrolled"`
		PolicyReceived bool  `json:"policy_received"`
		FirstEvents    int64 `json:"first_events"`
	} `json:"steps"`
	Sources  []string  `json:"sources"`
	Problems []Problem `json:"problems"`
}

// Onboarding returns the onboarding status of a token.
func (f *Fleet) Onboarding(ctx context.Context, tokenID string) (*OnboardingStatus, error) {
	if !reTokenID.MatchString(tokenID) {
		return nil, errNotFound
	}
	tok, err := f.getToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	rows, err := f.db.QueryContext(ctx, `SELECT `+sourceCols+` FROM fleet_sources WHERE token_id = ? ORDER BY enrolled_at, id`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	st := &OnboardingStatus{Sources: []string{}, Problems: []Problem{}}
	seen := map[string]bool{}
	addProblem := func(code string) {
		if !seen[code] {
			seen[code] = true
			st.Problems = append(st.Problems, problem(code))
		}
	}
	f.mu.RLock()
	ec := f.events
	failCode := f.enrollFail[tokenID]
	f.mu.RUnlock()
	for rows.Next() {
		s, err := f.scanSource(rows)
		if err != nil {
			return nil, err
		}
		st.Steps.Enrolled = true
		st.Sources = append(st.Sources, s.SourceID)
		if _, ok := f.SignedPolicyBody(s.policyHash); ok {
			st.Steps.PolicyReceived = true
		}
		if ec != nil {
			st.Steps.FirstEvents += int64(ec.AcceptedEvents(s.SourceID))
		} else {
			st.Steps.FirstEvents += s.eventsSent
		}
		for _, p := range s.Problems {
			addProblem(p.Code)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := f.now()
	if tok.Revoked {
		addProblem("token_revoked")
	} else if !now.Before(tok.ExpiresAt) && !st.Steps.Enrolled {
		addProblem("token_expired")
	}
	if failCode != "" {
		if _, ok := problemText[failCode]; ok {
			addProblem(failCode)
		}
	}
	return st, nil
}
