package fleet

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/policy"
)

var b64 = base64.RawURLEncoding

// loadSigningKeys reads the stored policy signing keys.
func (f *Fleet) loadSigningKeys(ctx context.Context) (keys []SigningKey, revoked []string, err error) {
	rows, err := f.db.QueryContext(ctx, `SELECT kid, public_key, endorsed_by, endorsement, revoked FROM fleet_signing_keys ORDER BY added_at, kid`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k SigningKey
		var pub string
		var rev int
		if err := rows.Scan(&k.Kid, &pub, &k.EndorsedBy, &k.Endorsement, &rev); err != nil {
			return nil, nil, err
		}
		if rev == 1 {
			revoked = append(revoked, k.Kid)
			continue
		}
		raw, err := b64.DecodeString(pub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil, errors.New("fleet: stored signing key is malformed")
		}
		k.PublicKey = raw
		keys = append(keys, k)
	}
	return keys, revoked, rows.Err()
}

// refreshSigningKeys fetches the policy signing keys from keyguard and
// stores the new ones. A kid that was revoked is never re-added, and a kid
// is never re-bound to a different key.
func (f *Fleet) refreshSigningKeys(ctx context.Context) error {
	keys, err := f.signer.PolicySigningKeys(ctx)
	if err != nil {
		return err
	}
	now := f.now().Unix()
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, k := range keys {
			if !policy.ValidSigningKid(k.Kid) || len(k.PublicKey) != ed25519.PublicKeySize {
				return errors.New("fleet: keyguard returned a malformed signing key")
			}
			if (k.EndorsedBy == "") != (k.Endorsement == "") || k.EndorsedBy == k.Kid {
				return errors.New("fleet: keyguard returned a malformed endorsement")
			}
			var pub, endorsedBy string
			err := tx.QueryRowContext(ctx, `SELECT public_key, endorsed_by FROM fleet_signing_keys WHERE kid = ?`, k.Kid).Scan(&pub, &endorsedBy)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_signing_keys(kid, public_key, endorsed_by, endorsement, added_at) VALUES(?,?,?,?,?)`,
					k.Kid, b64.EncodeToString(k.PublicKey), k.EndorsedBy, k.Endorsement, now); err != nil {
					return err
				}
			case err != nil:
				return err
			case pub != b64.EncodeToString(k.PublicKey):
				return errors.New("fleet: keyguard changed the public key of an existing kid")
			case endorsedBy == "" && k.EndorsedBy != "":
				// A key learned before keyguard endorsed it (upgrade from a
				// keyguard without endorsements): store the endorsement now,
				// so enrolled sources can still learn the key.
				if _, err := tx.ExecContext(ctx, `UPDATE fleet_signing_keys SET endorsed_by = ?, endorsement = ? WHERE kid = ?`,
					k.EndorsedBy, k.Endorsement, k.Kid); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return f.reloadKeys(ctx)
}

func (f *Fleet) reloadKeys(ctx context.Context) error {
	keys, revoked, err := f.loadSigningKeys(ctx)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.keys, f.revoked = keys, revoked
	f.mu.Unlock()
	return nil
}

// RevokeSigningKey marks a policy signing kid as revoked: sources are told
// to stop trusting it at their next heartbeat (revoke_signing_keys) and it
// is no longer handed out at enrollment (admin API
// POST /api/v1/fleet/signing-keys/{kid}/revoke). It is refused for
// keyguard's active signing kid (RT3-KEY-2), for the last valid kid, and
// until enough recently seen sources confirmed another valid key
// (RT3-KEY-1, Options.KeyRevokeMinConfirmed).
func (f *Fleet) RevokeSigningKey(ctx context.Context, kid string, actor audit.Actor) error {
	if !policy.ValidSigningKid(kid) {
		return errNotFound
	}
	active, err := f.activeSigningKid(ctx)
	if err != nil {
		return err
	}
	var conf RotationConfirm
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		var rev int
		err := tx.QueryRowContext(ctx, `SELECT revoked FROM fleet_signing_keys WHERE kid = ?`, kid).Scan(&rev)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if rev == 1 {
			return conflict("already_revoked", "the signing key is already revoked")
		}
		var left int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_signing_keys WHERE revoked = 0 AND kid != ?`, kid).Scan(&left); err != nil {
			return err
		}
		if left == 0 {
			// Sources would trust no key at all: rotate in keyguard first.
			return conflict("last_signing_key", "cannot revoke the last valid signing key: add a new key in keyguard first")
		}
		if kid == active {
			return conflict("active_signing_key", "keyguard still signs with this key: rotate it in keyguard first (new key on the first line)")
		}
		conf, err = f.rotationConfirm(ctx, tx, kid, active)
		if err != nil {
			return err
		}
		if !conf.OK {
			return conflict("rotation_unconfirmed", fmt.Sprintf("only %d of %d sources seen in the last %s confirmed the new signing key (%.0f%% required; %d still run a policy signed by this key): wait for their heartbeats",
				conf.Confirmed, conf.Seen, f.opts.KeyConfirmWindow, conf.Required*100, conf.OnOldKey))
		}
		_, err = tx.ExecContext(ctx, `UPDATE fleet_signing_keys SET revoked = 1 WHERE kid = ?`, kid)
		return err
	})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			f.record(ctx, audit.Event{Actor: actor, Action: "fleet.signing_key_revoke", Target: audit.Target{Type: "signing_key", ID: kid},
				Outcome: audit.Denied, Details: map[string]string{"reason": ae.Code}})
		}
		return err
	}
	f.record(ctx, audit.Event{Actor: actor, Action: "fleet.signing_key_revoke", Target: audit.Target{Type: "signing_key", ID: kid}, Outcome: audit.Success,
		Details: map[string]string{"confirmed_sources": strconv.Itoa(conf.Confirmed), "seen_sources": strconv.Itoa(conf.Seen)}})
	return f.reloadKeys(ctx)
}

// activeSigningKid returns the kid keyguard signs policies with: read
// fresh from keyguard, else the last known value. Empty when keyguard does
// not report it. Fails closed when keyguard was never reached.
func (f *Fleet) activeSigningKid(ctx context.Context) (string, error) {
	if st, err := f.signer.Status(ctx); err == nil {
		if st.OpeningApprovals == 1 || st.OpeningApprovals == 2 {
			f.mu.Lock()
			f.kgStatus, f.kgKnown = st, true
			f.mu.Unlock()
		}
		return st.PolicyKid, nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.kgKnown {
		return "", apiErr(http.StatusServiceUnavailable, "keyguard_unavailable", "keyguard cannot be reached: its active signing key is unknown")
	}
	return f.kgStatus.PolicyKid, nil
}

// RotationConfirm tells how many recently seen sources already trust the
// key that signs after a revocation.
type RotationConfirm struct {
	Seen      int `json:"seen_sources"`
	Confirmed int `json:"confirmed_sources"`
	// OnOldKey counts the seen sources that still run a policy signed by
	// the key to revoke (they are not confirmed: tt-core re-signs active
	// policies with keyguard's active key at its next maintenance pass).
	OnOldKey int     `json:"sources_on_old_key"`
	Required float64 `json:"required_fraction"`
	OK       bool    `json:"ok"`
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// seenSource is what a recently seen source reported: the kids it trusts
// and the signer kid of the policy it runs ("" when none or unknown).
type seenSource struct {
	kids      []string
	signerKid string
}

// seenSources returns every non-revoked source seen (heartbeat or
// enrollment) within KeyConfirmWindow.
func (f *Fleet) seenSources(ctx context.Context, q querier) ([]seenSource, error) {
	since := f.now().Add(-f.opts.KeyConfirmWindow).Unix()
	rows, err := q.QueryContext(ctx, `SELECT s.signing_kids, COALESCE((SELECT v.signer_kid FROM fleet_policy_versions v
		WHERE s.policy_hash != '' AND v.hash = s.policy_hash LIMIT 1), '')
		FROM fleet_sources s WHERE s.revoked = 0 AND MAX(s.last_seen, s.enrolled_at) >= ?`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []seenSource
	for rows.Next() {
		var js string
		var ss seenSource
		if err := rows.Scan(&js, &ss.signerKid); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(js), &ss.kids)
		out = append(out, ss)
	}
	return out, rows.Err()
}

// rotationConfirm counts the recently seen sources and those that trust
// the key that will sign after the revocation of kid: keyguard's active
// kid when known, otherwise any other non-revoked kid.
func (f *Fleet) rotationConfirm(ctx context.Context, q querier, kid, active string) (RotationConfirm, error) {
	out := RotationConfirm{Required: *f.opts.KeyRevokeMinConfirmed}
	valid := map[string]bool{}
	if active != "" && active != kid {
		valid[active] = true
	} else {
		rows, err := q.QueryContext(ctx, `SELECT kid FROM fleet_signing_keys WHERE revoked = 0 AND kid != ?`, kid)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return out, err
			}
			valid[k] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	seen, err := f.seenSources(ctx, q)
	if err != nil {
		return out, err
	}
	out.Seen = len(seen)
	for _, ss := range seen {
		if ss.signerKid == kid {
			out.OnOldKey++
			continue
		}
		for _, k := range ss.kids {
			if valid[k] {
				out.Confirmed++
				break
			}
		}
	}
	out.OK = out.Seen == 0 || float64(out.Confirmed) >= out.Required*float64(out.Seen)-1e-9
	return out, nil
}

// signingKids returns the non-revoked signing kids, sorted (what a source
// pins at enrollment).
func (f *Fleet) signingKids() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.keys))
	for _, k := range f.keys {
		out = append(out, k.Kid)
	}
	slices.Sort(out)
	return out
}

// endorsedInOrder returns the endorsed keys so that an endorser always
// comes before the keys it endorses: a source pins them in order, so a
// chain k1 -> k2 -> k3 reaches a source that only has k1 in one heartbeat.
func endorsedInOrder(keys []SigningKey) []SigningKey {
	var pending, out []SigningKey
	for _, k := range keys {
		if k.EndorsedBy != "" && k.Endorsement != "" {
			pending = append(pending, k)
		}
	}
	placed := map[string]bool{}
	for len(pending) > 0 {
		var next []SigningKey
		for _, k := range pending {
			if placed[k.EndorsedBy] || !hasKid(pending, k.EndorsedBy) {
				out = append(out, k)
				placed[k.Kid] = true
			} else {
				next = append(next, k)
			}
		}
		if len(next) == len(pending) { // a cycle: keep the stored order
			return append(out, next...)
		}
		pending = next
	}
	return out
}

func hasKid(keys []SigningKey, kid string) bool {
	for _, k := range keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// SigningKeyInfo describes a policy signing key (public data only) and
// the state of its rotation.
type SigningKeyInfo struct {
	Kid        string `json:"kid"`
	Alg        string `json:"alg"`
	PublicKey  string `json:"public_key"`
	EndorsedBy string `json:"endorsed_by,omitempty"`
	Revoked    bool   `json:"revoked"`
	// Active is true for the kid keyguard currently signs with.
	Active bool `json:"active"`
	// TrustedBy counts the sources seen in the confirmation window whose
	// last heartbeat (or enrollment) lists this kid.
	TrustedBy int `json:"trusted_by"`
	// Revoke tells whether a revocation would be accepted now (absent for
	// revoked keys).
	Revoke *RevokeReadiness `json:"revoke,omitempty"`
}

// RevokeReadiness is the outcome a revocation of a key would have now.
type RevokeReadiness struct {
	RotationConfirm
	// Blocker is the refusal code (last_signing_key, active_signing_key,
	// rotation_unconfirmed), empty when the revocation would be accepted.
	Blocker string `json:"blocker,omitempty"`
}

// ListSigningKeys returns every known policy signing key with its
// rotation state.
func (f *Fleet) ListSigningKeys(ctx context.Context) ([]SigningKeyInfo, error) {
	active, _ := f.activeSigningKid(ctx) // "" when keyguard was never reached
	rows, err := f.db.QueryContext(ctx, `SELECT kid, public_key, endorsed_by, revoked FROM fleet_signing_keys ORDER BY added_at, kid`)
	if err != nil {
		return nil, err
	}
	out := []SigningKeyInfo{}
	for rows.Next() {
		k := SigningKeyInfo{Alg: "Ed25519"}
		var rev int
		if err := rows.Scan(&k.Kid, &k.PublicKey, &k.EndorsedBy, &rev); err != nil {
			rows.Close()
			return nil, err
		}
		k.Revoked = rev == 1
		k.Active = active != "" && k.Kid == active
		out = append(out, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	seen, err := f.seenSources(ctx, f.db)
	if err != nil {
		return nil, err
	}
	trusted := map[string]int{}
	for _, ss := range seen {
		for _, kid := range ss.kids {
			trusted[kid]++
		}
	}
	valid := 0
	for _, k := range out {
		if !k.Revoked {
			valid++
		}
	}
	for i := range out {
		k := &out[i]
		k.TrustedBy = trusted[k.Kid]
		if k.Revoked {
			continue
		}
		conf, err := f.rotationConfirm(ctx, f.db, k.Kid, active)
		if err != nil {
			return nil, err
		}
		r := &RevokeReadiness{RotationConfirm: conf}
		switch {
		case valid <= 1:
			r.Blocker, r.OK = "last_signing_key", false
		case k.Active:
			r.Blocker, r.OK = "active_signing_key", false
		case !conf.OK:
			r.Blocker = "rotation_unconfirmed"
		}
		k.Revoke = r
	}
	return out, nil
}

// keyRing returns a ring with the non-revoked signing keys.
func (f *Fleet) keyRing() *policy.KeyRing {
	r := policy.NewKeyRing()
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, k := range f.keys {
		_ = r.Pin(k.Kid, k.PublicKey)
	}
	return r
}

// refreshSignerStatus reads keyguard's approval settings. When keyguard
// cannot be reached the last known values are kept; before the first
// successful read Fleet assumes the strictest default (2 approvals).
func (f *Fleet) refreshSignerStatus(ctx context.Context) {
	st, err := f.signer.Status(ctx)
	if err != nil {
		f.log.Warn("fleet: cannot read keyguard status", "err", err)
		return
	}
	if st.OpeningApprovals != 1 && st.OpeningApprovals != 2 {
		f.log.Warn("fleet: keyguard reported an invalid opening_approvals; assuming 2")
		st.OpeningApprovals = 2
	}
	f.mu.Lock()
	f.kgStatus, f.kgKnown = st, true
	f.mu.Unlock()
}

// approvalSettings returns the effective approval settings.
func (f *Fleet) approvalSettings() (SignerStatus, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.kgKnown {
		return SignerStatus{OpeningApprovals: 2, AdminOverride: true, ApprovalsUnverified: true}, false
	}
	return f.kgStatus, true
}
