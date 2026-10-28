package drift

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Event types a webhook can subscribe to (admin API Webhook.events).
const (
	EventContractDrift = "contract.drift"
	EventRuleStale     = "rule.stale"
)

// Config tunes alerting and delivery.
type Config struct {
	// Allow lists the destinations webhooks may point to (TT_WEBHOOK_ALLOW):
	// "host", "host:port" or "*.suffix". Empty: no destination is accepted.
	// Names are checked again at delivery time on the address they resolve
	// to: an internal address is reached only when that exact IP literal is
	// an entry ("10.0.0.5" or "10.0.0.5:8443").
	Allow []string
	// AllowHTTP accepts plain http:// URLs (default: https only).
	AllowHTTP bool
	// MaxAlertsPerSnapshot bounds the alerts raised by one snapshot pair
	// (breaking changes first). Default 200.
	MaxAlertsPerSnapshot int
	// MaxAttempts is the number of delivery attempts per webhook and event.
	// Default 6.
	MaxAttempts int
	// Backoff is the wait before attempt n+1 (index n-1; the last value
	// repeats). Default 1s, 5s, 30s, 2m, 10m.
	Backoff []time.Duration
	// Timeout of one delivery request. Default 10 s.
	Timeout time.Duration
	// Poll is how often Run looks for due deliveries. Default 2 s.
	Poll time.Duration
	// NotifyNonBreaking sends non-breaking alerts to webhooks too. Default
	// true; set DisableNonBreaking to stop them.
	DisableNonBreaking bool
}

func (c *Config) setDefaults() {
	if c.MaxAlertsPerSnapshot <= 0 {
		c.MaxAlertsPerSnapshot = 200
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 6
	}
	if len(c.Backoff) == 0 {
		c.Backoff = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Poll <= 0 {
		c.Poll = 2 * time.Second
	}
}

// RuleLookup is implemented by the miner: the approved rules fed by an
// operation, so that alerts can list affected_rules.
type RuleLookup interface {
	RulesTouching(service, op string) []string
}

// RuleMarker may also be implemented by the RuleLookup: it is called for the
// rules affected by a breaking contract change, to mark them stale.
type RuleMarker interface {
	MarkStale(ctx context.Context, ruleID, reason string) error
}

// RuleStaleReport is what the miner reports when the confidence of an
// approved rule falls.
type RuleStaleReport struct {
	RuleID  string
	Service string
	Op      string
	// Confidence is the current confidence and Previous the one at approval.
	Confidence float64
	Previous   float64
	// Reason is a short machine code ("confidence-drop", "outcome-shift").
	Reason string
}

// RuleStaleness is the hook the rule miner calls. The Manager implements it.
type RuleStaleness interface {
	RuleStale(ctx context.Context, r RuleStaleReport) error
}

// Deps are the collaborators of a Manager.
type Deps struct {
	DB     *store.DB
	Audit  *audit.Log
	Logger *slog.Logger
	Now    func() time.Time
	// Client delivers webhooks; default is a client without redirects and
	// proxy whose dialer refuses internal addresses (loopback, link-local,
	// RFC 1918, CGNAT, ULA, multicast) unless that exact IP is in Allow.
	Client *http.Client
	Rules  RuleLookup
	// ServiceGroups, optional, maps each service to the groups that produced
	// it: alerts without a group are listed for the groups of their service.
	ServiceGroups func(ctx context.Context) (map[string][]string, error)
}

// Manager raises alerts and delivers webhooks.
type Manager struct {
	cfg   Config
	db    *store.DB
	audit *audit.Log
	log   *slog.Logger
	now   func() time.Time
	cli   *http.Client
	rules RuleLookup
	sg    func(ctx context.Context) (map[string][]string, error)
	wake  chan struct{}

	// busy holds the webhooks whose worker is still sending (a slow or
	// unreachable endpoint): the next passes skip them instead of waiting.
	busyMu sync.Mutex
	busy   map[int64]bool
}

var _ RuleStaleness = (*Manager)(nil)

// New creates a Manager.
func New(cfg Config, d Deps) (*Manager, error) {
	cfg.setDefaults()
	if d.DB == nil {
		return nil, errors.New("drift: DB is required")
	}
	m := &Manager{cfg: cfg, db: d.DB, audit: d.Audit, log: d.Logger, now: d.Now, cli: d.Client, rules: d.Rules, sg: d.ServiceGroups, wake: make(chan struct{}, 1), busy: map[int64]bool{}}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.cli == nil {
		m.cli = newDeliveryClient(cfg.Allow)
	}
	return m, nil
}

// Attach registers the manager as a snapshot hook of the contract engine.
func (m *Manager) Attach(e *contract.Engine) {
	e.OnSnapshot(m.HandleSnapshot)
}

// Alert is a stored alert.
type Alert struct {
	DriftID string `json:"drift_id"`
	// Kind is the event type of the alert ("contract.drift", "rule.stale").
	Kind    string `json:"kind"`
	Service string `json:"service"`
	// Group is the group of the contract that drifted ("" for rule alerts
	// and alerts raised before groups were tracked).
	Group         string    `json:"group"`
	Op            string    `json:"op"`
	Severity      string    `json:"severity"`
	Change        string    `json:"change"`
	FirstSeen     time.Time `json:"first_seen"`
	Evidence      Evidence  `json:"evidence"`
	State         string    `json:"state"`
	AffectedRules []string  `json:"affected_rules,omitempty"`
	// Where and ChangeKind locate the change (admin only).
	Where      string `json:"where,omitempty"`
	ChangeKind string `json:"change_kind,omitempty"`
	AckBy      string `json:"ack_by,omitempty"`
	// ResolvedBy is the user who marked the alert resolved.
	ResolvedBy string `json:"resolved_by,omitempty"`
	// Params are the names and figures behind Change (English), keyed by
	// ChangeKind: the console writes the sentence in its own language from
	// them (scope, status, name, part, from, to, count, pct...). Never data
	// values.
	Params map[string]string `json:"params,omitempty"`

	id int64
}

// Evidence is the quantitative evidence of an alert.
type Evidence struct {
	CallsAfterChange int64 `json:"calls_after_change"`
}

func alertID(id int64) string { return fmt.Sprintf("dr-%08d", id) }

func dedupeKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

// HandleSnapshot compares cur with prev and stores an alert per change. It
// is a [contract.SnapshotHook].
func (m *Manager) HandleSnapshot(ctx context.Context, prev, cur *contract.Snapshot) error {
	if prev == nil || cur == nil {
		return nil
	}
	changes := Quiet(prev.Window, cur.Window, contract.Diff(prev.Contract, cur.Contract, contract.DefaultConfig().Diff))
	// Breaking first, then by deterministic order.
	ordered := make([]contract.Change, 0, len(changes))
	for _, c := range changes {
		if c.Severity == contract.Breaking {
			ordered = append(ordered, c)
		}
	}
	for _, c := range changes {
		if c.Severity != contract.Breaking {
			ordered = append(ordered, c)
		}
	}
	if len(ordered) > m.cfg.MaxAlertsPerSnapshot {
		ordered = ordered[:m.cfg.MaxAlertsPerSnapshot]
	}
	now := m.now().UTC()
	var firstErr error
	for _, c := range ordered {
		var rules []string
		if m.rules != nil {
			rules = m.rules.RulesTouching(cur.Service, c.Op)
		}
		a, created, err := m.raise(ctx, Alert{
			Kind: EventContractDrift, Service: cur.Service, Group: cur.Group, Op: c.Op, Severity: c.Severity, Change: c.Text,
			Where: c.Where, ChangeKind: c.Kind, FirstSeen: now, Evidence: Evidence{CallsAfterChange: c.CallsAfter}, AffectedRules: rules,
			Params: c.Params,
		}, prev.SnapshotID, cur.SnapshotID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !created {
			continue
		}
		if mk, ok := m.rules.(RuleMarker); ok && c.Severity == contract.Breaking {
			for _, r := range rules {
				if err := mk.MarkStale(ctx, r, "contract-drift"); err != nil {
					m.log.WarnContext(ctx, "drift: mark rule stale", "rule", r, "err", err)
				}
			}
		}
		if c.Severity == contract.NonBreaking && m.cfg.DisableNonBreaking {
			continue
		}
		if err := m.enqueueAlert(ctx, a); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// raise stores the alert or refreshes the open duplicate. created tells
// whether a new alert exists.
func (m *Manager) raise(ctx context.Context, a Alert, from, to string) (Alert, bool, error) {
	key := dedupeKey(a.Kind, a.Service, a.Op, a.ChangeKind, a.Where, a.Change)
	if a.Group != "" {
		key = dedupeKey(a.Kind, a.Group, a.Service, a.Op, a.ChangeKind, a.Where, a.Change)
	}
	rules, _ := json.Marshal(nonNil(a.AffectedRules))
	params, _ := json.Marshal(nonNilParams(a.Params))
	var id int64
	var created bool
	err := m.db.InTx(ctx, func(tx *sql.Tx) error {
		var existing int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM drift_alerts WHERE dedupe_key = ? AND state = 'open'`, key).Scan(&existing)
		switch {
		case err == nil:
			id = existing
			_, err = tx.ExecContext(ctx, `UPDATE drift_alerts SET last_seen_ms = ?, calls_after = ?, snapshot_to = ? WHERE id = ?`,
				a.FirstSeen.UnixMilli(), a.Evidence.CallsAfterChange, to, id)
			return err
		case errors.Is(err, sql.ErrNoRows):
		default:
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO drift_alerts (kind, dedupe_key, service, op, where_text, change_kind, severity, change,
			first_seen_ms, last_seen_ms, calls_after, state, affected_rules, snapshot_from, snapshot_to, grp, params)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)`,
			a.Kind, key, a.Service, a.Op, a.Where, a.ChangeKind, a.Severity, a.Change,
			a.FirstSeen.UnixMilli(), a.FirstSeen.UnixMilli(), a.Evidence.CallsAfterChange, string(rules), from, to, a.Group, string(params))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		created = true
		return err
	})
	a.id, a.DriftID, a.State = id, alertID(id), "open"
	return a, created, err
}

func nonNilParams(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RuleStale implements [RuleStaleness]: it stores a rule.stale alert and
// notifies the subscribed webhooks.
func (m *Manager) RuleStale(ctx context.Context, r RuleStaleReport) error {
	sev := contract.NonBreaking
	text := fmt.Sprintf("rule %s confidence fell from %.2f to %.2f (%s)", r.RuleID, r.Previous, r.Confidence, r.Reason)
	a, created, err := m.raise(ctx, Alert{
		Kind: EventRuleStale, Service: r.Service, Op: r.Op, Severity: sev, Change: text,
		Where: "rule " + r.RuleID, ChangeKind: "rule-stale", FirstSeen: m.now().UTC(), AffectedRules: []string{r.RuleID},
		Params: map[string]string{"rule": r.RuleID, "from": fmt.Sprintf("%.2f", r.Previous), "to": fmt.Sprintf("%.2f", r.Confidence), "reason": r.Reason},
	}, "", "")
	if err != nil || !created {
		return err
	}
	return m.enqueueAlert(ctx, a)
}

// alertPayload is the webhook body of an alert: kinds, counts and
// identifiers, never values.
func alertPayload(kind string, a Alert) map[string]any {
	p := map[string]any{
		"type": kind, "drift_id": a.DriftID, "severity": a.Severity, "service": a.Service, "op": a.Op,
		"change": a.Change, "where": a.Where, "first_seen": a.FirstSeen.UTC().Format(time.RFC3339),
		"evidence": map[string]any{"calls_after_change": a.Evidence.CallsAfterChange},
	}
	if len(a.AffectedRules) > 0 {
		p["affected_rules"] = a.AffectedRules
	}
	return p
}

func (m *Manager) enqueueAlert(ctx context.Context, a Alert) error {
	return m.emit(ctx, a.Kind, a.id, alertPayload(a.Kind, a))
}

// Emit queues an arbitrary event for the webhooks subscribed to eventType
// (other packages use it for quarantine.opened, source.problem, ...). The
// payload must contain kinds, counts and identifiers only, never data values.
func (m *Manager) Emit(ctx context.Context, eventType string, payload map[string]any) error {
	p := map[string]any{"type": eventType}
	for k, v := range payload {
		p[k] = v
	}
	return m.emit(ctx, eventType, 0, p)
}

// Get returns one alert by its drift_id.
func (m *Manager) Get(ctx context.Context, driftID string) (Alert, error) {
	n, ok := parseAlertID(driftID)
	if !ok {
		return Alert{}, ErrNotFound
	}
	a, err := m.get(ctx, n)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (m *Manager) get(ctx context.Context, id int64) (Alert, error) {
	rows := m.db.QueryRowContext(ctx, alertSelect+` WHERE id = ?`, id)
	return scanAlert(rows)
}

const alertSelect = `SELECT id, kind, service, op, severity, change, first_seen_ms, calls_after, state, ack_by, affected_rules, where_text, change_kind, resolved_by, grp, params FROM drift_alerts`

func scanAlert(sc interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var first int64
	var rules, params string
	if err := sc.Scan(&a.id, &a.Kind, &a.Service, &a.Op, &a.Severity, &a.Change, &first, &a.Evidence.CallsAfterChange, &a.State, &a.AckBy, &rules, &a.Where, &a.ChangeKind, &a.ResolvedBy, &a.Group, &params); err != nil {
		return a, err
	}
	if params != "" && params != "{}" {
		_ = json.Unmarshal([]byte(params), &a.Params)
	}
	a.DriftID = alertID(a.id)
	a.FirstSeen = time.UnixMilli(first).UTC()
	_ = json.Unmarshal([]byte(rules), &a.AffectedRules)
	return a, nil
}

// ListFilter selects alerts.
type ListFilter struct {
	Severity string
	State    string
	// Kind: "" or "contract.drift" (default) lists contract alerts only;
	// "rule.stale" lists rule alerts; "all" lists everything.
	Kind  string
	Limit int
	// Groups keeps the alerts of these groups (empty: every group): the
	// alerts of their contracts, and the alerts without a group whose
	// service they produced.
	Groups groupscope.Set
}

// List returns alerts, newest first.
func (m *Manager) List(ctx context.Context, f ListFilter) ([]Alert, error) {
	var cond []string
	var args []any
	switch f.Kind {
	case "all":
	case "", EventContractDrift:
		cond = append(cond, "kind = ?")
		args = append(args, EventContractDrift)
	default:
		cond = append(cond, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.Severity != "" {
		cond = append(cond, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.State != "" {
		cond = append(cond, "state = ?")
		args = append(args, f.State)
	}
	q := alertSelect
	if len(cond) > 0 {
		q += " WHERE " + strings.Join(cond, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT %d", limit)
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sg map[string][]string
	if !f.Groups.All() && m.sg != nil {
		if sg, err = m.sg(ctx); err != nil {
			return nil, err
		}
	}
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		if !f.Groups.All() {
			if a.Group != "" && !f.Groups.Has(a.Group) || a.Group == "" && !f.Groups.Any(sg[a.Service]) {
				continue
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrNotFound is returned for unknown alerts and webhooks.
var ErrNotFound = errors.New("drift: not found")

// Alert states. An alert is born open; a person acknowledges it (seen,
// still relevant) or resolves it (no longer relevant). Resolving is final: a
// change that comes back raises a new alert.
const (
	StateOpen         = "open"
	StateAcknowledged = "acknowledged"
	StateResolved     = "resolved"
)

// ErrTransition is returned for a state change that is not allowed.
var ErrTransition = errors.New("drift: invalid state transition")

func parseAlertID(driftID string) (int64, bool) {
	var n int64
	if _, err := fmt.Sscanf(driftID, "dr-%d", &n); err != nil || alertID(n) != driftID {
		return 0, false
	}
	return n, true
}

// Ack acknowledges an alert; acknowledging twice is not an error, and an
// already resolved alert stays resolved.
func (m *Manager) Ack(ctx context.Context, driftID, by string) error {
	err := m.SetState(ctx, driftID, StateAcknowledged, by)
	if errors.Is(err, ErrTransition) {
		return nil // resolved implies seen
	}
	return err
}

// SetState moves an alert to acknowledged (from open) or resolved (from open
// or acknowledged). Repeating the current state is not an error; going back
// to open, or from resolved to acknowledged, is ErrTransition.
func (m *Manager) SetState(ctx context.Context, driftID, state, by string) error {
	n, ok := parseAlertID(driftID)
	if !ok {
		return ErrNotFound
	}
	var cur string
	if err := m.db.QueryRowContext(ctx, `SELECT state FROM drift_alerts WHERE id = ?`, n).Scan(&cur); err != nil {
		return ErrNotFound
	}
	now := m.now().UnixMilli()
	switch {
	case state == cur:
		return nil
	case state == StateAcknowledged && cur == StateOpen:
		_, err := m.db.ExecContext(ctx, `UPDATE drift_alerts SET state = 'acknowledged', ack_by = ?, ack_ms = ? WHERE id = ? AND state = 'open'`, by, now, n)
		return err
	case state == StateResolved && (cur == StateOpen || cur == StateAcknowledged):
		_, err := m.db.ExecContext(ctx, `UPDATE drift_alerts SET state = 'resolved', resolved_by = ?, resolved_ms = ? WHERE id = ? AND state IN ('open', 'acknowledged')`, by, now, n)
		return err
	}
	return ErrTransition
}

// sameTraffic: two snapshot windows are the same traffic when they overlap
// by at least half of the shorter one (a manual "update the contract now"
// takes a window that ends now and covers almost all of the previous one).
func sameTraffic(a, b contract.Window) bool {
	lo, hi := a.From, a.To
	if b.From.After(lo) {
		lo = b.From
	}
	if b.To.Before(hi) {
		hi = b.To
	}
	overlap := hi.Sub(lo)
	short := min(a.To.Sub(a.From), b.To.Sub(b.From))
	return overlap > 0 && short > 0 && overlap*2 >= short
}

// tinyShift is how far the presence of a field must move to count as a
// change of the API and not as the effect of more samples.
const tinyShift = 0.1

// Quiet drops from the changes of two snapshots the ones that say nothing
// about the API: a required flag that flips with a tiny shift of presence
// (a header seen in 98% then in 100% of the calls), and, when the two
// windows are the same traffic seen twice, every non-breaking change (the
// contract only completed with more samples: new enum value, a field seen
// more often). Breaking changes of different windows are always kept.
func Quiet(prev, cur contract.Window, changes []contract.Change) []contract.Change {
	same := sameTraffic(prev, cur)
	out := changes[:0:0]
	for _, c := range changes {
		switch {
		case c.Kind == "required-changed" && c.Shift <= tinyShift:
			continue
		case same && c.Severity != contract.Breaking:
			continue
		}
		out = append(out, c)
	}
	return out
}
