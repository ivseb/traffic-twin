package intake

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

// QuarantineKind is the kind of element whose cardinality exceeded its
// threshold (docs/spec/event.md 5.2).
type QuarantineKind string

// Quarantine kinds.
const (
	// QuarantineKeep: a keep: field (values rewritten to drop forms).
	QuarantineKeep QuarantineKind = "keep"
	// QuarantineName: the literal names under a parent (rewritten to {*}).
	QuarantineName QuarantineKind = "name"
	// QuarantineSegment: the literal segments at a path position
	// (rewritten to {drop:str:<class>}).
	QuarantineSegment QuarantineKind = "segment"
	// QuarantineHost: the registrable domains of the host services of a
	// source (spec v1.5: the registrable label of their patterns is
	// rewritten to {*}).
	QuarantineHost QuarantineKind = "host"
	// QuarantineHostLabel: the literal labels at one position of the host
	// patterns under one registrable domain (spec v1.5: rewritten to {*}).
	QuarantineHostLabel QuarantineKind = "host-label"
)

// AlarmHostCardinality is the alarm name of the two host kinds (the
// "alert" of the quarantine.opened notification).
const AlarmHostCardinality = "host_cardinality"

// QuarantineState is the lifecycle state of a quarantine.
type QuarantineState string

// Quarantine states.
const (
	// StateOpen: raised, rewriting active, alarm to acknowledge.
	StateOpen QuarantineState = "open"
	// StateClosed: a policy change closed the field (1 approval, policy.md
	// section 5). Rewriting stays active: only a release lifts it.
	StateClosed QuarantineState = "closed"
	// StateReleased: dissolved explicitly (counts as opening, 2 approvals);
	// rewriting stopped and counting restarted from zero.
	StateReleased QuarantineState = "released"
)

// Quarantine is one quarantined element.
type Quarantine struct {
	ID    int64
	Kind  QuarantineKind
	State QuarantineState
	// Key identifies the element (an opaque, stable string).
	Key       string
	Since     time.Time
	Estimate  int
	Threshold int
	// Decoded key (which fields apply depends on Kind).
	PolicyID string // keep, name
	Service  string // keep, name, segment ("host:*" for all external hosts)
	Op       string // keep, name ("(raw)" for raw routes)
	Part     string // keep, name: req.body, resp.body, req.query, req.headers, req.cookies, resp.headers, resp.cookies, req.path
	Path     string // keep, name: tt-path of the field or of the parent; header/query/cookie name; "p<i>" for path params
	Method   string // segment
	Position int    // segment: index in the operation path; host-label: position left of the registrable domain (1 = nearest)
	SourceID string // host
	Domain   string // host-label: registrable domain of the patterns (e.g. "tracking.example")
}

func (k QuarantineKind) obs() obsKind {
	switch k {
	case QuarantineKeep:
		return obsKeep
	case QuarantineName:
		return obsName
	case QuarantineSegment:
		return obsSegment
	case QuarantineHostLabel:
		return obsHostLabel
	}
	return obsHost
}

func kindOfObs(k obsKind) QuarantineKind {
	switch k {
	case obsKeep:
		return QuarantineKeep
	case obsName:
		return QuarantineName
	case obsSegment:
		return QuarantineSegment
	case obsHostLabel:
		return QuarantineHostLabel
	}
	return QuarantineHost
}

// decodeKey fills the structured fields from the key.
func (q *Quarantine) decodeKey() {
	p := strings.Split(q.Key, "\x1f")
	switch q.Kind {
	case QuarantineKeep, QuarantineName:
		if len(p) == 5 {
			q.PolicyID, q.Service, q.Op, q.Part, q.Path = p[0], p[1], p[2], p[3], p[4]
		}
	case QuarantineSegment:
		if len(p) == 3 {
			q.Service, q.Method = p[0], p[1]
			q.Position, _ = strconv.Atoi(p[2])
		}
	case QuarantineHost:
		q.SourceID = q.Key
	case QuarantineHostLabel:
		if len(p) == 2 {
			q.Domain = p[0]
			q.Position, _ = strconv.Atoi(p[1])
		}
		q.Service = "host:*"
	}
}

// qEntry is an active keep/name quarantine in a snapshot.
type qEntry struct {
	kind QuarantineKind
	part string
	path string
}

// qSnapshot is an immutable view of the active quarantines, used by the
// rewriter. Replaced atomically; version increases with every change.
type qSnapshot struct {
	version  uint64
	byPrefix map[string][]qEntry // policy \0 service \0 op \0
	segments map[string]map[int]struct{}
	hosts    map[string]struct{}         // source ids (QuarantineHost)
	labels   map[string]map[int]struct{} // registrable domain -> positions (QuarantineHostLabel)
}

func (s *qSnapshot) empty() bool {
	return len(s.byPrefix) == 0 && len(s.segments) == 0 && len(s.hosts) == 0 && len(s.labels) == 0
}

// quarantineManager owns the quarantine table and the active snapshot.
type quarantineManager struct {
	db   *store.DB
	mu   sync.Mutex
	byID map[int64]*Quarantine
	snap atomic.Pointer[qSnapshot]
	ver  uint64
}

func newQuarantineManager(db *store.DB) *quarantineManager {
	m := &quarantineManager{db: db, byID: map[int64]*Quarantine{}}
	m.snap.Store(&qSnapshot{})
	return m
}

func (m *quarantineManager) load(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx, `SELECT id, kind, qkey, state, since_ms, estimate, threshold FROM intake_quarantine`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	for rows.Next() {
		var q Quarantine
		var since int64
		var kind, state string
		if err := rows.Scan(&q.ID, &kind, &q.Key, &state, &since, &q.Estimate, &q.Threshold); err != nil {
			return err
		}
		q.Kind, q.State, q.Since = QuarantineKind(kind), QuarantineState(state), time.UnixMilli(since).UTC()
		q.decodeKey()
		m.byID[q.ID] = &q
	}
	if err := rows.Err(); err != nil {
		return err
	}
	m.rebuildLocked()
	return nil
}

func (m *quarantineManager) rebuildLocked() {
	s := &qSnapshot{
		byPrefix: map[string][]qEntry{},
		segments: map[string]map[int]struct{}{},
		hosts:    map[string]struct{}{},
		labels:   map[string]map[int]struct{}{},
	}
	ids := make([]int64, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		q := m.byID[id]
		if q.State == StateReleased {
			continue
		}
		switch q.Kind {
		case QuarantineKeep, QuarantineName:
			pre := q.PolicyID + "\x1f" + q.Service + "\x1f" + q.Op + "\x1f"
			s.byPrefix[pre] = append(s.byPrefix[pre], qEntry{kind: q.Kind, part: q.Part, path: q.Path})
		case QuarantineSegment:
			k := q.Service + "\x1f" + q.Method
			if s.segments[k] == nil {
				s.segments[k] = map[int]struct{}{}
			}
			s.segments[k][q.Position] = struct{}{}
		case QuarantineHost:
			s.hosts[q.SourceID] = struct{}{}
		case QuarantineHostLabel:
			if s.labels[q.Domain] == nil {
				s.labels[q.Domain] = map[int]struct{}{}
			}
			s.labels[q.Domain][q.Position] = struct{}{}
		}
	}
	m.ver++
	s.version = m.ver
	m.snap.Store(s)
}

func (m *quarantineManager) snapshot() *qSnapshot { return m.snap.Load() }

// raise records a new quarantine.
func (m *quarantineManager) raise(ctx context.Context, n newQuarantine, now time.Time) (Quarantine, error) {
	q := Quarantine{Kind: kindOfObs(n.kind), State: StateOpen, Key: n.key, Since: now.UTC().Truncate(time.Millisecond), Estimate: n.estimate, Threshold: n.threshold}
	res, err := m.db.ExecContext(ctx, `INSERT INTO intake_quarantine (kind, qkey, state, since_ms, estimate, threshold) VALUES (?, ?, 'open', ?, ?, ?)`,
		string(q.Kind), q.Key, q.Since.UnixMilli(), q.Estimate, q.Threshold)
	if err != nil {
		return Quarantine{}, fmt.Errorf("intake: record quarantine: %w", err)
	}
	q.ID, _ = res.LastInsertId()
	q.decodeKey()
	m.mu.Lock()
	m.byID[q.ID] = &q
	m.rebuildLocked()
	m.mu.Unlock()
	return q, nil
}

// ErrNoQuarantine is returned for an unknown quarantine id.
var ErrNoQuarantine = errors.New("intake: no such quarantine")

func (m *quarantineManager) setState(ctx context.Context, id int64, from []QuarantineState, to QuarantineState, now time.Time) (Quarantine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.byID[id]
	if q == nil {
		return Quarantine{}, ErrNoQuarantine
	}
	ok := false
	for _, f := range from {
		if q.State == f {
			ok = true
		}
	}
	if !ok {
		return *q, fmt.Errorf("intake: quarantine %d is %s, cannot become %s", id, q.State, to)
	}
	if _, err := m.db.ExecContext(ctx, `UPDATE intake_quarantine SET state = ?, changed_ms = ? WHERE id = ?`, string(to), now.UnixMilli(), id); err != nil {
		return *q, err
	}
	q.State = to
	m.rebuildLocked()
	return *q, nil
}

func (m *quarantineManager) list(includeReleased bool) []Quarantine {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Quarantine, 0, len(m.byID))
	for _, q := range m.byID {
		if q.State == StateReleased && !includeReleased {
			continue
		}
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *quarantineManager) get(id int64) (Quarantine, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.byID[id]
	if q == nil {
		return Quarantine{}, false
	}
	return *q, true
}
