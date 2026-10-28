// Package audit is the append-only, hash-chained audit log of tt-core
// (threat model M4, M7, M17; guarantee G8).
//
// Every entry stores the SHA-256 of the previous entry, so editing, deleting
// or reordering rows breaks [Log.Verify]. SQLite triggers additionally refuse
// UPDATE and DELETE on the table. Truncating the newest entries cannot be
// detected from inside the database: anchor [Log.Head] externally (export it
// periodically, or compare it with the value shown to auditors).
//
// The log records who did what, to which object, when and with which
// outcome. It never records payload values: details are restricted to short
// identifier-like strings (ids, versions, hashes, counts, codes) and free
// text is rejected by [Event.validate].
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "audit", Migrations: migrations})
}

var migrations = []store.Migration{
	{Version: 1, Name: "entries", SQL: `
CREATE TABLE audit_entries (
	seq         INTEGER PRIMARY KEY,
	ts          TEXT NOT NULL,
	actor_kind  TEXT NOT NULL,
	actor_id    TEXT NOT NULL,
	actor_name  TEXT NOT NULL,
	action      TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_id   TEXT NOT NULL,
	outcome     TEXT NOT NULL,
	reason      TEXT NOT NULL,
	request_id  TEXT NOT NULL,
	details     TEXT NOT NULL,
	prev_hash   TEXT NOT NULL,
	hash        TEXT NOT NULL UNIQUE
) STRICT;
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`},
	{Version: 2, Name: "archived_segments", SQL: archiveMigration},
}

// Outcome of an audited action.
type Outcome string

// Outcomes.
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// ActorKind distinguishes humans from automated callers.
type ActorKind string

// Actor kinds.
const (
	ActorUser      ActorKind = "user"
	ActorSystem    ActorKind = "system"
	ActorSource    ActorKind = "source"
	ActorAnonymous ActorKind = "anonymous"
)

// Actor is who performed the action.
type Actor struct {
	Kind ActorKind `json:"kind"`
	ID   string    `json:"id"`
	Name string    `json:"name"`
}

// Target is the object acted upon.
type Target struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Event is what callers record.
type Event struct {
	Actor     Actor
	Action    string // dotted verb, e.g. "auth.login", "policy.approve"
	Target    Target
	Outcome   Outcome
	Reason    string // machine code, e.g. "invalid_credentials"
	RequestID string
	Details   map[string]string
}

// Entry is a stored event.
type Entry struct {
	Seq       int64             `json:"seq"`
	Time      time.Time         `json:"ts"`
	Actor     Actor             `json:"actor"`
	Action    string            `json:"action"`
	Target    Target            `json:"target"`
	Outcome   Outcome           `json:"outcome"`
	Reason    string            `json:"reason,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// GenesisHash is the prev_hash of the first entry.
var GenesisHash = strings.Repeat("0", 64)

var (
	reAction = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){1,4}$`)
	reCode   = regexp.MustCompile(`^[a-z0-9_.:-]{0,64}$`)
	reKey    = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	// Identifier-like values only: no spaces, no free text.
	reValue = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=,-]{0,128}$`)
	reName  = regexp.MustCompile(`^[\pL\pN_.@+ -]{0,128}$`)
)

const maxDetails = 16

// ErrInvalidEvent reports an event that could carry payload values.
var ErrInvalidEvent = errors.New("audit: invalid event")

func (e Event) validate() error {
	bad := func(field string) error { return fmt.Errorf("%w: %s", ErrInvalidEvent, field) }
	switch e.Actor.Kind {
	case ActorUser, ActorSystem, ActorSource, ActorAnonymous:
	default:
		return bad("actor.kind")
	}
	if !reValue.MatchString(e.Actor.ID) {
		return bad("actor.id")
	}
	if !reName.MatchString(e.Actor.Name) {
		return bad("actor.name")
	}
	if !reAction.MatchString(e.Action) {
		return bad("action")
	}
	if !reCode.MatchString(e.Target.Type) || !reValue.MatchString(e.Target.ID) {
		return bad("target")
	}
	switch e.Outcome {
	case Success, Failure, Denied:
	default:
		return bad("outcome")
	}
	if !reCode.MatchString(e.Reason) || !reValue.MatchString(e.RequestID) {
		return bad("reason/request_id")
	}
	if len(e.Details) > maxDetails {
		return bad("details: too many keys")
	}
	for k, v := range e.Details {
		if !reKey.MatchString(k) || !reValue.MatchString(v) {
			return bad("details." + sanitizeKey(k))
		}
	}
	return nil
}

// SafeName maps a display name (e.g. from OIDC claims) to the character set
// accepted for Actor.Name: other characters become '_' and the result is cut
// to 128 runes.
func SafeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if len(out) == 128 {
			break
		}
		if !reName.MatchString(string(r)) {
			r = '_'
		}
		out = append(out, r)
	}
	return string(out)
}

// SafeValue maps s to the identifier-like set accepted for ids and detail
// values: other characters become '_' and the result is cut to 128 bytes.
func SafeValue(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < 128; i++ {
		c := s[i]
		if !reValue.Match([]byte{c}) {
			c = '_'
		}
		out = append(out, c)
	}
	return string(out)
}

func sanitizeKey(k string) string {
	if reKey.MatchString(k) {
		return k
	}
	return "<invalid key>"
}

// Log appends to and reads from the audit table.
type Log struct {
	db  *store.DB
	now func() time.Time
	mu  sync.Mutex
}

// New returns a Log backed by db (migrated by store.Open).
func New(db *store.DB) *Log {
	return &Log{db: db, now: time.Now}
}

// Record appends e. It returns an error when the event is invalid or cannot
// be stored; callers performing a sensitive action should fail closed.
func (l *Log) Record(ctx context.Context, e Event) (Entry, error) {
	if err := e.validate(); err != nil {
		return Entry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	var out Entry
	err := l.db.InTx(ctx, func(tx *sql.Tx) error {
		prev := GenesisHash
		var lastSeq int64
		err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prev)
		if errors.Is(err, sql.ErrNoRows) {
			// Empty table: continue after the archived segments, if any.
			lastSeq, prev, err = l.anchor(ctx, tx)
		}
		if err != nil {
			return err
		}
		out = Entry{
			Seq:       lastSeq + 1,
			Time:      l.now().UTC().Truncate(time.Microsecond),
			Actor:     e.Actor,
			Action:    e.Action,
			Target:    e.Target,
			Outcome:   e.Outcome,
			Reason:    e.Reason,
			RequestID: e.RequestID,
			Details:   e.Details,
			PrevHash:  prev,
		}
		out.Hash = out.computeHash()
		details, err := json.Marshal(nonNil(out.Details))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_entries
			(seq, ts, actor_kind, actor_id, actor_name, action, target_type, target_id, outcome, reason, request_id, details, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			out.Seq, out.Time.Format(time.RFC3339Nano), string(out.Actor.Kind), out.Actor.ID, out.Actor.Name,
			out.Action, out.Target.Type, out.Target.ID, string(out.Outcome), out.Reason, out.RequestID,
			string(details), out.PrevHash, out.Hash)
		return err
	})
	if err != nil {
		return Entry{}, fmt.Errorf("audit: record: %w", err)
	}
	return out, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// computeHash hashes a canonical JSON encoding of every field except Hash.
// encoding/json writes struct fields in declaration order and map keys
// sorted, so the encoding is deterministic.
func (e Entry) computeHash() string {
	canon := struct {
		Seq       int64             `json:"seq"`
		Time      string            `json:"ts"`
		Actor     Actor             `json:"actor"`
		Action    string            `json:"action"`
		Target    Target            `json:"target"`
		Outcome   Outcome           `json:"outcome"`
		Reason    string            `json:"reason"`
		RequestID string            `json:"request_id"`
		Details   map[string]string `json:"details"`
		PrevHash  string            `json:"prev_hash"`
	}{e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Outcome, e.Reason, e.RequestID, nonNil(e.Details), e.PrevHash}
	b, err := json.Marshal(canon)
	if err != nil {
		panic(err) // only strings and ints: cannot fail
	}
	sum := sha256.Sum256(append([]byte("tt.audit/v1\n"), b...))
	return hex.EncodeToString(sum[:])
}

// Head returns the sequence number and hash of the newest entry
// (0 and GenesisHash when empty).
func (l *Log) Head(ctx context.Context) (int64, string, error) {
	var seq int64
	hash := GenesisHash
	err := l.db.QueryRowContext(ctx, `SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return l.anchor(ctx, l.db)
	}
	return seq, hash, err
}

// ErrTampered reports a broken chain.
var ErrTampered = errors.New("audit: chain verification failed")

// VerifyResult summarizes a verification run.
type VerifyResult struct {
	Entries  int64  `json:"entries"`
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	// Archived is the number of entries moved to archived segments and
	// Segments the number of segments (the chain is verified from the
	// anchor of the last one; VerifyArchive checks the files).
	Archived int64 `json:"archived"`
	Segments int   `json:"segments"`
}

// Verify walks the whole chain. It returns ErrTampered (wrapped, with the
// first bad sequence number) when an entry was modified, removed, inserted
// or reordered. When old segments were archived, the segment records must
// link to each other from the genesis and the first entry left in the
// database must link to the head hash of the last pruned segment.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{HeadHash: GenesisHash}
	segs, err := l.Segments(ctx)
	if err != nil {
		return res, err
	}
	lastSeg, lastHead, exported, err := verifySegments(segs)
	if err != nil {
		return res, err
	}
	res.Segments = len(segs)
	// Start from the anchor: the head of the newest pruned segment (or of
	// the newest segment when nothing is left in the database).
	prev := GenesisHash
	var want int64 = 1
	for _, s := range segs {
		res.Archived += s.Entries
		if s.State == "pruned" {
			want, prev = s.LastSeq+1, s.HeadHash
		}
	}
	if len(segs) > 0 {
		res.HeadSeq, res.HeadHash = lastSeg, lastHead
		var first sql.NullInt64
		if err := l.db.QueryRowContext(ctx, `SELECT min(seq) FROM audit_entries`).Scan(&first); err != nil {
			return res, err
		}
		switch {
		case !first.Valid:
			// Everything archived (the head is the last segment's).
		case first.Int64 < want:
			return res, fmt.Errorf("%w: seq %d belongs to a pruned segment", ErrTampered, first.Int64)
		case first.Int64 > want && first.Int64 <= lastSeg:
			// The deletion of an exported segment was interrupted: its
			// remaining entries are checked against its head hash.
			want, prev = first.Int64, ""
		}
	}
	// The links are checked in order; the hashes, the costly part (one
	// JSON encoding and one SHA-256 per entry), are computed by a few
	// workers on blocks of entries read ahead.
	check := func(batch []Entry) error {
		ok := make([]bool, len(batch))
		workers := min(runtime.GOMAXPROCS(0), 8)
		per := (len(batch) + workers - 1) / workers
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			lo, hi := w*per, min((w+1)*per, len(batch))
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					ok[i] = batch[i].computeHash() == batch[i].Hash
				}
			}()
		}
		wg.Wait()
		for i := range batch {
			e := &batch[i]
			if e.Seq != want {
				return fmt.Errorf("%w: expected seq %d, found %d", ErrTampered, want, e.Seq)
			}
			if prev != "" && e.PrevHash != prev {
				return fmt.Errorf("%w: seq %d does not link to its predecessor", ErrTampered, e.Seq)
			}
			if s, ok := exported[e.Seq]; ok && e.Hash != s.HeadHash {
				return fmt.Errorf("%w: seq %d does not match its archived segment", ErrTampered, e.Seq)
			}
			if !ok[i] {
				return fmt.Errorf("%w: seq %d content does not match its hash", ErrTampered, e.Seq)
			}
			prev = e.Hash
			want++
			res.Entries++
			res.HeadSeq, res.HeadHash = e.Seq, e.Hash
		}
		return nil
	}
	const block = 4096
	batch := make([]Entry, 0, block)
	err = l.Iterate(ctx, want-1, 0, func(e Entry) error {
		batch = append(batch, e)
		if len(batch) < block {
			return nil
		}
		err := check(batch)
		batch = batch[:0]
		return err
	})
	if err == nil && len(batch) > 0 {
		err = check(batch)
	}
	return res, err
}

// Iterate calls fn for entries with seq > afterSeq in ascending order,
// at most limit entries (0 = no limit).
func (l *Log) Iterate(ctx context.Context, afterSeq int64, limit int, fn func(Entry) error) error {
	q := entrySelect + ` WHERE seq > ? ORDER BY seq`
	args := []any{afterSeq}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	return l.iterateQuery(ctx, q, args, fn)
}

// IterateTail calls fn, in ascending order, for the newest n entries whose
// seq is below beforeSeq (beforeSeq <= 0: the whole log), so that a reader
// can start from the end of a long log and page backwards.
func (l *Log) IterateTail(ctx context.Context, beforeSeq int64, n int, fn func(Entry) error) error {
	if n <= 0 {
		return nil
	}
	q := entrySelect + ` WHERE seq >= COALESCE((SELECT MIN(seq) FROM (SELECT seq FROM audit_entries
		WHERE (? <= 0 OR seq < ?) ORDER BY seq DESC LIMIT ?)), 0) AND (? <= 0 OR seq < ?) ORDER BY seq`
	return l.iterateQuery(ctx, q, []any{beforeSeq, beforeSeq, n, beforeSeq, beforeSeq}, fn)
}

const entrySelect = `SELECT seq, ts, actor_kind, actor_id, actor_name, action, target_type, target_id, outcome, reason, request_id, details, prev_hash, hash
		FROM audit_entries`

func (l *Log) iterateQuery(ctx context.Context, q string, args []any, fn func(Entry) error) error {
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		var ts, kind, outcome, details string
		if err := rows.Scan(&e.Seq, &ts, &kind, &e.Actor.ID, &e.Actor.Name, &e.Action, &e.Target.Type, &e.Target.ID,
			&outcome, &e.Reason, &e.RequestID, &details, &e.PrevHash, &e.Hash); err != nil {
			return err
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return fmt.Errorf("%w: seq %d has an invalid timestamp", ErrTampered, e.Seq)
		}
		e.Time, e.Actor.Kind, e.Outcome = t, ActorKind(kind), Outcome(outcome)
		if err := json.Unmarshal([]byte(details), &e.Details); err != nil {
			return fmt.Errorf("%w: seq %d has invalid details", ErrTampered, e.Seq)
		}
		if len(e.Details) == 0 {
			e.Details = nil
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}
