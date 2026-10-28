package contract

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "contract", Migrations: []store.Migration{
		{Version: 1, Name: "snapshots", SQL: `
CREATE TABLE contract_snapshots (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	service        TEXT    NOT NULL,
	window_from_ms INTEGER NOT NULL,
	window_to_ms   INTEGER NOT NULL,
	created_ms     INTEGER NOT NULL,
	ops            INTEGER NOT NULL,
	calls          INTEGER NOT NULL,
	hash           TEXT    NOT NULL,
	model          BLOB    NOT NULL,
	UNIQUE (service, window_from_ms, window_to_ms)
) STRICT;
CREATE INDEX contract_snapshots_service ON contract_snapshots (service, id);
`},
		{Version: 2, Name: "snapshot_change_counts", SQL: `
ALTER TABLE contract_snapshots ADD COLUMN breaking     INTEGER NOT NULL DEFAULT -1;
ALTER TABLE contract_snapshots ADD COLUMN non_breaking INTEGER NOT NULL DEFAULT -1;
`},
		// Multi-team isolation: a snapshot is the contract of one group's
		// traffic to a service (grp '' for the snapshots taken before, of
		// every group; tt-core attributes them to the only group that
		// produced the service at start).
		{Version: 3, Name: "snapshot_group", SQL: `
CREATE TABLE contract_snapshots_g (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	grp            TEXT    NOT NULL DEFAULT '',
	service        TEXT    NOT NULL,
	window_from_ms INTEGER NOT NULL,
	window_to_ms   INTEGER NOT NULL,
	created_ms     INTEGER NOT NULL,
	ops            INTEGER NOT NULL,
	calls          INTEGER NOT NULL,
	hash           TEXT    NOT NULL,
	model          BLOB    NOT NULL,
	breaking       INTEGER NOT NULL DEFAULT -1,
	non_breaking   INTEGER NOT NULL DEFAULT -1,
	UNIQUE (grp, service, window_from_ms, window_to_ms)
) STRICT;
INSERT INTO contract_snapshots_g (id, grp, service, window_from_ms, window_to_ms, created_ms, ops, calls, hash, model, breaking, non_breaking)
	SELECT id, '', service, window_from_ms, window_to_ms, created_ms, ops, calls, hash, model, breaking, non_breaking FROM contract_snapshots;
DROP TABLE contract_snapshots;
ALTER TABLE contract_snapshots_g RENAME TO contract_snapshots;
CREATE INDEX contract_snapshots_service ON contract_snapshots (grp, service, id);
`},
	}})
}

// ErrNotFound is returned when a snapshot does not exist.
var ErrNotFound = errors.New("contract: not found")

// SnapshotInfo describes a stored snapshot (admin API SnapshotInfo).
type SnapshotInfo struct {
	Service string `json:"service"`
	// Group is the group whose traffic the snapshot describes ("": the
	// traffic of every group, snapshots taken before groups were tracked).
	Group      string    `json:"group"`
	SnapshotID string    `json:"snapshot_id"`
	Window     Window    `json:"window"`
	Ops        int       `json:"ops"`
	Calls      int64     `json:"calls"`
	CreatedAt  time.Time `json:"created_at"`
	Hash       string    `json:"hash"`
	// Breaking and NonBreaking count the changes against the previous
	// snapshot of the same service (0 and 0 for the first one).
	Breaking    int `json:"breaking"`
	NonBreaking int `json:"non_breaking"`
	// ReplacedBy (listContracts only) is set on the contract of an old
	// host:<pattern> service that the group's policy declares since under
	// this name (ReplacedLookup): kept as history, out of the packs by
	// default.
	ReplacedBy string `json:"replaced_by,omitempty"`

	seq     int64
	counted bool // Breaking and NonBreaking are known (stored)
}

// Seq is the monotonically increasing sequence number of the snapshot.
func (i SnapshotInfo) Seq() int64 { return i.seq }

// Snapshot is a stored snapshot with its model.
type Snapshot struct {
	SnapshotInfo
	Contract *Contract `json:"-"`
}

const snapshotPrefix = "sn-"

func snapshotID(seq int64) string { return fmt.Sprintf("%s%08d", snapshotPrefix, seq) }

func parseSnapshotID(id string) (int64, bool) {
	r, ok := strings.CutPrefix(id, snapshotPrefix)
	if !ok || len(r) == 0 || len(r) > 18 {
		return 0, false
	}
	n, err := strconv.ParseInt(r, 10, 64)
	return n, err == nil && n > 0
}

// SnapshotStore persists snapshots in SQLite.
type SnapshotStore struct {
	db   *store.DB
	diff DiffConfig
	// protect lists the snapshots that must survive Prune and Compact
	// (retention.go).
	protect Protector
}

// NewSnapshotStore returns a store on a database opened with store.Open.
func NewSnapshotStore(db *store.DB) *SnapshotStore {
	return &SnapshotStore{db: db, diff: DefaultConfig().Diff}
}

// Save stores the contract as the snapshot of its window. A second save for
// the same (service, window) replaces the model and keeps the id.
func (s *SnapshotStore) Save(ctx context.Context, c *Contract, now time.Time) (*Snapshot, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	var seq int64
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO contract_snapshots (grp, service, window_from_ms, window_to_ms, created_ms, ops, calls, hash, model)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (grp, service, window_from_ms, window_to_ms) DO UPDATE SET created_ms = excluded.created_ms,
				ops = excluded.ops, calls = excluded.calls, hash = excluded.hash, model = excluded.model,
				breaking = -1, non_breaking = -1`,
			c.Group, c.Service, c.Window.From.UnixMilli(), c.Window.To.UnixMilli(), now.UnixMilli(), len(c.Ops), c.Calls(), hash, zb.Bytes())
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT id FROM contract_snapshots WHERE grp = ? AND service = ? AND window_from_ms = ? AND window_to_ms = ?`,
			c.Group, c.Service, c.Window.From.UnixMilli(), c.Window.To.UnixMilli()).Scan(&seq)
	})
	if err != nil {
		return nil, err
	}
	info := SnapshotInfo{Service: c.Service, Group: c.Group, SnapshotID: snapshotID(seq), Window: c.Window, Ops: len(c.Ops), Calls: c.Calls(), CreatedAt: now.UTC(), Hash: hash, seq: seq}
	return &Snapshot{SnapshotInfo: info, Contract: c}, nil
}

const infoCols = `id, grp, service, window_from_ms, window_to_ms, created_ms, ops, calls, hash, breaking, non_breaking`

func scanInfo(sc interface{ Scan(...any) error }, extra ...any) (SnapshotInfo, error) {
	var i SnapshotInfo
	var from, to, created int64
	var br, nb int
	dest := append([]any{&i.seq, &i.Group, &i.Service, &from, &to, &created, &i.Ops, &i.Calls, &i.Hash, &br, &nb}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return i, err
	}
	if br >= 0 && nb >= 0 {
		i.Breaking, i.NonBreaking, i.counted = br, nb, true
	}
	i.SnapshotID = snapshotID(i.seq)
	i.Window = Window{From: time.UnixMilli(from).UTC(), To: time.UnixMilli(to).UTC()}
	i.CreatedAt = time.UnixMilli(created).UTC()
	return i, nil
}

func decodeModel(zb []byte) (*Contract, error) {
	zr, err := gzip.NewReader(bytes.NewReader(zb))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 256<<20))
	if err != nil {
		return nil, err
	}
	var c Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Get returns the snapshot id of service (group "": the snapshots of every
// group's traffic).
func (s *SnapshotStore) Get(ctx context.Context, service, id string) (*Snapshot, error) {
	return s.GetIn(ctx, "", service, id)
}

// GetIn returns the snapshot id of (group, service).
func (s *SnapshotStore) GetIn(ctx context.Context, group, service, id string) (*Snapshot, error) {
	seq, ok := parseSnapshotID(id)
	if !ok {
		return nil, ErrNotFound
	}
	return s.one(ctx, `SELECT `+infoCols+`, model FROM contract_snapshots WHERE grp = ? AND service = ? AND id = ?`, group, service, seq)
}

// Latest returns the newest snapshot of service (group "").
func (s *SnapshotStore) Latest(ctx context.Context, service string) (*Snapshot, error) {
	return s.LatestIn(ctx, "", service)
}

// LatestIn returns the newest snapshot of (group, service).
func (s *SnapshotStore) LatestIn(ctx context.Context, group, service string) (*Snapshot, error) {
	return s.one(ctx, `SELECT `+infoCols+`, model FROM contract_snapshots WHERE grp = ? AND service = ? ORDER BY id DESC LIMIT 1`, group, service)
}

// Previous returns the newest snapshot of service (group "") older than seq.
func (s *SnapshotStore) Previous(ctx context.Context, service string, seq int64) (*Snapshot, error) {
	return s.PreviousIn(ctx, "", service, seq)
}

// PreviousIn returns the newest snapshot of (group, service) older than seq.
func (s *SnapshotStore) PreviousIn(ctx context.Context, group, service string, seq int64) (*Snapshot, error) {
	return s.one(ctx, `SELECT `+infoCols+`, model FROM contract_snapshots WHERE grp = ? AND service = ? AND id < ? ORDER BY id DESC LIMIT 1`, group, service, seq)
}

func (s *SnapshotStore) one(ctx context.Context, q string, args ...any) (*Snapshot, error) {
	var zb []byte
	row := s.db.QueryRowContext(ctx, q, args...)
	info, err := scanInfo(row, &zb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c, err := decodeModel(zb)
	if err != nil {
		return nil, fmt.Errorf("contract: snapshot %s: %w", info.SnapshotID, err)
	}
	return &Snapshot{SnapshotInfo: info, Contract: c}, nil
}

// SetCounts stores the change counts of a snapshot against its predecessor.
func (s *SnapshotStore) SetCounts(ctx context.Context, i *SnapshotInfo, breaking, nonBreaking int) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE contract_snapshots SET breaking = ?, non_breaking = ? WHERE id = ?`, breaking, nonBreaking, i.seq); err != nil {
		return err
	}
	i.Breaking, i.NonBreaking, i.counted = breaking, nonBreaking, true
	return nil
}

// fillCounts computes and stores the counts of snapshots saved before they
// were kept (a one-time cost per old snapshot).
func (s *SnapshotStore) fillCounts(ctx context.Context, infos []SnapshotInfo) error {
	for k := range infos {
		i := &infos[k]
		if i.counted {
			continue
		}
		cur, err := s.GetIn(ctx, i.Group, i.Service, i.SnapshotID)
		if err != nil {
			return err
		}
		br, nb := 0, 0
		prev, err := s.PreviousIn(ctx, i.Group, i.Service, i.seq)
		switch {
		case err == nil:
			d := DiffOf(prev, cur, s.diff)
			br, nb = d.Breaking, d.NonBreaking
		case !errors.Is(err, ErrNotFound):
			return err
		}
		if err := s.SetCounts(ctx, i, br, nb); err != nil {
			return err
		}
	}
	return nil
}

// List returns the snapshots of service (group ""), newest first (limit <= 0: 100).
func (s *SnapshotStore) List(ctx context.Context, service string, limit int) ([]SnapshotInfo, error) {
	return s.ListIn(ctx, "", service, limit)
}

// ListIn returns the snapshots of (group, service), newest first.
func (s *SnapshotStore) ListIn(ctx context.Context, group, service string, limit int) ([]SnapshotInfo, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+infoCols+` FROM contract_snapshots WHERE grp = ? AND service = ? ORDER BY id DESC LIMIT ?`, group, service, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotInfo
	for rows.Next() {
		i, err := scanInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.fillCounts(ctx, out)
}

// LatestInfos returns the newest snapshot of every (group, service), sorted
// by service then group.
func (s *SnapshotStore) LatestInfos(ctx context.Context) ([]SnapshotInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+infoCols+` FROM contract_snapshots
		WHERE id IN (SELECT max(id) FROM contract_snapshots GROUP BY grp, service) ORDER BY service, grp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotInfo
	for rows.Next() {
		i, err := scanInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.fillCounts(ctx, out)
}

// LatestRefs is LatestInfos without the change counts (no snapshot is read
// or compared): the newest snapshot of every (group, service), sorted by
// service then group. For callers that only need to know which snapshot is
// current, cheaply.
func (s *SnapshotStore) LatestRefs(ctx context.Context) ([]SnapshotInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+infoCols+` FROM contract_snapshots
		WHERE id IN (SELECT max(id) FROM contract_snapshots GROUP BY grp, service) ORDER BY service, grp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotInfo
	for rows.Next() {
		i, err := scanInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Prune keeps the newest keep snapshots of service (group ""), plus the
// protected ones (SetProtector).
func (s *SnapshotStore) Prune(ctx context.Context, service string, keep int) error {
	return s.PruneIn(ctx, "", service, keep)
}

// PruneIn is Prune for (group, service).
func (s *SnapshotStore) PruneIn(ctx context.Context, group, service string, keep int) error {
	prot, err := s.protected(ctx)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM contract_snapshots WHERE grp = ? AND service = ? AND id NOT IN
		(SELECT id FROM contract_snapshots WHERE grp = ? AND service = ? ORDER BY id DESC LIMIT ?)`, group, service, group, service, keep)
	if err != nil {
		return err
	}
	var drop []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !prot[id] {
			drop = append(drop, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = s.deleteIDs(ctx, drop)
	return err
}

// HasWindow reports whether any service has a snapshot for the window.
func (s *SnapshotStore) HasWindow(ctx context.Context, w Window) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM contract_snapshots WHERE window_from_ms = ? AND window_to_ms = ?`,
		w.From.UnixMilli(), w.To.UnixMilli()).Scan(&n)
	return n > 0, err
}
