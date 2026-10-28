package miner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Operation kinds decided by a person (rules v1.6, C5): "this operation is
// a read" (or is not), per group and operation, from the console. The
// decision wins over the classification from the traffic (reads.go) in
// every later run. Stored in miner_op_kinds; every change is audited
// (rule.op_kind_set).

func init() {
	store.Register(store.Namespace{Name: "miner_op_kinds", Migrations: []store.Migration{
		{Version: 1, Name: "op_kinds", SQL: `
CREATE TABLE miner_op_kinds (
	grp TEXT NOT NULL,
	service TEXT NOT NULL,
	op TEXT NOT NULL,
	read INTEGER NOT NULL,
	set_by TEXT NOT NULL,
	set_at INTEGER NOT NULL,
	PRIMARY KEY (grp, service, op)
) STRICT;
`},
	}})
}

// OpKind is one decision of a person on the kind of an operation.
type OpKind struct {
	Group   string `json:"group"`
	Service string `json:"service"`
	Op      string `json:"op"`
	Read    bool   `json:"read"`
	SetBy   string `json:"set_by"`
	SetAt   string `json:"set_at"`
}

// OpKinds returns the decisions (group "" = all).
func (rp *Repo) OpKinds(ctx context.Context, group string) ([]OpKind, error) {
	q := `SELECT grp, service, op, read, set_by, set_at FROM miner_op_kinds`
	var args []any
	if group != "" {
		q += ` WHERE grp = ?`
		args = append(args, group)
	}
	rows, err := rp.db.QueryContext(ctx, q+` ORDER BY grp, service, op`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OpKind{}
	for rows.Next() {
		var k OpKind
		var read, at int64
		if err := rows.Scan(&k.Group, &k.Service, &k.Op, &read, &k.SetBy, &at); err != nil {
			return nil, err
		}
		k.Read, k.SetAt = read != 0, time.Unix(at, 0).UTC().Format(time.RFC3339)
		out = append(out, k)
	}
	return out, rows.Err()
}

// OpReads returns the decisions as MineOptions.OpReads takes them.
func (rp *Repo) OpReads(ctx context.Context) (map[string]map[string]bool, error) {
	ks, err := rp.OpKinds(ctx, "")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, k := range ks {
		if out[k.Group] == nil {
			out[k.Group] = map[string]bool{}
		}
		out[k.Group][k.Service+" "+k.Op] = k.Read
	}
	return out, nil
}

// SetOpKind stores a decision; read nil removes it (the traffic decides
// again).
func (rp *Repo) SetOpKind(ctx context.Context, group, service, op string, read *bool, by string, now time.Time) error {
	return rp.db.InTx(ctx, func(tx *sql.Tx) error {
		if read == nil {
			_, err := tx.ExecContext(ctx, `DELETE FROM miner_op_kinds WHERE grp = ? AND service = ? AND op = ?`, group, service, op)
			return err
		}
		v := 0
		if *read {
			v = 1
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO miner_op_kinds (grp, service, op, read, set_by, set_at) VALUES (?,?,?,?,?,?)
ON CONFLICT (grp, service, op) DO UPDATE SET read = excluded.read, set_by = excluded.set_by, set_at = excluded.set_at`,
			group, service, op, v, by, now.Unix())
		return err
	})
}

// lastReads returns the read decisions of the latest run.
func (rp *Repo) lastReads(ctx context.Context) ([]ReadDecision, error) {
	var s sql.NullString
	err := rp.db.QueryRowContext(ctx, `SELECT diagnostics FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) || !s.Valid {
		return []ReadDecision{}, nil
	}
	if err != nil {
		return nil, err
	}
	var d Diagnostics
	if err := json.Unmarshal([]byte(s.String), &d); err != nil {
		return nil, err
	}
	if d.Reads == nil {
		return []ReadDecision{}, nil
	}
	return d.Reads, nil
}

var reGroupParam = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// getOpKinds serves GET /api/v1/rules/op-kinds: the decisions of the
// persons and the classification of the latest run.
func (s *Service) getOpKinds(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	group := r.URL.Query().Get("group")
	if group != "" && !reGroupParam.MatchString(group) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid group")
		return
	}
	ks, err := s.repo.OpKinds(r.Context(), group)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	reads, err := s.repo.lastReads(r.Context())
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	auto := []ReadDecision{}
	for _, d := range reads {
		if d.Auto && (group == "" || d.Group == group) {
			auto = append(auto, d)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"decisions": ks, "auto": auto})
}

// putOpKind serves PUT /api/v1/rules/op-kinds: {group, service, op, read}
// with read true, false or null (back to the traffic). Rule reviewers only;
// audited as rule.op_kind_set. The next run uses it.
func (s *Service) putOpKind(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(w, r, true, "rule.op_kind_set", "")
	if !ok {
		return
	}
	var body struct {
		Group   string `json:"group"`
		Service string `json:"service"`
		Op      string `json:"op"`
		Read    *bool  `json:"read"`
	}
	if err := httpx.DecodeJSON(w, r, maxBody, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
		return
	}
	if (body.Group != "" && !reGroupParam.MatchString(body.Group)) || !reService.MatchString(body.Service) || !reOp.MatchString(body.Op) || len(body.Op) > 512 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "group, service or op is not valid")
		return
	}
	target := audit.Target{Type: "operation", ID: audit.SafeValue(body.Service + " " + body.Op)}
	if err := s.repo.SetOpKind(r.Context(), body.Group, body.Service, body.Op, body.Read, p.UserID, s.now()); err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.op_kind_set", Target: target,
			Outcome: audit.Failure, Reason: "store", RequestID: httpx.RequestID(r.Context())})
		s.writeRepoError(w, err)
		return
	}
	kind := "auto"
	if body.Read != nil {
		kind = "write"
		if *body.Read {
			kind = "read"
		}
	}
	det := map[string]string{"kind": kind}
	if body.Group != "" {
		det["group"] = audit.SafeValue(body.Group)
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.op_kind_set", Target: target,
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, det)})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"group": body.Group, "service": body.Service, "op": body.Op,
		"read": body.Read, "kind": kind, "applies": "next_run", "set_by": p.UserID, "set_at": s.now().UTC().Format(time.RFC3339)})
}
