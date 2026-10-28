package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// The tracing driver wraps the pure-Go sqlite driver: every statement is
// recorded with its count and its cumulative time (from the call to the end
// of the iteration of its rows), so that the harness can list the queries
// that the product really runs and EXPLAIN each of them on the dataset.

const tracedDriver = "sqlite-ttperf"

type queryStat struct {
	SQL     string        `json:"sql"`
	Count   int64         `json:"count"`
	Total   time.Duration `json:"total_ns"`
	Max     time.Duration `json:"max_ns"`
	Rows    int64         `json:"rows"`
	Plan    []string      `json:"plan,omitempty"`
	Flags   []string      `json:"flags,omitempty"`
	example []driver.NamedValue
}

type tracer struct {
	mu    sync.Mutex
	stats map[string]*queryStat
	on    bool
}

var trace = &tracer{stats: map[string]*queryStat{}}

var wsRe = regexp.MustCompile(`\s+`)

// normalize folds whitespace and the expanded VALUES lists of multi-row
// inserts so that one statement shape is one entry.
func normalize(q string) string {
	q = strings.TrimSpace(wsRe.ReplaceAllString(q, " "))
	if i := strings.Index(q, "VALUES (?,?,?,?,?),"); i > 0 {
		q = q[:i] + "VALUES (?,?,?,?,?),..."
	}
	return q
}

func (t *tracer) record(q string, args []driver.NamedValue, d time.Duration, rows int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.on {
		return
	}
	k := normalize(q)
	s := t.stats[k]
	if s == nil {
		s = &queryStat{SQL: k}
		t.stats[k] = s
	}
	s.Count++
	s.Total += d
	s.Rows += rows
	if d > s.Max {
		s.Max = d
		s.example = append([]driver.NamedValue(nil), args...)
	}
}

func (t *tracer) setOn(on bool) { t.mu.Lock(); t.on = on; t.mu.Unlock() }

func (t *tracer) snapshot() []*queryStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*queryStat, 0, len(t.stats))
	for _, s := range t.stats {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// explain runs EXPLAIN QUERY PLAN for every traced statement (with the
// arguments of its slowest call) and flags full scans and temporary sorts.
func (t *tracer) explain(ctx context.Context, db *sql.DB) {
	for _, s := range t.snapshot() {
		up := strings.ToUpper(s.SQL)
		if strings.HasPrefix(up, "PRAGMA") || strings.HasPrefix(up, "BEGIN") || strings.HasPrefix(up, "COMMIT") ||
			strings.HasPrefix(up, "CREATE") || strings.HasPrefix(up, "ALTER") || strings.HasPrefix(up, "ROLLBACK") {
			continue
		}
		args := make([]any, len(s.example))
		for i, a := range s.example {
			args[i] = a.Value
		}
		q := s.SQL
		if strings.HasSuffix(q, "VALUES (?,?,?,?,?),...") {
			q = strings.TrimSuffix(q, ",...")
			if len(args) > 5 {
				args = args[:5]
			}
		}
		rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			s.Plan = []string{"(explain failed: " + err.Error() + ")"}
			continue
		}
		var plan []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if rows.Scan(&id, &parent, &notused, &detail) == nil {
				plan = append(plan, detail)
			}
		}
		rows.Close()
		s.Plan = plan
		s.Flags = planFlags(plan)
	}
}

func planFlags(plan []string) []string {
	var f []string
	for _, p := range plan {
		switch {
		case strings.HasPrefix(p, "SCAN ") && !strings.Contains(p, "COVERING INDEX") && !strings.Contains(p, "USING INDEX") &&
			!strings.Contains(p, "CONSTANT ROW") && !strings.HasPrefix(p, "SCAN json_each"):
			f = append(f, "full-scan: "+p)
		case strings.Contains(p, "USE TEMP B-TREE"):
			f = append(f, "temp-sort: "+p)
		}
	}
	return f
}

// ---- driver wrapper ----

type tDriver struct{ inner driver.Driver }

func registerTracedDriver() error {
	db, err := sql.Open("sqlite", "")
	if err != nil {
		return err
	}
	inner := db.Driver()
	_ = db.Close()
	sql.Register(tracedDriver, tDriver{inner})
	return nil
}

func (d tDriver) Open(name string) (driver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &tConn{c}, nil
}

type tConn struct{ driver.Conn }

func (c *tConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin() //nolint:staticcheck // fallback of the interface
}

func (c *tConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	var st driver.Stmt
	var err error
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		st, err = p.PrepareContext(ctx, q)
	} else {
		st, err = c.Conn.Prepare(q)
	}
	if err != nil {
		return nil, err
	}
	return &tStmt{Stmt: st, q: q}, nil
}

func (c *tConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	t0 := time.Now()
	r, err := e.ExecContext(ctx, q, args)
	trace.record(q, args, time.Since(t0), 0)
	return r, err
}

func (c *tConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	qc, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	t0 := time.Now()
	r, err := qc.QueryContext(ctx, q, args)
	if err != nil {
		trace.record(q, args, time.Since(t0), 0)
		return nil, err
	}
	return &tRows{Rows: r, q: q, args: args, t0: t0}, nil
}

func (c *tConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *tConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *tConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (c *tConn) CheckNamedValue(nv *driver.NamedValue) error {
	if ch, ok := c.Conn.(driver.NamedValueChecker); ok {
		return ch.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

type tStmt struct {
	driver.Stmt
	q string
}

func (s *tStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	t0 := time.Now()
	var r driver.Result
	var err error
	if e, ok := s.Stmt.(driver.StmtExecContext); ok {
		r, err = e.ExecContext(ctx, args)
	} else {
		err = errors.New("ttperf: statement without ExecContext")
	}
	trace.record(s.q, args, time.Since(t0), 0)
	return r, err
}

func (s *tStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	t0 := time.Now()
	q, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("ttperf: statement without QueryContext")
	}
	r, err := q.QueryContext(ctx, args)
	if err != nil {
		trace.record(s.q, args, time.Since(t0), 0)
		return nil, err
	}
	return &tRows{Rows: r, q: s.q, args: args, t0: t0}, nil
}

func (s *tStmt) CheckNamedValue(nv *driver.NamedValue) error {
	if ch, ok := s.Stmt.(driver.NamedValueChecker); ok {
		return ch.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

type tRows struct {
	driver.Rows
	q    string
	args []driver.NamedValue
	t0   time.Time
	n    int64
	done bool
}

func (r *tRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		r.n++
	} else if err == io.EOF {
		r.finish()
	}
	return err
}

func (r *tRows) finish() {
	if !r.done {
		r.done = true
		trace.record(r.q, r.args, time.Since(r.t0), r.n)
	}
}

func (r *tRows) Close() error {
	r.finish()
	return r.Rows.Close()
}

// ColumnTypeDatabaseTypeName etc. are not needed by the product.
