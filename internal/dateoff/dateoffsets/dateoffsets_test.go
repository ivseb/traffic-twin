package dateoffsets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/store"
)

func do(t *testing.T, h *Store, p *auth.Principal, method, path string, body any) (int, map[string]any) {
	t.Helper()
	rd := bytes.NewReader(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return rec.Code, v
}

func TestStoreAndAPI(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{DB: db, Audit: audit.New(db), Now: func() time.Time { return time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC) }}
	op := &auth.Principal{UserID: "u1", Username: "olga", Roles: []auth.Role{auth.RoleOperator}}
	pub := &auth.Principal{UserID: "u2", Username: "pia", Roles: []auth.Role{auth.RolePublisher}}

	if code, v := do(t, s, op, "PUT", Prefix+"/renewalDate", map[string]any{"group": "team-a", "min": "+30d", "max": "+365d"}); code != 200 || v["min"] != "+30d" || v["updated_by"] != "olga" {
		t.Fatalf("put: %d %v", code, v)
	}
	if code, v := do(t, s, op, "PUT", Prefix+"/renewalDate", map[string]any{"group": "team-a", "min": "+30d", "max": "-1d"}); code != 422 || v["code"] != "invalid_offset" {
		t.Fatalf("min after max: %d %v", code, v)
	}
	if code, _ := do(t, s, op, "PUT", Prefix+"/renewalDate", map[string]any{"group": "team-a", "min": "30 days", "max": "+1d"}); code != 422 {
		t.Fatalf("bad offset: %d", code)
	}
	if code, _ := do(t, s, pub, "PUT", Prefix+"/x", map[string]any{"group": "team-a", "min": "+1d", "max": "+2d"}); code != 403 {
		t.Fatalf("publisher may not write: %d", code)
	}
	code, v := do(t, s, pub, "GET", Prefix+"?group=team-a", nil)
	if code != 200 || len(v["offsets"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, v)
	}
	m, err := s.DateOffsetsIn(context.Background(), "team-a")
	if err != nil || m["renewalDate"].Max != "+365d" {
		t.Fatalf("in: %v %v", m, err)
	}
	if all, _ := s.DateOffsetsIn(context.Background(), ""); len(all) != 1 {
		t.Fatalf("all groups: %v", all)
	}
	if code, _ := do(t, s, op, "DELETE", Prefix+"/renewalDate?group=team-a", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := do(t, s, op, "DELETE", Prefix+"/renewalDate?group=team-a", nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
}
