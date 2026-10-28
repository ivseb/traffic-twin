package idformats

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/store"
)

func do(t *testing.T, h *Store, p *auth.Principal, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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

	code, v := do(t, s, op, "POST", Prefix+"/preview", map[string]any{"format": "NN-NNNNNN", "domain": "order"})
	if code != 200 || v["valid"] != true || len(v["preview"].([]any)) != 3 {
		t.Fatalf("preview: %d %v", code, v)
	}
	code, v = do(t, s, op, "POST", Prefix+"/preview", map[string]any{"format": "NN"})
	if code != 200 || v["valid"] != false || v["error"].(map[string]any)["code"] != "too_small" {
		t.Fatalf("invalid preview: %d %v", code, v)
	}
	code, v = do(t, s, op, "PUT", Prefix+"/order", map[string]any{"group": "shop", "format": "N?"})
	if code != 422 || v["code"] != "invalid_format" || v["details"].([]any)[0].(map[string]any)["code"] != "bad_char" {
		t.Fatalf("invalid format: %d %v", code, v)
	}
	if code, _ := do(t, s, pub, "PUT", Prefix+"/order", map[string]any{"group": "shop", "format": "NNNNNN"}); code != 403 {
		t.Fatalf("publisher wrote a format: %d", code)
	}
	code, v = do(t, s, op, "PUT", Prefix+"/order", map[string]any{"group": "shop", "format": "NN-NNNNNN"})
	if code != 200 || v["format"] != "NN-NNNNNN" || v["updated_by"] != "olga" {
		t.Fatalf("set: %d %v", code, v)
	}
	do(t, s, op, "PUT", Prefix+"/shipment", map[string]any{"group": "other", "format": "AAANNNN"})
	code, v = do(t, s, pub, "GET", Prefix+"?group=shop", nil)
	if code != 200 || len(v["formats"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, v)
	}
	got, err := s.IDFormatsIn(context.Background(), "shop")
	if err != nil || got["order"] != "NN-NNNNNN" || len(got) != 1 {
		t.Fatalf("IDFormatsIn(shop) = %v %v", got, err)
	}
	if all, _ := s.IDFormatsIn(context.Background(), ""); len(all) != 2 {
		t.Fatalf("IDFormatsIn(every group) = %v", all)
	}
	if code, _ := do(t, s, op, "DELETE", Prefix+"/order?group=shop", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := do(t, s, op, "DELETE", Prefix+"/order?group=shop", nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
	var acts []string
	_ = s.Audit.Iterate(context.Background(), 0, 100, func(e audit.Entry) error { acts = append(acts, e.Action); return nil })
	if j := strings.Join(acts, ","); !strings.Contains(j, "idformat.set") || !strings.Contains(j, "idformat.delete") {
		t.Fatalf("audit: %s", j)
	}
}
