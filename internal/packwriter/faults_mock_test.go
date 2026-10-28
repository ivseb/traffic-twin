package packwriter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Usability test 3: `tt mock --faults observed` answered 300 × 201 to a
// catalog whose contract showed 5 % 409 "no copies left", because faults.json
// only took server errors. The observed 409 must reach faults.json and the
// mock must replay it per endpoint at that frequency, with the session seed.
func TestObservedConflictReachesTheMock(t *testing.T) {
	spec := packtest.DemoSpec()
	now := time.Date(2026, 10, 24, 19, 0, 0, 0, time.UTC)
	var evs memEvents
	for i := 0; i < 2000; i++ {
		st := 202
		switch {
		case i%20 == 7: // 5 %
			st = 409
		case i%100 == 3: // 1 %
			st = 503
		}
		evs = append(evs, &intake.StoredEvent{Event: &event.Event{Dir: event.Outbound, Service: "shipping-ext", Op: "POST /v1/shipments",
			Status: st, Time: now.Add(-time.Duration(i) * time.Second), LatencyMS: 40}})
	}
	contracts := []world.Contract{{Service: "shipping-ext", Doc: spec.Files["contracts/shipping-ext.openapi.json"]}}
	f, err := (&EventFaults{Events: evs, Now: func() time.Time { return now }}).Faults(context.Background(), contracts, 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.file(func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"status":409`) || !strings.Contains(string(b), `"example":"shipment-exists"`) {
		t.Fatalf("faults.json without the observed 409: %s", b)
	}
	spec.Files["faults.json"] = b
	built, err := packtest.Build(filepath.Join(t.TempDir(), "pack"), spec)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mock.New(mock.Config{Pack: built.Dir, GatePubKeys: built.Keys, Faults: "observed", Latency: mock.LatencyOff, MaxPackAge: -1})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	do := func(method, path, sid string, body any) (int, []byte) {
		t.Helper()
		bb, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(bb))
		req.Header.Set("Content-Type", "application/json")
		if sid != "" {
			req.Header.Set("X-TT-Session", sid)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		return res.StatusCode, out
	}
	run := func(seed int) (map[int]int, string) {
		code, body := do("POST", "/__tt/sessions", "", map[string]any{"seed": seed})
		if code != 201 {
			t.Fatalf("session: %d %s", code, body)
		}
		var s struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &s)
		n := map[int]int{}
		var seq strings.Builder
		conflict := ""
		for i := 0; i < 2000; i++ {
			code, body := do("POST", "/__svc/shipping-ext/v1/shipments", s.ID, map[string]any{
				"orderId": "ORD-SYN-0099", "service": "STANDARD", "parcels": 1,
				"recipient": map[string]any{"fullName": "Anna Rossi", "email": "anna.rossi@example.com"},
				"address":   map[string]any{"line1": "Via Finta 1", "city": "Torino", "postcode": "10100", "country": "IT"}})
			n[code]++
			seq.WriteString(http.StatusText(code)[:1])
			if code == 409 && conflict == "" {
				conflict = string(body)
			}
		}
		if !strings.Contains(conflict, "SHIPMENT_EXISTS") {
			t.Errorf("409 body is not the contract example: %s", conflict)
		}
		return n, seq.String()
	}
	n, a := run(7)
	if n[409] < 70 || n[409] > 130 { // 5 % of 2000 = 100
		t.Errorf("409: %d of 2000, want about 100 (%v)", n[409], n)
	}
	if n[503] < 8 || n[503] > 35 { // 1 % of 2000 = 20
		t.Errorf("503: %d of 2000, want about 20 (%v)", n[503], n)
	}
	if n[202]+n[409]+n[503] != 2000 {
		t.Errorf("statuses: %v", n)
	}
	if _, b := run(7); b != a {
		t.Error("the same seed gave another fault sequence")
	}
}
