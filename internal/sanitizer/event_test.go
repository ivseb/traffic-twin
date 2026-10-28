package sanitizer

import (
	"strings"
	"testing"
	"time"
)

func TestBuildEvent(t *testing.T) {
	e := engine(t, `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},
	 "global":{"request":{"headers":{"content-type":"keep"}}}}`)
	ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"), Status: 201,
		ReqHeaders: hdr("Content-Type", "application/json"), ReqBody: []byte(`{"qty":2}`)}
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d"
	m := EventMeta{
		PolicyID: "p-shop", PolicyVersion: 7, PolicyHash: hash,
		SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: "src-01JB7Q2W",
		TS: time.Date(2026, 10, 19, 10, 0, 0, 412_999_999, time.UTC), LatencyMS: 184, Status: 201,
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7",
	}
	got, err := BuildEvent(m, out)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"dir":"inbound","latency_ms":184,"op":"POST /{drop:str:l8}","policy":{"hash":"` + hash + `","id":"p-shop","version":7},` +
		`"req":{"body":{"qty":"drop:int"},"ct":"application/json","headers":{"content-type":["keep:application/json"]},"path":"/{drop:str:l8}","size":"l32"},` +
		`"resp":{"size":"l8"},"route_source":"raw","sampled_by":"random","schema":"tt.http.exchange/v1","service":"shop-api",` +
		`"source":{"id":"src-01JB7Q2W","kind":"sdk-go","version":"0.1.0"},"span_id":"00f067aa0ba902b7","status":201,` +
		`"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","ts":"2026-10-19T10:00:00.412Z"}`
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	bad := []func(m *EventMeta){
		func(m *EventMeta) { m.PolicyHash = "sha256:XYZ" },
		func(m *EventMeta) { m.SourceKind = "sdk-rust" },
		func(m *EventMeta) { m.SourceVersion = "1.0" },
		func(m *EventMeta) { m.SourceID = "src_1" },
		func(m *EventMeta) { m.Status = 99 },
		func(m *EventMeta) { m.NetError = "timeout" }, // resp present
		func(m *EventMeta) { m.TraceID = strings.ToUpper(m.TraceID) },

		func(m *EventMeta) { m.LatencyMS = -1 },
		func(m *EventMeta) { m.TS = time.Time{} },
	}
	for i, f := range bad {
		mm := m
		f(&mm)
		if _, err := BuildEvent(mm, out); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// Network error: no status, no resp.
	ex.Status, ex.NetError = 0, "reset"
	out, _ = e.Sanitize(ex, t0, ByRandom)
	m.Status, m.NetError = 0, "reset"
	got, err = BuildEvent(m, out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), `"resp"`) || strings.Contains(string(got), `"status"`) || !strings.Contains(string(got), `"net_error":"reset"`) {
		t.Errorf("net error event: %s", got)
	}
}
