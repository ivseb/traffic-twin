package intake

import (
	"strconv"
	"strings"
	"testing"
)

const vbTestSource = "src-TEST0001"

func vbBatch(timeNano string, eventTS string) []byte {
	ev := `{"dir":"inbound","latency_ms":12,"op":"GET /ping","policy":{"hash":"sha256:` + strings.Repeat("0", 64) + `","id":"p-shop","version":1},` +
		`"req":{"path":"/ping","size":"l8"},"resp":{"size":"l8"},"route_source":"policy","sampled_by":"subject","schema":"tt.http.exchange/v1",` +
		`"service":"svc","source":{"id":"` + vbTestSource + `","kind":"egress","version":"0.1.0"},"status":200,"ts":"` + eventTS + `"}`
	return []byte(`{"resourceLogs":[{"resource":{"attributes":[` +
		`{"key":"service.name","value":{"stringValue":"svc"}},{"key":"tt.source.kind","value":{"stringValue":"egress"}},` +
		`{"key":"tt.source.version","value":{"stringValue":"0.1.0"}},{"key":"tt.source.id","value":{"stringValue":"` + vbTestSource + `"}}]},` +
		`"scopeLogs":[{"scope":{"name":"traffic-twin","version":"0.1.0"},"logRecords":[{"timeUnixNano":"` + timeNano + `","observedTimeUnixNano":"1792404000500000000",` +
		`"severityNumber":9,"severityText":"INFO","eventName":"tt.http.exchange","attributes":[` +
		`{"key":"tt.schema","value":{"stringValue":"tt.http.exchange/v1"}},{"key":"tt.policy.hash","value":{"stringValue":"sha256:` + strings.Repeat("0", 64) + `"}}],` +
		`"body":{"stringValue":` + strconv.Quote(ev) + `}}]}]}]}`)
}

func TestValidateBatchChecksTimeUnixNano(t *testing.T) {
	src := SourceInfo{ID: vbTestSource, ServiceName: "svc"}
	ok, rej, err := ValidateBatch(vbBatch("1792404000412000000", "2026-10-19T10:00:00.412Z"), src)
	if err != nil || len(ok) != 1 || len(rej) != 0 {
		t.Fatalf("a consistent batch: %v %v %v", ok, rej, err)
	}
	// nanosecond precision where the event carries milliseconds: the lab's P1
	ok, rej, err = ValidateBatch(vbBatch("1792404000412345678", "2026-10-19T10:00:00.412Z"), src)
	if err != nil || len(ok) != 0 || len(rej) != 1 || rej[0].Reason != ReasonResourceMismatch || !strings.Contains(rej[0].Detail, "timeUnixNano") {
		t.Fatalf("nanosecond timeUnixNano: %v %v %v", ok, rej, err)
	}
	// other certificate identity, other service
	if _, rej, _ := ValidateBatch(vbBatch("1792404000412000000", "2026-10-19T10:00:00.412Z"), SourceInfo{ID: "src-OTHER"}); len(rej) != 1 || rej[0].Reason != ReasonSourceMismatch {
		t.Fatalf("other source: %v", rej)
	}
	if _, rej, _ := ValidateBatch(vbBatch("1792404000412000000", "2026-10-19T10:00:00.412Z"), SourceInfo{ID: vbTestSource, ServiceName: "billing"}); len(rej) != 1 {
		t.Fatalf("other service: %v", rej)
	}
	if _, _, err := ValidateBatch([]byte(`{"resourceLogs":1}`), src); err == nil {
		t.Fatal("garbage must be a bad batch")
	}
	if _, _, err := ValidateBatch([]byte(`{"resourceLogs":[],"extra":true}`), src); err == nil {
		t.Fatal("unknown fields must be refused")
	}
}
