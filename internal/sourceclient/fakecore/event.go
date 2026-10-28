package fakecore

import (
	"fmt"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// SampleEvent builds a canonical tt.http.exchange/v1 event that the real
// intake accepts for the given source (the fake runs the intake's stateless
// checks on every batch, so tests must not send placeholder bodies). The
// event time is truncated to the millisecond, as sources do.
func SampleEvent(sourceID, kind, version string, ts time.Time) sourceclient.Event {
	ts = ts.UTC().Truncate(time.Millisecond)
	hash := "sha256:" + strings.Repeat("0", 64)
	body := fmt.Sprintf(`{"dir":"inbound","latency_ms":12,"op":"GET /ping","policy":{"hash":%q,"id":"p-shop","version":1},`+
		`"req":{"path":"/ping","size":"l8"},"resp":{"size":"l8"},"route_source":"policy","sampled_by":"subject","schema":"tt.http.exchange/v1",`+
		`"service":"egress-svc","source":{"id":%q,"kind":%q,"version":%q},"status":200,"ts":%q}`,
		hash, sourceID, kind, version, ts.Format("2006-01-02T15:04:05.000Z"))
	return sourceclient.Event{JSON: []byte(body), TS: ts, PolicyHash: hash}
}
