package egress_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// latencyRig measures one POST /v1/shipments round trip (about 200 bytes each
// way) through one of three paths: straight to the upstream, through the
// proxy with capture off (no source), and through the proxy with capture on.
type latencyRig struct {
	url    string
	client *http.Client
	close  func()
}

const reqJSON = `{"orderId":"ord-1001","items":[{"sku":"sku-1","qty":2},{"sku":"sku-2","qty":1}],"note":"leave at the door"}`
const respJSON = `{"shipmentId":"shp-77","status":"CREATED","eta":"2026-10-24","items":[{"orderId":"ord-1001","status":"CREATED"}]}`

func newRig(tb testing.TB, mode string) *latencyRig {
	tb.Helper()
	up := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respJSON))
	}
	cl := &http.Client{Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 256}}
	if mode == "direct" {
		s := httptest.NewServer(http.HandlerFunc(up))
		return &latencyRig{url: s.URL + "/v1/shipments", client: cl, close: s.Close}
	}
	e := newEnv(tb, envOpts{plainUp: true, noSource: mode == "off"})
	e.setUpstream(up)
	if mode == "on" {
		e.waitCapturing()
	}
	return &latencyRig{url: e.front.URL + "/carrier/v1/shipments", client: cl, close: func() {}}
}

func (r *latencyRig) once() {
	req, _ := http.NewRequest("POST", r.url, strings.NewReader(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Customer-Id", "cust-1")
	resp, err := r.client.Do(req)
	if err != nil {
		panic(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func percentiles(d []time.Duration) (p50, p99 time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2], d[len(d)*99/100]
}

func BenchmarkProxy(b *testing.B) {
	for _, mode := range []string{"direct", "off", "on"} {
		b.Run(mode, func(b *testing.B) {
			r := newRig(b, mode)
			defer r.close()
			for i := 0; i < 200; i++ {
				r.once()
			}
			lat := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				r.once()
				lat = append(lat, time.Since(t0))
			}
			b.StopTimer()
			p50, p99 := percentiles(lat)
			b.ReportMetric(float64(p50.Microseconds()), "p50-us")
			b.ReportMetric(float64(p99.Microseconds()), "p99-us")
		})
	}
}

func BenchmarkProxyParallel(b *testing.B) {
	for _, mode := range []string{"direct", "off", "on"} {
		b.Run(mode, func(b *testing.B) {
			r := newRig(b, mode)
			defer r.close()
			b.SetParallelism(4)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r.once()
				}
			})
		})
	}
}

// TestAddedLatency reports the latency the proxy adds (p50 and p99) with
// capture on and off, against a direct call. The bounds are deliberately
// loose: it is a regression alarm, the real numbers are in the log.
func TestAddedLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement")
	}
	const n = 2000
	res := map[string][2]time.Duration{}
	for _, mode := range []string{"direct", "off", "on"} {
		r := newRig(t, mode)
		for i := 0; i < 200; i++ {
			r.once()
		}
		lat := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			t0 := time.Now()
			r.once()
			lat = append(lat, time.Since(t0))
		}
		p50, p99 := percentiles(lat)
		res[mode] = [2]time.Duration{p50, p99}
		r.close()
	}
	for _, m := range []string{"off", "on"} {
		t.Logf("capture %-3s: p50 %v (+%v)  p99 %v (+%v)   [direct p50 %v p99 %v]", m,
			res[m][0], res[m][0]-res["direct"][0], res[m][1], res[m][1]-res["direct"][1], res["direct"][0], res["direct"][1])
	}
	if add := res["on"][0] - res["direct"][0]; add > 25*time.Millisecond {
		t.Fatalf("capture adds %v at p50", add)
	}
}
