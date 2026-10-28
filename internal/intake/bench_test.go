package intake

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// benchEvents builds n realistic events (orders, order lookups, carrier
// calls) with distinct HMAC tokens, as a fleet of shops would send them.
func benchEvents(tb testing.TB, hash string, n int) []string {
	tb.Helper()
	tok := func(prefix string, i int) string { return fmt.Sprintf("tk1:k1:%s%0*d", prefix, 22-len(prefix), i) }
	out := make([]string, n)
	for i := range out {
		var s string
		switch i % 20 {
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11:
			s = orderPost(hash)
			s = strings.Replace(s, tokOrder1, tok("O", i), 1)
			s = strings.Replace(s, tokSubject, tok("S", i%5000), 1)
			s = strings.Replace(s, `"total":"num:50-100"`, fmt.Sprintf(`"total":"num:%s"`, []string{"0-50", "50-100", "100-250", ">=250"}[i%4]), 1)
		case 12, 13, 14, 15, 16:
			s = orderGet(hash)
			s = strings.Replace(s, tokOrder1, tok("O", i), 1)
			s = strings.Replace(s, `"keep:SHIPPED"`, fmt.Sprintf(`"keep:%s"`, []string{"SHIPPED", "PACKED", "DELIVERED"}[i%3]), 1)
		default:
			s = shipmentPost(hash)
			s = strings.Replace(s, tokOrder1, tok("O", i), 1)
			s = strings.Replace(s, tokShip1, tok("P", i), 1)
		}
		out[i] = s
	}
	return out
}

func BenchmarkDecodeEvent(b *testing.B) {
	hash := "sha256:" + strings.Repeat("a", 64)
	evs := benchEvents(b, hash, 100)
	var bytes int64
	for _, e := range evs {
		bytes += int64(len(e))
	}
	b.SetBytes(bytes / int64(len(evs)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := event.Decode([]byte(evs[i%len(evs)])); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

// BenchmarkCheckEvent measures decode plus every policy check and the
// cardinality monitors, without the database.
func BenchmarkCheckEvent(b *testing.B) {
	h := newHarness(b)
	evs := benchEvents(b, h.pol.Hash, 2000)
	src, _ := h.sources.LookupSource(testSource)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw := evs[i%len(evs)]
		ev, derr := event.Decode([]byte(raw))
		if derr != nil {
			b.Fatal(derr)
		}
		c := checkerPool.Get().(*checker)
		c.cfg, c.pol, c.src, c.ev = &h.in.cfg, h.pol, &src, ev
		if !c.run() {
			b.Fatal(c.rej)
		}
		h.in.monitors.observe(&c.obs, testNow)
		*c = checker{obs: c.obs, base: c.base[:0], prefix: c.prefix[:0], steps: c.steps[:0]}
		checkerPool.Put(c)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

// BenchmarkIngest is the end-to-end ingestion rate through IngestEvent:
// canonical decode, policy checks, monitors, queue, SQLite writer with the
// event table, its four indexes and the token index. Time includes waiting
// for the last event to be committed.
func BenchmarkIngest(b *testing.B) {
	type variant struct {
		workers int
		tokens  string // "keyguard": index and outbox; "index": index only; "none"
	}
	for _, v := range []variant{{1, "keyguard"}, {4, "keyguard"}, {1, "index"}, {1, "none"}} {
		workers := v.workers
		b.Run(fmt.Sprintf("workers=%d/tokens=%s", workers, v.tokens), func(b *testing.B) {
			opts := []harnessOpt{withConfig(func(c *Config) { c.QueueEvents = 20_000; c.IndexTokens = v.tokens != "none" })}
			if v.tokens != "keyguard" {
				opts = append(opts, withoutSink())
			}
			h := newHarness(b, opts...)
			evs := benchEvents(b, h.pol.Hash, 4000)
			ctx := context.Background()
			var next atomic.Int64
			b.ReportAllocs()
			b.ResetTimer()
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := int(next.Add(1)) - 1
						if i >= b.N {
							return
						}
						for {
							rej, err := h.in.IngestEvent(ctx, testSource, []byte(evs[i%len(evs)]))
							if err == ErrOverloaded {
								time.Sleep(200 * time.Microsecond)
								continue
							}
							if err != nil || rej.Reason != ReasonNone {
								b.Errorf("%v %v", err, rej)
								return
							}
							break
						}
					}
				}()
			}
			wg.Wait()
			if err := h.in.WaitIdle(ctx); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			if n, _ := h.in.Store().Count(ctx); n != int64(b.N) {
				b.Fatalf("stored %d of %d", n, b.N)
			}
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
		})
	}
}

// BenchmarkOTLPRequests is the same through the HTTP handler over mTLS,
// with requests of 100 events, uncompressed and gzip.
func BenchmarkOTLPRequests(b *testing.B) {
	for _, gzipOn := range []bool{false, true} {
		b.Run(fmt.Sprintf("gzip=%v", gzipOn), func(b *testing.B) {
			r := newTLSRig(b, withConfig(func(c *Config) { c.QueueEvents = 20_000; c.MaxInflightPerSource = 64 }))
			evs := benchEvents(b, r.h.pol.Hash, 4000)
			const per = 100
			var bodies [][]byte
			for i := 0; i+per <= len(evs); i += per {
				body := marshalOTLP(b, otlpFor(b, evs[i:i+per]...))
				if gzipOn {
					body = gz(body)
				}
				bodies = append(bodies, body)
			}
			c := r.client(r.sourceCert(b, testSource))
			hdr := map[string]string{}
			if gzipOn {
				hdr["Content-Encoding"] = "gzip"
			}
			var sent int
			b.ResetTimer()
			for sent < b.N {
				res := r.post(b, c, bodies[(sent/per)%len(bodies)], hdr)
				if res.code == 429 {
					time.Sleep(time.Millisecond)
					continue
				}
				if res.code != 200 || res.body != "{}\n" && res.body != "{}" {
					b.Fatalf("%d %s", res.code, res.body)
				}
				sent += per
			}
			if err := r.h.in.WaitIdle(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			b.ReportMetric(float64(sent)/b.Elapsed().Seconds(), "events/s")
		})
	}
}
