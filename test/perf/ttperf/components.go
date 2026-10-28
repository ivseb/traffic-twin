package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack"
)

func fakeToken(i int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("perf-token-%d", i)))
	return "tk1:" + core.DevHMACKid + ":" + base64.RawURLEncoding.EncodeToString(s[:16])[:22]
}

// benchKeyguard feeds the real-token Bloom filter like the intake outbox
// does (every batch re-sends the identifiers seen in it, so most tokens are
// repeats), then matches a large candidate set and snapshots the filters.
func (h *harness) benchKeyguard(ctx context.Context) {
	kg := h.kg.Service
	unique := max(1, h.sc.KGTokens/5) // each identifier seen five times
	const batch = 50000
	runtime.GC()
	base := heapNow()
	h.job("keyguard.add_tokens", func() (map[string]any, error) {
		toks := make([]string, 0, batch)
		sent := 0
		for i := 0; sent < h.sc.KGTokens; i++ {
			toks = append(toks, fakeToken(i%unique))
			sent++
			if len(toks) == batch || sent == h.sc.KGTokens {
				if err := kg.AddTokens(ctx, "2026-10", toks); err != nil {
					return nil, err
				}
				toks = toks[:0]
			}
		}
		runtime.GC()
		segs := 0
		if st, err := kg.Status(ctx); err == nil {
			for _, f := range st.Filters {
				segs += f.Segments
			}
		}
		return map[string]any{"tokens_sent": sent, "unique_tokens": unique, "segments": segs,
			"filter_heap_mb": float64(int64(heapNow())-int64(base)) / (1 << 20)}, nil
	})
	var ver int64
	{
		var arr []map[string]any
		if h.admin.json(200, "GET", "/api/v1/fleet/policies", nil, &arr) == nil {
			for _, p := range arr {
				if p["policy_id"] == "p-demo" && p["status"] == "active" {
					if v, ok := p["version"].(float64); ok {
						ver = int64(v)
					}
				}
			}
		}
	}
	h.job("keyguard.match_10k", func() (map[string]any, error) {
		cands := make([]keyguard.Candidate, 10000)
		for i := range cands {
			cands[i] = keyguard.Candidate{Value: fmt.Sprintf("ORD-%08d", i)}
		}
		res, err := kg.Match(ctx, []keyguard.PolicyRef{{ID: "p-demo", Version: ver}}, cands)
		if err != nil {
			return nil, err
		}
		return map[string]any{"positives": res.Positives}, nil
	})
	h.job("keyguard.snapshot", func() (map[string]any, error) {
		err := kg.Snapshot(ctx)
		var sz int64
		if fi, e := os.Stat(filepath.Join(h.dir, "keyguard", "tt-keyguard.db")); e == nil {
			sz = fi.Size()
		}
		return map[string]any{"keyguard_db_mb": mb(sz)}, err
	})
}

// benchMock serves the real pack with many sessions, fills their journals
// and advances one clock by a year.
func (h *harness) benchMock(ctx context.Context) {
	if h.ids["pack"] == "" {
		return
	}
	code, archive, _, err := h.admin.do("GET", "/api/v1/packs/"+h.ids["pack"]+"/download", nil)
	if err != nil || code != 200 {
		h.rep.Jobs = append(h.rep.Jobs, &JobStats{Name: "mock.sessions", Error: fmt.Sprintf("download %d %v", code, err)})
		return
	}
	pks, err := h.c.Keyguard().PublicKeys(ctx)
	if err != nil {
		return
	}
	keys, err := pack.ParseKeySet(pks.GatePubKeys())
	if err != nil {
		return
	}
	pf := filepath.Join(h.dir, "perf.ttpack")
	if err := os.WriteFile(pf, archive, 0o600); err != nil {
		return
	}
	pk, err := pack.Load(pf, pack.Options{Keys: keys})
	if err != nil {
		h.rep.Jobs = append(h.rep.Jobs, &JobStats{Name: "mock.sessions", Error: err.Error()})
		return
	}
	m, err := mock.New(mock.Config{Pack: pf, Keys: keys, Latency: "off", Faults: "off", MaxSessions: h.sc.MockSessions + 10})
	if err != nil {
		h.rep.Jobs = append(h.rep.Jobs, &JobStats{Name: "mock.sessions", Error: err.Error()})
		return
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	hc := &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	call := func(method, path string, body any, sess string) (int, []byte, error) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if sess != "" {
			req.Header.Set("X-TT-Session", sess)
			req.Header.Set("Authorization", "Bearer synthetic-test-token")
			req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, nil
	}
	order := map[string]any{"items": []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1}}, "email": "anna.rossi@example.com",
		"shippingAddress": map[string]any{"fullName": "Anna Rossi", "line1": "Via Inventata 2", "city": "Roma", "postcode": "00100", "country": "IT"}}
	var sids []string
	const perSession = 50
	h.job("mock.sessions", func() (map[string]any, error) {
		for i := 0; i < h.sc.MockSessions; i++ {
			cust := pk.World.Customers[i%len(pk.World.Customers)].ID
			code, b, err := call("POST", "/__tt/sessions", map[string]any{"seed": i, "customer": cust}, "")
			if err != nil {
				return nil, err
			}
			if code != 201 {
				return nil, fmt.Errorf("session = %d: %.200s", code, b)
			}
			var s struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(b, &s)
			sids = append(sids, s.ID)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		var lat []float64
		sem := make(chan struct{}, 16)
		for _, sid := range sids {
			wg.Add(1)
			sem <- struct{}{}
			go func(sid string) {
				defer wg.Done()
				defer func() { <-sem }()
				for j := 0; j < perSession; j++ {
					t0 := time.Now()
					_, _, _ = call("POST", "/__svc/shop-api/orders", order, sid)
					d := float64(time.Since(t0).Microseconds()) / 1000
					mu.Lock()
					lat = append(lat, d)
					mu.Unlock()
				}
			}(sid)
		}
		wg.Wait()
		runtime.GC()
		return map[string]any{"sessions": len(sids), "requests": len(lat), "p50_ms": percentile(lat, .5), "p95_ms": percentile(lat, .95),
			"heap_after_gc_mb": float64(heapNow()) / (1 << 20)}, nil
	})
	if len(sids) == 0 {
		return
	}
	h.job("mock.journal", func() (map[string]any, error) {
		code, b, err := call("GET", "/__tt/sessions/"+sids[0]+"/journal", nil, "")
		if err != nil || code != 200 {
			return nil, fmt.Errorf("journal %d %v", code, err)
		}
		return map[string]any{"bytes": len(b)}, nil
	})
	h.job("mock.clock_advance_1y", func() (map[string]any, error) {
		code, b, err := call("POST", "/__tt/sessions/"+sids[0]+"/clock/advance", map[string]any{"by": "365d"}, "")
		if err != nil {
			return nil, err
		}
		if code != 200 {
			return nil, fmt.Errorf("advance = %d: %.200s", code, b)
		}
		return map[string]any{"response_bytes": len(b), "applied": strings.Count(string(b), `"entity"`)}, nil
	})
	for _, s := range sids {
		_, _, _ = call("DELETE", "/__tt/sessions/"+s, nil, "")
	}
}
