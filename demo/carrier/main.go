// Command carrier is a fake external shipping carrier ("carrier.example")
// whose behaviour is fully driven by a known ground truth (truth.json).
//
//	POST /v1/shipments            register a shipment for an order (202, PENDING)
//	GET  /v1/shipments?orderId=   list visible shipments of an order
//	GET  /__truth                 ground truth config + exact counts produced
//	GET  /__health                liveness (not counted, no faults)
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/demo/internal/simclock"
)

func main() {
	probe := flag.String("probe", "", "GET this URL and exit 0 on HTTP 200 (for healthchecks)")
	flag.Parse()
	if *probe != "" {
		resp, err := http.Get(*probe)
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	truth, err := loadTruth()
	if err != nil {
		log.Fatal(err)
	}
	clock, err := simclock.FromEnv()
	if err != nil {
		log.Fatal(err)
	}
	store := NewStore(truth, clock)
	go func() {
		for range time.Tick(20 * time.Millisecond) {
			store.Advance()
		}
	}()

	srv := &server{truth: truth, clock: clock, store: store,
		rng: rand.New(rand.NewPCG(truth.Seed, 0xC0FFEE)), metrics: newMetrics()}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/shipments", srv.wrap(srv.createShipment))
	mux.Handle("GET /v1/shipments", srv.wrap(srv.listShipments))
	mux.HandleFunc("GET /__truth", srv.groundTruth)
	mux.HandleFunc("GET /__health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := ":" + envOr("PORT", "8080")
	log.Printf("carrier listening on %s (seed=%d, time_scale=%g, sim_now=%s, next_batch=%s)",
		addr, truth.Seed, clock.Scale, clock.Now().Format(time.RFC3339), store.nextBatch.Format(time.RFC3339))
	log.Fatal(http.ListenAndServe(addr, mux))
}

type server struct {
	truth   *Truth
	clock   *simclock.Clock
	store   *Store
	rngMu   sync.Mutex
	rng     *rand.Rand
	metrics *metrics
}

// wrap injects the ground-truth latency and fault rate, and counts the
// status actually returned for each operation.
func (s *server) wrap(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := r.Pattern
		dist := s.truth.Latency[op]
		s.rngMu.Lock()
		fault := s.rng.Float64() < s.truth.Faults.UnavailableP
		ms := int(math.Round(dist.MedianMs * math.Exp(dist.Sigma*s.rng.NormFloat64())))
		s.rngMu.Unlock()
		if dist.MaxMs > 0 && ms > dist.MaxMs {
			ms = dist.MaxMs
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		if fault {
			writeError(rec, s.truth.Faults.Status, s.truth.Faults.Code, "carrier temporarily unavailable, retry later")
		} else {
			h(rec, r)
		}
		s.metrics.observe(op, rec.status, ms)
	})
}

type shipmentRequest struct {
	OrderID   string `json:"orderId"`
	Service   string `json:"service"`
	Parcels   int    `json:"parcels"`
	Recipient *struct {
		FullName string `json:"fullName"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
	} `json:"recipient"`
	Address *struct {
		Line1    string `json:"line1"`
		Line2    string `json:"line2"`
		City     string `json:"city"`
		Postcode string `json:"postcode"`
		Country  string `json:"country"`
	} `json:"address"`
}

func (s *server) createShipment(w http.ResponseWriter, r *http.Request) {
	var req shipmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "body is not valid JSON")
		return
	}
	switch {
	case req.OrderID == "":
		writeFieldError(w, "orderId", "orderId is required")
		return
	case req.Recipient == nil || req.Recipient.FullName == "":
		writeFieldError(w, "recipient.fullName", "recipient.fullName is required")
		return
	case req.Address == nil || req.Address.Line1 == "" || req.Address.City == "" ||
		req.Address.Postcode == "" || req.Address.Country == "":
		writeFieldError(w, "address", "address.line1, city, postcode and country are required")
		return
	}
	if req.Service == "" {
		req.Service = "STANDARD"
	}
	if req.Service != "STANDARD" && req.Service != "EXPRESS" {
		writeFieldError(w, "service", "service must be STANDARD or EXPRESS")
		return
	}
	sh, err := s.store.Create(req.OrderID, req.Service)
	var dup ErrDuplicate
	if errors.As(err, &dup) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "SHIPMENT_EXISTS", "message": "a shipment already exists for this order", "shipmentId": dup.ShipmentID}})
		return
	}
	w.Header().Set("Location", "/v1/shipments?orderId="+sh.OrderID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"shipmentId": sh.ID,
		"orderId":    sh.OrderID,
		"status":     sh.Status,
		"service":    sh.Service,
		"createdAt":  sh.CreatedAt.Format(time.RFC3339),
	})
}

func (s *server) listShipments(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("orderId")
	if orderID == "" {
		writeFieldError(w, "orderId", "query parameter orderId is required")
		return
	}
	items := []map[string]any{}
	for _, sh := range s.store.FindByOrder(orderID) {
		it := map[string]any{
			"shipmentId": sh.ID,
			"orderId":    sh.OrderID,
			"status":     sh.Status,
			"service":    sh.Service,
			"updatedAt":  sh.UpdatedAt.Format(time.RFC3339),
		}
		if sh.ETA != nil {
			it["eta"] = sh.ETA.Format(time.RFC3339)
		}
		if sh.Status == Cancelled {
			it["cancelReason"] = sh.CancelReason
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) groundTruth(w http.ResponseWriter, _ *http.Request) {
	counts := s.store.Snapshot()
	counts["requests"], counts["latency_ms"] = s.metrics.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "carrier.example",
		"note":    "config is the ground truth; counts are exact counts of what was produced, not estimates",
		"config":  s.truth,
		"clock": map[string]any{
			"time_scale": s.clock.Scale,
			"sim_epoch":  s.clock.Epoch,
			"anchor":     s.clock.Anchor,
			"sim_now":    s.clock.Now(),
		},
		"counts": counts,
	})
}

// metrics counts statuses per operation and keeps an exact 1 ms latency
// histogram of the latency that was injected.
type metrics struct {
	mu       sync.Mutex
	statuses map[string]map[int]int
	hist     map[string][]int
}

func newMetrics() *metrics {
	return &metrics{statuses: map[string]map[int]int{}, hist: map[string][]int{}}
}

func (m *metrics) observe(op string, status, ms int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statuses[op] == nil {
		m.statuses[op] = map[int]int{}
	}
	m.statuses[op][status]++
	h := m.hist[op]
	for len(h) <= ms {
		h = append(h, 0)
	}
	h[ms]++
	m.hist[op] = h
}

func (m *metrics) snapshot() (map[string]map[int]int, map[string]map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := map[string]map[int]int{}
	for op, byStatus := range m.statuses {
		st[op] = map[int]int{}
		for k, v := range byStatus {
			st[op][k] = v
		}
	}
	lat := map[string]map[string]int{}
	for op, h := range m.hist {
		n := 0
		for _, c := range h {
			n += c
		}
		lat[op] = map[string]int{"n": n, "p50": quantile(h, n, 0.50), "p95": quantile(h, n, 0.95), "p99": quantile(h, n, 0.99)}
	}
	return st, lat
}

func quantile(h []int, n int, q float64) int {
	target := int(math.Ceil(q * float64(n)))
	acc := 0
	for ms, c := range h {
		acc += c
		if acc >= target && c > 0 {
			return ms
		}
	}
	return len(h) - 1
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func writeFieldError(w http.ResponseWriter, field, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{
		"code": "INVALID_REQUEST", "field": field, "message": msg}})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
