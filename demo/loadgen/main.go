// Command loadgen plays N fake customers against the shop. Each customer has
// a behaviour profile and, after ordering, polls its shipment periodically
// like a real client app would, until the shipment is final or it gives up.
//
// Pacing is expressed in simulated time and converted with the shared clock,
// so TIME_SCALE accelerates customers and carrier alike.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ivseb/traffic-twin/demo/internal/simclock"
)

const day = 24 * time.Hour

// profile is a behaviour archetype. Means are in simulated time.
type profile struct {
	Name        string
	Weight      float64
	OrderEvery  time.Duration // mean time between orders; 0 = never orders
	BrowseEvery time.Duration // mean time between "my orders" visits
}

var profiles = []profile{
	{"frequent_buyer", 0.15, 1 * day, 12 * time.Hour},
	{"occasional_buyer", 0.45, 6 * day, 2 * day},
	{"browser_only", 0.40, 0, 12 * time.Hour},
}

// Per-request behaviour probabilities (documented in GROUND_TRUTH.md).
const (
	pInvalidOrder  = 0.03 // POST /orders with a broken body -> 400
	pKeyReuse      = 0.02 // reuse a previous Idempotency-Key with a new body -> 409
	pAlsoGetOrder  = 0.30 // a shipment poll also re-reads the order
	pNoToken       = 0.01 // browse without Authorization -> 401
	pOtherCustomer = 0.02 // browse someone else's orders -> 403
	pUnknownOrder  = 0.05 // open an order id that does not exist -> 404
	giveUpAfter    = 4 * day
)

func main() {
	shop := envOr("SHOP_BASE_URL", "http://localhost:3000")
	customers := envInt("CUSTOMERS", 2000)
	seed := uint64(envInt("SEED", 42))
	maxRPS := envInt("MAX_RPS", 300)
	dur, err := time.ParseDuration(envOr("DURATION", "0s"))
	if err != nil {
		log.Fatalf("invalid DURATION: %v", err)
	}
	clock, err := simclock.FromEnv()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dur)
		defer cancel()
	}

	g := &gen{
		shop:  shop,
		clock: clock,
		http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			MaxIdleConns: 512, MaxIdleConnsPerHost: 512, IdleConnTimeout: 90 * time.Second}},
		limiter: newLimiter(ctx, maxRPS),
		stats:   map[string]int{},
	}
	if err := g.waitForShop(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("loadgen: %d customers, seed=%d, max_rps=%d, duration=%s, time_scale=%g, sim_now=%s",
		customers, seed, maxRPS, dur, clock.Scale, clock.Now().Format(time.RFC3339))

	var wg sync.WaitGroup
	byProfile := map[string]int{}
	for i := 1; i <= customers; i++ {
		r := mrand.New(mrand.NewPCG(seed, uint64(i)))
		c := &customer{identity: newIdentity(r, i), profile: pickProfile(r), r: r, seed: seed, idx: uint64(i)}
		byProfile[c.profile.Name]++
		wg.Add(1)
		go func() { defer wg.Done(); g.run(ctx, c, &wg) }()
	}
	log.Printf("loadgen: profiles %v", byProfile)

	go func() {
		for range time.Tick(15 * time.Second) {
			log.Printf("loadgen: sim_now=%s requests=%d orders_created=%d tracking=%d",
				clock.Now().Format(time.RFC3339), g.total.Load(), g.created.Load(), g.tracking.Load())
		}
	}()
	wg.Wait()
	g.report(customers, byProfile)
}

func pickProfile(r *mrand.Rand) profile {
	u := r.Float64()
	for _, p := range profiles {
		if u < p.Weight {
			return p
		}
		u -= p.Weight
	}
	return profiles[len(profiles)-1]
}

type customer struct {
	identity
	profile profile
	r       *mrand.Rand // owned by the customer goroutine only
	seed    uint64
	idx     uint64
	nOrders uint64
	keys    []string
	orders  []string
	mu      sync.Mutex // guards orders (appended by run, read by browse)
}

type gen struct {
	shop     string
	clock    *simclock.Clock
	http     *http.Client
	limiter  <-chan struct{}
	mu       sync.Mutex
	stats    map[string]int
	total    atomic.Int64
	created  atomic.Int64
	tracking atomic.Int64
}

// run is the life of one customer: wait an exponential (simulated) time,
// then either place an order or browse, forever.
func (g *gen) run(ctx context.Context, c *customer, wg *sync.WaitGroup) {
	expo := func(mean time.Duration) time.Duration {
		if mean == 0 {
			return time.Duration(math.MaxInt64)
		}
		return time.Duration(c.r.ExpFloat64() * float64(mean))
	}
	nextOrder, nextBrowse := expo(c.profile.OrderEvery), expo(c.profile.BrowseEvery)
	for {
		wait := min(nextOrder, nextBrowse)
		if !g.sleepSim(ctx, wait) {
			return
		}
		nextOrder -= wait
		nextBrowse -= wait
		if nextOrder <= 0 {
			if id := g.placeOrder(ctx, c); id != "" {
				c.nOrders++
				tr := mrand.New(mrand.NewPCG(c.seed, c.idx<<20|c.nOrders))
				wg.Add(1)
				go func() { defer wg.Done(); g.track(ctx, c, id, tr) }()
			}
			nextOrder = expo(c.profile.OrderEvery)
		} else {
			g.browse(ctx, c)
			nextBrowse = expo(c.profile.BrowseEvery)
		}
	}
}

func (g *gen) placeOrder(ctx context.Context, c *customer) string {
	body := c.newOrder(c.r)
	key := newKey(c.r)
	switch {
	case c.r.Float64() < pInvalidOrder:
		body = breakOrder(c.r, body)
	case len(c.keys) > 0 && c.r.Float64() < pKeyReuse:
		key = pick(c.r, c.keys) // a buggy client re-sending an old key with a new cart
	}
	status, resp := g.call(ctx, c, "POST", "/orders", "POST /orders", body, map[string]string{"Idempotency-Key": key})
	if status != http.StatusCreated {
		return ""
	}
	var o struct{ ID string }
	if json.Unmarshal(resp, &o) != nil || o.ID == "" {
		return ""
	}
	c.keys = append(c.keys, key)
	c.mu.Lock()
	c.orders = append(c.orders, o.ID)
	c.mu.Unlock()
	g.created.Add(1)
	return o.ID
}

// track polls the shipment the way a client app does: soon after ordering,
// then every 2-4 simulated hours, until DELIVERED/CANCELLED or giveUpAfter.
func (g *gen) track(ctx context.Context, c *customer, orderID string, r *mrand.Rand) {
	g.tracking.Add(1)
	defer g.tracking.Add(-1)
	start := g.clock.Now()
	wait := time.Minute + time.Duration(r.Int64N(int64(19*time.Minute)))
	for {
		if !g.sleepSim(ctx, wait) {
			return
		}
		if r.Float64() < pAlsoGetOrder {
			g.call(ctx, c, "GET", "/orders/"+orderID, "GET /orders/{id}", nil, nil)
		}
		status, resp := g.call(ctx, c, "GET", "/orders/"+orderID+"/shipment", "GET /orders/{id}/shipment", nil, nil)
		if status == http.StatusOK {
			var s struct{ Status string }
			_ = json.Unmarshal(resp, &s)
			if s.Status == "DELIVERED" || s.Status == "CANCELLED" {
				return
			}
		}
		if g.clock.Now().Sub(start) > giveUpAfter {
			return // never shipped: the customer stops looking
		}
		wait = 2*time.Hour + time.Duration(r.Int64N(int64(2*time.Hour)))
	}
}

func (g *gen) browse(ctx context.Context, c *customer) {
	u := c.r.Float64()
	switch {
	case u < pNoToken:
		g.callAs(ctx, "", "GET", "/customers/"+c.ID+"/orders", "GET /customers/{id}/orders", nil, nil)
	case u < pNoToken+pOtherCustomer:
		other := fmt.Sprintf("CUS-%06d", 1+c.r.IntN(999_999))
		g.call(ctx, c, "GET", "/customers/"+other+"/orders", "GET /customers/{id}/orders", nil, nil)
	case u < pNoToken+pOtherCustomer+pUnknownOrder:
		g.call(ctx, c, "GET", "/orders/ORD-"+newKey(c.r)[:10], "GET /orders/{id}", nil, nil)
	default:
		g.call(ctx, c, "GET", "/customers/"+c.ID+"/orders", "GET /customers/{id}/orders", nil, nil)
		c.mu.Lock()
		var id string
		if len(c.orders) > 0 && c.r.Float64() < 0.4 {
			id = pick(c.r, c.orders)
		}
		c.mu.Unlock()
		if id != "" {
			g.call(ctx, c, "GET", "/orders/"+id, "GET /orders/{id}", nil, nil)
		}
	}
}

func (g *gen) call(ctx context.Context, c *customer, method, path, op string, body any, hdr map[string]string) (int, []byte) {
	return g.callAs(ctx, c.Token, method, path, op, body, hdr)
}

func (g *gen) callAs(ctx context.Context, token, method, path, op string, body any, hdr map[string]string) (int, []byte) {
	select {
	case <-g.limiter:
	case <-ctx.Done():
		return 0, nil
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, g.shop+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("traceparent", newTraceparent())
	req.Header.Set("User-Agent", "tt-demo-loadgen/0.1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := g.http.Do(req)
	status := 0
	var out []byte
	if err == nil {
		out, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		status = resp.StatusCode
	} else if ctx.Err() != nil {
		return 0, nil // shutting down: not a real outcome
	}
	g.total.Add(1)
	g.mu.Lock()
	g.stats[op+" "+strconv.Itoa(status)]++
	g.mu.Unlock()
	return status, out
}

// sleepSim waits for a simulated duration; false if the run is over.
func (g *gen) sleepSim(ctx context.Context, sim time.Duration) bool {
	t := time.NewTimer(g.clock.RealDuration(sim))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (g *gen) waitForShop(ctx context.Context) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(g.shop + "/__health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("shop not reachable at %s", g.shop)
}

func (g *gen) report(customers int, byProfile map[string]int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := make([]string, 0, len(g.stats))
	for k := range g.stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("\nloadgen summary: customers=%d profiles=%v requests=%d orders_created=%d\n",
		customers, byProfile, g.total.Load(), g.created.Load())
	for _, k := range keys {
		fmt.Printf("  %-40s %7d\n", k, g.stats[k])
	}
}

// newLimiter returns a channel that yields at most rps tokens per second.
func newLimiter(ctx context.Context, rps int) <-chan struct{} {
	ch := make(chan struct{}, rps)
	go func() {
		t := time.NewTicker(time.Second / time.Duration(rps))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case ch <- struct{}{}:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

func newKey(r *mrand.Rand) string {
	return fmt.Sprintf("%016x%016x", r.Uint64(), r.Uint64())
}

func newTraceparent() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "00-" + hex.EncodeToString(b[:16]) + "-" + hex.EncodeToString(b[16:]) + "-01"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid %s %q", k, v)
	}
	return n
}
