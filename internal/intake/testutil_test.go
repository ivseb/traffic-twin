package intake

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/store"
)

const (
	testSource = "src-01JB7Q2W"
	testGroup  = "prod"
	// Valid but fake tokens (22 base64url characters after tk1:<kid>:).
	tokOrder1   = "tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg"
	tokOrder2   = "tk1:k1:Qm3bN7vXc9LpK2sD5fGh8J"
	tokShip1    = "tk1:k1:Yt2eWgZx81mQ4pLr0aVb7c"
	tokSubject  = "tk1:k1:7Hq2nB5sKe9dXo3uLw1cRf"
	tokOldKid   = "tk1:k0:Zx81mQ4pLr0aVb7cYt2eWg"
	tokOtherKid = "tk1:zz:Zx81mQ4pLr0aVb7cYt2eWg"
)

// The clock of the tests: inside the validity window of the policy.
var testNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// policyTemplate is the compiled policy of an invented web shop
// (tt.policy.body/v1). DISCOVERY is replaced by the discovery section.
const policyTemplate = `{
 "format":"tt.policy.body/v1","policy_id":"p-shop","version":7,"issued_seq":31,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":["k0"],"epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate_bp":500,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T08:00:00Z","allow":["v1","v2"],"hosts_allow":["partner.example"]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 DISCOVERY
 "global":{
   "errors":{"body":[{"path":"$.error.code","action":{"action":"keep"}}]}
 },
 "services":[
  {"name":"shipping-ext","match":{"base":"https://api.carrier.example"},
   "errors":{"body":[{"path":"$.error.code","action":{"action":"keep"}}]},
   "ops":[
    {"op":"GET /v1/rates/{zone}","request":{"path":{"zone":{"action":"keep"}}}},
    {"op":"GET /v1/shipments","request":{"query":{"orderId":{"action":"hmac","domain":"order"}}},
      "response":{"body":[
        {"path":"$.items[*].eta","action":{"action":"bucket","kind":"time","unit":"day"}},
        {"path":"$.items[*].orderId","action":{"action":"hmac","domain":"order"}},
        {"path":"$.items[*].status","action":{"action":"keep"}}]}},
    {"op":"POST /v1/shipments",
      "request":{"body":[{"path":"$.orderId","action":{"action":"hmac","domain":"order"}}]},
      "response":{"body":[
        {"path":"$.shipmentId","action":{"action":"hmac","domain":"shipment"}},
        {"path":"$.status","action":{"action":"keep"}}]}}
   ]},
  {"name":"shop-api","match":{"inbound":true,"internal":false},
   "request":{"headers":{"content-type":{"action":"keep"}}},
   "response":{"headers":{"content-type":{"action":"keep"}}},
   "ops":[
    {"op":"GET /orders/{id}","request":{"path":{"id":{"action":"hmac","domain":"order"}}},
      "response":{"body":[
        {"path":"$.eta","action":{"action":"bucket","kind":"time","unit":"day"}},
        {"path":"$.status","action":{"action":"keep"}}]}},
    {"op":"POST /orders",
      "request":{"query":{"promo":{"action":"keep"}}},
      "response":{"body":[
        {"path":"$.id","action":{"action":"hmac","domain":"order"}},
        {"path":"$.status","action":{"action":"keep"}},
        {"path":"$.total","action":{"action":"bucket","kind":"num","bounds":[0,50,100,250]}}]}}
   ]}
 ]
}`

const discoveryOn = `"discovery":{"enabled":true,"expires_at":"2026-10-22T08:00:00Z"},`
const discoveryOff = `"discovery":{"enabled":false,"expires_at":"2026-10-22T08:00:00Z"},`

// hostsOff is the strict mode of spec v1.5: no host patterns.
const hostsOff = `"hosts":{"discovery":"off"},`

func mustPolicy(t testing.TB, discovery string) *Policy {
	t.Helper()
	body := strings.Replace(policyTemplate, "DISCOVERY", discovery, 1)
	if !json.Valid([]byte(body)) {
		t.Fatal("policy template is not valid JSON")
	}
	p, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Base events ---------------------------------------------------------------

func mustEvent(t testing.TB, canonical string) *event.Event {
	t.Helper()
	ev, err := event.Decode([]byte(canonical))
	if err != nil {
		t.Fatalf("fixture is not a valid event: %v\n%s", err, canonical)
	}
	return ev
}

// header returns the fixed part of the fixture events.
func eventJSON(hash, dir, service, op, route, extra string) string {
	return fmt.Sprintf(`{"dir":%q,"latency_ms":184,"op":%q,"policy":{"hash":%q,"id":"p-shop","version":7},%s"route_source":%q,"sampled_by":"subject","schema":"tt.http.exchange/v1","service":%q,"source":{"id":%q,"kind":"sdk-node","version":"0.1.0"},"ts":"2026-10-19T10:00:00.412Z"}`,
		dir, op, hash, extra, route, service, testSource)
}

// orderPost: POST /orders handled by shop-api (policy route), with keep, hmac
// and bucket(num) values in the response and a keep query value.
func orderPost(hash string) string {
	req := `"req":{"body":{"email":"drop:str:email","items":[{"qty":"drop:int","sku":"drop:str:l32"}],"note":"drop:str:l8"},"ct":"application/json","headers":{"content-type":["keep:application/json"]},"path":"/orders","query":{"promo":["keep:AUTUMN10"]},"size":"l128"},`
	resp := `"resp":{"body":{"id":"` + tokOrder1 + `","status":"keep:CREATED","total":"num:50-100"},"ct":"application/json","headers":{"content-type":["keep:application/json; charset=utf-8"]},"size":"l128"},`
	s := eventJSON(hash, "inbound", "shop-api", "POST /orders", "policy", req+resp)
	return strings.Replace(s, `"ts":`, `"span_id":"00f067aa0ba902b7","status":201,"subject":"`+tokSubject+`","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","ts":`, 1)
}

// orderGet: GET /orders/{id} with an hmac path parameter.
func orderGet(hash string) string {
	req := `"req":{"path":"/orders/{` + tokOrder1 + `}","size":"l8"},`
	resp := `"resp":{"body":{"eta":"time:2026-10-21","status":"keep:SHIPPED"},"ct":"application/json","size":"l32"},`
	s := eventJSON(hash, "inbound", "shop-api", "GET /orders/{id}", "policy", req+resp)
	return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
}

// shipmentPost: outbound call to the carrier.
func shipmentPost(hash string) string {
	req := `"req":{"body":{"orderId":"` + tokOrder1 + `"},"ct":"application/json","path":"/v1/shipments","size":"l32"},`
	resp := `"resp":{"body":{"shipmentId":"` + tokShip1 + `","status":"keep:LABELLED"},"ct":"application/json","size":"l128"},`
	s := eventJSON(hash, "outbound", "shipping-ext", "POST /v1/shipments", "policy", req+resp)
	return strings.Replace(s, `"ts":`, `"status":201,"ts":`, 1)
}

// rawPromo: inbound request that matches no template; "promo" is an
// automatic word.
func rawPromo(hash string) string {
	req := `"req":{"path":"/promo/{drop:str:l8}","size":"l8"},`
	resp := `"resp":{"size":"l8"},`
	s := eventJSON(hash, "inbound", "shop-api", "GET /promo/{drop:str:l8}", "raw", req+resp)
	return strings.Replace(s, `"ts":`, `"status":404,"ts":`, 1)
}

// mutate decodes a fixture, applies f and re-encodes it canonically.
func mutate(t testing.TB, canonical string, f func(*event.Event)) string {
	t.Helper()
	ev := mustEvent(t, canonical)
	f(ev)
	return string(ev.Canonical())
}

// Harness ---------------------------------------------------------------------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	in        *Intake
	db        *store.DB
	sources   *MemSourceRegistry
	policies  *MemPolicyRegistry
	tokens    *MemTokenSink
	alarms    *MemAlarmSink
	audit     *audit.Log
	clock     *testClock
	pol       *Policy // discovery on
	polOff    *Policy // discovery off (hosts.discovery auto by default)
	polStrict *Policy // discovery off and hosts.discovery off
	cfg       Config
	noSink    bool
}

type harnessOpt func(*harness)

func withoutSink() harnessOpt { return func(h *harness) { h.noSink = true } }

func withConfig(f func(*Config)) harnessOpt { return func(h *harness) { f(&h.cfg) } }

func newHarness(t testing.TB, opts ...harnessOpt) *harness {
	t.Helper()
	h := &harness{
		sources:  NewMemSourceRegistry(),
		policies: NewMemPolicyRegistry(),
		tokens:   NewMemTokenSink(),
		alarms:   &MemAlarmSink{},
		clock:    &testClock{t: testNow},
		cfg:      DefaultConfig(),
	}
	h.cfg.FlushInterval = time.Hour
	h.cfg.PurgeInterval = time.Hour
	for _, o := range opts {
		o(h)
	}
	var err error
	h.db, err = store.Open(context.Background(), filepath.Join(t.TempDir(), "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.db.Close() })
	h.audit = audit.New(h.db)
	h.sources.Set(SourceInfo{ID: testSource, Group: testGroup, ServiceName: "shop-api", AllowedServices: []string{"shop-api", "billing"}})
	h.pol = mustPolicy(t, discoveryOn)
	h.polOff = mustPolicy(t, discoveryOff)
	h.polStrict = mustPolicy(t, discoveryOff+hostsOff)
	h.policies.Add(h.pol)
	h.policies.Add(h.polOff)
	h.policies.Add(h.polStrict)
	var sink TokenSink = h.tokens
	if h.noSink {
		sink = nil
	}
	h.in, err = New(context.Background(), h.cfg, Deps{
		DB: h.db, Sources: h.sources, Policies: h.policies, Tokens: sink, Alarms: h.alarms, Audit: h.audit,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.in.Close(context.Background()) })
	return h
}

// ingest sends one event as the test source and returns the rejection.
func (h *harness) ingest(t testing.TB, body string) Reject {
	t.Helper()
	return h.ingestAs(t, testSource, body)
}

func (h *harness) ingestAs(t testing.TB, source, body string) Reject {
	t.Helper()
	rej, err := h.in.IngestEvent(context.Background(), source, []byte(body))
	if err != nil {
		t.Fatalf("IngestEvent: %v", err)
	}
	return rej
}

func (h *harness) idle(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.in.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) count(t testing.TB) int64 {
	t.Helper()
	h.idle(t)
	n, err := h.in.Store().Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type eventT = *event.Event
type discT = event.DiscEntry
