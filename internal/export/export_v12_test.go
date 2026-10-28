package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureV12 = "testdata/carrier-pack-v12"

// fixedNow keeps the not_after check independent of the day tests run.
func fixedNow() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }

func runV12(t *testing.T, cfg Config) (string, *Result) {
	t.Helper()
	dir := t.TempDir()
	cfg.Source = DirSource{Dir: fixtureV12}
	cfg.OutDir = dir
	cfg.Now = fixedNow
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dir, res
}

func loadV12(t *testing.T) *model {
	t.Helper()
	in, err := DirSource{Dir: fixtureV12}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return buildModel(in, nil)
}

func TestV12Deterministic(t *testing.T) {
	d1, _ := runV12(t, Config{})
	t1 := readTree(t, d1)
	for i := 0; i < 3; i++ {
		d2, _ := runV12(t, Config{})
		t2 := readTree(t, d2)
		for name, b := range t1 {
			if !bytes.Equal(b, t2[name]) {
				t.Fatalf("%s differs between runs", name)
			}
		}
	}
}

func TestV12ChainsUseOutcomeAndPending(t *testing.T) {
	m := loadV12(t)
	by := map[string]*chain{}
	for _, c := range m.chains {
		by[c.Subject] = c
	}
	happy := by["ORD-SYN-0042"]
	if happy == nil || happy.Outcome != "happy" || happy.Owner != "CUS-SYN-0007" {
		t.Fatalf("happy chain: %+v", happy)
	}
	var effects []string
	for _, s := range happy.Steps {
		effects = append(effects, s.Effect)
	}
	// The immediate create is the first step: no extra "not yet there" step.
	want := "shipment-requested,shipment-created,shipment-in-transit,shipment-delivered"
	if strings.Join(effects, ",") != want {
		t.Fatalf("steps = %v", effects)
	}
	last := happy.Steps[3]
	if !last.Projected || last.State["status"] != "DELIVERED" || last.State["orderId"] != "ORD-SYN-0042" || last.State["shipmentId"] != "SHP-SYN-0091" {
		t.Fatalf("pending step state: %+v", last)
	}
	if c := by["ORD-SYN-0043"]; c == nil || c.Outcome != "cancelled" || len(c.Steps) != 3 || c.Steps[2].Projected {
		t.Fatalf("cancelled chain: %+v", c)
	}
	if c := by["ORD-SYN-0044"]; c == nil || c.Outcome != "never-shipped" || len(c.Steps) != 1 {
		t.Fatalf("never-shipped chain: %+v", c)
	}
	// Updates of existing entities (order-linked, r-0008) are not chains.
	for _, c := range m.chains {
		if c.Entity.Name == "order" {
			t.Errorf("order chain from an update-only effect: %+v", c)
		}
	}
	var gotNote bool
	for _, n := range m.notes {
		if n.Kind == "state" && strings.Contains(n.Element, "effect:order-linked") {
			gotNote = true
		}
	}
	if !gotNote {
		t.Error("missing note for the update-only effect order-linked")
	}
}

func lookupOf(m *model, svc, op, key string) *lookup {
	for _, l := range m.lookups[svc] {
		if l.Op.Key == op && l.Key == key {
			return l
		}
	}
	return nil
}

func TestV12ReadByFeatures(t *testing.T) {
	m := loadV12(t)

	// hidden_when: the PENDING shipment is an empty list for the carrier list
	// and a 404 for the shop, but visible by id.
	l := lookupOf(m, "shipping-ext", "GET /v1/shipments", "ORD-SYN-0042")
	if l == nil || !l.Views[0].Absent || string(marshalJSON(l.Views[0].Body)) != "{\n  \"items\": []\n}\n" {
		t.Fatalf("hidden list view: %+v", l)
	}
	p := lookupOf(m, "shipping-ext", "GET /v1/shipments/{shipmentId}", "SHP-SYN-0091")
	if p == nil || p.Views[0].Absent || p.Views[0].Body.(map[string]any)["status"] != "PENDING" {
		t.Fatalf("path view must show PENDING: %+v", p)
	}

	// read_by.service + by.field on a path: shop-api exposes the shipment by order id.
	s := lookupOf(m, "shop-api", "GET /orders/{id}/shipment", "ORD-SYN-0042")
	if s == nil || s.Service != "shop-api" || s.Entity != "shipment" || s.Views[0].Status != 404 || s.Views[0].Body.(map[string]any)["error"].(map[string]any)["code"] != "SHIPMENT_NOT_FOUND" {
		t.Fatalf("shop-api shipment lookup: %+v", s)
	}
	if s.Foreign == nil || s.Foreign.Status != 404 || s.Owner != "CUS-SYN-0007" {
		t.Fatalf("owner scope: %+v", s.Foreign)
	}

	// customer collection: ordered by createdAt, count and customerId filled.
	o := lookupOf(m, "shop-api", "GET /customers/{id}/orders", "CUS-SYN-0007")
	if o == nil || !o.List {
		t.Fatalf("owner list: %+v", o)
	}
	body := o.Views[0].Body.(map[string]any)
	items := body["items"].([]any)
	if len(items) != 2 || body["customerId"] != "CUS-SYN-0007" || stringify(body["count"]) != "2" {
		t.Fatalf("owner list body: %v", body)
	}
	if items[0].(map[string]any)["id"] != "ORD-SYN-0042" || items[1].(map[string]any)["id"] != "ORD-SYN-0043" {
		t.Fatalf("order_by createdAt asc broken: %v", items)
	}
	if o.Foreign == nil || o.Foreign.Status != 403 {
		t.Fatalf("foreign answer of a collection must be 403: %+v", o.Foreign)
	}
	ord := lookupOf(m, "shop-api", "GET /orders/{id}", "ORD-SYN-0042")
	if ord == nil || ord.Foreign == nil || ord.Foreign.Status != 404 || ord.Foreign.Body.(map[string]any)["error"].(map[string]any)["code"] != "ORDER_NOT_FOUND" {
		t.Fatalf("order not_found_example: %+v", ord)
	}
}

// Exported examples keep the order <-> shipment links.
func TestV12LinksAreKept(t *testing.T) {
	m := loadV12(t)
	for _, c := range m.chains {
		if c.Entity.Name != "shipment" {
			continue
		}
		ord := lookupOf(m, "shop-api", "GET /orders/{id}", c.Subject)
		if ord == nil {
			t.Fatalf("no order lookup for %s", c.Subject)
		}
		if ord.Views[0].Body.(map[string]any)["shipmentId"] != c.EntityID {
			t.Errorf("order %s links to %v, chain is %s", c.Subject, ord.Views[0].Body.(map[string]any)["shipmentId"], c.EntityID)
		}
		for _, s := range c.Steps {
			if s.State != nil && s.State["orderId"] != c.Subject {
				t.Errorf("step %s of %s lost its orderId: %v", s.Effect, c.Subject, s.State)
			}
		}
	}
	if m.links["order.shipmentId->shipment"] != 3 || m.links["shipment.orderId->order"] != 3 {
		t.Fatalf("relation checks: %v", m.links)
	}
	for _, n := range m.notes {
		if n.Kind == "integrity" {
			t.Errorf("unexpected dangling relation: %+v", n)
		}
	}
}

func TestV12WireMockDelaysFaultsAndScope(t *testing.T) {
	dir, res := runV12(t, Config{Targets: []string{TargetWireMock}})
	read := func(svc string) []map[string]any {
		b, err := os.ReadFile(filepath.Join(dir, "wiremock", svc, "mappings", svc+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			Mappings []map[string]any `json:"mappings"`
		}
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d.Mappings
	}
	byName := func(ms []map[string]any, name string) map[string]any {
		for _, m := range ms {
			if m["name"] == name {
				return m
			}
		}
		t.Fatalf("no mapping %q", name)
		return nil
	}
	ship := read("shipping-ext")

	// after as {min,max} is kept in the metadata.
	st := byName(ship, "GET /v1/shipments | r-0007-ORD-SYN-0042--shipment-created")
	after := st["metadata"].(map[string]any)["tt"].(map[string]any)["after"].(map[string]any)
	if after["min"] != "2m" || after["max"] != "10m" {
		t.Fatalf("after range lost: %v", after)
	}
	imm := byName(ship, "GET /v1/shipments | r-0007-ORD-SYN-0042--Started")
	if imm["metadata"].(map[string]any)["tt"].(map[string]any)["after"] != "0s" {
		t.Fatalf("immediate effect keeps its single value: %v", imm["metadata"])
	}

	// normative network-fault mapping (mock.md section 4)
	want := map[string]string{
		"timeout": "EMPTY_RESPONSE", "reset": "CONNECTION_RESET_BY_PEER", "refused": "CONNECTION_RESET_BY_PEER",
		"dns": "CONNECTION_RESET_BY_PEER", "tls": "RANDOM_DATA_THEN_CLOSE", "other": "EMPTY_RESPONSE",
	}
	for kind, fault := range want {
		r := byName(ship, "GET /v1/shipments | net "+kind)["response"].(map[string]any)
		if r["fault"] != fault {
			t.Errorf("%s -> %v, want %s", kind, r["fault"], fault)
		}
		_, delayed := r["delayDistribution"]
		wantDelay := kind == "reset" || kind == "other"
		if delayed != wantDelay {
			t.Errorf("%s: latency injected = %v, want %v", kind, delayed, wantDelay)
		}
	}
	if byName(ship, "GET /v1/shipments | net timeout")["response"].(map[string]any)["fixedDelayMilliseconds"] != float64(30000) {
		t.Error("timeout must wait 30 s")
	}

	// owner scope: header variants plus a foreign stub with a lower number than the header-less copy
	shop := read("shop-api")
	own := byName(shop, "GET /orders/{id} | order-ORD-SYN-0042 [owner]")
	if own["request"].(map[string]any)["headers"].(map[string]any)["X-TT-Customer"].(map[string]any)["equalTo"] != "CUS-SYN-0007" {
		t.Fatalf("owner stub: %v", own["request"])
	}
	fo := byName(shop, "GET /orders/{id} | order-ORD-SYN-0042--foreign")
	nc := byName(shop, "GET /orders/{id} | order-ORD-SYN-0042 [no customer]")
	if own["priority"].(float64) >= fo["priority"].(float64) || fo["priority"].(float64) >= nc["priority"].(float64) {
		t.Fatalf("priorities must be owner < foreign < no customer: %v %v %v", own["priority"], fo["priority"], nc["priority"])
	}
	if fo["response"].(map[string]any)["status"] != float64(404) {
		t.Fatalf("foreign order must be 404: %v", fo["response"])
	}

	rep := res.Reports[TargetWireMock]
	if rep.LossByKind["approximation"] != 3 {
		t.Errorf("refused, dns and tls are approximations: %v", rep.LossByKind)
	}
	foundRange := false
	for _, l := range rep.Losses {
		if l.Kind == "time" && strings.Contains(l.Detail, "ranges {min,max}") {
			foundRange = true
		}
	}
	if !foundRange {
		t.Error("time loss must mention the range delays")
	}
}

func TestV12PresetsReport(t *testing.T) {
	_, res := runV12(t, Config{})
	status := func(target, id string) PresetReport {
		for _, p := range res.Reports[target].Presets {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("%s: no preset %s", target, id)
		return PresetReport{}
	}
	if p := status(TargetWireMock, "shipment-cancelled"); p.Status != "partial" || len(p.How) < 2 || !strings.Contains(strings.Join(p.How, " "), "r-0007-ORD-SYN-0043") || !strings.Contains(strings.Join(p.How, " "), "X-TT-Customer: CUS-SYN-0007") {
		t.Errorf("wiremock shipment-cancelled: %+v", p) // seed is lost, hence partial
	}
	if p := status(TargetWireMock, "never-shipped"); !strings.Contains(strings.Join(p.How, " "), "ORD-SYN-0044") {
		t.Errorf("never-shipped must pick the subject of CUS-SYN-0008: %+v", p)
	}
	td := status(TargetWireMock, "tracking-down")
	if td.Status != "partial" || !strings.Contains(strings.Join(td.How, " "), "X-TT-Fault: 503") || !strings.Contains(strings.Join(td.Lost, " "), "limited to 1 times") {
		t.Errorf("tracking-down: %+v", td)
	}
	if p := status(TargetMicrocks, "tracking-down"); !strings.Contains(strings.Join(p.How, " "), "tt-example-carrier-unavailable") {
		t.Errorf("microcks tracking-down: %+v", p)
	}
	if p := status(TargetPrism, "tracking-down"); !strings.Contains(strings.Join(p.How, " "), "Prefer: code=503") {
		t.Errorf("prism tracking-down: %+v", p)
	}
	fl := status(TargetMicrocks, "flaky-network")
	if fl.Status == "mapped" || !strings.Contains(strings.Join(fl.Lost, " "), "network error tls") {
		t.Errorf("microcks flaky-network must report the network fault as lost: %+v", fl)
	}
	if res.Reports[TargetWireMock].LossByKind["preset"] == 0 {
		t.Error("lost preset parts must also be losses")
	}
}

func TestV12MicrocksAndPrismArtifacts(t *testing.T) {
	dir, _ := runV12(t, Config{Targets: []string{TargetMicrocks, TargetPrism}})
	b, err := os.ReadFile(filepath.Join(dir, "microcks", "shop-api", "shop-api-metadata.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "GET /orders/{id}/shipment") || !strings.Contains(string(b), "SCRIPT") {
		t.Fatalf("shop-api shipment chain must be scripted:\n%s", b)
	}
	pb, _ := os.ReadFile(filepath.Join(dir, "prism", "shop-api", "shop-api.openapi.yaml"))
	if !strings.Contains(string(pb), "order-ORD-SYN-0042--foreign:") || !strings.Contains(string(pb), "order-owner-CUS-SYN-0007:") {
		t.Fatalf("prism must carry the foreign and owner-list examples")
	}
}

func TestPackExpiry(t *testing.T) {
	cfg := Config{Source: DirSource{Dir: fixtureV12}, OutDir: t.TempDir()}
	cfg.Now = func() time.Time { return time.Date(2027, 1, 17, 3, 20, 0, 0, time.UTC) }
	if _, err := Run(context.Background(), cfg); !errors.Is(err, ErrPackExpired) {
		t.Fatalf("want pack_expired at not_after, got %v", err)
	}
	cfg.Now = func() time.Time { return time.Date(2027, 1, 17, 3, 19, 59, 0, time.UTC) }
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("one second before not_after must work: %v", err)
	}
}

func TestDelayJSON(t *testing.T) {
	var e Effect
	if err := json.Unmarshal([]byte(`{"id":"a","entity":"x","after":{"min":"2m","max":"10m"}}`), &e); err != nil || !e.After.IsRange || e.After.Min != "2m" {
		t.Fatalf("range: %+v %v", e.After, err)
	}
	if err := json.Unmarshal([]byte(`{"id":"a","entity":"x","after":"0s"}`), &e); err != nil || e.After.IsRange || !e.After.Zero() {
		t.Fatalf("single: %+v %v", e.After, err)
	}
	if (Delay{Fixed: "5m"}).Zero() || !(Delay{Min: "0s", Max: "0s", IsRange: true}).Zero() {
		t.Fatal("Zero")
	}
}
