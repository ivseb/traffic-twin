package export

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const fixture = "testdata/carrier-pack"

func runFixture(t *testing.T, cfg Config) (string, *Result) {
	t.Helper()
	dir := t.TempDir()
	cfg.Source = DirSource{Dir: fixture}
	cfg.OutDir = dir
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dir, res
}

func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeterministicOutput(t *testing.T) {
	d1, r1 := runFixture(t, Config{})
	t1 := readTree(t, d1)
	for i := 0; i < 4; i++ { // map iteration order is random per run
		d2, r2 := runFixture(t, Config{})
		t2 := readTree(t, d2)
		if len(t1) != len(t2) || len(r1.Files) != len(r2.Files) {
			t.Fatalf("different file sets: %d vs %d", len(t1), len(t2))
		}
		for name, b := range t1 {
			if !bytes.Equal(b, t2[name]) {
				t.Fatalf("%s differs between runs", name)
			}
		}
	}
	for name := range t1 {
		if !strings.HasSuffix(name, "\n") && !bytes.HasSuffix(t1[name], []byte("\n")) {
			t.Errorf("%s has no trailing newline", name)
		}
	}
}

func TestNoDraftRulesNoInternalExtensions(t *testing.T) {
	dir, _ := runFixture(t, Config{})
	for name, b := range readTree(t, dir) {
		s := string(b)
		if strings.Contains(s, "GHOST") || strings.Contains(s, "r-0099") {
			t.Errorf("%s leaks a non-approved rule", name)
		}
		if strings.Contains(s, "x-tt-") {
			t.Errorf("%s keeps an x-tt-* extension", name)
		}
	}
}

func TestModelChains(t *testing.T) {
	in, err := DirSource{Dir: fixture}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := buildModel(in, nil)
	if m.stats.ApprovedRules != 2 || m.stats.CausalRules != 1 || m.stats.BatchRules != 1 {
		t.Fatalf("rule stats: %+v", m.stats)
	}
	bySubject := map[string]*chain{}
	for _, c := range m.chains {
		bySubject[c.Subject] = c
	}
	happy := bySubject["ORD-SYN-0042"]
	if happy == nil || happy.Outcome != "happy" {
		t.Fatalf("happy chain: %+v", happy)
	}
	var effects []string
	for _, s := range happy.Steps {
		effects = append(effects, s.Effect)
	}
	want := []string{"", "shipment-created", "shipment-in-transit", "shipment-delivered"}
	if strings.Join(effects, ",") != strings.Join(want, ",") {
		t.Fatalf("steps = %v, want %v", effects, want)
	}
	last := happy.Steps[len(happy.Steps)-1]
	if !last.Projected || last.State["status"] != "DELIVERED" || last.State["orderId"] != "ORD-SYN-0042" {
		t.Fatalf("projected step: %+v", last)
	}
	if c := bySubject["ORD-SYN-0043"]; c == nil || c.Outcome != "cancelled" || len(c.Steps) != 3 {
		t.Fatalf("cancelled chain: %+v", c)
	}
	if c := bySubject["ORD-SYN-0044"]; c == nil || c.Outcome != "never-shipped" || len(c.Steps) != 1 {
		t.Fatalf("never-shipped chain: %+v", c)
	}
	// every outcome has a representative: no coverage note
	for _, n := range m.notes {
		if n.Kind == "coverage" {
			t.Errorf("unexpected coverage note: %+v", n)
		}
	}
}

func TestWireMockStructure(t *testing.T) {
	dir, res := runFixture(t, Config{Targets: []string{TargetWireMock}})
	if len(res.Reports) != 1 {
		t.Fatalf("reports: %v", res.Reports)
	}
	b, err := os.ReadFile(filepath.Join(dir, "wiremock/shipping-ext/mappings/shipping-ext.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Mappings []map[string]any `json:"mappings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	allowedTop := map[string]bool{"id": true, "name": true, "priority": true, "request": true, "response": true, "metadata": true,
		"scenarioName": true, "requiredScenarioState": true, "newScenarioState": true}
	allowedReq := map[string]bool{"method": true, "urlPath": true, "urlPathTemplate": true, "queryParameters": true, "pathParameters": true, "headers": true, "bodyPatterns": true}
	allowedResp := map[string]bool{"status": true, "headers": true, "jsonBody": true, "body": true, "delayDistribution": true, "fixedDelayMilliseconds": true, "fault": true}
	ids := map[string]bool{}
	next := map[string]map[string]bool{} // scenario -> states reachable as "new"
	req := map[string]map[string]bool{}  // scenario -> required states
	for _, mp := range doc.Mappings {
		for k := range mp {
			if !allowedTop[k] {
				t.Errorf("undocumented mapping field %q", k)
			}
		}
		for k := range mp["request"].(map[string]any) {
			if !allowedReq[k] {
				t.Errorf("undocumented request field %q", k)
			}
		}
		for k := range mp["response"].(map[string]any) {
			if !allowedResp[k] {
				t.Errorf("undocumented response field %q", k)
			}
		}
		id := mp["id"].(string)
		if ids[id] {
			t.Errorf("duplicate id %s", id)
		}
		ids[id] = true
		if sn, ok := mp["scenarioName"].(string); ok {
			if req[sn] == nil {
				req[sn], next[sn] = map[string]bool{}, map[string]bool{}
			}
			req[sn][mp["requiredScenarioState"].(string)] = true
			if ns, ok := mp["newScenarioState"].(string); ok {
				next[sn][ns] = true
			}
		}
	}
	// Every scenario starts in Started and every target state has a stub.
	for sn := range req {
		if !req[sn]["Started"] {
			t.Errorf("scenario %s has no Started stub", sn)
		}
		for ns := range next[sn] {
			if !req[sn][ns] {
				t.Errorf("scenario %s moves to %q which has no stub", sn, ns)
			}
		}
	}
	if len(req) != 2 {
		t.Errorf("want 2 scenarios, got %d", len(req))
	}
	// priorities are sorted ascending in the file
	last := 0
	for _, mp := range doc.Mappings {
		p := int(mp["priority"].(float64))
		if p < last {
			t.Fatalf("priority order broken: %d after %d", p, last)
		}
		last = p
	}
}

func TestWireMockManualAdvance(t *testing.T) {
	dir, _ := runFixture(t, Config{Targets: []string{TargetWireMock}, WireMock: WireMockOptions{Advance: "manual"}})
	b, _ := os.ReadFile(filepath.Join(dir, "wiremock/shipping-ext/mappings/shipping-ext.json"))
	if strings.Contains(string(b), "newScenarioState") {
		t.Fatal("manual mode must not emit newScenarioState")
	}
}

func TestReportLosses(t *testing.T) {
	_, res := runFixture(t, Config{})
	for target, rep := range res.Reports {
		if rep.Format != "tt.export-report/v1" || rep.PackID != "pk-20261019-0001" {
			t.Errorf("%s: bad header %+v", target, rep)
		}
		if rep.LossByKind["batch-schedule"] != 1 {
			t.Errorf("%s: batch rule loss missing: %v", target, rep.LossByKind)
		}
		if rep.LossByKind["time"] == 0 || rep.LossByKind["probabilistic-fault"] == 0 {
			t.Errorf("%s: time/fault losses missing: %v", target, rep.LossByKind)
		}
		if len(rep.Files) == 0 {
			t.Errorf("%s: no files in report", target)
		}
	}
	// Prism drops every latency; WireMock keeps the log-normal.
	if res.Reports[TargetPrism].LossByKind["latency-distribution"] < res.Reports[TargetWireMock].LossByKind["latency-distribution"] {
		t.Error("prism must lose at least as many latency profiles as wiremock")
	}
}

func TestMicrocksArtifacts(t *testing.T) {
	dir, _ := runFixture(t, Config{Targets: []string{TargetMicrocks}})
	read := func(rel string) map[string]any {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		return m
	}
	ex := read("microcks/shipping-ext/shipping-ext-examples.yaml")
	md := read("microcks/shipping-ext/shipping-ext-metadata.yaml")
	for _, a := range []map[string]any{ex, md} {
		if a["apiVersion"] != "mocks.microcks.io/v1alpha1" {
			t.Errorf("apiVersion = %v", a["apiVersion"])
		}
	}
	if ex["kind"] != "APIExamples" || md["kind"] != "APIMetadata" {
		t.Errorf("kinds: %v %v", ex["kind"], md["kind"])
	}
	oa := read("microcks/shipping-ext/shipping-ext-openapi.yaml")
	info := oa["info"].(map[string]any)
	meta := md["metadata"].(map[string]any)
	if info["title"] != meta["name"] || info["version"] != meta["version"] {
		t.Errorf("secondary artifacts must match the primary name/version: %v vs %v", info, meta)
	}
	ops := md["operations"].(map[string]any)
	if d := ops["GET /v1/shipments"].(map[string]any)["dispatcher"]; d != "SCRIPT" {
		t.Errorf("stateful op dispatcher = %v", d)
	}
	if d := ops["POST /v1/shipments"].(map[string]any)["dispatcher"]; d != "JSON_BODY" {
		t.Errorf("body op dispatcher = %v", d)
	}
	// Correlation by name: the query param has one example per response example.
	p := oa["paths"].(map[string]any)["/v1/shipments"].(map[string]any)["get"].(map[string]any)["parameters"].([]any)[0].(map[string]any)
	pe := p["examples"].(map[string]any)
	if _, ok := pe["carrier-unavailable"]; !ok {
		t.Errorf("missing parameter example for carrier-unavailable: %v", pe)
	}
}

func TestMicrocksStateless(t *testing.T) {
	dir, _ := runFixture(t, Config{Targets: []string{TargetMicrocks}, Microcks: MicrocksOptions{Stateless: true}})
	b, _ := os.ReadFile(filepath.Join(dir, "microcks/shipping-ext/shipping-ext-metadata.yaml"))
	if strings.Contains(string(b), "SCRIPT") {
		t.Fatal("stateless export must not use SCRIPT")
	}
	if !strings.Contains(string(b), "FALLBACK") {
		t.Fatal("stateless export should fall back to URI_* dispatchers")
	}
}

func TestPrismExampleOrder(t *testing.T) {
	dir, _ := runFixture(t, Config{Targets: []string{TargetPrism}})
	b, err := os.ReadFile(filepath.Join(dir, "prism/shipping-ext/shipping-ext.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// Contract examples come before world examples so the default is a contract one.
	if strings.Index(s, "    empty:") > strings.Index(s, "r-0007-ORD-SYN-0042--Started:") {
		t.Fatal("contract example must precede world examples")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	get := doc["paths"].(map[string]any)["/v1/shipments"].(map[string]any)["get"].(map[string]any)
	r503 := get["responses"].(map[string]any)["503"].(map[string]any)
	if _, ok := r503["content"].(map[string]any)["application/json"].(map[string]any)["examples"].(map[string]any)["carrier-unavailable"]; !ok {
		t.Fatal("KO example must sit under its status code")
	}
}

func TestServiceFilterAndErrors(t *testing.T) {
	dir, _ := runFixture(t, Config{Services: []string{"shop-api"}, Targets: []string{TargetWireMock}})
	tree := readTree(t, dir)
	for name := range tree {
		if strings.Contains(name, "shipping-ext") {
			t.Errorf("service filter ignored: %s", name)
		}
	}
	for _, cfg := range []Config{
		{Source: DirSource{Dir: fixture}, OutDir: t.TempDir(), Targets: []string{"nope"}},
		{Source: DirSource{Dir: fixture}, OutDir: t.TempDir(), Services: []string{"ghost"}},
		{Source: DirSource{Dir: fixture}, OutDir: t.TempDir(), WireMock: WireMockOptions{Advance: "x"}},
		{OutDir: t.TempDir()},
		{Source: DirSource{Dir: fixture}},
	} {
		if _, err := Run(context.Background(), cfg); err == nil {
			t.Errorf("expected error for %+v", cfg)
		}
	}
}

func TestFlags(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse([]string{"--pack", "p", "--out", "o", "--target", "wiremock,prism", "--service", "a, b", "--wiremock-advance", "manual", "--microcks-stateless"}); err != nil {
		t.Fatal(err)
	}
	c := f.Config(DirSource{Dir: "p"})
	sort.Strings(c.Targets)
	if strings.Join(c.Targets, ",") != "prism,wiremock" || strings.Join(c.Services, ",") != "a,b" ||
		c.WireMock.Advance != "manual" || !c.Microcks.Stateless || c.OutDir != "o" {
		t.Fatalf("config: %+v", c)
	}
}

func TestHelpers(t *testing.T) {
	med, sg, derived, ok := lognormalOf(&Latency{P50: 80, P95: 215})
	if !ok || !derived || med != 80 || sg < 0.59 || sg > 0.61 {
		t.Fatalf("lognormalOf = %v %v %v %v", med, sg, derived, ok)
	}
	if _, _, _, ok := lognormalOf(nil); ok {
		t.Fatal("nil latency")
	}
	body, list, ok := shapeAt(Ref{Path: "$.items[*]"}, nil)
	if !ok || !list || !bytes.Contains(marshalJSON(body), []byte(`"items": []`)) {
		t.Fatalf("shapeAt list: %v", body)
	}
	if _, _, ok := shapeAt(Ref{Path: "$"}, nil); ok {
		t.Fatal("single shape without item must be absent")
	}
	b, _, _ := shapeAt(Ref{Path: "$.data.rows[*]"}, []map[string]any{{"a": "b"}})
	if string(bytes.Join(bytes.Fields(marshalJSON(b)), nil)) != `{"data":{"rows":[{"a":"b"}]}}` {
		t.Fatalf("nested shape: %s", marshalJSON(b))
	}
	m := map[string]any{}
	setPath(m, "delivery.eta", "x")
	if v, _ := getPath(m, "delivery.eta"); v != "x" {
		t.Fatal("setPath/getPath")
	}
	if detUUID("a", "b") != detUUID("a", "b") || detUUID("a", "b") == detUUID("a", "c") {
		t.Fatal("detUUID")
	}
}
