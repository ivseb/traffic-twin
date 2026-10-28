package gate

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
)

// Invented test values only.

type fakeMatcher struct {
	real  map[string]bool
	calls int
}

func (f *fakeMatcher) Match(_ context.Context, _ []client.PolicyRef, cands []client.Candidate) (*client.MatchResult, error) {
	f.calls++
	r := &client.MatchResult{Matches: make([]bool, len(cands))}
	for i, c := range cands {
		b, _ := c.MarshalJSON()
		if f.real[strings.Trim(string(b), `"`)] {
			r.Matches[i] = true
			r.Positives++
		}
	}
	return r, nil
}

func TestDetectors(t *testing.T) {
	bad := map[string]string{
		"mario.rossi@gmail.com":                    "e-mail",
		"see https://api.realshop.it/x":            "URL",
		"IT60X0542811101000000123456":              "IBAN",
		"4111 1111 1111 1111":                      "Luhn",
		"RSSMRA85T10A562S":                         "fiscal",
		"from 8.8.8.8":                             "IP",
		"2a00:1450:4001:82a::200e":                 "IP",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc": "JWT",
		"+39 347 123 4567":                         "phone",
		"id 12345678901":                           "digit",
	}
	for s, want := range bad {
		r := detect(s)
		if len(r) == 0 || !strings.Contains(strings.Join(r, ";"), want) {
			t.Errorf("%q: %v (want %s)", s, r, want)
		}
	}
	good := []string{"giulia.neri@example.com", "a@shop.example", "https://shop.example/r/1", "+39 555 123 4567",
		"192.0.2.10", "2001:db8::1", "ORD-SYN-0042", "2026-10-18T09:00:00Z", "CONFIRMED", "syn-luna-0042", "3.1.0",
		"550e8400-e29b-41d4-a716-446655440000", "SHIPMENT_NOT_FOUND", "GET /orders/{id}"}
	for _, s := range good {
		if r := detect(s); len(r) > 0 {
			t.Errorf("%q flagged: %v", s, r)
		}
	}
}

func files(world string) map[string][]byte {
	return map[string][]byte{
		"contracts/shop-api.openapi.json": []byte(`{"openapi":"3.1.0","paths":{"/orders":{"post":{"operationId":"createOrder","responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"string"},"status":{"type":"string","enum":["CONFIRMED"]}}}}}}}}}}}`),
		"rules.json":                      []byte(`{"format":"tt.rules/v1","entities":[{"name":"order","service":"shop-api","id_domain":"order","id_field":"id","id_prefix":"ORD-SYN-"}],"rules":[{"id":"r-0001","kind":"batch","status":"approved","title":"t","schedule":"0 2 * * *","entity":"order","set":{"status":"CONFIRMED"},"fraction":1,"evidence":{"counts":{"runs":0,"entities_changed":40}}}]}`),
		"world.jsonl":                     []byte(`{"format":"tt.world/v1","seed":1,"t0":"2026-10-19T00:00:00Z","type":"meta"}` + "\n" + world + "\n"),
	}
}

const okWorld = `{"archetype":"arch-01","id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi"},"type":"customer"}`

func input(world string, m Matcher) *Input {
	return &Input{PackID: "pk-test-1", KMin: 20, Files: files(world), Matcher: m, Policies: []client.PolicyRef{{ID: "p-shop", Version: 1}},
		Archetypes: []ArchetypeSize{{ID: "arch-01", Size: 25}},
		Prov:       Provenance{Synthetic: map[string]bool{"CUS-SYN-0001": true, "anna.rossi@example.com": true, "Anna Rossi": true, "2026-10-19T00:00:00Z": true}, Declared: map[string]int64{"CONFIRMED": 50}}}
}

func status(r *Result) map[string]string {
	out := map[string]string{}
	for _, c := range r.Report.Checks {
		out[c.ID] = c.Status
	}
	return out
}

func TestGatePassAndFailures(t *testing.T) {
	ctx := context.Background()
	res, err := Run(ctx, input(okWorld, &fakeMatcher{}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("clean pack failed: %+v", res.Report.Checks)
	}
	if !strings.Contains(string(res.Report.File()), `"verdict":"pass"`) {
		t.Fatal(string(res.Report.File()))
	}

	// A real value (keyguard says so) injected in the world.
	w := strings.Replace(okWorld, `"name":"Anna Rossi"`, `"name":"ORD-2026-000184"`, 1)
	res, _ = Run(ctx, input(w, &fakeMatcher{real: map[string]bool{"ORD-2026-000184": true}}))
	st := status(res)
	if res.Passed() || st[CheckReverseHMAC] != "fail" || st[CheckProvenance] != "fail" {
		t.Fatalf("real value passed: %v", st)
	}
	for _, c := range res.Report.Checks {
		for _, f := range c.Findings {
			if strings.Contains(f.Pointer+f.Reason, "ORD-2026") {
				t.Fatal("finding leaks the value")
			}
		}
		if c.ID == CheckReverseHMAC && (len(c.Findings) == 0 || c.Findings[0].File != "world.jsonl" || c.Findings[0].Pointer != "2:/profile/name") {
			t.Fatalf("reverse-hmac findings %+v", c.Findings)
		}
	}

	// A real-looking e-mail not tagged synthetic.
	w = strings.Replace(okWorld, "anna.rossi@example.com", "anna.rossi@gmail.com", 1)
	res, _ = Run(ctx, input(w, &fakeMatcher{}))
	st = status(res)
	if st[CheckPII] != "fail" || st[CheckProvenance] != "fail" || st[CheckReverseHMAC] != "pass" {
		t.Fatalf("e-mail: %v", st)
	}

	// Archetype below k, and a published count below k.
	in := input(okWorld, &fakeMatcher{})
	in.Archetypes[0].Size = 5
	in.Files["rules.json"] = []byte(strings.Replace(string(in.Files["rules.json"]), `"entities_changed":40`, `"entities_changed":7`, 1))
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("k: %v", st)
	}
	n := 0
	for _, c := range res.Report.Checks {
		if c.ID == CheckK {
			n = len(c.Findings)
		}
	}
	if n < 3 { // archetype size, its use in world.jsonl, the count
		t.Fatalf("k findings: %d", n)
	}

	// Enum value without enough subjects.
	in = input(okWorld, &fakeMatcher{})
	in.Prov.Declared["CONFIRMED"] = 3
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("enum k: %v", st)
	}
}

func TestMeasure(t *testing.T) {
	r := Measure(&RiskInput{
		Classes: []Class{{Vector: []string{"a", "x"}, Count: 1}, {Vector: []string{"a", "y"}, Count: 29}, {Vector: []string{"b", "y"}, Count: 20}},
		Archetypes: []ArchetypeRisk{
			{ID: "arch-01", Vector: []string{"a", "y"}, Members: []Class{{Vector: []string{"a", "x"}, Count: 1}, {Vector: []string{"a", "y"}, Count: 29}}},
			{ID: "arch-02", Vector: []string{"b", "y"}, Members: []Class{{Vector: []string{"b", "y"}, Count: 20}}},
		}}, 20)
	if r.Profiles != 50 || r.MinArchetypeSize != 20 || r.UniquenessRate != 0.02 || r.MaxHomogeneity != 1 || r.SinglingOutRate != 0 || r.ExactMatchShare != 0.98 {
		t.Fatalf("%+v", r)
	}
}
