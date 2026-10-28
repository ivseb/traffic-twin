package miner

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ivseb/traffic-twin/internal/policy"
)

func TestDelayJSON(t *testing.T) {
	for _, s := range []string{`"0s"`, `{"min":"2m","max":"10m"}`} {
		var d Delay
		if err := json.Unmarshal([]byte(s), &d); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(d)
		if string(b) != s {
			t.Errorf("round trip %s → %s", s, b)
		}
	}
	if err := validDelay(Delay{Min: "10m", Max: "2m"}); err == nil {
		t.Error("min > max accepted")
	}
	if parseDuration("2d") != 172800 || parseDuration("2w") != -1 {
		t.Error("parseDuration")
	}
}

func validRule() *CausalRule {
	return &CausalRule{ID: "r-0001", Kind: KindCausal, Status: StatusDraft, Title: "t",
		Cause: Cause{Service: "shop-api", Op: "POST /orders", When: When{Status: []int{201}},
			Bind: map[string]Ref{"order": {From: "resp.body", Path: "$.id"}}},
		Effects: []Effect{
			{ID: "a", Entity: "shipment", Create: map[string]any{"orderId": "${order}"}, After: Delay{Single: "0s"}},
			{ID: "b", Entity: "shipment", Target: "a", Set: map[string]any{"status": "X", "ref": "${effect:a}"}, AfterEffect: "a", After: Delay{Single: "1m"}},
		},
		Outcomes: []Outcome{{Name: "happy", P: 0.9, Effects: []string{"a", "b"}}, {Name: "never", P: 0.1, Effects: []string{"a"}}},
		Evidence: CausalEvidence{Counts: CausalCounts{Outcomes: map[string]int{}}}}
}

func TestValidateCrossFieldChecks(t *testing.T) {
	ok := Rule{Causal: validRule()}
	if err := ok.Validate(nil); err != nil {
		t.Fatalf("valid rule: %v", err)
	}
	cases := map[string]func(*CausalRule){
		"sum":           func(r *CausalRule) { r.Outcomes[1].P = 0.2 },
		"unknown":       func(r *CausalRule) { r.Outcomes[0].Effects = append(r.Outcomes[0].Effects, "zz") },
		"branch":        func(r *CausalRule) { r.Outcomes[1].Effects = []string{"b"} },
		"cycle":         func(r *CausalRule) { r.Effects[0].AfterEffect = "b" },
		"effect-ref":    func(r *CausalRule) { r.Effects[0].Create["x"] = "${effect:b}" },
		"unbound":       func(r *CausalRule) { r.Effects[0].Create["x"] = "${missing}" },
		"two-kinds":     func(r *CausalRule) { r.Effects[1].TargetID = "${order}" },
		"bad-target-id": func(r *CausalRule) { r.Effects[1].Target, r.Effects[1].TargetID = "", "${nope}" },
		"bad-id":        func(r *CausalRule) { r.ID = "rule-1" },
		"bad-path":      func(r *CausalRule) { r.Cause.Bind["order"] = Ref{From: "resp.body", Path: "id"} },
	}
	for name, mut := range cases {
		r := validRule()
		mut(r)
		if err := (&Rule{Causal: r}).Validate(nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestIDPrefixAndSlug(t *testing.T) {
	for in, want := range map[string]string{"order": "ORD-SYN-", "shipment": "SHP-SYN-", "customer": "CST-SYN-", "io": "IO-SYN-", "x": "XX-SYN-"} {
		if got := idPrefix(in); got != want || !rePrefix.MatchString(got) {
			t.Errorf("idPrefix(%s) = %s", in, got)
		}
	}
	if slug("IN_TRANSIT") != "in-transit" {
		t.Error(slug("IN_TRANSIT"))
	}
}

func TestPolicyDomains(t *testing.T) {
	p := &policy.Policy{Services: []policy.Service{{Name: "shop-api", Ops: []policy.Op{{Op: "GET /orders/{id}",
		Request:  policy.Part{Path: map[string]policy.Action{"id": {Kind: policy.ActHMAC, Domain: "order"}}},
		Response: policy.Part{Body: []policy.BodyRule{{Path: "$.items[*].id", Action: policy.Action{Kind: policy.ActHMAC}}}}}}}}}
	d := NewPolicyDomains()
	d.Add("sha256:x", p)
	if got, ok := d.Domain("sha256:x", "shop-api", "GET /orders/{id}", 200, "req.path[1]"); !ok || got != "order" {
		t.Errorf("path param: %q %v", got, ok)
	}
	if got, ok := d.Domain("sha256:x", "shop-api", "GET /orders/{id}", 200, "resp.body$.items[*].id"); !ok || got != "id" {
		t.Errorf("default domain: %q %v", got, ok)
	}
	if _, ok := d.Domain("sha256:other", "shop-api", "GET /orders/{id}", 200, "req.path[1]"); ok {
		t.Error("unknown policy resolved")
	}
	if g := guessDomain("GET /customers/{id}/orders", Ref{From: "req.path", Name: "id"}); g != "customer" {
		t.Errorf("guess: %s", g)
	}
	if g := guessDomain("GET /v1/shipments", Ref{From: "req.query", Name: "orderId"}); g != "order" {
		t.Errorf("guess: %s", g)
	}
}
