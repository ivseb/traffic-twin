package gate

import (
	"context"
	"strings"
	"testing"
)

// Security review r4 (k thresholds, linked fields, manual rules). Invented
// values only.

// A keep value observed for fewer than k_min subjects never reaches a pack
// through the world or a rule literal: contract.k_min may be lower than
// gate.k_min (config allows it), so the world generator can see values the
// pack contract filters out. The gate is the last line of defence.
func TestGateKRareDeclaredValueInWorldAndRules(t *testing.T) {
	ctx := context.Background()
	entity := `{"type":"entity","entity":"order","id":"ORD-SYN-0001","customer_id":"CUS-SYN-0001","state":{"status":"PARTIAL_HOLD"}}`

	in := input(okWorld+"\n"+entity, &fakeMatcher{})
	in.Prov.Synthetic["ORD-SYN-0001"] = true
	in.Prov.Declared["PARTIAL_HOLD"] = 40
	res, err := Run(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("a value of 40 subjects failed: %+v", res.Report.Checks)
	}

	in = input(okWorld+"\n"+entity, &fakeMatcher{})
	in.Prov.Synthetic["ORD-SYN-0001"] = true
	in.Prov.Declared["PARTIAL_HOLD"] = 5
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("world value of 5 subjects passed k-thresholds: %v", st)
	}
	for _, f := range findingsOf(res, CheckK) {
		if strings.Contains(f.Pointer+f.Reason, "PARTIAL_HOLD") {
			t.Fatal("a finding carries the value")
		}
	}

	// The same rare value as a literal of a rule (set) is refused too.
	in = input(okWorld, &fakeMatcher{})
	in.Files["rules.json"] = []byte(strings.Replace(string(in.Files["rules.json"]), `"set":{"status":"CONFIRMED"}`, `"set":{"status":"PARTIAL_HOLD"}`, 1))
	in.Prov.Declared["PARTIAL_HOLD"] = 5
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("rule literal of 5 subjects passed k-thresholds: %v", st)
	}
	// A rule literal no one observed (written by a person) is not a count.
	in = input(okWorld, &fakeMatcher{})
	in.Files["rules.json"] = []byte(strings.Replace(string(in.Files["rules.json"]), `"set":{"status":"CONFIRMED"}`, `"set":{"status":"ON_HOLD"}`, 1))
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "pass" {
		t.Fatalf("an unobserved manual literal failed k: %v %+v", st, findingsOf(res, CheckK))
	}
}

// at_least is a size class, never an exact count (pack.md 4.2): k_min or a
// power of ten not below it.
func TestGateDependencySizeClassIsNotACount(t *testing.T) {
	ctx := context.Background()
	for _, ok := range []string{"20", "100", "1000"} {
		in := depsInput()
		in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `"at_least":100,`, `"at_least":`+ok+`,`, 1))
		res, _ := Run(ctx, in)
		if st := status(res); st[CheckK] != "pass" {
			t.Errorf("at_least %s: %v %+v", ok, st, findingsOf(res, CheckK))
		}
	}
	for _, bad := range []string{"37", "150", "99", "20.5", "1e2", "-100"} {
		in := depsInput()
		in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `"at_least":100,`, `"at_least":`+bad+`,`, 1))
		res, _ := Run(ctx, in)
		if st := status(res); st[CheckK] != "fail" {
			t.Errorf("at_least %s passed: %v", bad, st)
		}
	}
}

// The example body a respond effect answers with (rules.md 3.6) is a
// contract example: it goes through provenance, PII and k like any other.
func TestGateRespondExampleBody(t *testing.T) {
	ctx := context.Background()
	contract := `{"openapi":"3.1.0","paths":{"/invoices/{id}":{"get":{"operationId":"getInvoice","responses":{"410":{"description":"gone","content":{"application/json":{"schema":{"type":"object","properties":{"code":{"type":"string"}}},"examples":{"invoice-gone":{"value":{"code":"VALUE"}}}}}}}}}}}`
	rules := `{"format":"tt.rules/v1","entities":[],"rules":[{"id":"r-m-0001","origin":"manual","kind":"causal","status":"approved","title":"t","cause":{"service":"billing","op":"POST /orders/{id}/cancel"},"effects":[{"id":"invoice-gone","respond":{"service":"billing","op":"GET /invoices/{id}","status":410,"times":1,"example":"invoice-gone"},"after":"0s"}],"evidence":{"counts":{}}}]}`
	run := func(val string, declared int64) map[string]string {
		in := input(okWorld, &fakeMatcher{})
		in.Files = map[string][]byte{"contracts/billing.openapi.json": []byte(strings.Replace(contract, "VALUE", val, 1)), "rules.json": []byte(rules), "world.jsonl": in.Files["world.jsonl"]}
		if declared > 0 {
			in.Prov.Declared[val] = declared
		}
		res, err := Run(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return status(res)
	}
	if st := run("INVOICE_GONE", 40); st[CheckProvenance] != "pass" || st[CheckK] != "pass" || st[CheckPII] != "pass" {
		t.Fatalf("clean respond example: %v", st)
	}
	if st := run("INVOICE_GONE", 0); st[CheckProvenance] != "fail" {
		t.Errorf("undeclared example value passed provenance: %v", st)
	}
	if st := run("INVOICE_GONE", 3); st[CheckK] != "fail" {
		t.Errorf("example value of 3 subjects passed k: %v", st)
	}
	if st := run("mario.rossi@gmail.com", 40); st[CheckPII] != "fail" {
		t.Errorf("real e-mail in the respond example passed PII: %v", st)
	}
}
