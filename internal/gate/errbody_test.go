package gate

import (
	"context"
	"strings"
	"testing"
)

// Error bodies typed by a person (rules 1.10 respond.body, preset faults
// body) pass provenance and are checked by the personal data detectors.
func TestErrorBodies(t *testing.T) {
	scen := func(body string) []byte {
		return []byte(`{"format":"tt.scenarios/v1","scenarios":[{"id":"down","name":"Down","faults":{"mode":"custom","rules":[{"service":"shop-api","op":"POST /orders","status":503,"p":1,"body":` + body + `}]}}]}`)
	}
	in := input(okWorld, &fakeMatcher{})
	in.Prov.Text = map[string]bool{"down": true, "Down": true}
	in.Files["scenarios.json"] = scen(`{"code":"E-UNAVAILABLE","message":"Servizio non disponibile, riprova"}`)
	res, err := Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("clean error body failed: %+v", res.Report.Checks)
	}
	in = input(okWorld, &fakeMatcher{})
	in.Files["scenarios.json"] = scen(`{"code":"E1","message":"scrivi a mario.rossi@azienda.it"}`)
	res, _ = Run(context.Background(), in)
	if status(res)[CheckPII] != "fail" {
		t.Fatalf("an e-mail in an error body passed: %+v", res.Report.Checks)
	}
	// a respond effect body in the rules
	in = input(okWorld, &fakeMatcher{})
	in.Files["rules.json"] = []byte(strings.Replace(string(in.Files["rules.json"]), `"rules":[`,
		`"rules":[{"id":"r-0002","kind":"causal","status":"approved","title":"t","cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]}},"effects":[{"id":"gone","respond":{"service":"shop-api","op":"POST /orders","status":409,"body":{"error":"Ordine duplicato, chiama +39 347 1234567"}},"after":"0s"}],"outcomes":[{"name":"happy","p":1,"effects":["gone"]}],"evidence":{"counts":{"causes":0}}},`, 1))
	res, _ = Run(context.Background(), in)
	if status(res)[CheckPII] != "fail" {
		t.Fatalf("a phone number in a respond body passed: %+v", res.Report.Checks)
	}
}
