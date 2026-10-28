package gate

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

// A pack whose contract declares an id format for domain order and whose
// world has an order with an id of that format (invented values).
func formatInput(format string, m Matcher) (*Input, string) {
	t := idfmt.MustParse("NNNNNNNNNNNN")
	if format != "" {
		t = idfmt.MustParse(format)
	}
	id := t.ID(1, "order", nil)
	in := input(okWorld+"\n"+`{"customer_id":"CUS-SYN-0001","entity":"order","id":"`+id+`","state":{"id":"`+id+`","status":"CONFIRMED"},"type":"entity"}`, m)
	in.Files["contracts/shop-api.openapi.json"] = []byte(`{"openapi":"3.1.0","paths":{"/orders":{"post":{"operationId":"createOrder","responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"string","x-tt-value":{"domain":"order","id_format":"` + t.String() + `","kind":"id"}},"status":{"type":"string","enum":["CONFIRMED"]}}}}}}}}}}}`)
	in.Prov.Synthetic[id] = true
	return in, id
}

func TestIDFormatPasses(t *testing.T) {
	// 12 digits are a "long digit run" to the detectors;
	// a generated id of a declared format is not personal data.
	in, _ := formatInput("", &fakeMatcher{})
	res, err := Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("pack with an id format failed: %+v", res.Report.Checks)
	}
	// The same string without generator provenance is still flagged.
	in, id := formatInput("", &fakeMatcher{})
	delete(in.Prov.Synthetic, id)
	res, _ = Run(context.Background(), in)
	if st := status(res); st[CheckProvenance] != "fail" || st[CheckPII] != "fail" {
		t.Fatalf("untagged id: %v", st)
	}
}

func TestIDFormatNeverEqualsRealToken(t *testing.T) {
	// An id of the world equal to a real value fails, as any string.
	in, id := formatInput("", nil)
	in.Matcher = &fakeMatcher{real: map[string]bool{id: true}}
	res, _ := Run(context.Background(), in)
	if status(res)[CheckReverseHMAC] != "fail" {
		t.Fatal("a world id equal to a real token passed")
	}
	// An id the mock would generate later (not in the pack) too.
	tpl := idfmt.MustParse("NNNNNNNNNNNN")
	later := tpl.ID(500, "order", nil)
	in, _ = formatInput("", nil)
	in.Matcher = &fakeMatcher{real: map[string]bool{later: true}}
	res, _ = Run(context.Background(), in)
	found := false
	for _, c := range res.Report.Checks {
		if c.ID != CheckReverseHMAC {
			continue
		}
		for _, f := range c.Findings {
			if f.File == idFormatsFile && f.Pointer == "/order" && strings.Contains(f.Reason, "id format") {
				found = true
			}
			if strings.Contains(f.Pointer+f.Reason, later) {
				t.Fatal("finding leaks the value")
			}
		}
	}
	if !found || res.Passed() {
		t.Fatalf("a run-time id equal to a real token passed: %+v", res.Report.Checks)
	}
}

func TestIDFormatProvenance(t *testing.T) {
	in, _ := formatInput("", &fakeMatcher{})
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(string(in.Files["contracts/shop-api.openapi.json"]), `"id_format":"NNNNNNNNNNNN"`, `"id_format":"NN?"`, 1))
	res, _ := Run(context.Background(), in)
	if status(res)[CheckProvenance] != "fail" {
		t.Fatal("an invalid id format must fail provenance")
	}
}
