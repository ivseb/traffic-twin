package gate

import (
	"context"
	"strings"
	"testing"
)

// A relative date (pack.md 4.4) is structure: a valid offset passes
// provenance, anything else fails.
func TestDateOffsetProvenance(t *testing.T) {
	c := `{"openapi":"3.1.0","paths":{"/p":{"get":{"operationId":"p","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"renewalDate":{"type":"string","format":"date","x-tt-value":{"date_offset":{"max":"MAX","min":"+30d"},"kind":"bucket","unit":"day"}}}}}}}}}}}}`
	in := input(okWorld, &fakeMatcher{})
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(c, "MAX", "+365d", 1))
	if res, _ := Run(context.Background(), in); !res.Passed() {
		t.Fatalf("%+v", res.Report.Checks)
	}
	in = input(okWorld, &fakeMatcher{})
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(c, "MAX", "2027-01-01", 1))
	if res, _ := Run(context.Background(), in); status(res)[CheckProvenance] != "fail" {
		t.Fatalf("a date in date_offset passed: %+v", res.Report.Checks)
	}
}
