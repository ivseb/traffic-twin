package gate

import (
	"context"
	"strings"
	"testing"
)

func TestNoApprovedRulesWarnsButPasses(t *testing.T) {
	ctx := context.Background()
	res, err := Run(ctx, input(okWorld, &fakeMatcher{}))
	if err != nil {
		t.Fatal(err)
	}
	if st := status(res); st[CheckRulesApproved] != CheckPass || !res.Passed() {
		t.Fatalf("pack with rules: %v", st)
	}

	in := input(okWorld, &fakeMatcher{})
	in.Files["rules.json"] = []byte(`{"format":"tt.rules/v1","entities":[],"rules":[]}`)
	res, err = Run(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("a warning must not fail the gate: %+v", res.Report.Checks)
	}
	if st := status(res); st[CheckRulesApproved] != CheckWarn {
		t.Fatalf("expected a warning: %v", st)
	}
	f := string(res.Report.File())
	if !strings.Contains(f, `"id":"rules-approved"`) || !strings.Contains(f, `"status":"warn"`) || !strings.Contains(f, `"verdict":"pass"`) {
		t.Fatal(f)
	}
}
