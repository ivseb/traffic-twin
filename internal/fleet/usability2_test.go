package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// A source that reports inbound_not_captured (the zero-code start found no web app to wrap)
// gets the problem of the same name: the service itself is missing from the console otherwise
// and nothing says why.
func TestInboundNotCapturedIsAProblem(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenGroup, "sdk-python")
	s := e.enrollSource(nt.Token, "sdk-python", "shop-api")
	s.heartbeat("capturing", 0)
	var one SourceStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	for _, p := range one.Problems {
		if p.Code == CodeInboundNotCaptured {
			t.Fatalf("a healthy source has the problem: %+v", one.Problems)
		}
	}
	s.lastErrors = []map[string]string{{"code": CodeInboundNotCaptured, "at": time.Now().UTC().Format(time.RFC3339)}}
	s.heartbeat("capturing", 0)
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	var got *Problem
	for i := range one.Problems {
		if one.Problems[i].Code == CodeInboundNotCaptured {
			got = &one.Problems[i]
		}
	}
	if got == nil || !strings.Contains(got.Hint, "traffic_twin.install(app)") {
		t.Fatalf("problems: %+v", one.Problems)
	}
	// The onboarding wizard shows it too.
	var ob OnboardingStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &ob)
	found := false
	for _, p := range ob.Problems {
		found = found || p.Code == CodeInboundNotCaptured
	}
	if !found {
		t.Fatalf("onboarding problems: %+v", ob.Problems)
	}
}

// The Python snippet is what the SDK really supports: the wheel of the kit, the "run" runner,
// and the one line for an app that cannot be wrapped by itself.
func TestPythonSnippetIsCorrect(t *testing.T) {
	sn := Snippets("sdk-python", "https://tt.example:4318", "tte_x", "pizzeria-orders")
	if len(sn) < 2 || sn[0].ID != "python" || sn[1].ID != "python-code" {
		t.Fatalf("snippets: %+v", sn)
	}
	main := sn[0].Text
	for _, want := range []string{"pip install ./traffic_twin-<version>-py3-none-any.whl", "python -m traffic_twin run -- uvicorn app:app",
		"TT_ENROLL_URL=https://tt.example:4318", "TT_SERVICE_NAME=pizzeria-orders", "TT_HMAC_KEY_FILE="} {
		if !strings.Contains(main, want) {
			t.Errorf("python snippet lacks %q:\n%s", want, main)
		}
	}
	for _, bad := range []string{"pip install traffic-twin\n", "traffic_twin.run"} {
		if strings.Contains(main, bad) {
			t.Errorf("python snippet still has %q:\n%s", bad, main)
		}
	}
	if !strings.Contains(sn[1].Text, "traffic_twin.install(app)") {
		t.Errorf("code snippet: %s", sn[1].Text)
	}
}

func principal(name string) *auth.Principal {
	return &auth.Principal{UserID: "usr_" + name, DisplayName: name, Roles: []auth.Role{auth.RoleOperator}}
}

// Two "Gemella" in a row: the second one adds to the draft of the first instead of creating a
// sibling built on the same version (approving one would make the other "remove" its service).
func TestSecondTwinFoldsIntoThePendingDraft(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.activateV1()
	ctx := context.Background()
	v2, err := e.fleet.ProposeHostTwin(ctx, principal("olivia"), "localhost:9301", HostTwinRequest{PolicyID: "p-shop", Service: "payments", Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || len(v2.Supersedes) != 0 {
		t.Fatalf("first twin: %+v", v2)
	}
	v3, err := e.fleet.ProposeHostTwin(ctx, principal("olivia"), "localhost:9302", HostTwinRequest{PolicyID: "p-shop", Service: "delivery", Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if v3.Version != 3 || len(v3.Supersedes) != 1 || v3.Supersedes[0] != 2 {
		t.Fatalf("second twin must fold v2: %+v", v3)
	}
	a, err := ParseAuthor([]byte(v3.AuthorYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Services["payments"]; !ok {
		t.Fatalf("v3 lost the first twin:\n%s", v3.AuthorYAML)
	}
	if _, ok := a.Services["delivery"]; !ok {
		t.Fatalf("v3 has no second twin:\n%s", v3.AuthorYAML)
	}
	for _, d := range v3.Diff {
		if d.Change == "removed" {
			t.Fatalf("the merged draft removes something: %+v", d)
		}
	}
	old, err := e.fleet.GetPolicyVersion(ctx, "p-shop", 2)
	if err != nil || old.Status != StatusSuperseded {
		t.Fatalf("v2 must be superseded: %+v %v", old, err)
	}
	// Exactly one pending draft remains, and approving it activates both services.
	drafts := 0
	vs, _ := e.fleet.ListPolicies(ctx)
	for _, v := range vs {
		if v.Status == StatusDraft {
			drafts++
		}
	}
	if drafts != 1 {
		t.Fatalf("pending drafts: %d", drafts)
	}
	e.must(e.approve("bob", *v3, nil), 200)
	var act PolicyVersion
	e.must(e.approve("carol", *v3, nil), 200).json(t, &act)
	if act.Status != StatusActive {
		t.Fatalf("not active: %+v", act)
	}
	// The same service twice is still refused (and names the problem).
	if _, err := e.fleet.ProposeHostTwin(ctx, principal("olivia"), "localhost:9301", HostTwinRequest{PolicyID: "p-shop", Service: "payments", Scheme: "http"}); err == nil {
		t.Fatal("a second twin of the same service must fail")
	}
}

// A pending draft that no longer builds on the active version (its diff removes things) is not
// used as the base: the new draft starts from the active version.
func TestStaleDraftIsNotABase(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.activateV1()
	ctx := context.Background()
	// A host-twin draft (v2) made before another one (v3, which we approve): v2 is now stale.
	v2, err := e.fleet.ProposeHostTwin(ctx, principal("olivia"), "localhost:9301", HostTwinRequest{PolicyID: "p-shop", Service: "payments", Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	other := policyV1 + "  other-api:\n    match: { inbound: true }\n"
	v3 := e.propose("olivia", other)
	e.must(e.approve("bob", v3, nil), 200)
	if cur, _ := e.fleet.GetPolicyVersion(ctx, "p-shop", v3.Version); cur.Status != StatusActive {
		e.must(e.approve("carol", v3, nil), 200)
	}
	st, err := e.fleet.GetPolicyVersion(ctx, "p-shop", v2.Version)
	if err != nil {
		t.Fatal(err)
	}
	removes := false
	for _, d := range st.Diff {
		removes = removes || d.Change == "removed"
	}
	if !removes {
		t.Skip("the setup did not make v2 stale")
	}
	v4, err := e.fleet.ProposeHostTwin(ctx, principal("olivia"), "localhost:9302", HostTwinRequest{PolicyID: "p-shop", Service: "delivery", Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v4.Supersedes) != 0 {
		t.Fatalf("a stale draft must not be folded: %+v", v4)
	}
	a, _ := ParseAuthor([]byte(v4.AuthorYAML))
	if _, ok := a.Services["payments"]; ok {
		t.Fatalf("the stale draft leaked into v4:\n%s", v4.AuthorYAML)
	}
}

func TestSamplingAdvice(t *testing.T) {
	// 10 users sampled at 5 %: about 200 users in the traffic; k=20 wants 40 sampled: ask for 20 %.
	sa := samplingAdvice(500, 10, "subject", 20)
	if sa.Enough || sa.PopulationEstimate != 200 || sa.SuggestedBP != 2000 || sa.TargetSubjects != 40 {
		t.Fatalf("advice: %+v", sa)
	}
	if !strings.Contains(sa.Message, "10 < k=20") || !strings.Contains(sa.Message, "20%") {
		t.Fatalf("message: %s", sa.Message)
	}
	// Enough users: nothing to change.
	if sa := samplingAdvice(500, 60, "subject", 20); !sa.Enough || sa.SuggestedBP != 500 {
		t.Fatalf("enough: %+v", sa)
	}
	// Too few users even at 100 %: wait, do not promise a rate that would not help.
	sa = samplingAdvice(1000, 3, "subject", 20)
	if sa.Enough || sa.PopulationEstimate != 30 || sa.SuggestedBP != 10000 || !strings.Contains(sa.Message, "wait for more traffic") {
		t.Fatalf("small population: %+v", sa)
	}
	// The suggestion never lowers the rate, and is a whole percent.
	if sa := samplingAdvice(3000, 25, "subject", 20); sa.SuggestedBP < 3000 || sa.SuggestedBP%100 != 0 {
		t.Fatalf("not lower: %+v", sa)
	}
	if sa := samplingAdvice(500, 0, "none", 20); sa.Enough || sa.SuggestedBP != 500 {
		t.Fatalf("nothing seen: %+v", sa)
	}
	// Usability 3: 34 users at 12 % is below the target of 40, but not below k=20.
	sa = samplingAdvice(1200, 34, "subject", 20)
	if sa.Enough || strings.Contains(sa.Message, "< k=") || !strings.Contains(sa.Message, "34, at least 40 wanted") {
		t.Fatalf("message contradicts itself: %s", sa.Message)
	}
	// Without identity.subject users cannot be counted.
	sa = samplingAdvice(1500, 0, "no_identity", 20)
	if sa.Enough || sa.SampledSubjects != 0 || sa.SuggestedBP != 1500 || !strings.Contains(sa.Message, "cannot be counted") {
		t.Fatalf("no identity: %+v", sa)
	}
}

func TestAssistSamplingAndDraft(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.activateV1()
	e.fleet.SetDiscoverySource(fakeDiscovery{
		ops:      []DiscoveredOp{{Service: "shop-api", Op: "POST /orders", Inbound: true, Calls: 400, RawOps: []string{"POST /orders"}}},
		subjects: 8,
	})
	var out AssistResult
	e.must(e.as("olivia", "GET", "/api/v1/fleet/policies/p-shop/assist", nil), 200).json(t, &out)
	sa := out.Sampling
	if sa == nil || sa.CurrentBP != 500 || sa.SampledSubjects != 8 || sa.Enough || sa.KMin != DefaultKMin || sa.SuggestedBP != 2500 {
		t.Fatalf("sampling advice: %+v", sa)
	}
	// The advice becomes a draft: sampling.rate in the author document, with the opening approvals.
	bp := sa.SuggestedBP
	var v PolicyVersion
	e.must(e.as("olivia", "POST", "/api/v1/fleet/policies/p-shop/assist/draft", map[string]any{"sampling_rate_bp": bp, "services": []any{}}), 201).json(t, &v)
	a, err := ParseAuthor([]byte(v.AuthorYAML))
	if err != nil {
		t.Fatalf("%v\n%s", err, v.AuthorYAML)
	}
	if a.Sampling == nil || a.Sampling.Rate != "0.25" {
		t.Fatalf("sampling in the draft: %+v\n%s", a.Sampling, v.AuthorYAML)
	}
	if v.Classification != Opening {
		t.Fatalf("raising the sampling opens data: %+v", v)
	}
	if r := e.as("olivia", "POST", "/api/v1/fleet/policies/p-shop/assist/draft", map[string]any{"dry_run": true, "sampling_rate_bp": 0, "services": []any{}}); r.code != 422 || r.errCode() != "invalid_sampling" {
		t.Fatalf("invalid rate: %d %s", r.code, r.body)
	}
}
