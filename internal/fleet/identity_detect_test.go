package fleet

import (
	"strings"
	"testing"
)

// syntheticDiscovery is invented inbound traffic: 2000 calls over two
// operations of one service, with a per-user header whose name says
// nothing (x-qz-ref), and distractors: a request id with a made-up name
// (unique per call), a tenant (few values), a timestamp, a credential-like
// header, a cookie and the standard protocol headers.
func syntheticDiscovery() *Discovery {
	ops := []DiscoveredOp{
		{Service: "app-api", Op: "GET /items/{id}", Inbound: true, Calls: 1200},
		{Service: "app-api", Op: "POST /items", Inbound: true, Calls: 800},
		{Service: "host:api.partner.example", Op: "GET /v1/x", Calls: 500},
	}
	f := func(op, path string, distinct int, observed int64, shape string) DiscoveredField {
		return DiscoveredField{Service: "app-api", Op: op, Path: path, Distinct: distinct, Observed: observed, Shape: shape}
	}
	const get, post = "GET /items/{id}", "POST /items"
	fields := []DiscoveredField{
		// Per user: about 150 users, repeated calls.
		f(get, "req.headers.x-qz-ref", 140, 1200, "drop:str:uuid"),
		f(post, "req.headers.x-qz-ref", 120, 800, "drop:str:uuid"),
		// Request id with a name that says nothing: a new value on every call.
		f(get, "req.headers.x-op-ref", 1195, 1200, "drop:str:hex"),
		f(post, "req.headers.x-op-ref", 798, 800, "drop:str:hex"),
		// Tenant: four values.
		f(get, "req.headers.x-tenant", 4, 1200, "drop:str:l8"),
		f(post, "req.headers.x-tenant", 4, 800, "drop:str:l8"),
		// A time stamp: many values but not an identity.
		f(get, "req.headers.x-sent-at", 900, 1200, "drop:str:datetime"),
		// A credential-like header that repeats per user.
		f(get, "req.headers.x-session-key", 150, 1200, "drop:str:l32"),
		// A cookie that repeats per user.
		f(get, "req.cookies.uid", 150, 1200, "drop:str:l32"),
		// Protocol and trace headers never show.
		f(get, "req.headers.user-agent", 60, 1200, "drop:str:l128"),
		f(get, "req.headers.content-length", 300, 1200, "drop:str:digits"),
		f(get, "req.headers.traceparent", 1200, 1200, "drop:str:l128"),
		// An outbound call is not who the user is.
		{Service: "host:api.partner.example", Op: "GET /v1/x", Path: "req.headers.x-partner-user", Distinct: 100, Observed: 500, Shape: "drop:str:uuid"},
	}
	return &Discovery{Ops: ops, Fields: fields, Auth: map[string]AuthStat{"app-api": {Calls: 2000}}}
}

func candidate(cs []IdentityCandidate, from, name string) *IdentityCandidate {
	for i := range cs {
		if cs[i].From == from && cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

func TestDetectIdentityFromData(t *testing.T) {
	disc := syntheticDiscovery()
	cs, best := detectIdentity(disc)
	if best == nil || best.From != "header" || best.Name != "x-qz-ref" || best.JWTClaim != "" {
		t.Fatalf("best: %+v (%+v)", best, cs)
	}
	user := candidate(cs, "header", "x-qz-ref")
	if user == nil || !user.Best || user.Excluded != "" || !user.ObserveSafe || user.Score < identityMinScore || cs[0].Name != "x-qz-ref" {
		t.Fatalf("user header: %+v", cs)
	}
	for _, sig := range []string{sigRepeats, sigIDShape, sigMostCalls} {
		if !strings.Contains(strings.Join(user.Signals, ","), sig) {
			t.Errorf("user header signals %v lack %s", user.Signals, sig)
		}
	}
	for name, want := range map[string]string{"x-op-ref": exclPerCall, "x-tenant": exclFewValues, "x-sent-at": exclShape, "x-session-key": exclCredential} {
		c := candidate(cs, "header", name)
		if c == nil || c.Excluded != want || c.Best {
			t.Errorf("%s: want excluded %s, got %+v", name, want, c)
		}
	}
	if c := candidate(cs, "cookie", "uid"); c == nil || c.Excluded != exclCookie || c.ObserveSafe {
		t.Errorf("cookie: %+v", c)
	}
	for _, name := range []string{"user-agent", "content-length", "traceparent", "x-partner-user"} {
		if c := candidate(cs, "header", name); c != nil {
			t.Errorf("%s must not be a candidate: %+v", name, c)
		}
	}

	// A name hint is weak: the same header with a person-like name scores
	// higher, but a request id named like a user is still a request id.
	hinted := syntheticDiscovery()
	for i := range hinted.Fields {
		hinted.Fields[i].Path = strings.Replace(hinted.Fields[i].Path, "x-op-ref", "x-user-ref", 1)
	}
	cs2, best2 := detectIdentity(hinted)
	if best2 == nil || best2.Name != "x-qz-ref" {
		t.Fatalf("a request id named like a user won: %+v", cs2)
	}
	if c := candidate(cs2, "header", "x-user-ref"); c == nil || c.Excluded != exclPerCall {
		t.Fatalf("request id named like a user: %+v", c)
	}

	// The bearer JWT on most calls wins: its claim sub.
	disc.Auth["app-api"] = AuthStat{Calls: 2000, WithAuthorization: 1900}
	cs3, best3 := detectIdentity(disc)
	if best3 == nil || best3.Name != "authorization" || best3.JWTClaim != "sub" || cs3[0].Name != "authorization" || !cs3[0].Best {
		t.Fatalf("jwt: %+v %+v", best3, cs3)
	}
	if c := candidate(cs3, "header", "x-qz-ref"); c == nil || c.Best {
		t.Fatalf("only one best: %+v", c)
	}

	// A header of raw JWTs: its claim sub.
	jwtHdr := syntheticDiscovery()
	jwtHdr.Fields = append(jwtHdr.Fields, DiscoveredField{Service: "app-api", Op: "GET /items/{id}", Path: "req.headers.x-id-token", Distinct: 300, Observed: 1200, Shape: "drop:str:jwt"},
		DiscoveredField{Service: "app-api", Op: "POST /items", Path: "req.headers.x-id-token", Distinct: 250, Observed: 800, Shape: "drop:str:jwt"})
	if _, b := detectIdentity(jwtHdr); b == nil || b.Name != "x-id-token" || b.JWTClaim != "sub" {
		t.Fatalf("jwt header: %+v", b)
	}

	// Nothing convincing: no pick.
	none := &Discovery{Ops: disc.Ops, Fields: []DiscoveredField{
		{Service: "app-api", Op: "GET /items/{id}", Path: "req.headers.x-tenant", Distinct: 3, Observed: 1200, Shape: "drop:str:l8"},
	}}
	if _, b := detectIdentity(none); b != nil {
		t.Fatalf("no candidate expected: %+v", b)
	}
}

func TestPersonNameHint(t *testing.T) {
	for _, n := range []string{"x-user-id", "personid", "customer-no", "x-codice-utente", "x-kunden-nr", "x-uid", "member", "x-usuario"} {
		if !personNameHint(n) {
			t.Errorf("%s hints a person", n)
		}
	}
	for _, n := range []string{"x-tenant", "x-qz-ref", "x-region", "x-subway-line"} {
		if personNameHint(n) {
			t.Errorf("%s does not hint a person", n)
		}
	}
}

// The console sets the identity: a header that is not a credential applies
// at once (observe-safe, audited); a cookie waits for the approvals; the
// observe pass never replaces the person's choice.
func TestSetIdentityFromConsole(t *testing.T) {
	e := newObserveEnv(t)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	e.fleet.SetDiscoverySource(fakeDiscovery{ops: syntheticDiscovery().Ops, fields: syntheticDiscovery().Fields})

	var st ObserveStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.IdentityBest == nil || st.IdentityBest.Name != "x-qz-ref" || len(st.IdentityCandidates) == 0 || st.IdentityCandidates[0].Name != "x-qz-ref" {
		t.Fatalf("observe status ranking: %+v %+v", st.IdentityBest, st.IdentityCandidates)
	}

	var v PolicyVersion
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", map[string]any{"from": "header", "name": "X-Kunden-Nr"}), 200).json(t, &v)
	if v.Status != StatusActive || v.OpensValues || v.ApprovalsRequired != 0 {
		t.Fatalf("a header identity applies at once: %+v", v)
	}
	a := activeOf(t, e, "p-shop")
	if !strings.Contains(a.AuthorYAML, "x-kunden-nr") {
		t.Fatalf("identity not in the policy: %s", a.AuthorYAML)
	}
	if !strings.Contains(e.auditDump(), `"policy.identity_set"`) {
		t.Fatal("the identity choice is not audited")
	}
	// Replacing it with another header is observe-safe too.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", map[string]any{"from": "header", "name": "authorization", "jwt_claim": "member_no"}), 200).json(t, &v)
	if v.Status != StatusActive {
		t.Fatalf("a JWT claim applies at once: %+v", v)
	}
	// The observe pass keeps the person's choice.
	cur, err := ParseAuthor([]byte(activeOf(t, e, "p-shop").AuthorYAML))
	if err != nil {
		t.Fatal(err)
	}
	req := observeDecisions(&AssistResult{IdentityBest: &AssistIdentity{From: "header", Name: "x-qz-ref"}}, cur, nil, codeOptions{on: true, alnum: true})
	if req.Identity != nil {
		t.Fatalf("the observe pass replaced the person's choice: %+v", req.Identity)
	}
	// A cookie needs the opening approvals.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", map[string]any{"from": "cookie", "name": "uid"}), 200).json(t, &v)
	if v.Status != StatusDraft || !v.OpensValues || v.ApprovalsRequired == 0 {
		t.Fatalf("a cookie waits for approvals: %+v", v)
	}
	// Invalid input; a group without policy.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", map[string]any{"from": "query", "name": "u"}), 422)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{"name": "empty", "allowed_service_names": []string{"e-api"}}), 201)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/empty/identity", map[string]any{"name": "x-user-id"}), 409)
}
