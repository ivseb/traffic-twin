package keyguard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// observeHMAC is the hmac block of observeBody.
var observeHMAC = `"hmac":{"kid":"k1","epoch":"2026-10"}`

// observeBody compiles an observe-style body: default drop, the onboarding
// windows, plus the given extra members.
func observeBody(t *testing.T, version, seq int64, groups []string, extra string) []byte {
	t.Helper()
	doc := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop",` + observeHMAC + `,"sampling":{"rate":0.1},` +
		`"segments":{"auto_words":true,"auto_words_expires_at":"` + t0.Add(72*3600e9).Format("2006-01-02T15:04:05Z") + `"},` +
		`"discovery":{"enabled":true,"expires_at":"` + t0.Add(72*3600e9).Format("2006-01-02T15:04:05Z") + `"}`
	if extra != "" {
		doc += "," + extra
	}
	doc += "}"
	d := json.NewDecoder(strings.NewReader(doc))
	d.UseNumber()
	var g any
	if err := d.Decode(&g); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(g)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := policy.Compile(a, policy.CompileMeta{Version: version, IssuedSeq: seq, CreatedAt: t0, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

const observeIDs = `"identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)"}},
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}`

func TestSignObserveSafeWithoutApprovals(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	g := []string{"shop"}
	// The starter policy: a first policy that opens no value.
	starter := observeBody(t, 1, 1, g, `"services":{"shop-api":{"match":{"inbound":true}}}`)
	res, err := e.svc.SignPolicy(ctx, starter, "system", nil)
	if err != nil {
		t.Fatalf("starter without approvals: %v", err)
	}
	if res.ApprovalMode != ModeObserve || res.OpensValues == nil || *res.OpensValues {
		t.Fatalf("mode %q opens %v", res.ApprovalMode, res.OpensValues)
	}
	verifyEnvelope(t, e, starter, res)
	// The automatic observe version: hmac on ids and the JWT subject.
	auto := observeBody(t, 2, 2, g, observeIDs)
	if res, err = e.svc.SignPolicy(ctx, auto, "system", nil); err != nil || res.ApprovalMode != ModeObserve {
		t.Fatalf("observe-auto: %v %+v", err, res)
	}
	// A keep never passes without approvals.
	keep := observeBody(t, 3, 3, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}`)
	if _, err := e.svc.SignPolicy(ctx, keep, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("keep without approvals: %v", err)
	}
	// An identity that is not automatic neither.
	cookie := observeBody(t, 3, 3, g, `"identity":{"subject":{"from":"cookie","name":"sid"}}`)
	if _, err := e.svc.SignPolicy(ctx, cookie, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("cookie identity without approvals: %v", err)
	}
	// With the approvals the keep is signed as before.
	if res, err = e.svc.SignPolicy(ctx, keep, "alice", []Approval{appr("bob"), appr("carol")}); err != nil || res.OpensValues == nil || !*res.OpensValues {
		t.Fatalf("keep with approvals: %v %+v", err, res)
	}
	// Once values are kept, adding a group opens them for that group.
	more := observeBody(t, 4, 4, []string{"shop", "edge"}, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}`)
	if _, err := e.svc.SignPolicy(ctx, more, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("group added with values: %v", err)
	}
	// Going back to drop is observe-safe.
	back := observeBody(t, 4, 4, g, observeIDs)
	if res, err = e.svc.SignPolicy(ctx, back, "system", nil); err != nil || res.ApprovalMode != ModeObserve {
		t.Fatalf("closing without approvals: %v %+v", err, res)
	}
	// A first policy for another id targeting a group whose current
	// policy keeps nothing: observe-safe too; but one that keeps values is not.
	if _, err := e.svc.SignPolicy(ctx, observeBodyID(t, "p-other", 1, 5, []string{"other"}, `"global":{"errors":{"body":{"$.error.code":"keep"}}}`), "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("first policy with keep: %v", err)
	}
}

func observeBodyID(t *testing.T, id string, version, seq int64, groups []string, extra string) []byte {
	t.Helper()
	b := observeBody(t, version, seq, groups, extra)
	p, err := policy.DecodeBody(b)
	if err != nil {
		t.Fatal(err)
	}
	p.PolicyID = id
	out, err := policy.EncodeBody(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSignObserveAutoDisabled(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ObserveAuto = false })
	starter := observeBody(t, 1, 1, []string{"shop"}, `"services":{"shop-api":{"match":{"inbound":true}}}`)
	if _, err := e.svc.SignPolicy(context.Background(), starter, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("observe auto disabled: %v", err)
	}
	st, err := e.svc.Status(context.Background())
	if err != nil || st.ObserveAuto {
		t.Fatalf("status observe_auto: %v %+v", err, st)
	}
}

func TestObserveAutoEnv(t *testing.T) {
	c, _ := ConfigFromEnv([]string{EnvObserveAuto + "=false"})
	if c.ObserveAuto {
		t.Fatal("TT_KEYGUARD_OBSERVE_AUTO=false not read")
	}
	if _, err := ConfigFromEnv([]string{EnvObserveAuto + "=maybe"}); err == nil {
		t.Fatal("an invalid TT_KEYGUARD_OBSERVE_AUTO must be refused")
	}
	if d := DefaultConfig(); !d.ObserveAuto {
		t.Fatal("observe auto must default to true")
	}
}

// RT4-OBS-1/2 (red team round 4): once a person approved keep rules,
// keyguard does not sign without approvals the changes that route traffic
// onto them (a service removed) or lift a container drop above them (drop
// to hmac on the container), while the same changes stay observe-safe on a
// policy without values.
func TestSignObserveRefusesRoutingAndContainerWithValues(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	g := []string{"shop"}
	withKeep := `"global":{"response":{"$.profile.email":"keep"}},"services":{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}},` +
		`"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"keep"}},"carrier-v2":{"match":{"base":"https://api.carrier.example/v2"}}}`
	v1 := observeBody(t, 1, 1, g, withKeep)
	if _, err := e.svc.SignPolicy(ctx, v1, "alice", []Approval{appr("bob"), appr("carol")}); err != nil {
		t.Fatalf("keep with approvals: %v", err)
	}
	noV2 := observeBody(t, 2, 2, g, `"global":{"response":{"$.profile.email":"keep"}},"services":{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}},`+
		`"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"keep"}}}`)
	if _, err := e.svc.SignPolicy(ctx, noV2, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("service removed with values, without approvals: %v", err)
	}
	hmacContainer := observeBody(t, 2, 2, g, strings.Replace(withKeep, `"$.profile":"drop"`, `"$.profile":"hmac(profile)"`, 1))
	if _, err := e.svc.SignPolicy(ctx, hmacContainer, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("container drop to hmac with values, without approvals: %v", err)
	}
	// Without values the observe phase is unchanged.
	e2 := newEnv(t, nil)
	noValues := `"services":{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}},"carrier-v2":{"match":{"base":"https://api.carrier.example/v2"}}}`
	if _, err := e2.svc.SignPolicy(ctx, observeBody(t, 1, 1, g, noValues), "system", nil); err != nil {
		t.Fatalf("starter: %v", err)
	}
	res, err := e2.svc.SignPolicy(ctx, observeBody(t, 2, 2, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"hmac(profile)"}},"GET /orders/{id}":{}}}}`), "system", nil)
	if err != nil || res.ApprovalMode != ModeObserve {
		t.Fatalf("observe-safe changes without values: %v %+v", err, res)
	}
}

// keyguard recomputes the identity verdict itself (policy.IdentityObserveSafe):
// any request header that is not a credential, whatever its name, and any
// claim of the bearer JWT sign without approvals; a credential header, a
// credential-like name without a claim and a cookie still need them.
func TestSignAnyIdentityHeaderWithoutApprovals(t *testing.T) {
	g := []string{"shop"}
	const svc = `"services":{"shop-api":{"match":{"inbound":true}}}`
	for _, sub := range []string{
		`{"from":"header","name":"x-kunden-nr"}`,
		`{"from":"header","name":"x-codice-utente"}`,
		`{"from":"header","name":"x-qz-7"}`,
		`{"from":"header","name":"personid"}`,
		`{"from":"header","name":"authorization","jwt_claim":"member_no"}`,
		`{"from":"header","name":"x-id-token","jwt_claim":"sub"}`,
	} {
		e := newEnv(t, nil)
		ctx := context.Background()
		if _, err := e.svc.SignPolicy(ctx, observeBody(t, 1, 1, g, svc), "system", nil); err != nil {
			t.Fatalf("starter: %v", err)
		}
		b := observeBody(t, 2, 2, g, `"identity":{"subject":`+sub+`},`+svc)
		if res, err := e.svc.SignPolicy(ctx, b, "system", nil); err != nil || res.ApprovalMode != ModeObserve || res.OpensValues == nil || *res.OpensValues {
			t.Fatalf("identity %s without approvals: %v %+v", sub, err, res)
		}
	}
	for _, sub := range []string{
		`{"from":"header","name":"x-session"}`,
		`{"from":"header","name":"authorization"}`,
		`{"from":"header","name":"x-api-key","jwt_claim":"sub"}`,
		`{"from":"header","name":"x-auth-token"}`,
		`{"from":"cookie","name":"uid"}`,
	} {
		e := newEnv(t, nil)
		ctx := context.Background()
		if _, err := e.svc.SignPolicy(ctx, observeBody(t, 1, 1, g, svc), "system", nil); err != nil {
			t.Fatal(err)
		}
		other := observeBody(t, 2, 2, g, `"identity":{"subject":`+sub+`},`+svc)
		if _, err := e.svc.SignPolicy(ctx, other, "system", nil); errCode(err) != "insufficient_approvals" {
			t.Fatalf("identity %s without approvals: %v", sub, err)
		}
	}
}
