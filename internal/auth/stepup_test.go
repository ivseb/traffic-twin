package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func stepUpEnv(t *testing.T) (*env, *fakeIdP) {
	t.Helper()
	e, idp := oidcEnv(t)
	e.svc.oidc.opts.ApprovalClientID = "tt-approve"
	e.svc.oidc.opts.ApprovalRedirectURL = "http://127.0.0.1:7070" + stepUpCallbackPath
	e.mux.Handle(stepUpStartPath, e.svc.Require()(e.svc.StepUpStartHandler()))
	e.mux.Handle(stepUpCallbackPath, e.svc.StepUpCallbackHandler())
	e.svc.SetStepUpBinder(func(_ context.Context, _ *Principal, purpose, ref string) (string, error) {
		if ref == "missing" {
			return "", ErrStepUpNotFound
		}
		return "nonce-" + purpose + "-" + ref, nil
	})
	return e, idp
}

// stepUp runs GET /stepup and simulates the provider; it returns the
// callback response.
func (e *env) stepUp(t *testing.T, idp *fakeIdP, sc *http.Cookie, purpose, ref string, tweak func(map[string]any)) resp {
	t.Helper()
	r := e.do(t, "GET", stepUpStartPath+"?purpose="+purpose+"&ref="+url.QueryEscape(ref)+"&return_to=/", "", nil, sc)
	if r.code != http.StatusFound {
		t.Fatalf("stepup start = %d %s", r.code, r.body)
	}
	loc := r.header.Get("Location")
	if !strings.HasPrefix(loc, idp.srv.URL+"/authorize") {
		return r // an error redirect back to the UI
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("client_id") != "tt-approve" || q.Get("prompt") != "login" || q.Get("max_age") != "600" || q.Get("nonce") != "nonce-"+purpose+"-"+ref ||
		q.Get("redirect_uri") != "http://127.0.0.1:7070"+stepUpCallbackPath {
		t.Fatalf("step-up authorization request: %s", loc)
	}
	var cookie *http.Cookie
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == stepUpCookiePlain {
			cookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	code := randomToken()
	idp.mu.Lock()
	idp.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	idp.mu.Unlock()
	idp.tweak = func(c map[string]any) {
		c["aud"] = "tt-approve"
		c["auth_time"] = e.clock.Now().Unix()
		if tweak != nil {
			tweak(c)
		}
	}
	defer func() { idp.tweak = nil }()
	vals := url.Values{"state": {q.Get("state")}, "code": {code}}
	return e.do(t, "GET", stepUpCallbackPath+"?"+vals.Encode(), "", nil, cookie)
}

func TestApprovalStepUp(t *testing.T) {
	e, idp := stepUpEnv(t)
	ctx := context.Background()
	state, code, cookie := e.startOIDC(t, idp, "/")
	sc := sessionCookie(t, e.callback(t, state, code, cookie))
	users, _ := e.svc.ListUsers(ctx)
	p := &Principal{UserID: users[0].ID, OIDCIssuer: idp.srv.URL, OIDCSubject: "sub-giulia"}
	const ref, nonce = "p-shop/2", "nonce-policy-approve-p-shop/2"

	if _, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, nonce, ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("before step-up: %v", err)
	}
	r := e.stepUp(t, idp, sc, "policy-approve", ref, nil)
	if r.code != http.StatusFound || r.header.Get("Location") != "/?stepup=ok" {
		t.Fatalf("callback = %d %q", r.code, r.header.Get("Location"))
	}
	tok, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, nonce, "")
	if err != nil || tok == "" {
		t.Fatalf("token after step-up: %v", err)
	}
	// Single use, and never for another change or user.
	if _, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, nonce, ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("second use: %v", err)
	}
	e.stepUp(t, idp, sc, "policy-approve", ref, nil)
	if _, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, "nonce-of-a-newer-draft-state", ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("stale binding: %v", err)
	}
	// The explicit form is verified the same way.
	if got, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, nonce, tok); err != nil || got != tok {
		t.Fatalf("explicit token: %v", err)
	}
	other := *p
	other.OIDCSubject = "sub-someone-else"
	if _, err := e.svc.ApprovalToken(ctx, &other, "policy-approve", ref, nonce, tok); !errors.Is(err, ErrApprovalToken) {
		t.Fatalf("someone else's token: %v", err)
	}
	if _, err := e.svc.ApprovalToken(ctx, p, "policy-approve", ref, "other-nonce", tok); !errors.Is(err, ErrApprovalToken) {
		t.Fatalf("token of another change: %v", err)
	}
	local := &Principal{UserID: "usr_local"}
	if _, err := e.svc.ApprovalToken(ctx, local, "policy-approve", ref, nonce, tok); !errors.Is(err, ErrLocalApprover) {
		t.Fatalf("local user with a token: %v", err)
	}
	if st, code, _ := ApprovalTokenError(ErrLocalApprover, true); st != 403 || code != "id_token_not_allowed" {
		t.Fatal(code)
	}

	// Rejections at the callback.
	cases := map[string]struct {
		tweak func(map[string]any)
		want  string
	}{
		"login token (login audience)": {func(c map[string]any) { c["aud"] = "tt-core" }, "id_token_invalid"},
		"other subject":                {func(c map[string]any) { c["sub"] = "sub-mallory" }, "subject_mismatch"},
		"wrong nonce":                  {func(c map[string]any) { c["nonce"] = "nonce-of-a-login" }, "nonce_mismatch"},
		"no auth_time":                 {func(c map[string]any) { delete(c, "auth_time") }, "stale_authentication"},
		"old auth_time":                {func(c map[string]any) { c["auth_time"] = e.clock.Now().Add(-time.Hour).Unix() }, "stale_authentication"},
	}
	for name, c := range cases {
		r := e.stepUp(t, idp, sc, "pack-publish", "pk-1", c.tweak)
		if r.header.Get("Location") != "/?stepup_error="+c.want {
			t.Errorf("%s: %q", name, r.header.Get("Location"))
		}
	}
	if r := e.stepUp(t, idp, sc, "pack-publish", "missing", nil); r.header.Get("Location") != "/?stepup_error=not_found" {
		t.Fatalf("unknown ref: %q", r.header.Get("Location"))
	}
	if r := e.stepUp(t, idp, sc, "login", "x", nil); r.header.Get("Location") != "/?stepup_error=invalid_request" {
		t.Fatalf("bad purpose: %q", r.header.Get("Location"))
	}

	// keyguard's audience must be the approval client, never the login one.
	if err := e.svc.CheckApprovalAudience(idp.srv.URL, "tt-approve"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckApprovalAudience(idp.srv.URL, "tt-core"); err == nil {
		t.Fatal("login audience accepted")
	}
	if err := e.svc.CheckApprovalAudience("https://other.example", "tt-approve"); err == nil {
		t.Fatal("other issuer accepted")
	}
}

func TestApprovalClientMustDifferFromLogin(t *testing.T) {
	_, err := newOIDCClient(OIDCOptions{IssuerURL: "https://idp.example", ClientID: "tt-core", RedirectURL: "https://tt.example/api/v1/auth/oidc/callback", ApprovalClientID: "tt-core"})
	if err == nil {
		t.Fatal("same client accepted")
	}
	c, err := newOIDCClient(OIDCOptions{IssuerURL: "https://idp.example", ClientID: "tt-core", RedirectURL: "https://tt.example/api/v1/auth/oidc/callback", ApprovalClientID: "tt-approve"})
	if err != nil || c.opts.ApprovalRedirectURL != "https://tt.example/api/v1/auth/oidc/stepup/callback" {
		t.Fatalf("%v %+v", err, c)
	}
}
