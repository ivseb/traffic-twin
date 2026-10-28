package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, token endpoint
// with PKCE verification. Claims can be tweaked per test.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	signKey *rsa.PrivateKey // normally == key; a different key simulates forgery
	mu      sync.Mutex
	codes   map[string]codeGrant
	tweak   func(claims map[string]any)
	now     func() time.Time
}

type codeGrant struct {
	challenge, nonce string
}

func newFakeIdP(t *testing.T, now func() time.Time) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, signKey: key, codes: map[string]codeGrant{}, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/authorize",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64u(key.N.Bytes()), "e": b64u(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		g, ok := idp.codes[r.Form.Get("code")]
		delete(idp.codes, r.Form.Get("code"))
		idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || b64u(sum[:]) != g.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		claims := map[string]any{
			"iss": idp.srv.URL, "sub": "sub-giulia", "aud": "tt-core",
			"iat": idp.now().Unix(), "exp": idp.now().Add(5 * time.Minute).Unix(),
			"nonce": g.nonce, "name": "Giulia Neri", "groups": []string{"tt-auditors", "unrelated"},
		}
		if idp.tweak != nil {
			idp.tweak(claims)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-123", "token_type": "Bearer", "expires_in": 300,
			"id_token": idp.sign(t, claims),
		})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (idp *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	input := b64u(h) + "." + b64u(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.signKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

// authorize simulates the user authenticating at the IdP: it parses the
// authorization URL and returns a code bound to its PKCE challenge/nonce.
func (idp *fakeIdP) authorize(t *testing.T, location string) (state, code string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, idp.srv.URL+"/authorize") {
		t.Fatalf("unexpected redirect %q", location)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("missing PKCE/nonce/state in %q", location)
	}
	if q.Get("client_id") != "tt-core" || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("bad client/scope in %q", location)
	}
	code = randomToken()
	idp.mu.Lock()
	idp.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	idp.mu.Unlock()
	return q.Get("state"), code
}

func oidcEnv(t *testing.T) (*env, *fakeIdP) {
	t.Helper()
	// go-oidc checks token expiry with the real clock, so the IdP uses
	// real time (the env clock only drives sessions).
	idp := newFakeIdP(t, time.Now)
	e := newEnv(t, func(o *Options) {
		o.OIDC = &OIDCOptions{
			IssuerURL: idp.srv.URL, HTTPClient: idp.srv.Client(),
			ClientID: "tt-core", ClientSecret: "s", RedirectURL: "http://127.0.0.1:7070/api/v1/auth/oidc/callback",
			Scopes: []string{"openid", "profile"}, RolesClaim: "groups",
			RoleMapping: map[string][]Role{"tt-auditors": {RoleAuditor}, "tt-ops": {RoleOperator}},
		}
	})
	return e, idp
}

func (e *env) startOIDC(t *testing.T, idp *fakeIdP, returnTo string) (state, code string, cookie *http.Cookie) {
	t.Helper()
	r := e.do(t, "GET", "/api/v1/auth/oidc/start?return_to="+url.QueryEscape(returnTo), "", nil)
	if r.code != http.StatusFound {
		t.Fatalf("start = %d %s", r.code, r.body)
	}
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == oidcCookiePlain {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("weak oidc cookie: %+v", c)
			}
			cookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if cookie == nil {
		t.Fatal("no oidc state cookie")
	}
	state, code = idp.authorize(t, r.header.Get("Location"))
	return state, code, cookie
}

func (e *env) callback(t *testing.T, state, code string, cookie *http.Cookie) resp {
	t.Helper()
	q := url.Values{"state": {state}, "code": {code}}
	var cs []*http.Cookie
	if cookie != nil {
		cs = append(cs, cookie)
	}
	return e.do(t, "GET", "/api/v1/auth/oidc/callback?"+q.Encode(), "", nil, cs...)
}

func TestOIDCLogin(t *testing.T) {
	e, idp := oidcEnv(t)
	state, code, cookie := e.startOIDC(t, idp, "/rules")
	r := e.callback(t, state, code, cookie)
	if r.code != http.StatusFound || r.header.Get("Location") != "/rules" {
		t.Fatalf("callback = %d %q", r.code, r.header.Get("Location"))
	}
	sc := sessionCookie(t, r)
	r = e.do(t, "GET", "/api/v1/auth/me", "", nil, sc)
	me := decodeMe(t, r)
	if r.code != http.StatusOK || me.User.Method != "oidc" || me.User.DisplayName != "Giulia Neri" ||
		len(me.Roles) != 1 || me.Roles[0] != RoleAuditor {
		t.Fatalf("me = %d %s", r.code, r.body)
	}

	// Replaying the same state fails (single use).
	if r := e.callback(t, state, code, cookie); !strings.Contains(r.header.Get("Location"), "auth_error=") {
		t.Fatalf("replay accepted: %q", r.header.Get("Location"))
	}

	// A second login updates roles from the claim and reuses the account.
	idp.tweak = func(c map[string]any) { c["groups"] = "tt-ops" }
	state, code, cookie = e.startOIDC(t, idp, "")
	r = e.callback(t, state, code, cookie)
	me = decodeMe(t, e.do(t, "GET", "/api/v1/auth/me", "", nil, sessionCookie(t, r)))
	if len(me.Roles) != 1 || me.Roles[0] != RoleOperator {
		t.Fatalf("roles not synced: %v", me.Roles)
	}
	users, _ := e.svc.ListUsers(context.Background())
	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
}

func TestOIDCRejections(t *testing.T) {
	cases := map[string]struct {
		tweak    func(c map[string]any)
		forge    bool
		noCookie bool
		badState bool
		want     string
	}{
		"missing cookie":   {noCookie: true, want: "state_mismatch"},
		"state mismatch":   {badState: true, want: "state_mismatch"},
		"wrong nonce":      {tweak: func(c map[string]any) { c["nonce"] = "other" }, want: "nonce_mismatch"},
		"wrong audience":   {tweak: func(c map[string]any) { c["aud"] = "someone-else" }, want: "id_token_invalid"},
		"wrong issuer":     {tweak: func(c map[string]any) { c["iss"] = "https://evil.example" }, want: "id_token_invalid"},
		"expired":          {tweak: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "id_token_invalid"},
		"forged signature": {forge: true, want: "id_token_invalid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e, idp := oidcEnv(t)
			idp.tweak = tc.tweak
			if tc.forge {
				other, _ := rsa.GenerateKey(rand.Reader, 2048)
				idp.signKey = other
			}
			state, code, cookie := e.startOIDC(t, idp, "/")
			if tc.noCookie {
				cookie = nil
			}
			if tc.badState {
				state = "tampered"
			}
			r := e.callback(t, state, code, cookie)
			if r.code != http.StatusFound || r.header.Get("Location") != "/?auth_error="+tc.want {
				t.Fatalf("callback = %d %q, want error %s", r.code, r.header.Get("Location"), tc.want)
			}
			for _, c := range (&http.Response{Header: r.header}).Cookies() {
				if c.Name == cookiePlain && c.Value != "" {
					t.Fatal("session cookie issued on failure")
				}
			}
		})
	}
}

func TestOIDCIdPErrorNotReflected(t *testing.T) {
	e, _ := oidcEnv(t)
	r := e.do(t, "GET", "/api/v1/auth/oidc/callback?error=access_denied&error_description=<script>", "", nil)
	if r.header.Get("Location") != "/?auth_error=idp_error" {
		t.Fatalf("location = %q", r.header.Get("Location"))
	}
}
