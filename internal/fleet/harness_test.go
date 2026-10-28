package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

var fastParams = auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

const testPassword = "correct-horse-battery-1"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSigner stands in for tt keyguard: it holds the policy signing key
// (which tt-core never has) and applies a minimal approval check.
type fakeSigner struct {
	mu        sync.Mutex
	kid       string
	priv      ed25519.PrivateKey
	extra     []SigningKey
	status    SignerStatus
	refuse    string // when set, SignPolicy refuses with this code
	signs     []SignRequest
	renews    int
	lastSeq   int64
	unreached bool
	last      map[string]*policy.Policy // last body signed per policy_id
}

func newFakeSigner() *fakeSigner {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fakeSigner{kid: "policy-2026-1", priv: priv, status: SignerStatus{OpeningApprovals: 2, AdminOverride: true, ApprovalsUnverified: true}}
}

func (s *fakeSigner) sign(body []byte) (Signature, error) {
	p, err := policy.DecodeBody(body)
	if err != nil {
		return Signature{}, &SignRefusedError{Code: "invalid_body"}
	}
	if p.IssuedSeq <= s.lastSeq {
		return Signature{}, &SignRefusedError{Code: "issued_seq_not_increasing"}
	}
	s.lastSeq = p.IssuedSeq
	return Signature{Alg: "Ed25519", Kid: s.kid, Sig: ed25519.Sign(s.priv, policy.SignedMessage(body))}, nil
}

func (s *fakeSigner) SignPolicy(_ context.Context, req SignRequest) (Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreached {
		return Signature{}, ErrSignerUnavailable
	}
	if s.refuse != "" {
		return Signature{}, &SignRefusedError{Code: s.refuse}
	}
	mode := ApprovalStandard
	cand, _ := policy.DecodeBody(req.Body)
	if len(req.Approvals) == 0 {
		// Like keyguard (policy.md 7): observe-safe changes are signed
		// without approvals when observe_auto is on.
		if cand == nil || !s.status.ObserveAuto || policy.ClassifyValues(s.last[cand.PolicyID], cand).OpensValues {
			return Signature{}, &SignRefusedError{Code: "insufficient_approvals"}
		}
		mode = ApprovalObserve
	} else if len(req.Approvals) == 1 && req.Approvals[0].Reason != "" && containsStr(req.Approvals[0].Roles, "admin") {
		mode = ApprovalAdmin
	} else {
		distinct := map[string]bool{}
		for _, a := range req.Approvals {
			if a.User != req.Proposer && containsStr(a.Roles, "policy-approver") {
				distinct[a.User] = true
			}
		}
		if len(distinct) < 1 {
			return Signature{}, &SignRefusedError{Code: "approvals_insufficient"}
		}
	}
	sig, err := s.sign(req.Body)
	if err != nil {
		return sig, err
	}
	s.signs = append(s.signs, req)
	if s.last == nil {
		s.last = map[string]*policy.Policy{}
	}
	if cand != nil {
		s.last[cand.PolicyID] = cand
	}
	sig.ApprovalMode = mode
	return sig, nil
}

func (s *fakeSigner) RenewPolicy(_ context.Context, body []byte) (Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renews++
	return s.sign(body)
}

func (s *fakeSigner) PolicySigningKeys(context.Context) ([]SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreached {
		return nil, ErrSignerUnavailable
	}
	return append([]SigningKey{{Kid: s.kid, PublicKey: s.priv.Public().(ed25519.PublicKey)}}, s.extra...), nil
}

func (s *fakeSigner) Status(context.Context) (SignerStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type alertRec struct {
	mu   sync.Mutex
	list []string
}

func (a *alertRec) Alert(_ context.Context, kind string, _ map[string]string) {
	a.mu.Lock()
	a.list = append(a.list, kind)
	a.mu.Unlock()
}

type env struct {
	t        *testing.T
	fleet    *Fleet
	signer   *fakeSigner
	alerts   *alertRec
	srv      *server.Server
	admin    http.Handler
	authSvc  *auth.Service
	audit    *audit.Log
	db       *store.DB
	clk      *clock
	intake   string // host:port
	cancel   context.CancelFunc
	done     chan error
	sessions map[string]session
	dir      string
}

type session struct {
	cookie *http.Cookie
	csrf   string
}

func newEnv(t *testing.T, mutate func(*Options)) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "tt.db")
	cfg.Intake.Addr = "127.0.0.1:0"
	cfg.Intake.TLS.Managed = true
	cfg.Keyguard.URL = "unix:///run/tt/keyguard.sock" // required by config since the core integration; not dialled here
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	al := audit.New(db)
	svc, err := auth.New(db, al, auth.Options{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, LocalEnabled: true, PasswordParams: &fastParams})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg, server.Deps{Auth: svc, Audit: al, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	intakeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	signer := newFakeSigner()
	alerts := &alertRec{}
	opts := Options{
		DB: db, Audit: al, Signer: signer, Alerts: alerts, Now: clk.Now,
		PublicURL: "https://" + intakeLn.Addr().String(), CADir: filepath.Join(dir, "ca"),
	}
	if mutate != nil {
		mutate(&opts)
	}
	f, err := New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	f.Register(srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, adminLn, intakeLn) }()
	e := &env{t: t, fleet: f, signer: signer, alerts: alerts, srv: srv, admin: srv.AdminHandler(), authSvc: svc, audit: al, db: db, clk: clk,
		intake: intakeLn.Addr().String(), cancel: cancel, done: done, sessions: map[string]session{}, dir: dir}
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

// user creates a local user with roles and logs in.
func (e *env) user(name string, roles ...auth.Role) {
	e.t.Helper()
	if _, err := e.authSvc.CreateLocalUser(context.Background(), name, testPassword, roles); err != nil {
		e.t.Fatal(err)
	}
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, name, testPassword)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.admin.ServeHTTP(rec, req)
	if rec.Code != 200 {
		e.t.Fatalf("login %s: %d %s", name, rec.Code, rec.Body)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	var c *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if strings.HasSuffix(ck.Name, "tt_session") {
			c = &http.Cookie{Name: ck.Name, Value: ck.Value}
		}
	}
	e.sessions[name] = session{cookie: c, csrf: me.CSRF}
}

type resp struct {
	code int
	body []byte
	hdr  http.Header
}

func (r resp) json(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.body, dst); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (r resp) errCode() string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Code
}

// as performs an admin API call as a logged-in user.
func (e *env) as(user, method, path string, body any, ctype ...string) resp {
	e.t.Helper()
	var rd io.Reader
	ct := "application/json"
	if len(ctype) > 0 {
		ct = ctype[0]
	}
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		js, _ := json.Marshal(b)
		rd = bytes.NewReader(js)
	}
	req := httptest.NewRequest(method, path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", ct)
	}
	if s, ok := e.sessions[user]; ok {
		req.AddCookie(s.cookie)
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	rec := httptest.NewRecorder()
	e.admin.ServeHTTP(rec, req)
	return resp{rec.Code, rec.Body.Bytes(), rec.Header()}
}

func (e *env) must(r resp, code int) resp {
	e.t.Helper()
	if r.code != code {
		e.t.Fatalf("status %d (want %d): %s", r.code, code, r.body)
	}
	return r
}

// ---------------------------------------------------------------------------
// Source side

// pinVerifier verifies the server chain the way a dependency-free SDK
// does: one presented certificate must hash to the pin, and the leaf must
// chain to it for the expected host.
func pinVerifier(pin, host string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		var root *x509.Certificate
		var certs []*x509.Certificate
		for _, r := range raw {
			c, err := x509.ParseCertificate(r)
			if err != nil {
				return err
			}
			certs = append(certs, c)
			sum := sha256.Sum256(r)
			if base64.RawURLEncoding.EncodeToString(sum[:]) == pin {
				root = c
			}
		}
		if root == nil || len(certs) == 0 {
			return errors.New("no certificate matches the token pin")
		}
		pool := x509.NewCertPool()
		pool.AddCert(root)
		_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
		return err
	}
}

type source struct {
	e      *env
	id     string
	client *http.Client
	enr    Enrollment
	// kids, when non-nil, is sent as signing_kids in heartbeats.
	kids []string
	// lastErrors, when non-nil, is sent as last_errors in heartbeats.
	lastErrors []map[string]string
}

func (e *env) httpClient(pin string, cert *tls.Certificate) *http.Client {
	host, _, _ := net.SplitHostPort(e.intake)
	cfg := &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: pinVerifier(pin, host), MinVersion: tls.VersionTLS12} //nolint:gosec // verified by pin
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 10 * time.Second}
}

func tokenPin(token string) string {
	return token[strings.LastIndexByte(token, '.')+1:]
}

// enroll calls the enrollment endpoint over TLS with pin verification.
func (e *env) enroll(token string, body map[string]any) (resp, error) {
	body["token"] = token
	js, _ := json.Marshal(body)
	c := e.httpClient(tokenPin(token), nil)
	r, err := c.Post("https://"+e.intake+PathEnroll, "application/json", bytes.NewReader(js))
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, b, r.Header}, nil
}

func srcInfo(kind, service string) map[string]any {
	return map[string]any{"kind": kind, "version": "0.4.1", "service_name": service, "instance": "pod-1"}
}

// enrollSource enrolls (no CSR) and returns an mTLS-capable source.
func (e *env) enrollSource(token, kind, service string) *source {
	e.t.Helper()
	r, err := e.enroll(token, map[string]any{"source": srcInfo(kind, service)})
	if err != nil {
		e.t.Fatal(err)
	}
	e.must(r, 201)
	var enr Enrollment
	r.json(e.t, &enr)
	cert, err := tls.X509KeyPair([]byte(enr.ClientCert), []byte(enr.ClientKey))
	if err != nil {
		e.t.Fatal(err)
	}
	return &source{e: e, id: enr.SourceID, enr: enr, client: e.httpClient(tokenPin(token), &cert)}
}

func (s *source) do(method, path string, body any, hdr map[string]string) (resp, error) {
	var rd io.Reader
	if body != nil {
		js, _ := json.Marshal(body)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, "https://"+s.e.intake+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := s.client.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, b, r.Header}, nil
}

func (s *source) heartbeat(state string, sent int64) (HeartbeatResponse, resp) {
	s.e.t.Helper()
	z := int64(0)
	body := map[string]any{
		"source_id": s.id, "state": state,
		"counters": map[string]any{"exchanges_seen": sent * 2, "exchanges_sampled": sent, "events_sent": sent, "events_dropped_queue": z,
			"events_rejected": z, "send_errors": z, "sanitizer_errors": 1},
		"overhead_us": map[string]any{"p50": 1100, "p99": 4000},
	}
	if s.kids != nil {
		body["signing_kids"] = s.kids
	}
	if s.lastErrors != nil {
		body["last_errors"] = s.lastErrors
	}
	r, err := s.do("POST", PathHeartbeat, body, nil)
	if err != nil {
		s.e.t.Fatal(err)
	}
	var hr HeartbeatResponse
	if r.code == 200 {
		r.json(s.e.t, &hr)
	}
	return hr, r
}

func certPEMToX509(t *testing.T, p string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(p))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setup creates a group "shop" (services shop-api) and an operator.
func (e *env) setup() {
	e.t.Helper()
	e.user("olivia", auth.RoleOperator)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{
		"name": "shop", "policy_id": "p-shop", "allowed_service_names": []string{"shop-api"},
	}), 201)
}

func (e *env) newToken(typ string, kind string) NewToken {
	e.t.Helper()
	var nt NewToken
	e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": kind, "group": "shop", "token_type": typ}), 201).json(e.t, &nt)
	return nt
}

const policyV1 = `format: tt.policy/v1
policy_id: p-shop
default: drop
hmac: { kid: k1, epoch: "2026-10" }
sampling: { rate: 0.05 }
services:
  shop-api:
    match: { inbound: true }
    ops:
      "POST /orders":
        response:
          $.status: keep
          $.id: hmac(order)
`

// policyClosing turns keep into drop: a closing change.
var policyClosing = strings.Replace(policyV1, "$.status: keep", "$.status: drop", 1)

// policyOpening adds a keep rule: an opening change.
var policyOpening = strings.Replace(policyV1, "$.id: hmac(order)", "$.id: hmac(order)\n          $.total: keep", 1)

func (e *env) propose(user, yml string) PolicyVersion {
	e.t.Helper()
	var v PolicyVersion
	e.must(e.as(user, "POST", "/api/v1/fleet/policies", yml, "application/yaml"), 201).json(e.t, &v)
	return v
}

func (e *env) approve(user string, v PolicyVersion, body any) resp {
	return e.as(user, "POST", fmt.Sprintf("/api/v1/fleet/policies/%s/versions/%d/approve", v.PolicyID, v.Version), body)
}

// activateV1 proposes policyV1 (by olivia) and approves it with two
// approvers; it returns the active version.
func (e *env) activateV1() PolicyVersion {
	e.t.Helper()
	if _, ok := e.sessions["bob"]; !ok {
		e.user("bob", auth.RolePolicyApprover)
		e.user("carol", auth.RolePolicyApprover)
	}
	v := e.propose("olivia", policyV1)
	e.must(e.approve("bob", v, nil), 200)
	var out PolicyVersion
	e.must(e.approve("carol", v, nil), 200).json(e.t, &out)
	if out.Status != StatusActive {
		e.t.Fatalf("not active: %+v", out)
	}
	return out
}

// auditDump returns every audit entry as JSON lines.
func (e *env) auditDump() string {
	e.t.Helper()
	var b strings.Builder
	err := e.audit.Iterate(context.Background(), 0, 0, func(en audit.Entry) error {
		js, _ := json.Marshal(en)
		b.Write(js)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return b.String()
}
