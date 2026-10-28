package core_rt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/server"
)

// limitsEnv is a second, small product with the default limits: auth rate
// limit 10/min burst 5, keyguard match 1 call/s, pack 1/s, and a daily
// match budget of 60 strings.
type limitsEnv struct {
	clock  *vclock
	kgDir  string
	kg     *core.DevKeyguard
	kgLog  *lockedBuf
	core   *core.Core
	base   string
	hc     *http.Client
	ada    *session
	policy client.PolicyRef
	key    []byte
}

const rtBudget = 60

func startLimitsKeyguard(t *testing.T, l *limitsEnv) {
	t.Helper()
	var err error
	l.kg, err = core.StartDevKeyguard(context.Background(), core.DevKeyguardOptions{Dir: l.kgDir, Now: l.clock.Now,
		Logger: keyguard.NewLogger(l.kgLog, "debug", "json"),
		Tune:   func(c *keyguard.Config) { c.MatchBudget = rtBudget }})
	if err != nil {
		t.Fatal(err)
	}
}

func newLimitsEnv(t *testing.T) *limitsEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("composed red-team environment")
	}
	l := &limitsEnv{clock: &vclock{t: time.Now().UTC().Truncate(time.Second)}, kgLog: &lockedBuf{}}
	var err error
	if l.kgDir, err = os.MkdirTemp("", "ttrt2l"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(l.kgDir) })
	startLimitsKeyguard(t, l)
	t.Cleanup(func() { l.kg.Close() })
	kf, _ := os.ReadFile(l.kg.HMACKeyFile)
	line := strings.TrimSpace(string(kf))
	l.key, _ = base64.RawURLEncoding.DecodeString(line[strings.Index(line, ":")+1:])

	dir := t.TempDir()
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(dir, l.kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Miner.Schedule = 0
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.core, err = core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-rt2l", AdminListener: adminLn, IntakeListener: intakeLn,
		Now: l.clock.Now, Logger: server.NewLogger(io.Discard, "error", "text"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.core.Run(ctx) }()
	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	l.hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	l.base = "https://" + adminLn.Addr().String()
	eventually(t, 5*time.Second, "readyz", func() bool {
		resp, err := l.hc.Get(l.base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	l.ada = signIn(t, l.base, l.hc, "/api/v1/setup", map[string]string{"setup_token": l.core.SetupToken(), "username": "ada", "password": testPassword}, "ada")
	l.ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "olga", "password": testPassword, "roles": []string{"operator"}})
	olga := signIn(t, l.base, l.hc, "/api/v1/auth/login", map[string]string{"username": "olga", "password": testPassword}, "olga")
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "rl", "allowed_service_names": []string{"rl-svc"}, "policy_id": "p-rl"})
	var pv policyVersion
	olga.json(201, "POST", "/api/v1/fleet/groups/rl/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &pv)
	if pv.Status != "active" { // observe-safe: active at once (policy.md 7)
		l.ada.must(200, "POST", approvePath(pv), map[string]any{"reason": "rt limits"})
	}
	l.policy = client.PolicyRef{ID: pv.PolicyID, Version: pv.Version}
	return l
}

func (l *limitsEnv) token(domain, value string) string {
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte("2026-10\x00" + domain + "\x00" + value))
	return "tk1:" + core.DevHMACKid + ":" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

func kgCode(err error) (int, string) {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Status, ce.Code
	}
	if err != nil {
		return -1, err.Error()
	}
	return 0, ""
}

// Login (and setup) are rate limited per client: with the defaults (10 per
// minute, burst 5) the sixth wrong password in a row is 429 with
// Retry-After, and so is a correct one right after.
func TestRT_Limits_Holds_LoginRateLimit(t *testing.T) {
	l := newLimitsEnv(t)
	got429 := false
	var retry string
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest("POST", l.base+"/api/v1/auth/login", strings.NewReader(`{"username":"olga","password":"wrong-password-000"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := l.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			got429, retry = true, resp.Header.Get("Retry-After")
			break
		}
		if resp.StatusCode != 401 {
			t.Fatalf("wrong password = %d", resp.StatusCode)
		}
	}
	if !got429 || retry == "" {
		t.Fatalf("no 429 with Retry-After after repeated wrong passwords (got429=%v)", got429)
	}
	if _, code, _ := trySignIn(t, l.base, l.hc, "/api/v1/auth/login", map[string]string{"username": "olga", "password": testPassword}, nil); code != 429 {
		t.Errorf("correct password while limited = %d (want 429)", code)
	}
	if _, code, _ := trySignIn(t, l.base, l.hc, "/api/v1/setup", map[string]string{"setup_token": "tts_x", "username": "x", "password": testPassword}, nil); code != 429 {
		t.Errorf("setup while limited = %d (want 429)", code)
	}
}

// keyguard's match oracle over its socket: batch cap, 1 call per second,
// a persistent daily budget (it survives a keyguard restart), an alert and
// an audit entry (without the candidate) for every positive.
func TestRT_Limits_Holds_MatchOracleLimits(t *testing.T) {
	l := newLimitsEnv(t)
	ctx := context.Background()
	kg, err := client.New(client.Config{URL: l.kg.URL})
	if err != nil {
		t.Fatal(err)
	}
	real := "rt-real-subject-0042"
	if err := kg.AddTokens(ctx, "2026-10", []string{l.token("subject", real)}); err != nil {
		t.Fatal(err)
	}
	big := make([]client.Candidate, 10001)
	for i := range big {
		big[i] = client.Str("x")
	}
	if s, c := kgCode(func() error { _, err := kg.Match(ctx, []client.PolicyRef{l.policy}, big); return err }()); s != 400 || c != "batch_too_large" {
		t.Errorf("10001 candidates: %d %s", s, c)
	}
	l.clock.Set(l.clock.Now().Add(2 * time.Second))
	res, err := kg.Match(ctx, []client.PolicyRef{l.policy}, []client.Candidate{client.Str("rt-nothing"), client.Str(real)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches[0] || !res.Matches[1] || res.Positives != 1 {
		t.Fatalf("match: %+v", res)
	}
	if s, c := kgCode(func() error {
		_, err := kg.Match(ctx, []client.PolicyRef{l.policy}, []client.Candidate{client.Str("a")})
		return err
	}()); s != 429 || c != "rate_limited" {
		t.Errorf("second call within 1 s: %d %s", s, c)
	}
	// Budget: 60 strings a day.
	cands := make([]client.Candidate, 40)
	for i := range cands {
		cands[i] = client.Str("rt-b-" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	l.clock.Set(l.clock.Now().Add(2 * time.Second))
	if _, err := kg.Match(ctx, []client.PolicyRef{l.policy}, cands); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	l.clock.Set(l.clock.Now().Add(2 * time.Second))
	if s, c := kgCode(func() error { _, err := kg.Match(ctx, []client.PolicyRef{l.policy}, cands); return err }()); s != 429 || c != "budget_exceeded" {
		t.Fatalf("over the daily budget: %d %s", s, c)
	}
	// Restart keyguard: the budget is persistent.
	st, err := kg.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	left := st.MatchBudgetLeft
	if err := l.kg.Close(); err != nil {
		t.Fatal(err)
	}
	startLimitsKeyguard(t, l)
	kg2, err := client.New(client.Config{URL: l.kg.URL})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := kg2.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st2.MatchBudgetLeft != left || left >= rtBudget {
		t.Errorf("budget left %d before restart, %d after (must persist)", left, st2.MatchBudgetLeft)
	}
	if s, c := kgCode(func() error { _, err := kg2.Match(ctx, []client.PolicyRef{l.policy}, cands); return err }()); s != 429 || c != "budget_exceeded" {
		t.Errorf("after restart: %d %s (budget must persist)", s, c)
	}
	logs := l.kgLog.String()
	if !strings.Contains(logs, "match.positive") {
		t.Error("no match.positive alert in keyguard's log")
	}
	if strings.Contains(logs, real) || strings.Contains(logs, l.token("subject", real)) {
		t.Error("keyguard log contains the candidate or its token")
	}
	entries, err := kg2.Audit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(entries)
	if strings.Contains(string(raw), real) || strings.Contains(string(raw), "rt-b-") || strings.Contains(string(raw), "tk1:") {
		t.Error("keyguard audit contains candidates or tokens")
	}
	if !strings.Contains(string(raw), "alert") {
		t.Error("no alert outcome in keyguard audit for the positive")
	}
}
