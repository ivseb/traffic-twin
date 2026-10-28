package keyguard

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

func TestTokenMatchesConformanceVector(t *testing.T) {
	// conformance/vectors/0002-hmac-equal-values.json
	got := tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("ORD-2026-000184"))
	if got != "tk1:k1:5QWSSNfrkE8dHsTh40ixTw" {
		t.Fatalf("token %s", got)
	}
	kid, mac, ok := parseToken(got)
	if !ok || kid != "k1" || b64(mac[:]) != "5QWSSNfrkE8dHsTh40ixTw" {
		t.Fatal("parseToken")
	}
	for _, bad := range []string{"tk1:K1:5QWSSNfrkE8dHsTh40ixTw", "tk1:k1:5QWSSNfrkE8dHsTh40ixT", "tk1:k1:5QWSSNfrkE8dHsTh40ixTx", "tkd:k1:5QWSSNfrkE8dHsTh40ixTw", "tk1:k1:5QWSSNfrkE8dHsTh40ix+w"} {
		if _, _, ok := parseToken(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

var tokenRE = regexp.MustCompile(`tk1:k1:[A-Za-z0-9_-]{22}`)

// sanitizedTokens runs the real sanitizer over an exchange and returns the
// tokens it produced: keyguard must recognise them.
func sanitizedTokens(t *testing.T, body []byte, respBody, authz string) []string {
	t.Helper()
	p, err := policy.DecodeBody(body)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sanitizer.ParseKey("k1:" + b64(k1Secret()))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := sanitizer.NewEngineWithKey(p, key)
	if err != nil {
		t.Fatal(err)
	}
	ex := &sanitizer.Exchange{
		Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"),
		ReqHeaders:  []sanitizer.Header{{Name: "Authorization", Value: []byte(authz)}},
		Status:      201,
		RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}},
		RespBody:    []byte(respBody),
	}
	out, err := eng.Sanitize(ex, t0, sanitizer.ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := out.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	toks := tokenRE.FindAllString(string(canon), -1)
	if out.Subject != "" {
		toks = append(toks, out.Subject)
	}
	if len(toks) < 2 {
		t.Fatalf("expected tokens in %s", canon)
	}
	return toks
}

func TestMatchAgainstSanitizerTokens(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MatchInterval = 0 })
	ctx := context.Background()
	body := e.signFirst(bodyOpts{version: 1, seq: 1})
	toks := sanitizedTokens(t, body, `{"id":184.0,"status":"CREATED","total":12}`, "Bearer user-77")
	if err := e.svc.AddTokens(ctx, "2026-10", toks); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		c    Candidate
		want bool
	}{
		{Candidate{Value: "184"}, true},
		{Candidate{Value: "184", IsNumber: true}, true},
		{Candidate{Value: "184.0", IsNumber: true}, true}, // canonical form 184
		{Candidate{Value: "1.84e2", IsNumber: true}, true},
		{Candidate{Value: "1.84E+2"}, true}, // numeric string: canonical form checked too
		{Candidate{Value: "185", IsNumber: true}, false},
		{Candidate{Value: "user-77"}, true}, // subject domain
		{Candidate{Value: "CREATED"}, false},
		{Candidate{Value: "ORD-SYN-0042"}, false},
		{Candidate{Value: "1e99999", IsNumber: true}, false}, // beyond the lexeme limits: bytes only
	}
	cands := make([]Candidate, len(cases))
	for i, c := range cases {
		cands[i] = c.c
	}
	res, err := e.svc.Match(ctx, []PolicyRef{{ID: "p-shop", Version: 1}}, cands)
	if err != nil {
		t.Fatal(err)
	}
	pos := 0
	for i, c := range cases {
		if res.Matches[i] != c.want {
			t.Errorf("candidate %d (%+v): got %v want %v", i, c.c, res.Matches[i], c.want)
		}
		if c.want {
			pos++
		}
	}
	if res.Positives != pos {
		t.Fatalf("positives %d want %d", res.Positives, pos)
	}
	if got := e.alertTypes(); len(got) == 0 || got[len(got)-1] != AlertMatchPositive {
		t.Fatalf("no positive alert: %v", got)
	}
	// Audit: counts only, outcome alert.
	entries, err := e.svc.Audit(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.Op != "keyguard.match" || last.Outcome != "alert" || last.Detail["positives"] != fmt.Sprint(pos) {
		t.Fatalf("audit %+v", last)
	}
}

func TestMatchRotationAndUnknownPolicy(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MatchInterval = 0 })
	ctx := context.Background()
	e.signFirst(bodyOpts{version: 1, seq: 1, hmac: `{"kid":"k2","accept_kids":["k1"],"epoch":"2026-11"}`})
	// A token made by a source still on k1 during the rotation.
	tok := tokenFor(k1Secret(), "k1", "2026-11", "order", []byte("ORD-2026-000777"))
	tok2 := tokenFor(e.k2, "k2", "2026-11", "order", []byte("ORD-2026-000778"))
	if err := e.svc.AddTokens(ctx, "2026-11", []string{tok, tok2}); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Match(ctx, []PolicyRef{{ID: "p-shop", Version: 1}}, []Candidate{{Value: "ORD-2026-000777"}, {Value: "ORD-2026-000778"}, {Value: "ORD-2026-000779"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matches[0] || !res.Matches[1] || res.Matches[2] {
		t.Fatalf("matches %v", res.Matches)
	}
	// Same value, other epoch: different token, no match.
	if err := e.svc.AddTokens(ctx, "2026-10", []string{tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("ORD-X"))}); err != nil {
		t.Fatal(err)
	}
	res, _ = e.svc.Match(ctx, []PolicyRef{{ID: "p-shop", Version: 1}}, []Candidate{{Value: "ORD-X"}})
	if res.Matches[0] {
		t.Fatal("epoch not respected")
	}
	if _, err := e.svc.Match(ctx, []PolicyRef{{ID: "p-shop", Version: 9}}, []Candidate{{Value: "x"}}); errCode(err) != "unknown_policy" {
		t.Fatalf("unknown policy: %v", err)
	}
}

func TestMatchRateLimitBatchAndBudget(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MatchMaxBatch = 5; c.MatchBudget = 8 })
	ctx := context.Background()
	e.signFirst(bodyOpts{version: 1, seq: 1})
	refs := []PolicyRef{{ID: "p-shop", Version: 1}}
	six := make([]Candidate, 6)
	for i := range six {
		six[i] = Candidate{Value: fmt.Sprint(i)}
	}
	if _, err := e.svc.Match(ctx, refs, six); errCode(err) != "batch_too_large" {
		t.Fatalf("batch cap: %v", err)
	}
	if _, err := e.svc.Match(ctx, refs, six[:5]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Match(ctx, refs, six[:1]); errCode(err) != "rate_limited" {
		t.Fatalf("rate limit: %v", err)
	}
	e.clock.Add(time.Second)
	if _, err := e.svc.Match(ctx, refs, six[:4]); errCode(err) != "budget_exceeded" {
		t.Fatalf("budget: %v", err)
	}
	e.clock.Add(time.Second)
	if _, err := e.svc.Match(ctx, refs, six[:3]); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	// The budget survives a restart.
	e.restart()
	e.clock.Add(time.Second)
	if _, err := e.svc.Match(ctx, refs, six[:1]); errCode(err) != "budget_exceeded" {
		t.Fatalf("budget after restart: %v", err)
	}
	st, _ := e.svc.Status(ctx)
	if st.MatchBudgetLeft != 0 {
		t.Fatalf("budget left %d", st.MatchBudgetLeft)
	}
	// Next UTC day: a fresh budget.
	e.clock.Add(24 * time.Hour)
	if _, err := e.svc.Match(ctx, refs, six[:1]); err != nil {
		t.Fatalf("next day: %v", err)
	}
	types := e.alertTypes()
	var rl, be bool
	for _, a := range types {
		rl = rl || a == AlertRateLimited
		be = be || a == AlertBudgetExceeded
	}
	if !rl || !be {
		t.Fatalf("alerts %v", types)
	}
}

func TestFiltersPersistAcrossRestart(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MatchInterval = 0; c.BloomCapacity = 1000 })
	ctx := context.Background()
	e.signFirst(bodyOpts{version: 1, seq: 1})
	var toks []string
	for i := 0; i < 2500; i++ { // three segments
		toks = append(toks, tokenFor(k1Secret(), "k1", "2026-10", "order", []byte(fmt.Sprintf("ORD-%05d", i))))
	}
	if err := e.svc.AddTokens(ctx, "2026-10", toks[:1200]); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Journal only (no snapshot before the "crash"): simulate by not
	// snapshotting, then reopening on the same database without Close.
	if err := e.svc.AddTokens(ctx, "2026-10", toks[1200:]); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(ctx, e.cfg, Options{Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	res, err := reopened.Match(ctx, []PolicyRef{{ID: "p-shop", Version: 1}}, []Candidate{{Value: "ORD-00000"}, {Value: "ORD-01500"}, {Value: "ORD-02499"}, {Value: "ORD-99999"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matches[0] || !res.Matches[1] || !res.Matches[2] || res.Matches[3] {
		t.Fatalf("after reopen %v", res.Matches)
	}
	st, _ := reopened.Status(ctx)
	if len(st.Filters) != 1 || st.Filters[0].Segments != 3 || st.Filters[0].Tokens != 2500 {
		t.Fatalf("filters %+v", st.Filters)
	}
}

func TestFilterRetention(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Retention = 48 * time.Hour })
	ctx := context.Background()
	if err := e.svc.AddTokens(ctx, "2026-09", []string{tokenFor(k1Secret(), "k1", "2026-09", "order", []byte("A"))}); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(72 * time.Hour)
	if err := e.svc.AddTokens(ctx, "2026-10", []string{tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("B"))}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	e.restart()
	st, _ := e.svc.Status(ctx)
	if len(st.Epochs) != 1 || st.Epochs[0] != "2026-10" {
		t.Fatalf("epochs %v", st.Epochs)
	}
}

func TestBloomFalsePositiveRate(t *testing.T) {
	seg := newBloomSeg(20000)
	for i := 0; i < 20000; i++ {
		var d digest
		copy(d[:], randSecret(16))
		seg.add(d)
	}
	fp := 0
	for i := 0; i < 200000; i++ {
		var d digest
		copy(d[:], randSecret(16))
		if seg.has(d) {
			fp++
		}
	}
	if fp > 3 { // expected 0.2 at 1e-6
		t.Fatalf("%d false positives", fp)
	}
	m, k := bloomParams(1000000)
	if k != 20 || m < 28_000_000 || m > 29_000_000 {
		t.Fatalf("params m=%d k=%d", m, k)
	}
}

func TestAddTokensRejectsMalformed(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	if err := e.svc.AddTokens(ctx, "2026 10", nil); errCode(err) != "invalid_request" {
		t.Fatal(err)
	}
	if err := e.svc.AddTokens(ctx, "2026-10", []string{"ORD-2026-000184"}); errCode(err) != "invalid_request" {
		t.Fatal(err)
	}
}
