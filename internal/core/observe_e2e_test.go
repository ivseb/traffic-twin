package core_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/core/demosim"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// TestObservePhaseEndToEnd is the plug & play onboarding (policy.md 7): a
// group and a token, the starter policy active at once (no approval, no
// policy to write), shapes from the demo traffic, then the observe version
// derived and signed by itself (origin observe-auto, actor system): hmac on
// the identifiers and the JWT subject, never a value in clear. The source
// captures tokens under it.
// reCodeKept is a value in clear with the shape of a code (sanitizer.md 5.6).
var reCodeKept = regexp.MustCompile(`^keep:[A-Za-z_-]{2,32}$`)

func TestObservePhaseEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end acceptance test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &vclock{t: time.Now().UTC().Truncate(time.Second)}
	kgDir, err := os.MkdirTemp("", "ttobs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(kgDir) })
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: kgDir, Now: clock.Now,
		Logger: keyguard.NewLogger(io.Discard, "error", "text"),
		Tune:   func(c *keyguard.Config) { c.MatchInterval, c.PackInterval, c.BloomCapacity = 0, 0, 200000 }})
	if err != nil {
		t.Fatal(err)
	}
	defer kg.Close()
	dir := t.TempDir()
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(dir, kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.PublicURL = "https://" + intakeLn.Addr().String()
	cfg.Fleet.ClientCertTTL = 30 * 24 * time.Hour
	cfg.Fleet.PolicyMaxAge = 30 * 24 * time.Hour
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = 50*time.Millisecond, 50*time.Millisecond
	cfg.Fleet.Observe = config.Observe{Enabled: true, After: 15 * time.Minute, MinEvents: 200, Interval: 50 * time.Millisecond, Codes: true}
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = 365 * 24 * time.Hour
	cfg.Miner.Schedule = 0
	cfg.Log.Level = "error"
	c, err := core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-e2e", AdminListener: adminLn, IntakeListener: intakeLn,
		Now: clock.Now, Logger: server.NewLogger(io.Discard, "error", "text"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(ctx) }()
	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	base := "https://" + adminLn.Addr().String()
	eventually(t, 5*time.Second, "readyz", func() bool {
		resp, err := hc.Get(base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	ada := signIn(t, base, hc, "/api/v1/setup", map[string]string{"setup_token": c.SetupToken(), "username": "ada", "password": testPassword})

	// The wizard: the service name, a token, the starter policy with
	// defaults only (kid from keyguard, epoch of the month). No approval.
	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "shop", "allowed_service_names": []string{"shop-api"}, "policy_id": nil})
	var tok struct {
		Token string `json:"token"`
	}
	ada.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "shop", "token_type": "one_time"}, &tok)
	var pv struct {
		PolicyID     string `json:"policy_id"`
		Version      int64  `json:"version"`
		Status       string `json:"status"`
		ApprovalMode string `json:"approval_mode"`
		OpensValues  bool   `json:"opens_values"`
	}
	ada.json(201, "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"sampling_rate": "1"}, &pv)
	if pv.Status != "active" || pv.ApprovalMode != "observe" || pv.OpensValues {
		t.Fatalf("starter: %+v", pv)
	}

	keyText, _ := os.ReadFile(kg.HMACKeyFile)
	keys, err := sanitizer.ParseKeys(string(keyText))
	if err != nil {
		t.Fatal(err)
	}
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: cfg.Fleet.PublicURL, Token: tok.Token, StateDir: filepath.Join(dir, "source"),
		Kind: "sdk-go", Version: "0.1.0", ServiceName: "shop-api", Instance: "obs-1", Keys: keys, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 40 * time.Millisecond, PolicyPollInterval: 40 * time.Millisecond, Now: clock.Now,
		Exporter: sourceclient.ExporterOptions{MaxEvents: 20000, FlushInterval: 20 * time.Millisecond, BaseBackoff: 10 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, MaxRetries: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	src.Start(ctx)
	defer func() {
		cctx, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_ = src.Close(cctx)
	}()
	eventually(t, 10*time.Second, "source capturing under the starter policy", func() bool { _, ok := src.Active(); return ok })

	type observe struct {
		Phase          string `json:"phase"`
		ObserveVersion int64  `json:"observe_version"`
		Events         int64  `json:"events"`
		Masked         []struct {
			Service, Op, Part, Kind, Field, Domain string
		} `json:"masked"`
		Identity *struct {
			Name     string `json:"name"`
			JWTClaim string `json:"jwt_claim"`
		} `json:"identity"`
	}
	var st observe
	ada.json(200, "GET", "/api/v1/fleet/groups/shop/observe", nil, &st)
	if st.Phase != "listening" || len(st.Masked) != 0 {
		t.Fatalf("before traffic: %+v", st)
	}

	// Shapes: a few hours of demo traffic, sanitized by the source.
	send := func(sim *demosim.Sim, version int64) {
		t.Helper()
		xs := sim.Exchanges()
		before := c.Intake().SourceStats(src.Identity().SourceID).Accepted
		for i := range xs {
			x := &xs[i]
			clock.Set(x.TS)
			cp, ok := src.Active()
			for wait := time.Now(); !ok || (version > 0 && cp.Policy.Policy.Version < version); cp, ok = src.Active() {
				if time.Since(wait) > 10*time.Second {
					t.Fatalf("source not capturing under v%d at exchange %d (state %s)", version, i, src.State())
				}
				src.Kick()
				time.Sleep(2 * time.Millisecond)
			}
			by := x.SampledBy()
			if by == sanitizer.BySubject && cp.Policy.Policy.Subject == nil {
				by = sanitizer.ByTrace
			}
			out, err := cp.Engine.Sanitize(&x.Ex, x.TS, by)
			if err != nil {
				t.Fatalf("sanitize: %v", err)
			}
			meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
				TS: x.TS, LatencyMS: x.Latency, Status: x.Ex.Status, TraceID: x.Trace, SpanID: x.Span, ParentSpanID: x.Parent}, cp.Policy)
			ev, err := sanitizer.BuildEvent(meta, out)
			if err != nil {
				t.Fatalf("build event: %v", err)
			}
			if i%256 == 0 {
				for src.Stats().QueueEvents > 10000 {
					time.Sleep(2 * time.Millisecond)
				}
			}
			src.Emit(sourceclient.Event{JSON: ev, TS: x.TS.Truncate(time.Millisecond), TraceID: x.Trace, SpanID: x.Span, PolicyHash: cp.Policy.Hash})
		}
		// While tt-core swaps the observe version the source stops capturing for
		// an instant and fails closed: an event emitted right then is not
		// captured. Wait for the queue to drain and allow that rare loss.
		eventually(t, 60*time.Second, "events stored", func() bool {
			s := c.Intake().SourceStats(src.Identity().SourceID)
			got := int(s.Accepted-before) + int(s.RejectedTotal)
			return got >= len(xs) || (src.Stats().QueueEvents == 0 && got >= len(xs)*99/100)
		})
		if err := c.Intake().WaitIdle(ctx); err != nil {
			t.Fatal(err)
		}
		if s := c.Intake().SourceStats(src.Identity().SourceID); s.RejectedTotal > 0 {
			t.Fatalf("rejected events: %v", s.Rejected)
		}
		clock.Set(sim.End().Add(time.Minute))
		ada = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "ada", "password": testPassword})
	}
	start := clock.Now().Truncate(time.Hour).Add(time.Hour)
	send(demosim.Run(demosim.Config{Seed: 11, Customers: 150, Days: 1, Start: start}), pv.Version)

	var ov struct {
		Status       string `json:"status"`
		Origin       string `json:"origin"`
		ProposedBy   string `json:"proposed_by"`
		ApprovalMode string `json:"approval_mode"`
		Author       string `json:"author_yaml"`
		Approvals    []any  `json:"approvals"`
	}
	// tt-core derives the observe version by itself. It may derive a newer one
	// while traffic is still being processed (codes detected later supersede the
	// first version), so read the version the phase points at until it is active.
	eventually(t, 20*time.Second, "observe version active", func() bool {
		ada.json(200, "GET", "/api/v1/fleet/groups/shop/observe", nil, &st)
		if st.Phase != "masked" {
			return false
		}
		ada.json(200, "GET", "/api/v1/fleet/policies/p-shop/versions/"+itoaE2E(st.ObserveVersion), nil, &ov)
		return ov.Status == "active"
	})
	if ov.Status != "active" || ov.Origin != "observe-auto" || ov.ProposedBy != "system" || ov.ApprovalMode != "observe" || len(ov.Approvals) != 0 {
		t.Fatalf("observe version: %+v", ov)
	}
	t.Logf("observe version:\n%s", ov.Author)
	for _, want := range []string{"hmac(order)", "hmac(customer)", "jwt_claim: sub"} {
		if !strings.Contains(ov.Author, want) {
			t.Errorf("observe version without %q", want)
		}
	}
	for _, never := range []string{"keep", "bucket", "email", "shippingAddress", "authorization: "} {
		if strings.Contains(ov.Author, never) {
			t.Errorf("observe version opens %q", never)
		}
	}
	if st.Identity == nil || st.Identity.JWTClaim != "sub" || len(st.Masked) == 0 {
		t.Fatalf("observe status: %+v", st)
	}
	// The audit trail names the system as actor of the automatic version.
	dump := string(ada.must(200, "GET", "/api/v1/audit/export", nil))
	sys := false
	for _, line := range strings.Split(dump, "\n") {
		sys = sys || (strings.Contains(line, `"action":"policy.observe-auto"`) && strings.Contains(line, `"kind":"system"`))
	}
	if !sys {
		t.Errorf("no policy.observe-auto audit entry by the system")
	}
	if t.Failed() {
		t.FailNow()
	}

	// Capture under the observe version: identifiers as tokens; the only
	// values in clear are codes (statuses, currencies) of code-like fields.
	from := clock.Now()
	send(demosim.Run(demosim.Config{Seed: 12, Customers: 150, Days: 1, Start: from.Add(time.Minute)}), st.ObserveVersion)
	var tokens, kept, subjects int
	err = c.Intake().Store().Scan(ctx, intake.Query{PolicyID: "p-shop", From: from}, func(se *intake.StoredEvent) error {
		ev := se.Event
		// tt-core may derive a newer observe version while this traffic flows
		// (codes detected later): every observe version must hold.
		if ev.Policy.Version < st.ObserveVersion {
			return nil
		}
		if ev.Subject != "" {
			subjects++
		}
		if ev.Resp != nil && ev.Resp.Body != nil {
			for _, v := range leaves(*ev.Resp.Body) {
				switch {
				case strings.HasPrefix(v, "tk1:"):
					tokens++
				case strings.HasPrefix(v, "keep:"):
					kept++
					if !reCodeKept.MatchString(v) {
						return fmt.Errorf("a value in clear that is not a code: %q", v)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokens == 0 || subjects == 0 || kept == 0 {
		t.Fatalf("capture under the observe version: %d tokens, %d subjects, %d kept values", tokens, subjects, kept)
	}
}

func itoaE2E(n int64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
