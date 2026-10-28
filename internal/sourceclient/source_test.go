package sourceclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

func newSource(t *testing.T, core *fakecore.Core, dir string, mod func(*sourceclient.Config)) *sourceclient.Source {
	t.Helper()
	keys, kids := fakecore.HMACKeys()
	cfg := sourceclient.Config{
		EnrollURL: core.URL, Token: core.Token, StateDir: dir,
		Kind: "egress", Version: "0.1.0", ServiceName: "egress-svc",
		Keys: keys, KeyKids: kids,
		HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond,
		Exporter: sourceclient.ExporterOptions{FlushInterval: 20 * time.Millisecond, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := sourceclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func start(t *testing.T, s *sourceclient.Source) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	t.Cleanup(func() {
		cctx, c2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer c2()
		_ = s.Close(cctx)
		cancel()
	})
}

func waitActive(t *testing.T, core *fakecore.Core, s *sourceclient.Source, want bool) {
	t.Helper()
	core.Eventually(5*time.Second, "capture active="+map[bool]string{true: "true", false: "false"}[want], func() bool {
		_, ok := s.Active()
		return ok == want
	})
}

func TestEnrollmentPinAndStatePermissions(t *testing.T) {
	core := fakecore.New(t, "shop")
	dir := filepath.Join(t.TempDir(), "state")
	s := newSource(t, core, dir, nil)
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	start(t, s)
	waitActive(t, core, s, true)

	if core.Enrollments() != 1 {
		t.Fatalf("enrollments = %d", core.Enrollments())
	}
	id := s.Identity()
	if id == nil || id.Group != "shop" || id.ServiceName != "egress-svc" || id.SourceID == "" {
		t.Fatalf("identity = %+v", id)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("state dir mode %v err %v", fi.Mode(), err)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) == 0 {
			t.Fatal("no state files")
		}
		for _, e := range entries {
			fi, _ := e.Info()
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v, want 0600", e.Name(), fi.Mode().Perm())
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "client.key")); err != nil {
		t.Fatal(err)
	}
	// A second source on the same state reuses the enrollment.
	cctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	_ = s.Close(cctx)
	s2 := newSource(t, core, dir, nil)
	if s2.Identity() == nil || s2.Identity().SourceID != id.SourceID {
		t.Fatal("enrollment not reused")
	}
	start(t, s2)
	waitActive(t, core, s2, true)
	if core.Enrollments() != 1 {
		t.Fatalf("enrollments after restart = %d", core.Enrollments())
	}
}

func TestEnrollPinMismatch(t *testing.T) {
	core := fakecore.New(t, "shop")
	_, _, err := sourceclient.Enroll(context.Background(), sourceclient.EnrollOptions{
		EnrollURL: core.URL, Token: fakecore.TokenWithPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		Source: sourceclient.SourceInfo{Kind: "egress", Version: "0.1.0", ServiceName: "egress-svc"},
	})
	if !errors.Is(err, sourceclient.ErrPinMismatch) {
		t.Fatalf("err = %v, want pin mismatch", err)
	}
	if core.Enrollments() != 0 {
		t.Fatal("enrolled despite the pin mismatch")
	}
	if _, _, err := sourceclient.Enroll(context.Background(), sourceclient.EnrollOptions{EnrollURL: core.URL, Token: "nope"}); !errors.Is(err, sourceclient.ErrTokenMalformed) {
		t.Fatalf("malformed token: %v", err)
	}
	if _, _, err := sourceclient.Enroll(context.Background(), sourceclient.EnrollOptions{EnrollURL: "http://x", Token: core.Token}); !errors.Is(err, sourceclient.ErrEnrollNotHTTPS) {
		t.Fatalf("plain http: %v", err)
	}
	// Right pin, unknown secret: the server refuses.
	_, _, err = sourceclient.Enroll(context.Background(), sourceclient.EnrollOptions{
		EnrollURL: core.URL, Token: fakecore.TokenWithPin(core.PinOfRoot()),
		Source: sourceclient.SourceInfo{Kind: "egress", Version: "0.1.0", ServiceName: "egress-svc"},
	})
	var se *sourceclient.StatusError
	if !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("err = %v, want 401", err)
	}
}

func TestNoCaptureBeforeHeartbeatAndPolicy(t *testing.T) {
	core := fakecore.New(t, "shop")
	s := newSource(t, core, t.TempDir(), nil)
	if _, ok := s.Active(); ok || s.State() != sourceclient.StateStarting {
		t.Fatalf("active before start: state %s", s.State())
	}
	start(t, s)
	// Heartbeats flow but no policy is assigned: never capture.
	core.Eventually(5*time.Second, "heartbeat", func() bool { return len(core.Heartbeats()) >= 2 })
	if _, ok := s.Active(); ok {
		t.Fatal("capturing without a policy")
	}
	if got := s.State(); got != "no_policy" {
		t.Fatalf("state = %s", got)
	}
	hbs := core.Heartbeats()
	if hbs[0].State != "starting" {
		t.Fatalf("first heartbeat state = %s", hbs[0].State)
	}
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	waitActive(t, core, s, true)
	if s.State() != "capturing" {
		t.Fatalf("state = %s", s.State())
	}
	core.Eventually(5*time.Second, "capturing heartbeat", func() bool {
		hs := core.Heartbeats()
		if len(hs) == 0 {
			return false
		}
		l := hs[len(hs)-1]
		return l.State == "capturing" && l.Policy != nil && l.Policy.IssuedSeq == 1
	})
}

func TestInvalidPoliciesFailClosed(t *testing.T) {
	core := fakecore.New(t, "shop")
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	now := time.Now()

	// Signed by a key the source never pinned.
	core.SetPolicy(core.CompileWith(fakecore.AuthorPolicy, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: now, Groups: []string{"shop"}}, "policy-evil", fakecore.ForeignKey()))
	core.Eventually(5*time.Second, "policy_rejected heartbeat", func() bool {
		hs := core.Heartbeats()
		return len(hs) > 0 && hs[len(hs)-1].State == "policy_rejected"
	})
	if _, ok := s.Active(); ok {
		t.Fatal("captured with an unsigned-by-us policy")
	}
	// Another group.
	core.SetPolicy(core.CompileWith(fakecore.AuthorPolicy, policy.CompileMeta{Version: 1, IssuedSeq: 2, CreatedAt: now, Groups: []string{"other"}}, fakecore.SigningKid, core.SigningPrivateKey()))
	time.Sleep(200 * time.Millisecond)
	if _, ok := s.Active(); ok {
		t.Fatal("captured with a policy for another group")
	}
	// A good one is accepted, then a replay with a lower issued_seq is not.
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 3, 10))
	waitActive(t, core, s, true)
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 2, 5))
	core.Eventually(5*time.Second, "stale policy refetched", func() bool { return core.PolicyFetches() > 3 })
	time.Sleep(150 * time.Millisecond)
	c, ok := s.Active()
	if !ok || c.Policy.Policy.IssuedSeq != 10 {
		t.Fatalf("stale policy replaced the good one: ok=%v", ok)
	}
	if st := s.Stats(); st.Policy == nil || st.Policy.IssuedSeq != 10 {
		t.Fatalf("stats policy = %+v", st.Policy)
	}
	// min_issued_seq raised above the current policy supersedes it for good.
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.MinIssuedSeq = 11 })
	waitActive(t, core, s, false)
}

// unsafeEnvelope returns a validly signed envelope whose body breaks
// hardening.md 2.1 H1 (keep on authorization): tt-core and keyguard would
// refuse to produce it, so the body is tampered with after compilation.
func unsafeEnvelope(t *testing.T, core *fakecore.Core, issuedSeq int64) []byte {
	t.Helper()
	var e struct {
		BodyB64 string `json:"body_b64"`
	}
	if err := json.Unmarshal(core.Compile(fakecore.AuthorPolicy, 1, issuedSeq), &e); err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(e.BodyB64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.DecodeBody(body)
	if err != nil {
		t.Fatal(err)
	}
	old := []byte(`"request":{"headers":{"content-type":{"action":"keep"}}}`)
	bad := bytes.Replace(body, old, []byte(`"request":{"headers":{"authorization":{"action":"keep"},"content-type":{"action":"keep"}}}`), 1)
	if bytes.Equal(bad, body) {
		t.Fatal("test body not tampered")
	}
	env, err := policy.Envelope(bad, p, fakecore.SigningKid, ed25519.Sign(core.SigningPrivateKey(), policy.SignedMessage(bad)))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Usability test 4: tt-core moves min_issued_seq to the new policy in the
// same heartbeat that announces it; the source switches without an error or
// a policy_rejected state.
func TestNormalPolicyChangeReportsNoError(t *testing.T) {
	core := fakecore.New(t, "shop")
	s := newSource(t, core, t.TempDir(), nil)
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	start(t, s)
	waitActive(t, core, s, true)
	from := len(core.Heartbeats())
	for seq := int64(2); seq <= 4; seq++ {
		core.SetPolicy(core.Compile(fakecore.AuthorPolicy, seq, seq))
		core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.MinIssuedSeq = seq })
		core.Eventually(5*time.Second, "switched", func() bool {
			c, ok := s.Active()
			return ok && c.Policy.Policy.IssuedSeq == seq
		})
	}
	for _, h := range core.Heartbeats()[from:] {
		if h.State == "policy_rejected" {
			t.Fatalf("policy_rejected during a normal change")
		}
	}
	for _, e := range s.Stats().LastErrors {
		if strings.HasPrefix(e.Code, "policy_") {
			t.Fatalf("error during a normal change: %s", e.Code)
		}
	}
}

func TestUnsafePolicyRefused(t *testing.T) {
	core := fakecore.New(t, "shop")
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	core.SetPolicy(unsafeEnvelope(t, core, 1))
	core.Eventually(5*time.Second, "policy_rejected heartbeat", func() bool {
		hs := core.Heartbeats()
		return len(hs) > 0 && hs[len(hs)-1].State == "policy_rejected"
	})
	if _, ok := s.Active(); ok {
		t.Fatal("captured with an unsafe policy")
	}
	core.Eventually(5*time.Second, "policy_unsafe in last_errors", func() bool {
		for _, e := range s.Stats().LastErrors {
			if e.Code == "policy_unsafe" {
				return true
			}
		}
		return false
	})
	// A safe policy replaces the refusal.
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 2))
	waitActive(t, core, s, true)
}

func TestKillSwitchIsPersistent(t *testing.T) {
	core := fakecore.New(t, "shop")
	dir := t.TempDir()
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, dir, nil)
	start(t, s)
	waitActive(t, core, s, true)

	core.Kill(true)
	waitActive(t, core, s, false)
	if s.State() != "killed" {
		t.Fatalf("state = %s", s.State())
	}
	cctx, c := context.WithTimeout(context.Background(), time.Second)
	_ = s.Close(cctx)
	c()

	// Restart without talking to the core: the stop survives.
	s2 := newSource(t, core, dir, nil)
	if _, ok := s2.Active(); ok {
		t.Fatal("restarted source captures although the kill switch was on")
	}
	start(t, s2)
	time.Sleep(200 * time.Millisecond)
	if _, ok := s2.Active(); ok {
		t.Fatal("kill switch not honored after restart")
	}
	core.Kill(false)
	waitActive(t, core, s2, true)
}

func TestRevokedSourceStops(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	waitActive(t, core, s, true)
	core.RevokeSource(s.Identity().SourceID, true)
	waitActive(t, core, s, false)
}

func TestSigningKeyRotationAndRevocation(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	dir := t.TempDir()
	s := newSource(t, core, dir, nil)
	start(t, s)
	waitActive(t, core, s, true)

	add, priv := core.EndorseNewKey("policy-test-2")
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.AddSigningKeys = []sourceclient.AddSigningKey{add} })
	core.Eventually(5*time.Second, "key pinned", func() bool {
		id := s.Identity()
		for _, k := range id.PinnedKeys {
			if k.Kid == "policy-test-2" {
				return true
			}
		}
		return false
	})
	core.SetPolicy(core.CompileWith(fakecore.AuthorPolicy, policy.CompileMeta{Version: 2, IssuedSeq: 2, CreatedAt: time.Now(), Groups: []string{"shop"}}, "policy-test-2", priv))
	core.Eventually(5*time.Second, "policy by the new key", func() bool {
		c, ok := s.Active()
		return ok && c.Policy.Policy.IssuedSeq == 2
	})
	// The heartbeat reports both trusted kids (tt-core waits for this
	// before it allows revoking the old key), and the key repeated at every
	// heartbeat is not an error.
	core.Eventually(5*time.Second, "signing_kids reported", func() bool {
		hbs := core.Heartbeats()
		return len(hbs) > 0 && slices.Equal(hbs[len(hbs)-1].SigningKids, []string{fakecore.SigningKid, "policy-test-2"})
	})
	time.Sleep(150 * time.Millisecond)
	for _, e := range s.Stats().LastErrors {
		if strings.HasPrefix(e.Code, "signing_key") {
			t.Fatalf("repeated endorsed key reported as error: %+v", e)
		}
	}
	// An endorsement by nobody is refused.
	bad := add
	bad.Kid, bad.Endorsement = "policy-test-3", add.Endorsement
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.AddSigningKeys = []sourceclient.AddSigningKey{bad} })
	time.Sleep(150 * time.Millisecond)
	for _, k := range s.Identity().PinnedKeys {
		if k.Kid == "policy-test-3" {
			t.Fatal("unendorsed key pinned")
		}
	}
	// Revoking the key in use stops capture immediately and forever.
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) {
		r.AddSigningKeys = nil
		r.RevokeSigningKeys = []string{"policy-test-2"}
	})
	waitActive(t, core, s, false)
	// The revocation is persisted.
	cctx, c := context.WithTimeout(context.Background(), time.Second)
	_ = s.Close(cctx)
	c()
	s2 := newSource(t, core, dir, nil)
	for _, k := range s2.Identity().PinnedKeys {
		if k.Kid == "policy-test-2" {
			t.Fatal("revoked key pinned again after restart")
		}
	}
}

// RT3-KEY-3: revocations apply before additions, so a key endorsed by a
// kid revoked in the same heartbeat is never pinned.
func TestSigningKeyEndorsedByKidRevokedInSameHeartbeat(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	waitActive(t, core, s, true)
	add, _ := core.EndorseNewKey("evil-rt3")
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) {
		r.RevokeSigningKeys = []string{fakecore.SigningKid}
		r.AddSigningKeys = []sourceclient.AddSigningKey{add}
	})
	waitActive(t, core, s, false)
	core.Eventually(5*time.Second, "empty signing_kids", func() bool {
		hbs := core.Heartbeats()
		return len(hbs) > 0 && hbs[len(hbs)-1].SigningKids != nil && len(hbs[len(hbs)-1].SigningKids) == 0
	})
	for _, k := range s.Identity().PinnedKeys {
		if k.Kid == "evil-rt3" {
			t.Fatal("key endorsed by a kid revoked in the same heartbeat was pinned")
		}
	}
}

func TestSamplingOverrideAndExpiry(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	waitActive(t, core, s, true)
	if c, _ := s.Active(); c.OverrideBP != -1 {
		t.Fatalf("override = %d", c.OverrideBP)
	}
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { v := 250; r.SamplingOverrideBP = &v })
	core.Eventually(5*time.Second, "override", func() bool { c, _ := s.Active(); return c.OverrideBP == 250 })
}

func TestCertificateRenewal(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), nil)
	start(t, s)
	waitActive(t, core, s, true)
	old := s.Identity().ClientCertPEM
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { past := time.Now().Add(-time.Minute); r.RenewBefore = &past })
	core.Eventually(5*time.Second, "renewal", func() bool { return core.Renewals() >= 1 })
	core.Eventually(5*time.Second, "new cert", func() bool { return s.Identity().ClientCertPEM != old })
	core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.RenewBefore = nil })
	// The new certificate works for mTLS calls.
	n := len(core.Heartbeats())
	core.Eventually(5*time.Second, "heartbeats after renewal", func() bool { return len(core.Heartbeats()) > n+2 })
}

func emit(s *sourceclient.Source, n int) {
	for i := 0; i < n; i++ {
		s.Emit(fakecore.SampleEvent(s.Identity().SourceID, "egress", "0.1.0", time.Now()))
	}
}

// exporterBatchSource starts a source whose exporter sends exactly one batch
// of n events per round: the periodic flush is effectively off and the batch
// size is n, so the worker only wakes up when the n-th event is queued and then
// takes all of them. Nothing here depends on timing, so the number of requests,
// the batch contents and the counters are exact.
func exporterBatchSource(t *testing.T, core *fakecore.Core, n int) *sourceclient.Source {
	t.Helper()
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), func(c *sourceclient.Config) {
		c.Exporter.BatchEvents = n
		c.Exporter.FlushInterval = time.Hour
	})
	start(t, s)
	waitActive(t, core, s, true)
	return s
}

// counterIs waits for a counter to reach exactly want. Counters are updated by
// the exporter after the fake core has answered, so they must be awaited, not
// read right after the events arrived.
func counterIs(t *testing.T, core *fakecore.Core, what string, c interface{ Load() int64 }, want int64) {
	t.Helper()
	core.Eventually(5*time.Second, what, func() bool { return c.Load() == want })
}

func TestExporterRetryDropAndPartial(t *testing.T) {
	t.Run("retry", func(t *testing.T) {
		core := fakecore.New(t, "shop")
		s := exporterBatchSource(t, core, 3)
		// 503 twice (with Retry-After 0), then success: nothing is lost and the
		// batch is delivered once.
		core.FailLogs(2, 503, "0")
		emit(s, 3)
		core.WaitEvents(3, 5*time.Second)
		counterIs(t, core, "events sent", &s.Counters().EventsSent, 3)
		c := s.Counters().Snapshot()
		if c.SendErrors != 2 || c.EventsRejected != 0 || c.EventsDroppedQueue != 0 {
			t.Fatalf("counters = %+v", c)
		}
		if n, b := len(core.Events()), core.Batches(); n != 3 || b != 1 {
			t.Fatalf("events = %d, batches = %d; want 3 events in 1 batch", n, b)
		}
	})

	t.Run("client error is dropped without retry", func(t *testing.T) {
		core := fakecore.New(t, "shop")
		s := exporterBatchSource(t, core, 2)
		// 400 is dropped without retry and counted.
		core.FailLogs(1, 400, "")
		emit(s, 2)
		counterIs(t, core, "events rejected", &s.Counters().EventsRejected, 2)
		c := s.Counters().Snapshot()
		if c.SendErrors != 1 || c.EventsSent != 0 {
			t.Fatalf("counters = %+v", c)
		}
		if n := len(core.Events()); n != 0 {
			t.Fatalf("rejected batch reached the intake (%d events)", n)
		}
		// A retry of the rejected batch would be sent before the next one (one
		// sender, in order): the next batch must be the first thing delivered.
		emit(s, 2)
		core.WaitEvents(2, 5*time.Second)
		counterIs(t, core, "events sent", &s.Counters().EventsSent, 2)
		if n, b := len(core.Events()), core.Batches(); n != 2 || b != 1 {
			t.Fatalf("events = %d, batches = %d; the rejected batch was retried", n, b)
		}
		if c := s.Counters().Snapshot(); c.EventsRejected != 2 || c.SendErrors != 1 {
			t.Fatalf("counters = %+v", c)
		}
	})

	t.Run("partial success", func(t *testing.T) {
		core := fakecore.New(t, "shop")
		s := exporterBatchSource(t, core, 3)
		// partialSuccess: rejected records are counted, not retried, and only
		// the accepted ones count as sent.
		core.RejectLogs(1)
		emit(s, 3)
		core.WaitEvents(3, 5*time.Second)
		counterIs(t, core, "events rejected", &s.Counters().EventsRejected, 1)
		counterIs(t, core, "events sent", &s.Counters().EventsSent, 2)
		if b := core.Batches(); b != 1 {
			t.Fatalf("batches = %d, want 1 (rejected records are not retried)", b)
		}
		if c := s.Counters().Snapshot(); c.SendErrors != 0 || c.EventsDroppedQueue != 0 {
			t.Fatalf("counters = %+v", c)
		}
	})
}

func TestExporterBoundedQueueDropsOldest(t *testing.T) {
	core := fakecore.New(t, "shop")
	core.SetPolicy(core.Compile(fakecore.AuthorPolicy, 1, 1))
	s := newSource(t, core, t.TempDir(), func(c *sourceclient.Config) {
		c.Exporter.MaxEvents = 10
		c.Exporter.BatchEvents = 4
	})
	start(t, s)
	waitActive(t, core, s, true)
	block := make(chan struct{})
	core.BlockLogs(block)
	emit(s, 200)
	if c := s.Counters().Snapshot(); c.EventsDroppedQueue == 0 {
		t.Fatalf("no drops with a blocked intake: %+v", c)
	}
	if st := s.Stats(); st.QueueEvents > 10 {
		t.Fatalf("queue = %d events, bound 10", st.QueueEvents)
	}
	// Killing drops what is queued and never blocks.
	core.Kill(true)
	waitActive(t, core, s, false)
	if st := s.Stats(); st.QueueEvents != 0 {
		t.Fatalf("queue after kill = %d", st.QueueEvents)
	}
	close(block)
}
