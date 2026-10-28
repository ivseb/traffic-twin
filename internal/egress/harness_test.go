package egress_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/egress"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

const carrierOrigin = "https://api.carrier.example"

type env struct {
	t     testing.TB
	core  *fakecore.Core
	up    *httptest.Server
	upFn  atomic.Pointer[http.HandlerFunc]
	src   *sourceclient.Source
	px    *egress.Proxy
	front *httptest.Server
	cl    *http.Client
}

type envOpts struct {
	noPolicy   bool
	noSource   bool
	noKeys     bool
	plainUp    bool
	capture    egress.CaptureConfig
	onSanitize func()
	policy     func(core *fakecore.Core, upURL string) []byte
	srcMod     func(*sourceclient.Config)
	upstreams  func(upURL string) []egress.Upstream
	aliasPol   bool
}

func newEnv(t testing.TB, o envOpts) *env {
	t.Helper()
	e := &env{t: t}
	e.core = fakecore.New(t, "shop")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no handler", 500) })
	e.upFn.Store(&h)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*e.upFn.Load())(w, r) })
	if o.plainUp {
		e.up = httptest.NewServer(dispatch)
	} else {
		e.up = httptest.NewTLSServer(dispatch)
	}
	t.Cleanup(e.up.Close)

	if !o.noPolicy {
		if o.policy != nil {
			e.core.SetPolicy(o.policy(e.core, e.up.URL))
		} else {
			e.core.SetPolicy(e.core.Compile(fakecore.AuthorPolicy, 1, 1))
		}
	}
	cfg := egress.Config{Capture: o.capture, OnSanitize: o.onSanitize, AliasFromPolicy: o.aliasPol, Version: "test"}
	if o.upstreams != nil {
		cfg.Upstreams = o.upstreams(e.up.URL)
	} else {
		cfg.Upstreams = []egress.Upstream{{Alias: "carrier", URL: e.up.URL, CaptureOrigin: carrierOrigin}}
	}
	if !o.plainUp {
		cfg.ExtraCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.up.Certificate().Raw})
	}
	var px *egress.Proxy
	if !o.noSource {
		keys, kids := fakecore.HMACKeys()
		if o.noKeys {
			keys, kids = emptyKeys()
		}
		sc := sourceclient.Config{
			EnrollURL: e.core.URL, Token: e.core.Token, StateDir: t.TempDir(),
			Kind: "egress", Version: "0.1.0", ServiceName: "egress-svc", Keys: keys, KeyKids: kids,
			HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond,
			Exporter: sourceclient.ExporterOptions{FlushInterval: 15 * time.Millisecond, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
			OnPolicy: func(v *policyVerified) {
				if px != nil {
					px.SetPolicy(v)
				}
			},
		}
		if o.srcMod != nil {
			o.srcMod(&sc)
		}
		var err error
		e.src, err = sourceclient.New(sc)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Source = e.src
	}
	var err error
	e.px, err = egress.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	px = e.px
	e.front = httptest.NewServer(e.px)
	e.cl = &http.Client{Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 64}, Timeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	if e.src != nil {
		e.src.Start(ctx)
	}
	t.Cleanup(func() {
		e.front.Close()
		cctx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = e.px.Close(cctx)
		if e.src != nil {
			_ = e.src.Close(cctx)
		}
		cancel()
	})
	return e
}

func (e *env) setUpstream(h http.HandlerFunc) { e.upFn.Store(&h) }

// waitCapturing waits until the source allows capture.
func (e *env) waitCapturing() {
	e.t.Helper()
	e.core.Eventually(5*time.Second, "capture to start", func() bool { _, ok := e.src.Active(); return ok })
}

type policyVerified = policy.Verified

func emptyKeys() (sanitizer.KeySet, []string) { return sanitizer.KeySet{}, nil }
