// Package core is the composition root of tt-core: it opens the store (after
// every package with migrations is imported), builds auth, audit and the
// HTTP server, the keyguard client and its adapters, Fleet, the intake,
// contract inference, drift alerts, the rule miner, worlds, the publication
// gate and the pack writer, mounts their admin APIs plus the endpoints that
// belong to no single package (users, exports, event export, jobs, keyguard
// status, retention), and runs everything with readiness checks and an
// ordered graceful shutdown.
//
// cmd/tt uses it for `tt core` and `tt dev up`; the end-to-end acceptance
// test of the product lives next to it.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/dateoff/dateoffsets"
	"github.com/ivseb/traffic-twin/internal/drift"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/idfmt/idformats"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/lifecycle"
	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/mockreg"
	"github.com/ivseb/traffic-twin/internal/packwriter"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Options configure a Core.
type Options struct {
	// Config is a validated configuration (config.Load).
	Config *config.Config
	// Version and Commit are reported by /api/v1/version and in the audit.
	Version, Commit string
	// Logger defaults to a JSON logger on stderr at cfg.Log.Level.
	Logger *slog.Logger
	// AdminListener and IntakeListener replace the configured addresses
	// (tests, tt dev up). When nil, Core listens on admin.addr and
	// intake.addr.
	AdminListener, IntakeListener net.Listener
	// UI is served at "/" on the admin listener (nil: 404).
	UI http.Handler
	// Now is the clock of the analysis components (fleet, intake,
	// contracts, drift, miner, worlds, packs). Authentication and TLS use
	// the real clock. Tests inject a virtual clock.
	Now func() time.Time
	// PasswordParams overrides the argon2id parameters (tests).
	PasswordParams *auth.PasswordParams
	// MockKubernetes overrides the Kubernetes API of the managed mocks
	// (APIServer, Token, CA, Client; tests with a fake API server).
	MockKubernetes mockreg.KubeConfig
	// MemoryLimit replaces the memory limit found at startup (cgroup,
	// /proc/meminfo, GOMEMLIMIT: memlimit.go), in bytes (tests, the perf
	// harness emulating a smaller host).
	MemoryLimit uint64
}

// Core is a composed, not yet running tt-core.
type Core struct {
	cfg     *config.Config
	opts    Options
	log     *slog.Logger
	now     func() time.Time
	dataDir string

	adminLn, intakeLn net.Listener

	db     *store.DB
	audit  *audit.Log
	auth   *auth.Service
	srv    *server.Server
	kg     *client.Client
	fleet  *fleet.Fleet
	intake *intake.Intake
	eng    *contract.Engine
	drift  *drift.Manager
	miner  *miner.Service
	world  *world.Service
	packs  *packwriter.Service
	mocks  *mockreg.Registry

	labels    labels
	policies  *policyWatcher
	jobs      *jobs
	alerts    *alertBridge
	lifecycle *lifecycle.Manager

	mockKube mockreg.KubeConfig

	setupToken string
	memLimit   uint64 // memory limit (0: unknown), memlimit.go
	heavy      *heavyGate
	minerMax   int // effective miner.max_events
	// syncWaitOverride replaces syncWait (tests).
	syncWaitOverride time.Duration
	serving          atomic.Bool
	closeOnce        sync.Once
	closeErr         error
	ran              atomic.Bool
}

// New composes tt-core. On error everything opened so far is closed.
func New(ctx context.Context, o Options) (c *Core, err error) {
	if o.Config == nil {
		return nil, errors.New("core: no configuration")
	}
	cfg := o.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if o.Logger == nil {
		o.Logger = server.NewLogger(os.Stderr, cfg.Log.Level, cfg.Log.Format)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	c = &Core{cfg: cfg, opts: o, log: o.Logger, now: o.Now, adminLn: o.AdminListener, intakeLn: o.IntakeListener, mockKube: o.MockKubernetes}
	c.memLimit = applyMemoryLimit(o.Logger, o.MemoryLimit)
	c.heavy = newHeavyGate(heavySlots(c.memLimit))
	c.minerMax = c.sizeMinerWindow()
	o.Logger.Info("heavy jobs", "slots", c.heavy.capacity(), "miner_max_events", c.minerMax)
	defer func() {
		if err != nil {
			c.closeAll()
			c = nil
		}
	}()

	abs, err := filepath.Abs(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("core: storage.path: %w", err)
	}
	c.dataDir = filepath.Dir(abs)

	// Listeners first: a port already in use fails before any state is
	// touched, and the readiness check knows the intake listener.
	if c.adminLn == nil {
		if c.adminLn, err = net.Listen("tcp", cfg.Admin.Addr); err != nil {
			return nil, fmt.Errorf("core: admin listener: %w", err)
		}
	}
	if c.intakeLn == nil && cfg.Intake.Addr != "" {
		if c.intakeLn, err = net.Listen("tcp", cfg.Intake.Addr); err != nil {
			return nil, fmt.Errorf("core: intake listener: %w", err)
		}
	}

	// keyguard client: it holds no key, only tt-core's TLS identity.
	if c.kg, err = client.New(client.Config{
		URL: cfg.Keyguard.URL, ClientCert: cfg.Keyguard.ClientCertFile, ClientKey: cfg.Keyguard.ClientKeyFile,
		CA: cfg.Keyguard.CAFile, ServerPin: cfg.Keyguard.ServerPin, Timeout: cfg.Keyguard.Timeout,
	}); err != nil {
		return nil, fmt.Errorf("core: %w", err)
	}

	// The store applies the migrations of every imported package
	// (audit, auth, fleet, intake, contract, drift, miner, world, gate).
	if c.db, err = store.Open(ctx, cfg.Storage.Path); err != nil {
		return nil, err
	}
	c.audit = audit.New(c.db)
	if c.auth, err = auth.New(c.db, c.audit, authOptions(cfg, c.log, o.PasswordParams, c.now)); err != nil {
		return nil, err
	}
	if c.srv, err = server.New(*cfg, server.Deps{Logger: c.log, Auth: c.auth, Audit: c.audit, DB: c.db, UI: o.UI}); err != nil {
		return nil, err
	}
	if err := c.compose(ctx); err != nil {
		return nil, err
	}
	if _, err := c.audit.Record(ctx, audit.Event{
		Actor: systemActor, Action: "core.start", Target: audit.Target{Type: "process"}, Outcome: audit.Success,
		Details: map[string]string{"version": audit.SafeValue(o.Version)},
	}); err != nil {
		return nil, err
	}
	if c.setupToken, err = c.auth.EnsureSetupToken(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

var systemActor = audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}

// compose builds and wires the components, in dependency order.
func (c *Core) compose(ctx context.Context) error {
	cfg := c.cfg
	var err error
	c.alerts = &alertBridge{log: c.log}
	c.jobs = newJobs(filepath.Join(c.dataDir, "exports"), cfg.Retention.Exports, c.log)

	// Fleet: enrollment, Fleet CA, signed policy distribution, health.
	validity := cfg.Fleet.PolicyValidity
	renewBefore := min(7*24*time.Hour, validity/4)
	if c.fleet, err = fleet.New(ctx, fleet.Options{
		DB: c.db, Audit: c.audit, Signer: &signer{kg: c.kg}, Alerts: c.alerts, Logger: c.log, Now: c.now,
		PublicURL: cfg.FleetPublicURL(), ServerNames: cfg.FleetServerNames(), CADir: cfg.Fleet.CADir,
		ClientCertTTL: cfg.Fleet.ClientCertTTL, HeartbeatInterval: cfg.Fleet.HeartbeatInterval,
		PolicyPollInterval: cfg.Fleet.PolicyPollInterval, PolicyMaxAge: cfg.Fleet.PolicyMaxAge,
		PolicyValidity: validity, PolicyRenewBefore: renewBefore,
		KeyRevokeMinConfirmed: &cfg.Fleet.KeyRotation.MinConfirmed, KeyConfirmWindow: cfg.Fleet.KeyRotation.Window,
		LastErrorsWindow: cfg.Fleet.LastErrorsWindow, EgressHosts: cfg.Fleet.EgressHosts, KMin: cfg.Miner.KMin,
		Observe: fleet.ObserveOptions{Enabled: cfg.Fleet.Observe.Enabled, After: cfg.Fleet.Observe.After, MinEvents: cfg.Fleet.Observe.MinEvents,
			Interval: cfg.Fleet.Observe.Interval, NoCodes: !cfg.Fleet.Observe.Codes, NoCodeDigits: !cfg.Fleet.Observe.CodeDigits,
			NoGraphQL: !cfg.Fleet.Observe.GraphQL, Quarantined: c.keepQuarantined},
		Bodies:           bodiesDefaults(cfg.Fleet.Sanitizer),
		EnrollIPLimit:    fleet.RateLimit{PerMinute: cfg.Fleet.EnrollRateLimit.IP.RequestsPerMinute, Burst: cfg.Fleet.EnrollRateLimit.IP.Burst},
		EnrollTokenLimit: fleet.RateLimit{PerMinute: cfg.Fleet.EnrollRateLimit.Token.RequestsPerMinute, Burst: cfg.Fleet.EnrollRateLimit.Token.Burst},
	}); err != nil {
		return err
	}

	// Intake: sources and policies from Fleet, real tokens to keyguard's
	// Bloom filter, quarantine alarms to the drift webhooks.
	icfg := intake.DefaultConfig()
	icfg.Retention, icfg.PurgeInterval = cfg.Retention.Events, cfg.Retention.PurgeInterval
	if c.intake, err = intake.New(ctx, icfg, intake.Deps{
		DB: c.db, Sources: c.fleet.IntakeSources(), Policies: c.fleet.IntakePolicies(),
		Tokens: c.kg, Alarms: c.alerts, Audit: c.audit, Logger: c.log, Now: c.now,
	}); err != nil {
		return err
	}
	if err := c.loadSettings(ctx); err != nil {
		return err
	}
	if err := c.loadLabels(ctx); err != nil {
		return err
	}
	c.fleet.SetApprovalTokens(c.auth)
	c.fleet.SetEventCounter(fleet.IntakeEventCounter(c.intake))
	c.intake.SetEgressHosts(c.fleet.EgressHosts)
	c.fleet.SetDiscoverySource(fleet.IntakeDiscovery(c.intake))
	c.fleet.Register(c.srv)
	c.intake.Mount(c.srv)

	// Contract inference and drift.
	c.policies = newPolicyWatcher(c.fleet, c.log)
	if c.eng, err = contract.New(contract.Config{
		KMin: cfg.Contract.KMin, MinSamples: cfg.Contract.MinSamples, Window: cfg.Contract.SnapshotWindow,
		Grace: cfg.Contract.Grace, KeepSnapshots: cfg.Contract.KeepSnapshots,
	}, contract.Deps{DB: c.db, Events: c.intake.Store(), Hints: c.policies.Hints(), Groups: c.fleet, Logger: c.log, Now: c.now}); err != nil {
		return err
	}
	c.policies.eng = c.eng
	rules := &ruleLookup{now: c.now}
	if c.drift, err = drift.New(drift.Config{
		Allow: cfg.Drift.WebhookAllow, AllowHTTP: cfg.Drift.WebhookAllowHTTP, DisableNonBreaking: !cfg.Drift.NotifyNonBreaking,
	}, drift.Deps{DB: c.db, Audit: c.audit, Logger: c.log, Now: c.now, Rules: rules, ServiceGroups: c.serviceGroups}); err != nil {
		return err
	}
	c.drift.Attach(c.eng)
	c.alerts.setManager(c.drift)

	// Rule miner: staleness to drift, gaps to the contract API.
	mcfg := miner.DefaultConfig()
	mcfg.KMin, mcfg.Window, mcfg.MaxEvents = cfg.Miner.KMin, cfg.Miner.Window, c.minerMaxEvents()
	if cfg.Miner.MinBirthShare > 0 {
		mcfg.MinBirthShare = cfg.Miner.MinBirthShare
	}
	switch {
	case cfg.Miner.CandidateMaxEvents > 0:
		mcfg.CandidateMaxEvents = cfg.Miner.CandidateMaxEvents
	case cfg.Miner.CandidateMaxEvents < 0:
		mcfg.CandidateMaxEvents = 0 // candidates below the threshold off
	}
	if cfg.Miner.StaleRuns > 0 {
		mcfg.StaleRuns = cfg.Miner.StaleRuns
	}
	if cfg.Miner.MinHorizon > 0 {
		mcfg.MinHorizon = cfg.Miner.MinHorizon
	}
	contracts := contractsSource{eng: c.eng, now: c.now, window: cfg.Miner.Window, cache: &liveContracts{}}
	if c.miner, err = miner.New(miner.Deps{
		DB: c.db, Events: c.intake.Store(), Domains: c.policies.Domains(), Audit: c.audit,
		Staleness: staleness{m: c.drift}, Config: &mcfg, Logger: c.log, Now: c.now,
		Contracts: &ruleContracts{c: c, src: contracts}, Groups: c.fleet,
		// Spec v1.18 (C0): groups marked as test are mined with their lower k.
		TestK: c.fleet.GroupTestK,
	}); err != nil {
		return err
	}
	rules.repo = c.miner.Repo()
	contract.Mount(c.srv, contract.APIDeps{Engine: c.eng, Audit: c.audit, ExtraGaps: []contract.GapSource{minerGaps{repo: c.miner.Repo(), kMin: cfg.Miner.KMin}}, Twin: twinStore{c}, Replaced: replacedLookup{c},
		// A snapshot infers the contract from the raw events of its window:
		// minutes on a busy service, longer than the write timeout.
		Wrap: func(h http.Handler) http.Handler {
			return c.longJobs(map[string]string{"POST /api/v1/contracts/{service}/snapshots": "contract.snapshot"}, h)
		}})
	drift.Mount(c.srv, c.drift)
	// The scheduled snapshot of every service is a heavy job too.
	c.eng.SetGate(func(ctx context.Context) (func(), error) { return c.heavy.acquire(ctx, nil) })
	c.srv.Mount("/api/v1/rules", c.longJobs(map[string]string{"POST /api/v1/rules/mine": "rules.mine"}, c.groupRules(c.rulesHandler())),
		auth.RoleRuleReviewer, auth.RoleOperator, auth.RoleAuditor)

	// Worlds, gate and pack writer.
	approved := approvedRules{repo: c.miner.Repo(), now: c.now}
	// Id formats chosen in the console (pack.md 4.3): worlds, packs and
	// mocks generate ids in those shapes.
	idFormats := &idformats.Store{DB: c.db, Audit: c.audit, Now: c.now, Logger: c.log}
	c.srv.Mount(idformats.Prefix, idFormats.Handler(), idformats.RolesRead...)
	// Relative dates chosen in the console (pack.md 4.4).
	dateOffsets := &dateoffsets.Store{DB: c.db, Audit: c.audit, Now: c.now, Logger: c.log}
	c.srv.Mount(dateoffsets.Prefix, dateOffsets.Handler(), dateoffsets.RolesRead...)
	if c.world, err = world.New(world.Options{
		DB: c.db, Audit: c.audit, Events: c.intake.Store(), Contracts: contracts, Rules: approved, Now: c.now,
		ProfileWindow: cfg.World.ProfileWindow, Locale: cfg.World.Locale, KMin: cfg.World.KMin, Logger: c.log, Groups: c.fleet,
		IDFormats: idFormats, DateOffsets: dateOffsets,
	}); err != nil {
		return err
	}
	tmp := filepath.Join(c.dataDir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	if c.packs, err = packwriter.New(packwriter.Options{
		DB: c.db, Audit: c.audit, Worlds: c.world, Keyguard: c.kg, Policies: c.policies, Rules: approved,
		Faults: &packwriter.EventFaults{Events: c.intake.Store(), Window: cfg.Miner.Window, Now: c.now, Groups: c.fleet}, Presets: presetStore{c},
		KMin: cfg.Gate.KMin, TTVersion: c.opts.Version, Locale: cfg.World.Locale, Now: c.now, TempDir: tmp, Logger: c.log,
		Approvals: approvalTokens{auth: c.auth, fleet: c.fleet, log: c.log}, ServiceGroups: c.serviceGroups,
		TestK: c.fleet.GroupTestK,
	}); err != nil {
		return err
	}
	c.auth.SetStepUpBinder(c.stepUpBinder)
	worldRoles := []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor} // as world.Mount
	c.srv.Mount(world.PrefixArchetypes, c.longJobs(map[string]string{"POST " + world.PrefixArchetypes + "/build": "archetypes.build"},
		kMinGuard(c.world.Handler(), cfg.World.KMin)), worldRoles...)
	c.srv.Mount(world.PrefixWorlds, c.longJobs(map[string]string{"POST " + world.PrefixWorlds: "world.generate"}, c.world.Handler()), worldRoles...)
	packs := gate.Handler(twinDefaults{PackService: packDefaults{PackService: c.packs, validDays: cfg.Gate.ValidDays}, c: c}, c.log, gate.WithAudit(c.audit))
	c.srv.Mount(gate.PrefixPacks, c.longJobs(map[string]string{"POST " + gate.PrefixPacks: "pack.build"}, packs), gate.MountRoles...)

	// Mock registry ("Mock" page) and the agent API of the mocks.
	if c.mocks, err = c.newMockRegistry(); err != nil {
		return err
	}
	c.mountMocks()

	// Data lifecycle: retention of every dataset, rollups, audit archive,
	// size budget (docs/DATA_LIFECYCLE.md).
	if c.lifecycle, err = c.newLifecycle(ctx); err != nil {
		return err
	}

	// Endpoints of the admin API that belong to no single package.
	c.mountAPI()

	// Readiness: db is built in; keyguard reachable; intake listening.
	c.srv.AddReadinessCheck("keyguard", func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return c.kg.Health(ctx)
	})
	if c.intakeLn != nil {
		c.srv.AddReadinessCheck("intake", func(context.Context) error {
			if !c.serving.Load() {
				return errors.New("intake listener not serving")
			}
			return nil
		})
	}
	c.policies.Refresh()
	if err := c.attributeLegacy(ctx); err != nil {
		c.log.Warn("core: attributing the data stored before groups to groups failed", "err", err)
	}
	return nil
}

// SetupToken is the one-time bootstrap token ("" once an administrator
// exists). It is meant for the operator console, never for the log.
func (c *Core) SetupToken() string { return c.setupToken }

// AdminAddr and IntakeAddr are the bound listener addresses.
func (c *Core) AdminAddr() net.Addr { return c.adminLn.Addr() }

// IntakeAddr is nil when the intake listener is disabled.
func (c *Core) IntakeAddr() net.Addr {
	if c.intakeLn == nil {
		return nil
	}
	return c.intakeLn.Addr()
}

// AdminScheme is https when the admin listener has TLS.
func (c *Core) AdminScheme() string {
	if c.cfg.Admin.TLS.Enabled() {
		return "https"
	}
	return "http"
}

// Fleet, Intake, Miner, Contracts and Keyguard expose components (tests,
// tt dev up).
func (c *Core) Fleet() *fleet.Fleet         { return c.fleet }
func (c *Core) Intake() *intake.Intake      { return c.intake }
func (c *Core) Miner() *miner.Service       { return c.miner }
func (c *Core) Contracts() *contract.Engine { return c.eng }
func (c *Core) Keyguard() *client.Client    { return c.kg }
func (c *Core) RefreshPolicies()            { c.policies.Refresh() }
func (c *Core) AdminHandler() http.Handler  { return c.srv.AdminHandler() }
func (c *Core) Server() *server.Server      { return c.srv }
func (c *Core) Config() *config.Config      { return c.cfg }
func (c *Core) Logger() *slog.Logger        { return c.log }
func (c *Core) DataDir() string             { return c.dataDir }
func (c *Core) Version() (string, string)   { return c.opts.Version, c.opts.Commit }
func (c *Core) background() []func(ctx context.Context) {
	fns := []func(context.Context){
		c.fleet.Run,
		func(ctx context.Context) {
			if err := c.eng.Run(ctx); err != nil && ctx.Err() == nil {
				c.log.Error("contract snapshots stopped", "err", err)
			}
		},
		c.drift.Run,
		c.policies.Run,
		c.jobs.Run,
		c.watchSources,
		c.runLifecycle,
	}
	if d := c.cfg.Miner.Schedule; d > 0 {
		fns = append(fns, func(ctx context.Context) { c.mineEvery(ctx, d) })
	}
	return fns
}

// Run serves until ctx is done, then shuts down in order: listeners
// (in-flight requests drain within admin.shutdown_timeout), background
// jobs, the intake (flushing its queue), the keyguard client and the
// store. It can be called once.
func (c *Core) Run(ctx context.Context) error {
	if !c.ran.CompareAndSwap(false, true) {
		return errors.New("core: already running")
	}
	bg, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, fn := range c.background() {
		wg.Add(1)
		go func() { defer wg.Done(); fn(bg) }()
	}
	c.serving.Store(true)
	serveErr := c.srv.Serve(ctx, c.adminLn, c.intakeLn)
	c.serving.Store(false)
	c.adminLn, c.intakeLn = nil, nil // closed by Serve

	stop()
	wg.Wait()
	return errors.Join(serveErr, c.Close())
}

// Close releases everything (Run calls it). Safe to call more than once.
func (c *Core) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.closeAll() })
	return c.closeErr
}

func (c *Core) closeAll() error {
	var errs []error
	if c.adminLn != nil {
		_ = c.adminLn.Close()
	}
	if c.intakeLn != nil {
		_ = c.intakeLn.Close()
	}
	if c.intake != nil {
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Admin.ShutdownTimeout)
		errs = append(errs, c.intake.Close(ctx))
		cancel()
	}
	if c.kg != nil {
		c.kg.Close()
	}
	if c.db != nil {
		errs = append(errs, c.db.Close())
	}
	return errors.Join(errs...)
}

// minerMaxEvents is the effective miner.max_events (sizeMinerWindow).
func (c *Core) minerMaxEvents() int {
	if c.minerMax > 0 {
		return c.minerMax
	}
	return c.sizeMinerWindow()
}

// sizeMinerWindow is miner.max_events, sized from the memory limit when 0
// and lowered to what fits in the limit when larger (a window with more
// events is narrowed to its newest ones instead of exhausting the memory:
// the OOM on a 4 GiB test core mined 1.95 M events with max_events 5 M and no
// limit known).
func (c *Core) sizeMinerWindow() int {
	fit := autoMinerEvents(c.memLimit, heavySlots(c.memLimit))
	n := c.cfg.Miner.MaxEvents
	switch {
	case n <= 0:
		return fit
	case c.memLimit > 0 && n > fit:
		c.log.Warn("miner.max_events lowered to what fits in the memory limit", "max_events", n, "fit", fit, "limit_mb", c.memLimit>>20)
		return fit
	}
	return n
}

// mineEvery runs the mining job every d (first run after one interval), as
// a job of kind rules.mine (owner: the system) through the heavy gate. A
// tick while a mining job is queued or running is skipped: that run covers
// the same window.
func (c *Core) mineEvery(ctx context.Context, d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.scheduledMine(ctx)
		}
	}
}

func (c *Core) scheduledMine(ctx context.Context) {
	j, joined := c.jobs.startOrJoin("rules.mine", "", true)
	if joined {
		c.log.Info("scheduled mining run skipped: a mining job is in progress", "job", j.ID)
		return
	}
	release, err := c.heavy.acquire(ctx, nil)
	if err != nil {
		c.jobs.fail(j, "canceled")
		return
	}
	defer release()
	c.jobs.setStatus(j, "running")
	c.policies.Refresh()
	rep, err := c.miner.RunOnce(ctx)
	if err != nil {
		c.jobs.fail(j, "mining_failed")
		if ctx.Err() == nil {
			c.log.Error("scheduled mining run failed", "err", err)
		}
		return
	}
	c.jobs.done(j, mineResult(rep, nil))
}

// PrintSetupToken writes the bootstrap token to the operator console
// (stdout), never to the structured log.
func PrintSetupToken(w io.Writer, token, baseURL string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "No administrator exists yet. Create the first one with this one-time setup token")
	fmt.Fprintf(w, "(valid %s, replaced at every restart until used, never shown again):\n\n", auth.SetupTokenTTL)
	fmt.Fprintf(w, "    %s\n\n", token)
	fmt.Fprintf(w, "Open %s/ or POST %s/api/v1/setup {\"setup_token\", \"username\", \"password\"}.\n\n", baseURL, baseURL)
}
