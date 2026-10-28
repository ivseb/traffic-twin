package core

import (
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/mockreg"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/world"
)

// The "Mock" page: the registry of the mocks connected to the console
// (internal/mockreg) and the one action that hides the packs, "Prepara e
// avvia il mock" (POST /api/v1/mocks/prepare): archetypes of the group,
// world, pack (gate and keyguard signature), publication, and the mock
// started (Kubernetes) or refreshed (the connected mocks switch to the new
// pack by themselves).

// mockPacks adapts the pack writer to mockreg.PackSource.
type mockPacks struct{ c *Core }

func (m mockPacks) LatestPublished(ctx context.Context, group string) (string, error) {
	return m.c.packs.LatestPublished(ctx, group)
}

func (m mockPacks) Archive(ctx context.Context, id, group string, actor audit.Actor) ([]byte, error) {
	b, err := m.c.packs.MockArchive(ctx, id, group, actor)
	var ae *gate.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return nil, mockNotFound
	}
	return b, err
}

var mockNotFound = apiErr(http.StatusNotFound, "no_pack", "no published pack of this group")

// mockImage is mock.image, or the tt image of this version.
func (c *Core) mockImage() string {
	if c.cfg.Mock.Image != "" {
		return c.cfg.Mock.Image
	}
	v := c.opts.Version
	if v == "" || v == "dev" || strings.ContainsAny(v, " /") {
		v = "latest"
	}
	return "ghcr.io/ivseb/traffic-twin:" + strings.TrimPrefix(v, "v")
}

// newMockRegistry builds the registry (and the Kubernetes client when
// mock.kubernetes is enabled).
func (c *Core) newMockRegistry() (*mockreg.Registry, error) {
	mc := c.cfg.Mock
	var kube *mockreg.Kube
	if mc.Kubernetes.Enabled {
		var ca []byte
		if mc.ConsoleCAFile != "" {
			b, err := os.ReadFile(mc.ConsoleCAFile)
			if err != nil {
				return nil, errors.New("core: mock.console_ca_file cannot be read")
			}
			ca = b
		}
		k := mc.Kubernetes
		var err error
		if kube, err = mockreg.NewKube(mockreg.KubeConfig{
			Namespace: k.Namespace, Image: c.mockImage(), ImagePullPolicy: k.ImagePullPolicy, ServiceAccount: k.ServiceAccount,
			CPURequest: k.CPURequest, MemoryRequest: k.MemoryRequest, CPULimit: k.CPULimit, MemoryLimit: k.MemoryLimit,
			Route: k.Route, ConsoleURL: mc.ConsoleURL, ConsoleCA: ca,
			APIServer: c.mockKube.APIServer, Token: c.mockKube.Token, CA: c.mockKube.CA, Client: c.mockKube.Client,
		}); err != nil {
			return nil, err
		}
	}
	return mockreg.New(mockreg.Options{
		DB: c.db, Audit: c.audit, Logger: c.log, Now: c.now, Packs: mockPacks{c},
		GroupExists: func(ctx context.Context, g string) (bool, error) {
			_, err := c.fleet.GetGroup(ctx, g)
			if err != nil {
				return false, nil
			}
			return true, nil
		},
		GatePubKeys: func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			pk, err := c.kg.PublicKeys(ctx)
			if err != nil {
				return "", err
			}
			return pk.GatePubKeys(), nil
		},
		RealBases:  c.realBases,
		ConsoleURL: mc.ConsoleURL, Image: c.mockImage(), Kube: kube, ReportInterval: mc.ReportInterval,
	})
}

// realBases maps the external services of a group's policies to their
// declared base URL (match.base): the endpoint the mock replaces.
func (c *Core) realBases(group string) map[string]string {
	out := map[string]string{}
	pid := ""
	if g, err := c.fleet.GetGroup(context.Background(), group); err == nil && g != nil && g.PolicyID != nil {
		pid = *g.PolicyID
	}
	if pid == "" {
		return out
	}
	c.policies.mu.Lock()
	defer c.policies.mu.Unlock()
	best := int64(0)
	for _, p := range c.policies.known {
		if p.PolicyID != pid || p.Version < best {
			continue
		}
		best = p.Version
		clear(out)
		for _, s := range p.Services {
			if s.Match.Base != "" {
				out[s.Name] = s.Match.Base
			}
		}
	}
	return out
}

// mountMocks mounts /api/v1/mocks (console) and /api/v1/mock-agent (mocks).
func (c *Core) mountMocks() {
	extra := func(route func(string, []auth.Role, mockreg.HandlerFunc)) {
		route("POST "+mockreg.PrefixMocks+"/prepare", mockreg.RolesWrite, c.apiPrepareMock)
	}
	c.srv.Mount(mockreg.PrefixMocks, c.mocks.AdminHandler(c.audit, extra), mockreg.MountRoles...)
	c.srv.MountPublic(mockreg.PrefixAgent, c.mocks.AgentHandler())
}

// PrepareStep is one step of "Prepara e avvia il mock", shown as it runs.
type PrepareStep struct {
	ID     string `json:"id"`     // archetypes, world, pack, publish, mock
	Status string `json:"status"` // pending, running, done, skipped, failed, waiting
	// Code is a stable code for the UI (why skipped / failed / waiting).
	Code string `json:"code,omitempty"`
	// Detail carries identifiers and counts (world id, pack id, archetypes...).
	Detail map[string]string `json:"detail,omitempty"`
}

type prepareRun struct {
	c     *Core
	job   *Job
	mu    sync.Mutex
	steps []PrepareStep
}

func (pr *prepareRun) set(id, status, code string, detail map[string]string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	for i := range pr.steps {
		if pr.steps[i].ID == id {
			pr.steps[i].Status, pr.steps[i].Code = status, code
			if detail != nil {
				pr.steps[i].Detail = detail
			}
		}
	}
	cp := make([]PrepareStep, len(pr.steps))
	copy(cp, pr.steps)
	pr.c.jobs.setProgress(pr.job, map[string]any{"steps": cp})
}

func (pr *prepareRun) snapshot() []PrepareStep {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	cp := make([]PrepareStep, len(pr.steps))
	copy(cp, pr.steps)
	return cp
}

// Defaults of the world built by "Prepara e avvia".
const (
	prepareCustomers = 50
	prepareSeed      = 42
)

func (c *Core) apiPrepareMock(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group     string `json:"group"`
		Reason    string `json:"reason"`
		Start     *bool  `json:"start"`
		Customers int    `json:"customers"`
		Seed      *int64 `json:"seed"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if !mockreg.GroupRE.MatchString(req.Group) {
		return apiErr(http.StatusUnprocessableEntity, "invalid_group", "choose the group (team) of the mock")
	}
	if _, err := c.fleet.GetGroup(r.Context(), req.Group); err != nil {
		return apiErr(http.StatusUnprocessableEntity, "unknown_group", "group not found")
	}
	if req.Customers == 0 {
		req.Customers = prepareCustomers
	}
	if req.Customers < 1 || req.Customers > 10000 {
		return apiErr(http.StatusUnprocessableEntity, "invalid_customers", "customers must be 1..10000")
	}
	seed := uint64(prepareSeed)
	if req.Seed != nil {
		if *req.Seed < 0 {
			return apiErr(http.StatusUnprocessableEntity, "invalid_seed", "seed must be >= 0")
		}
		seed = uint64(*req.Seed)
	}
	if j := c.jobs.find("mock.prepare", "group", req.Group); j != nil && (j.Status == "running" || j.Status == "queued") {
		return apiErr(http.StatusConflict, "already_running", "the mock of this group is being prepared: follow that job")
	}
	start := req.Start == nil || *req.Start
	j, _ := c.jobs.startOrJoin("mock.prepare", p.UserID, false)
	c.jobs.setMeta(j, "group", req.Group)
	pr := &prepareRun{c: c, job: j}
	for _, id := range []string{"archetypes", "world", "pack", "publish", "mock"} {
		pr.steps = append(pr.steps, PrepareStep{ID: id, Status: "pending"})
	}
	pr.set("archetypes", "pending", "", nil)
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "mock.prepare", Target: audit.Target{Type: "mock", ID: mockreg.ObjectName(req.Group)},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: map[string]string{"group": req.Group, "job": j.ID}})
	ctx := context.WithoutCancel(r.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if v := recover(); v != nil {
				c.log.Error("mock prepare panicked")
				c.jobs.fail(j, "internal")
			}
		}()
		// Archetypes, world and pack: one heavy job (heavy.go).
		release, err := c.heavy.acquire(c.jobs.context(), func() { c.jobs.setStatus(j, "queued") })
		if err != nil {
			c.jobs.fail(j, "shutting_down")
			return
		}
		defer release()
		c.jobs.setStatus(j, "running")
		c.prepareMock(ctx, pr, p, req.Group, req.Reason, start, req.Customers, seed)
	}()
	// Small installations finish in a second: answer with the final state.
	t := time.NewTimer(min(c.syncWait(), 3*time.Second))
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

// prepareMock runs the steps; the job ends done (with the result) or failed
// (with the code of the failed step).
func (c *Core) prepareMock(ctx context.Context, pr *prepareRun, p *auth.Principal, group, reason string, start bool, customers int, seed uint64) {
	fail := func(step, code string) {
		pr.set(step, "failed", code, nil)
		for _, s := range pr.snapshot() {
			if s.Status == "pending" {
				pr.set(s.ID, "skipped", "", nil)
			}
		}
		c.jobs.fail(pr.job, code)
	}
	codeOf := func(err error, fallback string) string {
		var ae *apiError
		var ge *gate.APIError
		var we *world.APIError
		switch {
		case mockreg.ErrorCode(err) != "":
			return mockreg.ErrorCode(err)
		case errors.As(err, &ae):
			return ae.code
		case errors.As(err, &ge):
			return ge.Code
		case errors.As(err, &we):
			return we.Code
		}
		c.log.Error("mock prepare step failed", "step", fallback, "err", err)
		return fallback
	}
	result := map[string]any{"group": group}

	// 1. Archetypes of the group (automatic): without enough customers to
	// build them safely the world uses invented customers.
	pr.set("archetypes", "running", "", nil)
	use := true
	b, bid, err := c.world.BuildArchetypesIn(ctx, c.cfg.World.KMin, group)
	ev := audit.Event{Actor: p.AuditActor(), Action: "archetypes.build", Target: audit.Target{Type: "archetypes"}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "via": "mock.prepare"}}
	switch {
	case err != nil:
		ev.Outcome, ev.Reason = audit.Failure, "build_failed"
		use = false
		pr.set("archetypes", "skipped", "archetypes_failed", nil)
	case len(b.Archetypes) == 0:
		ev.Target.ID = strconv.FormatInt(bid, 10)
		use = false
		pr.set("archetypes", "skipped", "no_archetypes", map[string]string{"profiles": strconv.Itoa(b.Profiles), "k_min": strconv.Itoa(b.KMin)})
	default:
		ev.Target.ID = strconv.FormatInt(bid, 10)
		ev.Details["archetypes"] = strconv.Itoa(len(b.Archetypes))
		pr.set("archetypes", "done", "", map[string]string{"archetypes": strconv.Itoa(len(b.Archetypes)), "profiles": strconv.Itoa(b.Profiles)})
	}
	c.record(ctx, ev)

	// 2. World of the group.
	pr.set("world", "running", "", nil)
	info, err := c.world.Generate(ctx, world.GenerateRequest{Seed: seed, Customers: customers, UseArchetypes: &use, Group: group}, p.AuditActor())
	wev := audit.Event{Actor: p.AuditActor(), Action: "world.generate", Target: audit.Target{Type: "world"}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "via": "mock.prepare"}}
	if err != nil {
		wev.Outcome, wev.Reason = audit.Failure, codeOf(err, "generate_failed")
		c.record(ctx, wev)
		fail("world", wev.Reason)
		// Which of the group's rules cannot be used, and the services they
		// miss (no_usable_rules): the step says what to fix.
		var we *world.APIError
		if errors.As(err, &we) && len(we.Details) > 0 {
			pr.set("world", "failed", wev.Reason, ruleDetails(we.Details))
		}
		return
	}
	wev.Target.ID = info.WorldID
	wev.Details["customers"], wev.Details["entities"] = strconv.Itoa(info.Customers), strconv.Itoa(info.Entities)
	c.record(ctx, wev)
	wd := map[string]string{"world_id": info.WorldID, "customers": strconv.Itoa(info.Customers), "entities": strconv.Itoa(info.Entities)}
	wcode := ""
	if len(info.ExcludedRules) > 0 {
		// Some of the group's rules need another group's services: the
		// world is made without them, and the step says so.
		var ids, svcs []string
		for _, x := range info.ExcludedRules {
			ids = append(ids, x.ID)
			svcs = append(svcs, x.Services...)
		}
		wcode, wd["rules"], wd["services"] = "rules_excluded", strings.Join(ids, ", "), strings.Join(uniqueSorted(svcs), ", ")
	}
	pr.set("world", "done", wcode, wd)
	result["world_id"] = info.WorldID

	// 3. Pack: assembly, gate, keyguard signature (as POST /api/v1/packs).
	pr.set("pack", "running", "", nil)
	ps := twinDefaults{PackService: packDefaults{PackService: c.packs, validDays: c.cfg.Gate.ValidDays}, c: c}
	// The scenarios saved on the Mock page go into the pack; one that does
	// not fit this group's pack (other services) leaves them all out.
	var presets []string
	if ds, err := c.loadPresets(ctx, nil); err == nil {
		for _, d := range ds {
			presets = append(presets, d.PresetID)
		}
	}
	presetsNote := ""
	pk, err := ps.BuildPack(ctx, p, gate.BuildRequest{WorldID: info.WorldID, Group: group, ScenarioPresets: presets})
	if err != nil && len(presets) > 0 && codeOf(err, "") == "invalid_preset" {
		presetsNote = "presets_skipped"
		pk, err = ps.BuildPack(ctx, p, gate.BuildRequest{WorldID: info.WorldID, Group: group})
	}
	if err != nil {
		fail("pack", codeOf(err, "pack_failed"))
		return
	}
	result["pack_id"] = pk.PackID
	// A pack built on little traffic still goes ahead, but says so: the
	// counts per pack, rule, outcome and endpoint ("poche osservazioni").
	result["warnings"], result["warnings_total"] = pk.Warnings, pk.WarningsTotal
	if pk.Status != gate.StatusSigned {
		pr.set("pack", "failed", "gate_failed", map[string]string{"pack_id": pk.PackID})
		fail("pack", "gate_failed")
		return
	}
	pr.set("pack", "done", presetsNote, map[string]string{"pack_id": pk.PackID, "services": strconv.Itoa(len(pk.Services)), "warnings": strconv.Itoa(pk.WarningsTotal)})

	// 4. Publication ("Rilascia ai test"): a publisher, or an admin with a reason.
	pr.set("publish", "running", "", nil)
	if !p.HasAny(auth.RolePublisher) {
		pr.set("publish", "waiting", "needs_publisher", map[string]string{"pack_id": pk.PackID})
		for _, s := range pr.snapshot() {
			if s.Status == "pending" {
				pr.set(s.ID, "skipped", "", nil)
			}
		}
		result["waiting"] = "needs_publisher"
		c.jobs.done(pr.job, map[string]any{"result": result, "steps": pr.snapshot()})
		return
	}
	if p.IsAdmin() && strings.TrimSpace(reason) == "" {
		// An administrator publishes alone, but always with a reason (audited).
		fail("publish", "admin_reason_required")
		return
	}
	if _, err := ps.PublishPack(ctx, p, pk.PackID, reason, ""); err != nil {
		fail("publish", codeOf(err, "publish_failed"))
		return
	}
	c.mocks.PackPublished(group)
	pr.set("publish", "done", "", map[string]string{"pack_id": pk.PackID})

	// 5. The mock: started in Kubernetes, or the connected mocks switch to
	// the new pack at their next report.
	pr.set("mock", "running", "", nil)
	if !start {
		pr.set("mock", "skipped", "not_requested", nil)
	} else if mv, err := c.mocks.EnsureManaged(ctx, p, group); err != nil {
		code := codeOf(err, "mock_failed")
		if code == "kubernetes_disabled" {
			pr.set("mock", "done", c.mocks.ConnectedCode(group), nil)
		} else {
			fail("mock", code)
			return
		}
	} else {
		pr.set("mock", "done", "managed", map[string]string{"url": mv.URL})
		result["url"] = mv.URL
	}
	c.jobs.done(pr.job, map[string]any{"result": result, "steps": pr.snapshot()})
}

// ruleDetails folds the details of a world error (rule, services, reason)
// into the step detail: the rule ids, the services they miss.
func ruleDetails(ds []map[string]any) map[string]string {
	var ids, svcs []string
	for _, d := range ds {
		if id, _ := d["rule"].(string); id != "" {
			ids = append(ids, id)
		}
		switch v := d["services"].(type) {
		case []string:
			svcs = append(svcs, v...)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					svcs = append(svcs, s)
				}
			}
		}
	}
	out := map[string]string{"rules": strings.Join(ids, ", "), "services": "—"}
	if len(svcs) > 0 {
		out["services"] = strings.Join(uniqueSorted(svcs), ", ")
	}
	return out
}

func uniqueSorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}
