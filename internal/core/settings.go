package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// ---------------------------------------------------------------------------
// Settings (admin-api getSettings, updateSettings)
//
// Only labels are changeable at run time: the installation name and the
// environment label. Everything that matters for security (k thresholds,
// retention windows' bounds, sessions, SSO, approvals) lives in the
// configuration file or in keyguard and is shown read-only, so that a
// compromised admin session cannot weaken it.

const (
	settingInstallation = "general.installation_name"
	settingEnvironment  = "general.environment"
)

// Environments are the accepted environment labels ("" clears it).
var environments = []string{"production", "staging", "development"}

var reInstallation = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._:/@+-]*$`)

// labels is the in-memory copy of the editable labels.
type labels struct {
	mu                        sync.RWMutex
	installation, environment string
}

func (l *labels) get() (string, string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.installation, l.environment
}

func (l *labels) set(installation, environment string) {
	l.mu.Lock()
	l.installation, l.environment = installation, environment
	l.mu.Unlock()
}

func (c *Core) loadLabels(ctx context.Context) error {
	var inst, env string
	for key, dst := range map[string]*string{settingInstallation: &inst, settingEnvironment: &env} {
		err := c.db.QueryRowContext(ctx, `SELECT value FROM core_settings WHERE key = ?`, key).Scan(dst)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	c.labels.set(inst, env)
	return nil
}

type settingsView struct {
	General generalView `json:"general"`
	Privacy privacyView `json:"privacy"`
	Access  accessView  `json:"access"`
}

type generalView struct {
	InstallationName string `json:"installation_name"`
	Environment      string `json:"environment"`
}

type privacyView struct {
	EventsRetentionDays int      `json:"events_retention_days"`
	AggregatesDays      int      `json:"aggregates_days"`
	KMin                kMinView `json:"k_min"`
	MinSamples          int      `json:"min_samples"`
}

type kMinView struct {
	Contract int `json:"contract"`
	Miner    int `json:"miner"`
	World    int `json:"world"`
	Gate     int `json:"gate"`
}

type accessView struct {
	LocalEnabled bool        `json:"local_enabled"`
	OIDC         oidcView    `json:"oidc"`
	Session      sessionView `json:"session"`
}

type oidcView struct {
	Enabled   bool     `json:"enabled"`
	IssuerURL string   `json:"issuer_url"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	// RolesClaim is empty when roles of SSO users are managed in the console.
	RolesClaim string `json:"roles_claim"`
}

type sessionView struct {
	IdleTimeoutS     int64 `json:"idle_timeout_s"`
	AbsoluteTimeoutS int64 `json:"absolute_timeout_s"`
}

func (c *Core) settingsView() settingsView {
	cfg := c.cfg
	inst, env := c.labels.get()
	scopes := cfg.Auth.OIDC.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return settingsView{
		General: generalView{InstallationName: inst, Environment: env},
		Privacy: privacyView{
			EventsRetentionDays: int(c.intake.Retention().Hours() / 24), AggregatesDays: c.aggregatesDays(),
			KMin:       kMinView{Contract: cfg.Contract.KMin, Miner: cfg.Miner.KMin, World: cfg.World.KMin, Gate: cfg.Gate.KMin},
			MinSamples: cfg.Contract.MinSamples,
		},
		Access: accessView{
			LocalEnabled: cfg.Auth.Local.Enabled,
			// The client secret is never part of an answer.
			OIDC: oidcView{Enabled: cfg.Auth.OIDC.Enabled, IssuerURL: cfg.Auth.OIDC.IssuerURL, ClientID: cfg.Auth.OIDC.ClientID,
				Scopes: scopes, RolesClaim: cfg.Auth.OIDC.RolesClaim},
			Session: sessionView{IdleTimeoutS: int64(cfg.Auth.Session.IdleTimeout.Seconds()), AbsoluteTimeoutS: int64(cfg.Auth.Session.AbsoluteTimeout.Seconds())},
		},
	}
}

func (c *Core) apiGetSettings(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) error {
	httpx.WriteJSON(w, http.StatusOK, c.settingsView())
	return nil
}

func (c *Core) apiUpdateSettings(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	// Unknown fields are refused: nothing but the two labels can be set here.
	var req struct {
		InstallationName *string `json:"installation_name"`
		Environment      *string `json:"environment"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.InstallationName == nil && req.Environment == nil {
		return apiErr(http.StatusBadRequest, "invalid_input", "nothing to change")
	}
	inst, env := c.labels.get()
	details := map[string]string{}
	if req.InstallationName != nil {
		n := *req.InstallationName
		if n != "" && (utf8.RuneCountInString(n) > 64 || !reInstallation.MatchString(n)) {
			return apiErr(http.StatusBadRequest, "invalid_input", "installation_name: up to 64 letters, digits, spaces and . _ - : / @ +")
		}
		inst = n
		details["installation_name"] = "changed"
	}
	if req.Environment != nil {
		if e := *req.Environment; e != "" && !slices.Contains(environments, e) {
			return apiErr(http.StatusBadRequest, "invalid_input", "environment must be production, staging, development or empty")
		}
		env = *req.Environment
		details["environment"] = audit.SafeValue(env)
		if env == "" {
			details["environment"] = "cleared"
		}
	}
	ctx := r.Context()
	if err := c.saveSetting(ctx, settingInstallation, inst); err != nil {
		return err
	}
	if err := c.saveSetting(ctx, settingEnvironment, env); err != nil {
		return err
	}
	c.labels.set(inst, env)
	c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "settings.update", Target: audit.Target{Type: "settings"}, Outcome: audit.Success,
		RequestID: httpx.RequestID(ctx), Details: details})
	httpx.WriteJSON(w, http.StatusOK, c.settingsView())
	return nil
}

// ---------------------------------------------------------------------------
// Twin selection: which discovered services get a twin by default

// twinStore implements contract.TwinStore over core_twin.
type twinStore struct{ c *Core }

func (t twinStore) Selection(ctx context.Context) (map[string]bool, error) {
	rows, err := t.c.db.QueryContext(ctx, `SELECT service, twin FROM core_twin`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		var v bool
		if err := rows.Scan(&s, &v); err != nil {
			return nil, err
		}
		out[s] = v
	}
	return out, rows.Err()
}

func (t twinStore) SetTwin(ctx context.Context, service string, twin bool) error {
	_, err := t.c.db.ExecContext(ctx, `INSERT INTO core_twin (service, twin) VALUES (?, ?)
		ON CONFLICT(service) DO UPDATE SET twin = excluded.twin`, service, twin)
	return err
}

// twinDefaults applies the stored twin selection to build requests that
// name no services: the services an operator switched off are left out.
// With no explicit "no" the request is unchanged (every service).
type twinDefaults struct {
	gate.PackService
	c *Core
}

func (p twinDefaults) BuildPack(ctx context.Context, pr *auth.Principal, req gate.BuildRequest) (*gate.PackInfo, error) {
	if len(req.Services) > 0 {
		return p.PackService.BuildPack(ctx, pr, req)
	}
	sel, err := twinStore{p.c}.Selection(ctx)
	if err != nil {
		return nil, err
	}
	// The choices are per (group, service): the pack's group, else the
	// world's.
	group := req.Group
	if group == "" {
		if rec, err := p.c.world.Record(ctx, req.WorldID); err == nil {
			group = rec.Group
		}
	}
	var srcs []string
	if group != "" {
		if srcs, err = p.c.eng.SourcesOf(ctx, groupscope.Set{group}); err != nil {
			return nil, err
		}
	}
	now := p.c.now()
	sums, err := p.c.intake.Store().OpSummariesFor(ctx, now.Add(-p.c.cfg.Miner.Window), now.Add(time.Minute), srcs)
	if err != nil {
		return nil, err
	}
	replaced, err := p.c.replacedBy(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range sums {
		names = append(names, s.Service)
	}
	on, out, off := pickTwins(names, sel, group, replaced)
	// keep is the request that keeps the replaced services (the fallback).
	keep := req
	if off {
		keep.Services = append(slices.Clone(on), out...)
		slices.Sort(keep.Services)
		if len(keep.Services) == 0 && len(names) > 0 {
			return nil, gate.Errorf(http.StatusUnprocessableEntity, "no_services", "every service is switched off in the twin selection")
		}
	}
	if len(out) == 0 {
		return p.PackService.BuildPack(ctx, pr, keep)
	}
	with := req
	switch {
	case off && len(on) == 0:
		return p.PackService.BuildPack(ctx, pr, keep)
	case off:
		with.Services = on
	default:
		with.ExcludeServices = append(slices.Clone(req.ExcludeServices), out...)
		slices.Sort(with.ExcludeServices)
	}
	info, err := p.PackService.BuildPack(ctx, pr, with)
	var ae *gate.APIError
	if err != nil && errors.As(err, &ae) && (ae.Code == "missing_service" || ae.Code == "no_services") {
		// Approved rules (or the world) still need the old name: the pack
		// keeps it rather than failing.
		return p.PackService.BuildPack(ctx, pr, keep)
	}
	return info, err
}

// pickTwins applies the twin selection to the services of a pack built
// without an explicit list: on are the services to include (sorted),
// replaced the old host:<pattern> services left out because the group
// declares their host since under another name (contract.ReplacedLookup;
// their twin would be the declared service again, as ext-N in the mock),
// off whether an operator switched a service off. A replaced service with
// an explicit "twin: true" stays in.
func pickTwins(services []string, sel map[string]bool, group string, replacedBy func(group, service string) string) (on, replaced []string, off bool) {
	seen := map[string]bool{}
	for _, s := range services {
		if seen[s] {
			continue
		}
		seen[s] = true
		v, explicit := contract.TwinOf(sel, group, s)
		switch {
		case explicit && !v:
			off = true
		case !explicit && group != "" && replacedBy != nil && replacedBy(group, s) != "":
			replaced = append(replaced, s)
		default:
			on = append(on, s)
		}
	}
	slices.Sort(on)
	slices.Sort(replaced)
	return on, replaced, off
}
