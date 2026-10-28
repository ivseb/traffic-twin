package core

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Endpoints for the people who use an installed console (docs/USER_GUIDE.md):
//
//	GET /api/v1/gate/keys          the public keys of the publication gate, as the
//	                               TT_GATE_PUBKEYS value `tt mock` needs (?format=txt:
//	                               gate-keys.txt); any authenticated user
//	GET /api/v1/scope              groups, the groups the caller works with and the
//	                               groups of every observed service (the console's
//	                               Group/Team filter); any authenticated user
//	GET /api/v1/sources/key-check  per source, the HMAC key ids it uses that keyguard
//	                               does not hold (reverse-HMAC cannot protect them)

func (c *Core) mountUserAPI() {
	gk := c.newRouter()
	gk.handle("GET /api/v1/gate/keys", rolesAny, c.apiGateKeys)
	c.srv.MountAuthenticated("/api/v1/gate/keys", gk.mux)

	sc := c.newRouter()
	sc.handle("GET /api/v1/scope", rolesAny, c.apiScope)
	c.srv.MountAuthenticated("/api/v1/scope", sc.mux)

	kc := c.newRouter()
	roles := []auth.Role{auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor}
	kc.handle("GET /api/v1/sources/key-check", roles, c.apiKeyCheck)
	c.srv.Mount("/api/v1/sources", kc.mux, roles...)

	c.mountApprovers()
}

// gateKeyFile renders the trusted gate keys as a TT_GATE_PUBKEYS file.
func gateKeyFile(value, installation string, now time.Time) string {
	var sb strings.Builder
	sb.WriteString("# traffic-twin: public keys of the publication gate (public, not secret).\n")
	if installation != "" {
		sb.WriteString("# Installation: " + installation + "\n")
	}
	sb.WriteString("# Downloaded " + now.UTC().Format(time.RFC3339) + ". Use it as\n")
	sb.WriteString("#   TT_GATE_PUBKEYS=./gate-keys.txt tt mock --pack <file.ttpack>\n")
	sb.WriteString("# (the file must not be writable by group or others: chmod 644).\n")
	for _, e := range strings.Split(value, ",") {
		if e = strings.TrimSpace(e); e != "" {
			sb.WriteString(e + "\n")
		}
	}
	return sb.String()
}

func (c *Core) apiGateKeys(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pk, err := c.kg.PublicKeys(ctx)
	if err != nil {
		return apiErr(http.StatusBadGateway, "keyguard_unreachable", "keyguard did not answer")
	}
	value := pk.GatePubKeys()
	if value == "" {
		return apiErr(http.StatusServiceUnavailable, "no_gate_keys", "keyguard has no pack signing key")
	}
	inst, _ := c.labels.get()
	if r.URL.Query().Get("format") == "txt" {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="gate-keys.txt"`)
		h.Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(gateKeyFile(value, inst, c.now())))
		return nil
	}
	keys := make([]map[string]string, 0, len(pk.Pack))
	for _, k := range pk.Pack {
		keys = append(keys, map[string]string{"kid": k.Kid, "public_key": k.PublicKey})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"tt_gate_pubkeys": value, "keys": keys, "file_name": "gate-keys.txt",
		"command": "TT_GATE_PUBKEYS='" + value + "' tt mock --pack <file.ttpack>",
	})
	return nil
}

// scopeView is the answer of GET /api/v1/scope.
type scopeView struct {
	Groups []string `json:"groups"`
	// Mine: groups the caller created enrollment tokens for or proposed a
	// policy version of. The console filters on them by default (all
	// groups for an administrator).
	Mine []string `json:"mine"`
	// Services maps each observed service (inbound, declared outbound,
	// host:...) to the groups of the sources that produced its events.
	Services map[string][]string `json:"services"`
}

func (c *Core) apiScope(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	v, err := c.scope(r.Context(), p)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (c *Core) scope(ctx context.Context, p *auth.Principal) (*scopeView, error) {
	v := &scopeView{Groups: []string{}, Mine: []string{}, Services: map[string][]string{}}
	groups, err := c.fleet.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		v.Groups = append(v.Groups, g.Name)
	}
	mine := map[string]bool{}
	rows, err := c.db.QueryContext(ctx, `SELECT DISTINCT grp FROM fleet_tokens WHERE created_by = ?
		UNION SELECT DISTINCT g.name FROM fleet_groups g JOIN fleet_policy_versions v ON v.policy_id = g.policy_id WHERE v.proposed_by = ?`, p.UserID, p.UserID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return nil, err
		}
		mine[g] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for g := range mine {
		v.Mine = append(v.Mine, g)
	}
	sort.Strings(v.Mine)

	srcs, err := c.fleet.ListSources(ctx, "")
	if err != nil {
		return nil, err
	}
	// Every source ever enrolled (fleet_source_groups keeps the deleted ones).
	groupOf, err := c.fleet.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	add := func(svc, g string) {
		if g != "" && !slices.Contains(v.Services[svc], g) {
			v.Services[svc] = append(v.Services[svc], g)
		}
	}
	for _, s := range srcs {
		add(s.ServiceName, s.Group)
	}
	bySvc, err := c.intake.Store().ServiceSources(ctx)
	if err != nil {
		return nil, err
	}
	for svc, ids := range bySvc {
		for _, id := range ids {
			add(svc, groupOf[id])
		}
		if _, ok := v.Services[svc]; !ok {
			v.Services[svc] = []string{}
		}
	}
	for _, gs := range v.Services {
		sort.Strings(gs)
	}
	return v, nil
}

// keyCheck is one source whose HMAC key ids keyguard does not hold.
type keyCheck struct {
	SourceID string   `json:"source_id"`
	Unknown  []string `json:"unknown_kids"`
}

func (c *Core) apiKeyCheck(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := c.kg.Status(ctx)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"reachable": false, "keyguard_kids": []string{}, "sources": []keyCheck{}})
		return nil
	}
	out, err := c.unknownKids(r.Context(), st.HMACKids)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reachable": true, "keyguard_kids": nonNil(st.HMACKids), "sources": out})
	return nil
}

// unknownKids lists the live sources whose tokens carry a key id keyguard
// does not hold: the hmac.kid of the policy they run, or before they have a
// policy the first kid they declared at enrollment.
func (c *Core) unknownKids(ctx context.Context, held []string) ([]keyCheck, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT id, hmac_kids, policy_hash FROM fleet_sources WHERE revoked = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pols := c.fleet.IntakePolicies()
	out := []keyCheck{}
	for rows.Next() {
		var id, kidsJSON, hash string
		if err := rows.Scan(&id, &kidsJSON, &hash); err != nil {
			return nil, err
		}
		var kids []string
		_ = json.Unmarshal([]byte(kidsJSON), &kids)
		policyKid := ""
		if hash != "" {
			if p, ok := pols.LookupPolicy(hash); ok {
				policyKid = p.HMACKID
			}
		}
		kid := policyKid
		if kid == "" && len(kids) > 0 {
			kid = kids[0]
		}
		if kid != "" && !slices.Contains(held, kid) {
			out = append(out, keyCheck{SourceID: id, Unknown: []string{kid}})
		}
	}
	return out, rows.Err()
}
