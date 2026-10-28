package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

var reServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Group binds the service names its sources may use, the policy assigned
// to them, a sampling override and a kill switch (admin-api Group).
type Group struct {
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	PolicyID            *string  `json:"policy_id"`
	AllowedServiceNames []string `json:"allowed_service_names"`
	SamplingOverrideBP  *int     `json:"sampling_override_bp"`
	Killed              bool     `json:"killed"`
	// TestKMin is the lower k of a group marked as test (spec v1.18; 0:
	// not a test group). Ignored on input: PUT .../groups/{group}/test-k
	// sets it.
	TestKMin int `json:"test_k_min"`
	// PolicyDraft reports the draft created when a PUT re-targets an
	// active policy (admin-api updateGroup: "the response reports the
	// draft"). Ignored on input.
	PolicyDraft *DraftRef `json:"policy_draft,omitempty"`
}

// DraftRef names a policy version.
type DraftRef struct {
	PolicyID string `json:"policy_id"`
	Version  int64  `json:"version"`
}

func (g *Group) validate() error {
	if !policy.ValidGroup(g.Name) {
		return invalid("invalid_group", "group name must match ^[a-z0-9][a-z0-9-]{0,62}$")
	}
	if len(g.Description) > 500 {
		return invalid("invalid_description", "description is longer than 500 characters")
	}
	if g.PolicyID != nil && !policy.ValidPolicyID(*g.PolicyID) {
		return invalid("invalid_policy_id", "policy_id must match ^[a-z0-9][a-z0-9-]{0,62}$")
	}
	if g.AllowedServiceNames == nil {
		return invalid("invalid_services", "allowed_service_names is required")
	}
	if len(g.AllowedServiceNames) > 256 {
		return invalid("invalid_services", "at most 256 service names")
	}
	for _, s := range g.AllowedServiceNames {
		if !reServiceName.MatchString(s) {
			return invalid("invalid_services", "service names must match ^[a-z0-9][a-z0-9._-]{0,62}$")
		}
	}
	if o := g.SamplingOverrideBP; o != nil && (*o < 0 || *o > 10000) {
		return invalid("invalid_sampling", "sampling_override_bp must be between 0 and 10000")
	}
	return nil
}

func normalizeNames(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return slices.Compact(out)
}

func scanGroup(sc interface{ Scan(...any) error }) (*Group, error) {
	g := &Group{}
	var pid sql.NullString
	var allowed string
	var ov sql.NullInt64
	var killed int
	if err := sc.Scan(&g.Name, &g.Description, &pid, &allowed, &ov, &killed, &g.TestKMin); err != nil {
		return nil, err
	}
	if pid.Valid {
		g.PolicyID = &pid.String
	}
	if err := json.Unmarshal([]byte(allowed), &g.AllowedServiceNames); err != nil {
		return nil, err
	}
	g.SamplingOverrideBP, g.Killed = intPtr(ov), killed == 1
	return g, nil
}

const groupCols = `name, description, policy_id, allowed_service_names, sampling_override_bp, killed, test_k_min`

// ListGroups returns all groups.
func (f *Fleet) ListGroups(ctx context.Context) ([]*Group, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT `+groupCols+` FROM fleet_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SourceGroups maps every source ever enrolled to its group
// (groupscope.Resolver): fleet_source_groups outlives the source rows that
// retention deletes, so the stored events stay attributed to their group.
func (f *Fleet) SourceGroups(ctx context.Context) (map[string]string, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT source_id, grp FROM fleet_source_groups UNION ALL SELECT id, grp FROM fleet_sources`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, g string
		if err := rows.Scan(&id, &g); err != nil {
			return nil, err
		}
		out[id] = g
	}
	return out, rows.Err()
}

// PolicyGroups maps each policy id to the groups it serves: the groups
// bound to it (fleet_groups.policy_id) and the groups its versions target.
func (f *Fleet) PolicyGroups(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	rows, err := f.db.QueryContext(ctx, `SELECT policy_id, name FROM fleet_groups WHERE policy_id IS NOT NULL
		UNION SELECT DISTINCT v.policy_id, j.value FROM fleet_policy_versions v, json_each(v.targets) j`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pid, g string
		if err := rows.Scan(&pid, &g); err != nil {
			return nil, err
		}
		if pid != "" && g != "" && !slices.Contains(out[pid], g) {
			out[pid] = append(out[pid], g)
		}
	}
	for _, gs := range out {
		sort.Strings(gs)
	}
	return out, rows.Err()
}

// GetGroup returns one group.
func (f *Fleet) GetGroup(ctx context.Context, name string) (*Group, error) {
	g, err := scanGroup(f.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM fleet_groups WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return g, err
}

// CreateGroup creates a group. When policy_id names a policy with an active
// version, a re-targeting draft is created (adding a group opens data).
func (f *Fleet) CreateGroup(ctx context.Context, p *auth.Principal, g Group) (*Group, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	g.AllowedServiceNames = normalizeNames(g.AllowedServiceNames)
	now := f.now().Unix()
	res, err := f.db.ExecContext(ctx, `INSERT INTO fleet_groups(name, description, policy_id, allowed_service_names, sampling_override_bp, killed, created_at, updated_at)
		VALUES(?,?,?,?,?,0,?,?) ON CONFLICT(name) DO NOTHING`,
		g.Name, g.Description, nullStr(g.PolicyID), mustJSON(g.AllowedServiceNames), nullInt(g.SamplingOverrideBP), now, now)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, conflict("group_exists", "a group with this name already exists")
	}
	f.mu.Lock()
	f.groups[g.Name] = &memGroup{allowed: slices.Clone(g.AllowedServiceNames), overrideBP: g.SamplingOverrideBP, policyID: deref(g.PolicyID)}
	f.mu.Unlock()
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.group_create", Target: audit.Target{Type: "group", ID: g.Name}, Outcome: audit.Success,
		Details: map[string]string{"policy_id": deref(g.PolicyID), "services": strconv.Itoa(len(g.AllowedServiceNames))}})
	out, err := f.GetGroup(ctx, g.Name)
	if err != nil {
		return nil, err
	}
	if g.PolicyID != nil {
		ref, err := f.retarget(ctx, p, *g.PolicyID)
		if err != nil {
			return nil, err
		}
		out.PolicyDraft = ref
	}
	return out, nil
}

// UpdateGroup replaces a group's settings. Changing policy_id to a policy
// with an active version creates a re-targeting draft; adding allowed
// service names is audited. The kill switch is changed only through
// SetKill (the killed field is read-only here).
func (f *Fleet) UpdateGroup(ctx context.Context, p *auth.Principal, name string, g Group) (*Group, error) {
	if g.Name != name {
		return nil, invalid("name_mismatch", "the group name in the body must match the path")
	}
	if err := g.validate(); err != nil {
		return nil, err
	}
	g.AllowedServiceNames = normalizeNames(g.AllowedServiceNames)
	old, err := f.GetGroup(ctx, name)
	if err != nil {
		return nil, err
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE fleet_groups SET description = ?, policy_id = ?, allowed_service_names = ?, sampling_override_bp = ?, updated_at = ? WHERE name = ?`,
		g.Description, nullStr(g.PolicyID), mustJSON(g.AllowedServiceNames), nullInt(g.SamplingOverrideBP), f.now().Unix(), name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	if mg := f.groups[name]; mg != nil {
		mg.allowed, mg.overrideBP, mg.policyID = slices.Clone(g.AllowedServiceNames), g.SamplingOverrideBP, deref(g.PolicyID)
	}
	f.mu.Unlock()
	added := 0
	for _, s := range g.AllowedServiceNames {
		if !slices.Contains(old.AllowedServiceNames, s) {
			added++
		}
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.group_update", Target: audit.Target{Type: "group", ID: name}, Outcome: audit.Success,
		Details: map[string]string{
			"policy_id": deref(g.PolicyID), "services_added": strconv.Itoa(added),
			"services_removed":     strconv.Itoa(len(old.AllowedServiceNames) + added - len(g.AllowedServiceNames)),
			"sampling_override_bp": optInt(g.SamplingOverrideBP),
		}})
	out, err := f.GetGroup(ctx, name)
	if err != nil {
		return nil, err
	}
	if g.PolicyID != nil && deref(old.PolicyID) != *g.PolicyID {
		ref, err := f.retarget(ctx, p, *g.PolicyID)
		if err != nil {
			return nil, err
		}
		out.PolicyDraft = ref
	}
	if g.PolicyID == nil && old.PolicyID != nil {
		// Unbinding stops the group's sources at once (currentFor, and
		// min_issued_seq in the heartbeat). The signed targets of the
		// active version still name the group: a closing version without
		// it is drafted (one approval) so that they stop naming it. When
		// no group is left on the policy there is nothing to draft: the
		// version is not renewed any more and lapses at its not_after.
		ref, err := f.retarget(ctx, p, *old.PolicyID)
		var ae *APIError
		if err != nil && !(errors.As(err, &ae) && ae.Code == "no_target_groups") {
			return nil, err
		}
		out.PolicyDraft = ref
	}
	return out, nil
}

func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func optInt(p *int) string {
	if p == nil {
		return "none"
	}
	return strconv.Itoa(*p)
}

// boundGroups returns the groups whose policy_id is pid (the targets of
// the next signed version of pid).
func (f *Fleet) boundGroups(pid string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []string
	for name, g := range f.groups {
		if g.policyID == pid {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
