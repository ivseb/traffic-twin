package fleet

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Spec v1.18: joinable HMAC domain families (C15) and a lower k for the
// groups marked as test (C0).

// noteFamily is the note of the versions made by SetFamily.
const noteFamily = "hmac domain family chosen in the console"

// SetFamily sets (or, with Remove, removes) one family of hmac.families of
// the group's policy: every hmac(d) with d in the family compiles to
// hmac(<family>), so the joined fields carry equal tokens for equal values.
// Changing hmac domains opens no value (policy.md 7.1): the version is
// proposed like any draft and, being observe-safe, signed and activated at
// once. The choice is audited as policy.families_set or
// policy.families_removed (names only).
func (f *Fleet) SetFamily(ctx context.Context, p *auth.Principal, group string, fc FamilyChange) (*PolicyVersion, error) {
	g, err := f.GetGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	if g.PolicyID == nil {
		return nil, conflict("no_policy", "the group has no policy yet: connect a source first")
	}
	fc.Family = strings.TrimSpace(fc.Family)
	for i, d := range fc.Domains {
		fc.Domains[i] = strings.TrimSpace(d)
	}
	_, v, err := f.AssistDraftWith(ctx, p, *g.PolicyID, AssistDraftRequest{Family: &fc}, noteFamily)
	if err != nil {
		return nil, err
	}
	action := "policy.families_set"
	det := map[string]string{"policy": v.PolicyID, "version": itoa(v.Version), "family": audit.SafeValue(fc.Family),
		"status": v.Status, "opens_values": strconv.FormatBool(v.OpensValues)}
	if fc.Remove {
		action = "policy.families_removed"
	} else {
		det["domains"] = audit.SafeValue(strings.Join(fc.Domains, ","))
	}
	f.record(ctx, audit.Event{Actor: actorOf(p), Action: action, Target: audit.Target{Type: "group", ID: group}, Outcome: audit.Success, Details: det})
	return v, nil
}

// familiesOf returns hmac.families of the author document of the active
// version of pid (nil when none).
func (f *Fleet) familiesOf(ctx context.Context, pid string) map[string][]string {
	doc, err := f.latestAuthor(ctx, pid)
	if err != nil {
		return nil
	}
	a, err := ParseAuthor(doc)
	if err != nil {
		return nil
	}
	return a.Families
}

// MinTestK is the least k of a group marked as test: never below 2.
const MinTestK = 2

// maxTestKReason bounds the reason of a test k.
const maxTestKReason = 500

// TestKOf returns the lower k of a group marked as test (0: not a test
// group).
func (f *Fleet) TestKOf(ctx context.Context, group string) (int, error) {
	var k int
	err := f.db.QueryRowContext(ctx, `SELECT test_k_min FROM fleet_groups WHERE name = ?`, group).Scan(&k)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNotFound
	}
	return k, err
}

// GroupTestK returns, for every group marked as test, its lower k (the
// miner mines the group with it, the pack writer builds its packs with it).
func (f *Fleet) GroupTestK(ctx context.Context) (map[string]int, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT name, test_k_min FROM fleet_groups WHERE test_k_min > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var g string
		var k int
		if err := rows.Scan(&g, &k); err != nil {
			return nil, err
		}
		out[g] = k
	}
	return out, rows.Err()
}

// kMin is the installation k (Options.KMin, default DefaultKMin).
func (f *Fleet) kMin() int {
	if f.opts.KMin > 0 {
		return f.opts.KMin
	}
	return DefaultKMin
}

// SetTestK marks a group as test with a lower k (2 ≤ k < the installation
// k), or unmarks it (k = 0). Only an administrator may do it, with a
// reason; the change is audited (fleet.group_test_k) and shown in the
// console. Rules mined with the lower k and the packs built from them
// carry a warning.
func (f *Fleet) SetTestK(ctx context.Context, p *auth.Principal, group string, k int, reason string) error {
	if !p.Has(auth.RoleAdmin) {
		return apiErr(http.StatusForbidden, "forbidden", "only an administrator can lower k for a test group")
	}
	reason = strings.TrimSpace(reason)
	if k != 0 && (k < MinTestK || k >= f.kMin()) {
		return invalid("invalid_k_min", "k_min must be 0 (off) or between "+strconv.Itoa(MinTestK)+" and "+strconv.Itoa(f.kMin()-1))
	}
	if k != 0 && reason == "" {
		return invalid("reason_required", "say why this group is a test environment")
	}
	if len(reason) > maxTestKReason {
		return invalid("invalid_reason", "the reason is longer than 500 characters")
	}
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_groups SET test_k_min = ?, updated_at = ? WHERE name = ?`, k, f.now().Unix(), group)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.group_test_k", Target: audit.Target{Type: "group", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"k_min": strconv.Itoa(k), "k_installation": strconv.Itoa(f.kMin()), "reason": audit.SafeValue(reason)}})
	return nil
}

// apiSetFamily sets one HMAC domain family of the group's policy:
// {"family": "...", "domains": ["...", ...]}.
func (f *Fleet) apiSetFamily(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var in struct {
		Family  string   `json:"family"`
		Domains []string `json:"domains"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		return err
	}
	v, err := f.SetFamily(r.Context(), p, r.PathValue("group"), FamilyChange{Family: in.Family, Domains: in.Domains})
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// apiRemoveFamily removes one HMAC domain family of the group's policy.
func (f *Fleet) apiRemoveFamily(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	v, err := f.SetFamily(r.Context(), p, r.PathValue("group"), FamilyChange{Family: r.PathValue("family"), Remove: true})
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// apiSetTestK marks a group as test with a lower k: {"k_min": n, "reason":
// "..."}; k_min 0 turns it off. The answer is the observe status.
func (f *Fleet) apiSetTestK(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var in struct {
		KMin   *int   `json:"k_min"`
		Reason string `json:"reason"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		return err
	}
	if in.KMin == nil {
		return invalid("invalid_input", "k_min (integer) is required")
	}
	g := r.PathValue("group")
	if err := f.SetTestK(r.Context(), p, g, *in.KMin, in.Reason); err != nil {
		return err
	}
	out, err := f.ObserveStatusOf(r.Context(), g)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}
