package core_rt

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/core/demosim"
)

type policyVersion struct {
	PolicyID     string `json:"policy_id"`
	Version      int64  `json:"version"`
	Status       string `json:"status"`
	ApprovalMode string `json:"approval_mode"`
	Approvals    []struct {
		UserID string `json:"user_id"`
	} `json:"approvals"`
	Classification    string `json:"classification"`
	ApprovalsRequired int    `json:"approvals_required"`
}

// draftFor creates a group bound to a new policy id and its starter policy
// (a first policy: an opening change, two approvals needed).
func (e *env) draftFor(t *testing.T, group string) policyVersion {
	t.Helper()
	olga := e.u(t, "olga")
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": group, "allowed_service_names": []string{group + "-svc"}, "policy_id": "p-" + group})
	var pv policyVersion
	// A first policy that opens values (a keep): it needs approvals. The
	// starter policy opens none and is active at once (policy.md 7).
	doc := `{"format":"tt.policy/v1","policy_id":"p-` + group + `","default":"drop","hmac":{"kid":"` + core.DevHMACKid + `","epoch":"2026-10"},` +
		`"sampling":{"rate":0.05},"global":{"response":{"headers":{"content-type":"keep"}}}}`
	olga.json(201, "POST", "/api/v1/fleet/policies", doc, &pv)
	if pv.Status != "draft" {
		t.Fatalf("draft for %s: %+v", group, pv)
	}
	return pv
}

func approvePath(pv policyVersion) string {
	return fmt.Sprintf("/api/v1/fleet/policies/%s/versions/%d/approve", pv.PolicyID, pv.Version)
}

// webhookEventsSince lists the event types delivered (or queued) to the
// env's catch-all webhook after the given delivery id.
func (e *env) deliveries(t *testing.T) []map[string]any {
	t.Helper()
	var ds []map[string]any
	e.u(t, "ada").json(200, "GET", "/api/v1/webhooks/"+e.hookID+"/deliveries", nil, &ds)
	return ds
}

func maxDelivery(ds []map[string]any) float64 {
	m := 0.0
	for _, d := range ds {
		if v, _ := d["delivery_id"].(float64); v > m {
			m = v
		}
	}
	return m
}

// FIXED (was medium, red team round 2; now a regression test). Granting
// policy-approver or event-exporter (or admin) was only marked in the audit
// entry (sensitive_role=true), with no webhook/alert, so a compromised admin
// account could grant these roles silently (admin-api updateUser "audited
// and notified to all admins"; threat model M17). Now every sensitive grant
// writes user.sensitive_role and raises keyguard.alert (alert
// user.sensitive_role, identifiers only).
func TestRT_Core_Fixed_SensitiveRoleGrantNotNotified(t *testing.T) {
	e := getEnv(t)
	before := maxDelivery(e.deliveries(t))
	head := e.auditHead(t)
	e.newUser(t, "rt-grant", "auditor")
	e.u(t, "ada").must(200, "PATCH", "/api/v1/users/"+e.ids["rt-grant"], map[string]any{"roles": []string{"auditor", "event-exporter", "policy-approver"}})
	time.Sleep(3 * time.Second) // drift.Run polls every 2 s
	var got []string
	for _, d := range e.deliveries(t) {
		if d["delivery_id"].(float64) > before {
			got = append(got, fmt.Sprint(d["event"]))
		}
	}
	if !slices.Contains(got, "keyguard.alert") {
		t.Fatalf("granting policy-approver and event-exporter emitted no keyguard.alert (deliveries: %v)", got)
	}
	found := false
	for _, a := range e.auditSince(t, head) {
		if a["action"] == "user.sensitive_role" && a["target"] != nil && strings.Contains(fmt.Sprint(a["target"]), e.ids["rt-grant"]) {
			found = true
		}
	}
	if !found {
		t.Error("no user.sensitive_role audit entry for the grant")
	}
}

// DECISION (owner, October 2026; was FIXED in red team round 2 with 409
// self_grant / 409 sod_conflict). admin is the superuser: it may grant
// roles to itself and combine admin with any role, because it can do all of
// it anyway. Separation of duties gives way to traceability: every grant of
// a sensitive role (also to oneself, marked self_grant) is audited and
// alerted (user.sensitive_role), and any approval by an admin is still the
// admin override (reason required, policy.admin_approval, alert). A
// non-admin still cannot grant roles, to itself or to anybody.
func TestRT_Core_Decision_AdminGrantsTracedNotRefused(t *testing.T) {
	e := getEnv(t)
	adm := e.newUser(t, "rt-adm2", "admin")
	before := maxDelivery(e.deliveries(t))
	head := e.auditHead(t)
	adm.must(200, "PATCH", "/api/v1/users/"+e.ids["rt-adm2"], map[string]any{"roles": []string{"admin", "auditor", "event-exporter"}})
	e.u(t, "ada").must(200, "PATCH", "/api/v1/users/"+e.ids["rt-adm2"], map[string]any{"roles": []string{"admin", "auditor", "event-exporter", "policy-approver"}})
	e.u(t, "ada").must(201, "POST", "/api/v1/users", map[string]any{"username": "rt-adm-exp", "password": testPassword, "roles": []string{"admin", "event-exporter"}})
	var selfGrant, sensitive, update bool
	for _, a := range e.auditSince(t, head) {
		det, _ := a["details"].(map[string]any)
		switch {
		case a["action"] == "user.sensitive_role" && det["self_grant"] == "true" && strings.Contains(fmt.Sprint(det["roles_granted"]), "event-exporter"):
			selfGrant = true
		case a["action"] == "user.sensitive_role" && strings.Contains(fmt.Sprint(det["roles_granted"]), "policy-approver"):
			sensitive = true
		case a["action"] == "user.update" && det["self_grant"] == "true":
			update = true
		}
	}
	if !selfGrant || !sensitive || !update {
		t.Errorf("grants not traced: self-grant sensitive_role=%v, sensitive_role=%v, user.update self_grant=%v", selfGrant, sensitive, update)
	}
	time.Sleep(3 * time.Second) // drift.Run polls every 2 s
	alerts := 0
	for _, d := range e.deliveries(t) {
		if d["delivery_id"].(float64) > before && d["event"] == "keyguard.alert" {
			alerts++
		}
	}
	if alerts < 3 {
		t.Errorf("sensitive grants raised %d keyguard.alert deliveries (want >= 3: self-grant, grant, creation)", alerts)
	}
	// A non-admin never grants roles: not to itself, not to others.
	nob := e.newUser(t, "rt-nonadm", "operator")
	if code, b := nob.do("PATCH", "/api/v1/users/"+e.ids["rt-nonadm"], map[string]any{"roles": []string{"operator", "admin"}}); code != 403 || errCode(b) != "forbidden" {
		t.Errorf("non-admin self-grant = %d %s (want 403 forbidden)", code, b)
	}
	if code, _ := e.u(t, "pia").do("PATCH", "/api/v1/users/"+e.ids["rt-nonadm"], map[string]any{"roles": []string{"policy-approver"}}); code != 403 {
		t.Errorf("non-admin grant to another user = %d (want 403)", code)
	}
	var ul []map[string]any
	e.u(t, "ada").json(200, "GET", "/api/v1/users", nil, &ul)
	for _, u := range ul {
		if u["id"] == e.ids["rt-nonadm"] && fmt.Sprint(u["roles"]) != "[operator]" {
			t.Errorf("non-admin roles changed anyway: %v", u["roles"])
		}
	}
	// The admin's own approval stays the override, also with
	// policy-approver: no reason is 422, never a silent standard approval.
	pv := e.draftFor(t, "rt-sod")
	if code, b := adm.do("POST", approvePath(pv), nil); code != 422 || errCode(b) != "reason_required" {
		t.Errorf("admin approval without reason = %d %s (want 422 reason_required)", code, b)
	}
	head = e.auditHead(t)
	var out policyVersion
	adm.json(200, "POST", approvePath(pv), map[string]any{"reason": "Rt superuser approval"}, &out)
	if out.Status != "active" || out.ApprovalMode != "admin" {
		t.Errorf("admin + policy-approver approval: status %s mode %s (want active, admin)", out.Status, out.ApprovalMode)
	}
	if !hasAction(e.auditSince(t, head), "policy.admin_approval") {
		t.Error("no policy.admin_approval for an admin holding policy-approver")
	}
}

// FIXED (was low/medium, red team round 2; now a regression test). An approval stays counted after the approver is
// disabled or loses policy-approver: the quorum of an opening change is
// reached with only one approver still entitled to approve (fleet counts
// stored approvals; keyguard gets the roles captured at approval time).
func TestRT_Core_Fixed_StaleApprovalCountsAfterDisable(t *testing.T) {
	e := getEnv(t)
	gone := e.newUser(t, "rt-gone", "policy-approver")
	pv := e.draftFor(t, "rt-stale")
	gone.must(200, "POST", approvePath(pv), nil)
	e.u(t, "ada").must(200, "PATCH", "/api/v1/users/"+e.ids["rt-gone"], map[string]any{"disabled": true})
	var out policyVersion
	code, b := e.u(t, "pete").do("POST", approvePath(pv), nil)
	_ = json.Unmarshal(b, &out)
	if code == 200 && out.Status == "active" {
		t.Fatalf("opening change signed with approvals of a disabled user + one active approver (%d approvals, required %d)", len(out.Approvals), out.ApprovalsRequired)
	}
}

// quarantine raises a new quarantine item by sending many distinct values in
// a keep field of the demo shop and returns its id.
func (e *env) quarantine(t *testing.T, slashes int, field string) string {
	t.Helper()
	known := map[string]bool{}
	var qs []map[string]any
	e.u(t, "audrey").json(200, "GET", "/api/v1/quarantine", nil, &qs)
	for _, q := range qs {
		known[fmt.Sprint(q["item_id"])] = true
	}
	xs := e.sim.Exchanges()
	var tmpl *demosim.Exchange
	for i := range xs {
		if xs[i].Inbound && xs[i].Ex.Method == "GET" && xs[i].Ex.Status == 200 && strings.Count(string(xs[i].Ex.RawPath), "/") == slashes {
			var m map[string]any
			if json.Unmarshal(xs[i].Ex.RespBody, &m) == nil && m[field] != nil {
				tmpl = &xs[i]
				break
			}
		}
	}
	if tmpl == nil {
		t.Fatalf("no template exchange with %s", field)
	}
	var body map[string]any
	_ = json.Unmarshal(tmpl.Ex.RespBody, &body)
	for i := range 80 {
		x := *tmpl
		body[field] = fmt.Sprintf("RTQ%s%04d", strings.ToUpper(field[:2]), i)
		x.Ex.RespBody, _ = json.Marshal(body)
		e.emit(t, x.Ex, e.clock.Now().Add(time.Duration(i)*time.Millisecond), x.SampledBy(), 5, x.Trace, x.Span, "")
	}
	var id string
	eventually(t, 20*time.Second, "quarantine of "+field, func() bool {
		qs = nil
		e.u(t, "audrey").json(200, "GET", "/api/v1/quarantine", nil, &qs)
		for _, q := range qs {
			if k := fmt.Sprint(q["item_id"]); !known[k] {
				id = k
				return true
			}
		}
		return false
	})
	return id
}

// Dismissing a quarantine (it opens data again) needs two distinct
// policy-approvers; nobody else but an admin may resolve (the admin
// override: see TestRT_Core_Fixed_QuarantineDismissStaleApproval); the same
// approver twice is 409.
func TestRT_Core_Holds_QuarantineDismissTwoPersons(t *testing.T) {
	e := getEnv(t)
	item := e.quarItem
	path := "/api/v1/quarantine/" + item + "/resolve"
	for _, who := range []string{"olga", "audrey", "nora"} {
		if code, b := e.u(t, who).do("POST", path, map[string]any{"resolution": "dismiss"}); code != 403 {
			t.Errorf("%s dismiss = %d %s", who, code, b)
		}
	}
	var qi map[string]any
	e.u(t, "pia").json(200, "POST", path, map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] != "dismiss-pending" {
		t.Fatalf("after one dismissal: %v", qi)
	}
	if code, _ := e.u(t, "pia").do("POST", path, map[string]any{"resolution": "dismiss"}); code != 409 {
		t.Errorf("same approver twice = %d", code)
	}
	e.u(t, "pete").json(200, "POST", path, map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] != "resolved" {
		t.Fatalf("after two dismissals: %v", qi)
	}
	if strings.Contains(fmt.Sprint(qi), "RTQSTATE") {
		t.Errorf("quarantine view shows values: %v", qi)
	}
}

// FIXED (was low/medium, red team round 2; now a regression test). The dismiss of a quarantine (opens data again) counts
// the first approval even after that approver was disabled: one entitled
// person lifts the quarantine.
func TestRT_Core_Fixed_QuarantineDismissStaleApproval(t *testing.T) {
	e := getEnv(t)
	item := e.quarantine(t, 2, "currency")
	path := "/api/v1/quarantine/" + item + "/resolve"
	q1 := e.newUser(t, "rt-qgone", "policy-approver")
	q1.must(200, "POST", path, map[string]any{"resolution": "dismiss"})
	e.u(t, "ada").must(200, "PATCH", "/api/v1/users/"+e.ids["rt-qgone"], map[string]any{"disabled": true})
	var qi map[string]any
	e.u(t, "pete").json(200, "POST", path, map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] == "resolved" {
		t.Fatalf("quarantine %s lifted with the approval of a disabled user plus one active approver", item)
	}
	// DECISION (owner, October 2026; was 403 sod_conflict): an admin
	// resolves alone, as an admin override: allowed, audited
	// (quarantine.admin_override, approval_mode admin) and, for a
	// dismissal, alerted.
	before := maxDelivery(e.deliveries(t))
	head := e.auditHead(t)
	e.u(t, "ada").json(200, "POST", path, map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] != "resolved" {
		t.Fatalf("admin dismissal: %v (want resolved)", qi)
	}
	es := e.auditSince(t, head)
	if !hasAction(es, "quarantine.admin_override") || !hasAction(es, "authz.admin_override") {
		t.Errorf("admin dismissal not traced: %v", es)
	}
	time.Sleep(3 * time.Second)
	found := false
	for _, d := range e.deliveries(t) {
		if d["delivery_id"].(float64) > before && d["event"] == "keyguard.alert" {
			found = true
		}
	}
	if !found {
		t.Error("no keyguard.alert delivery for the admin dismissal")
	}
}

// The admin override: no reason -> 422; with a reason the approval is
// audited as policy.admin_approval with a digest (never the text) and an
// alert reaches the webhooks.
func TestRT_Core_Holds_AdminOverrideReasonAuditAlert(t *testing.T) {
	e := getEnv(t)
	pv := e.draftFor(t, "rt-ovr")
	ada := e.u(t, "ada")
	if code, b := ada.do("POST", approvePath(pv), nil); code != 422 || errCode(b) != "reason_required" {
		t.Errorf("admin without reason = %d %s", code, b)
	}
	if code, b := ada.do("POST", approvePath(pv), map[string]any{"reason": "   "}); code != 422 {
		t.Errorf("admin with blank reason = %d %s", code, b)
	}
	if code, b := e.u(t, "pia").do("POST", approvePath(pv), map[string]any{"reason": "I am not an admin"}); code != 403 {
		t.Errorf("approver with reason = %d %s", code, b)
	}
	before := maxDelivery(e.deliveries(t))
	head := e.auditHead(t)
	reason := "Rt override motivation qz4242 text"
	var out policyVersion
	ada.json(200, "POST", approvePath(pv), map[string]any{"reason": reason}, &out)
	if out.Status != "active" || out.ApprovalMode != "admin" {
		t.Fatalf("override: %+v", out)
	}
	es := e.auditSince(t, head)
	if !hasAction(es, "policy.admin_approval") {
		t.Error("no policy.admin_approval audit entry")
	}
	raw, _ := json.Marshal(es)
	if strings.Contains(string(raw), "qz4242") {
		t.Error("audit contains the reason text")
	}
	time.Sleep(3 * time.Second)
	found := false
	for _, d := range e.deliveries(t) {
		if d["delivery_id"].(float64) > before && d["event"] == "keyguard.alert" {
			found = true
		}
	}
	if !found {
		t.Error("no keyguard.alert delivery for the admin approval")
	}
}

// Packs: publish by publisher (or admin with a reason), download by
// publisher (and admin, traced); jobs and event exports are visible only to
// their owner (plus admin/auditor for jobs, admin for exports, traced).
func TestRT_Core_Holds_PackAndExportAuthz(t *testing.T) {
	e := getEnv(t)
	pub := "/api/v1/packs/" + e.packID + "/publish"
	dl := "/api/v1/packs/" + e.packID + "/download"
	for _, who := range []string{"olga", "audrey", "eve", "pia", "nora"} {
		if code, _ := e.u(t, who).do("POST", pub, nil); code != 403 {
			t.Errorf("%s publish = %d", who, code)
		}
		if code, _ := e.u(t, who).do("GET", dl, nil); code != 403 {
			t.Errorf("%s download = %d", who, code)
		}
	}
	// DECISION (owner, October 2026; was 403 publisher only): the admin
	// downloads too, as a traced override.
	head := e.auditHead(t)
	e.u(t, "ada").must(200, "GET", dl, nil)
	if !overrideIn(e.auditSince(t, head), "pack.download") || !hasAction(e.auditSince(t, head), "authz.admin_override") {
		t.Error("admin pack download not audited as an admin override")
	}
	e.u(t, "paula").must(200, "GET", dl, nil)
	// Event export: only its owner downloads it (or an admin, traced and
	// alerted); jobs: owner, admin, auditor.
	ev := "/api/v1/events/export/" + e.eveJob + "/download"
	if code, _ := e.u(t, "evan").do("GET", ev, nil); code != 404 {
		t.Errorf("another event-exporter downloads eve's export: %d", code)
	}
	e.u(t, "eve").must(200, "GET", ev, nil)
	before := maxDelivery(e.deliveries(t))
	head = e.auditHead(t)
	e.u(t, "ada").must(200, "GET", ev, nil)
	if !overrideIn(e.auditSince(t, head), "events.download") {
		t.Error("admin download of eve's event export not audited as an admin override")
	}
	// An event export by the admin itself: allowed, audited and alerted.
	e.u(t, "ada").must(202, "POST", "/api/v1/events/export", map[string]any{"from": e.start, "to": e.end, "format": "jsonl"})
	if !overrideIn(e.auditSince(t, head), "events.export") {
		t.Error("admin event export not audited as an admin override")
	}
	time.Sleep(3 * time.Second)
	alerts := 0
	for _, d := range e.deliveries(t) {
		if d["delivery_id"].(float64) > before && d["event"] == "keyguard.alert" {
			alerts++
		}
	}
	if alerts < 2 {
		t.Errorf("admin event download + export raised %d keyguard.alert deliveries (want >= 2)", alerts)
	}
	for who, want := range map[string]int{"evan": 404, "paul": 404, "olga": 404, "audrey": 200, "ada": 200, "eve": 200} {
		if code, _ := e.u(t, who).do("GET", "/api/v1/jobs/"+e.eveJob, nil); code != want {
			t.Errorf("%s GET job = %d (want %d)", who, code, want)
		}
	}
	// Exports of packs: role only (no owner in the spec); auditor reads the
	// status, not the file.
	e.u(t, "audrey").must(200, "GET", "/api/v1/exports/"+e.exportID, nil)
	if code, _ := e.u(t, "audrey").do("GET", "/api/v1/exports/"+e.exportID+"/download", nil); code != 403 {
		t.Errorf("auditor export download = %d", code)
	}
	head = e.auditHead(t)
	e.u(t, "ada").must(200, "GET", "/api/v1/exports/"+e.exportID+"/download", nil)
	if !overrideIn(e.auditSince(t, head), "export.download") {
		t.Error("admin export download not audited as an admin override")
	}
}

// overrideIn reports whether es holds action with details.admin_override.
func overrideIn(es []map[string]any, action string) bool {
	for _, a := range es {
		if det, _ := a["details"].(map[string]any); a["action"] == action && det["admin_override"] == "true" {
			return true
		}
	}
	return false
}
