package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/world"
)

// ---------------------------------------------------------------------------
// Quarantine (admin-api listQuarantine, resolveQuarantine; event.md 5.2)
//
// close keeps the element closed for good: the rewrite of stored and future
// values stays in force (a closing change, one policy-approver). dismiss
// lifts the quarantine, which opens data again: it is recorded as an
// approval and takes effect only with two distinct policy-approvers
// (policy.md 5, threat model M7). An admin resolves alone (admin
// override): close or dismiss take effect at once, audited as
// quarantine.admin_override; a dismissal also raises an alert.

type qApproval struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

func parseItemID(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimPrefix(s, "q-"), 10, 64)
	return n, err == nil && n > 0 && strings.HasPrefix(s, "q-")
}

func (c *Core) quarantineApprovals(ctx context.Context, id int64, resolution string) ([]qApproval, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT user_id, at_ms FROM core_quarantine_approvals WHERE item_id = ? AND resolution = ? ORDER BY at_ms`, id, resolution)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []qApproval
	for rows.Next() {
		var a qApproval
		var ms int64
		if err := rows.Scan(&a.By, &ms); err != nil {
			return nil, err
		}
		a.At = time.UnixMilli(ms).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

func (c *Core) quarantineView(ctx context.Context, q intake.Quarantine) (map[string]any, error) {
	kind := string(q.Kind)
	switch q.Kind {
	case intake.QuarantineKeep:
		kind = "keep-value"
	case intake.QuarantineSegment:
		kind = "path-segment"
	}
	pending, err := c.quarantineApprovals(ctx, q.ID, "dismiss")
	if err != nil {
		return nil, err
	}
	state := "quarantined"
	switch {
	case q.State == intake.StateClosed || q.State == intake.StateReleased:
		state = "resolved"
	case len(pending) > 0:
		state = "dismiss-pending"
	}
	where := strings.TrimSpace(q.Part + " " + q.Path)
	if where == "" && q.Method != "" {
		where = q.Method + " position " + strconv.Itoa(q.Position)
	}
	if q.Kind == intake.QuarantineHostLabel {
		where = "hosts under " + q.Domain + " position " + strconv.Itoa(q.Position)
	}
	if where == "" && q.SourceID != "" {
		where = "registrable domains of the hosts of " + q.SourceID
	}
	approvals := []qApproval{}
	approvals = append(approvals, pending...)
	m := map[string]any{"item_id": "q-" + strconv.FormatInt(q.ID, 10), "kind": kind, "service": q.Service, "where": where,
		"distinct_estimate": q.Estimate, "state": state, "since": q.Since.UTC().Format(time.RFC3339), "approvals": approvals}
	if q.Op != "" {
		m["op"] = q.Op
	}
	if q.Kind == intake.QuarantineKeep {
		// Kept or code values with more distinct values than the threshold:
		// probably an identifier (policy.md 1.5, spec v1.19). The console
		// explains it; the observe phase stops proposing code on the field.
		m["alert"] = "value_cardinality"
	}
	if q.Kind == intake.QuarantineHost || q.Kind == intake.QuarantineHostLabel {
		m["alert"] = intake.AlarmHostCardinality
		if q.Service == "" {
			m["service"] = "host:*"
		}
	}
	return m, nil
}

func (c *Core) apiListQuarantine(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	qs := c.intake.Quarantines(false)
	out := make([]map[string]any, 0, len(qs))
	keep, err := c.quarantineGroups(r.Context(), groupscope.FromRequest(r))
	if err != nil {
		return err
	}
	for _, q := range qs {
		gs, ok := keep(q)
		if !ok {
			continue // another group's item
		}
		v, err := c.quarantineView(r.Context(), q)
		if err == nil && gs != nil {
			v["groups"] = gs
		}
		if err != nil {
			return err
		}
		out = append(out, v)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (c *Core) findQuarantine(id int64) (intake.Quarantine, bool) {
	for _, q := range c.intake.Quarantines(true) {
		if q.ID == id {
			return q, true
		}
	}
	return intake.Quarantine{}, false
}

func (c *Core) apiResolveQuarantine(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id, ok := parseItemID(r.PathValue("item_id"))
	if !ok {
		return apiErr(http.StatusNotFound, "not_found", "quarantine item not found")
	}
	var req struct {
		Resolution string `json:"resolution"`
		IDToken    string `json:"id_token"`
		Note       string `json:"note"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Resolution != "close" && req.Resolution != "dismiss" {
		return apiErr(http.StatusBadRequest, "invalid_input", "resolution must be close or dismiss")
	}
	if len(req.Note) > 1000 {
		return apiErr(http.StatusBadRequest, "invalid_input", "note is limited to 1000 characters")
	}
	ctx := r.Context()
	q, ok := c.findQuarantine(id)
	if !ok {
		return apiErr(http.StatusNotFound, "not_found", "quarantine item not found")
	}
	if q.State == intake.StateReleased || (q.State == intake.StateClosed && req.Resolution == "close") {
		v, err := c.quarantineView(ctx, q)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, v)
		return nil
	}
	ev := audit.Event{Actor: p.AuditActor(), Action: "quarantine." + req.Resolution, Target: audit.Target{Type: "quarantine", ID: "q-" + strconv.FormatInt(id, 10)}, Outcome: audit.Success}

	// A dismissal opens data again: when keyguard verifies approvals with
	// OIDC, each dismiss approval needs a step-up ID token bound to this
	// item (approvebind.QuarantineNonce), verified here by tt-core (keyguard
	// takes no part in quarantine resolutions). Local accounts cannot
	// attach tokens.
	if req.IDToken != "" && p.OIDCSubject == "" {
		ev.Outcome, ev.Reason = audit.Denied, "id_token_not_allowed"
		c.record(ctx, ev)
		return apiErr(http.StatusForbidden, "id_token_not_allowed", "local accounts cannot attach OIDC ID tokens")
	}
	// An admin resolves as an admin override (alone, traced), also when it
	// holds policy-approver: an admin is never one of the two persons.
	adminOvr := p.IsAdmin()
	if req.Resolution == "dismiss" {
		at := approvalTokens{auth: c.auth, fleet: c.fleet, log: c.log}
		if at.Verified() {
			ref := "q-" + strconv.FormatInt(id, 10)
			if _, err := at.ApprovalToken(ctx, p, approvebind.PurposeQuarantine, ref, approvebind.QuarantineNonce(ref), req.IDToken); err != nil {
				status, code, msg := auth.ApprovalTokenError(err, req.IDToken != "")
				ev.Outcome, ev.Reason = audit.Denied, code
				c.record(ctx, ev)
				return apiErr(status, code, msg)
			}
		}
	}

	// The approval is checked and stored in one transaction (separation
	// of duties: an approver counts once; the system raised the item, so
	// there is no author to exclude).
	var quorum bool
	var dropped []string
	err := c.db.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT user_id FROM core_quarantine_approvals WHERE item_id = ? AND resolution = ?`, id, req.Resolution)
		if err != nil {
			return err
		}
		var prior []string
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err != nil {
				rows.Close()
				return err
			}
			prior = append(prior, u)
		}
		rows.Close()
		if err := auth.CheckApproval(p, auth.RolePolicyApprover, "", prior); err != nil {
			return err
		}
		// Stale approvals: an earlier approver counts only while still
		// enabled and entitled (policy-approver, not admin); the others
		// are dropped before the quorum is evaluated.
		cur, err := auth.CurrentRoles(ctx, tx, prior)
		if err != nil {
			return err
		}
		valid := prior[:0:0]
		for _, u := range prior {
			if rs, ok := cur[u]; ok && auth.EntitledApprover(rs, auth.RolePolicyApprover) {
				valid = append(valid, u)
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM core_quarantine_approvals WHERE item_id = ? AND resolution = ? AND user_id = ?`, id, req.Resolution, u); err != nil {
				return err
			}
			dropped = append(dropped, u)
		}
		prior = valid
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_quarantine_approvals (item_id, resolution, user_id, at_ms) VALUES (?, ?, ?, ?)`,
			id, req.Resolution, p.UserID, time.Now().UnixMilli()); err != nil {
			return err
		}
		need := 1
		if req.Resolution == "dismiss" {
			need = 2
		}
		quorum = adminOvr || auth.DistinctApprovals("", append(prior, p.UserID)) >= need
		return nil
	})
	if errors.Is(err, auth.ErrDuplicateApproval) {
		ev.Outcome, ev.Reason = audit.Denied, "duplicate_approval"
		c.record(ctx, ev)
		return apiErr(http.StatusConflict, "duplicate_approval", "you already approved this resolution")
	}
	if err != nil {
		return err
	}
	for _, u := range dropped {
		c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "quarantine.approval_dropped", Target: ev.Target, Outcome: audit.Success,
			Reason: "approver_disabled_or_role_removed", Details: map[string]string{"user": audit.SafeValue(u), "resolution": req.Resolution}})
	}
	if quorum {
		if req.Resolution == "close" {
			q, err = c.intake.CloseQuarantine(ctx, id)
		} else {
			q, err = c.intake.ReleaseQuarantine(ctx, id)
		}
		if err != nil && !errors.Is(err, intake.ErrNoQuarantine) {
			return err
		}
		if err == nil {
			ev.Details = map[string]string{"state": string(q.State)}
		}
	} else {
		ev.Details = map[string]string{"state": "dismiss-pending"}
	}
	if adminOvr {
		if ev.Details == nil {
			ev.Details = map[string]string{}
		}
		ev.Details["approval_mode"] = "admin"
	}
	c.record(ctx, ev)
	if adminOvr {
		// Traceability instead of a second person: the override has its own
		// entry, and a dismissal (it opens data again) is alerted.
		c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "quarantine.admin_override", Target: ev.Target, Outcome: audit.Success,
			Details: map[string]string{"resolution": req.Resolution, "state": ev.Details["state"]}})
		if req.Resolution == "dismiss" {
			c.alerts.emit(ctx, "keyguard.alert", map[string]any{"alert": "quarantine.admin_override", "item": ev.Target.ID, "resolution": req.Resolution, "by": p.UserID})
		}
	}
	q, _ = c.findQuarantine(id)
	v, err := c.quarantineView(ctx, q)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// ---------------------------------------------------------------------------
// Scenario presets (admin-api scenario-presets): stored in zone B, added to
// a pack when its build request names them (the gate checks their texts).

var rePresetID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type presetDoc struct {
	PresetID    string                `json:"preset_id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Customer    string                `json:"customer,omitempty"`
	Archetype   string                `json:"archetype,omitempty"`
	Seed        *uint64               `json:"seed,omitempty"`
	Faults      map[string]any        `json:"faults,omitempty"`
	Outcomes    []world.PresetOutcome `json:"outcomes,omitempty"`
}

func (d *presetDoc) validate() error {
	switch {
	case !rePresetID.MatchString(d.PresetID):
		return apiErr(http.StatusBadRequest, "invalid_input", "preset_id must match ^[a-z0-9][a-z0-9-]{0,62}$")
	case d.Name == "" || len(d.Name) > 120:
		return apiErr(http.StatusBadRequest, "invalid_input", "name is required (at most 120 characters)")
	case len(d.Description) > 1000:
		return apiErr(http.StatusBadRequest, "invalid_input", "description is limited to 1000 characters")
	case d.Customer != "" && d.Archetype != "":
		return apiErr(http.StatusBadRequest, "invalid_input", "customer and archetype are exclusive")
	}
	for _, o := range d.Outcomes {
		if o.Rule == "" || o.Outcome == "" || o.Times < 0 {
			return apiErr(http.StatusBadRequest, "invalid_input", "every outcome needs rule and outcome (times >= 1)")
		}
	}
	return nil
}

func (d *presetDoc) preset() world.Preset {
	return world.Preset{ID: d.PresetID, Name: d.Name, Description: d.Description, Customer: d.Customer, Archetype: d.Archetype,
		Seed: d.Seed, Faults: d.Faults, Outcomes: d.Outcomes}
}

func (c *Core) loadPresets(ctx context.Context, ids []string) ([]presetDoc, error) {
	q := `SELECT doc FROM core_scenario_presets ORDER BY id`
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []presetDoc
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		var d presetDoc
		if err := json.Unmarshal([]byte(s), &d); err != nil {
			return nil, err
		}
		if len(want) == 0 || want[d.PresetID] {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// presetStore implements packwriter.PresetsSource.
type presetStore struct{ c *Core }

func (s presetStore) Presets(ctx context.Context, ids []string) ([]world.Preset, error) {
	ds, err := s.c.loadPresets(ctx, ids)
	if err != nil {
		return nil, err
	}
	if len(ds) != len(ids) {
		return nil, apiErr(http.StatusUnprocessableEntity, "unknown_preset", "a requested scenario preset does not exist")
	}
	out := make([]world.Preset, len(ds))
	for i := range ds {
		out[i] = ds[i].preset()
	}
	return out, nil
}

func (c *Core) apiListPresets(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ds, err := c.loadPresets(r.Context(), nil)
	if err != nil {
		return err
	}
	if ds == nil {
		ds = []presetDoc{}
	}
	httpx.WriteJSON(w, http.StatusOK, ds)
	return nil
}

func (c *Core) savePreset(w http.ResponseWriter, r *http.Request, p *auth.Principal, create bool) error {
	var d presetDoc
	if err := decode(w, r, &d); err != nil {
		return err
	}
	if !create {
		if d.PresetID == "" {
			d.PresetID = r.PathValue("preset_id")
		}
		if d.PresetID != r.PathValue("preset_id") {
			return apiErr(http.StatusBadRequest, "invalid_input", "preset_id does not match the path")
		}
	}
	if err := d.validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(d)
	ctx := r.Context()
	var res sql.Result
	var err error
	if create {
		res, err = c.db.ExecContext(ctx, `INSERT INTO core_scenario_presets (id, doc, updated_ms) VALUES (?, ?, ?) ON CONFLICT(id) DO NOTHING`,
			d.PresetID, string(b), time.Now().UnixMilli())
	} else {
		res, err = c.db.ExecContext(ctx, `UPDATE core_scenario_presets SET doc = ?, updated_ms = ? WHERE id = ?`, string(b), time.Now().UnixMilli(), d.PresetID)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if create {
			return apiErr(http.StatusConflict, "preset_exists", "a preset with this id exists")
		}
		return apiErr(http.StatusNotFound, "not_found", "preset not found")
	}
	action, status := "preset.update", http.StatusOK
	if create {
		action, status = "preset.create", http.StatusCreated
	}
	c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: action, Target: audit.Target{Type: "preset", ID: d.PresetID}, Outcome: audit.Success})
	httpx.WriteJSON(w, status, d)
	return nil
}

func (c *Core) apiCreatePreset(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	return c.savePreset(w, r, p, true)
}

func (c *Core) apiUpdatePreset(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	return c.savePreset(w, r, p, false)
}

func (c *Core) apiDeletePreset(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("preset_id")
	res, err := c.db.ExecContext(r.Context(), `DELETE FROM core_scenario_presets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return apiErr(http.StatusNotFound, "not_found", "preset not found")
	}
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "preset.delete", Target: audit.Target{Type: "preset", ID: audit.SafeValue(id)}, Outcome: audit.Success})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// quarantineGroups returns, for the selected groups, whether a quarantine
// item belongs to them and its groups: through its source, else its policy,
// else its service. Items of none (a registrable domain of every host) are
// kept for every group.
func (c *Core) quarantineGroups(ctx context.Context, sel groupscope.Set) (func(intake.Quarantine) ([]string, bool), error) {
	src, err := c.fleet.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	pg, err := c.fleet.PolicyGroups(ctx)
	if err != nil {
		return nil, err
	}
	sg, err := c.serviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	return func(q intake.Quarantine) ([]string, bool) {
		var gs []string
		switch {
		case q.SourceID != "" && src[q.SourceID] != "":
			gs = []string{src[q.SourceID]}
		case q.PolicyID != "" && len(pg[q.PolicyID]) > 0:
			gs = pg[q.PolicyID]
		case q.Service != "" && len(sg[q.Service]) > 0:
			gs = sg[q.Service]
		default:
			return nil, true
		}
		return gs, sel.Any(gs)
	}, nil
}

// keepQuarantined reports whether the intake quarantined the kept values of
// a field of a policy (fleet.ObserveOptions.Quarantined): the observe phase
// stops proposing code on it (policy.md 1.5, spec v1.19). part is request or
// response; path is "$..." for the body or "<part>.<name>" as in the
// assistant.
func (c *Core) keepQuarantined(policyID, service, op, part, path string) bool {
	if c.intake == nil {
		return false
	}
	side := "req"
	if part == "response" {
		side = "resp"
	}
	qpart, qpath := side+".body", path
	if !strings.HasPrefix(path, "$") {
		k, n, ok := strings.Cut(path, ".")
		if !ok {
			return false
		}
		qpart, qpath = side+"."+k, n
	}
	for _, q := range c.intake.Quarantines(false) {
		if q.Kind == intake.QuarantineKeep && q.PolicyID == policyID && q.Service == service && q.Op == op &&
			q.Part == qpart && q.Path == qpath {
			return true
		}
	}
	return false
}

// bodiesDefaults is the bodies object of fleet.sanitizer (spec v1.19), nil
// when it is off.
func bodiesDefaults(s config.SanitizerDefaults) *policy.Bodies {
	if !s.Bodies {
		return nil
	}
	return &policy.Bodies{XML: s.XML, Multipart: s.Multipart, Docs: s.Docs, MaxLargeBytes: s.MaxLargeBodyBytes,
		LargeArray: s.LargeArray, LargeNestedArray: s.LargeNestedArray}
}
