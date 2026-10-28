package mock

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"code":"internal","message":"encoding failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorEnvelope(code, msg, ""))
}

// writeErrorP is writeError with the JSON Pointer of the offending field of
// the request body.
func writeErrorP(w http.ResponseWriter, status int, code, msg, ptr string) {
	writeJSON(w, status, errorEnvelope(code, msg, ptr))
}

func (m *Mock) authorized(r *http.Request) bool {
	if m.cfg.ControlToken == "" {
		return true
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(m.cfg.ControlToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// serveControl routes /__tt/... per api/control-api.v1.openapi.yaml.
func (m *Mock) serveControl(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/__tt"), "/")
	method := r.Method

	allow := func(methods ...string) bool {
		for _, mm := range methods {
			if method == mm {
				return true
			}
		}
		w.Header().Set("Allow", strings.Join(methods, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return false
	}

	// health is the only public control path (liveness probes carry no secret)
	if rest == "health" {
		if allow("GET") {
			writeJSON(w, 200, map[string]any{"status": "ok"})
		}
		return
	}
	if !m.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid control token is required")
		return
	}
	seg := strings.Split(rest, "/")

	switch {
	case rest == "pack":
		if allow("GET") {
			m.getPack(w)
		}
	case rest == "customers":
		if allow("GET") {
			m.listCustomers(w, r)
		}
	case rest == "scenarios":
		if allow("GET") {
			m.listPresets(w)
		}
	case rest == "sessions":
		if allow("POST") {
			m.createSession(w, r)
		}
	case rest == "pages":
		if allow("GET", "PUT") {
			m.controlPages(w, r)
		}
	case len(seg) >= 2 && seg[0] == "sessions":
		id := seg[1]
		if !sessionIDRE.MatchString(id) {
			writeError(w, http.StatusBadRequest, "bad_session_id", "session id is malformed")
			return
		}
		sub := strings.Join(seg[2:], "/")
		switch sub {
		case "":
			if !allow("GET", "DELETE") {
				return
			}
			if method == "GET" {
				m.withSession(w, id, func(s *session) { writeJSON(w, 200, s.view()) })
			} else {
				m.deleteSession(w, id)
			}
		case "reset":
			if allow("POST") {
				m.withSession(w, id, func(s *session) { s.reset(); writeJSON(w, 200, s.view()) })
			}
		case "customer":
			if allow("POST") {
				m.selectCustomer(w, r, id)
			}
		case "clock":
			if allow("GET") {
				m.withSession(w, id, func(s *session) { writeJSON(w, 200, s.clockView()) })
			}
		case "clock/advance":
			if allow("POST") {
				m.advanceClock(w, r, id)
			}
		case "faults":
			if !allow("GET", "PUT") {
				return
			}
			if method == "GET" {
				m.withSession(w, id, func(s *session) { writeJSON(w, 200, faultsView(s.faults)) })
			} else {
				m.setFaults(w, r, id)
			}
		case "scenario":
			if allow("POST") {
				m.scenario(w, r, id)
			}
		case "entities":
			if allow("GET") {
				m.withSession(w, id, func(s *session) {
					writeJSON(w, 200, s.listEntities(r.URL.Query().Get("entity"), r.URL.Query().Get("id")))
				})
			}
		case "journal":
			if allow("GET") {
				m.getJournal(w, r, id, false)
			}
		case "journal/unmatched":
			if allow("GET") {
				m.getJournal(w, r, id, true)
			}
		default:
			if len(seg) == 5 && seg[2] == "pages" {
				switch seg[4] {
				case "complete":
					if allow("POST") {
						m.controlSessionPages(w, r, id, seg[3], "complete")
					}
					return
				case "auto":
					if allow("PUT", "DELETE") {
						m.controlSessionPages(w, r, id, seg[3], "auto")
					}
					return
				}
			}
			writeError(w, http.StatusNotFound, "not_found", "unknown control path")
		}
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown control path")
	}
}

func (m *Mock) withSession(w http.ResponseWriter, id string, f func(*session)) {
	s := m.lookup(id)
	if s == nil {
		writeError(w, http.StatusNotFound, "session_not_found", "unknown session")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// decodeBody reads a strict JSON control body: unknown fields, wrong types
// and trailing data give 400 bad_request with a pointer into the body when
// the field is identifiable. present is false for an empty body.
func (m *Mock) decodeBody(w http.ResponseWriter, r *http.Request, v any) (present, ok bool) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, m.cfg.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
		return false, false
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return false, true
	}
	if ptr, err := strictDecode(data, v); err != nil {
		writeErrorP(w, http.StatusBadRequest, "bad_request", "invalid body: "+err.Error(), ptr)
		return true, false
	}
	return true, true
}

// fieldFail answers 400 for a validation error, prefixing the pointer.
func fieldFail(w http.ResponseWriter, prefix string, err error) {
	var fe *fieldError
	if errors.As(err, &fe) {
		writeErrorP(w, http.StatusBadRequest, "bad_request", fe.msg, prefix+fe.ptr)
		return
	}
	writeError(w, http.StatusBadRequest, "bad_request", err.Error())
}

// ---- pack ----

func (m *Mock) getPack(w http.ResponseWriter) {
	mod := m.model
	type ruleView struct {
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Outcomes []string `json:"outcomes"`
	}
	services := make([]string, 0, len(mod.services))
	for _, s := range mod.services {
		services = append(services, s.name)
	}
	rules := []ruleView{}
	for _, id := range mod.pack.Rules.Order {
		ri := mod.ruleInfo[id]
		oc := ri.outcomes
		if oc == nil {
			oc = []string{}
		}
		rules = append(rules, ruleView{ID: id, Title: ri.title, Outcomes: oc})
	}
	scen := []string{}
	for _, p := range mod.presets {
		scen = append(scen, p.ID)
	}
	var notAfter any
	if !mod.pack.NotAfter.IsZero() {
		notAfter = fmtTime(mod.pack.NotAfter)
	}
	writeJSON(w, 200, map[string]any{
		"pack_id": mod.pack.Manifest.PackID, "created_at": mod.pack.Manifest.CreatedAt, "not_after": notAfter,
		"services": services, "rules": rules, "customers": len(mod.custs), "scenarios": scen,
	})
}

func (m *Mock) listPresets(w http.ResponseWriter) {
	out := make([]pack.Scenario, 0, len(m.model.presets))
	for _, p := range m.model.presets {
		out = append(out, *p)
	}
	writeJSON(w, 200, out)
}

type customerView struct {
	ID        string         `json:"id"`
	Archetype *string        `json:"archetype"`
	Profile   map[string]any `json:"profile"`
}

func (m *Mock) listCustomers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be an integer within 1..1000")
			return
		}
		limit = n
	}
	arch := q.Get("archetype")
	out := []customerView{}
	for _, c := range m.model.custs {
		if arch != "" && (c.Archetype == nil || *c.Archetype != arch) {
			continue
		}
		out = append(out, customerView{ID: c.ID, Archetype: c.Archetype, Profile: c.Profile})
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, 200, out)
}

// ---- sessions ----

type sessionCreate struct {
	ID       string        `json:"id"`
	Seed     *uint64       `json:"seed"`
	Customer string        `json:"customer"`
	T0       string        `json:"t0"`
	Faults   *FaultsConfig `json:"faults"`
	Scenario string        `json:"scenario"`
}

type sessionView struct {
	ID       string       `json:"id"`
	Seed     uint64       `json:"seed"`
	Customer *string      `json:"customer"`
	Scenario *string      `json:"scenario"`
	Now      string       `json:"now"`
	Faults   FaultsConfig `json:"faults"`
	// ByIdentity: chosen by the caller's identity (mock.md 2.6).
	ByIdentity bool `json:"by_identity,omitempty"`
}

func (s *session) view() sessionView {
	v := sessionView{ID: s.id, Seed: s.seed, Customer: s.customer, Now: fmtTime(s.now), Faults: faultsView(s.faults), ByIdentity: s.byIdentity}
	if s.scenario != "" {
		sc := s.scenario
		v.Scenario = &sc
	}
	return v
}

func faultsView(f FaultsConfig) FaultsConfig {
	c := cloneFaults(f)
	return c
}

var presetIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (m *Mock) createSession(w http.ResponseWriter, r *http.Request) {
	var req sessionCreate
	if _, ok := m.decodeBody(w, r, &req); !ok {
		return
	}
	if req.ID != "" && !sessionIDRE.MatchString(req.ID) {
		writeErrorP(w, http.StatusBadRequest, "bad_request", "id must match ^[A-Za-z0-9_-]{1,64}$", "/id")
		return
	}
	var preset *pack.Scenario
	if req.Scenario != "" {
		if preset = m.model.presetBy[req.Scenario]; preset == nil || !presetIDRE.MatchString(req.Scenario) {
			writeError(w, http.StatusNotFound, "preset_not_found", "unknown scenario preset")
			return
		}
	}
	// the request wins over the preset, the preset over the defaults
	seed := m.model.pack.Manifest.Seed
	if m.cfg.Seed != nil {
		seed = *m.cfg.Seed
	}
	if preset != nil && preset.Seed != nil {
		seed = *preset.Seed
	}
	if req.Seed != nil {
		seed = *req.Seed
	}
	t0 := m.model.t0
	if req.T0 != "" {
		t, err := time.Parse(time.RFC3339, req.T0)
		if err != nil {
			writeErrorP(w, http.StatusBadRequest, "bad_request", "t0 must be an RFC 3339 date-time", "/t0")
			return
		}
		t0 = t.UTC()
	}
	var customer *string
	if preset != nil {
		customer = m.model.presetCustomer(preset)
	}
	if req.Customer != "" {
		if m.model.custByID[req.Customer] == nil {
			writeError(w, http.StatusNotFound, "customer_not_found", "unknown customer")
			return
		}
		c := req.Customer
		customer = &c
	}
	createFaults := FaultsConfig{Mode: m.cfg.Faults}
	baseFaults := createFaults
	if preset != nil && preset.Faults != nil {
		baseFaults = faultsFromPack(preset.Faults)
	}
	if req.Faults != nil {
		if err := m.model.validateFaults(*req.Faults); err != nil {
			fieldFail(w, "/faults", err)
			return
		}
		createFaults, baseFaults = *req.Faults, *req.Faults
	}

	if m.cfg.SessionIdleTTL > 0 {
		m.EvictIdle() // idle sessions make room first
	}
	m.mu.Lock()
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too_many_sessions", "session limit reached; delete unused sessions")
		return
	}
	id := req.ID
	if id == "" {
		for {
			m.nextAuto++
			id = fmt.Sprintf("s-%02d", m.nextAuto)
			if m.sessions[id] == nil {
				break
			}
		}
	} else if m.sessions[id] != nil {
		m.mu.Unlock()
		writeError(w, http.StatusConflict, "session_exists", "a session with this id already exists")
		return
	}
	s := newSession(m, sessionInit{id: id, seed: seed, customer: customer, t0: t0, createFaults: createFaults, baseFaults: baseFaults, preset: preset})
	m.sessions[id] = s
	m.mu.Unlock()

	s.mu.Lock()
	v := s.view()
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, v)
}

func (m *Mock) deleteSession(w http.ResponseWriter, id string) {
	if id == defaultSession {
		writeError(w, http.StatusBadRequest, "bad_request", "the default session cannot be deleted; reset it instead")
		return
	}
	m.mu.Lock()
	_, ok := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "session_not_found", "unknown session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Mock) selectCustomer(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Customer  string `json:"customer"`
		Archetype string `json:"archetype"`
	}
	present, ok := m.decodeBody(w, r, &req)
	if !ok {
		return
	}
	if !present || (req.Customer == "") == (req.Archetype == "") {
		writeError(w, http.StatusBadRequest, "bad_request", "exactly one of customer or archetype is required")
		return
	}
	var cust *customerView
	if req.Customer != "" {
		if c := m.model.custByID[req.Customer]; c != nil {
			cust = &customerView{ID: c.ID, Archetype: c.Archetype, Profile: c.Profile}
		}
	} else {
		for _, c := range m.model.custs { // sorted by id
			if c.Archetype != nil && *c.Archetype == req.Archetype {
				cust = &customerView{ID: c.ID, Archetype: c.Archetype, Profile: c.Profile}
				break
			}
		}
	}
	if cust == nil {
		writeError(w, http.StatusNotFound, "customer_not_found", "unknown customer or archetype")
		return
	}
	m.withSession(w, id, func(s *session) {
		cid := cust.ID
		s.customer = &cid
		writeJSON(w, 200, cust)
	})
}

// ---- clock ----

func (s *session) clockView() map[string]any {
	v := map[string]any{"now": fmtTime(s.now), "t0": fmtTime(s.t0), "next_due": nil}
	if t, ok := s.nextDue(); ok {
		v["next_due"] = fmtTime(t)
	}
	return v
}

// maxAppliedShown bounds the effects listed by one clock advance.
const maxAppliedShown = 1000

func (m *Mock) advanceClock(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		By *string `json:"by"`
		To *string `json:"to"`
	}
	present, ok := m.decodeBody(w, r, &req)
	if !ok {
		return
	}
	if !present || (req.By == nil) == (req.To == nil) {
		writeError(w, http.StatusBadRequest, "bad_request", "exactly one of by or to is required")
		return
	}
	m.withSession(w, id, func(s *session) {
		var target time.Time
		if req.By != nil {
			d, err := pack.ParseDuration(*req.By)
			if err != nil {
				writeErrorP(w, http.StatusBadRequest, "bad_request", "by must match ^[0-9]{1,6}(s|m|h|d)$", "/by")
				return
			}
			target = s.now.Add(d)
		} else {
			t, err := time.Parse(time.RFC3339, *req.To)
			if err != nil {
				writeErrorP(w, http.StatusBadRequest, "bad_request", "to must be an RFC 3339 date-time", "/to")
				return
			}
			target = t.UTC()
			if target.Before(s.now) {
				writeError(w, http.StatusBadRequest, "clock_backwards", "the clock never goes backwards")
				return
			}
		}
		if target.Sub(s.now) > m.cfg.MaxAdvance {
			writeError(w, http.StatusBadRequest, "advance_too_large", "advance exceeds the configured maximum")
			return
		}
		applied, total, err := s.advanceTo(target, maxAppliedShown)
		if err != nil {
			writeError(w, http.StatusBadRequest, "too_many_steps", "too many scheduled steps in one advance; the clock stopped at "+fmtTime(s.now))
			return
		}
		if applied == nil {
			applied = []appliedEffect{}
		}
		out := map[string]any{"now": fmtTime(s.now), "applied": applied}
		if total > len(applied) {
			// Only the first maxAppliedShown are listed; the session state
			// has all of them (GET .../entities).
			out["applied_total"], out["applied_truncated"] = total, true
		}
		writeJSON(w, 200, out)
	})
}

// ---- faults, scenarios ----

func (m *Mock) setFaults(w http.ResponseWriter, r *http.Request, id string) {
	var f FaultsConfig
	present, ok := m.decodeBody(w, r, &f)
	if !ok {
		return
	}
	if !present {
		writeError(w, http.StatusBadRequest, "bad_request", "a faults body is required")
		return
	}
	if err := m.model.validateFaults(f); err != nil {
		fieldFail(w, "", err)
		return
	}
	m.withSession(w, id, func(s *session) {
		s.faults = cloneFaults(f)
		s.faultUsed = make([]int, len(s.faults.Rules))
		writeJSON(w, 200, faultsView(s.faults))
	})
}

var ruleIDPatternRE = regexp.MustCompile(`^r-[0-9]{4,}$`)

// scenario forces outcomes (rule + outcome) or applies a preset (preset).
func (m *Mock) scenario(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Rule    *string `json:"rule"`
		Outcome *string `json:"outcome"`
		Times   *int    `json:"times"`
		Preset  *string `json:"preset"`
	}
	present, ok := m.decodeBody(w, r, &req)
	if !ok {
		return
	}
	if !present {
		writeError(w, http.StatusBadRequest, "bad_request", "rule and outcome, or preset, are required")
		return
	}
	if req.Preset != nil {
		if req.Rule != nil || req.Outcome != nil || req.Times != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "preset excludes rule, outcome and times")
			return
		}
		preset := m.model.presetBy[*req.Preset]
		if preset == nil || !presetIDRE.MatchString(*req.Preset) {
			writeError(w, http.StatusNotFound, "preset_not_found", "unknown scenario preset")
			return
		}
		m.withSession(w, id, func(s *session) {
			s.applyPreset(preset)
			writeJSON(w, 200, map[string]any{"pending": s.pendingScenarios(), "session": s.view()})
		})
		return
	}
	if req.Rule == nil || !ruleIDPatternRE.MatchString(*req.Rule) {
		writeErrorP(w, http.StatusBadRequest, "bad_request", "rule (r-NNNN) is required", "/rule")
		return
	}
	if req.Outcome == nil || *req.Outcome == "" {
		writeErrorP(w, http.StatusBadRequest, "bad_request", "outcome is required", "/outcome")
		return
	}
	times := 1
	if req.Times != nil {
		if *req.Times < 1 {
			writeErrorP(w, http.StatusBadRequest, "bad_request", "times must be >= 1", "/times")
			return
		}
		times = *req.Times
	}
	ri, known := m.model.ruleInfo[*req.Rule]
	if !known || !ri.causal {
		writeError(w, http.StatusNotFound, "rule_not_found", "unknown rule, or a rule without outcomes")
		return
	}
	found := false
	for _, o := range ri.outcomes {
		if o == *req.Outcome {
			found = true
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "outcome_not_found", "unknown outcome for this rule")
		return
	}
	m.withSession(w, id, func(s *session) {
		s.forceOutcome(*req.Rule, *req.Outcome, times)
		writeJSON(w, 200, map[string]any{"pending": s.pendingScenarios()})
	})
}

// ---- journal ----

func (m *Mock) getJournal(w http.ResponseWriter, r *http.Request, id string, unmatchedOnly bool) {
	q := r.URL.Query()
	since, ok := parseSince(q.Get("since"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "since must be a non-negative integer")
		return
	}
	format := q.Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "har" {
		writeError(w, http.StatusBadRequest, "bad_request", "format must be jsonl or har")
		return
	}
	m.withSession(w, id, func(s *session) {
		var entries []*journalEntry
		for _, e := range s.journalSince(since) {
			if unmatchedOnly && e.Matched {
				continue
			}
			entries = append(entries, e)
		}
		if format == "har" && !unmatchedOnly {
			writeJSON(w, 200, har(entries, Version))
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		_, _ = w.Write(ndjson(entries))
	})
}
