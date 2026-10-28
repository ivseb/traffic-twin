package miner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Mining states reported by GET /api/v1/rules/status.
const (
	// StateNeverRun: the miner has not completed a run yet.
	StateNeverRun = "never_run"
	// StateNoData: the last run found no events in its window.
	StateNoData = "no_data"
	// StateInsufficientData: the observed traffic spans less than
	// min_hours, so no cause can have a decided outcome yet.
	StateInsufficientData = "insufficient_data"
	// StateFewSubjects: enough traffic over time, but fewer distinct sampled
	// users than k_min. The policy's sampling is per user: with a low rate and
	// few users no rule can be proposed (a value is published only when at
	// least k_min distinct users produced it). Raise the sampling or wait.
	StateFewSubjects = "few_subjects"
	// StateOK: enough traffic was observed.
	StateOK = "ok"
)

// Status is the state of the mining pipeline: what the last run saw and
// whether it saw enough traffic to decide anything.
type Status struct {
	State string `json:"state"`
	// MinHours is the least span of traffic a run needs; ObservedHours is
	// what the last run saw (first to last event).
	MinHours      float64 `json:"min_hours"`
	ObservedHours float64 `json:"observed_hours"`
	Events        int     `json:"events"`
	// Subjects is the number of distinct users (subject tokens) the last run saw
	// and KMin the least a rule needs (k-anonymity); Subjects is absent for a run
	// stored before it was recorded.
	Subjects  *int   `json:"subjects,omitempty"`
	KMin      int    `json:"k_min"`
	RunID     int64  `json:"run_id,omitempty"`
	LastRunAt string `json:"last_run_at,omitempty"`
	// Rules counts the stored rules by status.
	Rules map[string]int `json:"rules"`
	// MinBirthShare and StaleRuns are the thresholds the diagnostics refer to.
	MinBirthShare float64 `json:"min_birth_share"`
	StaleRuns     int     `json:"stale_runs"`
	// Entities and RuleDiagnostics explain the last run: why each entity
	// candidate was accepted or dropped and what became of each rule
	// (proposed, kept, on watch with its strikes, stale, not mined and why).
	Entities        []EntityDiag `json:"entities"`
	RuleDiagnostics []RuleDiag   `json:"rule_diagnostics"`
	// Merges are the identifiers the last run found relayed under another
	// HMAC domain (an id minted by an external service, returned by the own
	// service under its own field name).
	Merges []DomainMerge `json:"merges"`
	// Groups is, per group, what the last run examined: its events, its
	// observed span and whether states were observed (a state field in clear
	// that changes over time). Events, observed_hours and subjects above are
	// the whole console's; tt-core replaces them with the selected groups'
	// when the request names groups.
	Groups []GroupDiag `json:"groups"`
	// Candidates and Families (rules v1.9): structures seen by fewer than k
	// subjects, offered as guided drafts (C0), and HMAC domains that look
	// like one identifier (C15). TestK is, per group mined with a lower k,
	// the k used.
	Candidates []Candidate       `json:"candidates"`
	Families   []FamilyCandidate `json:"families"`
	TestK      map[string]int    `json:"test_k,omitempty"`
	// Warnings are the problems worth a badge: dropped entities, rules on
	// watch or stale, with their reasons.
	Warnings []string `json:"warnings"`
}

func hours(d time.Duration) float64 {
	return float64(int64(d.Hours()*100+0.5)) / 100
}

// classify derives the state of a run from its numbers.
func classify(events int, observed, min time.Duration) string {
	switch {
	case events == 0:
		return StateNoData
	case observed < min:
		return StateInsufficientData
	}
	return StateOK
}

// Status reports the last run's coverage.
func (rp *Repo) Status(ctx context.Context) (*Status, error) {
	st := &Status{State: StateNeverRun, MinHours: hours(rp.cfg.MinCoverage()), KMin: rp.cfg.KMin, Rules: map[string]int{},
		MinBirthShare: rp.cfg.MinBirthShare, StaleRuns: rp.cfg.StaleRuns,
		Entities: []EntityDiag{}, RuleDiagnostics: []RuleDiag{}, Merges: []DomainMerge{}, Groups: []GroupDiag{}, Warnings: []string{},
		Candidates: []Candidate{}, Families: []FamilyCandidate{}}
	var id, finished, events, observed int64
	var diag sql.NullString
	err := rp.db.QueryRowContext(ctx, `SELECT id, finished_at, events, observed_seconds, diagnostics FROM miner_runs ORDER BY id DESC LIMIT 1`).
		Scan(&id, &finished, &events, &observed, &diag)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		obs := time.Duration(observed) * time.Second
		st.RunID, st.Events, st.ObservedHours = id, int(events), hours(obs)
		st.LastRunAt = time.UnixMilli(finished).UTC().Format(time.RFC3339)
		st.State = classify(int(events), obs, rp.cfg.MinCoverage())
		if diag.Valid {
			var d Diagnostics
			if json.Unmarshal([]byte(diag.String), &d) == nil {
				st.Entities, st.RuleDiagnostics = nonNilEntities(d.Entities), nonNilRules(d.Rules)
				st.Subjects = d.Subjects
				if d.Merges != nil {
					st.Merges = d.Merges
				}
				if d.Groups != nil {
					st.Groups = d.Groups
				}
				if d.Candidates != nil {
					st.Candidates = d.Candidates
				}
				if d.Families != nil {
					st.Families = d.Families
				}
				st.TestK = d.TestK
			}
		}
		if st.State == StateOK && st.Subjects != nil && *st.Subjects < rp.cfg.KMin {
			st.State = StateFewSubjects
		}
	}
	rows, err := rp.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM miner_rules GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		st.Rules[s] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	st.Warnings = warnings(st)
	return st, nil
}

// warnings lists what the operator should look at, from the diagnostics.
func warnings(st *Status) []string {
	out := []string{}
	for _, e := range st.Entities {
		if !e.Accepted && e.significant() {
			out = append(out, "entity "+e.Name+" dropped: "+e.Reason)
		}
	}
	for _, r := range st.RuleDiagnostics {
		switch r.Decision {
		case DecisionWatch:
			out = append(out, fmt.Sprintf("rule %s on watch (%d of %d runs): %s", r.RuleID, r.Strikes, r.StaleRuns, r.Reason))
		case DecisionStale:
			out = append(out, fmt.Sprintf("rule %s stale: %s", r.RuleID, r.Reason))
		}
	}
	if st.State == StateFewSubjects {
		out = append(out, fmt.Sprintf("few distinct sampled users: %d < k=%d; raise the policy sampling or wait for more traffic", *st.Subjects, st.KMin))
	}
	if st.State == StateOK && st.Rules["draft"]+st.Rules["approved"]+st.Rules["stale"]+st.Rules["rejected"]+st.Rules[StatusSuperseded] == 0 {
		out = append(out, "no rule proposed: see the entity and rule diagnostics")
	}
	return out
}

func (s *Service) getStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	st, err := s.repo.Status(r.Context())
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
