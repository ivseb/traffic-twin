package miner

import (
	"fmt"
	"math"
)

// Diagnostics explain what a run decided and why: per entity (accepted or
// dropped) and per rule (proposed, kept, dropped, on its way to stale). They
// are stored with the run and shown by the status endpoint and the job
// result, so that "0 rules" is never a silent outcome.

// Rule decisions.
const (
	// DecisionProposed: mined in this run (new or refreshed draft).
	DecisionProposed = "proposed"
	// DecisionNotMined: a candidate that produced no rule; Reason says why.
	DecisionNotMined = "not_mined"
	// DecisionKept: an approved rule confirmed by the run.
	DecisionKept = "kept"
	// DecisionWatch: an approved rule that failed this run but has not yet
	// failed StaleRuns consecutive runs (Strikes of StaleRuns).
	DecisionWatch = "watch"
	// DecisionStale: an approved rule that became stale in this run.
	DecisionStale = "stale"
	// DecisionNotSeen: an approved rule whose cause was not seen in the
	// window (nothing to judge: neither confirmed nor failed).
	DecisionNotSeen = "not_seen"
	// DecisionSkipped: not judged because the run had too little traffic.
	DecisionSkipped = "skipped"
)

// EntityDiag explains the acceptance of an entity candidate.
type EntityDiag struct {
	Name string `json:"name"`
	// Op is the candidate creator ("service op").
	Op string `json:"op"`
	// AtCreator is the number of distinct objects seen at the creator's id
	// location, Born those whose creation exchange was captured (the
	// creator minted them), so AtCreator-Born were seen there without being
	// minted. Objects counts every object of the domain, PreExisting those
	// first seen without a creation (restart, retention cutoff, sampling):
	// they are not evidence against the entity.
	AtCreator   int `json:"at_creator"`
	Born        int `json:"born"`
	Objects     int `json:"objects"`
	PreExisting int `json:"pre_existing"`
	// BirthShare is Born/AtCreator; BirthShareLow its Wilson lower bound
	// (95 %), the figure compared with MinBirthShare.
	BirthShare    float64 `json:"birth_share"`
	BirthShareLow float64 `json:"birth_share_low"`
	MinBirthShare float64 `json:"min_birth_share"`
	Accepted      bool    `json:"accepted"`
	Reason        string  `json:"reason"`
	// Code names the decision for the UI (it translates it): accepted,
	// few_births, low_birth_share, reference. Reference is true for the id of
	// the requesting user (a member, a customer): it exists before the call,
	// it never blocks a rule and it is not worth a warning.
	Code      string `json:"code,omitempty"`
	Reference bool   `json:"reference,omitempty"`
}

// Entity decision codes (EntityDiag.Code).
const (
	EntityAccepted      = "accepted"
	EntityFewBirths     = "few_births"
	EntityLowBirthShare = "low_birth_share"
	EntityReference     = "reference"
)

// significant reports whether a dropped candidate is worth a warning: it was
// seen being created for a fair share of the domain's objects. Ids that are
// only minted along the way (a customer id in an order response) are listed
// but stay quiet.
func (d EntityDiag) significant() bool {
	return !d.Reference && d.Objects > 0 && float64(d.Born) >= 0.25*float64(d.Objects)
}

// RuleDiag explains what happened to a rule (or a rule candidate).
type RuleDiag struct {
	RuleID    string `json:"rule_id,omitempty"`
	Signature string `json:"signature"`
	Kind      string `json:"kind"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	// Confidence is the confidence of this run; Strikes the number of
	// consecutive failed runs of an approved rule, of StaleRuns.
	Confidence float64 `json:"confidence,omitempty"`
	Strikes    int     `json:"strikes,omitempty"`
	StaleRuns  int     `json:"stale_runs,omitempty"`
	// Code names the reason for the UI, which translates it (Why*); Service,
	// Op and Entity say which candidate (causal: the cause and the entity it
	// creates); Causes, Decided, Subjects and HorizonSeconds are the figures
	// behind a not_mined decision (creations captured, causes old enough to
	// have a decided outcome, distinct users, the decision horizon).
	Code           string `json:"code,omitempty"`
	Service        string `json:"service,omitempty"`
	Op             string `json:"op,omitempty"`
	Entity         string `json:"entity,omitempty"`
	Causes         int    `json:"causes,omitempty"`
	Decided        int    `json:"decided,omitempty"`
	Subjects       int    `json:"subjects,omitempty"`
	HorizonSeconds int64  `json:"horizon_s,omitempty"`
	// Values says whether the object the candidate creates has values in
	// clear (keep, or code: a status that leaves as DELIVERED counts):
	// ValuesInClear, or ValuesDropped when none of its fields do and a
	// policy approval may be what is missing. ClearFields names up to
	// maxClearFields of them. Only set on causal candidates.
	Values      string   `json:"values,omitempty"`
	ClearFields []string `json:"clear_fields,omitempty"`
}

// RuleDiag.Values.
const (
	ValuesInClear = "in_clear"
	ValuesDropped = "dropped"
)

// Reason codes of a causal candidate (RuleDiag.Code).
const (
	WhyMined = "mined"
	// WhyFewCauses: fewer than k creations captured (or no status with k).
	WhyFewCauses = "few_causes"
	// WhyNoEffect: the operation creates its object and nothing else is
	// observed (no nested creation, no lifecycle): nothing to simulate.
	WhyNoEffect = "no_effect"
	// WhyFewSubjects: fewer than k distinct users made the causes.
	WhyFewSubjects = "few_subjects"
	// WhyUndecided: no cause is old enough to have a decided outcome yet.
	WhyUndecided = "undecided"
	// WhyOutcomeFewSubjects: outcomes are decided but none has k users.
	WhyOutcomeFewSubjects = "outcome_few_subjects"
	WhyNoOutcome          = "no_outcome"
	// WhyEntity: the entity the rule would create was not accepted.
	WhyEntity = "entity_not_accepted"
)

// Diagnostics is the explanation of one run.
type Diagnostics struct {
	Entities []EntityDiag `json:"entities"`
	Rules    []RuleDiag   `json:"rules"`
	// Groups tells, for each group mined apart, how much traffic the run
	// examined and whether states were observed (see GroupDiag).
	Groups []GroupDiag `json:"groups,omitempty"`
	// Subjects is the number of distinct users (subject tokens) the run saw; nil in
	// runs stored before it was recorded.
	Subjects *int `json:"subjects,omitempty"`
	// Merges are the identifiers found relayed under another HMAC domain
	// (relay.go): the two domains were mined as one.
	Merges []DomainMerge `json:"merges,omitempty"`
	// Reads are the operations whose kind the run did not take from the
	// method (rules v1.6): POSTs classified as reads by their behaviour and
	// the decisions of a person in the console.
	Reads []ReadDecision `json:"reads,omitempty"`
	// Candidates are the structures seen by fewer than k subjects (C0,
	// rules v1.9); Families the HMAC domains that look like one identifier
	// (C15).
	Candidates []Candidate       `json:"candidates,omitempty"`
	Families   []FamilyCandidate `json:"families,omitempty"`
	// TestK is, per group mined with a lower k (a group marked as test in
	// the console), the k used.
	TestK map[string]int `json:"test_k,omitempty"`
}

// wilsonLow is the lower bound of the Wilson score interval (z = 1.96) for k
// successes in n trials: a small sample cannot reach a high bound by luck.
func wilsonLow(k, n int) float64 {
	if n <= 0 {
		return 0
	}
	const z = 1.96
	p := float64(k) / float64(n)
	nf := float64(n)
	den := 1 + z*z/nf
	centre := p + z*z/(2*nf)
	margin := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	return math.Max(0, (centre-margin)/den)
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// acceptBirths decides whether an entity candidate has enough evidence: at
// least KMin objects seen being created, and the lower bound of the share of
// objects at the creator location that were born there at least
// MinBirthShare. It returns the lower bound and a reason.
func (m *miner) acceptBirths(born, atCreator int) (bool, float64, string, string) {
	low := wilsonLow(born, atCreator)
	switch {
	case born < m.cfg.KMin:
		return false, low, EntityFewBirths, fmt.Sprintf("only %d objects seen being created, at least %d needed", born, m.cfg.KMin)
	case low < m.cfg.MinBirthShare:
		return false, low, EntityLowBirthShare, fmt.Sprintf("birth share %.2f (lower bound %.2f) < %.2f (%d of %d objects seen being created)",
			float64(born)/float64(atCreator), low, m.cfg.MinBirthShare, born, atCreator)
	}
	return true, low, EntityAccepted, fmt.Sprintf("birth share %.2f (lower bound %.2f) >= %.2f (%d of %d objects seen being created)",
		float64(born)/float64(atCreator), low, m.cfg.MinBirthShare, born, atCreator)
}

// GroupDiag is what one run examined of one group's traffic.
type GroupDiag struct {
	// Group is the fleet group ("" when sources are not attributed).
	Group string `json:"group"`
	// Events, Objects and Subjects are the group's events examined by the
	// run, the objects found in them and the distinct users; ObservedSeconds
	// the span between its first and last event.
	Events          int   `json:"events"`
	Objects         int   `json:"objects"`
	Subjects        int   `json:"subjects"`
	ObservedSeconds int64 `json:"observed_s"`
	// Entities counts the accepted entities. StatesObserved is true when the
	// group has at least one object whose state field is in clear and changes
	// over time (a lifecycle): then no policy approval is needed to get
	// states. StateFields names those fields; ClearFields the string fields
	// of the group's objects seen in clear. Lifecycles counts the entities
	// with a lifecycle.
	Entities       int      `json:"entities"`
	Lifecycles     int      `json:"lifecycles"`
	StatesObserved bool     `json:"states_observed"`
	StateFields    []string `json:"state_fields,omitempty"`
	ClearFields    []string `json:"clear_fields,omitempty"`
}

// Candidate is a structure seen by fewer than k subjects (rules v1.9, C0):
// what the miner would propose with a lower k, shown in the console as a
// guided draft. It carries structure only (operations, field names, clear
// states, a status) and the number of subjects as a bucket, never an
// example, a token or an exact count.
type Candidate struct {
	Group     string `json:"group,omitempty"`
	Signature string `json:"signature"`
	// Kind is create, update, keyed_update, update_all, remove, limit,
	// precondition, later or revert; Template is the editor template it
	// fills (write_changes_field, expires_after, at_most_n, until, custom).
	Kind     string   `json:"kind"`
	Template string   `json:"template"`
	Service  string   `json:"service"`
	Op       string   `json:"op"`
	Entity   string   `json:"entity,omitempty"`
	Fields   []string `json:"fields,omitempty"`
	States   []string `json:"states,omitempty"`
	Status   int      `json:"status,omitempty"`
	// Target is the "service op" whose answers a response effect changes.
	Target string `json:"target,omitempty"`
	// Subjects is a bucket: "1", "2-4", "5-9" or "10+" (always below k).
	Subjects string `json:"subjects"`
	// MissingEntities are the entities the draft needs that the run did not
	// accept (seen by fewer than k users): the draft can be saved only once
	// they exist, for instance after marking the group as test (lower k).
	MissingEntities []string `json:"missing_entities,omitempty"`
	// Draft is the rule skeleton the editor starts from: counts zeroed, no
	// keys nor hints, origin manual, status draft.
	Draft *Rule `json:"draft"`
}

// Candidate kinds and editor templates (C0, C18).
const (
	CandCreate       = "create"
	CandUpdate       = "update"
	CandKeyedUpdate  = "keyed_update"
	CandUpdateAll    = "update_all"
	CandRemove       = "remove"
	CandLimit        = "limit"
	CandPrecondition = "precondition"
	CandLater        = "later"
	CandRevert       = "revert"

	TplWriteChangesField = "write_changes_field"
	TplExpiresAfter      = "expires_after"
	TplAtMostN           = "at_most_n"
	TplUntil             = "until"
	TplCustom            = "custom"
)

// FamilyCandidate proposes two HMAC domains that look like one identifier
// under two names (rules v1.9, C15), judged from structure only: the same
// number of distinct tokens per subject, a token of one first seen right
// after a new token of the other, the same operations. Tokens of two
// domains are never compared (they cannot be equal).
type FamilyCandidate struct {
	Group    string   `json:"group,omitempty"`
	Domains  []string `json:"domains"`
	Subjects int      `json:"subjects"`
	Signals  []string `json:"signals"`
	Score    float64  `json:"score"`
}

// Family signals.
const (
	SignalSameCardinality = "same_cardinality"
	SignalWriteReadFollow = "write_read_follow"
	SignalSameOps         = "same_ops"
)

// subjectBucket is the bucket of a number of subjects below k.
func subjectBucket(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n <= 4:
		return "2-4"
	case n <= 9:
		return "5-9"
	}
	return "10+"
}
