package pack

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Manifest is manifest.json (tt.pack/v1).
type Manifest struct {
	Format    string `json:"format"`
	PackID    string `json:"pack_id"`
	CreatedAt string `json:"created_at"`
	NotAfter  string `json:"not_after,omitempty"`
	TTVersion string `json:"tt_version"`
	Seed      uint64 `json:"seed"`
	KMin      int    `json:"k_min"`
	Source    struct {
		Window struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"window"`
		Policies []struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
		} `json:"policies"`
	} `json:"source"`
	Services []ManifestService `json:"services"`
	Rules    struct {
		Path     string   `json:"path"`
		Approved []string `json:"approved"`
	} `json:"rules"`
	World struct {
		Path      string `json:"path"`
		Customers int    `json:"customers"`
	} `json:"world"`
	Faults     string         `json:"faults"`
	GateReport string         `json:"gate_report"`
	Files      []ManifestFile `json:"files"`
	Scenarios  string         `json:"scenarios,omitempty"`
	// Group is the group (team) the pack was built for (pack.md 2, v1.5):
	// absent for packs of every group and multi-group packs. A mock in
	// console mode refuses a pack of another group.
	Group string `json:"group,omitempty"`
}

// ManifestService is one service entry.
type ManifestService struct {
	Name          string `json:"name"`
	Contract      string `json:"contract"`
	UpstreamAlias string `json:"upstream_alias,omitempty"`
}

// ManifestFile is one entry of manifest.files.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Signature is manifest.sig.json (tt.pack.sig/v1).
type Signature struct {
	Format         string `json:"format"`
	Alg            string `json:"alg"`
	KID            string `json:"kid"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Sig            string `json:"sig"`
}

// Pack is a loaded and fully verified twin pack.
type Pack struct {
	Manifest  Manifest
	Signature Signature
	// CreatedAt is Manifest.CreatedAt parsed.
	CreatedAt time.Time
	// NotAfter is Manifest.NotAfter parsed (zero when the pack does not expire).
	NotAfter time.Time
	// Contracts maps a service name to its decoded OpenAPI document. Numbers
	// are json.Number.
	Contracts  map[string]map[string]any
	Rules      *Rules
	World      *World
	Faults     *Faults
	GateReport *GateReport
	// Scenarios is scenarios.json (nil when the pack has none).
	Scenarios *Scenarios
	// Files holds the raw bytes of every file listed in the manifest, after
	// signature and hash verification, keyed by pack-relative path.
	Files map[string][]byte
}

// ---- rules (tt.rules/v1) ----

// Ref points at a place of an exchange: {from, path} for bodies, {from, name}
// (+ optional field) for the rest.
type Ref struct {
	From  string `json:"from"`
	Path  string `json:"path,omitempty"`
	Name  string `json:"name,omitempty"`
	Field string `json:"field,omitempty"`
	// Owner (selectors of read_by only): the parameter is compared with the
	// owner customer of the entities instead of their id or a field.
	Owner bool `json:"owner,omitempty"`
}

// NameRef names a request parameter (list pagination).
type NameRef struct {
	From string `json:"from"`
	Name string `json:"name"`
}

// ListShape is the envelope and pagination of a list read.
type ListShape struct {
	Count        string   `json:"count,omitempty"`
	Total        string   `json:"total,omitempty"`
	Limit        *NameRef `json:"limit,omitempty"`
	Offset       *NameRef `json:"offset,omitempty"`
	Page         *NameRef `json:"page,omitempty"`
	Cursor       *NameRef `json:"cursor,omitempty"`
	NextCursor   string   `json:"next_cursor,omitempty"`
	DefaultLimit int      `json:"default_limit,omitempty"`
	MaxLimit     int      `json:"max_limit,omitempty"`
	OrderBy      string   `json:"order_by,omitempty"`
	Order        string   `json:"order,omitempty"`
	// Filters (rules v1.9) keep the items whose field equals the value of a
	// request parameter, when the request carries it.
	Filters []ListFilter `json:"filters,omitempty"`
}

// Relation declares that a field holds the id of another entity.
type Relation struct {
	Field  string `json:"field"`
	Entity string `json:"entity"`
	Many   bool   `json:"many,omitempty"`
}

// CreatedBy describes how an entity is created by a service operation.
type CreatedBy struct {
	Op       string         `json:"op"`
	ID       Ref            `json:"id"`
	State    *Ref           `json:"state,omitempty"`
	Defaults map[string]any `json:"defaults,omitempty"`
}

// ReadBy describes an operation that exposes an entity.
type ReadBy struct {
	Op string `json:"op"`
	// Service exposes the operation; empty = the service of the entity.
	Service string `json:"service,omitempty"`
	// By is nil for lists of the session customer's entities.
	By              *Ref           `json:"by,omitempty"`
	At              Ref            `json:"at"`
	HiddenWhen      map[string]any `json:"hidden_when,omitempty"`
	Scope           string         `json:"scope,omitempty"`
	Foreign         string         `json:"foreign,omitempty"`
	ForeignExample  string         `json:"foreign_example,omitempty"`
	NotFoundExample string         `json:"not_found_example,omitempty"`
	List            *ListShape     `json:"list,omitempty"`
	// Key selects the record of a keyed entity (rules v1.6): key field →
	// request parameter.
	Key map[string]Ref `json:"key,omitempty"`
	// RemovedStatus answers a single read of an entity removed in the
	// session (rules v1.6; 0: as one that does not exist).
	RemovedStatus int `json:"removed_status,omitempty"`
}

// Seed (rules v1.6) is how many objects of an entity each customer has
// before any session, and the shares of some of their clear values.
type Seed struct {
	PerCustomer []SeedBucket                  `json:"per_customer"`
	Values      map[string]map[string]float64 `json:"values,omitempty"`
	Subjects    int                           `json:"subjects"`
}

// SeedBucket is one bucket of a seed: N is "0", "3", "2-5" or "11+".
type SeedBucket struct {
	N     string  `json:"n"`
	Share float64 `json:"share"`
}

// Range returns the bounds of the bucket (hi = -1 for "11+").
func (b SeedBucket) Range() (lo, hi int, ok bool) {
	if !seedBucketRE.MatchString(b.N) {
		return 0, 0, false
	}
	if strings.HasSuffix(b.N, "+") {
		n, _ := strconv.Atoi(strings.TrimSuffix(b.N, "+"))
		return n, -1, true
	}
	a, z, isRange := strings.Cut(b.N, "-")
	lo, _ = strconv.Atoi(a)
	if !isRange {
		return lo, lo, true
	}
	hi, _ = strconv.Atoi(z)
	return lo, hi, hi > lo
}

// StateKey identifies the records of a keyed entity (rules v1.6): the owner
// and/or the values of Fields.
type StateKey struct {
	Owner  bool     `json:"owner,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// UpsertedBy is a write that creates or replaces the record of a keyed
// entity with the key it carries.
type UpsertedBy struct {
	Op      string         `json:"op"`
	Service string         `json:"service,omitempty"`
	Key     map[string]Ref `json:"key,omitempty"`
	State   *Ref           `json:"state,omitempty"`
}

// Entity is a rules entity.
type Entity struct {
	Name      string     `json:"name"`
	Service   string     `json:"service"`
	IDDomain  string     `json:"id_domain"`
	IDField   string     `json:"id_field"`
	IDPrefix  string     `json:"id_prefix"`
	CreatedBy *CreatedBy `json:"created_by,omitempty"`
	// Seed, Key and UpsertedBy: rules v1.6 (pre-existing objects per
	// customer, keyed records without an id).
	Seed       *Seed        `json:"seed,omitempty"`
	Key        *StateKey    `json:"key,omitempty"`
	UpsertedBy []UpsertedBy `json:"upserted_by,omitempty"`
	Relations  []Relation   `json:"relations,omitempty"`
	ReadBy     []ReadBy     `json:"read_by,omitempty"`
}

// Cause is the trigger of a causal rule.
type Cause struct {
	Service string `json:"service"`
	Op      string `json:"op"`
	When    struct {
		Status []int `json:"status"`
		// Match (rules v1.9): conditions on the request and on the
		// customer, all of which must hold for the rule to fire.
		Match []Match `json:"match,omitempty"`
	} `json:"when"`
	Bind map[string]Ref `json:"bind,omitempty"`
}

// Delay is the figurative delay of an effect: one duration (Min == Max,
// Range false) or a range from which the mock draws a whole number of seconds.
type Delay struct {
	Min, Max time.Duration
	Range    bool
}

// UnmarshalJSON accepts "5m" or {"min":"2m","max":"10m"}.
func (d *Delay) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Delay{Min: v, Max: v}
		return nil
	}
	var r struct {
		Min *string `json:"min"`
		Max *string `json:"max"`
	}
	dec := newDecoder(b)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("after must be a duration or {min, max}: %v", err)
	}
	if r.Min == nil || r.Max == nil {
		return fmt.Errorf("after range needs min and max")
	}
	lo, err := ParseDuration(*r.Min)
	if err != nil {
		return err
	}
	hi, err := ParseDuration(*r.Max)
	if err != nil {
		return err
	}
	if lo > hi {
		return fmt.Errorf("after range has min > max")
	}
	*d = Delay{Min: lo, Max: hi, Range: true}
	return nil
}

// Effect is one scheduled consequence.
type Effect struct {
	ID     string         `json:"id"`
	Entity string         `json:"entity"`
	Create map[string]any `json:"create,omitempty"`
	// Target is an earlier effect of the rule whose entity is updated.
	Target string `json:"target,omitempty"`
	// TargetID is "${var}": update the existing entity whose id is the variable.
	TargetID string         `json:"target_id,omitempty"`
	Set      map[string]any `json:"set,omitempty"`
	// Respond (rules v1.4) changes the answers of a later call instead of an
	// entity: the effect has no entity.
	Respond *Respond `json:"respond,omitempty"`
	// Remove (rules v1.6) removes the target entity.
	Remove bool `json:"remove,omitempty"`
	// Where (rules v1.7) guards a target or target_id effect: it applies
	// only while the entity's fields equal these literal values.
	Where map[string]any `json:"where,omitempty"`
	// TargetKey (rules v1.8) targets the record of a keyed entity: the key
	// field values ("${var}" or literals), empty for the customer's
	// singleton.
	TargetKey *map[string]string `json:"target_key,omitempty"`
	// TargetAll (rules v1.9) targets every entity of Entity owned by the
	// customer of the cause that matches Where.
	TargetAll   bool   `json:"target_all,omitempty"`
	AfterEffect string `json:"after_effect,omitempty"`
	After       Delay  `json:"after"`
}

// Respond is a response effect (docs/spec/rules.md section 3.6): from the
// instant it applies, the calls of the session to Service/Op answer Status
// (the contract example Example, else the first of that status) with
// probability P each, for at most Times calls (0: no limit).
type Respond struct {
	Service string  `json:"service"`
	Op      string  `json:"op"`
	Status  int     `json:"status"`
	P       float64 `json:"p,omitempty"`
	Times   int     `json:"times,omitempty"`
	Example string  `json:"example,omitempty"`
	// Body is an example error body written by a person (rules 1.10): it
	// wins over Example and the contract.
	Body any `json:"body,omitempty"`
	// Limit (rules v1.8) makes the effect a counter per key: a call answers
	// Status when N counted calls with its key fall within Window.
	Limit *Limit `json:"limit,omitempty"`
	// Until (rules v1.9, a precondition): from the start of the session the
	// calls answer Status until the effect applies.
	Until bool `json:"until,omitempty"`
}

// Limit is the counter of a response effect (docs/spec/rules.md 3.9).
type Limit struct {
	N      int    `json:"n"`
	Window string `json:"window,omitempty"`
	Key    string `json:"key,omitempty"`
}

// Prob is P with its default (1).
func (r *Respond) Prob() float64 {
	if r.P == 0 {
		return 1
	}
	return r.P
}

// Outcome is one alternative branch of a causal rule.
type Outcome struct {
	Name    string   `json:"name"`
	P       float64  `json:"p"`
	Effects []string `json:"effects"`
	// When (rules v1.9): the outcome is eligible only when all its
	// conditions hold (docs/spec/rules.md 3.12).
	When []Match `json:"when,omitempty"`
}

// CausalRule is a cause -> effects rule.
type CausalRule struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Cause    Cause     `json:"cause"`
	Effects  []Effect  `json:"effects"`
	Outcomes []Outcome `json:"outcomes"`
}

// BatchRule is a scheduled spontaneous change.
type BatchRule struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Schedule string         `json:"schedule"`
	Entity   string         `json:"entity"`
	Where    map[string]any `json:"where,omitempty"`
	Set      map[string]any `json:"set"`
	Fraction float64        `json:"fraction"`
}

// Rules is rules.json restricted to approved rules (in file order).
type Rules struct {
	Format   string
	Entities []Entity
	Causal   []CausalRule
	Batch    []BatchRule
	// Order lists the rule ids in file order.
	Order []string
	// Attributes, Aggregates and Lists: rules v1.9 (docs/spec/rules.md
	// 2.11-2.13).
	Attributes []Attribute
	Aggregates []Aggregate
	Lists      []ListOp
}

// ---- world (tt.world/v1) ----

// Customer is a synthetic customer.
type Customer struct {
	ID        string         `json:"id"`
	Archetype *string        `json:"archetype"`
	Profile   map[string]any `json:"profile"`
}

// WorldEntity is an entity at t0.
type WorldEntity struct {
	Entity     string         `json:"entity"`
	ID         string         `json:"id"`
	CustomerID *string        `json:"customer_id"`
	State      map[string]any `json:"state"`
}

// WorldHistory is one past state change of an entity (before t0).
type WorldHistory struct {
	Entity   string         `json:"entity"`
	ID       string         `json:"id"`
	At       string         `json:"at"`
	Seq      int            `json:"seq"`
	RuleID   string         `json:"rule_id,omitempty"`
	Outcome  string         `json:"outcome,omitempty"`
	EffectID string         `json:"effect_id,omitempty"`
	State    map[string]any `json:"state"`
}

// WorldPending is an effect of a rule firing that started before t0 and is
// still due after it.
type WorldPending struct {
	DueOffsetS int64             `json:"due_offset_s"`
	Seq        int               `json:"seq"`
	RuleID     string            `json:"rule_id"`
	Outcome    string            `json:"outcome"`
	EffectID   string            `json:"effect_id"`
	Entity     string            `json:"entity"`
	ID         string            `json:"id"`
	CustomerID *string           `json:"customer_id"`
	Vars       map[string]any    `json:"vars,omitempty"`
	EffectIDs  map[string]string `json:"effect_ids,omitempty"`
}

// World is world.jsonl.
type World struct {
	Seed      uint64
	T0        time.Time
	Customers []Customer
	Entities  []WorldEntity
	History   []WorldHistory
	Pending   []WorldPending
}

// ---- faults (tt.faults/v1) ----

// FaultStatus is an observed error status.
type FaultStatus struct {
	Status  int     `json:"status"`
	P       float64 `json:"p"`
	Example string  `json:"example,omitempty"`
}

// FaultNetError is an observed network failure.
type FaultNetError struct {
	Kind string  `json:"kind"`
	P    float64 `json:"p"`
}

// Latency is an observed latency distribution.
type Latency struct {
	P50       *int `json:"p50,omitempty"`
	P95       *int `json:"p95,omitempty"`
	P99       *int `json:"p99,omitempty"`
	Lognormal *struct {
		Median float64 `json:"median"`
		Sigma  float64 `json:"sigma"`
	} `json:"lognormal,omitempty"`
}

// FaultOp holds the observed faults of one operation.
type FaultOp struct {
	Service   string          `json:"service"`
	Op        string          `json:"op"`
	Statuses  []FaultStatus   `json:"statuses,omitempty"`
	NetErrors []FaultNetError `json:"net_errors,omitempty"`
	Latency   *Latency        `json:"latency_ms,omitempty"`
}

// Faults is faults.json.
type Faults struct {
	Format string    `json:"format"`
	Ops    []FaultOp `json:"ops"`
}

// GateReport is gate-report.json.
type GateReport struct {
	Format  string `json:"format"`
	PackID  string `json:"pack_id"`
	Verdict string `json:"verdict"`
	KMin    int    `json:"k_min"`
	Checks  []struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Findings []struct {
			File    string `json:"file"`
			Pointer string `json:"pointer"`
			Reason  string `json:"reason"`
		} `json:"findings"`
		StringsChecked *int   `json:"strings_checked,omitempty"`
		By             string `json:"by,omitempty"`
	} `json:"checks"`
}

// ---- scenarios (tt.scenarios/v1) ----

// SessionFaultRule is one rule of a preset's faults.
type SessionFaultRule struct {
	Service   string  `json:"service"`
	Op        string  `json:"op"`
	Status    int     `json:"status,omitempty"`
	NetError  string  `json:"net_error,omitempty"`
	LatencyMs *int    `json:"latency_ms,omitempty"`
	P         float64 `json:"p"`
	Times     *int    `json:"times,omitempty"`
	// Example (a named example of the contract) and Body (typed by a
	// person) give the body of a status fault (mock 1.12, 4.1).
	Example string `json:"example,omitempty"`
	Body    any    `json:"body,omitempty"`
}

// SessionFaults has the shape of the control API Faults object.
type SessionFaults struct {
	Mode  string             `json:"mode"`
	Rules []SessionFaultRule `json:"rules,omitempty"`
}

// ScenarioOutcome forces the outcome of a rule.
type ScenarioOutcome struct {
	Rule    string `json:"rule"`
	Outcome string `json:"outcome"`
	Times   *int   `json:"times,omitempty"`
}

// Scenario is one preset.
type Scenario struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Customer    string            `json:"customer,omitempty"`
	Archetype   string            `json:"archetype,omitempty"`
	Seed        *uint64           `json:"seed,omitempty"`
	Faults      *SessionFaults    `json:"faults,omitempty"`
	Outcomes    []ScenarioOutcome `json:"outcomes,omitempty"`
}

// Scenarios is scenarios.json.
type Scenarios struct {
	Format    string     `json:"format"`
	Scenarios []Scenario `json:"scenarios"`
}
