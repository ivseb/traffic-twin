package miner

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/derive"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// Format is the rules document format (docs/spec/rules.md).
const Format = "tt.rules/v1"

// Rule statuses (docs/spec/rules.md section 5).
const (
	StatusDraft    = "draft"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusStale    = "stale"
	// StatusSuperseded: an approved rule replaced by a newer approved one
	// (same signature family or `supersedes`); it keeps its history, leaves
	// the active set and never enters a pack.
	StatusSuperseded = "superseded"
)

// Reasons stored in stale_reason for rules that left the active set on
// purpose.
const (
	ReasonSupersededPrefix = "superseded_by:"
	ReasonRetired          = "retired"
)

// Rule kinds.
const (
	KindCausal = "causal"
	KindBatch  = "batch"
)

// Rule origins (rules v1.4): who wrote the rule. Absent means mined.
const (
	OriginMined  = "mined"
	OriginManual = "manual"
)

// Magnitude hints (evidence.hints.magnitude).
const (
	MagSeconds = "seconds"
	MagMinutes = "minutes"
	MagHours   = "hours"
	MagDays    = "days"
)

// Document is a tt.rules/v1 document.
type Document struct {
	Format      string   `json:"format"`
	GeneratedAt string   `json:"generated_at,omitempty"`
	Window      *Window  `json:"window,omitempty"`
	Entities    []Entity `json:"entities"`
	Rules       []Rule   `json:"rules"`
	// Attributes, Aggregates and Lists (rules v1.9): customer attributes
	// carried by responses, numbers computed from the collections at read
	// time, list operations no entity reads. Like the entities they describe
	// the reads and come with the latest run.
	Attributes []Attribute `json:"attributes,omitempty"`
	Aggregates []Aggregate `json:"aggregates,omitempty"`
	Lists      []ListOp    `json:"lists,omitempty"`
}

// Window is the event-time window a document was mined from.
type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Ref points into an event: {from, path} for bodies, {from, name} for the
// other parts. Field and Owner are only used by read_by selectors.
type Ref struct {
	From  string `json:"from"`
	Path  string `json:"path,omitempty"`
	Name  string `json:"name,omitempty"`
	Field string `json:"field,omitempty"`
	Owner bool   `json:"owner,omitempty"`
}

// String renders a ref for logs and signatures ("resp.body$.id", "req.path:id").
func (r Ref) String() string {
	if r.Path != "" {
		return r.From + r.Path
	}
	return r.From + ":" + r.Name
}

// Entity is a business object with a stable identity (rules.md section 2).
type Entity struct {
	Name      string     `json:"name"`
	Service   string     `json:"service"`
	IDDomain  string     `json:"id_domain"`
	IDField   string     `json:"id_field"`
	IDPrefix  string     `json:"id_prefix"`
	CreatedBy *CreatedBy `json:"created_by,omitempty"`
	// Seed (rules v1.6): objects that exist before any session, per
	// customer (an entity no write creates, read by its owner).
	Seed *Seed `json:"seed,omitempty"`
	// Key (rules v1.6): the record has no id of its own; it is identified
	// by its owner and/or the values of some of its fields, and the writes
	// of UpsertedBy replace its state.
	Key        *StateKey    `json:"key,omitempty"`
	UpsertedBy []UpsertedBy `json:"upserted_by,omitempty"`
	Relations  []Relation   `json:"relations,omitempty"`
	ReadBy     []ReadBy     `json:"read_by,omitempty"`
}

// Seed tells how many objects of an entity each customer has before any
// session (rules.md 2.8): a distribution over buckets of counts, learned
// from the objects each subject read, with every bucket seen for at least
// k_min subjects; Values optionally gives the shares of the clear values of
// some fields (each value seen for at least k_min subjects).
type Seed struct {
	PerCustomer []SeedBucket                  `json:"per_customer"`
	Values      map[string]map[string]float64 `json:"values,omitempty"`
	// Subjects is the exact number of subjects the distribution counts.
	Subjects int `json:"subjects"`
}

// SeedBucket is one bucket of a seed distribution: N is "0", "3", "2-5" or
// "11+", Share its probability.
type SeedBucket struct {
	N     string  `json:"n"`
	Share float64 `json:"share"`
}

// StateKey identifies the records of a keyed entity (rules.md 2.9): its
// owner (the session customer) and/or the values of Fields.
type StateKey struct {
	Owner  bool     `json:"owner,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// UpsertedBy is a write that creates or replaces the record of a keyed
// entity with the key read from the request.
type UpsertedBy struct {
	Op      string         `json:"op"`
	Service string         `json:"service,omitempty"`
	Key     map[string]Ref `json:"key,omitempty"`
	State   *Ref           `json:"state,omitempty"`
}

// CreatedBy names the operation that creates an entity.
type CreatedBy struct {
	Op       string         `json:"op"`
	ID       Ref            `json:"id"`
	State    *Ref           `json:"state,omitempty"`
	Defaults map[string]any `json:"defaults,omitempty"`
}

// Relation is a foreign key of an entity (rules.md section 2.2).
type Relation struct {
	Field  string `json:"field"`
	Entity string `json:"entity"`
	Many   bool   `json:"many,omitempty"`
}

// ReadBy describes an operation that exposes an entity.
type ReadBy struct {
	Op         string         `json:"op"`
	Service    string         `json:"service,omitempty"`
	By         *Ref           `json:"by,omitempty"`
	At         Ref            `json:"at"`
	HiddenWhen map[string]any `json:"hidden_when,omitempty"`
	Scope      string         `json:"scope,omitempty"`
	Foreign    string         `json:"foreign,omitempty"`
	// ForeignExample and NotFoundExample name contract examples; the miner
	// does not set them (contract inference owns examples), the reviewer may.
	ForeignExample  string     `json:"foreign_example,omitempty"`
	NotFoundExample string     `json:"not_found_example,omitempty"`
	List            *ListShape `json:"list,omitempty"`
	// Key selects the record of a keyed entity (rules v1.6): its field →
	// the request parameter holding its value.
	Key map[string]Ref `json:"key,omitempty"`
	// RemovedStatus is the status of a by-id read of an entity removed in
	// the session (rules v1.6; 0: as one that does not exist).
	RemovedStatus int `json:"removed_status,omitempty"`
}

// ListShape is the envelope of a list read (rules.md section 2.3). The
// miner only fills Count; the other members are kept for round trips.
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

// NameRef names a request parameter (list pagination).
type NameRef struct {
	From string `json:"from"`
	Name string `json:"name"`
}

// Rule is a causal or a batch rule. Exactly one of Causal and Batch is set;
// the JSON form is the flat rules.v1 object.
type Rule struct {
	Causal *CausalRule
	Batch  *BatchRule
}

// ID returns the rule id.
func (r *Rule) ID() string {
	if r.Causal != nil {
		return r.Causal.ID
	}
	if r.Batch != nil {
		return r.Batch.ID
	}
	return ""
}

// Kind returns causal or batch.
func (r *Rule) Kind() string {
	if r.Causal != nil {
		return KindCausal
	}
	return KindBatch
}

// Status returns the rule status.
func (r *Rule) Status() string {
	if r.Causal != nil {
		return r.Causal.Status
	}
	if r.Batch != nil {
		return r.Batch.Status
	}
	return ""
}

// Origin returns the origin of the rule (mined when absent).
func (r *Rule) Origin() string {
	o := ""
	if r.Causal != nil {
		o = r.Causal.Origin
	} else if r.Batch != nil {
		o = r.Batch.Origin
	}
	if o == "" {
		return OriginMined
	}
	return o
}

func validOrigin(o string) bool { return o == "" || o == OriginMined || o == OriginManual }

func (r *Rule) common() (id, status, title, supersedes *string, review **Review) {
	if r.Causal != nil {
		c := r.Causal
		return &c.ID, &c.Status, &c.Title, &c.Supersedes, &c.Review
	}
	b := r.Batch
	return &b.ID, &b.Status, &b.Title, &b.Supersedes, &b.Review
}

// MarshalJSON writes the flat rules.v1 object.
func (r Rule) MarshalJSON() ([]byte, error) {
	switch {
	case r.Causal != nil:
		return json.Marshal(r.Causal)
	case r.Batch != nil:
		return json.Marshal(r.Batch)
	}
	return nil, errors.New("miner: empty rule")
}

// UnmarshalJSON reads a flat rules.v1 object (strict).
func (r *Rule) UnmarshalJSON(b []byte) error {
	var k struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return err
	}
	switch k.Kind {
	case KindCausal:
		var c CausalRule
		if err := decodeStrict(b, &c); err != nil {
			return err
		}
		*r = Rule{Causal: &c}
	case KindBatch:
		var c BatchRule
		if err := decodeStrict(b, &c); err != nil {
			return err
		}
		*r = Rule{Batch: &c}
	default:
		return errors.New("miner: unknown rule kind")
	}
	return nil
}

func decodeStrict(b []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(dst)
}

// CausalRule is a cause → effects rule (rules.md section 3).
type CausalRule struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Status     string         `json:"status"`
	Title      string         `json:"title"`
	Origin     string         `json:"origin,omitempty"`
	Supersedes string         `json:"supersedes,omitempty"`
	Cause      Cause          `json:"cause"`
	Effects    []Effect       `json:"effects"`
	Outcomes   []Outcome      `json:"outcomes"`
	Evidence   CausalEvidence `json:"evidence"`
	Review     *Review        `json:"review,omitempty"`
}

// Cause is the trigger of a causal rule.
type Cause struct {
	Service string         `json:"service"`
	Op      string         `json:"op"`
	When    When           `json:"when"`
	Bind    map[string]Ref `json:"bind,omitempty"`
}

// When lists the response statuses that fire the rule and (rules v1.9)
// the conditions on the request and on the customer that must all hold.
type When struct {
	Status []int   `json:"status"`
	Match  []Match `json:"match,omitempty"`
}

// Effect is one consequence of a cause: an entity is created or changed,
// or (Respond, rules v1.4) the answers of a later call change.
type Effect struct {
	ID       string         `json:"id"`
	Entity   string         `json:"entity,omitempty"`
	Create   map[string]any `json:"create,omitempty"`
	Target   string         `json:"target,omitempty"`
	TargetID string         `json:"target_id,omitempty"`
	Set      map[string]any `json:"set,omitempty"`
	Respond  *Respond       `json:"respond,omitempty"`
	// Remove (rules v1.6) deletes the target entity: it leaves the lists
	// and its by-id reads answer as removed.
	Remove bool `json:"remove,omitempty"`
	// Where (rules v1.7) is a guard of a target or target_id effect: it
	// applies only while the entity's fields equal these literal values (a
	// spontaneous step of a lifecycle does not undo the state a write set).
	Where map[string]any `json:"where,omitempty"`
	// TargetKey (rules v1.8) targets the record of a keyed entity (§2.9):
	// the session customer's record (when the key has the owner) whose key
	// fields take these values ("${var}" or a literal); empty for the
	// singleton of the customer. With set the record is created when
	// missing.
	TargetKey *KeyTarget `json:"target_key,omitempty"`
	// TargetAll (rules v1.9) targets every entity of Entity owned by the
	// customer of the cause that matches Where (mark all read).
	TargetAll   bool   `json:"target_all,omitempty"`
	AfterEffect string `json:"after_effect,omitempty"`
	After       Delay  `json:"after"`
}

// KeyTarget gives the values of the key fields of a keyed record.
type KeyTarget map[string]string

// Respond is a response effect (rules.md section 3.6): from the instant the
// effect applies, the calls of the session to Service/Op answer Status
// with probability P each (default 1), for at most Times calls (0: no
// limit), with the contract example Example (default: the first of that
// status).
type Respond struct {
	Service string  `json:"service"`
	Op      string  `json:"op"`
	Status  int     `json:"status"`
	P       float64 `json:"p,omitempty"`
	Times   int     `json:"times,omitempty"`
	Example string  `json:"example,omitempty"`
	// Body is an example error body typed by a person (rules 1.10).
	Body any `json:"body,omitempty"`
	// Limit (rules v1.8, uniqueness and counters per key) turns the effect
	// into a counter: every application counts one call for its key, and a
	// call of Service/Op answers Status when at least N counted calls with
	// the same key fall within Window before it.
	Limit *Limit `json:"limit,omitempty"`
	// Until (rules v1.9, preconditions) inverts the effect: from the start
	// of the session the calls answer Status until the effect applies.
	Until bool `json:"until,omitempty"`
}

// Limit is the counter of a response effect (rules.md 3.9): N counted
// calls within Window (a duration; empty: the whole session) per Key (a
// "${var}" bound to the request of the cause; empty: per customer).
type Limit struct {
	N      int    `json:"n"`
	Window string `json:"window,omitempty"`
	Key    string `json:"key,omitempty"`
}

// Delay is a figurative delay: a duration or a {min, max} range.
type Delay struct {
	Single   string
	Min, Max string
}

// IsRange reports whether d is a {min, max} range.
func (d Delay) IsRange() bool { return d.Single == "" }

// MarshalJSON writes a string or a {min, max} object.
func (d Delay) MarshalJSON() ([]byte, error) {
	if d.Single != "" {
		return json.Marshal(d.Single)
	}
	return json.Marshal(struct {
		Min string `json:"min"`
		Max string `json:"max"`
	}{d.Min, d.Max})
}

// UnmarshalJSON reads a string or a {min, max} object.
func (d *Delay) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*d = Delay{Single: s}
		return nil
	}
	var r struct {
		Min string `json:"min"`
		Max string `json:"max"`
	}
	if err := decodeStrict(b, &r); err != nil {
		return err
	}
	*d = Delay{Min: r.Min, Max: r.Max}
	return nil
}

// Outcome is one alternative branch.
type Outcome struct {
	Name    string   `json:"name"`
	P       float64  `json:"p"`
	Effects []string `json:"effects"`
	// When (rules v1.9) makes the outcome conditional: it is eligible only
	// when all its conditions hold (see rules.md 3.12).
	When []Match `json:"when,omitempty"`
}

// CausalEvidence holds exact counts, link keys and hints.
type CausalEvidence struct {
	Counts CausalCounts `json:"counts"`
	Keys   []KeyRef     `json:"keys,omitempty"`
	Hints  *CausalHints `json:"hints,omitempty"`
}

// CausalCounts are exact counts over the window.
type CausalCounts struct {
	Causes           int            `json:"causes"`
	DistinctSubjects int            `json:"distinct_subjects"`
	Outcomes         map[string]int `json:"outcomes"`
	KeyMatches       *int           `json:"key_matches,omitempty"`
}

// CausalHints are estimates, only used to propose values.
type CausalHints struct {
	Magnitude map[string]string `json:"magnitude,omitempty"`
}

// KeyRef is a link key reported in evidence.keys (rules.md section 3.4).
type KeyRef struct {
	Domain  string `json:"domain"`
	From    KeyEnd `json:"from"`
	To      KeyEnd `json:"to"`
	Matches int    `json:"matches"`
}

// KeyEnd is one end of a link key.
type KeyEnd struct {
	Service string `json:"service"`
	Op      string `json:"op"`
	At      Ref    `json:"at"`
}

// BatchRule is a scheduled spontaneous change (rules.md section 4).
type BatchRule struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Status     string         `json:"status"`
	Title      string         `json:"title"`
	Origin     string         `json:"origin,omitempty"`
	Supersedes string         `json:"supersedes,omitempty"`
	Schedule   string         `json:"schedule"`
	Entity     string         `json:"entity"`
	Where      map[string]any `json:"where,omitempty"`
	Set        map[string]any `json:"set"`
	Fraction   float64        `json:"fraction"`
	Evidence   BatchEvidence  `json:"evidence"`
	Review     *Review        `json:"review,omitempty"`
}

// BatchEvidence holds the counts of a batch rule.
type BatchEvidence struct {
	Counts BatchCounts `json:"counts"`
	Hints  *BatchHints `json:"hints,omitempty"`
}

// BatchCounts are exact counts.
type BatchCounts struct {
	Runs            int `json:"runs"`
	EntitiesChanged int `json:"entities_changed"`
}

// BatchHints are estimates.
type BatchHints struct {
	ScheduleConfidence string `json:"schedule_confidence,omitempty"`
}

// Review records the human decision on a rule.
type Review struct {
	By   []string `json:"by"`
	At   *string  `json:"at"`
	Note string   `json:"note"`
}

// ---------------------------------------------------------------------------
// Validation: the patterns of schemas/rules.v1.schema.json plus the
// cross-field checks the schema leaves to tt-core (outcome probabilities sum
// to 1, referenced effects exist and belong to the same outcome, no cycles in
// after_effect, ${effect:...} only to earlier ancestors, relation targets
// exist).

var (
	reIdent     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	reRuleID    = regexp.MustCompile(`^r-[0-9]{4,}$`)
	reService   = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62}|host:[a-z0-9.-]{1,253}(:[0-9]{1,5})?|host:(\{\*\}|[a-z0-9-]{1,63})(\.(\{\*\}|[a-z0-9-]{1,63}))*(:[0-9]{1,5})?|host:ip:(private|public)(:[0-9]{1,5})?)$`)
	reOp        = regexp.MustCompile(`^[A-Z]{1,16} /[!-~]*$`)
	reDuration  = regexp.MustCompile(`^[0-9]{1,6}(s|m|h|d)$`)
	reTTPath    = regexp.MustCompile(`^\$(\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\])*$`)
	reName      = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
	reFieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	reFieldPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
	reDomain    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	rePrefix    = regexp.MustCompile(`^[A-Z]{2,5}-SYN-$`)
	reBindName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	reBindRef   = regexp.MustCompile(`^\$\{[a-z][a-z0-9_]{0,31}\}$`)
	reEffectRef = regexp.MustCompile(`^\$\{effect:([a-z][a-z0-9_-]{0,63})\}$`)
	reNotRef    = regexp.MustCompile(`^\$\{not:([A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7})\}$`)
	reCron      = regexp.MustCompile(`^[0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+$`)
	reExample   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("miner: invalid rules")

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

func validRef(r Ref, body bool) error {
	switch r.From {
	case "req.body", "resp.body":
		if !reTTPath.MatchString(r.Path) || r.Name != "" || r.Field != "" || r.Owner {
			return invalidf("bad body ref %s", r)
		}
	case "req.path", "req.query", "req.headers", "req.cookies", "resp.headers", "resp.cookies":
		if body || r.Path != "" || !reName.MatchString(r.Name) {
			return invalidf("bad ref %s", r)
		}
		if r.Field != "" && !reFieldName.MatchString(r.Field) {
			return invalidf("bad ref field %s", r)
		}
		if r.Owner && (r.Field != "" || strings.HasPrefix(r.From, "resp.")) {
			return invalidf("bad owner selector %s", r)
		}
	default:
		return invalidf("bad ref source %q", r.From)
	}
	return nil
}

func validValues(m map[string]any) error {
	if len(m) > 256 {
		return invalidf("too many field values")
	}
	for k, v := range m {
		if !reFieldPath.MatchString(k) {
			return invalidf("bad field path %q", k)
		}
		switch v.(type) {
		case nil, string, bool, float64, int, int64, json.Number:
		default:
			return invalidf("bad field value type for %q", k)
		}
	}
	return nil
}

// validRespond checks the shape of a response effect (the service and the
// operation are checked against the contracts by ValidateAgainst).
func validRespond(r *Respond) error {
	if !reService.MatchString(r.Service) || !reOp.MatchString(r.Op) {
		return invalidf("bad respond service or op")
	}
	if r.Status < 100 || r.Status > 599 {
		return invalidf("bad respond status")
	}
	if r.P < 0 || r.P > 1 || math.IsNaN(r.P) {
		return invalidf("bad respond p")
	}
	if r.Times < 0 || r.Times > 1000000 {
		return invalidf("bad respond times")
	}
	if r.Example != "" && !reExample.MatchString(r.Example) {
		return invalidf("bad respond example")
	}
	if r.Body != nil {
		if err := pack.ValidateErrorBody(r.Body); err != nil {
			return invalidf("bad respond body: %v", err)
		}
	}
	return nil
}

// validEffectValues checks create and set: scalars or derived values
// (rules 1.10, docs/spec/rules.md 3.15).
func validEffectValues(m map[string]any) error {
	plain := make(map[string]any, len(m))
	for k, v := range m {
		if derive.Is(v) {
			if !reFieldPath.MatchString(k) {
				return invalidf("bad field path %q", k)
			}
			if _, err := derive.Parse(v); err != nil {
				return invalidf("field %s: %v", k, err)
			}
			continue
		}
		plain[k] = v
	}
	if len(m) > 256 {
		return invalidf("too many field values")
	}
	return validValues(plain)
}

func validDelay(d Delay) error {
	if !d.IsRange() {
		if !reDuration.MatchString(d.Single) {
			return invalidf("bad duration %q", d.Single)
		}
		return nil
	}
	if !reDuration.MatchString(d.Min) || !reDuration.MatchString(d.Max) {
		return invalidf("bad delay range")
	}
	if parseDuration(d.Min) > parseDuration(d.Max) {
		return invalidf("delay min > max")
	}
	return nil
}

// parseDuration parses ^[0-9]{1,6}(s|m|h|d)$ into seconds (-1 if invalid).
func parseDuration(s string) int64 {
	if !reDuration.MatchString(s) {
		return -1
	}
	var n int64
	for _, c := range s[:len(s)-1] {
		n = n*10 + int64(c-'0')
	}
	switch s[len(s)-1] {
	case 'm':
		n *= 60
	case 'h':
		n *= 3600
	case 'd':
		n *= 86400
	}
	return n
}

// Validate checks a whole document.
func (d *Document) Validate() error {
	if d.Format != Format {
		return invalidf("format")
	}
	ents := map[string]*Entity{}
	for i := range d.Entities {
		e := &d.Entities[i]
		if err := e.validate(); err != nil {
			return err
		}
		if ents[e.Name] != nil {
			return invalidf("duplicate entity %q", e.Name)
		}
		ents[e.Name] = e
	}
	for _, e := range d.Entities {
		for _, rel := range e.Relations {
			if ents[rel.Entity] == nil {
				return invalidf("entity %q: relation to unknown entity %q", e.Name, rel.Entity)
			}
		}
	}
	if err := d.validateExtras(ents); err != nil {
		return err
	}
	attrs := map[string]bool{}
	for _, a := range d.Attributes {
		attrs[a.Name] = true
	}
	ids := map[string]bool{}
	for i := range d.Rules {
		r := &d.Rules[i]
		if err := r.Validate(ents); err != nil {
			return err
		}
		if err := r.validCustomerRefs(attrs); err != nil {
			return err
		}
		if ids[r.ID()] {
			return invalidf("duplicate rule id %q", r.ID())
		}
		ids[r.ID()] = true
	}
	return nil
}

func (e *Entity) validate() error {
	if !reIdent.MatchString(e.Name) || !reService.MatchString(e.Service) || !reDomain.MatchString(e.IDDomain) ||
		!reFieldName.MatchString(e.IDField) || !rePrefix.MatchString(e.IDPrefix) {
		return invalidf("entity %q: bad identity fields", e.Name)
	}
	if c := e.CreatedBy; c != nil {
		if !reOp.MatchString(c.Op) {
			return invalidf("entity %q: bad created_by.op", e.Name)
		}
		if err := validRef(c.ID, false); err != nil {
			return err
		}
		if c.State != nil && (c.State.From != "req.body" || !reTTPath.MatchString(c.State.Path)) {
			return invalidf("entity %q: bad created_by.state", e.Name)
		}
		if err := validValues(c.Defaults); err != nil {
			return err
		}
	}
	if err := e.validateState(); err != nil {
		return err
	}
	if len(e.Relations) > 32 {
		return invalidf("entity %q: too many relations", e.Name)
	}
	for _, r := range e.Relations {
		if !reFieldPath.MatchString(r.Field) || !reIdent.MatchString(r.Entity) {
			return invalidf("entity %q: bad relation", e.Name)
		}
	}
	for _, rb := range e.ReadBy {
		if !reOp.MatchString(rb.Op) || (rb.Service != "" && !reService.MatchString(rb.Service)) {
			return invalidf("entity %q: bad read_by", e.Name)
		}
		if err := validRef(rb.At, false); err != nil {
			return err
		}
		if rb.By != nil {
			if err := validSelector(*rb.By); err != nil {
				return err
			}
		}
		if len(rb.Key) > 0 {
			if e.Key == nil || rb.By != nil {
				return invalidf("entity %q: read_by.key needs a keyed entity and excludes by", e.Name)
			}
			if err := validKeyRefs(e.Key, rb.Key); err != nil {
				return invalidf("entity %q: read_by.key: %v", e.Name, err)
			}
		}
		if rb.RemovedStatus != 0 && (rb.RemovedStatus < 400 || rb.RemovedStatus > 599) {
			return invalidf("entity %q: bad removed_status", e.Name)
		}
		for k, v := range rb.HiddenWhen {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "${") {
				return invalidf("entity %q: hidden_when %q is a reference", e.Name, k)
			}
		}
		if err := validValues(rb.HiddenWhen); err != nil {
			return err
		}
		switch rb.Scope {
		case "", "any", "owner":
		default:
			return invalidf("entity %q: bad scope", e.Name)
		}
		switch rb.Foreign {
		case "", "not_found", "forbidden":
		default:
			return invalidf("entity %q: bad foreign", e.Name)
		}
		for _, ex := range []string{rb.ForeignExample, rb.NotFoundExample} {
			if ex != "" && !reExample.MatchString(ex) {
				return invalidf("entity %q: bad example name", e.Name)
			}
		}
		if l := rb.List; l != nil {
			for _, p := range []string{l.Count, l.Total, l.NextCursor} {
				if p != "" && !reTTPath.MatchString(p) {
					return invalidf("entity %q: bad list path", e.Name)
				}
			}
			if l.OrderBy != "" && !reFieldPath.MatchString(l.OrderBy) {
				return invalidf("entity %q: bad list.order_by", e.Name)
			}
			if err := validListFilters(l.Filters); err != nil {
				return invalidf("entity %q: %v", e.Name, err)
			}
		}
	}
	return nil
}

// Validate checks one rule against the known entities (nil skips the
// entity checks).
func (r *Rule) Validate(ents map[string]*Entity) error {
	switch {
	case r.Causal != nil && r.Batch == nil:
		return r.Causal.validate(ents)
	case r.Batch != nil && r.Causal == nil:
		return r.Batch.validate(ents)
	}
	return invalidf("rule must be causal or batch")
}

func validStatus(s string) bool {
	return s == StatusDraft || s == StatusApproved || s == StatusRejected || s == StatusStale || s == StatusSuperseded
}

func validReview(rv *Review) error {
	if rv == nil {
		return nil
	}
	if len(rv.Note) > 1000 {
		return invalidf("review note too long")
	}
	return nil
}

func (c *CausalRule) validate(ents map[string]*Entity) error {
	if !reRuleID.MatchString(c.ID) || c.Kind != KindCausal || !validStatus(c.Status) || len([]rune(c.Title)) > 200 || !validOrigin(c.Origin) {
		return invalidf("rule %q: bad header", c.ID)
	}
	if c.Supersedes != "" && !reRuleID.MatchString(c.Supersedes) {
		return invalidf("rule %q: bad supersedes", c.ID)
	}
	if !reService.MatchString(c.Cause.Service) || !reOp.MatchString(c.Cause.Op) || len(c.Cause.When.Status) == 0 {
		return invalidf("rule %q: bad cause", c.ID)
	}
	for _, s := range c.Cause.When.Status {
		if s < 100 || s > 599 {
			return invalidf("rule %q: bad cause status", c.ID)
		}
	}
	if c.Cause.When.Match != nil {
		if err := validMatches(c.Cause.When.Match, nil); err != nil {
			return invalidf("rule %q: cause.when.match: %v", c.ID, err)
		}
	}
	for k, ref := range c.Cause.Bind {
		if !reBindName.MatchString(k) {
			return invalidf("rule %q: bad bind name", c.ID)
		}
		if err := validRef(ref, false); err != nil {
			return err
		}
	}
	if len(c.Effects) == 0 || len(c.Outcomes) == 0 {
		return invalidf("rule %q: effects and outcomes are required", c.ID)
	}
	idx := map[string]int{}
	respond := map[string]bool{}
	all := map[string]bool{} // target_all effects (rules v1.9)
	for i, e := range c.Effects {
		if e.Respond != nil {
			if !reIdent.MatchString(e.ID) {
				return invalidf("rule %q: bad effect id", c.ID)
			}
			if _, dup := idx[e.ID]; dup {
				return invalidf("rule %q: duplicate effect %q", c.ID, e.ID)
			}
			idx[e.ID] = i
			respond[e.ID] = true
			if e.Entity != "" || e.Create != nil || e.Target != "" || e.TargetID != "" || e.Set != nil || e.Remove || e.Where != nil {
				return invalidf("rule %q: effect %q: respond excludes entity, create, target and set", c.ID, e.ID)
			}
			if err := validRespond(e.Respond); err != nil {
				return invalidf("rule %q: effect %q: %v", c.ID, e.ID, err)
			}
			if err := c.validLimit(e.Respond); err != nil {
				return invalidf("rule %q: effect %q: %v", c.ID, e.ID, err)
			}
			if e.Respond.Until && (e.Respond.Times != 0 || e.Respond.Limit != nil || e.Respond.P != 0) {
				return invalidf("rule %q: effect %q: until excludes times, limit and p", c.ID, e.ID)
			}
			if e.TargetKey != nil || e.TargetAll {
				return invalidf("rule %q: effect %q: respond excludes target_key", c.ID, e.ID)
			}
			if err := validDelay(e.After); err != nil {
				return err
			}
			continue
		}
		if !reIdent.MatchString(e.ID) || !reIdent.MatchString(e.Entity) {
			return invalidf("rule %q: bad effect id", c.ID)
		}
		if _, dup := idx[e.ID]; dup {
			return invalidf("rule %q: duplicate effect %q", c.ID, e.ID)
		}
		idx[e.ID] = i
		if ents != nil && ents[e.Entity] == nil {
			return invalidf("rule %q: effect %q on unknown entity", c.ID, e.ID)
		}
		if e.Where != nil {
			if e.Create != nil || e.Remove {
				return invalidf("rule %q: effect %q: where guards a target, target_id or target_key set", c.ID, e.ID)
			}
			if err := validValues(e.Where); err != nil {
				return err
			}
			for k, v := range e.Where {
				if s, ok := v.(string); ok && strings.HasPrefix(s, "${") {
					return invalidf("rule %q: effect %q: where %q is a reference", c.ID, e.ID, k)
				}
			}
		}
		if e.TargetAll {
			if err := validTargetAll(e); err != nil {
				return invalidf("rule %q: effect %q: %v", c.ID, e.ID, err)
			}
			if err := validValues(e.Set); err != nil {
				return err
			}
			if err := validDelay(e.After); err != nil {
				return err
			}
			all[e.ID] = true
			continue
		}
		if e.TargetKey != nil {
			if err := c.validTargetKey(e, ents); err != nil {
				return invalidf("rule %q: effect %q: %v", c.ID, e.ID, err)
			}
		}
		if e.Remove {
			// rules v1.6: remove takes a target and nothing else.
			targets := 0
			for _, has := range []bool{e.Target != "", e.TargetID != "", e.TargetKey != nil} {
				if has {
					targets++
				}
			}
			if e.Create != nil || e.Set != nil || targets != 1 {
				return invalidf("rule %q: effect %q: remove takes target, target_id or target_key and no create or set", c.ID, e.ID)
			}
			if e.TargetID != "" {
				if !reBindRef.MatchString(e.TargetID) {
					return invalidf("rule %q: bad target_id", c.ID)
				}
				if _, ok := c.Cause.Bind[e.TargetID[2:len(e.TargetID)-1]]; !ok {
					return invalidf("rule %q: target_id of unbound variable", c.ID)
				}
			}
			if err := validDelay(e.After); err != nil {
				return err
			}
			continue
		}
		n := 0
		if e.Create != nil {
			n++
		}
		if e.Target != "" {
			n++
		}
		if e.TargetID != "" {
			n++
		}
		if e.TargetKey != nil {
			n++
		}
		if n != 1 || (e.Create != nil) == (e.Set != nil) {
			return invalidf("rule %q: effect %q must be create, target+set, target_id+set or target_key+set", c.ID, e.ID)
		}
		if e.TargetID != "" {
			if !reBindRef.MatchString(e.TargetID) {
				return invalidf("rule %q: bad target_id", c.ID)
			}
			if _, ok := c.Cause.Bind[e.TargetID[2:len(e.TargetID)-1]]; !ok {
				return invalidf("rule %q: target_id of unbound variable", c.ID)
			}
		}
		if err := validEffectValues(e.Create); err != nil {
			return err
		}
		if err := validEffectValues(e.Set); err != nil {
			return err
		}
		if err := validDelay(e.After); err != nil {
			return err
		}
	}
	// References, ancestry and cycles.
	ancestors := func(id string) (map[string]bool, error) {
		seen := map[string]bool{}
		cur := c.Effects[idx[id]].AfterEffect
		for cur != "" {
			if seen[cur] || cur == id {
				return nil, invalidf("rule %q: after_effect cycle", c.ID)
			}
			j, ok := idx[cur]
			if !ok {
				return nil, invalidf("rule %q: unknown after_effect %q", c.ID, cur)
			}
			seen[cur] = true
			cur = c.Effects[j].AfterEffect
		}
		return seen, nil
	}
	deps := map[string][]string{}
	for i, e := range c.Effects {
		anc, err := ancestors(e.ID)
		if err != nil {
			return err
		}
		if e.Target != "" {
			if _, ok := idx[e.Target]; !ok || respond[e.Target] || all[e.Target] {
				return invalidf("rule %q: unknown target %q", c.ID, e.Target)
			}
			deps[e.ID] = append(deps[e.ID], e.Target)
		}
		if e.AfterEffect != "" {
			deps[e.ID] = append(deps[e.ID], e.AfterEffect)
		}
		for _, m := range []map[string]any{e.Create, e.Set} {
			// derived values (rules 1.10): bound variables, earlier ancestors
			dv, _ := derive.ParseValues(m)
			for _, x := range dv {
				refs := x.References()
				for _, name := range refs.Vars {
					if _, ok := c.Cause.Bind[name]; !ok {
						return invalidf("rule %q: derived value references an unbound variable", c.ID)
					}
				}
				for _, id := range refs.Effects {
					j, ok := idx[id]
					if !ok || j >= i || !anc[id] || respond[id] {
						return invalidf("rule %q: ${effect:%s} must name an earlier ancestor", c.ID, id)
					}
					deps[e.ID] = append(deps[e.ID], id)
				}
			}
			for _, v := range m {
				s, ok := v.(string)
				if !ok {
					continue
				}
				if sm := reEffectRef.FindStringSubmatch(s); sm != nil {
					j, ok := idx[sm[1]]
					if !ok || j >= i || !anc[sm[1]] || respond[sm[1]] || all[sm[1]] {
						return invalidf("rule %q: ${effect:%s} must name an earlier ancestor", c.ID, sm[1])
					}
					deps[e.ID] = append(deps[e.ID], sm[1])
				} else if reBindRef.MatchString(s) {
					if _, ok := c.Cause.Bind[s[2:len(s)-1]]; !ok {
						return invalidf("rule %q: reference to unbound variable", c.ID)
					}
				} else if strings.HasPrefix(s, "${not:") {
					// rules v1.7: the negation of a boolean of the target.
					if e.Create != nil || !reNotRef.MatchString(s) {
						return invalidf("rule %q: effect %q: ${not:field} is a set value of a field path", c.ID, e.ID)
					}
				}
			}
		}
	}
	sum := 0.0
	names := map[string]bool{}
	for _, o := range c.Outcomes {
		if !reIdent.MatchString(o.Name) || names[o.Name] || o.P < 0 || o.P > 1 || math.IsNaN(o.P) {
			return invalidf("rule %q: bad outcome %q", c.ID, o.Name)
		}
		names[o.Name] = true
		sum += o.P
		if o.When != nil {
			if err := validMatches(o.When, nil); err != nil {
				return invalidf("rule %q: outcome %q: when: %v", c.ID, o.Name, err)
			}
		}
		in := map[string]bool{}
		for _, e := range o.Effects {
			if _, ok := idx[e]; !ok {
				return invalidf("rule %q: outcome %q names unknown effect %q", c.ID, o.Name, e)
			}
			in[e] = true
		}
		for _, e := range o.Effects {
			for _, d := range deps[e] {
				if !in[d] {
					return invalidf("rule %q: outcome %q has %q without %q", c.ID, o.Name, e, d)
				}
			}
		}
	}
	if math.Abs(sum-1) > 0.001 {
		return invalidf("rule %q: outcome probabilities sum to %.4f", c.ID, sum)
	}
	ev := c.Evidence
	if ev.Counts.Causes < 0 || ev.Counts.DistinctSubjects < 0 || ev.Counts.Outcomes == nil {
		return invalidf("rule %q: bad evidence counts", c.ID)
	}
	if len(ev.Keys) > 64 {
		return invalidf("rule %q: too many keys", c.ID)
	}
	for _, k := range ev.Keys {
		if !reDomain.MatchString(k.Domain) || k.Matches < 0 {
			return invalidf("rule %q: bad key", c.ID)
		}
		for _, end := range []KeyEnd{k.From, k.To} {
			if !reService.MatchString(end.Service) || !reOp.MatchString(end.Op) {
				return invalidf("rule %q: bad key end", c.ID)
			}
			if err := validRef(end.At, false); err != nil {
				return err
			}
		}
	}
	if ev.Hints != nil {
		for _, m := range ev.Hints.Magnitude {
			switch m {
			case MagSeconds, MagMinutes, MagHours, MagDays:
			default:
				return invalidf("rule %q: bad magnitude", c.ID)
			}
		}
	}
	return validReview(c.Review)
}

func (b *BatchRule) validate(ents map[string]*Entity) error {
	if !reRuleID.MatchString(b.ID) || b.Kind != KindBatch || !validStatus(b.Status) || len([]rune(b.Title)) > 200 || !validOrigin(b.Origin) {
		return invalidf("rule %q: bad header", b.ID)
	}
	if b.Supersedes != "" && !reRuleID.MatchString(b.Supersedes) {
		return invalidf("rule %q: bad supersedes", b.ID)
	}
	if !reCron.MatchString(b.Schedule) || !reIdent.MatchString(b.Entity) {
		return invalidf("rule %q: bad schedule or entity", b.ID)
	}
	if ents != nil && ents[b.Entity] == nil {
		return invalidf("rule %q: unknown entity", b.ID)
	}
	if b.Set == nil || !(b.Fraction > 0 && b.Fraction <= 1) {
		return invalidf("rule %q: bad set or fraction", b.ID)
	}
	if err := validValues(b.Where); err != nil {
		return err
	}
	if err := validValues(b.Set); err != nil {
		return err
	}
	if b.Evidence.Counts.Runs < 0 || b.Evidence.Counts.EntitiesChanged < 0 {
		return invalidf("rule %q: bad evidence", b.ID)
	}
	if h := b.Evidence.Hints; h != nil {
		switch h.ScheduleConfidence {
		case "", "low", "medium", "high":
		default:
			return invalidf("rule %q: bad schedule_confidence", b.ID)
		}
	}
	return validReview(b.Review)
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validSelector checks a read_by selector: a request parameter, or (rules
// v1.6) a request body path, by id, by field or by owner.
func validSelector(r Ref) error {
	if r.From == "req.body" {
		if !reTTPath.MatchString(r.Path) || r.Path == "$" || strings.Contains(r.Path, "[*]") || strings.Contains(r.Path, ".*") || r.Name != "" {
			return invalidf("bad body selector %s", r)
		}
		if r.Field != "" && !reFieldName.MatchString(r.Field) {
			return invalidf("bad selector field %s", r)
		}
		if r.Owner && r.Field != "" {
			return invalidf("bad owner selector %s", r)
		}
		return nil
	}
	if strings.HasPrefix(r.From, "resp.") {
		return invalidf("selector from the response %s", r)
	}
	return validRef(r, false)
}

// validRequestRef checks a reference to a request parameter or a request
// body path (keys of keyed entities).
func validRequestRef(r Ref) error {
	if r.Field != "" || r.Owner {
		return invalidf("bad key ref %s", r)
	}
	return validSelector(r)
}

// seedBucketRE is the grammar of a seed bucket: "0", "3", "2-5", "11+".
var seedBucketRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})(-[1-9][0-9]{0,3}|\+)?$`)

// SeedBucketRange returns the bounds of a seed bucket ("11+" has hi = -1).
func SeedBucketRange(n string) (lo, hi int, ok bool) {
	if !seedBucketRE.MatchString(n) {
		return 0, 0, false
	}
	a, b, isRange := strings.Cut(n, "-")
	if strings.HasSuffix(n, "+") {
		lo = atoiSmall(strings.TrimSuffix(n, "+"))
		return lo, -1, true
	}
	lo = atoiSmall(a)
	if !isRange {
		return lo, lo, true
	}
	hi = atoiSmall(b)
	return lo, hi, hi > lo
}

func atoiSmall(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func validKeyRefs(k *StateKey, refs map[string]Ref) error {
	if len(refs) > len(k.Fields) {
		return errors.New("more key fields than the entity key")
	}
	for f, r := range refs {
		if !slicesContains(k.Fields, f) {
			return fmt.Errorf("%q is not a key field", f)
		}
		if err := validRequestRef(r); err != nil {
			return err
		}
	}
	return nil
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// validateState checks seed, key and upserted_by (rules v1.6).
func (e *Entity) validateState() error {
	if s := e.Seed; s != nil {
		if len(s.PerCustomer) == 0 || len(s.PerCustomer) > 16 || s.Subjects < 0 {
			return invalidf("entity %q: bad seed", e.Name)
		}
		sum := 0.0
		seen := map[string]bool{}
		for _, b := range s.PerCustomer {
			if _, _, ok := SeedBucketRange(b.N); !ok || seen[b.N] || b.Share < 0 || b.Share > 1 || math.IsNaN(b.Share) {
				return invalidf("entity %q: bad seed bucket %q", e.Name, b.N)
			}
			seen[b.N] = true
			sum += b.Share
		}
		if math.Abs(sum-1) > 0.001 {
			return invalidf("entity %q: seed shares sum to %.4f", e.Name, sum)
		}
		if len(s.Values) > 16 {
			return invalidf("entity %q: too many seed values", e.Name)
		}
		for f, vs := range s.Values {
			if !reFieldPath.MatchString(f) || len(vs) == 0 || len(vs) > 64 {
				return invalidf("entity %q: bad seed values %q", e.Name, f)
			}
			sum := 0.0
			for v, p := range vs {
				if len(v) > 256 || strings.HasPrefix(v, "${") || p < 0 || p > 1 || math.IsNaN(p) {
					return invalidf("entity %q: bad seed value of %q", e.Name, f)
				}
				sum += p
			}
			if math.Abs(sum-1) > 0.001 {
				return invalidf("entity %q: seed values of %q sum to %.4f", e.Name, f, sum)
			}
		}
	}
	if k := e.Key; k != nil {
		if (!k.Owner && len(k.Fields) == 0) || len(k.Fields) > 8 || e.CreatedBy != nil {
			return invalidf("entity %q: bad key (owner or fields, never with created_by)", e.Name)
		}
		seen := map[string]bool{}
		for _, f := range k.Fields {
			if !reFieldName.MatchString(f) || seen[f] {
				return invalidf("entity %q: bad key field", e.Name)
			}
			seen[f] = true
		}
	}
	if len(e.UpsertedBy) > 0 && e.Key == nil {
		return invalidf("entity %q: upserted_by needs a key", e.Name)
	}
	if len(e.UpsertedBy) > 16 {
		return invalidf("entity %q: too many upserted_by", e.Name)
	}
	for _, u := range e.UpsertedBy {
		if !reOp.MatchString(u.Op) || (u.Service != "" && !reService.MatchString(u.Service)) {
			return invalidf("entity %q: bad upserted_by", e.Name)
		}
		if len(u.Key) != len(e.Key.Fields) {
			return invalidf("entity %q: upserted_by.key must give every key field", e.Name)
		}
		if err := validKeyRefs(e.Key, u.Key); err != nil {
			return invalidf("entity %q: upserted_by.key: %v", e.Name, err)
		}
		if u.State != nil && (u.State.From != "req.body" || !reTTPath.MatchString(u.State.Path)) {
			return invalidf("entity %q: bad upserted_by.state", e.Name)
		}
	}
	return nil
}
