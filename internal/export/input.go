package export

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Source supplies the already verified content of a twin pack. The exporter
// never verifies signatures or hashes: that is the job of internal/pack, which
// provides the production Source. DirSource is an unverified loader meant for
// tests, fixtures and local experiments.
type Source interface {
	Load(ctx context.Context) (*Input, error)
}

// Input is the in-memory view of a twin pack that the exporters need.
type Input struct {
	Manifest Manifest
	Services []Service
	Rules    Rules
	World    World
	Faults   Faults
	// Scenarios are the optional presets of scenarios.json (tt.scenarios/v1).
	Scenarios []Preset
}

// Manifest carries the few manifest fields the exporters use.
type Manifest struct {
	PackID    string `json:"pack_id"`
	CreatedAt string `json:"created_at"`
	Seed      int64  `json:"seed"`
	KMin      int    `json:"k_min"`
	// NotAfter is the optional end of validity (v1.2); internal/pack refuses
	// expired packs, Run checks it again as defence in depth.
	NotAfter string `json:"not_after,omitempty"`
}

// Preset is one entry of scenarios.json.
type Preset struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Customer    string          `json:"customer,omitempty"`
	Archetype   string          `json:"archetype,omitempty"`
	Seed        *int64          `json:"seed,omitempty"`
	Faults      *PresetFaults   `json:"faults,omitempty"`
	Outcomes    []PresetOutcome `json:"outcomes,omitempty"`
}

// PresetFaults mirrors the control API Faults object.
type PresetFaults struct {
	Mode  string            `json:"mode"`
	Rules []PresetFaultRule `json:"rules,omitempty"`
}

// PresetFaultRule is one forced fault.
type PresetFaultRule struct {
	Service   string  `json:"service"`
	Op        string  `json:"op"`
	Status    int     `json:"status,omitempty"`
	NetError  string  `json:"net_error,omitempty"`
	LatencyMS int     `json:"latency_ms,omitempty"`
	P         float64 `json:"p"`
	Times     int     `json:"times,omitempty"`
}

// PresetOutcome forces the outcome of a rule.
type PresetOutcome struct {
	Rule    string `json:"rule"`
	Outcome string `json:"outcome"`
	Times   int    `json:"times,omitempty"`
}

// Service is one contract of the pack.
type Service struct {
	Name          string
	UpstreamAlias string
	// Contract is the parsed OpenAPI 3.1 document (with x-tt-* extensions).
	Contract map[string]any
}

// Rules mirrors tt.rules/v1.
type Rules struct {
	Format   string   `json:"format"`
	Entities []Entity `json:"entities"`
	Rules    []Rule   `json:"rules"`
	// Attributes, Aggregates and Lists (rules v1.9) answer per session in
	// the mock: the stubs do not reproduce them (reported as losses).
	Attributes []NamedPart `json:"attributes,omitempty"`
	Aggregates []OpPart    `json:"aggregates,omitempty"`
	Lists      []OpPart    `json:"lists,omitempty"`
}

// NamedPart is a named member of the rules (a customer attribute).
type NamedPart struct {
	Name string `json:"name"`
}

// OpPart is a member of the rules on one operation (an aggregate, a list).
type OpPart struct {
	Service string `json:"service"`
	Op      string `json:"op"`
}

// Entity is a business object (rules.md section 2).
type Entity struct {
	Name      string     `json:"name"`
	Service   string     `json:"service"`
	IDDomain  string     `json:"id_domain"`
	IDField   string     `json:"id_field"`
	IDPrefix  string     `json:"id_prefix"`
	CreatedBy *Creation  `json:"created_by,omitempty"`
	Relations []Relation `json:"relations,omitempty"`
	ReadBy    []ReadBy   `json:"read_by,omitempty"`
}

// Relation declares that Field holds the id of an Entity (foreign key).
type Relation struct {
	Field  string `json:"field"`
	Entity string `json:"entity"`
	Many   bool   `json:"many,omitempty"`
}

// Creation describes the operation that creates an entity.
type Creation struct {
	Op       string         `json:"op"`
	ID       Ref            `json:"id"`
	State    *Ref           `json:"state,omitempty"`
	Defaults map[string]any `json:"defaults,omitempty"`
}

// ReadBy describes an operation that exposes an entity.
type ReadBy struct {
	Op string `json:"op"`
	// Service is set when another service exposes the entity (v1.2).
	Service string `json:"service,omitempty"`
	// By is nil for lists of the session's customer (v1.2).
	By *Ref `json:"by,omitempty"`
	At Ref  `json:"at"`

	HiddenWhen      map[string]any `json:"hidden_when,omitempty"`
	Scope           string         `json:"scope,omitempty"`
	Foreign         string         `json:"foreign,omitempty"`
	ForeignExample  string         `json:"foreign_example,omitempty"`
	NotFoundExample string         `json:"not_found_example,omitempty"`
	List            *ListShape     `json:"list,omitempty"`
}

// ListShape is the envelope and pagination of a list read.
type ListShape struct {
	Count        string `json:"count,omitempty"`
	Total        string `json:"total,omitempty"`
	Limit        *Ref   `json:"limit,omitempty"`
	Offset       *Ref   `json:"offset,omitempty"`
	Page         *Ref   `json:"page,omitempty"`
	Cursor       *Ref   `json:"cursor,omitempty"`
	NextCursor   string `json:"next_cursor,omitempty"`
	DefaultLimit int    `json:"default_limit,omitempty"`
	MaxLimit     int    `json:"max_limit,omitempty"`
	OrderBy      string `json:"order_by,omitempty"`
	Order        string `json:"order,omitempty"`
	// Filters (rules v1.9) select items by a request parameter: not
	// exported.
	Filters []json.RawMessage `json:"filters,omitempty"`
}

// Ref points at a place of an exchange.
type Ref struct {
	From  string `json:"from"`
	Path  string `json:"path,omitempty"`
	Name  string `json:"name,omitempty"`
	Field string `json:"field,omitempty"`
	Owner bool   `json:"owner,omitempty"`
}

// Rule is a causal or batch rule.
type Rule struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Status   string    `json:"status"`
	Title    string    `json:"title"`
	Cause    *Cause    `json:"cause,omitempty"`
	Effects  []Effect  `json:"effects,omitempty"`
	Outcomes []Outcome `json:"outcomes,omitempty"`

	// Batch rules.
	Schedule string         `json:"schedule,omitempty"`
	Entity   string         `json:"entity,omitempty"`
	Where    map[string]any `json:"where,omitempty"`
	Set      map[string]any `json:"set,omitempty"`
	Fraction float64        `json:"fraction,omitempty"`
}

// Cause is the trigger of a causal rule.
type Cause struct {
	Service string         `json:"service"`
	Op      string         `json:"op"`
	When    CauseWhen      `json:"when"`
	Bind    map[string]Ref `json:"bind,omitempty"`
}

// CauseWhen filters the cause by response status.
type CauseWhen struct {
	Status []int `json:"status"`
	// Match (rules v1.9): conditions on the request and the customer, not
	// exported (the stubs answer every request alike).
	Match []json.RawMessage `json:"match,omitempty"`
}

// Effect is one step of a causal rule.
type Effect struct {
	ID       string         `json:"id"`
	Entity   string         `json:"entity"`
	Create   map[string]any `json:"create,omitempty"`
	Target   string         `json:"target,omitempty"`
	TargetID string         `json:"target_id,omitempty"`
	Set      map[string]any `json:"set,omitempty"`
	// Respond is a response effect (rules v1.4): not exported (see buildModel).
	Respond map[string]any `json:"respond,omitempty"`
	// Remove (rules v1.6): not exported either.
	Remove bool `json:"remove,omitempty"`
	// TargetKey (rules v1.8): an effect on a keyed record, not exported.
	TargetKey map[string]string `json:"target_key,omitempty"`
	// TargetAll (rules v1.9): every object of the customer, not exported.
	TargetAll   bool   `json:"target_all,omitempty"`
	AfterEffect string `json:"after_effect,omitempty"`
	After       Delay  `json:"after"`
}

// Delay is a figurative delay: one duration ("5m") or a range {min, max}.
type Delay struct {
	Fixed    string
	Min, Max string
	IsRange  bool
}

// UnmarshalJSON accepts a string or an object with min and max.
func (d *Delay) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*d = Delay{Fixed: s}
		return nil
	}
	var r struct {
		Min string `json:"min"`
		Max string `json:"max"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("delay: want a duration or {min,max}: %w", err)
	}
	*d = Delay{Min: r.Min, Max: r.Max, IsRange: true}
	return nil
}

// Value renders the delay as it appears in metadata: a string or {min,max}.
func (d Delay) Value() any {
	if d.IsRange {
		return map[string]any{"min": d.Min, "max": d.Max}
	}
	return d.Fixed
}

// Zero reports whether the delay is 0 (single value or range 0..0).
func (d Delay) Zero() bool {
	z := func(s string) bool { return s == "" || (len(s) > 1 && strings.Trim(s[:len(s)-1], "0") == "") }
	if d.IsRange {
		return z(d.Min) && z(d.Max)
	}
	return z(d.Fixed)
}

// Outcome is an alternative branch of a causal rule.
type Outcome struct {
	Name    string   `json:"name"`
	P       float64  `json:"p"`
	Effects []string `json:"effects"`
	// When (rules v1.9): a conditional outcome.
	When []json.RawMessage `json:"when,omitempty"`
}

// World is the content of world.jsonl.
type World struct {
	Customers []WorldCustomer
	Entities  []WorldEntity
	History   []WorldHistory
	Pending   []WorldPending
}

// WorldEntity is an "entity" row: the state at t0.
type WorldEntity struct {
	CustomerID string         `json:"customer_id"`
	Entity     string         `json:"entity"`
	ID         string         `json:"id"`
	State      map[string]any `json:"state"`
}

// WorldHistory is a "history" row.
type WorldHistory struct {
	At       string         `json:"at"`
	EffectID string         `json:"effect_id"`
	Entity   string         `json:"entity"`
	ID       string         `json:"id"`
	RuleID   string         `json:"rule_id"`
	Seq      int            `json:"seq"`
	Outcome  string         `json:"outcome,omitempty"`
	State    map[string]any `json:"state"`
}

// WorldPending is a "pending" row (v1.2): an effect of an already drawn
// branch whose instant is after t0.
type WorldPending struct {
	CustomerID string         `json:"customer_id"`
	DueOffsetS int64          `json:"due_offset_s"`
	EffectID   string         `json:"effect_id"`
	Entity     string         `json:"entity"`
	ID         string         `json:"id"`
	Outcome    string         `json:"outcome"`
	RuleID     string         `json:"rule_id"`
	Seq        int            `json:"seq"`
	Vars       map[string]any `json:"vars,omitempty"`
	EffectIDs  map[string]any `json:"effect_ids,omitempty"`
}

// WorldCustomer is a "customer" row.
type WorldCustomer struct {
	ID        string `json:"id"`
	Archetype string `json:"archetype"`
}

// Faults mirrors tt.faults/v1.
type Faults struct {
	Format string     `json:"format"`
	Ops    []FaultOps `json:"ops"`
}

// FaultOps is the fault and latency profile of one operation.
type FaultOps struct {
	Service   string        `json:"service"`
	Op        string        `json:"op"`
	Statuses  []FaultStatus `json:"statuses,omitempty"`
	NetErrors []FaultNet    `json:"net_errors,omitempty"`
	Latency   *Latency      `json:"latency_ms,omitempty"`
}

// FaultStatus is an observed error status.
type FaultStatus struct {
	Status  int     `json:"status"`
	P       float64 `json:"p"`
	Example string  `json:"example,omitempty"`
}

// FaultNet is an observed network error.
type FaultNet struct {
	Kind string  `json:"kind"`
	P    float64 `json:"p"`
}

// Latency is the observed latency profile.
type Latency struct {
	P50       int            `json:"p50,omitempty"`
	P95       int            `json:"p95,omitempty"`
	P99       int            `json:"p99,omitempty"`
	Lognormal *LogNormalSpec `json:"lognormal,omitempty"`
}

// LogNormalSpec is a fitted log-normal.
type LogNormalSpec struct {
	Median float64 `json:"median"`
	Sigma  float64 `json:"sigma"`
}

// ParseWorldJSONL parses world.jsonl rows (meta and customer rows are skipped).
func ParseWorldJSONL(r io.Reader) (World, error) {
	var w World
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return w, fmt.Errorf("world.jsonl line %d: %w", line, err)
		}
		switch head.Type {
		case "customer":
			var c WorldCustomer
			if err := decodeJSON(raw, &c); err != nil {
				return w, fmt.Errorf("world.jsonl line %d: %w", line, err)
			}
			w.Customers = append(w.Customers, c)
		case "pending":
			var p WorldPending
			if err := decodeJSON(raw, &p); err != nil {
				return w, fmt.Errorf("world.jsonl line %d: %w", line, err)
			}
			w.Pending = append(w.Pending, p)
		case "entity":
			var e WorldEntity
			if err := decodeJSON(raw, &e); err != nil {
				return w, fmt.Errorf("world.jsonl line %d: %w", line, err)
			}
			w.Entities = append(w.Entities, e)
		case "history":
			var h WorldHistory
			if err := decodeJSON(raw, &h); err != nil {
				return w, fmt.Errorf("world.jsonl line %d: %w", line, err)
			}
			w.History = append(w.History, h)
		}
	}
	return w, sc.Err()
}

// decodeJSON decodes with numbers kept exact (json.Number) inside maps.
func decodeJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(v)
}

// DirSource reads an unpacked pack directory WITHOUT verifying signature or
// hashes. Use it only for fixtures; production code uses internal/pack.
type DirSource struct{ Dir string }

// Load implements Source.
func (s DirSource) Load(ctx context.Context) (*Input, error) {
	return loadFrom(ctx, func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(s.Dir, filepath.FromSlash(rel)))
	})
}

// loadFrom builds an Input from pack files returned by read.
func loadFrom(ctx context.Context, read func(rel string) ([]byte, error)) (*Input, error) {
	var in Input

	mb, err := read("manifest.json")
	if err != nil {
		return nil, err
	}
	var mf struct {
		Manifest
		Services []struct {
			Name          string `json:"name"`
			Contract      string `json:"contract"`
			UpstreamAlias string `json:"upstream_alias"`
		} `json:"services"`
		Rules struct {
			Path string `json:"path"`
		} `json:"rules"`
		World struct {
			Path string `json:"path"`
		} `json:"world"`
		Faults    string `json:"faults"`
		Scenarios string `json:"scenarios"`
	}
	if err := decodeJSON(mb, &mf); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	in.Manifest = mf.Manifest
	for _, sv := range mf.Services {
		cb, err := read(sv.Contract)
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := decodeJSON(cb, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", sv.Contract, err)
		}
		in.Services = append(in.Services, Service{Name: sv.Name, UpstreamAlias: sv.UpstreamAlias, Contract: doc})
	}
	if mf.Rules.Path != "" {
		rb, err := read(mf.Rules.Path)
		if err != nil {
			return nil, err
		}
		if err := decodeJSON(rb, &in.Rules); err != nil {
			return nil, fmt.Errorf("%s: %w", mf.Rules.Path, err)
		}
	}
	if mf.World.Path != "" {
		wb, err := read(mf.World.Path)
		if err != nil {
			return nil, err
		}
		if in.World, err = ParseWorldJSONL(bytes.NewReader(wb)); err != nil {
			return nil, err
		}
	}
	if mf.Faults != "" {
		fb, err := read(mf.Faults)
		if err != nil {
			return nil, err
		}
		if err := decodeJSON(fb, &in.Faults); err != nil {
			return nil, fmt.Errorf("%s: %w", mf.Faults, err)
		}
	}
	if mf.Scenarios != "" {
		sb, err := read(mf.Scenarios)
		if err != nil {
			return nil, err
		}
		var sc struct {
			Scenarios []Preset `json:"scenarios"`
		}
		if err := decodeJSON(sb, &sc); err != nil {
			return nil, fmt.Errorf("%s: %w", mf.Scenarios, err)
		}
		in.Scenarios = sc.Scenarios
	}
	return &in, ctx.Err()
}

// validate checks the structural invariants the exporters rely on.
func (in *Input) validate() error {
	if in == nil {
		return errors.New("export: nil input")
	}
	if len(in.Services) == 0 {
		return errors.New("export: input has no services")
	}
	seen := map[string]bool{}
	for _, s := range in.Services {
		if s.Name == "" || s.Contract == nil {
			return errors.New("export: service without name or contract")
		}
		if seen[s.Name] {
			return fmt.Errorf("export: duplicate service %q", s.Name)
		}
		seen[s.Name] = true
	}
	sort.SliceStable(in.Services, func(i, j int) bool { return in.Services[i].Name < in.Services[j].Name })
	return nil
}
