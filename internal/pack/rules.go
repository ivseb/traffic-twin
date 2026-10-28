package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/derive"
)

var (
	seedBucketRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})(-[1-9][0-9]{0,3}|\+)?$`)
	bindRefRE    = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]{0,31})\}$`)
	effectRefRE  = regexp.MustCompile(`^\$\{effect:([a-z][a-z0-9_-]{0,63})\}$`)
	// notRefRE is the negation of a boolean of the target (rules v1.7).
	notRefRE = regexp.MustCompile(`^\$\{not:([A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7})\}$`)
)

type rulesWire struct {
	Format      string            `json:"format"`
	GeneratedAt string            `json:"generated_at,omitempty"`
	Window      json.RawMessage   `json:"window,omitempty"`
	Entities    []json.RawMessage `json:"entities"`
	Rules       []json.RawMessage `json:"rules"`
	Attributes  []Attribute       `json:"attributes,omitempty"`
	Aggregates  []Aggregate       `json:"aggregates,omitempty"`
	Lists       []ListOp          `json:"lists,omitempty"`
}

type causalWire struct {
	CausalRule
	Kind       string          `json:"kind"`
	Status     string          `json:"status"`
	Origin     string          `json:"origin,omitempty"`
	Supersedes string          `json:"supersedes,omitempty"`
	Evidence   json.RawMessage `json:"evidence"`
	Review     json.RawMessage `json:"review,omitempty"`
}

type batchWire struct {
	BatchRule
	Kind       string          `json:"kind"`
	Status     string          `json:"status"`
	Origin     string          `json:"origin,omitempty"`
	Supersedes string          `json:"supersedes,omitempty"`
	Evidence   json.RawMessage `json:"evidence"`
	Review     json.RawMessage `json:"review,omitempty"`
}

func parseRules(data []byte, approved []string, services map[string]bool) (*Rules, error) {
	var w rulesWire
	if err := decodeStrict(data, &w); err != nil {
		return nil, err
	}
	if w.Format != "tt.rules/v1" {
		return nil, errors.New("format must be tt.rules/v1")
	}
	out := &Rules{Format: w.Format}
	entNames := map[string]bool{}
	for _, raw := range w.Entities {
		var e Entity
		if err := decodeStrict(raw, &e); err != nil {
			return nil, fmt.Errorf("entity: %v", err)
		}
		if err := validateEntity(&e, services); err != nil {
			return nil, fmt.Errorf("entity %q: %v", e.Name, err)
		}
		if entNames[e.Name] {
			return nil, fmt.Errorf("duplicate entity %q", e.Name)
		}
		entNames[e.Name] = true
		out.Entities = append(out.Entities, e)
	}
	ents := map[string]*Entity{}
	for i := range out.Entities {
		ents[out.Entities[i].Name] = &out.Entities[i]
	}
	if err := validateExtras(&w, ents, services); err != nil {
		return nil, err
	}
	out.Attributes, out.Aggregates, out.Lists = w.Attributes, w.Aggregates, w.Lists
	attrs := map[string]bool{}
	for _, a := range w.Attributes {
		attrs[a.Name] = true
	}
	for i := range out.Entities {
		e := &out.Entities[i]
		for _, rel := range e.Relations {
			if ents[rel.Entity] == nil {
				return nil, fmt.Errorf("entity %q: relation %q targets unknown entity %q", e.Name, rel.Field, rel.Entity)
			}
		}
	}

	seen := map[string]bool{}
	for _, raw := range w.Rules {
		var head struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return nil, fmt.Errorf("rule: %v", err)
		}
		if !ruleIDRE.MatchString(head.ID) {
			return nil, fmt.Errorf("malformed rule id %q", head.ID)
		}
		if seen[head.ID] {
			return nil, fmt.Errorf("duplicate rule %q", head.ID)
		}
		seen[head.ID] = true
		switch head.Kind {
		case "causal":
			var c causalWire
			if err := decodeStrict(raw, &c); err != nil {
				return nil, fmt.Errorf("rule %s: %v", head.ID, err)
			}
			if c.Status != "approved" {
				return nil, fmt.Errorf("rule %s: status %q (only approved rules belong in a pack)", head.ID, c.Status)
			}
			if !validOrigin(c.Origin) {
				return nil, fmt.Errorf("rule %s: origin must be mined or manual", head.ID)
			}
			if err := validateCausal(&c.CausalRule, ents, services); err != nil {
				return nil, fmt.Errorf("rule %s: %v", head.ID, err)
			}
			if err := validateConditions(&c.CausalRule, attrs); err != nil {
				return nil, fmt.Errorf("rule %s: %v", head.ID, err)
			}
			out.Causal = append(out.Causal, c.CausalRule)
		case "batch":
			var b batchWire
			if err := decodeStrict(raw, &b); err != nil {
				return nil, fmt.Errorf("rule %s: %v", head.ID, err)
			}
			if b.Status != "approved" {
				return nil, fmt.Errorf("rule %s: status %q (only approved rules belong in a pack)", head.ID, b.Status)
			}
			if !validOrigin(b.Origin) {
				return nil, fmt.Errorf("rule %s: origin must be mined or manual", head.ID)
			}
			if err := validateBatch(&b.BatchRule, ents); err != nil {
				return nil, fmt.Errorf("rule %s: %v", head.ID, err)
			}
			out.Batch = append(out.Batch, b.BatchRule)
		default:
			return nil, fmt.Errorf("rule %s: unknown kind %q", head.ID, head.Kind)
		}
		out.Order = append(out.Order, head.ID)
	}
	want := map[string]bool{}
	for _, id := range approved {
		want[id] = true
	}
	if len(want) != len(approved) || len(want) != len(seen) {
		return nil, errors.New("manifest.rules.approved does not match the rules in the file")
	}
	for id := range seen {
		if !want[id] {
			return nil, fmt.Errorf("rule %s is not listed in manifest.rules.approved", id)
		}
	}
	return out, nil
}

func isListPath(p string) bool { return strings.HasSuffix(p, "[*]") }

// validOrigin: rules v1.4, absent means mined.
func validOrigin(o string) bool { return o == "" || o == "mined" || o == "manual" }

// validateRespond checks a response effect against the services of the pack.
func validateRespond(r *Respond, services map[string]bool) error {
	if !services[r.Service] {
		return fmt.Errorf("respond: unknown service %q", r.Service)
	}
	if !opRE.MatchString(r.Op) {
		return errors.New("respond: malformed op")
	}
	if r.Status < 100 || r.Status > 599 {
		return errors.New("respond: status out of range")
	}
	if r.P < 0 || r.P > 1 || math.IsNaN(r.P) {
		return errors.New("respond: p out of range")
	}
	if r.Times < 0 || r.Times > 1000000 {
		return errors.New("respond: times out of range")
	}
	if r.Example != "" && !exampleKeyRE.MatchString(r.Example) {
		return errors.New("respond: malformed example name")
	}
	if r.Body != nil {
		if err := ValidateErrorBody(r.Body); err != nil {
			return fmt.Errorf("respond: %v", err)
		}
	}
	return nil
}

// MaxErrorBody bounds an error body typed by a person (rules 1.10, mock 1.12).
const MaxErrorBody = 16 << 10

// ValidateErrorBody checks an example error body: a JSON object, array or
// string of at most MaxErrorBody bytes.
func ValidateErrorBody(b any) error {
	switch b.(type) {
	case map[string]any, []any, string:
	default:
		return errors.New("body must be a JSON object, array or string")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return errors.New("body is not valid JSON")
	}
	if len(raw) > MaxErrorBody {
		return fmt.Errorf("body is larger than %d bytes", MaxErrorBody)
	}
	return nil
}

func validateEntity(e *Entity, services map[string]bool) error {
	if !identRE.MatchString(e.Name) || !svcNameRE.MatchString(e.Service) || !idDomainRE.MatchString(e.IDDomain) ||
		!idFieldRE.MatchString(e.IDField) || !idPrefixRE.MatchString(e.IDPrefix) {
		return errors.New("malformed fields")
	}
	if cb := e.CreatedBy; cb != nil {
		if !opRE.MatchString(cb.Op) {
			return errors.New("malformed created_by.op")
		}
		if err := validateRef(cb.ID); err != nil {
			return fmt.Errorf("created_by.id: %v", err)
		}
		if cb.State != nil {
			if cb.State.From != "req.body" || cb.State.Path == "" || !ttPathRE.MatchString(cb.State.Path) {
				return errors.New("created_by.state must be a req.body path")
			}
		}
		if err := validateFieldValues(cb.Defaults); err != nil {
			return fmt.Errorf("created_by.defaults: %v", err)
		}
	}
	if err := validateState(e, services); err != nil {
		return err
	}
	for _, rel := range e.Relations {
		if !fieldPathRE.MatchString(rel.Field) || !identRE.MatchString(rel.Entity) {
			return errors.New("malformed relation")
		}
	}
	if len(e.Relations) > 32 {
		return errors.New("too many relations")
	}
	for i := range e.ReadBy {
		if err := validateReadBy(&e.ReadBy[i], e.Key, services); err != nil {
			return fmt.Errorf("read_by %q: %v", e.ReadBy[i].Op, err)
		}
	}
	return nil
}

func validateReadBy(rb *ReadBy, key *StateKey, services map[string]bool) error {
	if !opRE.MatchString(rb.Op) {
		return errors.New("malformed op")
	}
	if rb.Service != "" && (!svcNameRE.MatchString(rb.Service) || !services[rb.Service]) {
		return fmt.Errorf("unknown service %q", rb.Service)
	}
	if rb.At.From != "resp.body" {
		return errors.New("at must be a resp.body path")
	}
	if err := validateRef(rb.At); err != nil {
		return fmt.Errorf("at: %v", err)
	}
	list := isListPath(rb.At.Path)
	if len(rb.Key) > 0 {
		if key == nil || rb.By != nil {
			return errors.New("key needs a keyed entity and excludes by")
		}
		if err := validateKeyRefs(key, rb.Key); err != nil {
			return fmt.Errorf("key: %v", err)
		}
	}
	if rb.RemovedStatus != 0 && (rb.RemovedStatus < 400 || rb.RemovedStatus > 599) {
		return errors.New("removed_status out of range")
	}
	if rb.By == nil {
		if !list && key == nil {
			return errors.New("by is required unless the read is a list")
		}
	} else {
		if err := validateSelector(*rb.By); err != nil {
			return fmt.Errorf("by: %v", err)
		}
		if rb.By.From == "resp.body" || rb.By.From == "resp.headers" || rb.By.From == "resp.cookies" {
			return errors.New("by must select from the request (a parameter or a body member)")
		}
		if rb.By.Owner {
			if !list {
				return errors.New("by.owner is only for lists")
			}
			if rb.By.Field != "" {
				return errors.New("by.owner excludes field")
			}
		}
	}
	if err := validateFieldValues(rb.HiddenWhen); err != nil {
		return fmt.Errorf("hidden_when: %v", err)
	}
	for _, v := range rb.HiddenWhen {
		if s, ok := v.(string); ok && strings.Contains(s, "${") {
			return errors.New("hidden_when takes literal values only")
		}
	}
	switch rb.Scope {
	case "", "any", "owner":
	default:
		return errors.New("scope must be any or owner")
	}
	switch rb.Foreign {
	case "", "not_found", "forbidden":
	default:
		return errors.New("foreign must be not_found or forbidden")
	}
	for _, ex := range []string{rb.ForeignExample, rb.NotFoundExample} {
		if ex != "" && !exampleKeyRE.MatchString(ex) {
			return errors.New("malformed example name")
		}
	}
	if rb.List != nil {
		if !list {
			return errors.New("list is only for lists")
		}
		if err := validateListShape(rb.List); err != nil {
			return fmt.Errorf("list: %v", err)
		}
		if err := validateListFilters(rb.List.Filters); err != nil {
			return fmt.Errorf("list: %v", err)
		}
	}
	return nil
}

func validateListShape(l *ListShape) error {
	for _, p := range []string{l.Count, l.Total, l.NextCursor} {
		if p != "" && !ttPathRE.MatchString(p) {
			return errors.New("malformed path")
		}
	}
	n := 0
	for _, nr := range []*NameRef{l.Limit, l.Offset, l.Page, l.Cursor} {
		if nr == nil {
			continue
		}
		switch nr.From {
		case "req.path", "req.query", "req.headers", "req.cookies":
		default:
			return errors.New("pagination parameters come from the request")
		}
		if !refNameRE.MatchString(nr.Name) {
			return errors.New("malformed parameter name")
		}
	}
	for _, nr := range []*NameRef{l.Offset, l.Page, l.Cursor} {
		if nr != nil {
			n++
		}
	}
	if n > 1 {
		return errors.New("offset, page and cursor are mutually exclusive")
	}
	if l.NextCursor != "" && l.Cursor == nil {
		return errors.New("next_cursor needs cursor")
	}
	for _, v := range []int{l.DefaultLimit, l.MaxLimit} {
		if v < 0 || v > 1000 {
			return errors.New("limits must be within 1..1000")
		}
	}
	if l.OrderBy != "" && !fieldPathRE.MatchString(l.OrderBy) {
		return errors.New("malformed order_by")
	}
	switch l.Order {
	case "", "asc", "desc":
	default:
		return errors.New("order must be asc or desc")
	}
	return nil
}

// BodySelectorRef reports whether a request body reference can select an
// entity (rules v1.6): a member outside arrays, below the root.
func BodySelectorRef(r Ref) bool {
	return r.From == "req.body" && r.Path != "$" && ttPathRE.MatchString(r.Path) && !strings.Contains(r.Path, "[*]") && !strings.Contains(r.Path, ".*")
}

// validateSelector checks read_by.by: a request parameter, or a body member
// (rules v1.6), by id, field or owner.
func validateSelector(r Ref) error {
	if r.From != "req.body" {
		return validateRef(r)
	}
	if !BodySelectorRef(r) || r.Name != "" {
		return errors.New("a body selector needs a path outside arrays")
	}
	if r.Field != "" && !idFieldRE.MatchString(r.Field) {
		return errors.New("malformed field")
	}
	return nil
}

func validateKeyRefs(k *StateKey, refs map[string]Ref) error {
	if len(refs) > len(k.Fields) {
		return errors.New("more key fields than the entity key")
	}
	for f, r := range refs {
		found := false
		for _, kf := range k.Fields {
			found = found || kf == f
		}
		if !found {
			return fmt.Errorf("%q is not a key field", f)
		}
		if r.Field != "" || r.Owner {
			return errors.New("a key ref is a request parameter or body member only")
		}
		if err := validateSelector(r); err != nil {
			return err
		}
		if strings.HasPrefix(r.From, "resp.") {
			return errors.New("a key comes from the request")
		}
	}
	return nil
}

// validateState checks seed, key and upserted_by (rules v1.6).
func validateState(e *Entity, services map[string]bool) error {
	if s := e.Seed; s != nil {
		if len(s.PerCustomer) == 0 || len(s.PerCustomer) > 16 || s.Subjects < 0 {
			return errors.New("malformed seed")
		}
		sum := 0.0
		seen := map[string]bool{}
		for _, b := range s.PerCustomer {
			if _, _, ok := b.Range(); !ok || seen[b.N] || b.Share < 0 || b.Share > 1 || math.IsNaN(b.Share) {
				return fmt.Errorf("malformed seed bucket %q", b.N)
			}
			seen[b.N] = true
			sum += b.Share
		}
		if math.Abs(sum-1) > 0.001 {
			return errors.New("seed shares must sum to 1")
		}
		if len(s.Values) > 16 {
			return errors.New("too many seed values")
		}
		for f, vs := range s.Values {
			if !fieldPathRE.MatchString(f) || len(vs) == 0 || len(vs) > 64 {
				return fmt.Errorf("malformed seed values of %q", f)
			}
			sum := 0.0
			for v, p := range vs {
				if len(v) > 256 || strings.Contains(v, "${") || p < 0 || p > 1 || math.IsNaN(p) {
					return fmt.Errorf("malformed seed value of %q", f)
				}
				sum += p
			}
			if math.Abs(sum-1) > 0.001 {
				return fmt.Errorf("seed values of %q must sum to 1", f)
			}
		}
	}
	if k := e.Key; k != nil {
		if (!k.Owner && len(k.Fields) == 0) || len(k.Fields) > 8 || e.CreatedBy != nil {
			return errors.New("key needs owner or fields and excludes created_by")
		}
		seen := map[string]bool{}
		for _, f := range k.Fields {
			if !idFieldRE.MatchString(f) || seen[f] {
				return errors.New("malformed key field")
			}
			seen[f] = true
		}
	}
	if len(e.UpsertedBy) > 0 && e.Key == nil {
		return errors.New("upserted_by needs a key")
	}
	if len(e.UpsertedBy) > 16 {
		return errors.New("too many upserted_by")
	}
	for _, u := range e.UpsertedBy {
		if !opRE.MatchString(u.Op) {
			return errors.New("malformed upserted_by.op")
		}
		if u.Service != "" && (!svcNameRE.MatchString(u.Service) || !services[u.Service]) {
			return fmt.Errorf("upserted_by: unknown service %q", u.Service)
		}
		if len(u.Key) != len(e.Key.Fields) {
			return errors.New("upserted_by.key must give every key field")
		}
		if err := validateKeyRefs(e.Key, u.Key); err != nil {
			return fmt.Errorf("upserted_by.key: %v", err)
		}
		if u.State != nil && (u.State.From != "req.body" || !ttPathRE.MatchString(u.State.Path)) {
			return errors.New("upserted_by.state must be a req.body path")
		}
	}
	return nil
}

func validateRef(r Ref) error {
	switch r.From {
	case "req.body", "resp.body":
		if r.Name != "" || r.Field != "" || r.Owner || !ttPathRE.MatchString(r.Path) {
			return errors.New("body reference needs a valid path only")
		}
	case "req.path", "req.query", "req.headers", "req.cookies", "resp.headers", "resp.cookies":
		if r.Path != "" || !refNameRE.MatchString(r.Name) {
			return errors.New("reference needs a valid name only")
		}
		if r.Field != "" && !idFieldRE.MatchString(r.Field) {
			return errors.New("malformed field")
		}
	default:
		return fmt.Errorf("unknown source %q", r.From)
	}
	return nil
}

// validateEffectValues checks the values of create and set: scalars or
// derived values (rules 1.10, 3.15).
func validateEffectValues(m map[string]any) error {
	plain := map[string]any{}
	for k, v := range m {
		if derive.Is(v) {
			if !fieldPathRE.MatchString(k) {
				return fmt.Errorf("malformed field path %q", k)
			}
			if _, err := derive.Parse(v); err != nil {
				return fmt.Errorf("field %q: %v", k, err)
			}
			continue
		}
		plain[k] = v
	}
	if len(m) > 256 {
		return errors.New("too many fields")
	}
	return validateFieldValues(plain)
}

func sortedFieldKeys(m map[string]*derive.Expr) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validateFieldValues(m map[string]any) error {
	if len(m) > 256 {
		return errors.New("too many fields")
	}
	for k, v := range m {
		if !fieldPathRE.MatchString(k) {
			return fmt.Errorf("malformed field path %q", k)
		}
		switch v.(type) {
		case string, json.Number, bool, nil:
		default:
			return fmt.Errorf("field %q: value must be a scalar", k)
		}
	}
	return nil
}

func validateCausal(r *CausalRule, ents map[string]*Entity, services map[string]bool) error {
	if !services[r.Cause.Service] {
		return fmt.Errorf("unknown service %q", r.Cause.Service)
	}
	if !opRE.MatchString(r.Cause.Op) {
		return errors.New("malformed cause.op")
	}
	if len(r.Cause.When.Status) == 0 {
		return errors.New("cause.when.status is empty")
	}
	for _, s := range r.Cause.When.Status {
		if s < 100 || s > 599 {
			return errors.New("cause status out of range")
		}
	}
	for name, ref := range r.Cause.Bind {
		if !bindNameRE.MatchString(name) {
			return fmt.Errorf("malformed bind name %q", name)
		}
		if err := validateRef(ref); err != nil {
			return fmt.Errorf("bind %s: %v", name, err)
		}
	}
	if len(r.Effects) == 0 || len(r.Outcomes) == 0 {
		return errors.New("effects and outcomes are required")
	}
	byID := map[string]*Effect{}
	index := map[string]int{}
	for i := range r.Effects {
		e := &r.Effects[i]
		if !identRE.MatchString(e.ID) {
			return fmt.Errorf("malformed effect id %q", e.ID)
		}
		if byID[e.ID] != nil {
			return fmt.Errorf("duplicate effect %q", e.ID)
		}
		byID[e.ID] = e
		index[e.ID] = i
	}
	// refs[id] lists the effects whose ids an effect cites with ${effect:..}
	refs := map[string][]string{}
	for i := range r.Effects {
		e := &r.Effects[i]
		if e.Respond != nil {
			if e.Entity != "" || e.Create != nil || e.Target != "" || e.TargetID != "" || e.Set != nil || e.Remove || e.Where != nil {
				return fmt.Errorf("effect %s: respond excludes entity, create, target, target_id, set and where", e.ID)
			}
			if err := validateRespond(e.Respond, services); err != nil {
				return fmt.Errorf("effect %s: %v", e.ID, err)
			}
			if e.TargetKey != nil {
				return fmt.Errorf("effect %s: respond excludes target_key", e.ID)
			}
			if err := validateLimit(r, e.Respond); err != nil {
				return fmt.Errorf("effect %s: %v", e.ID, err)
			}
			if e.Respond.Until && (e.Respond.Times != 0 || e.Respond.Limit != nil || e.Respond.P != 0) {
				return fmt.Errorf("effect %s: until excludes times, limit and p", e.ID)
			}
			if e.TargetAll {
				return fmt.Errorf("effect %s: respond excludes target_all", e.ID)
			}
			continue
		}
		if e.TargetAll {
			if err := validateTargetAll(r, e); err != nil {
				return fmt.Errorf("effect %s: %v", e.ID, err)
			}
			if ents[e.Entity] == nil {
				return fmt.Errorf("effect %s: unknown entity %q", e.ID, e.Entity)
			}
			continue
		}
		if e.TargetKey != nil {
			if err := validateTargetKey(r, e, ents); err != nil {
				return fmt.Errorf("effect %s: %v", e.ID, err)
			}
		}
		if ents[e.Entity] == nil {
			return fmt.Errorf("effect %s: unknown entity %q", e.ID, e.Entity)
		}
		if e.Where != nil {
			if e.Create != nil || e.Remove {
				return fmt.Errorf("effect %s: where guards a target or target_id set", e.ID)
			}
			if err := validateFieldValues(e.Where); err != nil {
				return fmt.Errorf("effect %s: where: %v", e.ID, err)
			}
			for _, v := range e.Where {
				if s, ok := v.(string); ok && strings.Contains(s, "${") {
					return fmt.Errorf("effect %s: where takes literal values only", e.ID)
				}
			}
		}
		if e.Remove {
			targets := 0
			for _, has := range []bool{e.Target != "", e.TargetID != "", e.TargetKey != nil} {
				if has {
					targets++
				}
			}
			if e.Create != nil || e.Set != nil || targets != 1 {
				return fmt.Errorf("effect %s: remove takes target, target_id or target_key and no create or set", e.ID)
			}
			if e.TargetID != "" {
				m := bindRefRE.FindStringSubmatch(e.TargetID)
				if m == nil {
					return fmt.Errorf("effect %s: target_id must be ${variable}", e.ID)
				}
				if _, ok := r.Cause.Bind[m[1]]; !ok {
					return fmt.Errorf("effect %s: ${%s} is not bound by the cause", e.ID, m[1])
				}
			}
			continue
		}
		isCreate := e.Create != nil
		kinds := 0
		if isCreate {
			kinds++
		}
		if e.Target != "" {
			kinds++
		}
		if e.TargetID != "" {
			kinds++
		}
		if e.TargetKey != nil {
			kinds++
		}
		if kinds != 1 {
			return fmt.Errorf("effect %s: needs exactly one of create, target, target_id or target_key", e.ID)
		}
		if isCreate && e.Set != nil {
			return fmt.Errorf("effect %s: create excludes set", e.ID)
		}
		if !isCreate && e.Set == nil {
			return fmt.Errorf("effect %s: target and target_id need set", e.ID)
		}
		if e.TargetID != "" {
			m := bindRefRE.FindStringSubmatch(e.TargetID)
			if m == nil {
				return fmt.Errorf("effect %s: target_id must be ${variable}", e.ID)
			}
			if _, ok := r.Cause.Bind[m[1]]; !ok {
				return fmt.Errorf("effect %s: ${%s} is not bound by the cause", e.ID, m[1])
			}
		}
		if err := validateEffectValues(e.Create); err != nil {
			return fmt.Errorf("effect %s: %v", e.ID, err)
		}
		if err := validateEffectValues(e.Set); err != nil {
			return fmt.Errorf("effect %s: %v", e.ID, err)
		}
		for _, vals := range []map[string]any{e.Create, e.Set} {
			// derived values (rules 1.10, 3.15): variables bound, effects cited
			dv, _ := derive.ParseValues(vals)
			for _, k := range sortedFieldKeys(dv) {
				refs0 := dv[k].References()
				for _, name := range refs0.Vars {
					if _, ok := r.Cause.Bind[name]; !ok {
						return fmt.Errorf("effect %s: field %s: ${%s} is not bound by the cause", e.ID, k, name)
					}
				}
				refs[e.ID] = append(refs[e.ID], refs0.Effects...)
			}
			for _, v := range vals {
				s, ok := v.(string)
				if !ok || !strings.Contains(s, "${") {
					continue
				}
				if m := bindRefRE.FindStringSubmatch(s); m != nil {
					if _, ok := r.Cause.Bind[m[1]]; !ok {
						return fmt.Errorf("effect %s: ${%s} is not bound by the cause", e.ID, m[1])
					}
				} else if m := effectRefRE.FindStringSubmatch(s); m != nil {
					refs[e.ID] = append(refs[e.ID], m[1])
				} else if notRefRE.MatchString(s) && !isCreate {
					// rules v1.7: the opposite of a boolean of the target.
				} else {
					return fmt.Errorf("effect %s: a reference must be the whole string ${var} or ${effect:id}", e.ID)
				}
			}
		}
	}
	for _, e := range r.Effects {
		if e.AfterEffect != "" && byID[e.AfterEffect] == nil {
			return fmt.Errorf("effect %s: unknown after_effect %q", e.ID, e.AfterEffect)
		}
		if e.Target != "" {
			t := byID[e.Target]
			if t == nil || t == byID[e.ID] || t.Respond != nil || t.TargetAll {
				return fmt.Errorf("effect %s: unknown target %q", e.ID, e.Target)
			}
			if t.Entity != e.Entity {
				return fmt.Errorf("effect %s: target is of another entity", e.ID)
			}
		}
		// after_effect chains must not loop.
		cur, steps := e.AfterEffect, 0
		for cur != "" {
			if steps++; steps > len(r.Effects) {
				return fmt.Errorf("effect %s: after_effect cycle", e.ID)
			}
			cur = byID[cur].AfterEffect
		}
	}
	// ${effect:X}: X is an ancestor in the after_effect chain, listed earlier.
	for id, list := range refs {
		for _, x := range list {
			if byID[x] == nil || byID[x].Respond != nil || byID[x].TargetAll {
				return fmt.Errorf("effect %s: ${effect:%s} is unknown", id, x)
			}
			if index[x] >= index[id] {
				return fmt.Errorf("effect %s: ${effect:%s} must be listed before it", id, x)
			}
			anc := false
			for cur := byID[id].AfterEffect; cur != ""; cur = byID[cur].AfterEffect {
				if cur == x {
					anc = true
					break
				}
			}
			if !anc {
				return fmt.Errorf("effect %s: ${effect:%s} must be an ancestor in the after_effect chain", id, x)
			}
		}
	}
	var sum float64
	names := map[string]bool{}
	for _, o := range r.Outcomes {
		if !identRE.MatchString(o.Name) || names[o.Name] {
			return fmt.Errorf("malformed or duplicate outcome %q", o.Name)
		}
		names[o.Name] = true
		if o.P < 0 || o.P > 1 || math.IsNaN(o.P) {
			return fmt.Errorf("outcome %s: p out of range", o.Name)
		}
		sum += o.P
		in := map[string]bool{}
		for _, id := range o.Effects {
			if byID[id] == nil {
				return fmt.Errorf("outcome %s: unknown effect %q", o.Name, id)
			}
			in[id] = true
		}
		for _, id := range o.Effects {
			e := byID[id]
			needs := []string{e.AfterEffect, e.Target}
			needs = append(needs, refs[id]...)
			for _, n := range needs {
				if n != "" && !in[n] {
					return fmt.Errorf("outcome %s: effect %s needs %s in the same outcome", o.Name, id, n)
				}
			}
		}
	}
	if math.Abs(sum-1) > 0.001 {
		return fmt.Errorf("outcome probabilities sum to %g", sum)
	}
	return nil
}

func validateBatch(b *BatchRule, ents map[string]*Entity) error {
	if !scheduleRE.MatchString(b.Schedule) {
		return errors.New("malformed schedule")
	}
	if ents[b.Entity] == nil {
		return fmt.Errorf("unknown entity %q", b.Entity)
	}
	if err := validateFieldValues(b.Where); err != nil {
		return err
	}
	if len(b.Set) == 0 {
		return errors.New("set is empty")
	}
	if err := validateFieldValues(b.Set); err != nil {
		return err
	}
	if !(b.Fraction > 0 && b.Fraction <= 1) {
		return errors.New("fraction must be in (0, 1]")
	}
	return nil
}

// GraphQLVariableRef reports a request body reference to a top-level
// GraphQL variable ($.variables.id): the selector of a read of a GraphQL
// operation (rules.md 2.3, v1.14), the counterpart of a path parameter.
func GraphQLVariableRef(r Ref) bool {
	name, ok := strings.CutPrefix(r.Path, "$.variables.")
	return r.From == "req.body" && ok && refNameRE.MatchString(name)
}
