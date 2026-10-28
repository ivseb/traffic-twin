// Package derive implements the derived values of rules 1.10
// (docs/spec/rules.md 3.15): a create/set value written as
//
//	{"$derive": {"fn": "sum", "args": ["${field:items[*].price}"]}}
//
// is computed when the effect applies, from the variables of the cause, the
// entity's own fields, the virtual clock and the id formats. The same code is
// used by the pack loader (validation), the miner (checks against the
// contracts), the world generator and the mock, so they agree byte for byte.
package derive

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

// Key is the only key of a derived value object.
const Key = "$derive"

// Functions.
const (
	FnCopy     = "copy"
	FnSum      = "sum"
	FnCount    = "count"
	FnAdd      = "add"
	FnSub      = "sub"
	FnMul      = "mul"
	FnDiv      = "div"
	FnMin      = "min"
	FnMax      = "max"
	FnRound    = "round"
	FnDate     = "date"
	FnTemplate = "template"
)

// Fns lists the functions in a stable order (for messages and the console).
var Fns = []string{FnCopy, FnSum, FnCount, FnAdd, FnSub, FnMul, FnDiv, FnMin, FnMax, FnRound, FnDate, FnTemplate}

// MaxDepth bounds the nesting of derived values inside arguments.
const MaxDepth = 4

// Expr is a parsed derived value.
type Expr struct {
	Fn string `json:"fn"`
	// Args are numbers, references ("${var}", "${field:path}",
	// "${effect:id}", "${now}") or nested {"$derive": ...} values.
	Args []any `json:"args,omitempty"`
	// Offset is the offset of a date ("+30d", "-12h"); Format "date" or
	// "date-time" (default).
	Offset string `json:"offset,omitempty"`
	Format string `json:"format,omitempty"`
	// Template is an id format (docs/spec/pack.md 4.3) for FnTemplate.
	Template string `json:"template,omitempty"`
	// Digits are the decimals of FnRound (0-6, default 2).
	Digits *int `json:"digits,omitempty"`

	args []arg
	tpl  *idfmt.Template
	off  time.Duration
}

// arg is a compiled argument.
type arg struct {
	kind  string // num, var, field, effect, now, str, expr
	num   float64
	lit   any
	name  string
	segs  []fieldSeg
	inner *Expr
}

type fieldSeg struct {
	name string
	all  bool // [*]
}

var (
	varRE    = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]{0,31})\}$`)
	effectRE = regexp.MustCompile(`^\$\{effect:([a-z][a-z0-9_-]{0,63})\}$`)
	fieldRE  = regexp.MustCompile(`^\$\{field:([A-Za-z_][A-Za-z0-9_]{0,63}(?:\[\*\])?(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}(?:\[\*\])?){0,7})\}$`)
	offsetRE = regexp.MustCompile(`^[+-]?[0-9]{1,6}(s|m|h|d)$`)
)

// Is reports whether v is a derived value object ({"$derive": ...}).
func Is(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, ok = m[Key]
	return ok
}

// Parse compiles a derived value object. The error names the problem
// without values.
func Parse(v any) (*Expr, error) { return parse(v, 0) }

func parse(v any, depth int) (*Expr, error) {
	if depth > MaxDepth {
		return nil, errors.New("derived values nested too deeply")
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, errors.New(`a derived value is an object with the only key "$derive"`)
	}
	raw, ok := m[Key]
	if !ok {
		return nil, errors.New(`a derived value is an object with the only key "$derive"`)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	e := &Expr{}
	if err := dec.Decode(e); err != nil {
		return nil, fmt.Errorf("derived value: %v", err)
	}
	if err := e.compile(depth); err != nil {
		return nil, err
	}
	return e, nil
}

// ParseOffset parses "+30d", "-12h", "90m", "45s".
func ParseOffset(s string) (time.Duration, error) {
	if !offsetRE.MatchString(s) {
		return 0, fmt.Errorf("offset must look like +30d, -12h, 90m or 45s")
	}
	sign := time.Duration(1)
	switch s[0] {
	case '-':
		sign, s = -1, s[1:]
	case '+':
		s = s[1:]
	}
	n, _ := strconv.Atoi(s[:len(s)-1])
	unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}[s[len(s)-1]]
	return sign * time.Duration(n) * unit, nil
}

func (e *Expr) compile(depth int) error {
	n := len(e.Args)
	need := func(lo, hi int) error {
		if n < lo || (hi >= 0 && n > hi) {
			if hi == lo {
				return fmt.Errorf("%s takes %d argument(s)", e.Fn, lo)
			}
			if hi < 0 {
				return fmt.Errorf("%s takes at least %d argument(s)", e.Fn, lo)
			}
			return fmt.Errorf("%s takes %d to %d argument(s)", e.Fn, lo, hi)
		}
		return nil
	}
	var err error
	switch e.Fn {
	case FnCopy, FnCount:
		err = need(1, 1)
	case FnSum:
		err = need(1, 8)
	case FnAdd, FnMul, FnMin, FnMax:
		err = need(2, 8)
	case FnSub, FnDiv:
		err = need(2, 2)
	case FnRound:
		err = need(1, 1)
		if e.Digits != nil && (*e.Digits < 0 || *e.Digits > 6) {
			err = errors.New("round digits must be 0 to 6")
		}
	case FnDate:
		err = need(0, 1)
		if err == nil {
			if e.Offset == "" {
				e.Offset = "+0d"
			}
			e.off, err = ParseOffset(e.Offset)
		}
		if err == nil && e.Format != "" && e.Format != "date" && e.Format != "date-time" {
			err = errors.New(`date format must be "date" or "date-time"`)
		}
	case FnTemplate:
		err = need(0, 0)
		if err == nil {
			e.tpl, err = idfmt.Parse(e.Template)
		}
	default:
		return fmt.Errorf("unknown function %q (one of %s)", e.Fn, strings.Join(Fns, ", "))
	}
	if err != nil {
		return err
	}
	if e.Fn != FnDate && (e.Offset != "" || e.Format != "") {
		return fmt.Errorf("offset and format are only for date")
	}
	if e.Fn != FnTemplate && e.Template != "" {
		return fmt.Errorf("template is only for the template function")
	}
	if e.Fn != FnRound && e.Digits != nil {
		return fmt.Errorf("digits are only for round")
	}
	for i, a := range e.Args {
		c, err := compileArg(a, depth)
		if err != nil {
			return fmt.Errorf("argument %d: %v", i+1, err)
		}
		if c.kind == "str" && e.Fn != FnCopy {
			return fmt.Errorf("argument %d: a text is only an argument of copy", i+1)
		}
		e.args = append(e.args, c)
	}
	return nil
}

func compileArg(a any, depth int) (arg, error) {
	switch x := a.(type) {
	case json.Number:
		f, err := x.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return arg{}, errors.New("not a finite number")
		}
		return arg{kind: "num", num: f, lit: x}, nil
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return arg{}, errors.New("not a finite number")
		}
		return arg{kind: "num", num: x, lit: json.Number(strconv.FormatFloat(x, 'f', -1, 64))}, nil
	case string:
		switch {
		case x == "${now}":
			return arg{kind: "now"}, nil
		case varRE.MatchString(x):
			return arg{kind: "var", name: varRE.FindStringSubmatch(x)[1]}, nil
		case effectRE.MatchString(x):
			return arg{kind: "effect", name: effectRE.FindStringSubmatch(x)[1]}, nil
		case fieldRE.MatchString(x):
			p := fieldRE.FindStringSubmatch(x)[1]
			var segs []fieldSeg
			for _, s := range strings.Split(p, ".") {
				name, all := strings.CutSuffix(s, "[*]")
				segs = append(segs, fieldSeg{name: name, all: all})
			}
			return arg{kind: "field", name: p, segs: segs}, nil
		case strings.HasPrefix(x, "${"):
			return arg{}, errors.New("unknown reference (use ${var}, ${field:path}, ${effect:id} or ${now})")
		}
		return arg{kind: "str", lit: x}, nil
	case map[string]any:
		in, err := parse(x, depth+1)
		if err != nil {
			return arg{}, err
		}
		return arg{kind: "expr", inner: in}, nil
	}
	return arg{}, errors.New("an argument is a number, a reference or a derived value")
}

// Refs are the references of an expression, for the checks against the
// rule and the contracts.
type Refs struct {
	Vars    []string
	Fields  []string // dotted paths, [*] removed
	Effects []string
}

// References lists the references of e and its nested values.
func (e *Expr) References() Refs {
	var r Refs
	var walk func(e *Expr)
	walk = func(e *Expr) {
		for _, a := range e.args {
			switch a.kind {
			case "var":
				r.Vars = append(r.Vars, a.name)
			case "field":
				r.Fields = append(r.Fields, strings.ReplaceAll(a.name, "[*]", ""))
			case "effect":
				r.Effects = append(r.Effects, a.name)
			case "expr":
				walk(a.inner)
			}
		}
		if e.tpl != nil {
			r.Fields = append(r.Fields, e.tpl.Refs()...)
		}
	}
	walk(e)
	return r
}

// ResultType is the JSON type of the result: number, string or any (copy).
func (e *Expr) ResultType() string {
	switch e.Fn {
	case FnCopy:
		return "any"
	case FnDate, FnTemplate:
		return "string"
	}
	return "number"
}

// Env is what an expression reads when it is evaluated.
type Env struct {
	// Var is a variable of the cause (bind); Field the values of the
	// entity at a dotted path; Effect the id of an earlier effect.
	Var    func(name string) (any, bool)
	Object map[string]any
	Effect func(id string) (string, bool)
	// Now is the virtual instant the effect applies at.
	Now time.Time
	// Scope and Seq number the ids of a template: Seq(scope) is the n-th
	// value of that scope (rule, effect and field).
	Scope string
	Seq   func(scope string) uint64
}

// ErrMissing is returned when a reference has no value: the field is then
// left out, like an unresolved "${var}".
var ErrMissing = errors.New("derived value: a reference has no value")

// Eval computes the value.
func (e *Expr) Eval(env Env) (any, error) {
	switch e.Fn {
	case FnCopy:
		vs, err := e.vals(e.args[0], env)
		if err != nil {
			return nil, err
		}
		if len(vs) == 1 {
			return vs[0], nil
		}
		return vs, nil
	case FnCount:
		vs, err := e.vals(e.args[0], env)
		if err != nil && !errors.Is(err, ErrMissing) {
			return nil, err
		}
		n := len(vs)
		if len(vs) == 1 {
			if arr, ok := vs[0].([]any); ok {
				n = len(arr)
			}
		}
		return Number(float64(n)), nil
	case FnDate:
		base := env.Now
		if len(e.args) == 1 {
			vs, err := e.vals(e.args[0], env)
			if err != nil {
				return nil, err
			}
			if len(vs) != 1 {
				return nil, ErrMissing
			}
			s, _ := vs[0].(string)
			t, ok := parseTime(s)
			if !ok {
				return nil, fmt.Errorf("derived value: the base of a date is not a date")
			}
			base = t
		}
		t := base.Add(e.off).UTC()
		if e.Format == "date" {
			return t.Format("2006-01-02"), nil
		}
		return t.Format(time.RFC3339), nil
	case FnTemplate:
		n := uint64(1)
		if env.Seq != nil {
			n = env.Seq(env.Scope)
		}
		return e.tpl.ID(n, env.Scope, idfmt.MapRef(env.Object)), nil
	}
	var nums []float64
	for _, a := range e.args {
		vs, err := e.vals(a, env)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			if arr, ok := v.([]any); ok && e.Fn == FnSum {
				for _, x := range arr {
					f, ok := toFloat(x)
					if !ok {
						return nil, errors.New("derived value: sum of a value that is not a number")
					}
					nums = append(nums, f)
				}
				continue
			}
			f, ok := toFloat(v)
			if !ok {
				return nil, fmt.Errorf("derived value: %s of a value that is not a number", e.Fn)
			}
			nums = append(nums, f)
		}
		if e.Fn != FnSum && len(vs) != 1 {
			return nil, fmt.Errorf("derived value: %s needs one value per argument", e.Fn)
		}
	}
	var r float64
	switch e.Fn {
	case FnSum, FnAdd:
		for _, f := range nums {
			r += f
		}
	case FnSub:
		r = nums[0] - nums[1]
	case FnMul:
		r = 1
		for _, f := range nums {
			r *= f
		}
	case FnDiv:
		if nums[1] == 0 {
			return nil, errors.New("derived value: division by zero")
		}
		r = nums[0] / nums[1]
	case FnMin, FnMax:
		r = nums[0]
		for _, f := range nums[1:] {
			if (e.Fn == FnMin && f < r) || (e.Fn == FnMax && f > r) {
				r = f
			}
		}
	case FnRound:
		d := 2
		if e.Digits != nil {
			d = *e.Digits
		}
		p := math.Pow(10, float64(d))
		r = math.Round(nums[0]*p) / p
	}
	if math.IsInf(r, 0) || math.IsNaN(r) {
		return nil, errors.New("derived value: result is not a finite number")
	}
	return Number(r), nil
}

// vals resolves an argument to its values (several for a [*] field).
func (e *Expr) vals(a arg, env Env) ([]any, error) {
	switch a.kind {
	case "num", "str":
		return []any{a.lit}, nil
	case "now":
		return []any{env.Now.UTC().Format(time.RFC3339)}, nil
	case "var":
		if env.Var != nil {
			if v, ok := env.Var(a.name); ok {
				return []any{v}, nil
			}
		}
		return nil, ErrMissing
	case "effect":
		if env.Effect != nil {
			if id, ok := env.Effect(a.name); ok {
				return []any{id}, nil
			}
		}
		return nil, ErrMissing
	case "field":
		vs := fieldValues(env.Object, a.segs)
		if len(vs) == 0 {
			return nil, ErrMissing
		}
		return vs, nil
	case "expr":
		v, err := a.inner.Eval(env)
		if err != nil {
			return nil, err
		}
		return []any{v}, nil
	}
	return nil, ErrMissing
}

func fieldValues(obj map[string]any, segs []fieldSeg) []any {
	cur := []any{obj}
	for _, s := range segs {
		var next []any
		for _, c := range cur {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			v, ok := m[s.name]
			if !ok {
				continue
			}
			if s.all {
				if arr, ok := v.([]any); ok {
					next = append(next, arr...)
				}
				continue
			}
			next = append(next, v)
		}
		cur = next
	}
	return cur
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	return 0, false
}

func parseTime(s string) (time.Time, bool) {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Number renders a result: integers without decimals, other values with at
// most 9 decimals (no binary noise such as 0.30000000000000004).
func Number(f float64) json.Number {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return json.Number(strconv.FormatInt(int64(f), 10))
	}
	return json.Number(strconv.FormatFloat(math.Round(f*1e9)/1e9, 'f', -1, 64))
}

// ParseValues compiles every derived value of a create/set map, keyed by
// field. A map without derived values gives nil.
func ParseValues(m map[string]any) (map[string]*Expr, error) {
	var out map[string]*Expr
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !Is(m[k]) {
			continue
		}
		e, err := Parse(m[k])
		if err != nil {
			return nil, fmt.Errorf("field %q: %v", k, err)
		}
		if out == nil {
			out = map[string]*Expr{}
		}
		out[k] = e
	}
	return out, nil
}

// Resolve computes the values of a create/set map for one application of an
// effect: the literal values first (lit resolves "${var}" and
// "${effect:id}"; ok false leaves the field out), then the derived values
// in key order, each one seeing the object with every value computed before
// it (state plus the map's values). A derived value whose reference has no
// value, or whose computation fails, is left out. setPath writes a dotted
// path into an object. The result maps each field to its value.
func Resolve(values map[string]any, state map[string]any, env Env, lit func(any) (any, bool), setPath func(map[string]any, string, any)) map[string]any {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	work := copyMap(state)
	out := map[string]any{}
	for _, k := range keys {
		if Is(values[k]) {
			continue
		}
		if v, ok := lit(values[k]); ok {
			out[k] = v
			setPath(work, k, copyAny(v))
		}
	}
	scope := env.Scope
	for _, k := range keys {
		if !Is(values[k]) {
			continue
		}
		e, err := Parse(values[k])
		if err != nil {
			continue
		}
		env.Object, env.Scope = work, scope+"/"+k
		v, err := e.Eval(env)
		if err != nil {
			continue
		}
		out[k] = v
		setPath(work, k, copyAny(v))
	}
	return out
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = copyAny(v)
	}
	return out
}

func copyAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return copyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = copyAny(e)
		}
		return out
	}
	return v
}
