// Package gate runs the publication checks that block any artifact
// containing real data before it leaves zone B (docs/ARCHITECTURE.md 9,
// docs/spec/pack.md 7): provenance, reverse-HMAC pre-check by keyguard,
// PII detectors and k thresholds, in this order. It also measures residual
// re-identification risk (numbers, not guarantees: docs/THREAT_MODEL.md 7).
//
// Findings name a file and a JSON pointer (for world.jsonl
// "<line>:<pointer>") and a reason, never the value found.
//
// The admin API of packs (/api/v1/packs) is served by Mount with a
// PackService (implemented by internal/packwriter). Wiring in cmd/tt:
//
//	pw, _ := packwriter.New(packwriter.Options{...})
//	gate.Mount(srv, pw, logger)
package gate

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Check ids, in the order they run.
const (
	CheckProvenance  = "provenance"
	CheckReverseHMAC = "reverse-hmac"
	CheckPII         = "pii-detectors"
	CheckK           = "k-thresholds"
	// CheckRulesApproved is advisory: it warns (never fails) when the pack
	// carries no approved rule, which makes the twin a static mock.
	CheckRulesApproved = "rules-approved"
)

// Check statuses. Only StatusFail makes the verdict fail.
const (
	CheckPass = "pass"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// MaxFindings bounds the findings of one check.
const MaxFindings = 100

// Matcher is keyguard's reverse-HMAC check (*client.Client).
type Matcher interface {
	Match(ctx context.Context, policies []client.PolicyRef, candidates []client.Candidate) (*client.MatchResult, error)
}

// Provenance tags the values that may appear in a pack.
type Provenance struct {
	// Synthetic are values produced by a generator (world, examples,
	// presets).
	Synthetic map[string]bool
	// Declared are observed keep values (from the contracts) with the
	// number of distinct subjects behind each one.
	Declared map[string]int64
	// Text are texts written by people for the pack (preset names and
	// descriptions). Rule titles are taken from rules.json itself.
	Text map[string]bool
}

// ArchetypeSize is an archetype id with its number of real subjects.
type ArchetypeSize struct {
	ID   string
	Size int
}

// Input is a candidate pack.
type Input struct {
	PackID string
	KMin   int
	// Files are the pack files to check, by pack-relative path: contracts/*,
	// rules.json, world.jsonl, faults.json, scenarios.json. The manifest,
	// its signature and the gate report are not part of the input.
	Files map[string][]byte
	// ContractServices maps contract paths to service names (default: the
	// file name without .openapi.json).
	ContractServices map[string]string
	Prov             Provenance
	Archetypes       []ArchetypeSize
	// OutcomeSubjects: distinct subjects per rule id and outcome (optional).
	OutcomeSubjects map[string]map[string]int64
	// Combos: distinct subjects per published field combination of the
	// contracts (x-tt-dependencies), keyed like contract.ComboKey. When set,
	// a combination absent or below k_min fails k-thresholds.
	Combos   map[string]int64
	Policies []client.PolicyRef
	Matcher  Matcher
	// MatchBatch is the number of candidates per Match call (default 10000).
	MatchBatch int
	// Risk, optional, feeds the residual risk measures.
	Risk *RiskInput
}

// Finding locates a problem; it never carries the value.
type Finding struct {
	File    string `json:"file"`
	Pointer string `json:"pointer"`
	Reason  string `json:"reason"`
}

// Check is one check of the report.
type Check struct {
	ID             string    `json:"id"`
	Status         string    `json:"status"`
	Findings       []Finding `json:"findings"`
	StringsChecked *int64    `json:"strings_checked,omitempty"`
	By             string    `json:"by"`

	flaggedKeys map[string]bool // see renderPointers
}

// Report is gate-report.json (tt.gate-report/v1).
type Report struct {
	Format  string  `json:"format"`
	PackID  string  `json:"pack_id"`
	Verdict string  `json:"verdict"`
	KMin    int     `json:"k_min"`
	Checks  []Check `json:"checks"`
}

// Result is a gate run.
type Result struct {
	Report Report
	// Risk are the residual risk measures (not part of the pack).
	Risk *ResidualRisk
}

// Passed reports a pass verdict.
func (r *Result) Passed() bool { return r.Report.Verdict == "pass" }

// File renders gate-report.json in canonical JSON with a final newline.
func (r Report) File() []byte {
	checks := make([]ttjson.Value, 0, len(r.Checks))
	for _, c := range r.Checks {
		fs := make([]ttjson.Value, 0, len(c.Findings))
		for _, f := range c.Findings {
			fs = append(fs, ttjson.Obj(
				ttjson.Member{Key: "file", Value: ttjson.Str(f.File)},
				ttjson.Member{Key: "pointer", Value: ttjson.Str(f.Pointer)},
				ttjson.Member{Key: "reason", Value: ttjson.Str(f.Reason)}))
		}
		m := []ttjson.Member{
			{Key: "by", Value: ttjson.Str(c.By)},
			{Key: "findings", Value: ttjson.Arr(fs...)},
			{Key: "id", Value: ttjson.Str(c.ID)},
			{Key: "status", Value: ttjson.Str(c.Status)},
		}
		if c.StringsChecked != nil {
			m = append(m, ttjson.Member{Key: "strings_checked", Value: ttjson.Num(itoa(*c.StringsChecked))})
		}
		checks = append(checks, ttjson.Obj(m...))
	}
	v := ttjson.Obj(
		ttjson.Member{Key: "checks", Value: ttjson.Arr(checks...)},
		ttjson.Member{Key: "format", Value: ttjson.Str("tt.gate-report/v1")},
		ttjson.Member{Key: "k_min", Value: ttjson.Num(itoa(int64(r.KMin)))},
		ttjson.Member{Key: "pack_id", Value: ttjson.Str(r.PackID)},
		ttjson.Member{Key: "verdict", Value: ttjson.Str(r.Verdict)},
	)
	b, _ := ttjson.Encode(v)
	return append(b, '\n')
}

// findings collects findings of one check, bounded.
type findings struct {
	list []Finding
	seen map[Finding]bool
	n    int
	keys map[string]bool // keys that are the subject of a finding (kept past MaxFindings)
}

func (f *findings) add(file, ptr, reason string) {
	f.n++
	if k, ok := keyOf(ptr); ok {
		if f.keys == nil {
			f.keys = map[string]bool{}
		}
		f.keys[k] = true
	}
	fd := Finding{File: file, Pointer: ptr, Reason: reason}
	if f.seen == nil {
		f.seen = map[Finding]bool{}
	}
	if len(f.list) >= MaxFindings || f.seen[fd] {
		return
	}
	f.seen[fd] = true
	f.list = append(f.list, fd)
}

func (f *findings) check(id, by string) Check {
	c := Check{ID: id, Status: "pass", Findings: f.list, By: by, flaggedKeys: f.keys}
	if c.Findings == nil {
		c.Findings = []Finding{}
	}
	if f.n > 0 {
		c.Status = "fail"
	}
	return c
}

// parsed is a pack file decoded for the checks.
type parsed struct {
	path  string
	kind  string // contract, rules, world, faults, scenarios, unknown
	doc   ttjson.Value
	lines []ttjson.Value // world.jsonl
	bad   bool
}

func kindOf(path string) string {
	switch {
	case strings.HasPrefix(path, "contracts/") && strings.HasSuffix(path, ".json"):
		return "contract"
	case path == "rules.json":
		return "rules"
	case path == "world.jsonl":
		return "world"
	case path == "faults.json":
		return "faults"
	case path == "scenarios.json":
		return "scenarios"
	}
	return "unknown"
}

var parseOpts = ttjson.ParseOptions{MaxDepth: 128, RejectDuplicates: true}

func parseFiles(files map[string][]byte) []*parsed {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []*parsed
	for _, n := range names {
		p := &parsed{path: n, kind: kindOf(n)}
		data := files[n]
		if p.kind == "world" {
			for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				v, err := ttjson.Parse([]byte(line), parseOpts)
				if err != nil {
					p.bad = true
					break
				}
				p.lines = append(p.lines, v)
			}
		} else {
			v, err := ttjson.Parse(data, parseOpts)
			p.doc, p.bad = v, err != nil
		}
		out = append(out, p)
	}
	return out
}

// Run runs every check in order and returns the report. It fails only if
// a check cannot be run (keyguard unreachable): a pack that cannot be
// checked is never passed.
func Run(ctx context.Context, in *Input) (*Result, error) {
	if in.KMin < 2 {
		return nil, errors.New("gate: k_min must be >= 2")
	}
	if in.Matcher == nil {
		return nil, errors.New("gate: keyguard is required for the reverse-HMAC check")
	}
	if len(in.Policies) == 0 {
		return nil, errors.New("gate: the source policies are required for the reverse-HMAC check")
	}
	files := parseFiles(in.Files)
	ctxs := buildContext(files, in)
	checks := []Check{provenance(files, ctxs, in)}
	rh, err := reverseHMAC(ctx, files, in)
	if err != nil {
		return nil, err
	}
	checks = append(checks, rh, piiCheck(files, in), kCheck(files, ctxs, in), rulesApprovedCheck(files))
	renderPointers(checks)
	verdict := "pass"
	for _, c := range checks {
		if c.Status != CheckPass && c.Status != CheckWarn {
			verdict = "fail"
		}
	}
	res := &Result{Report: Report{Format: "tt.gate-report/v1", PackID: in.PackID, Verdict: verdict, KMin: in.KMin, Checks: checks}}
	if in.Risk != nil {
		res.Risk = Measure(in.Risk, in.KMin)
	}
	return res, nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func escapePointer(s string) string {
	r := strings.NewReplacer("~", "~0", "/", "~1", "\x00", "~2", "\x01", "~3")
	return r.Replace(s)
}

func unescapePointer(s string) string {
	r := strings.NewReplacer("~0", "~", "~1", "/", "~2", "\x00", "~3", "\x01")
	return r.Replace(s)
}

// Internal pointers: walk writes each object key segment as
// "<escaped key>\x00<member index>" and ends the pointer of a key visit with
// keyMark. Findings keep that form until Run renders them (renderPointers):
// a key that is itself the subject of a finding (a reverse-HMAC positive, a
// PII-looking or unknown key, a key without provenance) is never written
// into any pointer of the report; it becomes "@k<n>", the n-th member
// (0-based) of its parent object. So neither the key nor a finding below it
// ("/<real id>/status") carries a value.
const keyMark = "\x01"

func renderPointer(ptr string, redact map[string]bool) string {
	ptr = strings.TrimSuffix(ptr, keyMark)
	parts := strings.Split(ptr, "/")
	for i, seg := range parts {
		esc, idx, ok := strings.Cut(seg, "\x00")
		if !ok {
			continue
		}
		if redact[unescapePointer(esc)] {
			parts[i] = "@k" + idx
		} else {
			parts[i] = esc
		}
	}
	return strings.Join(parts, "/")
}

// keyOf returns the (unescaped) key a key-visit pointer ends with.
func keyOf(ptr string) (string, bool) {
	if !strings.HasSuffix(ptr, keyMark) {
		return "", false
	}
	ptr = strings.TrimSuffix(ptr, keyMark)
	seg := ptr[strings.LastIndexByte(ptr, '/')+1:]
	esc, _, ok := strings.Cut(seg, "\x00")
	return unescapePointer(esc), ok
}

// renderPointers renders the internal pointers of every finding, redacting
// the keys flagged by any check (see keyMark).
func renderPointers(checks []Check) {
	redact := map[string]bool{}
	for _, c := range checks {
		for k := range c.flaggedKeys {
			redact[k] = true
		}
	}
	for ci := range checks {
		for fi := range checks[ci].Findings {
			checks[ci].Findings[fi].Pointer = renderPointer(checks[ci].Findings[fi].Pointer, redact)
		}
	}
}

// visit walks a value with its JSON pointer and the keys from the root.
type visitFn func(v ttjson.Value, ptr string, keys []string, isKey bool)

func walk(v ttjson.Value, ptr string, keys []string, fn visitFn) {
	fn(v, ptr, keys, false)
	switch v.Kind {
	case ttjson.Array:
		for i, e := range v.Arr {
			walk(e, ptr+"/"+itoa(int64(i)), with(keys, "[]"), fn)
		}
	case ttjson.Object:
		for i, m := range v.Obj {
			p := ptr + "/" + escapePointer(m.Key) + "\x00" + itoa(int64(i))
			fn(ttjson.Str(m.Key), p+keyMark, keys, true)
			walk(m.Value, p, with(keys, m.Key), fn)
		}
	}
}

// each walks every file (world line by line, pointers "<line>:<ptr>").
func each(p *parsed, fn func(v ttjson.Value, ptr string, keys []string, isKey bool)) {
	if p.kind == "world" {
		for i, l := range p.lines {
			pre := itoa(int64(i+1)) + ":"
			walk(l, pre, nil, fn)
		}
		return
	}
	walk(p.doc, "", nil, fn)
}

func with(keys []string, k string) []string {
	out := make([]string, len(keys)+1)
	copy(out, keys)
	out[len(keys)] = k
	return out
}

func last(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return keys[len(keys)-1]
}

func has(keys []string, set map[string]bool) bool {
	for _, k := range keys {
		if set[k] {
			return true
		}
	}
	return false
}

// rulesApprovedCheck warns when the pack has no approved rule. A twin
// without rules answers every request but never evolves state (orders stay
// as created), so the publisher should see it before releasing the pack.
func rulesApprovedCheck(files []*parsed) Check {
	n := 0
	for _, p := range files {
		if p.kind == "rules" && !p.bad {
			rules, _ := p.doc.Get("rules")
			n += len(rules.Arr)
		}
	}
	c := Check{ID: CheckRulesApproved, Status: CheckPass, Findings: []Finding{}, By: "tt-core"}
	if n == 0 {
		c.Status = CheckWarn
		c.Findings = []Finding{{File: "rules.json", Pointer: "/rules", Reason: "no approved rules: the mock will not evolve state over time"}}
	}
	return c
}
