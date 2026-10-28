// Package packwriter assembles twin packs (docs/spec/pack.md v1.2): k-filtered
// contracts, approved rules, the synthetic world, faults from observed
// statistics, scenario presets, the gate report and the manifest with
// hashes. It runs the publication gate, asks tt keyguard to sign, and
// verifies the result with internal/pack before declaring success.
//
// Assemble is pure and deterministic: the same inputs, pack id and creation
// instant give the same bytes for every file and for the archive.
package packwriter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/world"
)

// File names of the pack.
const (
	ManifestPath   = "manifest.json"
	SignaturePath  = "manifest.sig.json"
	RulesPath      = "rules.json"
	WorldPath      = "world.jsonl"
	FaultsPath     = "faults.json"
	ScenariosPath  = "scenarios.json"
	GateReportPath = "gate-report.json"
)

// Assembly is everything a pack is made of.
type Assembly struct {
	PackID    string
	CreatedAt time.Time
	// NotAfter, optional, ends the validity of the pack (pack.md 2.1).
	NotAfter  *time.Time
	KMin      int
	TTVersion string
	Window    [2]time.Time
	Policies  []client.PolicyRef
	// Contracts of the services in the pack.
	Contracts []world.Contract
	// Rules: the approved rules of the world, and the rule set they came from.
	Rules   *world.Rules
	RuleSet *world.RuleSet
	World   *world.Output
	Seed    uint64
	// Presets: derived and stored scenario presets. Stored presets'
	// texts are listed in PresetTexts.
	Presets     []world.Preset
	PresetTexts []string
	Faults      *Faults
	// Anonymize replaces external host names with aliases (M16).
	Anonymize  bool
	Archetypes []world.Archetype
	// Group is the group of a single-group pack (manifest group, pack.md 2).
	Group string
}

// Assembled is an assembled pack before the gate.
type Assembled struct {
	// Files are the content files (no manifest, signature, gate report).
	Files map[string][]byte
	// ContractServices maps contract paths to their service names.
	ContractServices map[string]string
	Prov             gate.Provenance
	OutcomeSubjects  map[string]map[string]int64
	// Combos are the published field combinations of the contracts
	// (x-tt-dependencies) with their distinct subjects, for the gate; nil
	// when no contract carries them (the gate then checks the values only).
	Combos   map[string]int64
	services []manifestService
	a        *Assembly
}

type manifestService struct {
	Name, Contract, Alias string
}

var fileNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func contractPath(name string) string {
	n := strings.Trim(fileNameRE.ReplaceAllString(name, "-"), "-.")
	if n == "" {
		n = "service"
	}
	return "contracts/" + n + ".openapi.json"
}

// Assemble builds the content files and the provenance tags.
func Assemble(a *Assembly) (*Assembled, error) {
	if a.KMin < 2 {
		return nil, errors.New("packwriter: k_min must be >= 2")
	}
	if a.Rules == nil || a.World == nil {
		return nil, errors.New("packwriter: rules and world are required")
	}
	out := &Assembled{Files: map[string][]byte{}, ContractServices: map[string]string{}, a: a,
		Prov: gate.Provenance{Synthetic: map[string]bool{}, Declared: map[string]int64{}, Text: map[string]bool{}}}
	ruleLits := ruleLiterals(a.Rules.Doc)

	// Service names: external hosts become aliases when anonymizing.
	rename := map[string]string{}
	ext := 0
	cs := append([]world.Contract(nil), a.Contracts...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].Service < cs[j].Service })
	for _, c := range cs {
		if a.Anonymize && strings.HasPrefix(c.Service, "host:") {
			ext++
			alias := c.Alias
			if alias == "" {
				alias = fmt.Sprintf("ext-%d", ext)
			}
			rename[c.Service] = alias
		}
	}
	name := func(s string) string {
		if n, ok := rename[s]; ok {
			return n
		}
		return s
	}
	usedPaths := map[string]bool{}
	for _, c := range cs {
		for v, n := range c.Declared {
			if n > out.Prov.Declared[v] {
				out.Prov.Declared[v] = n
			}
		}
		for _, s := range c.Synthetic {
			out.Prov.Synthetic[s] = true
		}
		for key, n := range c.Combos {
			if out.Combos == nil {
				out.Combos = map[string]int64{}
			}
			if n > out.Combos[key] {
				out.Combos[key] = n
			}
		}
		var doc map[string]any
		if err := world.DecodeGeneric(c.Doc, &doc); err != nil {
			return nil, fmt.Errorf("packwriter: contract %s is not JSON", c.Service)
		}
		filterContract(doc, c.Declared, ruleLits, int64(a.KMin), a.Anonymize)
		b, err := world.CanonicalFile(doc)
		if err != nil {
			return nil, err
		}
		n := name(c.Service)
		p := contractPath(n)
		if usedPaths[p] {
			return nil, fmt.Errorf("packwriter: two services map to %s", p)
		}
		usedPaths[p] = true
		out.Files[p] = b
		out.ContractServices[p] = n
		ms := manifestService{Name: n, Contract: p}
		if a.Anonymize && c.External && c.Alias != "" && rename[c.Service] == "" && c.Alias != n {
			ms.Alias = c.Alias
		}
		out.services = append(out.services, ms)
	}
	sort.Slice(out.services, func(i, j int) bool { return out.services[i].Name < out.services[j].Name })

	// Rules: approved only, review removed, small counts suppressed.
	rdoc := deepCopy(a.Rules.Doc).(map[string]any)
	out.OutcomeSubjects = map[string]map[string]int64{}
	if a.RuleSet != nil && a.RuleSet.OutcomeSubjects != nil {
		for r, m := range a.RuleSet.OutcomeSubjects {
			out.OutcomeSubjects[r] = m
		}
	}
	rules, _ := rdoc["rules"].([]any)
	for _, x := range rules {
		r, _ := x.(map[string]any)
		delete(r, "review")
		id, _ := r["id"].(string)
		ev, _ := r["evidence"].(map[string]any)
		if _, given := out.OutcomeSubjects[id]; !given {
			if cnt, ok := ev["counts"].(map[string]any); ok {
				if ocs, ok := cnt["outcomes"].(map[string]any); ok {
					m := map[string]int64{}
					for k, v := range ocs {
						if n, err := strconv.ParseInt(fmt.Sprint(v), 10, 64); err == nil {
							m[k] = n
						}
					}
					out.OutcomeSubjects[id] = m
				}
			}
		}
		suppressCounts(ev, int64(a.KMin))
	}
	renameServices(rdoc, rename)
	rb, err := world.CanonicalFile(rdoc)
	if err != nil {
		return nil, err
	}
	out.Files[RulesPath] = rb

	out.Files[WorldPath] = a.World.World
	for _, s := range a.World.Synthetic {
		out.Prov.Synthetic[s] = true
	}

	faults := a.Faults
	if faults == nil {
		faults = &Faults{}
	}
	fb, err := faults.file(name)
	if err != nil {
		return nil, err
	}
	out.Files[FaultsPath] = fb

	presets := append([]world.Preset(nil), a.Presets...)
	for i := range presets {
		if f, ok := presets[i].Faults["rules"].([]any); ok {
			for _, x := range f {
				if m, ok := x.(map[string]any); ok {
					if s, ok := m["service"].(string); ok {
						m["service"] = name(s)
					}
				}
			}
		}
	}
	texts := map[string]bool{}
	for _, t := range a.PresetTexts {
		texts[t] = true
	}
	for _, p := range presets {
		for _, s := range p.Strings() {
			if s == "" {
				continue
			}
			if texts[s] {
				out.Prov.Text[s] = true
			} else {
				out.Prov.Synthetic[s] = true
			}
		}
	}
	sb, err := world.ScenariosFile(presets)
	if err != nil {
		return nil, err
	}
	out.Files[ScenariosPath] = sb
	return out, nil
}

// ruleLiterals are the literal values of the approved rules' field values.
func ruleLiterals(doc map[string]any) map[string]bool {
	out := map[string]bool{}
	var walk func(v any, inFV bool)
	walk = func(v any, inFV bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(e, inFV || k == "create" || k == "set" || k == "defaults" || k == "where" || k == "hidden_when")
			}
		case []any:
			for _, e := range x {
				walk(e, inFV)
			}
		case string:
			if inFV && !strings.HasPrefix(x, "${") {
				out[x] = true
			}
		}
	}
	walk(doc, false)
	// rules v1.9: the values of the customer attributes are clear values
	// of the rules too (the world's profiles carry them).
	if attrs, ok := doc["attributes"].([]any); ok {
		for _, a := range attrs {
			if m, ok := a.(map[string]any); ok {
				if vals, ok := m["values"].(map[string]any); ok {
					for v := range vals {
						out[v] = true
					}
				}
			}
		}
	}
	return out
}

func lexeme(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "null"
	}
	return fmt.Sprint(v)
}

// filterContract applies the k rule of pack.md 4.1 to enums and counts.
func filterContract(v any, declared map[string]int64, ruleLits map[string]bool, k int64, anonymize bool) {
	keep := func(x any) bool {
		s := lexeme(x)
		n, ok := declared[s]
		if ok {
			return n >= k
		}
		_, isStr := x.(string)
		return isStr && ruleLits[s]
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if anonymize {
				delete(x, "servers")
			}
			if en, ok := x["enum"].([]any); ok {
				var kept []any
				for _, e := range en {
					if keep(e) {
						kept = append(kept, e)
					}
				}
				if len(kept) < len(en) {
					if x["kind"] == "enum" {
						x["enum_partial"] = true
					}
					if len(kept) == 0 && x["kind"] != "enum" {
						delete(x, "enum")
					} else {
						if kept == nil {
							kept = []any{}
						}
						x["enum"] = kept
					}
				}
			}
			if deps, ok := x["x-tt-dependencies"].([]any); ok {
				if kept := filterDeps(deps, keep, k); len(kept) > 0 {
					x["x-tt-dependencies"] = kept
				} else {
					delete(x, "x-tt-dependencies")
				}
			}
			if obs, ok := x["x-tt-observed"].(map[string]any); ok {
				if n, err := strconv.ParseInt(lexeme(obs["calls"]), 10, 64); err == nil && n > 0 && n < k {
					obs["calls"] = json.Number("0")
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
}

// filterDeps applies the k rule to the field dependencies: a combination
// with a keep value below k, or a size class below k, is removed (the
// dependency becomes partial), a dependency left without combinations is
// removed. at_least is rewritten as the pack's size class (contract.AtLeast
// with the pack's k: the contract may have used a different k_min), so it is
// never an exact count.
func filterDeps(deps []any, keep func(any) bool, k int64) []any {
	var out []any
	for _, d := range deps {
		dm, _ := d.(map[string]any)
		cs, _ := dm["combinations"].([]any)
		var kept []any
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			vals, _ := cm["values"].([]any)
			ok := len(vals) > 0
			for _, v := range vals {
				if _, band := v.(map[string]any); band {
					continue
				}
				if !keep(v) {
					ok = false
				}
			}
			al, err := strconv.ParseInt(lexeme(cm["at_least"]), 10, 64)
			if err != nil || al < k {
				ok = false
			}
			if ok {
				cm["at_least"] = json.Number(strconv.FormatInt(contract.AtLeast(al, int(k)), 10))
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			continue
		}
		if len(kept) < len(cs) {
			dm["partial"] = true
		}
		dm["combinations"] = kept
		out = append(out, dm)
	}
	return out
}

// suppressCounts sets every published count below k (except zero) to 0
// (pack.md 7): evidence.counts leaves and evidence.keys[].matches.
func suppressCounts(ev map[string]any, k int64) {
	var walk func(m map[string]any)
	walk = func(m map[string]any) {
		for key, v := range m {
			switch x := v.(type) {
			case map[string]any:
				walk(x)
			case json.Number:
				if n, err := x.Float64(); err == nil && n > 0 && n < float64(k) {
					m[key] = json.Number("0")
				}
			}
		}
	}
	if c, ok := ev["counts"].(map[string]any); ok {
		walk(c)
	}
	if keys, ok := ev["keys"].([]any); ok {
		for _, x := range keys {
			if m, ok := x.(map[string]any); ok {
				if n, err := strconv.ParseFloat(lexeme(m["matches"]), 64); err == nil && n > 0 && n < float64(k) {
					m["matches"] = json.Number("0")
				}
			}
		}
	}
}

func renameServices(v any, rename map[string]string) {
	if len(rename) == 0 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "service" {
				if n, ok := rename[s]; ok {
					x[k] = n
				}
				continue
			}
			renameServices(e, rename)
		}
	case []any:
		for _, e := range x {
			renameServices(e, rename)
		}
	}
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

// Finish adds the gate report and the manifest: the files of the pack
// without signature.
func (as *Assembled) Finish(report gate.Report) (map[string][]byte, error) {
	a := as.a
	files := map[string][]byte{}
	for p, b := range as.Files {
		files[p] = b
	}
	files[GateReportPath] = report.File()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var list []any
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		list = append(list, map[string]any{"bytes": int64(len(files[p])), "path": p, "sha256": hex.EncodeToString(sum[:])})
	}
	var svcs []any
	for _, s := range as.services {
		m := map[string]any{"contract": s.Contract, "name": s.Name}
		if s.Alias != "" {
			m["upstream_alias"] = s.Alias
		}
		svcs = append(svcs, m)
	}
	var pols []any
	ps := append([]client.PolicyRef(nil), a.Policies...)
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].ID != ps[j].ID {
			return ps[i].ID < ps[j].ID
		}
		return ps[i].Version < ps[j].Version
	})
	for _, p := range ps {
		pols = append(pols, map[string]any{"id": p.ID, "version": p.Version})
	}
	ids := append([]string{}, a.Rules.IDs...)
	ttv := manifestVersion(a.TTVersion)
	m := map[string]any{
		"format": "tt.pack/v1", "pack_id": a.PackID, "created_at": fmtTime(a.CreatedAt), "tt_version": ttv,
		"seed": a.Seed, "k_min": a.KMin,
		"source":   map[string]any{"window": map[string]any{"from": fmtTime(a.Window[0]), "to": fmtTime(a.Window[1])}, "policies": orEmpty(pols)},
		"services": orEmpty(svcs),
		"rules":    map[string]any{"path": RulesPath, "approved": ids},
		"world":    map[string]any{"path": WorldPath, "customers": len(a.World.Customers)},
		"faults":   FaultsPath, "gate_report": GateReportPath, "scenarios": ScenariosPath,
		"files": orEmpty(list),
	}
	if a.Group != "" {
		m["group"] = a.Group
	}
	if a.NotAfter != nil {
		if !a.NotAfter.After(a.CreatedAt) {
			return nil, errors.New("packwriter: not_after must follow created_at")
		}
		m["not_after"] = fmtTime(*a.NotAfter)
	}
	mb, err := world.CanonicalFile(m)
	if err != nil {
		return nil, err
	}
	files[ManifestPath] = mb
	return files, nil
}

func orEmpty(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}

func fmtTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

var (
	manifestSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	notVersionMeta = regexp.MustCompile(`[^0-9A-Za-z.-]+`)
)

// manifestVersion turns the build version of tt into the semantic version
// the manifest requires: a build from a checkout without tags reports a bare
// commit ("faa01eb", "faa01eb-dirty") or "dev", which the pack loader would
// refuse. Such a version is kept as build metadata of 0.0.0.
func manifestVersion(v string) string {
	if v == "" {
		return "0.1.0"
	}
	if rest := strings.TrimPrefix(v, "v"); manifestSemver.MatchString(rest) {
		return rest
	}
	meta := strings.Trim(notVersionMeta.ReplaceAllString(v, "-"), ".-")
	if meta == "" {
		return "0.1.0"
	}
	return "0.0.0+" + meta
}
