package export

import "sort"

// Loss is one thing a target format cannot represent.
type Loss struct {
	Kind    string `json:"kind"`
	Element string `json:"element"`
	Detail  string `json:"detail"`
	Count   int    `json:"count,omitempty"`
}

// Exported is one group of elements that made it into the target.
type Exported struct {
	Kind    string `json:"kind"`
	Element string `json:"element"`
	Count   int    `json:"count"`
}

// Report is export-report.json (format tt.export-report/v1).
type Report struct {
	Format     string         `json:"format"`
	Target     string         `json:"target"`
	PackID     string         `json:"pack_id"`
	Counts     map[string]int `json:"counts"`
	Exported   []Exported     `json:"exported"`
	Losses     []Loss         `json:"losses"`
	LossByKind map[string]int `json:"loss_by_kind"`
	Presets    []PresetReport `json:"presets"`
	Files      []fileEntry    `json:"files"`
}

type reportBuilder struct {
	target  string
	packID  string
	counts  map[string]int
	exp     map[[2]string]int
	losses  []Loss
	presets []PresetReport
}

func newReport(target, packID string) *reportBuilder {
	return &reportBuilder{target: target, packID: packID, counts: map[string]int{}, exp: map[[2]string]int{}}
}

func (r *reportBuilder) count(name string, n int) { r.counts[name] += n }

func (r *reportBuilder) exported(kind, element string, n int) {
	r.exp[[2]string{kind, element}] += n
}

func (r *reportBuilder) lose(kind, element, detail string, n int) {
	r.losses = append(r.losses, Loss{Kind: kind, Element: element, Detail: detail, Count: n})
}

// setPresets records how scenarios.json presets map to the target; every
// part that cannot be applied is also a loss.
func (r *reportBuilder) setPresets(ps []PresetReport) {
	r.presets = ps
	for _, p := range ps {
		for _, l := range p.Lost {
			r.lose("preset", "preset:"+p.ID, l, 1)
		}
		if p.Status != "lost" {
			r.exported("preset", "preset:"+p.ID, 1)
		}
	}
}

func (r *reportBuilder) addNotes(notes []Loss) { r.losses = append(r.losses, notes...) }

// build finalises the report: sorted, no timestamps.
func (r *reportBuilder) build(files []outFile) *Report {
	rep := &Report{Format: "tt.export-report/v1", Target: r.target, PackID: r.packID, Counts: r.counts, LossByKind: map[string]int{}}
	for k, n := range r.exp {
		rep.Exported = append(rep.Exported, Exported{Kind: k[0], Element: k[1], Count: n})
	}
	sort.Slice(rep.Exported, func(i, j int) bool {
		a, b := rep.Exported[i], rep.Exported[j]
		if a.Element != b.Element {
			return a.Element < b.Element
		}
		return a.Kind < b.Kind
	})
	rep.Losses = append(rep.Losses, r.losses...)
	sort.SliceStable(rep.Losses, func(i, j int) bool {
		a, b := rep.Losses[i], rep.Losses[j]
		if a.Element != b.Element {
			return a.Element < b.Element
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	for _, l := range rep.Losses {
		n := l.Count
		if n == 0 {
			n = 1
		}
		rep.LossByKind[l.Kind] += n
	}
	if rep.Exported == nil {
		rep.Exported = []Exported{}
	}
	if rep.Losses == nil {
		rep.Losses = []Loss{}
	}
	rep.Presets = append(rep.Presets, r.presets...)
	if rep.Presets == nil {
		rep.Presets = []PresetReport{}
	}
	for _, f := range files {
		rep.Files = append(rep.Files, fileEntry{Path: f.Path, SHA256: sha256Hex(f.Data), Bytes: len(f.Data)})
	}
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Path < rep.Files[j].Path })
	if rep.Files == nil {
		rep.Files = []fileEntry{}
	}
	return rep
}
