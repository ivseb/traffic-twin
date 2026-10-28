package gate

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

// Id formats (docs/spec/pack.md 4.3): synthetic ids that follow a format
// chosen in the console instead of <PREFIX>-SYN-NNNN.
//
//   - provenance: an id_format string must be a valid template;
//   - pii-detectors: a synthetic string (generator provenance) that has the
//     shape of a declared format is not personal data (a composite id of
//     digits would otherwise look like a card or phone number); the
//     reverse-HMAC check still runs on it;
//   - reverse-hmac: besides every string of the pack, the ids the mock will
//     generate at run time with each format (the first ones after the
//     world, and the first static ones) go to keyguard, so a format whose
//     ids match a real token fails the gate.

// idFormatsFile is the File of reverse-hmac findings about run-time ids.
const idFormatsFile = "id-formats"

// runtimeIDs is how many ids per format beyond the world size are checked.
const (
	runtimeIDs    = 1000
	maxRuntimeIDs = 50000
)

type packFormat struct {
	domain string
	t      *idfmt.Template
}

// packFormats returns the valid id formats declared by the contracts, by
// domain (first in file order wins).
func packFormats(in *Input) []packFormat {
	paths := make([]string, 0, len(in.Files))
	for p := range in.Files {
		if kindOf(p) == "contract" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	seen := map[string]bool{}
	var out []packFormat
	for _, p := range paths {
		var doc any
		if err := json.Unmarshal(in.Files[p], &doc); err != nil {
			continue
		}
		fm := idfmt.Collect(doc)
		doms := make([]string, 0, len(fm))
		for d := range fm {
			doms = append(doms, d)
		}
		sort.Strings(doms)
		for _, d := range doms {
			if seen[d] {
				continue
			}
			if t, err := idfmt.Parse(fm[d]); err == nil {
				seen[d] = true
				out = append(out, packFormat{domain: d, t: t})
			}
		}
	}
	return out
}

// formatShaped tells whether s has the shape of one of the formats.
func formatShaped(fs []packFormat, s string) bool {
	for _, f := range fs {
		if f.t.Match(s) {
			return true
		}
	}
	return false
}

// runtimeCandidates are the ids the mock can generate with the formats.
func runtimeCandidates(fs []packFormat, in *Input) map[string][]string {
	worldRows := 0
	for p, b := range in.Files {
		if kindOf(p) == "world" {
			worldRows = strings.Count(string(b), "\n")
		}
	}
	out := map[string][]string{}
	for _, f := range fs {
		n := min(worldRows+runtimeIDs, maxRuntimeIDs)
		if c := f.t.Capacity(); c < float64(n) {
			n = int(c)
		}
		ids := make([]string, 0, n)
		for i := 1; i <= n; i++ {
			ids = append(ids, f.t.ID(uint64(i), f.domain, nil))
		}
		out[f.domain] = ids
	}
	return out
}
