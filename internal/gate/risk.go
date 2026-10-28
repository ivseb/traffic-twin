package gate

import (
	"math"
	"strings"
)

// Residual risk measures (docs/THREAT_MODEL.md 7): k on archetypes is a
// measured property of the clustering, not a guarantee against every
// attack. These numbers are reported to the operator, never inside the
// pack.

// Class is a generalized real profile vector with the number of subjects
// that have it (no token).
type Class struct {
	Vector []string `json:"v"`
	Count  int      `json:"n"`
}

// ArchetypeRisk is a published archetype with its representative vector
// (the features a synthetic customer inherits) and its member classes.
type ArchetypeRisk struct {
	ID      string
	Vector  []string
	Members []Class
}

// RiskInput feeds Measure.
type RiskInput struct {
	Classes    []Class
	Archetypes []ArchetypeRisk
	Dropped    int
}

// ResidualRisk are the measures.
type ResidualRisk struct {
	Note       string `json:"note"`
	Profiles   int    `json:"profiles"`
	Archetypes int    `json:"archetypes"`
	// MinArchetypeSize is the k actually achieved.
	MinArchetypeSize int `json:"min_archetype_size"`
	// SuppressedSubjects were dropped because no k-anonymous group fits them.
	SuppressedSubjects int `json:"suppressed_subjects"`
	// UniquenessRate is the share of real subjects whose generalized vector
	// is unique before clustering (data-level risk).
	UniquenessRate float64 `json:"uniqueness_rate"`
	// SinglingOutRate is the share of archetypes whose representative
	// vector (without "mixed" features) matches exactly one real subject.
	SinglingOutRate float64 `json:"singling_out_rate"`
	// ExactMatchShare is the share of real subjects whose vector equals the
	// representative vector of an archetype (attribute disclosure exposure).
	ExactMatchShare float64 `json:"exact_match_share"`
	// MaxHomogeneity is, over archetypes, the largest share of members with
	// one identical vector: 1 means membership reveals every feature
	// (linkability measure).
	MaxHomogeneity float64 `json:"max_homogeneity"`
}

func key(v []string) string { return strings.Join(v, "\x1f") }

// matches reports whether a representative vector (with "mixed" as a
// wildcard) matches a real vector.
func matches(rep, real []string) bool {
	if len(rep) != len(real) {
		return false
	}
	for i := range rep {
		if rep[i] != "mixed" && rep[i] != real[i] {
			return false
		}
	}
	return true
}

func round4(x float64) float64 { return math.Round(x*10000) / 10000 }

// Measure computes the residual risk measures.
func Measure(in *RiskInput, kMin int) *ResidualRisk {
	r := &ResidualRisk{Note: "measured properties of this build, not guarantees", Archetypes: len(in.Archetypes), SuppressedSubjects: in.Dropped}
	total, unique := 0, 0
	for _, c := range in.Classes {
		total += c.Count
		if c.Count == 1 {
			unique++
		}
	}
	r.Profiles = total
	if total > 0 {
		r.UniquenessRate = round4(float64(unique) / float64(total))
	}
	singled, exact := 0, 0
	exactSeen := map[string]bool{}
	r.MinArchetypeSize = 0
	for i, a := range in.Archetypes {
		size, top := 0, 0
		for _, m := range a.Members {
			size += m.Count
			top = max(top, m.Count)
		}
		if i == 0 || size < r.MinArchetypeSize {
			r.MinArchetypeSize = size
		}
		if size > 0 {
			r.MaxHomogeneity = math.Max(r.MaxHomogeneity, round4(float64(top)/float64(size)))
		}
		hits := 0
		for _, c := range in.Classes {
			if matches(a.Vector, c.Vector) {
				hits += c.Count
				if !exactSeen[key(c.Vector)] && !strings.Contains(key(a.Vector), "mixed") {
					exactSeen[key(c.Vector)] = true
					exact += c.Count
				}
			}
		}
		if hits == 1 {
			singled++
		}
	}
	if len(in.Archetypes) > 0 {
		r.SinglingOutRate = round4(float64(singled) / float64(len(in.Archetypes)))
	}
	if total > 0 {
		r.ExactMatchShare = round4(float64(exact) / float64(total))
	}
	_ = kMin
	return r
}
