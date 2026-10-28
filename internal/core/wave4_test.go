package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/miner"
)

// Spec v1.18: the mining status of selected groups keeps only their
// candidates, families and test k; a mining job does not repeat them.
func TestStatusCandidatesAndFamiliesByGroup(t *testing.T) {
	st := miner.Status{
		Candidates: []miner.Candidate{
			{Group: "shop", Service: "shop-api", Op: "POST /x", Kind: miner.CandUpdate, Subjects: "2-4"},
			{Group: "edge", Service: "edge-api", Op: "POST /y", Kind: miner.CandLimit, Subjects: "1"},
		},
		Families: []miner.FamilyCandidate{{Group: "shop", Domains: []string{"client", "customer"}}, {Group: "edge", Domains: []string{"a", "b"}}},
		TestK:    map[string]int{"shop": 3, "edge": 4},
	}
	body, _ := json.Marshal(st)
	sg := map[string][]string{"shop-api": {"shop"}, "edge-api": {"edge"}}
	out, ok := filterStatus(body, sg, groupscope.Parse([]string{"shop"}))
	if !ok {
		t.Fatal("not filtered")
	}
	s := string(out)
	if strings.Contains(s, "edge") || !strings.Contains(s, `"POST /x"`) || !strings.Contains(s, `"client"`) || !strings.Contains(s, `"test_k":{"shop":3}`) {
		t.Fatalf("filtered status: %s", s)
	}
	res := mineResult(miner.RunReport{}, &st)
	cp := res["status"].(miner.Status)
	if cp.Candidates != nil || cp.Families != nil {
		t.Fatalf("the job status repeats candidates or families: %+v", cp)
	}
}
