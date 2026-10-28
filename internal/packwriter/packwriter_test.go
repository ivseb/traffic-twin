package packwriter

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/gate"
)

func runGate(t *testing.T, kg *fakeKeyguard, a *Assembly) (*gate.Result, map[string][]byte) {
	t.Helper()
	s := &Service{o: Options{Keyguard: kg, Now: func() time.Time { return testT0.Add(4 * time.Hour) }}}
	res, files, err := s.Gate(context.Background(), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res, files
}

func checkStatus(r *gate.Result) map[string]string {
	out := map[string]string{}
	for _, c := range r.Report.Checks {
		out[c.ID] = c.Status
	}
	return out
}

func TestDemoPackPassesAndLoads(t *testing.T) {
	kg := newFakeKeyguard()
	res, files := runGate(t, kg, demoAssembly(t, 42))
	if !res.Passed() {
		for _, c := range res.Report.Checks {
			t.Logf("%s %s %+v", c.ID, c.Status, c.Findings)
		}
		t.Fatal("demo pack did not pass the gate")
	}
	unsigned, err := Archive(files)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := kg.SignPack(context.Background(), unsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{o: Options{Keyguard: kg, Now: func() time.Time { return testT0.Add(4 * time.Hour) }}}
	if err := s.Verify(context.Background(), files, pr.Signature.SigFile()); err != nil {
		t.Fatalf("pack.Load: %v", err)
	}
	// Small counts are suppressed (r-0012 ran 14 times < k_min 20), review dropped.
	rules := string(files[RulesPath])
	if !strings.Contains(rules, `"runs":0`) || strings.Contains(rules, `"review"`) {
		t.Fatal("counts below k must be suppressed and review removed")
	}
	if !strings.Contains(string(files[ManifestPath]), `"upstream_alias":"carrier"`) {
		t.Fatal("external service alias missing")
	}
}

func TestPackDeterministic(t *testing.T) {
	kg := newFakeKeyguard()
	_, f1 := runGate(t, kg, demoAssembly(t, 42))
	_, f2 := runGate(t, kg, demoAssembly(t, 42))
	if len(f1) != len(f2) {
		t.Fatal("different file sets")
	}
	for p := range f1 {
		if !bytes.Equal(f1[p], f2[p]) {
			t.Fatalf("%s differs", p)
		}
	}
	a1, _ := Archive(f1)
	a2, _ := Archive(f2)
	if !bytes.Equal(a1, a2) {
		t.Fatal("archives differ")
	}
	_, f3 := runGate(t, kg, demoAssembly(t, 43))
	if bytes.Equal(f1[WorldPath], f3[WorldPath]) {
		t.Fatal("different seeds, same world")
	}
}

func TestGateBlocksInjectedRealValue(t *testing.T) {
	kg := newFakeKeyguard()
	a := demoAssembly(t, 42)
	// A value keyguard knows as a real token is copied into the world.
	w := string(a.World.World)
	i := strings.Index(w, `"name":"`) + len(`"name":"`)
	j := strings.Index(w[i:], `"`)
	a.World.World = []byte(w[:i] + "ORD-2026-000184" + w[i+j:])
	kg.real["ORD-2026-000184"] = true
	res, files := runGate(t, kg, a)
	st := checkStatus(res)
	if res.Passed() || st[gate.CheckReverseHMAC] != "fail" {
		t.Fatalf("real value not blocked: %v", st)
	}
	if strings.Contains(string(files[GateReportPath]), "ORD-2026-000184") {
		t.Fatal("gate report leaks the value")
	}

	// A declared contract value that is a real token: only reverse-HMAC sees it.
	kg2 := newFakeKeyguard()
	kg2.real["no such order"] = true
	res, _ = runGate(t, kg2, demoAssembly(t, 42))
	st = checkStatus(res)
	if st[gate.CheckReverseHMAC] != "fail" || st[gate.CheckProvenance] != "pass" || st[gate.CheckPII] != "pass" {
		t.Fatalf("declared real value: %v", st)
	}
}

func TestGateBlocksUntaggedEmail(t *testing.T) {
	a := demoAssembly(t, 42)
	w := string(a.World.World)
	at := strings.Index(w, "@example.")
	start := strings.LastIndex(w[:at], `"`) + 1
	end := at + strings.Index(w[at:], `"`)
	a.World.World = []byte(w[:start] + "giulia.verdi@gmail.com" + w[end:])
	res, _ := runGate(t, newFakeKeyguard(), a)
	st := checkStatus(res)
	if st[gate.CheckProvenance] != "fail" || st[gate.CheckPII] != "fail" || res.Passed() {
		t.Fatalf("untagged e-mail: %v", st)
	}
}

func TestGateBlocksSmallArchetypeAndEnum(t *testing.T) {
	a := demoAssembly(t, 42)
	a.Archetypes[1].Size = 7
	res, _ := runGate(t, newFakeKeyguard(), a)
	if st := checkStatus(res); st[gate.CheckK] != "fail" {
		t.Fatalf("archetype below k: %v", st)
	}
	// An enum value seen by too few subjects is removed from the contract.
	a = demoAssembly(t, 42)
	a.Contracts[1].Declared["CANCELLED"] = 3
	res, files := runGate(t, newFakeKeyguard(), a)
	if !res.Passed() {
		t.Fatalf("filtered pack should pass: %v", checkStatus(res))
	}
	if strings.Contains(string(files["contracts/shop-api.openapi.json"]), `"CANCELLED"`) {
		t.Fatal("rare enum value published")
	}
}
