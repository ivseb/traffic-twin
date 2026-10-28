package packwriter

import (
	"context"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/world"
)

// A pack with no approved rule passes the gate with a warning, is signed,
// and loads (mock and keyguard accept the warn status of rules-approved).
func TestPackWithoutRulesWarnsAndLoads(t *testing.T) {
	in := demoWorldInput(t, 42, 40)
	empty, err := world.ParseRules([]byte(`{"format":"tt.rules/v1","entities":[],"rules":[]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Rules = empty
	out, err := world.Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	a := demoAssembly(t, 42)
	a.Rules, a.World, a.Presets = empty, out, nil
	kg := newFakeKeyguard()
	res, files := runGate(t, kg, a)
	if !res.Passed() {
		for _, c := range res.Report.Checks {
			t.Logf("%s %s %+v", c.ID, c.Status, c.Findings)
		}
		t.Fatal("a pack without rules must pass the gate")
	}
	if st := checkStatus(res); st[gate.CheckRulesApproved] != gate.CheckWarn {
		t.Fatalf("expected the rules-approved warning: %v", st)
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
		t.Fatalf("pack.Load rejects the warning: %v", err)
	}
}
