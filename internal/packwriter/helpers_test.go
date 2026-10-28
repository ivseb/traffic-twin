package packwriter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Invented demo data only (e-commerce + carrier).

var testT0 = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func demoFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "world", "testdata", "demo", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tagContract plays the contract inference: enum values and keep values
// of error examples are declared (with 100 subjects), the other example
// values are synthetic.
func tagContract(t *testing.T, svc string, doc []byte, external bool) world.Contract {
	var d map[string]any
	if err := world.DecodeGeneric(doc, &d); err != nil {
		t.Fatal(err)
	}
	c := world.Contract{Service: svc, Doc: doc, External: external, Declared: map[string]int64{}}
	if external {
		c.Alias = "carrier"
	}
	var walk func(v any, inEnum, inExample, inError bool)
	walk = func(v any, inEnum, inExample, inError bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(e, k == "enum", inExample || k == "examples" || k == "example", inError || (inExample && k == "error"))
			}
		case []any:
			for _, e := range x {
				walk(e, inEnum, inExample, inError)
			}
		case string:
			switch {
			case inEnum || inError:
				c.Declared[x] = 100
			case inExample:
				c.Synthetic = append(c.Synthetic, x)
			}
		}
	}
	walk(d, false, false, false)
	return c
}

func demoContracts(t *testing.T) []world.Contract {
	return []world.Contract{
		tagContract(t, "shipping-ext", demoFile(t, "shipping-ext.openapi.json"), true),
		tagContract(t, "shop-api", demoFile(t, "shop-api.openapi.json"), false),
	}
}

func demoArchetypes() []world.Archetype {
	return []world.Archetype{
		{ID: "arch-01", Size: 120, Features: world.Features{OrdersPerMonth: "3-5", ActiveHours: "18-24", ErrorRate: "<5%", PrimaryOp: "shop-api POST /orders",
			EndpointMix: map[string]float64{"shop-api POST /orders": 0.4, "shop-api GET /orders/{id}": 0.6}}},
		{ID: "arch-02", Size: 40, Features: world.Features{OrdersPerMonth: "1-2", ActiveHours: "06-12", ErrorRate: "0", PrimaryOp: "shop-api GET /orders/{id}",
			EndpointMix: map[string]float64{"shop-api POST /orders": 0.2, "shop-api GET /orders/{id}": 0.8}}},
	}
}

func demoFaults() *Faults {
	return &Faults{Ops: []FaultOp{
		{Service: "shipping-ext", Op: "GET /v1/shipments", Statuses: []FaultStatus{{Status: 503, P: 0.012, Example: "carrier-unavailable"}},
			NetErrors: []FaultNet{{Kind: "timeout", P: 0.002}}, P50: 80, P95: 215, P99: 323},
		{Service: "shop-api", Op: "POST /orders", P50: 120, P95: 400, P99: 900},
	}}
}

func demoWorldInput(t *testing.T, seed uint64, n int) *world.Input {
	t.Helper()
	r, err := world.ParseRules(demoFile(t, "rules.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &world.Input{Params: world.Params{Seed: seed, Customers: n, T0: testT0, Locale: "it"}, Rules: r, Contracts: demoContracts(t), Archetypes: demoArchetypes()}
}

func demoAssembly(t *testing.T, seed uint64) *Assembly {
	t.Helper()
	in := demoWorldInput(t, seed, 40)
	out, err := world.Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	f := demoFaults()
	return &Assembly{PackID: "pk-20261019-0001", CreatedAt: testT0.Add(3 * time.Hour), KMin: 20, TTVersion: "0.1.0",
		Window: [2]time.Time{testT0.Add(-14 * 24 * time.Hour), testT0}, Policies: []client.PolicyRef{{ID: "p-shop", Version: 7}},
		Contracts: in.Contracts, Rules: in.Rules, World: out, Seed: seed, Faults: f,
		Presets: world.DerivePresets(in.Rules, out.Customers, f.Hints(), "it"), Anonymize: true, Archetypes: in.Archetypes}
}

// fakeKeyguard matches against a set of "real" values and signs like
// keyguard does (over "tt.pack/v1" || 0x00 || manifest).
type fakeKeyguard struct {
	real map[string]bool
	priv ed25519.PrivateKey
}

func newFakeKeyguard() *fakeKeyguard {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fakeKeyguard{real: map[string]bool{}, priv: priv}
}

func (f *fakeKeyguard) Match(_ context.Context, _ []client.PolicyRef, cands []client.Candidate) (*client.MatchResult, error) {
	r := &client.MatchResult{Matches: make([]bool, len(cands))}
	for i, c := range cands {
		b, _ := c.MarshalJSON()
		if f.real[strings.Trim(string(b), `"`)] {
			r.Matches[i] = true
			r.Positives++
		}
	}
	return r, nil
}

func (f *fakeKeyguard) SignPack(_ context.Context, archive []byte, req *client.Approval) (*client.PackResult, error) {
	files, err := ReadArchive(archive)
	if err != nil {
		return nil, err
	}
	m := files[ManifestPath]
	sum := sha256.Sum256(m)
	sig := ed25519.Sign(f.priv, append([]byte("tt.pack/v1\x00"), m...))
	mode := "standard"
	if req != nil && req.Reason != "" {
		mode = "admin"
	}
	return &client.PackResult{Signature: client.PackSignature{Format: "tt.pack.sig/v1", Alg: "Ed25519", Kid: "gate-test-1",
		ManifestSHA256: hex.EncodeToString(sum[:]), Sig: base64.RawURLEncoding.EncodeToString(sig)}, ReverseHMAC: client.ReverseHMAC{Status: "pass"}, ApprovalMode: mode}, nil
}

func (f *fakeKeyguard) PublicKeys(context.Context) (*client.PublicKeys, error) {
	return &client.PublicKeys{Pack: []client.PublicKey{{Kid: "gate-test-1", Alg: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey))}}}, nil
}
