package world

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Invented demo data (e-commerce + carrier, docs/spec/rules.md 7).

var testT0 = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "demo", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func demoContracts(t *testing.T) []Contract {
	return []Contract{
		{Service: "shop-api", Doc: readTestdata(t, "shop-api.openapi.json")},
		{Service: "shipping-ext", Doc: readTestdata(t, "shipping-ext.openapi.json"), External: true, Alias: "carrier"},
	}
}

func demoRules(t *testing.T) *Rules {
	t.Helper()
	r, err := ParseRules(readTestdata(t, "rules.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func demoArchetypes() []Archetype {
	return []Archetype{
		{ID: "arch-01", Size: 120, Features: Features{OrdersPerMonth: "3-5", ActiveHours: "18-24", ErrorRate: "<5%", PrimaryOp: "shop-api POST /orders",
			EndpointMix: map[string]float64{"shop-api POST /orders": 0.4, "shop-api GET /orders/{id}": 0.6}}},
		{ID: "arch-02", Size: 40, Features: Features{OrdersPerMonth: "1-2", ActiveHours: "06-12", ErrorRate: "0", PrimaryOp: "shop-api GET /orders/{id}",
			EndpointMix: map[string]float64{"shop-api POST /orders": 0.2, "shop-api GET /orders/{id}": 0.8}}},
	}
}

func demoInput(t *testing.T, seed uint64, n int) *Input {
	return &Input{Params: Params{Seed: seed, Customers: n, T0: testT0, Locale: "it"}, Rules: demoRules(t), Contracts: demoContracts(t), Archetypes: demoArchetypes()}
}
