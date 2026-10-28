package r4_rt

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Generative check of the observe property (RT4-OBS-1/2): random pairs of
// small policies built from a fixed vocabulary of services, operations,
// tt-paths, scopes and actions; for each pair and each exchange of a fixed
// set, a value that the next policy lets out and the previous one did not
// must make ClassifyValues open values. Deterministic seed.

var genSecrets = []string{"giulia.neri@example.com", "mario.rossi@example.org", "+39-333-1234567", "SECRET-ORDER-9F2"}

func genBody() string {
	return `{"email":"` + genSecrets[0] + `","profile":{"email":"` + genSecrets[1] + `","phone":"` + genSecrets[2] + `"},"items":[{"sku":"` + genSecrets[3] + `"}]}`
}

func genExchanges() []*sanitizer.Exchange {
	b := genBody()
	return []*sanitizer.Exchange{
		outbound("https://api.carrier.example", "/track", b),
		outbound("https://api.carrier.example", "/v2/track", b),
		outbound("https://api.other.example", "/track", b),
		inbound("GET", "/orders/export", b),
		inbound("GET", "/orders/o-1", b),
		inbound("GET", "/me", b),
	}
}

var (
	genPaths   = []string{"$.email", "$.profile", "$.profile.email", "$.profile.phone", "$.*", "$.profile.*", "$.items", "$.items[*]", "$.items[*].sku"}
	genActions = []string{"drop", "hmac(x)", "keep"}
	genOps     = []string{"GET /orders/{id}", "GET /orders/export", "GET /{kind}/export", "GET /me", "POST /me"}
	genBases   = []string{"https://api.carrier.example", "https://api.carrier.example/v2", "https://api.other.example"}
)

func genRules(r *rand.Rand, n int) map[string]any {
	out := map[string]any{}
	for range r.IntN(n + 1) {
		out[genPaths[r.IntN(len(genPaths))]] = genActions[r.IntN(len(genActions))]
	}
	return out
}

func genPolicy(r *rand.Rand) map[string]any {
	doc := map[string]any{
		"format": "tt.policy/v1", "policy_id": "p-gen", "default": "drop",
		"hmac": map[string]any{"kid": "k1", "epoch": "2026-10"}, "sampling": map[string]any{"rate": 1},
	}
	if r.IntN(2) == 0 {
		doc["global"] = map[string]any{"response": genRules(r, 2)}
	}
	svcs := map[string]any{}
	if r.IntN(3) > 0 {
		ops := map[string]any{}
		for _, op := range genOps {
			if r.IntN(2) == 0 {
				ops[op] = map[string]any{"response": genRules(r, 2)}
			}
		}
		svcs["shop-api"] = map[string]any{"match": map[string]any{"inbound": true}, "response": genRules(r, 2), "ops": ops}
	}
	for _, name := range []string{"carrier", "carrier-v2"} {
		if r.IntN(2) == 0 {
			svcs[name] = map[string]any{"match": map[string]any{"base": genBases[r.IntN(len(genBases))]}, "response": genRules(r, 2)}
		}
	}
	if len(svcs) > 0 {
		doc["services"] = svcs
	}
	return doc
}

// mutate returns a copy of doc with one random change (most pairs differ by
// one edit, as real versions do).
func mutate(r *rand.Rand, doc map[string]any) map[string]any {
	b, _ := json.Marshal(doc)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	if r.IntN(4) == 0 {
		return genPolicy(r)
	}
	svcs, _ := c["services"].(map[string]any)
	if svcs == nil {
		svcs = map[string]any{}
		c["services"] = svcs
	}
	switch r.IntN(5) {
	case 0: // service toggled
		name := []string{"carrier", "carrier-v2", "shop-api"}[r.IntN(3)]
		if _, ok := svcs[name]; ok {
			delete(svcs, name)
		} else if name == "shop-api" {
			svcs[name] = map[string]any{"match": map[string]any{"inbound": true}}
		} else {
			svcs[name] = map[string]any{"match": map[string]any{"base": genBases[r.IntN(len(genBases))]}}
		}
	case 1: // match changed
		for _, name := range []string{"carrier", "carrier-v2"} {
			if s, ok := svcs[name].(map[string]any); ok {
				s["match"] = map[string]any{"base": genBases[r.IntN(len(genBases))]}
			}
		}
	case 2: // operation toggled
		if s, ok := svcs["shop-api"].(map[string]any); ok {
			ops, _ := s["ops"].(map[string]any)
			if ops == nil {
				ops = map[string]any{}
				s["ops"] = ops
			}
			op := genOps[r.IntN(len(genOps))]
			if _, ok := ops[op]; ok {
				delete(ops, op)
			} else {
				ops[op] = map[string]any{}
			}
		}
	default: // one rule set, changed or removed somewhere
		var target map[string]any
		switch r.IntN(3) {
		case 0:
			g, _ := c["global"].(map[string]any)
			if g == nil {
				g = map[string]any{}
				c["global"] = g
			}
			target = g
		case 1:
			if s, ok := svcs["shop-api"].(map[string]any); ok {
				target = s
			}
		case 2:
			if s, ok := svcs["shop-api"].(map[string]any); ok {
				if ops, ok := s["ops"].(map[string]any); ok {
					if o, ok := ops[genOps[r.IntN(len(genOps))]].(map[string]any); ok {
						target = o
					}
				}
			}
		}
		if target == nil {
			return c
		}
		resp, _ := target["response"].(map[string]any)
		if resp == nil {
			resp = map[string]any{}
			target["response"] = resp
		}
		p := genPaths[r.IntN(len(genPaths))]
		if r.IntN(3) == 0 {
			delete(resp, p)
		} else {
			resp[p] = genActions[r.IntN(len(genActions))]
		}
	}
	return c
}

func genCompile(doc map[string]any) *policy.Policy {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var g any
	if d.Decode(&g) != nil {
		return nil
	}
	a, err := policy.AuthorFromGeneric(g)
	if err != nil {
		return nil
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: compiledAt, Groups: []string{"shop"}})
	if err != nil {
		return nil
	}
	return p
}

func TestR4ObservePropertyGenerative(t *testing.T) {
	n := 4000
	if testing.Short() {
		n = 500
	}
	if v, err := strconv.Atoi(os.Getenv("TT_R4_GEN_N")); err == nil && v > 0 {
		n = v // longer local runs
	}
	r := rand.New(rand.NewPCG(4, 2026))
	exs := genExchanges()
	checked := 0
	for i := 0; i < n; i++ {
		pd := genPolicy(r)
		nd := mutate(r, pd)
		prev, next := genCompile(pd), genCompile(nd)
		if prev == nil || next == nil {
			continue
		}
		checked++
		c := policy.ClassifyValues(prev, next)
		if c.OpensValues {
			continue
		}
		for _, ex := range exs {
			po, no := sanitize(t, prev, ex), sanitize(t, next, ex)
			for _, s := range genSecrets {
				if strings.Contains(no, s) && !strings.Contains(po, s) {
					pb, _ := json.Marshal(pd)
					nb, _ := json.Marshal(nd)
					t.Fatalf("observe-safe change lets %q out on %s %s %s\nprev: %s\nnext: %s", s, ex.Dir, ex.URLBase, ex.RawPath, pb, nb)
				}
			}
		}
	}
	if checked < n/4 {
		t.Fatalf("only %d of %d generated pairs compiled", checked, n)
	}
	t.Logf("%d pairs checked", checked)
}
