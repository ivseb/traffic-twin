package core_test

import (
	"strings"
	"testing"
)

// TestUserEndpoints covers what a developer of an installed console needs:
// the gate keys for `tt mock`, the scope of the Group/Team filter and the
// HMAC key check of the sources.
func TestUserEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("starts keyguard and tt-core")
	}
	_, ada, olga := listCore(t, 2000)

	var gk struct {
		Value   string `json:"tt_gate_pubkeys"`
		Command string `json:"command"`
		Keys    []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	olga.json(200, "GET", "/api/v1/gate/keys", nil, &gk)
	if len(gk.Keys) == 0 || !strings.HasPrefix(gk.Value, gk.Keys[0].Kid+":") || !strings.Contains(gk.Command, "TT_GATE_PUBKEYS='"+gk.Value+"' tt mock") {
		t.Fatalf("gate keys: %+v", gk)
	}
	txt := string(olga.must(200, "GET", "/api/v1/gate/keys?format=txt", nil))
	if !strings.Contains(txt, "\n"+gk.Value+"\n") || !strings.HasPrefix(txt, "# traffic-twin") {
		t.Fatalf("gate-keys.txt: %q", txt)
	}

	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "bookings", "allowed_service_names": []string{"bookings-api"}})
	ada.must(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-node", "group": "bookings", "token_type": "one_time"})
	var sc struct {
		Groups   []string            `json:"groups"`
		Mine     []string            `json:"mine"`
		Services map[string][]string `json:"services"`
	}
	ada.json(200, "GET", "/api/v1/scope", nil, &sc)
	if len(sc.Groups) != 1 || sc.Groups[0] != "bookings" || len(sc.Mine) != 1 || sc.Mine[0] != "bookings" {
		t.Fatalf("scope for the token's author: %+v", sc)
	}
	if _, ok := sc.Services["svc-0"]; !ok {
		t.Fatalf("observed services missing from the scope: %v", sc.Services)
	}
	olga.json(200, "GET", "/api/v1/scope", nil, &sc)
	if len(sc.Mine) != 0 {
		t.Fatalf("olga created nothing: %+v", sc.Mine)
	}

	var kc struct {
		Reachable bool     `json:"reachable"`
		Kids      []string `json:"keyguard_kids"`
	}
	olga.json(200, "GET", "/api/v1/sources/key-check", nil, &kc)
	if !kc.Reachable || len(kc.Kids) == 0 {
		t.Fatalf("key check: %+v", kc)
	}
}
