package contract_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

type fakeReplaced map[string]string

func (f fakeReplaced) ReplacedBy(context.Context) (func(group, service string) string, error) {
	return func(_, service string) string { return f[service] }, nil
}

// Usability test 4: an old service whose host the group declares since under
// another name is marked in the lists and out of the packs by default.
func TestListsMarkReplacedServices(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 200, contracttest.Variant{})
	h.Wait()
	now := day1.Add(48 * time.Hour)
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.SnapshotWindow(context.Background(), contract.Window{From: day1, To: day1.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	api := asRoles(contract.Handler(contract.APIDeps{Engine: eng, Replaced: fakeReplaced{"shipping-ext": "shipping-api"}}), auth.RoleOperator)

	var svcs []struct {
		Service    string `json:"service"`
		Twin       bool   `json:"twin"`
		ReplacedBy string `json:"replaced_by"`
	}
	rec := get(t, api, "GET", "/api/v1/services")
	if err := json.Unmarshal(rec.Body.Bytes(), &svcs); err != nil || len(svcs) == 0 {
		t.Fatalf("services: %v %s", err, rec.Body)
	}
	found := false
	for _, s := range svcs {
		switch s.Service {
		case "shipping-ext":
			found = true
			if s.ReplacedBy != "shipping-api" || s.Twin {
				t.Errorf("replaced service: %+v", s)
			}
		default:
			if s.ReplacedBy != "" {
				t.Errorf("not replaced: %+v", s)
			}
		}
	}
	if !found {
		t.Fatalf("no shipping-ext in %+v", svcs)
	}

	var infos []contract.SnapshotInfo
	rec = get(t, api, "GET", "/api/v1/contracts")
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil || len(infos) == 0 {
		t.Fatalf("contracts: %v %s", err, rec.Body)
	}
	for _, i := range infos {
		if want := map[string]string{"shipping-ext": "shipping-api"}[i.Service]; i.ReplacedBy != want {
			t.Errorf("contract %s: replaced_by %q, want %q", i.Service, i.ReplacedBy, want)
		}
	}
}
