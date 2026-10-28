package packwriter

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Two teams call the same host:port (host:ip:private:9301): a pack of one
// team never carries the other team's services, and a selection that mixes
// the teams is refused unless an administrator asks for several groups.
func TestPackGroups(t *testing.T) {
	sg := map[string][]string{
		"library-loans-api":    {"library"},
		"pizzeria-orders":      {"pizzeria"},
		"host:ip:private:9301": {"library", "pizzeria"},
	}
	s := &Service{o: Options{ServiceGroups: func(context.Context) (map[string][]string, error) { return sg, nil }}}
	ctx := context.Background()
	cs := func(names ...string) []world.Contract {
		var out []world.Contract
		for _, n := range names {
			out = append(out, world.Contract{Service: n})
		}
		return out
	}
	// The world of a group: its group, whatever the shared names.
	if gs, err := s.packGroups(ctx, "library", cs("library-loans-api", "host:ip:private:9301"), false); err != nil || !slices.Equal(gs, []string{"library"}) {
		t.Errorf("group world: %v %v", gs, err)
	}
	// A world of every group with one team's services: that team.
	if gs, err := s.packGroups(ctx, "", cs("library-loans-api"), false); err != nil || !slices.Equal(gs, []string{"library"}) {
		t.Errorf("one owner: %v %v", gs, err)
	}
	// A world of every group with the shared host: its contract mixes the
	// two teams' calls, refused (the world must be generated for a group).
	_, err := s.packGroups(ctx, "", cs("library-loans-api", "host:ip:private:9301"), false)
	var ae *gate.APIError
	if !errors.As(err, &ae) || ae.Code != "mixed_groups" {
		t.Errorf("shared host in a world of every group: %v", err)
	}
	// Mixed: refused without multi_group.
	_, err = s.packGroups(ctx, "", cs("library-loans-api", "pizzeria-orders", "host:ip:private:9301"), false)
	if !errors.As(err, &ae) || ae.Code != "mixed_groups" || len(ae.Details) != 3 {
		t.Errorf("mixed selection: %v", err)
	}
	// Only the shared host: it belongs to two groups, refused too.
	if _, err := s.packGroups(ctx, "", cs("host:ip:private:9301"), false); !errors.As(err, &ae) || ae.Code != "mixed_groups" {
		t.Errorf("shared host alone: %v", err)
	}
	// An administrator's explicit multi-group pack lists both.
	if gs, err := s.packGroups(ctx, "", cs("library-loans-api", "pizzeria-orders"), true); err != nil || !slices.Equal(gs, []string{"library", "pizzeria"}) {
		t.Errorf("multi group: %v %v", gs, err)
	}
}

func TestSelectContractsExclude(t *testing.T) {
	in := &world.Input{Rules: &world.Rules{}, Contracts: []world.Contract{{Service: "a"}, {Service: "host:ip:private:9301"}}}
	cs, err := selectContracts(in, nil, []string{"host:ip:private:9301"})
	if err != nil || len(cs) != 1 || cs[0].Service != "a" {
		t.Errorf("exclude: %v %v", cs, err)
	}
}
