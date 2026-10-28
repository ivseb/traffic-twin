package packwriter

import (
	"context"
	"errors"
	"testing"
)

// Spec v1.18 (C0): a pack of exactly one group marked as test takes the
// group's lower k; packs of several groups (or with multi_group) keep the
// installation k.
func TestPackKMinOfTestGroups(t *testing.T) {
	s := &Service{o: Options{KMin: 20, TestK: func(context.Context) (map[string]int, error) {
		return map[string]int{"staging": 3, "odd": 1, "big": 20}, nil
	}}}
	ctx := context.Background()
	cases := []struct {
		group  string
		groups []string
		multi  bool
		k      int
		test   bool
	}{
		{"staging", []string{"staging"}, false, 3, true},
		{"staging", []string{"staging", "shop"}, false, 20, false},
		{"staging", []string{"staging"}, true, 20, false},
		{"shop", []string{"shop"}, false, 20, false},
		{"odd", []string{"odd"}, false, 20, false},
		{"big", []string{"big"}, false, 20, false},
		{"", nil, false, 20, false},
	}
	for _, c := range cases {
		k, test, err := s.packKMin(ctx, c.group, c.groups, c.multi)
		if err != nil || k != c.k || test != c.test {
			t.Errorf("%+v: k %d test %v err %v", c, k, test, err)
		}
	}
	s.o.TestK = func(context.Context) (map[string]int, error) { return nil, errors.New("db") }
	if _, _, err := s.packKMin(ctx, "staging", []string{"staging"}, false); err == nil {
		t.Error("the error of the source is lost")
	}
	s.o.TestK = nil
	if k, test, _ := s.packKMin(ctx, "staging", []string{"staging"}, false); k != 20 || test {
		t.Error("without TestK the pack keeps KMin")
	}
}
