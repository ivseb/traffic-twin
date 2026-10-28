package core

import (
	"slices"
	"testing"
)

// Usability test 4: once host:ip:private:9301 is declared as catalog-api for
// a group, its old entries must not become a second twin (ext-1 in the mock).
func TestReplacedResolver(t *testing.T) {
	byPolicy := map[string]map[string]string{
		"p-orders": {"catalog-api": "127.0.0.1:9301", "payments-api": "127.0.0.1:9622"},
		"p-other":  {"other-catalog": "127.0.0.1:9301"},
	}
	polGroups := map[string][]string{"p-orders": {"orders"}, "p-other": {"other"}}
	r := replacedResolver(byPolicy, polGroups)
	for _, c := range []struct{ group, service, want string }{
		{"orders", "host:ip:private:9301", "catalog-api"},
		{"orders", "host:ip:private:9622", "payments-api"},
		{"orders", "host:ip:private:9623", ""}, // not declared yet
		{"orders", "catalog-api", ""},          // the declared service itself
		{"orders", "host:unlisted", ""},
		{"other", "host:ip:private:9301", "other-catalog"}, // each group its own name
		{"nobody", "host:ip:private:9301", ""},             // another team's declaration never relabels
	} {
		if got := r(c.group, c.service); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.group, c.service, got, c.want)
		}
	}
}

func TestPickTwins(t *testing.T) {
	replaced := func(group, service string) string {
		if group == "orders" && service == "host:ip:private:9301" {
			return "catalog-api"
		}
		return ""
	}
	svcs := []string{"orders-api", "catalog-api", "host:ip:private:9301", "host:ip:private:9623", "orders-api"}
	on, out, off := pickTwins(svcs, map[string]bool{}, "orders", replaced)
	if off || !slices.Equal(out, []string{"host:ip:private:9301"}) || !slices.Equal(on, []string{"catalog-api", "host:ip:private:9623", "orders-api"}) {
		t.Fatalf("default: on %v out %v off %v", on, out, off)
	}
	// An explicit "twin: true" keeps the old entry; an explicit no is off.
	on, out, off = pickTwins(svcs, map[string]bool{"orders/host:ip:private:9301": true, "orders/host:ip:private:9623": false}, "orders", replaced)
	if !off || len(out) != 0 || !slices.Equal(on, []string{"catalog-api", "host:ip:private:9301", "orders-api"}) {
		t.Fatalf("explicit: on %v out %v off %v", on, out, off)
	}
	// Without a group nothing is replaced (the declaration is per group).
	if _, out, _ = pickTwins(svcs, nil, "", replaced); len(out) != 0 {
		t.Fatalf("no group: %v", out)
	}
}
