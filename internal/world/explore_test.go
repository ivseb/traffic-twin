package world

import (
	"strings"
	"testing"
)

func TestPageCustomers(t *testing.T) {
	out, err := Generate(demoInput(t, 42, 120))
	if err != nil {
		t.Fatal(err)
	}
	p, err := PageCustomers(out.World, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.All != 120 || p.Total != 120 || p.Limit != DefaultCustomerPage || len(p.Customers) != DefaultCustomerPage {
		t.Fatalf("first page: all=%d total=%d limit=%d n=%d", p.All, p.Total, p.Limit, len(p.Customers))
	}
	first := p.Customers[0]
	if first.ID != "CUS-SYN-0001" || first.Name == "" || !strings.Contains(first.Email, "@example.") {
		t.Fatalf("first customer: %+v", first)
	}
	if first.Entities == nil {
		t.Fatal("entities must be an object, never null")
	}
	owned := 0
	for _, c := range p.Customers {
		for _, n := range c.Entities {
			owned += n
		}
	}
	if owned == 0 {
		t.Error("no customer owns an entity")
	}

	// Paging: the pages tile the list without gaps or overlaps.
	seen := map[string]bool{}
	for off := 0; off < 120; off += 50 {
		pg, err := PageCustomers(out.World, "", off, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range pg.Customers {
			if seen[c.ID] {
				t.Fatalf("%s on two pages", c.ID)
			}
			seen[c.ID] = true
		}
	}
	if len(seen) != 120 {
		t.Errorf("pages cover %d customers", len(seen))
	}
	// Past the end: empty page, not an error.
	if pg, err := PageCustomers(out.World, "", 500, 10); err != nil || len(pg.Customers) != 0 || pg.Total != 120 {
		t.Errorf("past the end: %+v %v", pg, err)
	}
	// The limit is capped.
	if pg, _ := PageCustomers(out.World, "", 0, 100000); pg.Limit != MaxCustomerPage || len(pg.Customers) != 120 {
		t.Errorf("limit cap: %d", pg.Limit)
	}

	// Search by id, by name and by archetype (case-insensitive); no match is an empty page.
	if pg, _ := PageCustomers(out.World, " cus-syn-0007 ", 0, 10); pg.Total != 1 || pg.Customers[0].ID != "CUS-SYN-0007" {
		t.Errorf("search by id: %+v", pg)
	}
	if pg, _ := PageCustomers(out.World, strings.ToUpper(first.Name), 0, 10); pg.Total < 1 || pg.Customers[0].Name == "" {
		t.Errorf("search by name: %+v", pg)
	}
	if pg, _ := PageCustomers(out.World, "arch-02", 0, 200); pg.Total == 0 || pg.Total >= 120 {
		t.Errorf("search by archetype: total %d", pg.Total)
	}
	if pg, _ := PageCustomers(out.World, "zzz-not-there", 0, 10); pg.Total != 0 || pg.All != 120 || pg.Customers == nil {
		t.Errorf("no match: %+v", pg)
	}
}
