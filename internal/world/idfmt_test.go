package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Id formats (docs/spec/pack.md 4.3) in the world: every entity id follows
// the format of its domain, ids are unique, and an id that copies a segment
// of another field still joins.
func TestGenerateWithIDFormats(t *testing.T) {
	in := demoInput(t, 7, 200)
	cs, err := WithIDFormats(in.Contracts, map[string]string{
		"order":    "NN-NNNNNN-NNNN",
		"shipment": "'S'.{orderId#2|trim0|pad6}NNN",
	})
	if err != nil {
		t.Fatal(err)
	}
	in.Contracts = cs
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if probs := Verify(out.World, in.Rules); len(probs) > 0 {
		t.Fatalf("integrity: %v", probs)
	}
	again, err := Generate(in)
	if err != nil || !bytes.Equal(again.World, out.World) {
		t.Fatal("generation with id formats must stay deterministic")
	}
	orderRE := regexp.MustCompile(`^[0-9]{2}-[0-9]{6}-[0-9]{4}$`)
	shipRE := regexp.MustCompile(`^S\.[0-9]{6}[0-9]{3}$`)
	synth := map[string]bool{}
	for _, s := range out.Synthetic {
		synth[s] = true
	}
	seen := map[string]bool{}
	orders, ships := 0, 0
	sc := bufio.NewScanner(bytes.NewReader(out.World))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var row struct {
			Type, Entity, ID string
			State            map[string]any
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row.Type != "entity" {
			continue
		}
		if seen[row.Entity+row.ID] {
			t.Fatalf("duplicate id %s", row.ID)
		}
		seen[row.Entity+row.ID] = true
		if !synth[row.ID] {
			t.Fatalf("id %s is not tagged synthetic", row.ID)
		}
		switch row.Entity {
		case "order":
			orders++
			if !orderRE.MatchString(row.ID) {
				t.Fatalf("order id %q", row.ID)
			}
		case "shipment":
			ships++
			if !shipRE.MatchString(row.ID) {
				t.Fatalf("shipment id %q", row.ID)
			}
			oid, _ := row.State["orderId"].(string)
			seg := strings.TrimLeft(strings.Split(oid, "-")[1], "0")
			if want := "S." + strings.Repeat("0", 6-len(seg)) + seg; oid != "" && !strings.HasPrefix(row.ID, want) {
				t.Fatalf("shipment %s of order %s: want prefix %s (join by the copied segment)", row.ID, oid, want)
			}
		}
	}
	if orders == 0 || ships == 0 {
		t.Fatalf("expected orders and shipments, got %d %d", orders, ships)
	}
}

func TestGenerateIDFormatTooSmall(t *testing.T) {
	in := demoInput(t, 7, 300)
	cs, err := WithIDFormats(in.Contracts, map[string]string{"order": "NNN"})
	if err != nil {
		t.Fatal(err)
	}
	in.Contracts = cs
	in.Customers = 2000
	if _, err := Generate(in); err == nil || !strings.Contains(err.Error(), "id format") {
		t.Fatalf("a format with fewer ids than the world needs must fail clearly, got %v", err)
	}
}
