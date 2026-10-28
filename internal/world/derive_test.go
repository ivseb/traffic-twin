package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Derived values (rules 1.10, 3.15) are computed by the generator as by the
// mock: a date relative to the instant the effect applies and a sum of the
// entity's quantity; generated strings are synthetic.
func TestWorldDerivedValues(t *testing.T) {
	raw := string(readTestdata(t, "rules.json"))
	raw = strings.Replace(raw, `"set": { "shipmentId": "${effect:shipment-requested}"`,
		`"set":{"shipmentId":"${effect:shipment-requested}","note":{"$derive":{"fn":"date","offset":"+30d","format":"date"}},"total":{"$derive":{"fn":"mul","args":["${field:qty}",2]}}`, 1)
	if !strings.Contains(raw, `"$derive"`) {
		t.Fatal("fixture changed: order-linked effect not found")
	}
	rules, err := ParseRules([]byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	in := demoInput(t, 7, 30)
	in.Rules = rules
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	syn := map[string]bool{}
	for _, s := range out.Synthetic {
		syn[s] = true
	}
	checked := 0
	sc := bufio.NewScanner(bytes.NewReader(out.World))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var l map[string]any
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.UseNumber()
		if err := dec.Decode(&l); err != nil {
			t.Fatal(err)
		}
		if l["type"] != "entity" || l["entity"] != "order" {
			continue
		}
		st := l["state"].(map[string]any)
		note, ok := st["note"].(string)
		if !ok {
			continue
		}
		d, err := time.Parse("2006-01-02", note)
		if err != nil || !syn[note] {
			t.Fatalf("note %q: %v (synthetic %v)", note, err, syn[note])
		}
		if d.Before(testT0.AddDate(0, -3, 0)) || d.After(testT0.AddDate(0, 0, 31)) {
			t.Fatalf("note %s is not near t0 + 30d", note)
		}
		q, ok := st["qty"].(json.Number)
		if !ok {
			continue
		}
		n, _ := q.Int64()
		if tot, _ := st["total"].(json.Number); tot.String() != itoa(2*n) {
			t.Fatalf("total %v != 2 x qty %d", st["total"], n)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no order with derived values")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
