package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/dateoff"
)

// A date field with a relative date (pack.md 4.4), set in the console and
// written into the contracts by WithDateOffsets, is generated as the
// instant of the value plus an offset of the range.
func TestWorldRelativeDates(t *testing.T) {
	in := demoInput(t, 11, 40)
	// the order request gains a date field the inference would mark as a
	// time bucket
	for i, c := range in.Contracts {
		if c.Service == "shop-api" {
			doc := strings.Replace(string(c.Doc), `"required": ["customerId", "sku", "qty"],`, `"required": ["customerId", "sku", "qty", "deliverBy"],`, 1)
			doc = strings.Replace(doc, `"qty": { "type": "integer" } }`, `"qty": { "type": "integer" }, "deliverBy": { "type": "string", "format": "date-time", "x-tt-value": { "kind": "bucket", "unit": "day" } } }`, 1)
			if doc == string(c.Doc) {
				t.Fatal("fixture changed")
			}
			in.Contracts[i].Doc = []byte(doc)
		}
	}
	cs, err := WithDateOffsets(in.Contracts, map[string]dateoff.Range{"deliverBy": {Min: "+2d", Max: "+5d"}})
	if err != nil {
		t.Fatal(err)
	}
	in.Contracts = cs
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	sc := bufio.NewScanner(bytes.NewReader(out.World))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var l map[string]any
		_ = json.Unmarshal(sc.Bytes(), &l)
		if l["type"] != "entity" || l["entity"] != "order" {
			continue
		}
		st := l["state"].(map[string]any)
		d, ok := st["deliverBy"].(string)
		if !ok {
			continue
		}
		created, _ := time.Parse(time.RFC3339, st["createdAt"].(string))
		at, err := time.Parse(time.RFC3339, d)
		if err != nil {
			t.Fatalf("deliverBy %q: %v", d, err)
		}
		if off := at.Sub(created); off < 2*24*time.Hour-time.Minute || off > 5*24*time.Hour+time.Minute {
			t.Fatalf("deliverBy %s is %s after createdAt %s", d, off, created)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no order with deliverBy")
	}
}
