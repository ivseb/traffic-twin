package dateoff

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseAndPick(t *testing.T) {
	lo, hi, err := Range{Min: "+30d", Max: "+365d"}.Parse()
	if err != nil || lo != 30*24*time.Hour || hi != 365*24*time.Hour {
		t.Fatal(lo, hi, err)
	}
	for _, bad := range []Range{{"30", "+1d"}, {"+2d", "+1d"}, {"+99999d", "+99999d"}, {"+1w", "+2w"}} {
		if _, _, err := bad.Parse(); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	if Pick(lo, hi, 0) != lo || Pick(lo, hi, 0.999999) != hi {
		t.Fatal("ends not reachable")
	}
	if p := Pick(-12*time.Hour, 12*time.Hour, 0.5); p%time.Hour != 0 {
		t.Fatal("hours")
	}
	now := time.Date(2026, 10, 27, 10, 30, 0, 0, time.UTC)
	if v := Value(now, 30*24*time.Hour, 30*24*time.Hour, 0.3, "date"); v != "2026-11-26" {
		t.Fatal(v)
	}
	if v := Value(now, -time.Hour, -time.Hour, 0, "date-time"); v != "2026-10-27T09:30:00Z" {
		t.Fatal(v)
	}
}

func TestAnnotate(t *testing.T) {
	doc := `{"paths":{"/p":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{
		"renewalDate":{"type":"string","format":"date-time","x-tt-value":{"kind":"bucket","unit":"day","date_offset":{"min":"+1d","max":"+2d"}}},
		"expiry":{"type":"string","format":"date"},
		"renewalCount":{"type":"integer"},
		"name":{"type":"string"}}}}}}}}}}}`
	out, err := Annotate([]byte(doc), map[string]Range{"renewalDate": {"+30d", "+365d"}, "expiry": {"-15d", "+0d"}, "renewalCount": {"+1d", "+1d"}, "name": {"+1d", "+1d"}})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	props := v["paths"].(map[string]any)["/p"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)
	xv := func(n string) map[string]any {
		m, _ := props[n].(map[string]any)["x-tt-value"].(map[string]any)
		return m
	}
	if lo, hi, ok := FromXTT(xv("renewalDate")); !ok || lo != 30*24*time.Hour || hi != 365*24*time.Hour || xv("renewalDate")["kind"] != "bucket" {
		t.Fatalf("person's range wins: %v", xv("renewalDate"))
	}
	if _, _, ok := FromXTT(xv("expiry")); !ok || xv("expiry")["kind"] != "shape" {
		t.Fatalf("date without x-tt-value: %v", xv("expiry"))
	}
	if xv("renewalCount") != nil || xv("name") != nil || strings.Contains(string(out), `"name":{"type":"string","x-tt`) {
		t.Fatal("non-date fields annotated")
	}
}
