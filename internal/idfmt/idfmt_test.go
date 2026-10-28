package idfmt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestParseErrors(t *testing.T) {
	for in, code := range map[string]string{
		"":                       "empty",
		strings.Repeat("N", 65):  "too_long",
		"NNNN?":                  "bad_char",
		"'ABC.NNNN":              "unclosed_quote",
		"''NNNN":                 "empty_literal",
		"'A B'NNNN":              "bad_literal",
		"{order NNNN":            "unclosed_ref",
		"{1x}NNNN":               "bad_ref",
		"{x#0}NNNN":              "bad_ref",
		"{x|pad0}NNNN":           "bad_ref",
		"{x|upper}NNNN":          "bad_ref",
		"<NN<NN>>":               "nested_b64",
		"<NNNN":                  "unclosed_b64",
		"<>NNNN":                 "empty_b64",
		"NN>":                    "bad_char",
		"NN":                     "too_small",
		"'ABC'.{customerId}":     "too_small",
		"b":                      "bad_char",
		"NN-NNNNNN-NNNN-NNNNNN ": "bad_char",
	} {
		_, err := Parse(in)
		var e *Error
		if !errors.As(err, &e) || e.Code != code {
			t.Errorf("Parse(%q) = %v, want code %s", in, err, code)
		}
	}
}

func TestShapes(t *testing.T) {
	cases := []struct {
		tpl string
		re  string
	}{
		{"NN-NNNNNN-NNNN-NNNNNN", `^[0-9]{2}-[0-9]{6}-[0-9]{4}-[0-9]{6}$`},
		{"'ABC'.NNNNNN", `^ABC\.[0-9]{6}$`},
		{"0000NNNNNN", `^0000[0-9]{6}$`},
		{"AAANNNN", `^[A-Z]{3}[0-9]{4}$`},
		{"aaa_XXXX", `^[a-z]{3}_[0-9A-Z]{4}$`},
		{"04-NNNNNN", `^04-[0-9]{6}$`},
	}
	for _, c := range cases {
		tp := MustParse(c.tpl)
		re := regexp.MustCompile(c.re)
		seen := map[string]bool{}
		for n := uint64(1); n <= 2000; n++ {
			id := tp.ID(n, "order", nil)
			if !re.MatchString(id) {
				t.Fatalf("%s: id %d = %q does not match %s", c.tpl, n, id, c.re)
			}
			if !tp.Match(id) {
				t.Fatalf("%s: Match(%q) = false", c.tpl, id)
			}
			if seen[id] {
				t.Fatalf("%s: id %q repeats within 2000", c.tpl, id)
			}
			seen[id] = true
		}
	}
}

func TestDeterministicAndScoped(t *testing.T) {
	tp := MustParse("NN-NNNNNN-NNNN-NNNNNN")
	if tp.ID(7, "order", nil) != MustParse("NN-NNNNNN-NNNN-NNNNNN").ID(7, "order", nil) {
		t.Fatal("same template, scope and n must give the same id")
	}
	if tp.ID(7, "order", nil) == tp.ID(7, "shipment", nil) {
		t.Fatal("two scopes should not share the sequence")
	}
	if got := tp.Preview("order", 3); len(got) != 3 || got[0] != tp.ID(1, "order", nil) {
		t.Fatalf("preview %v", got)
	}
}

// Uniqueness holds across the whole random space, also when only a part of
// it is a permutation (more than 62 bits).
func TestUniqueSmallAndLarge(t *testing.T) {
	small := MustParse("NNNN")
	seen := map[string]bool{}
	for n := uint64(1); n <= 10000; n++ {
		id := small.ID(n, "x", nil)
		if seen[id] {
			t.Fatalf("NNNN repeats at %d before the space (10000) is used up", n)
		}
		seen[id] = true
	}
	big := MustParse(strings.Repeat("N", 30))
	seen = map[string]bool{}
	for n := uint64(1); n <= 5000; n++ {
		id := big.ID(n, "x", nil)
		if len(id) != 30 || seen[id] {
			t.Fatalf("30 digits: bad or repeated id %q", id)
		}
		seen[id] = true
	}
}

func TestCopiedSegments(t *testing.T) {
	// The composite id carries the store id as its second segment: a client
	// that splits on '-' finds the store again.
	order := MustParse("NN-{storeId|pad6}-NNNN-NNNNNN")
	store := MustParse("NNNNNN")
	st := store.ID(3, "store", nil)
	id := order.ID(1, "order", MapRef(map[string]any{"storeId": st}))
	if seg := strings.Split(id, "-")[1]; seg != st {
		t.Fatalf("segment 2 of %q = %q, want the store id %q", id, seg, st)
	}
	// The part after the last dot without leading zeros is the customer number.
	contract := MustParse("'ABC'.{customerNo|pad6}NNN")
	id = contract.ID(5, "contract", MapRef(map[string]any{"customerNo": json.Number("123")}))
	if !strings.HasPrefix(id, "ABC.000123") {
		t.Fatalf("got %q", id)
	}
	back := MustParse("{contractId#-1|trim0}NNN")
	got := back.ID(1, "x", MapRef(map[string]any{"contractId": "ABC.000123"}))
	if !strings.HasPrefix(got, "123") || len(got) != 6 {
		t.Fatalf("got %q", got)
	}
	// A missing field gives random digits of the padded width.
	id = order.ID(2, "order", nil)
	if seg := strings.Split(id, "-")[1]; len(seg) != 6 || strings.Trim(seg, "0123456789") != "" {
		t.Fatalf("fallback segment %q", seg)
	}
	if id != order.ID(2, "order", nil) {
		t.Fatal("fallback must be deterministic")
	}
	// Nested fields.
	id = MustParse("{store.code}-NNNN").ID(1, "x", MapRef(map[string]any{"store": map[string]any{"code": "ST7"}}))
	if !strings.HasPrefix(id, "ST7-") {
		t.Fatalf("got %q", id)
	}
}

func TestBase64(t *testing.T) {
	tp := MustParse("<'Contract':NNNNNN>")
	id := tp.ID(9, "contract", nil)
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || !regexp.MustCompile(`^Contract:[0-9]{6}$`).Match(raw) {
		t.Fatalf("%q decodes to %q (%v)", id, raw, err)
	}
	if !tp.Match(id) {
		t.Fatal("Match on a base64url id")
	}
}

func TestAnnotate(t *testing.T) {
	doc := []byte(`{"paths":{"/orders":{"post":{"responses":{"201":{"content":{"application/json":{
	  "schema":{"type":"object","properties":{"id":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
	    "shipmentId":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}}}},
	  "example":{"id":"ORD-SYN-0042","shipmentId":"SHP-SYN-0042","note":"ORD-SYN-0042"}}}}}}}},
	  "description":"ORD-SYN-0042"}`)
	out, synth, err := Annotate(doc, map[string]string{"order": "NN-NNNNNN"})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if got := Collect(v); got["order"] != "NN-NNNNNN" || len(got) != 1 {
		t.Fatalf("Collect = %v", got)
	}
	want := MustParse("NN-NNNNNN").ID(ExampleN, "order", nil)
	if len(synth) != 1 || synth[0] != want {
		t.Fatalf("synthetic %v, want [%s]", synth, want)
	}
	s := string(out)
	if strings.Count(s, want) != 2 || !strings.Contains(s, `"description":"ORD-SYN-0042"`) || !strings.Contains(s, "SHP-SYN-0042") {
		t.Fatalf("examples not replaced as expected: %s", s)
	}
	same, syn, err := Annotate(doc, nil)
	if err != nil || string(same) != string(doc) || syn != nil {
		t.Fatal("no formats: unchanged")
	}
	if _, _, err := Annotate(doc, map[string]string{"order": "NN"}); err == nil {
		t.Fatal("an invalid format must be refused")
	}
}

func TestExampleID(t *testing.T) {
	for d, want := range map[string]string{"order": "ORD-SYN-0042", "shipment": "SHP-SYN-0042", "id": "OBJ-SYN-0042", "ab": "ABX-SYN-0042"} {
		if got := ExampleID(d); got != want {
			t.Errorf("ExampleID(%s) = %s, want %s", d, got, want)
		}
	}
}
