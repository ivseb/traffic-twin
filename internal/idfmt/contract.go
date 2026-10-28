package idfmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// Key is the x-tt-value field that carries an id format (pack.md 4.1).
const Key = "id_format"

// ExampleN is the counter of the id that replaces the inferred example id
// of a domain (the inference writes <PREFIX>-SYN-0042).
const ExampleN = 42

// ExampleID is the synthetic id the contract inference writes in examples
// for an id domain: the same domain always yields the same value, so that
// fields linked by a key agree inside an example (order -> ORD-SYN-0042).
func ExampleID(domain string) string {
	if domain == "id" || domain == "" {
		return "OBJ-SYN-0042"
	}
	// First letter, then the next consonants (order -> ORD, shipment -> SHP),
	// completed with the following letters when the word has fewer than three.
	d := strings.ToUpper(domain)
	var letters []byte
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c < 'A' || c > 'Z' {
			continue
		}
		if len(letters) == 0 || !strings.ContainsRune("AEIOU", rune(c)) {
			letters = append(letters, c)
		}
		if len(letters) == 3 {
			break
		}
	}
	for i := 0; len(letters) < 3; i++ {
		letters = append(letters, "XYZ"[i%3])
	}
	return string(letters) + "-SYN-0042"
}

// Collect returns the id formats a contract document declares, by id
// domain (x-tt-value.kind = id with an id_format). The walk is in key
// order, so the first one found wins deterministically.
func Collect(doc any) map[string]string {
	out := map[string]string{}
	walk(doc, func(m map[string]any) {
		xv, _ := m["x-tt-value"].(map[string]any)
		if xv == nil || xv["kind"] != "id" {
			return
		}
		d, _ := xv["domain"].(string)
		f, _ := xv[Key].(string)
		if f == "" {
			return
		}
		if _, ok := out[d]; !ok {
			out[d] = f
		}
	})
	return out
}

// Templates parses the formats Collect found; formats that do not parse
// are left out (the gate refuses them in a pack).
func Templates(formats map[string]string) map[string]*Template {
	out := map[string]*Template{}
	for d, f := range formats {
		if t, err := Parse(f); err == nil {
			out[d] = t
		}
	}
	return out
}

func walk(v any, fn func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		fn(x)
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(x[k], fn)
		}
	case []any:
		for _, e := range x {
			walk(e, fn)
		}
	}
}

// Annotate adds the id formats (by id domain) to a contract document: every
// x-tt-value of kind id with one of the domains gets id_format, and the
// example ids the inference wrote for those domains (ExampleID) are replaced
// by the template's id number ExampleN, so a mock answering from an example
// shows ids of the right shape. It returns the new document and the ids it
// wrote (synthetic values for the gate). Without formats the document is
// returned unchanged.
func Annotate(doc []byte, formats map[string]string) ([]byte, []string, error) {
	if len(formats) == 0 {
		return doc, nil, nil
	}
	tpls := map[string]*Template{}
	for d, f := range formats {
		t, err := Parse(f)
		if err != nil {
			return nil, nil, err
		}
		tpls[d] = t
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("idfmt: trailing data")
	}
	used := map[string]bool{}
	walk(v, func(m map[string]any) {
		xv, _ := m["x-tt-value"].(map[string]any)
		if xv == nil || xv["kind"] != "id" {
			return
		}
		d, _ := xv["domain"].(string)
		if t := tpls[d]; t != nil {
			xv[Key] = t.String()
			used[d] = true
		}
	})
	// Example ids: one inferred value per domain; two domains with the same
	// letters (order, orderline) share it and keep it.
	owner := map[string]string{}
	shared := map[string]bool{}
	for d := range used {
		old := ExampleID(d)
		if o, ok := owner[old]; ok && o != d {
			shared[old] = true
		}
		owner[old] = d
	}
	repl := map[string]string{}
	var synth []string
	for old, d := range owner {
		if shared[old] {
			continue
		}
		id := tpls[d].ID(ExampleN, d, nil)
		repl[old] = id
		synth = append(synth, id)
	}
	sort.Strings(synth)
	if len(repl) > 0 {
		replaceExamples(v, false, repl)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	return out, synth, nil
}

func replaceExamples(v any, in bool, repl map[string]string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = replaceExamples(e, in || k == "example" || k == "examples", repl)
		}
	case []any:
		for i, e := range x {
			x[i] = replaceExamples(e, in, repl)
		}
	case string:
		if r, ok := repl[x]; ok && in {
			return r
		}
	}
	return v
}
