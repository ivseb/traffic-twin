package mock

import (
	"testing"
	"time"
)

// A relation field missing from the state is never invented: null where the
// schema allows it, omitted otherwise (docs/spec/mock.md section 2).
func TestRelationFieldsAreNeverInvented(t *testing.T) {
	doc := mustJSON(t, `{"components":{"schemas":{"S":{"type":"object","required":["id","linkNullable","linkStrict","other"],"properties":{
		"id":{"type":"string"},
		"linkNullable":{"type":["string","null"],"x-tt-value":{"kind":"id","domain":"shipment"}},
		"linkStrict":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
		"other":{"type":"string"}}}}}}`).(map[string]any)
	b := &builder{sc: &schemaCtx{doc: doc}, now: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), seed: 1, key: "k", prefixes: map[string]string{"shipment": "SHP-SYN-"}}
	schema := map[string]any{"$ref": "#/components/schemas/S"}
	rel := map[string]bool{"linkNullable": true, "linkStrict": true}

	out := b.build(schema, some(entOverlay{vals: map[string]any{"id": "x"}, rel: rel}), optVal{}, "", 0).(map[string]any)
	if v, has := out["linkNullable"]; !has || v != nil {
		t.Errorf("nullable relation = %v (present %v), want null", v, has)
	}
	if _, has := out["linkStrict"]; has {
		t.Errorf("non-nullable relation must be omitted: %v", out)
	}
	if out["other"] != "synthetic" { // an ordinary required field is still generated
		t.Errorf("other = %v", out["other"])
	}
	// when the state has the link it is used as it is
	out = b.build(schema, some(entOverlay{vals: map[string]any{"id": "x", "linkStrict": "SHP-SYN-0007", "linkNullable": nil}, rel: rel}), optVal{}, "", 0).(map[string]any)
	if out["linkStrict"] != "SHP-SYN-0007" || out["linkNullable"] != nil {
		t.Errorf("out = %v", out)
	}
	// omitValue keys never reach the body
	out = b.build(schema, some(map[string]any{"id": "x", "other": omitValue{}, "linkNullable": omitValue{}}), optVal{}, "", 0).(map[string]any)
	if _, has := out["other"]; has {
		t.Errorf("omit marker leaked: %v", out)
	}
}

func TestStrictDecodeShapes(t *testing.T) {
	type inner struct {
		P float64 `json:"p"`
	}
	type body struct {
		N     uint64  `json:"n"`
		I     int     `json:"i"`
		S     string  `json:"s"`
		B     bool    `json:"b"`
		Rules []inner `json:"rules"`
	}
	cases := []struct {
		in, ptr string
		fails   bool
	}{
		{`{"n":1,"i":-2,"s":"x","b":true,"rules":[{"p":1.5}]}`, "", false},
		{`{"zz":1}`, "/zz", true},
		{`{"n":-1}`, "/n", true},
		{`{"n":1.5}`, "/n", true},
		{`{"i":"a"}`, "/i", true},
		{`{"s":3}`, "/s", true},
		{`{"b":"yes"}`, "/b", true},
		{`{"rules":{}}`, "/rules", true},
		{`{"rules":[{"p":1},{"p":"x"}]}`, "/rules/1/p", true},
		{`{"rules":[{"q":1}]}`, "/rules/0/q", true},
		{`[]`, "", true},
	}
	for _, c := range cases {
		var v body
		ptr, err := strictDecode([]byte(c.in), &v)
		if (err != nil) != c.fails || ptr != c.ptr {
			t.Errorf("%s: ptr %q err %v, want ptr %q fails %v", c.in, ptr, err, c.ptr, c.fails)
		}
	}
}
