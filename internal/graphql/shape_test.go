package graphql

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestShapeExamples(t *testing.T) {
	cases := []struct{ in, want string }{
		{`query GetPolicy($id: ID!) { policy(id: $id) { id holder { name } } }`,
			`query GetPolicy($id:ID!){policy(id:$id){id holder{name}}}`},
		{`{ policy(id: "PL-123", n: 5, r: 1.5e3, ok: true, s: ACTIVE, x: null) { id } }`,
			`{policy(id:?s n:?i r:?f ok:?b s:?e x:?n){id}}`},
		{"mutation M($a: [In!]! = [{k: \"v\", n: 1}]) @d(if: false) {\n  # comment \"secret\"\n  a: create(in: $a) { ...F ... on T { x } ... @skip(if: $b) { y } }\n}\nfragment F on T { z }",
			`mutation M($a:[In!]!=[{k:?s n:?i}])@d(if:?b){a:create(in:$a){...F...on T{x}...@skip(if:$b){y}}}fragment F on T{z}`},
		{`query { u123456: user(id: """block "" \""" string""") { abcdefabcdefabcdef } }`,
			`query{*:user(id:?s){*}}`},
		{`{ list(xs: [1, 2, 3]) }`, `{list(xs:[?i ?i ?i])}`},
		{bom + "{ a , b }", `{a b}`},
	}
	for _, c := range cases {
		r, ok := Shape(c.in)
		if !ok {
			t.Errorf("Shape(%q) failed", c.in)
			continue
		}
		if r.Shape != c.want {
			t.Errorf("Shape(%q)\n got %s\nwant %s", c.in, r.Shape, c.want)
		}
		if _, err := ParseShape(r.Shape); err != nil {
			t.Errorf("ParseShape(%q): %v", r.Shape, err)
		}
	}
}

func TestShapeRejects(t *testing.T) {
	for _, in := range []string{
		``, `Mario Rossi`, `query`, `{}`, `{ a(x: 01) }`, `{ a(x: 1.) }`, `{ a(x: 1abc) }`, `{ a(x: "unterminated) }`,
		"{ a(x: \"line\nbreak\") }", `{ a(x: "\q") }`, `{ a } }`, `{ a`, `type Query { a: Int }`, `{ a(x: ?s) }`,
		`fragment on on T { a }`, `query Q() { a }`, `{ a() }`, `{ a } garbage`, `{ a(x: 1) } "s"`,
		strings.Repeat("{a", 65) + strings.Repeat("}", 65),
	} {
		if r, ok := Shape(in); ok {
			t.Errorf("Shape(%q) = %q, want failure", in, r.Shape)
		}
	}
	if _, ok := Shape(strings.Repeat("{a", 64) + strings.Repeat("}", 64)); !ok {
		t.Error("64 levels must pass")
	}
	long := "{" + strings.Repeat("abcdefgh ", 4000) + "}"
	if _, ok := Shape(long); ok {
		t.Error("a shape over 32768 bytes must fail")
	}
}

func TestIntrospectionFlag(t *testing.T) {
	cases := map[string]bool{
		`query IntrospectionQuery { __schema { queryType { name } types { ...T } } } fragment T on __Type { name kind }`: true,
		`{ __type(name: "Policy") { name } }`:                               true,
		`{ __typename }`:                                                    true,
		`{ __schema { types { name } } policy(id: 1) { id } }`:              false,
		`{ __schema: policy(id: 1) { types: holder { name } } }`:            false,
		`{ ...F } fragment F on Query { __schema { types { name } } }`:      false,
		`query A { __schema { types { name } } } query B { policy { id } }`: false,
		`fragment F on Query { a }`:                                         false,
	}
	for in, want := range cases {
		r, ok := Shape(in)
		if !ok {
			t.Fatalf("Shape(%q) failed", in)
		}
		if r.Introspection != want {
			t.Errorf("Introspection(%q) = %v, want %v", in, r.Introspection, want)
		}
	}
}

func TestNameSafe(t *testing.T) {
	for n, want := range map[string]bool{
		"policy": true, "address1": true, "__schema": true, "p12345": true, "p123456": false,
		"abcdefabcdefabcd": false, "abcdefabcdefabc": true, "abcdefabcdefabcg": true,
		strings.Repeat("g", 64): true, strings.Repeat("g", 65): false, "": false, "1a": false,
	} {
		if NameSafe(n) != want {
			t.Errorf("NameSafe(%q) = %v", n, !want)
		}
	}
}

// TestShapeNoLiteralLeak is the property test of sanitizer.md 5.7: random
// documents with inline literals (secret marker values in every value
// position) never let a literal out.
func TestShapeNoLiteralLeak(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	secrets := []string{}
	lit := func() string {
		s := fmt.Sprintf("SECRET%d", r.IntN(1e5))
		secrets = append(secrets, s)
		switch r.IntN(7) {
		case 0:
			return `"` + s + ` mario@example.com"`
		case 1:
			return `"""` + s + "\n" + `multi "line" \""" end"""`
		case 2:
			n := fmt.Sprint(9000000 + r.IntN(1000000))
			secrets = append(secrets, n)
			return n
		case 3:
			return fmt.Sprintf("%d.%de-%d", r.IntN(1e6), r.IntN(1e6), r.IntN(9))
		case 4:
			return s // enum literal
		case 5:
			return `{ k: "` + s + `" , n: [` + s + `, "` + s + `"] }`
		}
		return `[` + s + `, "x` + s + `"]`
	}
	for i := 0; i < 2000; i++ {
		secrets = secrets[:0]
		var sb strings.Builder
		fmt.Fprintf(&sb, "query Op%d($v: In = %s) @dir(a: %s) {\n", i, lit(), lit())
		for j := 0; j < 1+r.IntN(4); j++ {
			fmt.Fprintf(&sb, "  f%d: field%d(a: %s, b: $v, c: %s) @include(if: %s) { id ... on T @d(x: %s) { n } }\n", j, j, lit(), lit(), lit(), lit())
		}
		sb.WriteString("}\n# trailing comment SECRETcomment\n")
		res, ok := Shape(sb.String())
		if !ok {
			t.Fatalf("document %d did not parse:\n%s", i, sb.String())
		}
		for _, s := range append(secrets, "SECRETcomment", "mario", "line") {
			if strings.Contains(res.Shape, s) {
				t.Fatalf("literal %q leaked in %s", s, res.Shape)
			}
		}
		if strings.ContainsAny(res.Shape, `"#,.`+"\n") && !strings.Contains(res.Shape, "...") {
			t.Fatalf("unexpected characters in %s", res.Shape)
		}
	}
}

func FuzzShape(f *testing.F) {
	f.Add(`query Q($id: ID!) { a(id: $id, x: "s", n: 1) { b ...F } } fragment F on T { c }`)
	f.Add(`{ a(x: ENUM, y: [1.5, null, true], z: {k: """b"""}) }`)
	f.Fuzz(func(t *testing.T, s string) {
		r, ok := Shape(s)
		if !ok {
			return
		}
		if len(r.Shape) > MaxShapeBytes {
			t.Fatal("over the limit")
		}
		for i := 0; i < len(r.Shape); i++ {
			c := r.Shape[i]
			if !(isNameCont(c) || strings.IndexByte("!$&():=@[]{}|.?* ", c) >= 0) {
				t.Fatalf("byte %q in %q", c, r.Shape)
			}
		}
		if _, err := ParseShape(r.Shape); err != nil {
			t.Fatalf("shape %q does not parse: %v", r.Shape, err)
		}
		if !ValidShape(r.Shape) {
			t.Fatalf("shape %q is not valid", r.Shape)
		}
	})
}

const bom = "\ufeff"
