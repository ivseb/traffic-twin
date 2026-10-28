package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// compileErr parses and compiles an author document, returning the first
// error.
func compileErr(s string) error {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		return err
	}
	a, err := AuthorFromGeneric(doc)
	if err != nil {
		return err
	}
	_, _, err = Compile(a, meta(1, 1))
	return err
}

const famOps = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "POST /orders":{"response":{"$.id":"hmac(order)","$.customerId":"hmac(customer)","$.status":"STATUS"}},
 "GET /clients/{id}":{"request":{"path":{"id":"hmac(client)"},"headers":{"x-client":"hmac(client)"}}}}}}`

func famDoc(families, status string) string {
	hm := `"hmac":{"kid":"k1","epoch":"2026-10"`
	if families != "" {
		hm += `,"families":` + families
	}
	hm += `}`
	return `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop",` + hm + `,"sampling":{"rate":0.05},` +
		strings.Replace(famOps, "STATUS", status, 1) + `}`
}

func TestFamiliesCompile(t *testing.T) {
	body, p, err := Compile(author(t, famDoc(`{"customer":["customer","client"]}`, "drop")), meta(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("families")) || bytes.Contains(body, []byte(`"client"`)) {
		t.Fatalf("the body must keep its shape and carry only the family domain: %s", body)
	}
	if !bytes.Contains(body, []byte(`"domain":"customer"`)) || !bytes.Contains(body, []byte(`"domain":"order"`)) {
		t.Fatalf("domains: %s", body)
	}
	if _, err := DecodeBody(body); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	var clients int
	for _, f := range []map[string]Action{p.Services[0].Ops[0].Request.Path, p.Services[0].Ops[0].Request.Headers} {
		for _, a := range f {
			if a.Kind == ActHMAC && a.Domain == "customer" {
				clients++
			}
		}
	}
	if clients != 2 {
		t.Fatalf("client rules not joined: %+v", p.Services[0].Ops)
	}
	// Without families the body is byte-identical to before.
	plain, _, err := Compile(author(t, famDoc("", "drop")), meta(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(`"domain":"client"`)) {
		t.Fatalf("plain: %s", plain)
	}
}

func TestFamiliesRejects(t *testing.T) {
	for _, f := range []string{
		`{"customer":["customer"]}`,
		`{"customer":["customer","customer"]}`,
		`{"customer":["client","subject"]}`,
		`{"subject":["client","customer"]}`,
		`{"Customer":["client","customer"]}`,
		`{"customer":["client","bad domain"]}`,
		`{"a":["client","x"],"b":["client","y"]}`,
		`{"a":["b","x"],"b":["c","y"]}`,
		`{"customer":"client"}`,
		`{"customer":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}`,
	} {
		if err := compileErr(famDoc(f, "drop")); err == nil {
			t.Errorf("families %s accepted", f)
		}
	}
}

func TestFamiliesObserveSafe(t *testing.T) {
	for _, status := range []string{"drop", "keep"} {
		_, prev, err := Compile(author(t, famDoc("", status)), meta(1, 1))
		if err != nil {
			t.Fatal(err)
		}
		_, next, err := Compile(author(t, famDoc(`{"customer":["customer","client"]}`, status)), meta(2, 2))
		if err != nil {
			t.Fatal(err)
		}
		if c := ClassifyValues(prev, next); c.OpensValues {
			t.Fatalf("joining domains (%s) must be observe-safe: %v", status, reasons(c))
		}
		if c := ClassifyValues(next, prev); c.OpensValues {
			t.Fatalf("splitting a family (%s) must be observe-safe: %v", status, reasons(c))
		}
	}
}

func TestSubjectJSONPathPolicy(t *testing.T) {
	ok := []string{
		`{"from":"header","name":"x-user-context","json_path":"user.id"}`,
		`{"from":"header","name":"x-auth-context","json_path":"sub"}`,
		`{"from":"header","name":"x-ctx","json_path":"a.b.c.d.e.f.g.h"}`,
	}
	for _, s := range ok {
		body, p, err := Compile(author(t, `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e"},"sampling":{"rate":0.1},"identity":{"subject":`+s+`}}`), meta(1, 1))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if p.Subject.JSONPath == "" || !bytes.Contains(body, []byte(`"json_path"`)) {
			t.Fatalf("%s: json_path lost: %s", s, body)
		}
		if !IdentityObserveSafe(p.Subject) {
			t.Errorf("%s: a member of a JSON header must be observe-safe", s)
		}
	}
	for _, s := range []string{
		`{"from":"cookie","name":"ctx","json_path":"user.id"}`,
		`{"from":"header","name":"x-ctx","json_path":"user.id","jwt_claim":"sub"}`,
		`{"from":"header","name":"x-ctx","json_path":""}`,
		`{"from":"header","name":"x-ctx","json_path":"a..b"}`,
		`{"from":"header","name":"x-ctx","json_path":".a"}`,
		`{"from":"header","name":"x-ctx","json_path":"a b"}`,
		`{"from":"header","name":"x-ctx","json_path":"a.b.c.d.e.f.g.h.i"}`,
	} {
		if compileErr(`{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e"},"sampling":{"rate":0.1},"identity":{"subject":`+s+`}}`) == nil {
			t.Errorf("%s accepted", s)
		}
	}
	// authorization still needs a JWT claim; credential headers never.
	for _, s := range []*Subject{
		{From: "header", Name: "authorization", JSONPath: "sub"},
		{From: "header", Name: "cookie", JSONPath: "sub"},
		{From: "header", Name: "x-api-key", JSONPath: "sub"},
	} {
		if IdentityObserveSafe(s) {
			t.Errorf("%+v must need approvals", s)
		}
	}
	if IdentityObserveSafe(&Subject{From: "header", Name: "x-auth-context"}) {
		t.Error("a credential-like header without json_path must need approvals")
	}
	if sameSubjectValue(&Subject{From: "header", Name: "x", JSONPath: "a"}, &Subject{From: "header", Name: "x", JSONPath: "b"}) {
		t.Error("another json_path is another subject")
	}
}
