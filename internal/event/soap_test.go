package event

import "testing"

// Spec v1.19 (event.md 6): a SOAP exchange is named by its soap_action, else
// by the only element of its SOAP Body.
func TestSOAPOperation(t *testing.T) {
	obj := func(ms ...Member) *Value { v := Value{Kind: Object, O: ms}; return &v }
	str := Value{Kind: String, S: "drop:str:l8"}
	body := func(keys ...string) *Value {
		var ms []Member
		for _, k := range keys {
			ms = append(ms, Member{K: k, V: str})
		}
		return obj(Member{K: "Envelope", V: *obj(Member{K: "Body", V: *obj(ms...)})})
	}
	for _, c := range []struct {
		name string
		req  Request
		want string
		ok   bool
	}{
		{"soap action", Request{Fmt: FmtSOAP11, SoapAction: "GetOrder", Body: body("Other")}, "GetOrder", true},
		{"body element", Request{Fmt: FmtSOAP12, SoapAction: "{*}", Body: body("@id", "Quote")}, "Quote", true},
		{"two elements", Request{Fmt: FmtSOAP11, Body: body("A", "B")}, "", false},
		{"collapsed", Request{Fmt: FmtSOAP11, Body: body("{*}")}, "", false},
		{"plain xml", Request{Fmt: FmtXML, SoapAction: "GetOrder", Body: body("A")}, "", false},
		{"marker body", Request{Fmt: FmtSOAP11, Body: &Value{Kind: String, S: "trunc:invalid-xml"}}, "", false},
	} {
		e := &Event{Req: c.req}
		if got, ok := e.SOAPOperation(); got != c.want || ok != c.ok {
			t.Errorf("%s: got %q %v", c.name, got, ok)
		}
	}
}
