package policy

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

func TestCodeValue(t *testing.T) {
	for _, s := range []string{"DELIVERED", "in_transit", "card_declined", "Return-Requested", "ok", strings.Repeat("x", 32), "--"} {
		if !CodeValue([]byte(s)) {
			t.Errorf("CodeValue(%q) = false", s)
		}
	}
	for _, s := range []string{"", "A", strings.Repeat("x", 33), "E404", "v2", "in transit", "IN.TRANSIT", "a:b",
		"DЕLIVERED", "annulé", "OPEN\n", "OPEN ", "\tOPEN", "DELI​VERED", "a+b"} {
		if CodeValue([]byte(s)) {
			t.Errorf("CodeValue(%q) = true", s)
		}
	}
}

func TestNameWords(t *testing.T) {
	for in, want := range map[string]string{
		"orderStatus":     "order status",
		"order_status":    "order status",
		"x-error-code":    "x error code",
		"HTTPStatus":      "http status",
		"error2Code":      "error2 code",
		"paymentMethodV2": "payment method v2",
		"status":          "status",
		"__status__":      "status",
		"OrderID":         "order id",
		"a.b":             "a b",
	} {
		if got := strings.Join(NameWords(in), " "); got != want {
			t.Errorf("NameWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeName(t *testing.T) {
	yes := []string{"status", "Status", "STATUS", "orderStatus", "order_status", "paymentState", "deliveryType",
		"kind", "cancelReason", "failure_reason", "code", "errorCode", "error_code", "category_code", "outcome",
		"result", "stage", "phase", "step", "mode", "paymentMethod", "channel", "level", "severity", "x-order-status",
		"x-error-code", "currency", "event", "eventType", "HTTPStatus"}
	no := []string{"name", "city", "user", "email", "address", "description", "note", "comment", "title", "category",
		"statusText", "statusMessage", "zipCode", "zip_code", "postalCode", "promoCode", "coupon_code", "otp_code",
		"verificationCode", "authCode", "resetCode", "inviteCode", "referralCode", "accessCode", "pinCode",
		"securityCode", "apiKeyType", "token_type", "session_state", "trackingCode", "taxCode", "iban_code", "id",
		"orderId", "statuses", "status2", ""}
	for _, n := range yes {
		if !CodeName(n) {
			t.Errorf("CodeName(%q) = false", n)
		}
	}
	for _, n := range no {
		if CodeName(n) {
			t.Errorf("CodeName(%q) = true", n)
		}
	}
}

func TestCodeRuleAllowed(t *testing.T) {
	for _, c := range []struct {
		kind, name string
		ok         bool
	}{
		{CodePartBody, "$.status", true},
		{CodePartBody, "$.items[*].status", true},
		{CodePartBody, "$.order.payment.state", true},
		{CodePartBody, "$.*.status", true},
		{CodePartBody, "$.status[*]", false},
		{CodePartBody, "$.status.*", false},
		{CodePartBody, "$", false},
		{CodePartBody, "$.name", false},
		{CodePartBody, "$.status.name", false},
		{CodePartBody, "status", false},
		{CodePartPath, "status", true},
		{CodePartPath, "id", false},
		{CodePartQuery, "status", true},
		{CodePartQuery, "code", false},
		{CodePartQuery, "CODE", false},
		{CodePartQuery, "state", false},
		{CodePartQuery, "error_code", true},
		{CodePartHeaders, "x-order-status", true},
		{CodePartHeaders, "authorization", false},
		{CodePartHeaders, "x-api-key", false},
		{CodePartCookies, "status", false},
		{"other", "status", true},
	} {
		if got := CodeRuleAllowed(c.kind, c.name); got != c.ok {
			t.Errorf("CodeRuleAllowed(%s, %q) = %v, want %v", c.kind, c.name, got, c.ok)
		}
	}
}

func TestCodeRuleSafeAndProposals(t *testing.T) {
	for _, c := range []struct {
		kind, name string
		safe, auto bool
	}{
		{CodePartBody, "$.version", true, false},
		{CodePartBody, "$.itemId", true, false},
		{CodePartBody, "$.itemCode", true, true},
		{CodePartBody, "$.Body.Get.@type", true, true},
		{CodePartBody, "$.Body.status.#text", true, true},
		{CodePartBody, "$.#text", false, false},
		{CodePartBody, "$.firstName", false, false},
		{CodePartBody, "$.customer", false, false},
		{CodePartBody, "$.customerType", true, true},
		{CodePartBody, "$.otpCode", false, false},
		{CodePartQuery, "code", false, false},
		{CodePartHeaders, "x-api-key", false, false},
		{CodePartCookies, "lang", false, false},
	} {
		if got := CodeRuleSafe(c.kind, c.name); got != c.safe {
			t.Errorf("CodeRuleSafe(%s, %q) = %v", c.kind, c.name, got)
		}
		if got := CodeRuleAllowed(c.kind, c.name); got != c.auto {
			t.Errorf("CodeRuleAllowed(%s, %q) = %v", c.kind, c.name, got)
		}
	}
	for _, c := range []struct {
		name, observed string
		alnum          bool
		shape          string
		ok             bool
	}{
		{"$.storeCode", "drop:str:digits", true, CodeShapeAlnum, true},
		{"$.storeCode", "drop:str:digits", false, "", false},
		{"$.orderStatus", "drop:str:digits", true, CodeShapeAlnum, true},
		{"$.channelType", "drop:str:l8", true, CodeShapeAlnum, true},
		{"$.channelType", "drop:str:l8", false, CodeShapeAlpha, true},
		{"$.orderStatus", "drop:str:l32", true, CodeShapeAlpha, true},
		{"$.orderStatus", "drop:str:l128", true, "", false},
		{"$.orderStatus", "drop:str:uuid", true, "", false},
	} {
		shape, ok := CodeProposalShape(CodePartBody, c.name, c.observed, c.alnum)
		if shape != c.shape || ok != c.ok {
			t.Errorf("CodeProposalShape(%q, %q, %v) = %q, %v", c.name, c.observed, c.alnum, shape, ok)
		}
	}
}

func TestParseAndEncodeCodeAlnum(t *testing.T) {
	a, err := ParseAction("code(alnum)")
	if err != nil || a.Kind != ActCode || a.Shape != CodeShapeAlnum {
		t.Fatalf("ParseAction(code(alnum)) = %+v, %v", a, err)
	}
	b, err := ttjson.Encode(actionValue(a))
	if err != nil || string(b) != `{"action":"code","shape":"alnum"}` {
		t.Fatalf("encoded = %s, %v", b, err)
	}
	if _, err := ParseAction("code(digits)"); err == nil {
		t.Fatal("code(digits) accepted")
	}
}

func TestCompileBodies(t *testing.T) {
	doc := func(extra string) *Author {
		return author(t, `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},`+
			`"sampling":{"rate":0.05}`+extra+`}`)
	}
	m := meta(1, 1)
	m.Groups = []string{"shop"}
	// No author block, no default: no bodies (sources before v1.19 accept the body).
	body, p, err := Compile(doc(""), m)
	if err != nil || p.Bodies != nil || strings.Contains(string(body), "bodies") {
		t.Fatalf("no bodies expected: %v %s", err, body)
	}
	// tt-core default.
	m.Bodies = DefaultBodies()
	if _, p, err = Compile(doc(""), m); err != nil || p.Bodies == nil || *p.Bodies != *DefaultBodies() {
		t.Fatalf("default bodies: %+v %v", p.Bodies, err)
	}
	// Author overrides, round trip through the compiled body.
	body, p, err = Compile(doc(`,"bodies":{"xml":false,"max_large_body_bytes":2097152,"large_array":20}`), m)
	if err != nil || p.Bodies.XML || !p.Bodies.Multipart || p.Bodies.MaxLargeBytes != 2097152 || p.Bodies.LargeArray != 20 || p.Bodies.LargeNestedArray != DefaultLargeNestedArray {
		t.Fatalf("author bodies: %+v %v", p.Bodies, err)
	}
	q, err := DecodeBody(body)
	if err != nil || *q.Bodies != *p.Bodies || q.CaptureLimit() != 2097153 {
		t.Fatalf("round trip: %+v %v", q, err)
	}
	// Everything off: no object at all.
	if _, p, err = Compile(doc(`,"bodies":{"xml":false,"multipart":false,"docs":false,"max_large_body_bytes":0}`), m); err != nil || p.Bodies != nil {
		t.Fatalf("all off: %+v %v", p.Bodies, err)
	}
	for _, bad := range []string{`,"bodies":{"max_large_body_bytes":67108865}`, `,"bodies":{"large_array":1025}`, `,"bodies":{"yaml":true}`} {
		a, err := authorErr(`{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},` +
			`"sampling":{"rate":0.05}` + bad + `}`)
		if err == nil {
			_, _, err = Compile(a, m)
		}
		if err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseAndEncodeCode(t *testing.T) {
	a, err := ParseAction("code")
	if err != nil || a.Kind != ActCode {
		t.Fatalf("ParseAction(code) = %+v, %v", a, err)
	}
	b, err := ttjson.Encode(actionValue(a))
	if err != nil || string(b) != `{"action":"code"}` {
		t.Fatalf("encoded = %s, %v", b, err)
	}
}

// codePolicy compiles a policy with one operation and the given op rules.
func codePolicy(t *testing.T, rules string) (*Policy, error) {
	t.Helper()
	doc := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},` +
		`"sampling":{"rate":0.05},"services":{"shop-api":{"match":{"inbound":true},"ops":{"GET /orders/{state}":` + rules + `}}}}`
	m := meta(1, 1)
	m.Groups = []string{"shop"}
	_, p, err := Compile(author(t, doc), m)
	return p, err
}

func TestValidateCodeRules(t *testing.T) {
	ok := []string{
		`{"response":{"$.status":"code","$.items[*].status":"code","$.error.code":"code"}}`,
		`{"request":{"path":{"state":"code"},"query":{"status":"code"},"headers":{"x-order-status":"code"}}}`,
		// Spec v1.19: a person may mark any field as a code field (not a
		// secret, a credential, a postal or personal field).
		`{"response":{"$.category":"code","$.itemId":"code(alnum)","$.version":"code(alnum)","$.Body.Get.@type":"code(alnum)","$.Body.Get.state.#text":"code"}}`,
	}
	for _, r := range ok {
		if _, err := codePolicy(t, r); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	bad := []string{
		`{"response":{"$.name":"code"}}`,
		`{"response":{"$.email":"code"}}`,
		`{"response":{"$.customerName":"code(alnum)"}}`,
		`{"response":{"$.#text":"code"}}`,
		`{"request":{"headers":{"x-user":"code(alnum)"}}}`,
		`{"response":{"$.zipCode":"code(alnum)"}}`,
		`{"response":{"$.status[*]":"code"}}`,
		`{"response":{"$.*":"code"}}`,
		`{"request":{"query":{"code":"code"}}}`,
		`{"request":{"query":{"state":"code"}}}`,
		`{"request":{"cookies":{"status":"code"}}}`,
		`{"request":{"headers":{"authorization":"code"}}}`,
		`{"request":{"headers":{"x-user":"code"}}}`,
		`{"response":{"$.promoCode":"code"}}`,
	}
	for _, r := range bad {
		if _, err := codePolicy(t, r); err == nil {
			t.Errorf("%s: accepted", r)
		}
	}
}

func TestCheckUnsafeCode(t *testing.T) {
	p, err := codePolicy(t, `{"response":{"$.status":"code"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckUnsafe(p); err != nil {
		t.Fatalf("code on $.status: %v", err)
	}
	q := *p
	q.Global.Request.Headers = map[string]Action{"cookie": {Kind: ActCode}}
	if err := CheckUnsafe(&q); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("H1 code on cookie: %v", err)
	}
	q = *p
	q.Global.Response.Body = []BodyRule{{Path: "$.items[*].status", Action: Action{Kind: ActCode}}}
	if err := CheckUnsafe(&q); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("H2 code on a global wildcard: %v", err)
	}
}

func TestClassifyCode(t *testing.T) {
	g := []string{"shop"}
	starter := obsPolicy(t, g, "")
	codes := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "GET /orders/{id}":{"response":{"$.status":"code","$.items[*].state":"code","$.error.code":"code"}}}}}`)
	if c := ClassifyValues(starter, codes); c.OpensValues {
		t.Fatalf("code on status fields must be observe-safe: %v", reasons(c))
	}
	if HasValues(codes) {
		t.Fatal("code rules are not values for the volume reasons")
	}
	// More sampling with only code rules stays observe-safe.
	more := obsPolicy(t, g, `"sampling":{"rate":0.5},"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "GET /orders/{id}":{"response":{"$.status":"code","$.items[*].state":"code","$.error.code":"code"}}}}}`)
	if c := ClassifyValues(codes, more); c.OpensValues {
		t.Fatalf("sampling with code rules only: %v", reasons(c))
	}
	// code -> keep opens (keep); keep -> code closes.
	keep := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "GET /orders/{id}":{"response":{"$.status":"keep","$.items[*].state":"code","$.error.code":"code"}}}}}`)
	if c := ClassifyValues(codes, keep); !slices.Contains(reasons(c), "keep@services.shop-api.ops.GET /orders/{id}.response.body.$.status") {
		t.Fatalf("code -> keep must open: %v", reasons(c))
	}
	if c := ClassifyValues(keep, codes); c.OpensValues {
		t.Fatalf("keep -> code must not open: %v", reasons(c))
	}
	// A code rule on a field that is not a status (refused by validation)
	// opens with code_field when classified anyway.
	odd := *codes
	odd.Services = slices.Clone(codes.Services)
	odd.Services[0].Ops = slices.Clone(codes.Services[0].Ops)
	odd.Services[0].Ops[0].Response.Body = append(slices.Clone(codes.Services[0].Ops[0].Response.Body),
		BodyRule{Path: "$.email", Action: Action{Kind: ActCode}})
	if c := ClassifyValues(codes, &odd); !slices.Contains(reasons(c), "code_field@services.shop-api.ops.GET /orders/{id}.response.body.$.email") {
		t.Fatalf("code on $.email: %v", reasons(c))
	}
	// Removing a code rule while the policy keeps values opens (a broader
	// rule may apply), like drop and hmac.
	k2 := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "GET /orders/{id}":{"response":{"$.status":"keep"}}}}}`)
	if c := ClassifyValues(keep, k2); !slices.Contains(reasons(c), "rule_removed_with_values@services.shop-api.ops.GET /orders/{id}.response.body.$.error.code") {
		t.Fatalf("removing code with values: %v", reasons(c))
	}
}
