package contract

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

var t0 = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

// tok returns a valid fake tk1 token for index i.
func tok(i int) string { return fmt.Sprintf("tk1:k1:%022d", i) }

func mustBody(t testing.TB, s string) *event.Value {
	t.Helper()
	v, err := event.ParseCanonical([]byte(s))
	if err != nil {
		t.Fatalf("body %s: %v", s, err)
	}
	return &v
}

type evSpec struct {
	service, op, dir string
	status           int
	netErr           string
	subject, trace   string
	latency          int64
	path             string
	query            event.Multi
	reqBody, resBody string
	reqCT, resCT     string
	at               time.Time
}

func mkEv(t testing.TB, s evSpec) *event.Event {
	t.Helper()
	if s.dir == "" {
		s.dir = event.Inbound
	}
	if s.path == "" {
		_, p, _ := event.ParseOp(s.op)
		s.path = p
	}
	if s.at.IsZero() {
		s.at = t0
	}
	ev := &event.Event{
		Service: s.service, Op: s.op, Dir: s.dir, Status: s.status, NetError: s.netErr,
		Subject: s.subject, TraceID: s.trace, LatencyMS: s.latency, Time: s.at, RouteSource: event.RoutePolicy,
	}
	ev.Req.Path = s.path
	ev.Req.Query = s.query
	if s.reqBody != "" {
		ev.Req.Body = mustBody(t, s.reqBody)
		ev.Req.CT = s.reqCT
		if ev.Req.CT == "" {
			ev.Req.CT = "application/json"
		}
	}
	if s.netErr == "" {
		ev.Resp = &event.Response{}
		if s.resBody != "" {
			ev.Resp.Body = mustBody(t, s.resBody)
			ev.Resp.CT = s.resCT
			if ev.Resp.CT == "" {
				ev.Resp.CT = "application/json"
			}
		}
	}
	return ev
}

func inferAll(t testing.TB, cfg Config, hints Hints, evs []*event.Event) *Contract {
	t.Helper()
	in := NewInferrer(cfg, hints)
	for _, e := range evs {
		in.Add(e, nil)
	}
	cs := in.Contracts(Window{From: t0, To: t0.Add(24 * time.Hour)})
	if len(cs) != 1 {
		t.Fatalf("contracts: %d", len(cs))
	}
	return cs[0]
}

// carrierEvents builds n GET /v1/shipments exchanges: 99% 200, 1% 503, eta
// in 37% of the items, 25 distinct subjects.
func carrierEvents(t testing.TB, n int) []*event.Event {
	var evs []*event.Event
	for i := 0; i < n; i++ {
		subj := tok(1000 + i%25)
		s := evSpec{service: "shipping-ext", op: "GET /v1/shipments", dir: event.Outbound, subject: subj,
			path: "/v1/shipments", latency: int64(70 + i%20), at: t0.Add(time.Duration(i) * time.Second)}
		switch {
		case i%100 == 99:
			s.status = 503
			s.resBody = `{"error":{"code":"keep:CARRIER_UNAVAILABLE","message":"drop:str:l32"}}`
		default:
			s.status = 200
			item := fmt.Sprintf(`{%s"orderId":"%s","shipmentId":"%s","status":"keep:%s"}`,
				map[bool]string{true: `"eta":"time:2026-10-21",`, false: ""}[i%100 < 37], tok(i), tok(5000+i), []string{"CREATED", "IN_TRANSIT", "DELIVERED"}[i%3])
			s.resBody = `{"items":[` + item + `]}`
		}
		s.query = event.Multi{{Name: "orderId", Values: []string{tok(i)}}}
		evs = append(evs, mkEv(t, s))
	}
	return evs
}

func TestInferCarrier(t *testing.T) {
	cfg := DefaultConfig()
	c := inferAll(t, cfg, nil, carrierEvents(t, 400))
	op := c.Op("GET /v1/shipments")
	if op == nil {
		t.Fatal("op missing")
	}
	if op.Calls != 400 {
		t.Errorf("calls %d", op.Calls)
	}
	r200, r503 := op.Response(200), op.Response(503)
	if r200 == nil || r503 == nil {
		t.Fatalf("responses %v", op.Responses)
	}
	if r503.Frequency < 0.0099 || r503.Frequency > 0.0101 {
		t.Errorf("503 frequency %v", r503.Frequency)
	}
	if op.Latency == nil || op.Latency.P50 < 70 || op.Latency.P50 > 90 || op.Latency.P99 < op.Latency.P50 {
		t.Errorf("latency %+v", op.Latency)
	}
	if len(op.Query) != 1 || op.Query[0].Name != "orderId" || !op.Query[0].Required || op.Query[0].Schema.Kind != "id" {
		t.Errorf("query %+v", op.Query)
	}
	items := r200.Body[0].Schema.Prop("items")
	if items == nil || !items.Required || !items.Schema.HasType("array") {
		t.Fatalf("items %+v", items)
	}
	it := items.Schema.Items
	for _, n := range []string{"orderId", "shipmentId", "status"} {
		if p := it.Prop(n); p == nil || !p.Required {
			t.Errorf("%s should be required: %+v", n, p)
		}
	}
	eta := it.Prop("eta")
	if eta == nil || eta.Required || eta.Presence < 0.36 || eta.Presence > 0.38 {
		t.Errorf("eta %+v", eta)
	}
	if eta.Schema.Kind != "bucket" || eta.Schema.Unit != "day" || eta.Schema.Format != "date-time" {
		t.Errorf("eta schema %+v", eta.Schema)
	}
	st := it.Prop("status").Schema
	if st.Kind != "enum" || len(st.PublishedEnum()) != 3 || st.EnumPartial {
		t.Errorf("status enum %+v", st)
	}
	code := r503.Body[0].Schema.Prop("error").Schema.Prop("code").Schema
	if code.Kind != "shape" || !code.EnumPartial {
		t.Errorf("error code below k should be hidden: %+v", code)
	}
}

func TestEnumKFilter(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 100; i++ {
		v := "COMMON"
		if i < 3 {
			v = "RARE"
		}
		evs = append(evs, mkEv(t, evSpec{service: "s", op: "GET /x", status: 200, subject: tok(i % 40),
			resBody: `{"k":"keep:` + v + `"}`}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	k := c.Ops[0].Response(200).Body[0].Schema.Prop("k").Schema
	if k.Kind != "enum" || !k.EnumPartial {
		t.Fatalf("kind %q partial %v", k.Kind, k.EnumPartial)
	}
	pub := k.PublishedEnum()
	if len(pub) != 1 || pub[0].Value != "COMMON" {
		t.Fatalf("published %+v", pub)
	}
	doc, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "RARE") {
		t.Error("hidden value leaked into the document")
	}
	if strings.Contains(string(doc), `"enum":["COMMON"]`) && !strings.Contains(string(doc), `"enum_partial":true`) {
		t.Error("partial enum must be flagged")
	}
}

func TestEnumTraceSubject(t *testing.T) {
	// Outbound events carry no subject: the resolver supplies the subject
	// of the inbound event of the same trace.
	in := NewInferrer(DefaultConfig(), nil)
	for i := 0; i < 30; i++ {
		i := i
		in.Add(mkEv(t, evSpec{service: "s", op: "GET /x", dir: event.Outbound, status: 200, trace: fmt.Sprintf("%032x", i),
			resBody: `{"k":"keep:A"}`}), func(ev *event.Event) string { return tok(100 + i) })
	}
	c := in.Contracts(Window{})[0]
	if k := c.Ops[0].Response(200).Body[0].Schema.Prop("k").Schema; k.Kind != "enum" {
		t.Fatalf("expected enum, got %+v", k)
	}
	// Without the resolver nothing can be published.
	in = NewInferrer(DefaultConfig(), nil)
	for i := 0; i < 30; i++ {
		in.Add(mkEv(t, evSpec{service: "s", op: "GET /x", dir: event.Outbound, status: 200, resBody: `{"k":"keep:A"}`}), nil)
	}
	if k := in.Contracts(Window{})[0].Ops[0].Response(200).Body[0].Schema.Prop("k").Schema; k.Kind == "enum" {
		t.Fatal("value without subjects must stay hidden")
	}
}

func TestNullableAndUnion(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 30; i++ {
		body := `{"a":"drop:str:l8","b":"drop:int","c":"drop:null"}`
		if i%2 == 0 {
			body = `{"a":"drop:str:l8","b":"drop:dec","c":"drop:str:email"}`
		}
		evs = append(evs, mkEv(t, evSpec{service: "s", op: "POST /y", status: 200, resBody: body}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	s := c.Ops[0].Response(200).Body[0].Schema
	if got := s.Prop("b").Schema.Types; len(got) != 1 || got[0] != "number" {
		t.Errorf("int+dec should be number: %v", got)
	}
	if got := s.Prop("c").Schema.Types; strings.Join(got, ",") != "string,null" {
		t.Errorf("c types %v", got)
	}
	if s.Prop("a").Schema.LenClass != "l8" {
		t.Errorf("len class %+v", s.Prop("a").Schema)
	}
}

func TestBucketNum(t *testing.T) {
	var evs []*event.Event
	toks := []string{"num:<0", "num:0-50", "num:50-100", "num:50-100", "num:100-250"}
	for i := 0; i < 100; i++ {
		evs = append(evs, mkEv(t, evSpec{service: "s", op: "GET /z", status: 200, subject: tok(i),
			resBody: `{"total":"` + toks[i%len(toks)] + `"}`}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	s := c.Ops[0].Response(200).Body[0].Schema.Prop("total").Schema
	if s.Kind != "bucket" || strings.Join(s.Bounds, ",") != "0,50,100,250" {
		t.Fatalf("bucket %+v", s)
	}
	if len(s.BucketP) != 5 || s.BucketP[2] < 0.39 || s.BucketP[2] > 0.41 {
		t.Errorf("bucket_p %v", s.BucketP)
	}
}

func TestParseBand(t *testing.T) {
	for tok, want := range map[string][3]string{
		"num:<0":            {"<", "0", ""},
		"num:>=250":         {">=", "250", ""},
		"num:-50--10":       {"-", "-50", "-10"},
		"num:1e-7-1e-5":     {"-", "1e-7", "1e-5"},
		"num:0-50":          {"-", "0", "50"},
		"num:1.5e+21-2e+21": {"-", "1.5e+21", "2e+21"},
	} {
		k, lo, hi, ok := parseBand(tok)
		if !ok || k != want[0] || lo != want[1] || hi != want[2] {
			t.Errorf("%s -> %q %q %q %v", tok, k, lo, hi, ok)
		}
	}
}

func TestPathParamsAndOutbound(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 25; i++ {
		evs = append(evs, mkEv(t, evSpec{service: "carrier", op: "GET /v1/rates/{zone}", dir: event.Outbound, status: 200,
			path: "/base/v1/rates/{" + tok(i) + "}", resBody: `{"rate":"drop:dec"}`}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	op := c.Ops[0]
	if len(op.PathParams) != 1 || op.PathParams[0].Name != "zone" || op.PathParams[0].Schema.Kind != "id" || !op.PathParams[0].Required {
		t.Fatalf("path params %+v", op.PathParams)
	}
}

func TestDeterministicRender(t *testing.T) {
	c := inferAll(t, DefaultConfig(), nil, carrierEvents(t, 300))
	a, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.JSON(RenderOptions{})
	if string(a) != string(b) {
		t.Fatal("render not deterministic")
	}
	y, err := c.YAML(RenderOptions{})
	if err != nil || !strings.Contains(string(y), "openapi: 3.1.0") {
		t.Fatalf("yaml: %v %.200s", err, y)
	}
	s := string(a)
	for _, want := range []string{`"x-tt-frequency"`, `"x-tt-presence":0.37`, `"x-tt-observed"`, `"x-tt-latency-ms"`, `"examples"`, `"required":["items"]`} {
		if !strings.Contains(s, want) {
			t.Errorf("document lacks %s", want)
		}
	}
	if strings.Contains(s, " ") && strings.Contains(s, "\n ") {
		t.Error("not canonical")
	}
}

func TestPackSafe(t *testing.T) {
	c := inferAll(t, DefaultConfig(), nil, carrierEvents(t, 300))
	doc := c.OpenAPI(RenderOptions{PackSafe: true})
	ops := doc["paths"].(map[string]any)["/v1/shipments"].(map[string]any)["get"].(map[string]any)
	resp := ops["responses"].(map[string]any)
	if _, ok := resp["503"]; ok {
		t.Error("503 has 3 calls (< k) and must not be published")
	}
	if _, ok := resp["200"]; !ok {
		t.Error("200 missing")
	}
}

func TestExamplesErrorCodes(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 60; i++ {
		evs = append(evs, mkEv(t, evSpec{service: "s", op: "GET /x", status: 404, subject: tok(i % 30),
			resBody: `{"error":{"code":"keep:ORDER_NOT_FOUND","message":"drop:str:l32"}}`}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	doc := c.OpenAPI(RenderOptions{})
	r := doc["paths"].(map[string]any)["/x"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["404"].(map[string]any)
	ex := r["content"].(map[string]any)["application/json"].(map[string]any)["examples"].(map[string]any)
	if _, ok := ex["order-not-found"]; !ok {
		t.Fatalf("examples %v", ex)
	}
}

func TestDiffBreaking(t *testing.T) {
	cfg := DefaultConfig()
	a := inferAll(t, cfg, nil, carrierEvents(t, 400))
	// New window: eta becomes an integer, a new 500 appears often, status loses a value.
	var evs []*event.Event
	for i := 0; i < 400; i++ {
		s := evSpec{service: "shipping-ext", op: "GET /v1/shipments", dir: event.Outbound, subject: tok(1000 + i%25),
			path: "/v1/shipments", latency: 80, at: t0.Add(24*time.Hour + time.Duration(i)*time.Second)}
		if i%10 == 0 {
			s.status = 500
			s.resBody = `{"error":{"code":"keep:BOOM","message":"drop:str:l32"}}`
		} else {
			s.status = 200
			s.resBody = fmt.Sprintf(`{"items":[{"eta":"drop:int","orderId":"%s","shipmentId":"%s","status":"keep:%s"}]}`, tok(i), tok(i), []string{"CREATED", "IN_TRANSIT"}[i%2])
		}
		evs = append(evs, mkEv(t, s))
	}
	b := inferAll(t, cfg, nil, evs)
	ch := Diff(a, b, cfg.Diff)
	want := map[string]string{
		"type-changed":     Breaking,
		"status-added":     Breaking,
		"enum-removed":     Breaking,
		"required-changed": "",
	}
	got := map[string]string{}
	for _, c := range ch {
		got[c.Kind] = c.Severity
		if strings.Contains(c.Text, "DELIVERED") || strings.Contains(c.Text, "BOOM") {
			t.Errorf("value in change text: %s", c.Text)
		}
	}
	for k, sev := range want {
		if sev == "" {
			continue
		}
		if got[k] != sev {
			t.Errorf("kind %s: got %q want %q (all: %v)", k, got[k], sev, ch)
		}
	}
	// Non-breaking: new optional field.
	var evs3 []*event.Event
	for _, e := range carrierEvents(t, 400) {
		e.Time = e.Time.Add(48 * time.Hour)
		if e.Status == 200 && e.LatencyMS%2 == 0 {
			items, _ := e.Resp.Body.Get("items")
			m := &items.A[0]
			m.O = append(m.O, event.Member{K: "note", V: event.Str("drop:str:l8")})
			m.SortMembers()
		}
		evs3 = append(evs3, e)
	}
	c3 := inferAll(t, cfg, nil, evs3)
	for _, c := range Diff(a, c3, cfg.Diff) {
		if c.Kind == "field-added" && c.Severity != NonBreaking {
			t.Errorf("new optional field must be non-breaking: %+v", c)
		}
	}
}
