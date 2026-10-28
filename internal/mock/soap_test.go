package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ttcontract "github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// SOAP and XML operations (docs/spec/mock.md 10). The contracts come from
// invented exchanges that go through the real sanitizer (bodies.xml on),
// the logical split of the intake (event.md 6.1) and the contract
// inference, exactly as tt-core builds a pack. All names and values are
// invented.

const (
	ordNS    = "http://ws.example.test/orders/v1"
	quoteNS  = "urn:example:quotes"
	soapEnv  = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="` + nsSOAP11 + `"><soap:Body>`
	soapEnd  = `</soap:Body></soap:Envelope>`
	soap12Ev = `<env:Envelope xmlns:env="` + nsSOAP12 + `"><env:Body>`
	soap12Ed = `</env:Body></env:Envelope>`
)

type xmlExchange struct {
	service, path, ct, action string
	req                       string
	status                    int
	resp, respCT              string
}

// soapExchanges is the invented traffic: a SOAP 1.1 order service (create,
// read by id with attributes and repeated lines, a fault, a ping with no
// SOAPAction), a SOAP 1.2 quote service (action in the content type) and a
// plain XML endpoint.
func soapExchanges(n int) []xmlExchange {
	var out []xmlExchange
	for i := 0; i < n; i++ {
		oid := fmt.Sprintf("ORD-2026-%06d", 500+i)
		out = append(out,
			xmlExchange{service: "orders-ws", path: "/ws/orders.asmx", ct: "text/xml; charset=utf-8", action: `"` + ordNS + `/IOrders/CreateOrder"`,
				req: soapEnv + `<CreateOrder xmlns="` + ordNS + `"><order><customerRef>CUST-` + fmt.Sprint(1000+i) + `</customerRef>` +
					`<line sku="SKU-` + fmt.Sprint(i) + `" qty="2"/><line sku="SKU-9" qty="1"/></order></CreateOrder>` + soapEnd,
				status: 200, respCT: "text/xml; charset=utf-8",
				resp: soapEnv + `<CreateOrderResponse xmlns="` + ordNS + `"><CreateOrderResult><orderId>` + oid + `</orderId>` +
					`<status>CREATED</status></CreateOrderResult></CreateOrderResponse>` + soapEnd},
			xmlExchange{service: "orders-ws", path: "/ws/orders.asmx", ct: "text/xml; charset=utf-8", action: `"` + ordNS + `/IOrders/GetOrder"`,
				req:    soapEnv + `<GetOrder xmlns="` + ordNS + `"><orderId>` + oid + `</orderId></GetOrder>` + soapEnd,
				status: 200, respCT: "text/xml; charset=utf-8",
				resp: soapEnv + `<GetOrderResponse xmlns="` + ordNS + `"><GetOrderResult currency="EUR"><orderId>` + oid + `</orderId>` +
					`<status>OPEN</status><customerRef>CUST-1</customerRef><line sku="SKU-1" qty="2"/><line sku="SKU-9" qty="1"/></GetOrderResult></GetOrderResponse>` + soapEnd},
			xmlExchange{service: "orders-ws", path: "/ws/orders.asmx", ct: "text/xml; charset=utf-8",
				req:    soapEnv + `<Ping xmlns="` + ordNS + `"/>` + soapEnd,
				status: 200, respCT: "text/xml; charset=utf-8",
				resp: soapEnv + `<PingResponse xmlns="` + ordNS + `"><PingResult>true</PingResult></PingResponse>` + soapEnd},
			xmlExchange{service: "quotes-ws", path: "/soap/quotes", ct: `application/soap+xml; charset=utf-8; action="urn:example:quotes#GetQuote"`,
				req:    soap12Ev + `<q:GetQuote xmlns:q="` + quoteNS + `"><q:amount>12</q:amount></q:GetQuote>` + soap12Ed,
				status: 200, respCT: "application/soap+xml; charset=utf-8",
				resp: soap12Ev + `<q:GetQuoteResponse xmlns:q="` + quoteNS + `"><q:price>14</q:price></q:GetQuoteResponse>` + soap12Ed},
			xmlExchange{service: "quotes-ws", path: "/api/rate", ct: "application/xml",
				req:    `<RateRequest><currency>EUR</currency></RateRequest>`,
				status: 200, respCT: "application/xml",
				resp: `<RateResponse source="desk"><rate>1.1</rate><rate>1.2</rate></RateResponse>`},
		)
		if i%5 == 0 {
			out = append(out, xmlExchange{service: "orders-ws", path: "/ws/orders.asmx", ct: "text/xml; charset=utf-8", action: `"` + ordNS + `/IOrders/GetOrder"`,
				req:    soapEnv + `<GetOrder xmlns="` + ordNS + `"><orderId>ORD-0</orderId></GetOrder>` + soapEnd,
				status: 500, respCT: "text/xml; charset=utf-8",
				resp: soapEnv + `<soap:Fault><faultcode>soap:Client</faultcode><faultstring>Order not found</faultstring></soap:Fault>` + soapEnd})
		}
	}
	return out
}

func soapPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	ops := func(rules map[string]any) map[string]any { return rules }
	author := map[string]any{
		"format": "tt.policy/v1", "policy_id": "p-soap", "default": "drop",
		"hmac":     map[string]any{"kid": "k1", "epoch": "2026-10"},
		"identity": map[string]any{"subject": map[string]any{"from": "header", "name": "x-user-id"}},
		"sampling": map[string]any{"rate": 1},
		"services": map[string]any{
			"orders-ws": map[string]any{"match": map[string]any{"inbound": true}, "ops": map[string]any{
				"POST /ws/orders.asmx": ops(map[string]any{
					"request": map[string]any{"$.Envelope.Body.GetOrder.orderId": "hmac(order)"},
					"response": map[string]any{
						"$.Envelope.Body.CreateOrderResponse.CreateOrderResult.orderId": "hmac(order)",
						"$.Envelope.Body.CreateOrderResponse.CreateOrderResult.status":  "code",
						"$.Envelope.Body.GetOrderResponse.GetOrderResult.orderId":       "hmac(order)",
						"$.Envelope.Body.GetOrderResponse.GetOrderResult.status":        "code",
						"$.Envelope.Body.GetOrderResponse.GetOrderResult.@currency":     "code",
						"$.Envelope.Body.PingResponse.PingResult":                       "code",
					}}),
			}},
			"quotes-ws": map[string]any{"match": map[string]any{"inbound": true}, "ops": map[string]any{
				"POST /soap/quotes": map[string]any{"request": map[string]any{}, "response": map[string]any{}},
				"POST /api/rate":    map[string]any{"request": map[string]any{"$.RateRequest.currency": "code"}, "response": map[string]any{"$.RateResponse.@source": "code"}},
			}},
		},
	}
	b, _ := json.Marshal(author)
	var doc any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: t0.Add(-time.Hour), Groups: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	p.Bodies = policy.DefaultBodies()
	return p
}

// soapContracts sanitizes the exchanges and infers the contracts of the
// two services, keyed by service.
func soapContracts(t *testing.T) map[string][]byte {
	t.Helper()
	p := soapPolicy(t)
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := sanitizer.NewEngineWithKey(p, key)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	in := ttcontract.NewInferrer(ttcontract.DefaultConfig(), nil)
	for i, x := range soapExchanges(25) {
		hdr := []sanitizer.Header{{Name: "Content-Type", Value: []byte(x.ct)}, {Name: "X-User-Id", Value: []byte(fmt.Sprintf("user-%02d", i%20))}}
		if x.action != "" {
			hdr = append(hdr, sanitizer.Header{Name: "SOAPAction", Value: []byte(x.action)})
		}
		ex := &sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: x.service, Method: "POST", RawPath: []byte(x.path),
			ReqHeaders: hdr, ReqBody: []byte(x.req), Status: x.status,
			RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte(x.respCT)}}, RespBody: []byte(x.resp)}
		ts := t0.Add(time.Duration(i) * time.Second)
		o, err := eng.Sanitize(ex, ts, sanitizer.ByRandom)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := sanitizer.BuildEvent(sanitizer.EventMeta{PolicyID: p.PolicyID, PolicyVersion: 1,
			PolicyHash: "sha256:" + strings.Repeat("ab", 32), SourceKind: "sdk-node", SourceVersion: "1.0.0", SourceID: "src-soap01",
			TS: ts, LatencyMS: 9, Status: x.status}, o)
		if err != nil {
			t.Fatal(err)
		}
		ev, derr := event.Decode(raw)
		if derr != nil {
			t.Fatal(derr)
		}
		if name, ok := ev.SOAPOperation(); ok {
			ev.Op += "#" + name // the logical split of the intake (event.md 6.1)
		}
		in.Add(ev, nil)
	}
	out := map[string][]byte{}
	for _, c := range in.Contracts(ttcontract.Window{}) {
		doc, err := c.JSON(ttcontract.RenderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		out[c.Service] = doc
	}
	return out
}

// soapEntity is the entity of the SOAP order service, as a person writes
// it from the observed operations: created by CreateOrder with the order
// element as state, read by the orderId element of GetOrder.
const soapEntity = `{"name":"sorder","service":"orders-ws","id_domain":"sorder","id_field":"orderId","id_prefix":"SOR-SYN-",
  "created_by":{"op":"POST /ws/orders.asmx#CreateOrder","id":{"from":"resp.body","path":"$.Envelope.Body.CreateOrderResponse.CreateOrderResult.orderId"},
    "state":{"from":"req.body","path":"$.Envelope.Body.CreateOrder.order"},"defaults":{"status":"CREATED"}},
  "read_by":[{"op":"POST /ws/orders.asmx#GetOrder","by":{"from":"req.body","path":"$.Envelope.Body.GetOrder.orderId"},
    "at":{"from":"resp.body","path":"$.Envelope.Body.GetOrderResponse.GetOrderResult"}}]}`

func withSOAP(t *testing.T) func(*packtest.Spec) {
	docs := soapContracts(t)
	return func(sp *packtest.Spec) {
		svcs := sp.Manifest["services"].([]any)
		for _, name := range []string{"orders-ws", "quotes-ws"} {
			doc := docs[name]
			if doc == nil {
				t.Fatalf("no contract for %s", name)
			}
			sp.Files["contracts/"+name+".openapi.json"] = packtest.Canon(string(doc))
			svcs = append(svcs, map[string]any{"name": name, "contract": "contracts/" + name + ".openapi.json"})
		}
		sp.Manifest["services"] = svcs
		var rules map[string]any
		if err := json.Unmarshal(sp.Files["rules.json"], &rules); err != nil {
			t.Fatal(err)
		}
		rules["entities"] = append(rules["entities"].([]any), packtest.JSON(soapEntity))
		b, _ := json.Marshal(rules)
		sp.Files["rules.json"] = packtest.Canon(string(b))
	}
}

// xmlReq posts an XML body with its own content type.
func (e *env) xmlReq(path, ct, body string, hdr map[string]string) resp {
	e.t.Helper()
	req, err := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("X-User-Id", "user-test")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

// parseXMLResp parses an answer of the mock with the closed parser: the
// mock never writes what the sources would reject.
func parseXMLResp(t *testing.T, r resp) *sanitizer.XMLDoc {
	t.Helper()
	d, err := sanitizer.ParseXML(r.body)
	if err != nil {
		t.Fatalf("answer is not valid XML (%d): %s", r.status, r.body)
	}
	return d
}

func TestSOAPCreateThenReadBySOAPAction(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	sid := e.newSession(map[string]any{"seed": 3})
	h := sess(sid)
	h["SOAPAction"] = `"` + ordNS + `/IOrders/CreateOrder"`
	create := soapEnv + `<CreateOrder xmlns="` + ordNS + `"><order><customerRef>CUST-7</customerRef>` +
		`<line sku="SKU-A1" qty="3"/><line sku="SKU-B2" qty="1"/></order></CreateOrder>` + soapEnd
	r := e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml; charset=utf-8", create, h)
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/xml") {
		t.Fatalf("create: %d %s %s", r.status, r.header.Get("Content-Type"), r.body)
	}
	body := string(r.body)
	for _, want := range []string{`<soap:Envelope xmlns:soap="` + nsSOAP11 + `">`, `<soap:Body>`,
		`<CreateOrderResponse xmlns="` + ordNS + `">`, `<status>CREATED</status>`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create answer misses %s: %s", want, body)
		}
	}
	d := parseXMLResp(t, r)
	if d.Format != "soap11" {
		t.Fatalf("format %s", d.Format)
	}
	id, _ := dig(d.Tree, "Envelope", "Body", "CreateOrderResponse", "CreateOrderResult", "orderId").(string)
	if !strings.HasPrefix(id, "SOR-SYN-") {
		t.Fatalf("created id %q: %s", id, body)
	}

	// read it back: state of the entity (lines and their attributes, the
	// default status) inside the observed envelope
	h["SOAPAction"] = `"` + ordNS + `/IOrders/GetOrder"`
	r = e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<GetOrder xmlns="`+ordNS+`"><orderId>`+id+`</orderId></GetOrder>`+soapEnd, h)
	if r.status != 200 {
		t.Fatalf("get: %d %s", r.status, r.body)
	}
	d = parseXMLResp(t, r)
	res, _ := dig(d.Tree, "Envelope", "Body", "GetOrderResponse", "GetOrderResult").(map[string]any)
	if res == nil || res["orderId"] != id || res["status"] != "CREATED" || res["customerRef"] != "CUST-7" {
		t.Fatalf("read: %s", r.body)
	}
	lines, _ := res["line"].([]any)
	if len(lines) != 2 || dig(lines[0], "@sku") != "SKU-A1" || dig(lines[1], "@qty") != "1" {
		t.Fatalf("repeated elements with attributes: %s", r.body)
	}
	if _, ok := res["@currency"].(string); !ok {
		t.Fatalf("attribute from the contract: %s", r.body)
	}
	if !strings.Contains(string(r.body), `<line qty="3" sku="SKU-A1"/>`) || !strings.Contains(string(r.body), `<GetOrderResponse xmlns="`+ordNS+`">`) {
		t.Fatalf("attributes and namespace: %s", r.body)
	}

	// an id the session never created: the observed fault status, as a SOAP fault
	r = e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<GetOrder xmlns="`+ordNS+`"><orderId>SOR-SYN-9999</orderId></GetOrder>`+soapEnd, h)
	d = parseXMLResp(t, r)
	if r.status != 500 || dig(d.Tree, "Envelope", "Body", "Fault", "faultcode") != "soap:Client" ||
		dig(d.Tree, "Envelope", "Body", "Fault", "detail", "code") != "not_found" {
		t.Fatalf("unknown id: a SOAP 1.1 fault with 500: %d %s", r.status, r.body)
	}
	jr := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if !strings.Contains(string(jr.body), `"op":"POST /ws/orders.asmx#GetOrder"`) {
		t.Fatalf("journal op: %.2000s", jr.body)
	}
}

// Without SOAPAction the first element of the Body names the operation.
func TestSOAPRouteByBodyElement(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	r := e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<Ping xmlns="`+ordNS+`"/>`+soapEnd, nil)
	if r.status != 200 {
		t.Fatalf("ping: %d %s", r.status, r.body)
	}
	d := parseXMLResp(t, r)
	if v := dig(d.Tree, "Envelope", "Body", "PingResponse", "PingResult"); v != "true" {
		t.Fatalf("ping: %s", r.body)
	}
	// a SOAPAction that was never observed but a known Body element
	r = e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<Ping xmlns="`+ordNS+`"/>`+soapEnd, map[string]string{"SOAPAction": `"urn:other#Unknown"`})
	if r.status != 200 {
		t.Fatalf("ping with another action: %d %s", r.status, r.body)
	}
}

func TestSOAP12ActionInContentType(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	r := e.xmlReq("/__svc/quotes-ws/soap/quotes", `application/soap+xml; charset=utf-8; action="urn:example:quotes#GetQuote"`,
		soap12Ev+`<q:GetQuote xmlns:q="`+quoteNS+`"><q:amount>40</q:amount></q:GetQuote>`+soap12Ed, nil)
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "application/soap+xml") {
		t.Fatalf("quote: %d %s %s", r.status, r.header.Get("Content-Type"), r.body)
	}
	d := parseXMLResp(t, r)
	if d.Format != "soap12" || dig(d.Tree, "Envelope", "Body", "GetQuoteResponse", "price") == nil {
		t.Fatalf("quote: %s", r.body)
	}
	if !strings.Contains(string(r.body), `<GetQuoteResponse xmlns="`+quoteNS+`">`) {
		t.Fatalf("namespace of the operation: %s", r.body)
	}
	// unknown operation: a SOAP 1.2 Sender fault
	r = e.xmlReq("/__svc/quotes-ws/soap/quotes", `application/soap+xml; action="urn:example:quotes#Cancel"`,
		soap12Ev+`<q:Cancel xmlns:q="`+quoteNS+`"/>`+soap12Ed, nil)
	if r.status != 400 || r.header.Get(hdrUnmatched) != "no-operation" {
		t.Fatalf("unknown 1.2: %d %s", r.status, r.body)
	}
	d = parseXMLResp(t, r)
	if dig(d.Tree, "Envelope", "Body", "Fault", "Code", "Value") != "env:Sender" ||
		dig(d.Tree, "Envelope", "Body", "Fault", "Reason", "Text", "#text") != "operation not observed: Cancel" {
		t.Fatalf("1.2 fault: %s", r.body)
	}
	if !strings.Contains(string(r.body), `<env:Text xml:lang="en">`) {
		t.Fatalf("xml:lang: %s", r.body)
	}
}

func TestSOAPUnknownOperationFault(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	sid := e.newSession(nil)
	h := sess(sid)
	h["SOAPAction"] = `"` + ordNS + `/IOrders/DeleteOrder"`
	r := e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<DeleteOrder xmlns="`+ordNS+`"/>`+soapEnd, h)
	if r.status != 500 || r.header.Get(hdrUnmatched) != "no-operation" {
		t.Fatalf("unknown: %d %v %s", r.status, r.header, r.body)
	}
	d := parseXMLResp(t, r)
	if dig(d.Tree, "Envelope", "Body", "Fault", "faultcode") != "soap:Client" ||
		dig(d.Tree, "Envelope", "Body", "Fault", "faultstring") != "operation not observed: DeleteOrder" {
		t.Fatalf("fault: %s", r.body)
	}
	if !strings.Contains(string(r.body), `<soap:Fault><faultcode>soap:Client</faultcode><faultstring>`) {
		t.Fatalf("fault children unqualified and in order: %s", r.body)
	}
	jr := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if !strings.Contains(string(jr.body), `"reason":"no-operation"`) {
		t.Fatalf("journal: %.1500s", jr.body)
	}
}

// Faults: forced by the test (status, typed body as text, as XML, as an
// object) and the observed fault body of the contract.
func TestSOAPFaults(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	call := func(sid string) resp {
		h := sess(sid)
		h["SOAPAction"] = "GetOrder"
		return e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", soapEnv+`<GetOrder xmlns="`+ordNS+`"><orderId>X</orderId></GetOrder>`+soapEnd, h)
	}
	faults := func(sid string, rule map[string]any) {
		rule["service"], rule["op"], rule["p"] = "orders-ws", "POST /ws/orders.asmx#GetOrder", 1
		if r := e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{"mode": "custom", "rules": []any{rule}}); r.status != 200 {
			t.Fatalf("faults: %d %s", r.status, r.body)
		}
	}

	// observed status 500: the observed fault body of the contract
	sid := e.newSession(nil)
	faults(sid, map[string]any{"status": 500})
	r := call(sid)
	d := parseXMLResp(t, r)
	if r.status != 500 || dig(d.Tree, "Envelope", "Body", "Fault", "faultcode") == nil || dig(d.Tree, "Envelope", "Body", "Fault", "faultstring") == nil {
		t.Fatalf("observed fault: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "<soap:faultcode") {
		t.Fatalf("faultcode is unqualified: %s", r.body)
	}

	// a status the contract never observed: a generated fault
	sid = e.newSession(nil)
	faults(sid, map[string]any{"status": 503})
	r = call(sid)
	d = parseXMLResp(t, r)
	if r.status != 503 || dig(d.Tree, "Envelope", "Body", "Fault", "faultcode") != "soap:Server" ||
		dig(d.Tree, "Envelope", "Body", "Fault", "faultstring") != "Service Unavailable" {
		t.Fatalf("generated fault: %d %s", r.status, r.body)
	}

	// a body typed by a person: plain text is the fault string
	sid = e.newSession(nil)
	faults(sid, map[string]any{"status": 500, "body": "Ordine bloccato E-LOCKED"})
	r = call(sid)
	d = parseXMLResp(t, r)
	if dig(d.Tree, "Envelope", "Body", "Fault", "faultstring") != "Ordine bloccato E-LOCKED" {
		t.Fatalf("typed text: %s", r.body)
	}

	// typed XML is served as it is
	typed := soapEnv + `<soap:Fault><faultcode>soap:Server</faultcode><faultstring>E-42</faultstring></soap:Fault>` + soapEnd
	sid = e.newSession(nil)
	faults(sid, map[string]any{"status": 500, "body": typed})
	if r = call(sid); string(r.body) != typed {
		t.Fatalf("typed XML: %s", r.body)
	}

	// a typed object becomes the detail of the fault
	sid = e.newSession(nil)
	faults(sid, map[string]any{"status": 500, "body": map[string]any{"code": "E-LOCKED", "message": "order locked"}})
	r = call(sid)
	d = parseXMLResp(t, r)
	if dig(d.Tree, "Envelope", "Body", "Fault", "faultstring") != "order locked" ||
		dig(d.Tree, "Envelope", "Body", "Fault", "detail", "code") != "E-LOCKED" {
		t.Fatalf("typed object: %s", r.body)
	}

	// a typed Fault object is wrapped in the envelope, its children unqualified
	sid = e.newSession(nil)
	faults(sid, map[string]any{"status": 500, "body": map[string]any{"Fault": map[string]any{"faultcode": "soap:Server", "faultstring": "E-9"}}})
	r = call(sid)
	if !strings.Contains(string(r.body), `<soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>E-9</faultstring></soap:Fault>`) {
		t.Fatalf("typed Fault: %s", r.body)
	}
}

// Plain XML (POX) on an HTTP operation: request read with the closed
// parser and validated, answer written as XML with repeated elements.
func TestPlainXMLOperation(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	r := e.xmlReq("/__svc/quotes-ws/api/rate", "application/xml", `<RateRequest><currency>EUR</currency></RateRequest>`, nil)
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "application/xml") {
		t.Fatalf("rate: %d %s %s", r.status, r.header.Get("Content-Type"), r.body)
	}
	d := parseXMLResp(t, r)
	if d.Format != "xml" || d.Root != "RateResponse" {
		t.Fatalf("rate: %s", r.body)
	}
	if _, ok := dig(d.Tree, "RateResponse", "@source").(string); !ok {
		t.Fatalf("attribute: %s", r.body)
	}
	if rates, _ := dig(d.Tree, "RateResponse", "rate").([]any); len(rates) == 0 {
		t.Fatalf("repeated elements: %s", r.body)
	}
	// JSON on an XML operation is refused
	r = e.req("POST", "/__svc/quotes-ws/api/rate", map[string]any{"currency": "EUR"}, map[string]string{"X-User-Id": "u"})
	if r.status != 400 || r.header.Get(hdrUnmatched) != "invalid-request" {
		t.Fatalf("json on xml: %d %s", r.status, r.body)
	}
	if _, err := sanitizer.ParseXML(r.body); err != nil {
		t.Fatalf("plain XML error is XML: %s", r.body)
	}
}

// Malicious XML is rejected by the closed parser (hardening.md 3): no
// DTD, no entity, no deep nesting; the answer is a fault, never an echo.
func TestSOAPMaliciousXMLRejected(t *testing.T) {
	e := newEnv(t, withSpec(withSOAP(t)))
	deep := strings.Repeat("<a>", 300) + strings.Repeat("</a>", 300)
	for name, doc := range map[string]string{
		"xxe": `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + soapEnv[len(`<?xml version="1.0" encoding="utf-8"?>`):] +
			`<GetOrder xmlns="` + ordNS + `"><orderId>&x;</orderId></GetOrder>` + soapEnd,
		"billion laughs": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>`,
		"unknown entity": soapEnv + `<GetOrder xmlns="` + ordNS + `"><orderId>&bad;</orderId></GetOrder>` + soapEnd,
		"nesting":        soapEnv + deep + soapEnd,
		"not xml":        `{"orderId":"x"}`,
	} {
		r := e.xmlReq("/__svc/orders-ws/ws/orders.asmx", "text/xml", doc, map[string]string{"SOAPAction": "GetOrder"})
		if r.status != 500 || r.header.Get(hdrUnmatched) != "invalid-request" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		if strings.Contains(string(r.body), "passwd") || strings.Contains(string(r.body), "lol") {
			t.Fatalf("%s: echoed: %s", name, r.body)
		}
		d := parseXMLResp(t, r)
		if dig(d.Tree, "Envelope", "Body", "Fault", "faultcode") != "soap:Client" {
			t.Fatalf("%s: %s", name, r.body)
		}
	}
	// a JSON content type on a SOAP endpoint
	r := e.req("POST", "/__svc/orders-ws/ws/orders.asmx", map[string]any{"x": 1}, map[string]string{"X-User-Id": "u"})
	if r.status != 500 || r.header.Get(hdrUnmatched) != "invalid-request" {
		t.Fatalf("json: %d %s", r.status, r.body)
	}
}

// Unit: the writer fits the namespaces of the contract, escapes values and
// orders the SOAP children.
func TestRenderXMLNamespacesAndEscaping(t *testing.T) {
	x := &xmlSpec{format: "soap11", ns: map[string]string{
		"$.Envelope": nsSOAP11, "$.Envelope.Body.R": "urn:a", "$.Envelope.Body.R.inner": "", "$.Envelope.Body.R.item": "urn:b"}}
	body := map[string]any{"Envelope": map[string]any{"Header": map[string]any{"h": "1"}, "Body": map[string]any{"R": map[string]any{
		"@id": `a"<&`, "inner": "x<y", "item": []any{"1", map[string]any{"@k": "v", "#text": "t"}}, "nil": nil, "bad key": "skip", "n": json.Number("2.5"), "b": true}}}}
	out := string(renderXML(body, x))
	for _, want := range []string{
		`<soap:Envelope xmlns:soap="` + nsSOAP11 + `"><soap:Header>`, `</soap:Header><soap:Body>`,
		`<R xmlns="urn:a" id="a&quot;&lt;&amp;">`, `<inner xmlns="">x&lt;y</inner>`,
		`<item xmlns="urn:b">1</item><item xmlns="urn:b" k="v">t</item>`, `<b>true</b>`, `<n>2.5</n>`, `xsi:nil="true"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("misses %s: %s", want, out)
		}
	}
	if strings.Contains(out, "bad key") {
		t.Fatalf("invalid names are skipped: %s", out)
	}
	if _, err := sanitizer.ParseXML([]byte(out)); err != nil {
		t.Fatalf("not valid: %s", out)
	}
	// an observed fault code with another prefix stays a valid QName
	out = string(renderXML(map[string]any{"Envelope": map[string]any{"Body": map[string]any{"Fault": map[string]any{"faultcode": "s:Client", "faultstring": "x"}}}},
		&xmlSpec{format: "soap11", ns: map[string]string{"$.Envelope.Body.Fault.faultcode": "", "$.Envelope.Body.Fault.faultstring": ""}}))
	if !strings.Contains(out, `xmlns:s="`+nsSOAP11+`"`) {
		t.Fatalf("fault code prefix: %s", out)
	}
}

// Rules reach attributes and mixed text of the XML trees (tt-path .@name
// and .#text, sanitizer.md 5.0).
func TestTTPathXMLSteps(t *testing.T) {
	segs, err := parseTTPath("$.Envelope.Body.GetOrder.@id")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sanitizer.ParseXML([]byte(soapEnv + `<GetOrder xmlns="` + ordNS + `" id="ORD-7">note<x/></GetOrder>` + soapEnd))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := first(evalPath(doc.Tree, segs)); !ok || v != "ORD-7" {
		t.Fatalf("@id: %v", v)
	}
	segs, err = parseTTPath("$.Envelope.Body.GetOrder.#text")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := first(evalPath(doc.Tree, segs)); !ok || v != "note" {
		t.Fatalf("#text: %v", v)
	}
	for _, bad := range []string{"$.a.#textx", "$.a.@", "$.a.@1"} {
		if _, err := parseTTPath(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}
