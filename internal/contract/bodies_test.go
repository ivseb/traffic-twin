package contract

import (
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Spec v1.19 bodies (sanitizer.md 22): an XML or SOAP body is an object tree
// whose envelope (fmt and namespaces) is kept for the mock as x-tt-xml;
// attributes become XML attributes of the schema; a SOAP operation is a
// logical op "<op>#<name>" (event.md 6); a multipart body is a form; a large
// body's truncated arrays leave no minItems; document shapes never break
// the inference.
func TestXMLBodyContract(t *testing.T) {
	const soapNS = "ns:http://schemas.xmlsoap.org/soap/envelope/"
	var evs []*event.Event
	for i := 0; i < 40; i++ {
		e := mkEv(t, evSpec{service: "orders-ws", op: "POST /ws/orders.asmx#GetOrder", status: 200, subject: tok(1000 + i%20),
			path: "/ws/orders.asmx", at: t0.Add(time.Duration(i) * time.Second),
			reqBody: `{"Envelope":{"Body":{"GetOrder":{"orderNumber":"drop:str:l32"}}}}`, reqCT: "text/xml",
			resBody: `{"Envelope":{"Body":{"GetOrderResponse":{"GetOrderResult":{"@status":"keep:OPEN","line":["drop:str:l8","trunc:n:l128"]}}}}}`,
			resCT:   "text/xml"})
		e.Req.Fmt, e.Req.SoapAction = event.FmtSOAP11, "GetOrder"
		e.Req.XMLNS = []event.XMLNSEntry{{Path: "$.Envelope", Token: soapNS}, {Path: "$.Envelope.Body.GetOrder", Token: "ns:http://ws.shop.example/orders/v2/"}}
		e.Resp.Fmt = event.FmtSOAP11
		e.Resp.XMLNS = []event.XMLNSEntry{{Path: "$.Envelope", Token: soapNS}}
		evs = append(evs, e)
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	op := c.Op("POST /ws/orders.asmx#GetOrder")
	if op == nil {
		t.Fatalf("no SOAP logical operation: %+v", c.Ops)
	}
	req := op.Body[0]
	if req.XML == nil || req.XML.Format != "soap11" || req.XML.Namespaces["$.Envelope"] != soapNS ||
		req.XML.Namespaces["$.Envelope.Body.GetOrder"] != "ns:http://ws.shop.example/orders/v2/" {
		t.Fatalf("request xml: %+v", req.XML)
	}
	res := op.Response(200).Body[0]
	result := res.Schema.Prop("Envelope").Schema.Prop("Body").Schema.Prop("GetOrderResponse").Schema.Prop("GetOrderResult").Schema
	if lines := result.Prop("line").Schema; lines.MinItems != nil {
		t.Fatalf("a truncated array has no minItems: %+v", lines)
	}
	b, err := c.JSON(RenderOptions{NoExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"x-tt-xml":{"format":"soap11","namespaces":{"$.Envelope":"ns:http://schemas.xmlsoap.org/soap/envelope/"`,
		`"@status":{`, `"xml":{"attribute":true,"name":"status"}`, `"/ws/orders.asmx#GetOrder"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("render misses %s: %.3000s", want, b)
		}
	}
}

func TestMultipartAndDocumentContract(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 30; i++ {
		e := mkEv(t, evSpec{service: "upload-api", op: "POST /uploads", status: 201, subject: tok(2000 + i%15),
			at:      t0.Add(time.Duration(i) * time.Second),
			reqBody: `{"file":["drop:file:pdf:l16k"],"note":["drop:str:l32"]}`, reqCT: event.CTMultipart,
			resBody: `{"id":"` + tok(i) + `","preview":"drop:doc:png:l1k"}`})
		e.Req.Fmt = event.FmtMultipart
		evs = append(evs, e)
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	op := c.Op("POST /uploads")
	body := op.Body[0]
	if body.XML != nil {
		t.Fatalf("a multipart body is not XML: %+v", body.XML)
	}
	for _, name := range []string{"note", "file"} {
		p := body.Schema.Prop(name)
		if p == nil || len(p.Schema.Types) != 1 || p.Schema.Types[0] != "string" {
			t.Fatalf("multipart part %s is a form field (one string): %+v", name, p)
		}
	}
	if _, err := c.JSON(RenderOptions{}); err != nil {
		t.Fatal(err)
	}
}
