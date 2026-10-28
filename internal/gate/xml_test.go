package gate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/event"
)

// A contract of a SOAP service passes provenance and PII: x-tt-xml holds
// only fmt values and namespace patterns (sanitizer.md 22.2, spec v1.19). A
// value slipped into it does not pass.
func TestGateXMLContract(t *testing.T) {
	in := contract.NewInferrer(contract.DefaultConfig(), nil)
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		ev := &event.Event{Service: "orders-ws", Op: "POST /ws/orders.asmx#GetOrder", Dir: event.Inbound, Status: 200,
			Subject: fmt.Sprintf("tk1:k1:%022d", 1000+i%20), Time: t0.Add(time.Duration(i) * time.Second), RouteSource: event.RoutePolicy}
		ev.Req.Path = "/ws/orders.asmx"
		body, _ := event.ParseCanonical([]byte(`{"Envelope":{"Body":{"GetOrder":{"@lang":"drop:str:l8","orderNumber":"drop:str:l32"}}}}`))
		ev.Req.Body, ev.Req.CT, ev.Req.Fmt, ev.Req.SoapAction = &body, "text/xml", event.FmtSOAP11, "GetOrder"
		ev.Req.XMLNS = []event.XMLNSEntry{{Path: "$.Envelope", Token: "ns:http://schemas.xmlsoap.org/soap/envelope/"},
			{Path: "$.Envelope.Body.GetOrder", Token: "ns:http://ws.shop-internal.net/orders/{*}/v2"}}
		ev.Resp = &event.Response{CT: "text/xml"}
		in.Add(ev, nil)
	}
	doc, err := in.Contracts(contract.Window{})[0].JSON(contract.RenderOptions{PackSafe: true, NoExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	run := func(doc string) map[string]string {
		inp := input(okWorld, &fakeMatcher{})
		inp.Files["contracts/orders-ws.openapi.json"] = []byte(doc)
		res, err := Run(context.Background(), inp)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Report.Checks {
			if c.Status == "fail" {
				t.Logf("%s: %+v", c.ID, c.Findings)
			}
		}
		return status(res)
	}
	if !strings.Contains(string(doc), `"x-tt-xml"`) {
		t.Fatalf("no x-tt-xml: %s", doc)
	}
	if st := run(string(doc)); st[CheckProvenance] != "pass" || st[CheckPII] != "pass" {
		t.Fatalf("SOAP contract refused: %v", st)
	}
	bad := strings.Replace(string(doc), `"format":"soap11"`, `"format":"mario.rossi@example.org"`, 1)
	if bad == string(doc) {
		t.Fatal("fixture changed")
	}
	if st := run(bad); st[CheckProvenance] != "fail" {
		t.Fatalf("a value in x-tt-xml passed: %v", st)
	}
}
