package sanitizer

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Tests of the v1.19 bodies (sanitizer.md 22): hostile XML, multipart and
// base64 documents. All data is invented.

// engineBodies compiles an author policy and turns the bodies switches on.
func engineBodies(t testing.TB, author string, b *policy.Bodies) *Engine {
	t.Helper()
	p := compileJSON(t, author)
	p.Bodies = b
	e, err := NewEngineWithKey(p, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func xmlExchange(body []byte) *Exchange {
	return &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/ws"),
		ReqHeaders: hdr("Content-Type", "text/xml; charset=utf-8", "SOAPAction", `"http://ws.example/orders/v2/GetOrder"`),
		ReqBody:    body, Status: 200}
}

// reqField returns a field of the sanitized request.
func reqOut(t testing.TB, e *Engine, ex *Exchange, key string) ttjson.Value {
	t.Helper()
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	checkOutput(t.(*testing.T), out, false)
	v, _ := out.Req.Get(key)
	return v
}

func bigLimits(n int) string {
	return limitsAuthor(fmt.Sprintf(`{"max_body_bytes":%d}`, n))
}

func TestXMLHostileInputs(t *testing.T) {
	e := engineBodies(t, bigLimits(16<<20), policy.DefaultBodies())
	cases := map[string]string{
		"xxe": `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		"billion laughs": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">` +
			`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>`,
		"entity without dtd":     `<r>&lol;</r>`,
		"parameter entity":       `<!ENTITY % p "x"><r/>`,
		"doctype after root":     `<r/><!DOCTYPE r>`,
		"doctype inside":         `<r><!DOCTYPE r></r>`,
		"char ref too big":       `<r>&#` + strings.Repeat("9", 100000) + `;</r>`,
		"hex ref too big":        `<r>&#x` + strings.Repeat("F", 100000) + `;</r>`,
		"char ref surrogate":     `<r>&#xD800;</r>`,
		"char ref zero":          `<r>&#0;</r>`,
		"unterminated ref":       `<r>&#65</r>`,
		"nested open 1e6":        strings.Repeat("<a>", 1000000),
		"nested open closed 1e6": strings.Repeat("<a>", 1000000) + strings.Repeat("</a>", 1000000),
		"nested 257":             strings.Repeat("<a>", 257) + strings.Repeat("</a>", 257),
		"unclosed comment":       `<r><!-- ` + strings.Repeat("-", 100000),
		"unclosed cdata":         `<r><![CDATA[` + strings.Repeat("]", 100000),
		"many attributes dup":    `<r ` + strings.Repeat(`a="1" `, 50000) + `/>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if v := reqOut(t, e, xmlExchange([]byte(doc)), "body"); v.Str != "trunc:invalid-xml" {
				t.Fatalf("body = %+v, want trunc:invalid-xml", v)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}
}

func TestXMLHugeCharRefLeadingZeros(t *testing.T) {
	e := engineBodies(t, limitsAuthor(`{"max_body_bytes":1048576}`), policy.DefaultBodies())
	doc := `<r><v>&#` + strings.Repeat("0", 200000) + `65;</v></r>`
	out := canon(t, e, xmlExchange([]byte(doc)), t0)
	if !strings.Contains(out, `"body":{"r":{"v":"drop:str:l8"}}`) {
		t.Fatalf("got %s", out)
	}
}

// heapGrowth returns the bytes allocated by fn.
func heapGrowth(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// Deep nesting, wide documents and many namespaces must stay bounded: the
// parser keeps at most 256 open elements and only the content it can emit.
func TestXMLBoundedMemory(t *testing.T) {
	e := engineBodies(t, bigLimits(16<<20), policy.DefaultBodies())
	var wide bytes.Buffer
	wide.WriteString(`<r>`)
	for i := 0; i < 200000; i++ {
		fmt.Fprintf(&wide, `<n%d xmlns="urn:x:%d" a="v">t</n%d>`, i, i, i)
	}
	wide.WriteString(`</r>`)
	var deep bytes.Buffer
	for i := 0; i < 120; i++ {
		deep.WriteString(`<d>`)
	}
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&deep, `<leaf%d xmlns="urn:y"/>`, i)
	}
	for i := 0; i < 120; i++ {
		deep.WriteString(`</d>`)
	}
	for name, doc := range map[string][]byte{
		"open tags":   bytes.Repeat([]byte("<a>"), 1000000),
		"wide":        wide.Bytes(),
		"deep xmlns":  deep.Bytes(),
		"empty elems": append(append([]byte("<r>"), bytes.Repeat([]byte("<e/>"), 2000000)...), "</r>"...),
	} {
		t.Run(name, func(t *testing.T) {
			var out ttjson.Value
			grown := heapGrowth(func() { out = reqOut(t, e, xmlExchange(doc), "xmlns") })
			// A generous bound: well under 40 bytes of allocation per input byte.
			if limit := uint64(len(doc))*40 + 64<<20; grown > limit {
				t.Fatalf("allocated %d bytes for a %d-byte body", grown, len(doc))
			}
			if len(out.Obj) > xmlnsMaxEntries+1 {
				t.Fatalf("xmlns has %d entries", len(out.Obj))
			}
		})
	}
}

func TestXMLXmlnsTrunc(t *testing.T) {
	e := engineBodies(t, bigLimits(1<<20), policy.DefaultBodies())
	var b strings.Builder
	b.WriteString(`<r>`)
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, `<n%c%c xmlns="urn:x"/>`, 'a'+i/26, 'a'+i%26)
	}
	b.WriteString(`</r>`)
	v := reqOut(t, e, xmlExchange([]byte(b.String())), "xmlns")
	if len(v.Obj) != 65 {
		t.Fatalf("xmlns has %d entries", len(v.Obj))
	}
	if tr, _ := v.Get("{trunc}"); tr.Str != "trunc:keys:l128" {
		t.Fatalf("{trunc} = %q", tr.Str)
	}
	if first, _ := v.Get("$.r.naa"); first.Str != "ns:urn:x" {
		t.Fatalf("first entry %q", first.Str)
	}
}

func TestXMLSoapFields(t *testing.T) {
	e := engineBodies(t, bigLimits(1<<20), policy.DefaultBodies())
	doc := `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><GetOrder xmlns="http://ws.example/policy/v2"><id>P-2026-0001</id></GetOrder></soap:Body></soap:Envelope>`
	out := canon(t, e, xmlExchange([]byte(doc)), t0)
	for _, want := range []string{`"fmt":"soap11"`, `"soap_action":"GetOrder"`,
		`"xmlns":{"$.Envelope":"ns:http://schemas.xmlsoap.org/soap/envelope/","$.Envelope.Body.GetOrder":"ns:http://ws.example/policy/v2"}`,
		`"body":{"Envelope":{"Body":{"GetOrder":{"id":"drop:str:l32"}}}}`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
	// XML switch off: an XML body is not parsed and has no fmt.
	off := engine(t, bigLimits(1<<20))
	if out := canon(t, off, xmlExchange([]byte(doc)), t0); strings.Contains(out, "fmt") || strings.Contains(out, "soap_action") {
		t.Fatalf("bodies off: %s", out)
	}
}

func TestMultipartHostile(t *testing.T) {
	e := engineBodies(t, bigLimits(16<<20), policy.DefaultBodies())
	mk := func(body string) *Exchange {
		return &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/up"),
			ReqHeaders: hdr("Content-Type", "multipart/form-data; boundary=XyZ"), ReqBody: []byte(body), Status: 200}
	}
	var many strings.Builder
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&many, "--XyZ\r\nContent-Disposition: form-data; name=\"f%d\"\r\n\r\nv\r\n", i%100)
	}
	many.WriteString("--XyZ--\r\n")
	v := reqOut(t, e, mk(many.String()), "body")
	if len(v.Obj) != 65 {
		t.Fatalf("names = %d", len(v.Obj))
	}
	for name, body := range map[string]string{
		"no close":     "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n" + strings.Repeat("x", 100000),
		"quote":        "--XyZ\r\nContent-Disposition: form-data; name=\"" + strings.Repeat("\\", 100000) + "\r\n\r\nv\r\n--XyZ--",
		"header lines": "--XyZ\r\n" + strings.Repeat("X-A: b\r\n", 100000) + "\r\nv\r\n--XyZ--",
	} {
		t.Run(name, func(t *testing.T) {
			if v := reqOut(t, e, mk(body), "body"); v.Str != "trunc:invalid-multipart" {
				t.Fatalf("body = %+v", v)
			}
		})
	}
}

func TestBase64Doc(t *testing.T) {
	pdf := append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0x01}, 2000)...)
	zip := append(append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 5000)...), "word/document.xml"...)
	for _, c := range []struct {
		s, want string
	}{
		{base64.StdEncoding.EncodeToString(pdf), "drop:doc:pdf:l16k"},
		{base64.RawURLEncoding.EncodeToString(pdf), "drop:doc:pdf:l16k"},
		{"data:application/pdf;base64," + base64.StdEncoding.EncodeToString(pdf), "drop:doc:pdf:l16k"},
		{"data:application/pdf;base64;x," + base64.StdEncoding.EncodeToString(pdf), ""},
		{base64.StdEncoding.EncodeToString(zip), "drop:doc:docx:l16k"},
		{base64.StdEncoding.EncodeToString(pdf[:12]), "drop:doc:pdf:l1k"},
		{base64.StdEncoding.EncodeToString(pdf[:9]), ""}, // 12 characters: under the 16 minimum
		{base64.StdEncoding.EncodeToString(pdf) + "===", ""},
		{base64.StdEncoding.EncodeToString(pdf)[1:], ""},
		{strings.Repeat("A", 40), ""},
	} {
		if got := base64Doc([]byte(c.s)); got != c.want {
			t.Errorf("base64Doc(%.40q…) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestCodeAlnum(t *testing.T) {
	for s, want := range map[string]bool{"0000123450": true, "2.1": true, "R": true, "": false, "2 1": false,
		strings.Repeat("9", 17): false, "٣": false, "a_b-c.d": true} {
		if got := policy.CodeAlnumValue([]byte(s)); got != want {
			t.Errorf("CodeAlnumValue(%q) = %v", s, got)
		}
	}
}

var fuzzXMLSeeds = []string{
	`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
		`<m:Get xmlns:m="urn:x" m:id="7"><a>1</a><a>2</a>mixed<![CDATA[<x>]]></m:Get></soap:Body></soap:Envelope>`,
	`<r a="1" b='&lt;&#65;&#x42;'><x/><x/><y xml:lang="it">t</y><!-- c --><?pi x?></r>`,
	`<r xmlns:p="" ><p:a/></r>`, `<a:b:c/>`, `<r>&bad;</r>`, "\xef\xbb\xbf<r>\r\n</r>",
	`<r><` + strings.Repeat("d><", 40) + `/></r>`,
}

// FuzzXMLBody runs the XML parser and the tree walk on arbitrary bytes:
// never a panic, always grammar-valid output, never more than 256 open
// elements.
func FuzzXMLBody(f *testing.F) {
	for _, s := range fuzzXMLSeeds {
		f.Add([]byte(s))
	}
	b := policy.DefaultBodies()
	e := engineBodies(f, emptyAuthor, b)
	small := engineBodies(f, limitsAuthor(`{"max_depth":3,"max_array":2,"max_keys":2,"max_body_bytes":256}`),
		&policy.Bodies{XML: true, Multipart: true, Docs: true, MaxLargeBytes: 4096, LargeArray: 1, LargeNestedArray: 0})
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, eng := range []*Engine{e, small} {
			for _, ct := range []string{"application/soap+xml; action=\"urn:x#Do\"", "text/xml"} {
				ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/"), Status: 200,
					ReqHeaders: hdr("Content-Type", ct), ReqBody: body, RespHeaders: hdr("Content-Type", ct), RespBody: body}
				out, err := eng.Sanitize(ex, t0, ByRandom)
				if err != nil {
					t.Fatalf("sanitize: %v", err)
				}
				checkOutput(t, out, true)
			}
		}
		x := &xmlParser{maxDepth: 4, maxKeys: 3, storeCap: 2}
		if _, err := x.parse(body); err == nil && len(x.stack) != 0 {
			t.Fatalf("open elements after a valid document")
		}
	})
}

// FuzzMultipartBody runs the multipart parser on arbitrary bytes.
func FuzzMultipartBody(f *testing.F) {
	f.Add([]byte("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--B\r\nContent-Disposition: form-data; "+
		"name=\"f\"; filename=\"x.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4\r\n--B--\r\n"), "B")
	f.Add([]byte("pre\r\n--B \t\r\n\r\nno headers\r\n--B--"), "B")
	f.Add([]byte("--a b\r\nContent-Disposition: form-data; name=\"\\\"q\\\"\"\r\n\r\n\xff\r\n--a b--"), "\"a b\"")
	e := engineBodies(f, limitsAuthor(`{"max_array":2,"max_body_bytes":4096}`), policy.DefaultBodies())
	f.Fuzz(func(t *testing.T, body []byte, boundary string) {
		ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/"), Status: 200,
			ReqHeaders: []Header{{Name: "Content-Type", Value: []byte("multipart/form-data; boundary=" + boundary)}}, ReqBody: body}
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			t.Fatalf("sanitize: %v", err)
		}
		checkOutput(t, out, true)
	})
}

// soapBody builds an invented SOAP response of about n bytes.
func soapBody(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
		`<GetOrderResponse xmlns="http://ws.example/policy/v2"><GetOrderResult><policyId>P-2026-000184</policyId>`)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "\n  <line code=\"C%d\" kind=\"BASE\"><amount currency=\"EUR\">%d.50</amount>"+
			"<description>Copertura inventata numero %d &amp; note</description><valid from=\"2026-01-01\" to=\"2026-12-31\"/></line>", i%40, 100+i, i)
	}
	b.WriteString(`</GetOrderResult></GetOrderResponse></soap:Body></soap:Envelope>`)
	return b.Bytes()
}

// ~1 MiB SOAP response in large-body mode.
func BenchmarkSanitizeSOAP1MiB(b *testing.B) {
	e := engineBodies(b, benchAuthor, policy.DefaultBodies())
	body := soapBody(1 << 20)
	ex := benchExchange(body)
	ex.RespHeaders = hdr("Content-Type", "text/xml; charset=utf-8")
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := out.Canonical(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSOAPBenchBody(t *testing.T) {
	e := engineBodies(t, benchAuthor, policy.DefaultBodies())
	ex := benchExchange(soapBody(1 << 20))
	ex.RespHeaders = hdr("Content-Type", "text/xml; charset=utf-8")
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	b := checkOutput(t, out, false)
	if !bytes.Contains(b, []byte(`"fmt":"soap11"`)) || !bytes.Contains(b, []byte(`"line":[`)) ||
		!bytes.Contains(b, []byte(`"trunc:n:lmax"`)) {
		t.Fatalf("unexpected output %.600s", b)
	}
}
