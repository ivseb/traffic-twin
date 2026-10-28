package sanitizer_rt

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Invented markers: none of these may appear in any output under the empty
// policy (THREAT_MODEL G1, sanitizer.md §13).
const (
	mWord  = "qzvmarkerqz"
	mMail  = "qwxjuno.vqz@kzqwx.zqx"
	mDigit = "73519284"
)

type probe struct {
	name string
	ex   *sanitizer.Exchange
}

func probes() []probe {
	jsonCT := hdr("content-type", "application/json")
	withBody := func(ct string, body string, extra ...string) *sanitizer.Exchange {
		ex := in("/orders")
		ex.Method = "POST"
		ex.ReqHeaders = append(hdr("content-type", ct), hdr(extra...)...)
		ex.ReqBody = []byte(body)
		return ex
	}
	var ps []probe
	add := func(n string, ex *sanitizer.Exchange) { ps = append(ps, probe{n, ex}) }

	// Path variants.
	add("path-plain", in("/orders/"+mWord))
	add("path-pct", in("/orders/%71%7a%76marker%71%7a"))
	add("path-matrix", in("/orders;"+mWord+"=1/x"))
	add("path-slash-enc", in("/orders%2F"+mWord))
	add("path-dotdot", in("/orders/../"+mWord))
	add("path-email", in("/u/"+mMail))
	add("path-digits", in("/u/"+mDigit))
	add("path-trailing-dot", in("/u/"+mWord+"."))
	add("path-upper", in("/u/"+strings.ToUpper(mWord)))
	// Query variants.
	q := func(raw string) *sanitizer.Exchange { ex := in("/s"); ex.RawQuery = []byte(raw); return ex }
	add("query-value", q("q="+mWord))
	add("query-noeq", q(mWord))
	add("query-name-with-value", q(mWord+"="+mWord))
	add("query-semicolon", q("a=1;"+mWord+"=2"))
	add("query-pct-name", q("%71%7a%76marker%71%7a=1"))
	add("query-plus", q("q+"+mWord+"=1"))
	add("query-email-name", q(mMail+"=1"))
	add("query-brackets", q("a["+mWord+"]=1"))
	add("query-dup", q("a=1&a="+mWord))
	add("query-empty-name", q("="+mWord))
	// Headers / cookies.
	h := func(kv ...string) *sanitizer.Exchange { ex := in("/h"); ex.ReqHeaders = hdr(kv...); return ex }
	add("hdr-value", h("x-trace-note", mWord))
	add("hdr-name", h("x-"+mWord, "1"))
	add("hdr-upper", h("X-Note", mWord))
	add("hdr-repeat", h("x-a", "1", "x-a", mWord))
	add("hdr-auth", h("authorization", "Bearer "+mWord))
	add("hdr-ws-name", h(" x-a", mWord))
	add("hdr-colon-name", h("x-a:"+mWord, "1"))
	add("hdr-ct-param", h("content-type", "application/json; charset="+mWord))
	add("hdr-ct-weird", h("content-type", mWord+"/json"))
	add("hdr-ce-weird", h("content-encoding", mWord))
	add("cookie-value", h("cookie", "sid="+mWord))
	add("cookie-name", h("cookie", mWord+"=1"))
	add("cookie-noeq", h("cookie", mWord))
	add("cookie-quoted", h("cookie", `a="`+mWord+`"`))
	add("setcookie", func() *sanitizer.Exchange {
		ex := in("/h")
		ex.RespHeaders = hdr("set-cookie", "sid="+mWord+"; Path=/; HttpOnly")
		return ex
	}())
	add("setcookie-attr", func() *sanitizer.Exchange {
		ex := in("/h")
		ex.RespHeaders = hdr("set-cookie", "sid=1; Domain="+mWord+".example; Path=/"+mWord)
		return ex
	}())
	add("location", func() *sanitizer.Exchange {
		ex := in("/h")
		ex.Status = 302
		ex.RespHeaders = hdr("location", "/u/"+mWord)
		return ex
	}())
	// JSON bodies.
	add("json-str", withBody("application/json", `{"a":"`+mWord+`"}`))
	add("json-esc", withBody("application/json", `{"a":"qzvmarkerqz"}`))
	add("json-key", withBody("application/json", `{"`+mWord+`":1}`))
	add("json-key-esc", withBody("application/json", `{"qzvmarkerqz":1}`))
	add("json-num", withBody("application/json", `{"a":`+mDigit+`}`))
	add("json-num-exp", withBody("application/json", `{"a":7351928.4e1}`))
	add("json-num-big", withBody("application/json", `{"a":735192840000000000000000000000000001}`))
	add("json-num-neg0", withBody("application/json", `{"a":-0.0000073519284}`))
	add("json-dup", withBody("application/json", `{"a":1,"a":"`+mWord+`"}`))
	add("json-top-str", withBody("application/json", `"`+mWord+`"`))
	add("json-top-num", withBody("application/json", mDigit))
	add("json-arr", withBody("application/json", `["`+mWord+`",`+mDigit+`]`))
	add("json-bad", withBody("application/json", `{"a":"`+mWord+`"`))
	add("json-trailing", withBody("application/json", `{"a":1} "`+mWord+`"`))
	add("json-bom", withBody("application/json", "\xef\xbb\xbf{\"a\":\""+mWord+"\"}"))
	add("json-nested", withBody("application/json", strings.Repeat(`{"a":`, 80)+`"`+mWord+`"`+strings.Repeat(`}`, 80)))
	add("json-suffix", withBody("application/vnd.x+json", `{"a":"`+mWord+`"}`))
	add("json-ct-case", withBody("Application/JSON", `{"a":"`+mWord+`"}`))
	add("json-gz", func() *sanitizer.Exchange {
		ex := withBody("application/json", "", "content-encoding", "gzip")
		ex.ReqBody = gz([]byte(`{"a":"` + mWord + `"}`))
		return ex
	}())
	add("json-gz-stacked", func() *sanitizer.Exchange {
		ex := withBody("application/json", "", "content-encoding", "gzip, gzip")
		ex.ReqBody = gz(gz([]byte(`{"a":"` + mWord + `"}`)))
		return ex
	}())
	add("json-gz-decoded-flag", func() *sanitizer.Exchange {
		ex := withBody("application/json", `{"a":"`+mWord+`"}`, "content-encoding", "gzip")
		ex.ReqBodyDecoded = true
		return ex
	}())
	add("form", withBody("application/x-www-form-urlencoded", "a="+mWord+"&"+mWord+"=1"))
	add("form-noeq", withBody("application/x-www-form-urlencoded", mWord))
	add("multipart", withBody("multipart/form-data; boundary=zz", "--zz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n"+mWord+"\r\n--zz--"))
	add("text", withBody("text/plain", mWord))
	add("xml", withBody("application/xml", "<a>"+mWord+"</a>"))
	add("noct", func() *sanitizer.Exchange { ex := in("/b"); ex.Method = "POST"; ex.ReqBody = []byte(mWord); return ex }())
	// Response / errors.
	add("resp-json", func() *sanitizer.Exchange {
		ex := in("/r")
		ex.RespHeaders = jsonCT
		ex.RespBody = []byte(`{"error":"user ` + mMail + ` not found"}`)
		ex.Status = 404
		return ex
	}())
	// Framework route.
	add("route-literal", func() *sanitizer.Exchange {
		ex := in("/orders/" + mWord)
		ex.Framework = "express"
		ex.FrameworkRoute = "/orders/" + mWord
		return ex
	}())
	add("route-mismatch", func() *sanitizer.Exchange {
		ex := in("/orders/1")
		ex.Framework = "express"
		ex.FrameworkRoute = "/orders/" + mWord
		return ex
	}())
	add("route-regex", func() *sanitizer.Exchange {
		ex := in("/orders/" + mWord)
		ex.Framework = "express"
		ex.FrameworkRoute = "/orders/:id(" + mWord + ")"
		return ex
	}())
	add("route-flask-conv", func() *sanitizer.Exchange {
		ex := in("/orders/" + mWord)
		ex.Framework = "flask"
		ex.FrameworkRoute = "/orders/<" + mWord + ":id>"
		return ex
	}())
	add("route-spring-regex", func() *sanitizer.Exchange {
		ex := in("/orders/" + mWord)
		ex.Framework = "spring"
		ex.FrameworkRoute = "/orders/{id:" + mWord + "}"
		return ex
	}())
	add("route-param-name", func() *sanitizer.Exchange {
		ex := in("/orders/1")
		ex.Framework = "express"
		ex.FrameworkRoute = "/orders/:" + mWord
		return ex
	}())
	add("route-django", func() *sanitizer.Exchange {
		ex := in("/orders/1")
		ex.Framework = "django"
		ex.FrameworkRoute = "orders/<int:" + mWord + ">"
		return ex
	}())
	add("route-aspnet", func() *sanitizer.Exchange {
		ex := in("/orders/1")
		ex.Framework = "aspnetcore"
		ex.FrameworkRoute = "/orders/{" + mWord + ":int}"
		return ex
	}())
	add("route-glob", func() *sanitizer.Exchange {
		ex := in("/files/a/b/" + mWord)
		ex.Framework = "express"
		ex.FrameworkRoute = "/files/*"
		return ex
	}())
	// Outbound.
	add("outbound-host", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://" + mWord + ".example.com", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-host-digits", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://u" + mDigit + ".example.com", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-host-hex", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://cdn-9f8e7d6c5b4a" + mDigit[:2] + ".example.com", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-ip", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "http://10.73.51.92:8080", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-ipv6", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "http://[2001:db8::7351:9284]", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-userinfo", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://" + mWord + "@api.example.com", Method: "GET", RawPath: []byte("/x"), Status: 200})
	add("outbound-port", &sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://api.example.com:" + mDigit[:4], Method: "GET", RawPath: []byte("/x"), Status: 200})
	// Method.
	add("method", func() *sanitizer.Exchange { ex := in("/m"); ex.Method = strings.ToUpper(mWord); return ex }())
	add("neterror", func() *sanitizer.Exchange { ex := in("/m"); ex.NetError = mWord; return ex }())
	return ps
}

// specAccepted lists probes whose marker sits in a NAME, the method or the
// content type: sanitizer.md §13 lets these out when they respect the name
// grammar (THREAT_MODEL §7 "Nomi"). Only the case-insensitive marker check
// is skipped for them.
//
// outbound-host: from spec v1.5 a host label that passes the safe-label rule
// (sanitizer.md 3.5) leaves as structure, like a name (residual risk of
// THREAT_MODEL §7 "Host"; the intake collapses a position beyond 50 distinct
// labels). TestRT_Sanitizer_Holds_StrictHosts checks it under
// hosts.discovery off.
var specAccepted = map[string]bool{
	"hdr-name": true, "query-name-with-value": true, "query-pct-name": true, "cookie-name": true,
	"json-key": true, "json-key-esc": true, "form": true, "hdr-ct-weird": true, "method": true,
	"outbound-host": true,
}

// Exploratory sweep: every probe under the empty policy.
func TestRT_Sanitizer_Holds_EmptyPolicySweep(t *testing.T) {
	e := engine(t, emptyAuthor)
	for _, p := range probes() {
		if specAccepted[p.name] {
			continue
		}
		s := strings.ToLower(out(t, e, p.ex))
		if f := leaks(s, mWord, mMail, mDigit); f != "" {
			t.Errorf("%s: fragment %q leaks: %s", p.name, f, s)
		}
	}
}

// Spec v1.5 strict mode: with hosts.discovery off no probe leaks, the host
// included (host:unlisted), exactly as before v1.5.
func TestRT_Sanitizer_Holds_StrictHosts(t *testing.T) {
	strict := strings.TrimSuffix(emptyAuthor, "}") + `,"hosts":{"discovery":"off"}}`
	e := engine(t, strict)
	for _, p := range probes() {
		if specAccepted[p.name] && p.name != "outbound-host" {
			continue
		}
		s := strings.ToLower(out(t, e, p.ex))
		if f := leaks(s, mWord, mMail, mDigit); f != "" {
			t.Errorf("%s: fragment %q leaks: %s", p.name, f, s)
		}
		if p.ex.Dir == sanitizer.Outbound && p.name != "outbound-userinfo" && !strings.Contains(s, `"service":"host:unlisted"`) {
			t.Errorf("%s: strict mode must give host:unlisted: %s", p.name, s)
		}
	}
}

// Spec v1.5 auto mode: the probes' host labels that look like values never
// leave; IP literals leave only as their class.
func TestRT_Sanitizer_Holds_HostPatterns(t *testing.T) {
	e := engine(t, emptyAuthor)
	want := map[string]string{
		"outbound-host":        `"service":"host:qzvmarkerqz.example.com"`,
		"outbound-host-digits": `"service":"host:{*}.example.com"`,
		"outbound-host-hex":    `"service":"host:{*}.example.com"`,
		"outbound-ip":          `"service":"host:ip:private:8080"`,
		"outbound-ipv6":        `"service":"host:ip:private"`,
	}
	for _, p := range probes() {
		w, ok := want[p.name]
		if !ok {
			continue
		}
		if s := out(t, e, p.ex); !strings.Contains(s, w) {
			t.Errorf("%s: want %s in %s", p.name, w, s)
		}
	}
}
