package sanitizer

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/hostpat"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Token grammar of an empty-policy output (event schema, drop/trunc only).
var (
	reClass      = `(l8|l32|l128|l1024|lmax)`
	reDocClass   = `(l1k|l16k|l128k|l1m|l8m|lmax)`
	reEmptyToken = regexp.MustCompile(`^(drop:(null|bool|int|dec|bytes|str:(invalid|uuid|jwt|email|datetime|date|url|ipv4|phone|digits|hex|` + reClass[1:len(reClass)-1] + `)|(obj|arr|bytes):` + reClass + `|(doc|file):[a-z]{2,5}:` + reDocClass + `)|trunc:(depth|invalid-json|invalid-xml|invalid-multipart|size|(n|keys):` + reClass + `))$`)
	reAnyToken   = regexp.MustCompile(`^(drop:(null|bool|int|dec|bytes|str:(invalid|uuid|jwt|email|datetime|date|url|ipv4|phone|digits|hex|` + reClass[1:len(reClass)-1] + `)|(obj|arr|bytes):` + reClass + `|(doc|file):[a-z]{2,5}:` + reDocClass + `)|keep:(?s:.*)|tk1:[a-z0-9]{1,8}:[A-Za-z0-9_-]{22}|num:(<|>=)?-?[0-9][0-9.e+-]*|time:[0-9]{4}(-[0-9]{2}(-[0-9]{2}(T[0-9]{2})?)?)?|trunc:(depth|invalid-json|invalid-xml|invalid-multipart|size|(n|keys):` + reClass + `))$`)
	reEmptyPath  = regexp.MustCompile(`^(/|(/\{(drop:[a-z0-9:]+|trunc)\})+)$`)
	reEventPath  = regexp.MustCompile(`^/$|^(/([A-Za-z0-9._~-]{1,64}|\{(drop:[a-z0-9:]{1,24}|keep:[A-Za-z0-9._~-]{1,64}|tk1:[a-z0-9]{1,8}:[A-Za-z0-9_-]{22}|num:[!-z|~]{1,80}|time:[0-9T-]{4,13}|trunc)\}))+$`)
	reCT         = regexp.MustCompile(`^([a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}|invalid)$`)
	reKey        = regexp.MustCompile(`^(@?[A-Za-z_][A-Za-z0-9_.-]{0,63}|#text|\{\*\}|\{trunc\}|[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64})$`)
	reDiscKey    = regexp.MustCompile(`^(req|resp)\.(body|query|headers|cookies|path)[!-~]{0,256}$`)
	reDiscVal    = regexp.MustCompile(`^tkd:[A-Za-z0-9_-]{6}$`)
	reXMLNSKey   = regexp.MustCompile(`^(\$(\.([A-Za-z_][A-Za-z0-9_.-]{0,63}|\*)(\[\*\])?)+|\{trunc\})$`)
	reXMLNSVal   = regexp.MustCompile(`^(ns:[!-~]{1,600}|trunc:keys:` + reClass + `)$`)
)

// vocabulary of strings the empty-policy output may legitimately contain.
const vocabulary = "drop:null drop:bool drop:int drop:dec drop:bytes drop:str:invalid uuid jwt email datetime date url ipv4 phone digits hex " +
	"l8 l32 l128 l1024 lmax drop:obj: drop:arr: drop:bytes: trunc:depth trunc:invalid-json trunc:size trunc:n: trunc:keys: sampled_by random host:unlisted " +
	"path query headers cookies ct size body op req resp route_source service raw policy framework {*} {trunc} shop-api OTHER invalid"

// checkOutput validates the structure of an output against the event
// grammar. empty requires the closed drop/trunc vocabulary.
func checkOutput(t *testing.T, out *Output, empty bool) []byte {
	t.Helper()
	b, err := out.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if !ttjson.IsCanonical(b) {
		t.Fatalf("output is not canonical JSON: %q", b)
	}
	tok := reAnyToken
	if empty {
		tok = reEmptyToken
	}
	var walk func(v ttjson.Value, where string)
	walk = func(v ttjson.Value, where string) {
		switch v.Kind {
		case ttjson.String:
			if !tok.MatchString(v.Str) {
				t.Fatalf("%s: string outside grammar: %q in %s", where, v.Str, b)
			}
		case ttjson.Number, ttjson.Bool, ttjson.Null:
			if empty {
				t.Fatalf("%s: non-string value with empty policy in %s", where, b)
			}
		case ttjson.Array:
			for _, e := range v.Arr {
				walk(e, where)
			}
		case ttjson.Object:
			for _, m := range v.Obj {
				if !reKey.MatchString(m.Key) {
					t.Fatalf("%s: bad key %q", where, m.Key)
				}
				walk(m.Value, where+"."+m.Key)
			}
		}
	}
	for side, part := range map[string]*ttjson.Value{"req": &out.Req, "resp": out.Resp} {
		if part == nil {
			continue
		}
		for _, m := range part.Obj {
			switch m.Key {
			case "path":
				re := reEventPath
				if empty {
					re = reEmptyPath
				}
				if !re.MatchString(m.Value.Str) {
					t.Fatalf("bad path %q", m.Value.Str)
				}
			case "ct":
				if !reCT.MatchString(m.Value.Str) {
					t.Fatalf("bad ct %q", m.Value.Str)
				}
			case "size":
				if !regexp.MustCompile(`^` + reClass + `$`).MatchString(m.Value.Str) {
					t.Fatalf("bad size %q", m.Value.Str)
				}
			case "query", "headers", "cookies":
				if len(m.Value.Obj) > 65 {
					t.Fatalf("too many names")
				}
				walk(m.Value, side+"."+m.Key)
			case "body":
				walk(m.Value, side+".body")
			case "fmt":
				switch m.Value.Str {
				case "xml", "soap11", "soap12", "multipart":
				default:
					t.Fatalf("bad fmt %q", m.Value.Str)
				}
			case "soap_action":
				if side != "req" || (m.Value.Str != "{*}" && !IsLiteralKey([]byte(m.Value.Str))) {
					t.Fatalf("bad soap_action %q", m.Value.Str)
				}
			case "xmlns":
				if len(m.Value.Obj) == 0 || len(m.Value.Obj) > 65 {
					t.Fatalf("bad xmlns size %d", len(m.Value.Obj))
				}
				for _, e := range m.Value.Obj {
					if !reXMLNSKey.MatchString(e.Key) || !reXMLNSVal.MatchString(e.Value.Str) {
						t.Fatalf("bad xmlns entry %q=%q", e.Key, e.Value.Str)
					}
				}
			default:
				t.Fatalf("unexpected field %s", m.Key)
			}
		}
	}
	if !strings.HasPrefix(out.Op, "OTHER /") && !regexp.MustCompile(`^[A-Z]{1,16} /[!-~]*$`).MatchString(out.Op) {
		t.Fatalf("bad op %q", out.Op)
	}
	for _, d := range out.Disc {
		if !reDiscKey.MatchString(d.Key) || !reDiscVal.MatchString(d.Value.Str) {
			t.Fatalf("bad disc %q=%q", d.Key, d.Value.Str)
		}
	}
	return b
}

// collectJSONStrings returns decoded string values and number lexemes of a
// JSON document (nil when it is not valid JSON), plus its keys.
func collectJSONStrings(d []byte) (vals, keys [][]byte) {
	v, err := ttjson.Parse(d, ttjson.ParseOptions{MaxDepth: 1 << 16})
	if err != nil {
		return nil, nil
	}
	var walk func(v ttjson.Value)
	walk = func(v ttjson.Value) {
		switch v.Kind {
		case ttjson.String, ttjson.Number:
			vals = append(vals, []byte(v.Str))
		case ttjson.Array:
			for _, e := range v.Arr {
				walk(e)
			}
		case ttjson.Object:
			for _, m := range v.Obj {
				keys = append(keys, []byte(m.Key))
				walk(m.Value)
			}
		}
	}
	walk(v)
	return vals, keys
}

// outputStrings returns every string (keys and values) of the output.
func outputStrings(out []byte) []string {
	v, err := ttjson.Parse(out, ttjson.ParseOptions{MaxDepth: 1 << 16})
	if err != nil {
		return nil
	}
	var res []string
	var walk func(v ttjson.Value)
	walk = func(v ttjson.Value) {
		switch v.Kind {
		case ttjson.String:
			res = append(res, v.Str)
		case ttjson.Array:
			for _, e := range v.Arr {
				walk(e)
			}
		case ttjson.Object:
			for _, m := range v.Obj {
				res = append(res, m.Key)
				walk(m.Value)
			}
		}
	}
	walk(v)
	return res
}

// assertNoLeak implements guarantee G1: with the empty policy no input
// value of 3 bytes or more appears in any output string, except as part of
// the fixed vocabulary or of a name the spec allows to pass (section 13).
func assertNoLeak(t *testing.T, out []byte, values, names [][]byte, extraVocab ...string) {
	t.Helper()
	vocab := vocabulary + " " + strings.Join(extraVocab, " ")
	for _, n := range names {
		vocab += " " + strings.ToLower(string(n)) + " " + string(n)
	}
	strs := outputStrings(out)
	for _, v := range values {
		if len(v) < 3 {
			continue
		}
		for _, s := range strs {
			if !strings.Contains(s, string(v)) {
				continue
			}
			if strings.Contains(vocab, string(v)) {
				continue
			}
			t.Fatalf("input value %q leaked into %s", v, out)
		}
	}
}

var fuzzCTs = []string{"application/json", "application/x-www-form-urlencoded", "text/plain", "", "application/vnd.x+json"}

func FuzzSanitizeBody(f *testing.F) {
	for _, s := range []string{
		`{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":""}`,
		`{"a":{"b":{"c":[1,2,3,{"d":"secret-value"}]}},"550e8400-e29b-41d4-a716-446655440000":"x"}`,
		`[1e400,-0.0,"\ud800","été",true,null]`, `a=secret&b=other+value`, "\"\xff\"", `{"a":1,"a":"dup-secret"}`,
	} {
		for i := range fuzzCTs {
			f.Add([]byte(s), uint8(i))
		}
	}
	e := engine(f, emptyAuthor)
	small := engine(f, limitsAuthor(`{"max_depth":3,"max_array":2,"max_keys":2,"max_body_bytes":256}`))
	f.Fuzz(func(t *testing.T, body []byte, cti uint8) {
		ct := fuzzCTs[int(cti)%len(fuzzCTs)]
		for _, eng := range []*Engine{e, small} {
			ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/"), Status: 200, ReqBody: body,
				RespBody: body}
			if ct != "" {
				ex.ReqHeaders = hdr("Content-Type", ct)
				ex.RespHeaders = hdr("Content-Type", ct)
			}
			out, err := eng.Sanitize(ex, t0, ByRandom)
			if err != nil {
				t.Fatalf("sanitize: %v", err)
			}
			b := checkOutput(t, out, true)
			vals, keys := collectJSONStrings(body)
			if vals == nil {
				// Not JSON: treat every '&'/'='-separated piece as a value.
				for _, p := range bytes.FieldsFunc(body, func(r rune) bool { return r == '&' || r == '=' }) {
					vals = append(vals, p, formDecode(p))
				}
				keys = vals // form names may pass; values never do (checked by grammar)
				if !strings.Contains(ct, "form") {
					keys = nil
				}
			}
			assertNoLeak(t, b, vals, keys, ct)
		}
	})
}

func FuzzSanitizeExchange(f *testing.F) {
	f.Add("GET", []byte("/customers/mario.rossi%40example.com/orders"), []byte("promo=AUTUMN10&x"), "X-Secret", []byte("token-123"),
		[]byte("sid=9f8e7d6c5b4a; lang=it"), []byte(`{"id":"ORD-2026-000184"}`), "https://api.carrier.example", uint8(0))
	f.Add("m-search", []byte("//a//%FF/"+strings.Repeat("x/", 40)), []byte("%FF=1&a=%ZZ"), "bad name", []byte{0xff, 0xfe},
		[]byte("=v; novalue"), []byte(`{`), "http://[::1]", uint8(1))
	e := engine(f, emptyAuthor)
	f.Fuzz(func(t *testing.T, method string, path, query []byte, hname string, hval, cookie, body []byte, base string, dir uint8) {
		ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: method, RawPath: path, RawQuery: query,
			ReqHeaders: []Header{{Name: hname, Value: hval}, {Name: "Cookie", Value: cookie}, {Name: "Content-Type", Value: []byte("application/json")}},
			ReqBody:    body, Status: 200 + int(dir)%400,
			RespHeaders: []Header{{Name: "Set-Cookie", Value: cookie}, {Name: hname, Value: hval}},
		}
		if dir%2 == 1 {
			ex.Dir, ex.URLBase = Outbound, base
		}
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			t.Fatalf("sanitize: %v", err)
		}
		b := checkOutput(t, out, true)
		if h, ok := strings.CutPrefix(out.Service, "host:"); ok && h != "invalid" && !hostpat.Valid(h) {
			t.Fatalf("service %q is not a host pattern of sanitizer.md 3.5", out.Service)
		}
		var vals, names [][]byte
		segs, _ := splitPath(path)
		for _, s := range segs {
			vals = append(vals, s.dec)
		}
		for _, p := range bytes.Split(query, []byte{'&'}) {
			n, v, _ := bytes.Cut(p, []byte{'='})
			names = append(names, formDecode(n))
			vals = append(vals, formDecode(v))
		}
		vals = append(vals, hval)
		names = append(names, []byte(hname))
		requestCookies(normalizeHeaders(ex.ReqHeaders), func(n, v []byte) { names = append(names, n); vals = append(vals, v) })
		responseCookies(normalizeHeaders(ex.RespHeaders), func(n, v []byte) { names = append(names, n); vals = append(vals, v) })
		bv, bk := collectJSONStrings(body)
		vals = append(vals, bv...)
		names = append(names, bk...)
		extra := []string{normalizeMethod(method), out.Service}
		for _, part := range []*ttjson.Value{&out.Req, out.Resp} {
			if part != nil {
				if ct, ok := part.Get("ct"); ok {
					extra = append(extra, ct.Str)
				}
			}
		}
		assertNoLeak(t, b, vals, names, extra...)
	})
}

// FuzzSanitizeRules runs a policy with every action kind: it must never
// panic and must always produce grammar-valid canonical output.
func FuzzSanitizeRules(f *testing.F) {
	a := `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},
	 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T00:00:00Z","allow":["ORD"],"hosts_allow":["api.carrier.example"]},
	 "discovery":{"enabled":true,"expires_at":"2026-10-22T00:00:00Z"},
	 "limits":{"max_depth":6,"max_array":4,"max_keys":8,"keep_max_bytes":16},
	 "global":{"request":{"$.t":"bucket(time, hour)","$.d":"drop",
	   "headers":{"accept":"keep"},"query":{"q":"keep"},"cookies":{"c":"hmac"}}},
	 "services":{"shop-api":{"match":{"inbound":true},
	   "request":{"$[*]":"bucket(num, [0, 10.5, 100])","$.*":"keep","$.a.*":"hmac(x)","$.*.*":"bucket(time, day)"},"errors":{"$.error.*":"keep"},
	   "ops":{"GET /o/{id}":{"request":{"path":{"id":"keep"}}},"POST /o/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}}`
	e := engine(f, a)
	f.Add("GET", []byte("/o/ORD-1"), []byte("q=1&q=x"), []byte(`{"a":{"b":"v"},"t":"2026-10-19T10:00:00Z","d":{"x":1},"z":[1,2]}`), uint16(200))
	f.Add("POST", []byte("/o/%FF"), []byte("q"), []byte(`[1,-5,1e400,"x",[1]]`), uint16(500))
	f.Fuzz(func(t *testing.T, method string, path, query, body []byte, status uint16) {
		ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: method, RawPath: path, RawQuery: query,
			ReqHeaders: hdr("Accept", string(body), "Content-Type", "application/json", "Cookie", "c="+string(query)),
			ReqBody:    body, Status: 100 + int(status)%500,
			RespHeaders: hdr("Content-Type", "application/json"), RespBody: body}
		out, err := e.Sanitize(ex, time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC), ByRandom)
		if err != nil {
			t.Fatalf("sanitize: %v", err)
		}
		checkOutput(t, out, false)
	})
}
