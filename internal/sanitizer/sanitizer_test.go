package sanitizer

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Expected bytes in this file are derived by hand from docs/spec/sanitizer.md
// rev. 1.1; HMAC tokens come from the formula (specToken), not from the code.

const pol = `"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1}`

func author(extra string) string {
	if extra == "" {
		return "{" + pol + "}"
	}
	return "{" + pol + "," + extra + "}"
}

// rulesAuthor puts the rules in the request scope of the inbound service shop-api: keep, hmac and
// bucket on a wildcard path are not allowed in global rules (hardening.md 2.1 H2).
func rulesAuthor(rules string) string {
	return author(`"services":{"shop-api":{"match":{"inbound":true},"request":` + rules + `}}`)
}

// ---- Section 14: complete example ----

const shopAuthor = `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T00:00:00Z"},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}
 }}}}`

func TestSpecExample14(t *testing.T) {
	e := engine(t, shopAuthor)
	ex := &Exchange{
		Dir: Inbound, ServiceName: "shop-api", Method: "POST",
		RawPath: []byte("/orders"), RawQuery: []byte("promo=AUTUMN10"),
		ReqHeaders:  hdr("Content-Type", "application/json", "Cookie", "sid=9f8e7d6c5b4a"),
		ReqBody:     []byte(`{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":""}`),
		Status:      201,
		RespHeaders: hdr("Content-Type", "application/json; charset=utf-8"),
		RespBody:    []byte(`{"id":"ORD-2026-000184","status":"CREATED","total":73.40}`),
	}
	want := `{"op":"POST /orders","req":{"body":{"email":"drop:str:email","items":[{"qty":"drop:int","sku":"drop:str:l32"}],"note":"drop:str:l8"},"cookies":{"sid":["drop:str:l32"]},"ct":"application/json","headers":{"content-type":["drop:str:l32"]},"path":"/orders","query":{"promo":["drop:str:l8"]},"size":"l128"},"resp":{"body":{"id":"` +
		specToken("order", "ORD-2026-000184") +
		`","status":"keep:CREATED","total":"num:50-100"},"ct":"application/json","headers":{"content-type":["drop:str:l32"]},"size":"l128"},"route_source":"policy","sampled_by":"random","service":"shop-api"}`
	if got := canon(t, e, ex, t0); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func bodyOf(t *testing.T, e *Engine, ct, body string) string {
	t.Helper()
	ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/x"), Status: 200, ReqBody: []byte(body)}
	if ct != "" {
		ex.ReqHeaders = hdr("Content-Type", ct)
	}
	return reqField(t, e, ex, "body")
}

func reqField(t *testing.T, e *Engine, ex *Exchange, field string) string {
	t.Helper()
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := out.Req.Get(field)
	if !ok {
		return "<absent>"
	}
	b, err := ttjson.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDropForms(t *testing.T) {
	e := engine(t, author(""))
	cases := []struct{ in, want string }{
		{`{"a":1,"b":-0,"c":1.0,"d":1e3,"e":true,"f":false,"g":null,"h":"x"}`,
			`{"a":"drop:int","b":"drop:int","c":"drop:dec","d":"drop:dec","e":"drop:bool","f":"drop:bool","g":"drop:null","h":"drop:str:l8"}`},
		{`"550e8400-e29b-41d4-a716-446655440000"`, `"drop:str:uuid"`},
		{`"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"`, `"drop:str:jwt"`},
		{`"eyJ.x."`, `"drop:str:jwt"`},
		{`"eyJ..x"`, `"drop:str:l8"`},
		{`"giulia.neri@example.com"`, `"drop:str:email"`},
		{`"a@localhost"`, `"drop:str:l32"`},
		{`"2026-10-19T10:00:00.412Z"`, `"drop:str:datetime"`},
		{`"2026-10-19 10:00:00+02:00"`, `"drop:str:datetime"`},
		{`"2026-13-45T99:99:99z"`, `"drop:str:datetime"`},
		{`"2026-10-19T10:00:00.1234567890Z"`, `"drop:str:l32"`},
		{`"2026-10-19"`, `"drop:str:date"`},
		{`"2026-10-19\n"`, `"drop:str:l32"`},
		{`"https://api.carrier.example/v1?x=1"`, `"drop:str:url"`},
		{`"https://a b"`, `"drop:str:l32"`},
		{`"192.168.0.1"`, `"drop:str:ipv4"`},
		{`"01.2.3.4"`, `"drop:str:l8"`},
		{`"256.1.1.1"`, `"drop:str:l32"`},
		{`"+393331234567"`, `"drop:str:phone"`},
		{`"+0123456"`, `"drop:str:l8"`},
		{`"-12345"`, `"drop:str:digits"`},
		{`"12345678901234567890"`, `"drop:str:hex"`},
		{`"deadbeefDEADBEEF"`, `"drop:str:hex"`},
		{`"9f8e7d6c5b4a"`, `"drop:str:l32"`},
		{`""`, `"drop:str:l8"`},
		{`"12345678x"`, `"drop:str:l32"`},
		{`"\u00e0\u00e8\u00ec\u00f2"`, `"drop:str:l8"`},
		{`"\u00e0\u00e8\u00ec\u00f2x"`, `"drop:str:l32"`},
		{`"\ud83d\ude00"`, `"drop:str:l8"`},
		{`"\ud800"`, `"drop:str:invalid"`},
		{`"x\udc00"`, `"drop:str:invalid"`},
		{`"` + strings.Repeat("x", 32) + `"`, `"drop:str:l32"`},
		{`"` + strings.Repeat("x", 33) + `"`, `"drop:str:l128"`},
		{`"` + strings.Repeat("x", 1024) + `"`, `"drop:str:l1024"`},
		{`"` + strings.Repeat("x", 1025) + `"`, `"drop:str:lmax"`},
		{`[1, 2.5, "x", null]`, `["drop:int","drop:dec","drop:str:l8","drop:null"]`},
		{` 7 `, `"drop:int"`},
		{`{}`, `{}`},
		{`[]`, `[]`},
	}
	for _, c := range cases {
		if got := bodyOf(t, e, "application/json", c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestInvalidJSON(t *testing.T) {
	e := engine(t, author(""))
	for _, in := range []string{
		`{"a":1,}`, `[1,2]x`, `NaN`, `{'a':1}`, "\"\xff\"", "\xef\xbb\xbf{}", `01`, `1.`, `.5`, `-`, `+1`,
		`{"a" 1}`, "\"\x01\"", `{"a":1}//c`, `[1 2]`, `tru`, `"\x"`, `"\u12"`, `[`, `Infinity`, `1e`, `[1,]`, `"abc`,
		"\"\xed\xa0\x80\"", "\"\xc0\xaf\"", `1 2`, "\f1",
	} {
		if got := bodyOf(t, e, "application/json", in); got != `"trunc:invalid-json"` {
			t.Errorf("%q: got %s", in, got)
		}
	}
	e2 := engine(t, limitsAuthor(`{"max_array":1,"max_depth":2}`))
	for _, in := range []string{"[1,\"\xc3\"]", `[1,{"a":[1,}]`, `[[[[1,]]]]`} {
		if got := bodyOf(t, e2, "application/json", in); got != `"trunc:invalid-json"` {
			t.Errorf("%q: got %s", in, got)
		}
	}
}

func TestObjectKeys(t *testing.T) {
	e := engine(t, author(""))
	long64 := "k" + strings.Repeat("x", 63)
	long65 := "k" + strings.Repeat("x", 64)
	cases := []struct{ in, want string }{
		{`{"a":1,"a":"x"}`, `{"a":"drop:str:l8"}`},
		{`{"550e8400-e29b-41d4-a716-446655440000":1,"mario@example.com":"x","name":true,"123":null}`,
			`{"name":"drop:bool","{*}":["drop:int","drop:null","drop:str:l8"]}`},
		{`{"deadbeefdeadbeef":1,"a.b":2,"_x":3,"-a":4}`, `{"_x":"drop:int","a.b":"drop:int","{*}":["drop:int","drop:int"]}`},
		{`{"eyJ.a.b":1}`, `{"{*}":["drop:int"]}`},
		{`{"user_391234":"x","user_39123":"y"}`, `{"user_39123":"drop:str:l8","{*}":["drop:str:l8"]}`},
		{`{"` + long64 + `":1,"` + long65 + `":"ab"}`, `{"` + long64 + `":"drop:int","{*}":["drop:str:l8"]}`},
		{`{"\u00e9":1,"z":2}`, `{"z":"drop:int","{*}":["drop:int"]}`},
		{`{"\ud800":1}`, `{"{*}":["drop:int"]}`},
		{`{"b c":"x","a c":true,"c c":{"k":1},"d d":[1]}`, `{"{*}":["drop:bool","drop:str:l8",["drop:int"],{"k":"drop:int"}]}`},
		{`{"n":{"1":{"2":3}}}`, `{"n":{"{*}":[{"{*}":["drop:int"]}]}}`},
	}
	for _, c := range cases {
		if got := bodyOf(t, e, "application/json", c.in); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.in, got, c.want)
		}
	}
}

func TestLimits(t *testing.T) {
	cases := []struct{ limits, ct, in, want string }{
		{`{"max_depth":2}`, "application/json", `{"a":{"b":{"c":1}},"x":[[1]],"y":[1]}`, `{"a":{"b":"trunc:depth"},"x":["trunc:depth"],"y":["drop:int"]}`},
		{`{"max_depth":1}`, "application/json", `[[],{}]`, `["trunc:depth","trunc:depth"]`},
		{`{"max_array":2}`, "application/json", `[1,2,3]`, `["drop:int","drop:int","trunc:n:l8"]`},
		{`{"max_array":2}`, "application/json", `[1,2]`, `["drop:int","drop:int"]`},
		{`{"max_array":0}`, "application/json", `[1]`, `["trunc:n:l8"]`},
		{`{"max_array":1}`, "application/json", `[` + strings.Repeat("1,", 99) + `1]`, `["drop:int","trunc:n:l128"]`},
		{`{"max_keys":2}`, "application/json", `{"c":1,"a":2,"b":3}`, `{"a":"drop:int","c":"drop:int","{trunc}":"trunc:keys:l8"}`},
		{`{"max_keys":2}`, "application/json", `{"a":1,"b":2,"a":"x","c":4}`, `{"a":"drop:str:l8","b":"drop:int","{trunc}":"trunc:keys:l8"}`},
		{`{"max_keys":1}`, "application/json", `{"1":1,"2":2}`, `{"{*}":["drop:int"],"{trunc}":"trunc:keys:l8"}`},
		{`{"max_body_bytes":10}`, "application/json", `{"a":12345}`, `"trunc:size"`},
		{`{"max_body_bytes":10}`, "text/plain", `{"a":12345}`, `"trunc:size"`},
		{`{"max_body_bytes":10}`, "application/json", `{"a":1234}`, `{"a":"drop:int"}`},
		{`{"max_body_bytes":0}`, "application/json", `1`, `"trunc:size"`},
	}
	for _, c := range cases {
		e := engine(t, limitsAuthor(c.limits))
		if got := bodyOf(t, e, c.ct, c.in); got != c.want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.limits, c.in, got, c.want)
		}
	}
}

func TestBodyTreatment(t *testing.T) {
	e := engine(t, author(""))
	cases := []struct{ ct, in, want string }{
		{"text/plain", "hello", `"drop:bytes:l8"`},
		{"", "abc", `"drop:bytes:l8"`},
		{"", "", `<absent>`},
		{"application/json", "", `<absent>`},
		{"application/problem+json", `{"a":1}`, `{"a":"drop:int"}`},
		{"Application/JSON ; charset=utf-8", `{"a":1}`, `{"a":"drop:int"}`},
		{"application/json5", `{"a":1}`, `"drop:bytes:l8"`},
		{"foo", "{}", `"drop:bytes:l8"`},
		{"application/x-www-form-urlencoded", "a=1&b=x+y&a=%C3%A9&550e8400-e29b-41d4-a716-446655440000=z&c=%FF&ORD123456",
			`{"a":["drop:str:digits","drop:str:l8"],"b":["drop:str:l8"],"{*}":["drop:str:l8","drop:str:l32"],"c":["drop:bytes"]}`},
	}
	for _, c := range cases {
		got := bodyOf(t, e, c.ct, c.in)
		if strings.Contains(c.ct, "form") {
			v, _ := ttjson.Parse([]byte(c.want), ttjson.ParseOptions{})
			w, _ := ttjson.Encode(v)
			c.want = string(w)
		}
		if got != c.want {
			t.Errorf("%q %q: got %s want %s", c.ct, c.in, got, c.want)
		}
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func zl(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func TestBodyEncodingAndLength(t *testing.T) {
	e := engine(t, limitsAuthor(`{"max_body_bytes":64}`))
	type c struct {
		name      string
		hdrs      []Header
		body      []byte
		total     int64
		noConsume bool
		decoded   bool
		size      string
		body2     string
	}
	json := []Header{{Name: "Content-Type", Value: []byte("application/json")}}
	with := func(enc string) []Header {
		return append(append([]Header{}, json...), Header{Name: "Content-Encoding", Value: []byte(enc)})
	}
	cases := []c{
		{"unknown total", json, []byte(`{"a":1}`), UnknownLength, false, false, `"lmax"`, `"trunc:size"`},
		{"not consumed", json, []byte(`{"a":1}`), 0, true, false, `"lmax"`, `"trunc:size"`},
		{"empty", json, nil, 0, false, false, `"l8"`, `<absent>`},
		{"prefix over limit", json, []byte(`{"a":1}`), 100, false, false, `"lmax"`, `"trunc:size"`},
		{"gzip", with("gzip"), gz(t, `{"a":"secret"}`), 0, false, false, `"l32"`, `{"a":"drop:str:l8"}`},
		{"x-gzip upper", with(" X-GZIP "), gz(t, `{"a":1}`), 0, false, false, `"l8"`, `{"a":"drop:int"}`},
		{"deflate", with("deflate"), zl(t, `[1,2]`), 0, false, false, `"l8"`, `["drop:int","drop:int"]`},
		{"gzip already decoded", with("gzip"), []byte(`{"a":1}`), 0, false, true, `"l8"`, `{"a":"drop:int"}`},
		{"gzip bomb", with("gzip"), gz(t, `"`+strings.Repeat("x", 1000)+`"`), 0, false, false, `"lmax"`, `"trunc:size"`},
		{"gzip broken", with("gzip"), []byte("not gzip"), 0, false, false, `<absent>`, `"drop:bytes"`},
		{"br", with("br"), []byte("xx"), 0, false, false, `<absent>`, `"drop:bytes"`},
		{"two layers", with("gzip, br"), gz(t, "x"), 0, false, false, `<absent>`, `"drop:bytes"`},
		{"two layers decoded", with("gzip, br"), []byte("x"), 0, false, true, `<absent>`, `"drop:bytes"`},
		{"identity", with("identity"), []byte(`1`), 0, false, false, `"l8"`, `"drop:int"`},
		{"encoding on empty body", with("br"), nil, 0, false, false, `"l8"`, `<absent>`},
	}
	for _, k := range cases {
		ex := in("/x")
		ex.ReqHeaders, ex.ReqBody, ex.ReqBodyTotal, ex.ReqBodyNotConsumed, ex.ReqBodyDecoded = k.hdrs, k.body, k.total, k.noConsume, k.decoded
		if got := reqField(t, e, ex, "size"); got != k.size {
			t.Errorf("%s: size %s want %s", k.name, got, k.size)
		}
		if got := reqField(t, e, ex, "body"); got != k.body2 {
			t.Errorf("%s: body %s want %s", k.name, got, k.body2)
		}
	}
}

func TestActions(t *testing.T) {
	long := strings.Repeat("x", 65)
	cases := []struct{ rules, in, want string }{
		{`{"$.s":"keep","$.n":"keep","$.b":"keep","$.z":"keep","$.l":"keep"}`,
			`{"s":"CREATED","n":73.40,"b":false,"z":null,"l":"` + long + `"}`,
			`{"b":false,"l":"drop:str:l128","n":73.4,"s":"keep:CREATED","z":null}`},
		{`{"$.n":"keep"}`, `{"n":1E3}`, `{"n":1000}`},
		{`{"$.n":"keep"}`, `{"n":-0.0}`, `{"n":0}`},
		{`{"$.n":"keep"}`, `{"n":123456789012345678901234567890}`, `{"n":1.2345678901234567890123456789e+29}`},
		{`{"$[*]":"keep"}`, `[1e9999,1e-9999,1e10000,1E+09999,` + strings.Repeat("1", 64) + `,` + strings.Repeat("1", 65) + `]`,
			`[1e+9999,1e-9999,"drop:dec",1e+9999,1.` + strings.Repeat("1", 63) + `e+63,"drop:int"]`},
		{`{"$.s":"keep"}`, `{"s":"\u00e9\"\\\n/\u007f"}`, `{"s":"keep:\u00e9\"\\\u000a/\u007f"}`},
		{`{"$.s":"keep"}`, `{"s":"\ud800"}`, `{"s":"drop:str:invalid"}`},
		{`{"$.a":"hmac(order)","$.b":"hmac(order)","$.c":"hmac(order)","$.d":"hmac(order)","$.e":"hmac(order)"}`,
			`{"a":"184","b":184,"c":184.0,"d":1.84e2,"e":"184.0"}`,
			`{"a":"` + specToken("order", "184") + `","b":"` + specToken("order", "184") + `","c":"` + specToken("order", "184") + `","d":"` + specToken("order", "184") + `","e":"` + specToken("order", "184.0") + `"}`},
		{`{"$.a":"hmac"}`, `{"a":"ORD-2026-000184"}`, `{"a":"` + specToken("id", "ORD-2026-000184") + `"}`},
		{`{"$.a":"hmac","$.b":"hmac","$.c":"hmac","$.d":"hmac"}`, `{"a":true,"b":null,"c":"\udc00","d":1e10000}`, `{"a":"drop:bool","b":"drop:null","c":"drop:str:invalid","d":"drop:dec"}`},
		{`{"$[*]":"bucket(num, [0, 50, 100, 250])"}`, `[73.40,-1,0,50,99.999,250,1e400,-1e400,-1e-400,"73",true,1e10000]`,
			`["num:50-100","num:<0","num:0-50","num:50-100","num:50-100","num:>=250","num:>=250","num:<0","num:0-50","drop:str:digits","drop:bool","drop:dec"]`},
		{`{"$[*]":"bucket(num, [0.5, 1.50])"}`, `[1,0.1,2]`, `["num:0.5-1.5","num:<0.5","num:>=1.5"]`},
		{`{"$[*]":"bucket(num, [-10, 0])"}`, `[-5]`, `["num:-10-0"]`},
		{`{"$.h":"bucket(time, hour)","$.d":"bucket(time, day)","$.m":"bucket(time, month)","$.y":"bucket(time, year)"}`,
			`{"h":"2026-10-19T10:30:00+02:00","d":"2026-10-19","m":"2026-10-19t23:59:59.999999999Z","y":"2026-12-31T23:30:00-01:00"}`,
			`{"d":"time:2026-10-19","h":"time:2026-10-19T08","m":"time:2026-10","y":"time:2027"}`},
		{`{"$[*]":"bucket(time, day)"}`,
			`["2026-02-30","2023-02-29","2024-02-29","2026-10-19T24:00:00Z","2026-10-19T10:00:60Z","2026-10-19T10:00:00+24:00","2026-00-01",7,"0001-01-01T00:30:00+01:00","9999-12-31T23:00:00-02:00","0000-06-01","2026-10-19T10:00:00+23:59"]`,
			`["drop:str:date","drop:str:date","time:2024-02-29","drop:str:datetime","drop:str:datetime","drop:str:datetime","drop:str:date","drop:int","drop:str:datetime","drop:str:datetime","drop:str:date","time:2026-10-18"]`},
		{`{"$.items":"drop","$.o":"drop"}`, `{"items":[1,[2],3],"o":{"a":1,"a":2,"b":{"c":1}}}`, `{"items":"drop:arr:l8","o":"drop:obj:l8"}`},
		{`{"$.items":"keep","$.o":"hmac"}`, `{"items":[1],"o":{"a":"x"}}`, `{"items":["drop:int"],"o":{"a":"drop:str:l8"}}`},
		{`{"$.*":"drop","$.a":"keep"}`, `{"a":"x","b":"y"}`, `{"a":"keep:x","b":"drop:str:l8"}`},
		{`{"$[*].id":"hmac(order)","$[*].st":"keep"}`, `[{"id":"o1","st":"OK"}]`, `[{"id":"` + specToken("order", "o1") + `","st":"keep:OK"}]`},
		{`{"$.a":"keep"}`, `{"a":{"b":1}}`, `{"a":{"b":"drop:int"}}`},
		{`{"$":"drop"}`, `{"a":1,"b":2}`, `"drop:obj:l8"`},
		{`{"$":"keep"}`, `"root"`, `"keep:root"`},
		// The container drop is ignored when a rule of the same group can
		// reach a descendant.
		{`{"$.items":"drop","$.items[*].id":"keep"}`, `{"items":[{"id":"a","x":1}]}`, `{"items":[{"id":"keep:a","x":"drop:int"}]}`},
	}
	for _, c := range cases {
		e := engine(t, rulesAuthor(c.rules))
		if got := bodyOf(t, e, "application/json", c.in); got != c.want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.rules, c.in, got, c.want)
		}
	}
}

const precedenceAuthor = `{` + pol + `,
 "global":{"response":{"$.status":"keep","$.g":"keep","$.items":"drop"},"errors":{"$.error.code":"keep","$.status":"hmac(st)"}},
 "services":{"shop-api":{"match":{"inbound":true},
   "response":{"$.svc":"keep"},
   "errors":{"$.g":"hmac(g)"},
   "ops":{"GET /orders":{"response":{"$.status":"hmac(op)","$.items[*].id":"hmac(order)"}}}}}}`

func respBody(t *testing.T, e *Engine, path string, status int, body string) string {
	t.Helper()
	ex := in(path)
	ex.Status = status
	ex.RespHeaders = hdr("content-type", "application/json")
	ex.RespBody = []byte(body)
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := out.Resp.Get("body")
	b, _ := ttjson.Encode(v)
	return string(b)
}

func TestPrecedence(t *testing.T) {
	e := engine(t, precedenceAuthor)
	body := `{"status":"S","g":"G","svc":"V","error":{"code":"E"},"items":[{"id":"o1","n":1}]}`
	items := `"items":[{"id":"` + specToken("order", "o1") + `","n":"drop:int"}]`
	cases := []struct {
		path   string
		status int
		want   string
	}{
		{"/orders", 200, `{"error":{"code":"drop:str:l8"},"g":"keep:G",` + items + `,"status":"` + specToken("op", "S") + `","svc":"keep:V"}`},
		{"/orders", 404, `{"error":{"code":"keep:E"},"g":"` + specToken("g", "G") + `",` + items + `,"status":"` + specToken("op", "S") + `","svc":"keep:V"}`},
		{"/other", 200, `{"error":{"code":"drop:str:l8"},"g":"keep:G","items":"drop:arr:l8","status":"keep:S","svc":"keep:V"}`},
		{"/other", 500, `{"error":{"code":"keep:E"},"g":"` + specToken("g", "G") + `","items":"drop:arr:l8","status":"` + specToken("st", "S") + `","svc":"keep:V"}`},
		{"/other", 399, `{"error":{"code":"drop:str:l8"},"g":"keep:G","items":"drop:arr:l8","status":"keep:S","svc":"keep:V"}`},
	}
	for _, c := range cases {
		if got := respBody(t, e, c.path, c.status, body); got != c.want {
			t.Errorf("%s %d:\n got %s\nwant %s", c.path, c.status, got, c.want)
		}
	}
}

const pathAuthor = `{` + pol + `,
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T00:00:00Z","allow":["ORD","x.y"]},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}},
   "GET /orders/new":{},
   "GET /a/{x}/c":{"request":{"path":{"x":"keep"}}},
   "GET /a/b/{y}":{},
   "GET /":{},
   "GET /d/{day}":{"request":{"path":{"day":"bucket(time, day)"}}},
   "DELETE /items/{sku}":{"request":{"path":{"sku":"keep"}}},
   "GET /api/orders/{oid}/lines/{n}":{"request":{"path":{"oid":"hmac(order)"}}}
 }}}}`

func TestPaths(t *testing.T) {
	e := engine(t, pathAuthor)
	tok := func(v string) string { return "{" + specToken("order", v) + "}" }
	cases := []struct{ method, path, route, op, rsrc, rpath string }{
		{"GET", "/orders/ORD-2026-000184", "", "GET /orders/{id}", "policy", "/orders/" + tok("ORD-2026-000184")},
		{"get", "/orders/new", "", "GET /orders/new", "policy", "/orders/new"},
		{"GET", "/orders/ORD%2D1", "", "GET /orders/{id}", "policy", "/orders/" + tok("ORD-1")},
		{"GET", "/orders/%FF", "", "", "raw", "/orders/{drop:bytes}"},
		{"GET", "/a/b/c", "", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/a/b/c", "express|/a/:x/c", "GET /a/{x}/c", "framework", "/a/{keep:b}/c"},
		{"GET", "/a/b/c", "gin|/a/:z/c", "GET /a/{x}/c", "framework", "/a/{keep:b}/c"},
		{"GET", "/a/q/c", "koa|/a/b/:y", "GET /a/b/{y}", "framework", "/a/b/{drop:str:l8}"},
		{"GET", "/a/q%20r/c", "", "GET /a/{x}/c", "policy", "/a/{drop:str:l8}/c"},
		{"GET", "/A/b/c", "spring|/a/{x}/c", "GET /a/{x}/c", "framework", "/a/{keep:b}/c"},
		{"GET", "/api/orders/O1/lines/2", "express|/api/orders/:id(\\d+)/lines/:n", "GET /api/orders/{oid}/lines/{n}", "framework", "/api/orders/" + tok("O1") + "/lines/{drop:str:digits}"},
		{"GET", "/api/orders/O1/lines/2", "aspnetcore|/api/orders/{id:int:min(1)}/lines/{n}", "GET /api/orders/{oid}/lines/{n}", "framework", "/api/orders/" + tok("O1") + "/lines/{drop:str:digits}"},
		{"GET", "/api/orders/O1/lines/2", "nethttp|/api/orders/{id}/lines/{n}/{$}", "GET /api/orders/{oid}/lines/{n}", "framework", "/api/orders/" + tok("O1") + "/lines/{drop:str:digits}"},
		{"GET", "/a/b/c", "aspnetcore|/a/{x?}/c", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/a/b/c", "express|/a/*/c", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/a/b/c", "fastapi|/a/{x:path}/c", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/api/orders/O1/lines/2", "jaxrs|/api/orders/{ id : [A-Z0-9]+ }/lines/{n}", "GET /api/orders/{oid}/lines/{n}", "framework", "/api/orders/" + tok("O1") + "/lines/{drop:str:digits}"},
		{"GET", "/api/orders/O1/lines/2", "flask|/api/orders/:id/lines/<int:n>", "GET /api/orders/{oid}/lines/{n}", "policy", "/api/orders/" + tok("O1") + "/lines/{drop:str:digits}"},
		{"GET", "/a/b/c", "|/a/:x/c", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/a/b/c", "spring|/a/:x/c", "GET /a/b/{y}", "policy", "/a/b/{drop:str:l8}"},
		{"GET", "/d/2026-10-19", "", "GET /d/{day}", "policy", "/d/{time:2026-10-19}"},
		{"GET", "/d/2026-10-19T10:00:00Z", "", "GET /d/{day}", "policy", "/d/{drop:str:datetime}"},
		{"GET", "/", "", "GET /", "policy", "/"},
		{"GET", "//", "", "GET /", "policy", "/"},
		{"POST", "/orders/new", "", "", "raw", "/orders/new"},
		{"POST", "//orders//ORD/", "", "", "raw", "/orders/ORD"},
		{"POST", "/v1/shipments", "", "", "raw", "/v1/shipments"},
		{"POST", "/customers/mario.rossi%40example.com/orders", "", "", "raw", "/customers/{drop:str:email}/orders"},
		{"POST", "/orders%0A", "", "", "raw", "/{drop:str:l8}"},
		{"POST", "/x.y/v1234/V1/my-word_x/a--b/-a/a_", "", "", "raw", "/x.y/{drop:str:l8}/{drop:str:l8}/my-word_x/{drop:str:l8}/{drop:str:l8}/{drop:str:l8}"},
		{"POST", "/" + strings.Repeat("x", 40) + "/" + strings.Repeat("x", 41), "", "", "raw", "/" + strings.Repeat("x", 40) + "/{drop:str:l128}"},
		{"M-SEARCH", "/", "", "OTHER /", "raw", "/"},
		{"OTHER", "/orders/new", "", "OTHER /orders/new", "raw", "/orders/new"},
		{"DELETE", "/items/a%20b", "", "DELETE /items/{sku}", "policy", "/items/{drop:str:l8}"},
		{"DELETE", "/items/AB-1", "", "DELETE /items/{sku}", "policy", "/items/{keep:AB-1}"},
	}
	for _, c := range cases {
		ex := in(c.path)
		ex.Method = c.method
		ex.Framework, ex.FrameworkRoute, _ = strings.Cut(c.route, "|")
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := out.Req.Get("path")
		op := c.op
		if op == "" {
			op = normalizeMethod(c.method) + " " + c.rpath
		}
		if out.Op != op || out.RouteSource != c.rsrc || p.Str != c.rpath {
			t.Errorf("%s %s (%s): got op=%q src=%q path=%q; want op=%q src=%q path=%q", c.method, c.path, c.route, out.Op, out.RouteSource, p.Str, op, c.rsrc, c.rpath)
		}
	}
	long := strings.Repeat("/orders", 40)
	out, _ := e.Sanitize(in(long), t0, ByRandom)
	p, _ := out.Req.Get("path")
	if want := strings.Repeat("/orders", 32) + "/{trunc}"; p.Str != want || out.RouteSource != "raw" {
		t.Errorf("trunc: %s %s", p.Str, out.RouteSource)
	}
	// Automatic words expire.
	for _, now := range []time.Time{time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), {}} {
		out, _ = e.Sanitize(&Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/v1/shipments"), Status: 200}, now, ByRandom)
		if out.Op != "POST /{drop:str:l8}/{drop:str:l32}" {
			t.Errorf("auto words at %v: %s", now, out.Op)
		}
	}
}

func TestHeadersCookiesQuery(t *testing.T) {
	a := author(`"global":{"request":{"headers":{"accept":"keep","x-id":"hmac(xid)","x-3912345678":"keep"},"cookies":{"lang":"keep"},"query":{"page":"keep","x123456":"keep"}},
	           "response":{"headers":{"content-type":"keep"},"cookies":{"sid":"hmac(sid)"}}}`)
	e := engine(t, a)
	ex := in("/x")
	ex.RawQuery = []byte("page=2&page=3&&b=&c=%ZZ&d=%FF&e+f=x&x123456=v&%FF=z&q=a+b%2Bc&ORD123456&k")
	ex.ReqHeaders = []Header{
		{Name: ":authority", Value: []byte("shop.example")},
		{Name: "Accept", Value: []byte(" application/json\t")},
		{Name: "X-Id", Value: []byte("abc")},
		{Name: "bad name", Value: []byte("1")},
		{Name: "x-bin", Value: []byte{0xff}},
		{Name: "ACCEPT", Value: []byte("text/html")},
		{Name: "X-3912345678", Value: []byte("giulia")},
		{Name: "Cookie", Value: []byte("lang=it; sid=\"quoted\" ;\tnovalue; =empty; 550e8400-e29b-41d4-a716-446655440000=1")},
		{Name: "Cookie", Value: []byte("lang=en")},
		{Name: "Set-Cookie", Value: []byte("ignored=1")},
		{Name: "content-type", Value: []byte("application/json")},
	}
	ex.RespHeaders = []Header{
		{Name: "Content-Type", Value: []byte("text/plain; charset=utf-8")},
		{Name: "Set-Cookie", Value: []byte("sid=abc; Path=/; HttpOnly")},
		{Name: "Set-Cookie", Value: []byte(" sp=1")},
		{Name: "Set-Cookie", Value: []byte("noeq; Path=/")},
		{Name: "Cookie", Value: []byte("ignored=1")},
	}
	got := canon(t, e, ex, t0)
	want := `{"op":"GET /{drop:str:l8}","req":{` +
		`"cookies":{"lang":["keep:it","keep:en"],"sid":["drop:str:l8"],"{*}":["drop:str:l8","drop:str:digits"]},` +
		`"ct":"application/json",` +
		`"headers":{"accept":["keep:application/json, text/html"],"content-type":["drop:str:l32"],"x-bin":["drop:bytes"],"x-id":["` + specToken("xid", "abc") + `"],"{*}":["drop:str:l32"]},` +
		`"path":"/{drop:str:l8}",` +
		`"query":{"b":["drop:str:l8"],"c":["drop:str:l8"],"d":["drop:bytes"],"page":["keep:2","keep:3"],"q":["drop:str:l8"],"{*}":["drop:str:l8","keep:v","drop:str:l8","drop:str:l32","drop:str:l8"]},` +
		`"size":"l8"},` +
		`"resp":{"cookies":{"sid":["` + specToken("sid", "abc") + `"],"sp":["drop:str:digits"]},"ct":"text/plain","headers":{"content-type":["keep:text/plain; charset=utf-8"]},"size":"l8"},` +
		`"route_source":"raw","sampled_by":"random","service":"shop-api"}`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	// Absent query vs empty query.
	ex2 := in("/x")
	if got := reqField(t, e, ex2, "query"); got != "<absent>" {
		t.Errorf("absent query: %s", got)
	}
	ex2.RawQuery = []byte{}
	if got := reqField(t, e, ex2, "query"); got != "<absent>" {
		t.Errorf("empty query: %s", got)
	}
	// content-type repeated → joined → invalid.
	ex3 := in("/x")
	ex3.ReqHeaders = hdr("content-type", "application/json", "Content-Type", "text/plain")
	if got := reqField(t, e, ex3, "ct"); got != `"invalid"` {
		t.Errorf("repeated ct: %s", got)
	}
}

func TestNameLimits(t *testing.T) {
	e := engine(t, limitsAuthor(`{"max_array":2}`))
	ex := in("/x")
	var q []string
	for i := 0; i < 70; i++ {
		ex.ReqHeaders = append(ex.ReqHeaders, Header{Name: "h" + itoa(i), Value: []byte("v")})
		q = append(q, "n"+itoa(i)+"=1")
	}
	ex.ReqHeaders = append(ex.ReqHeaders, Header{Name: "h0", Value: []byte("again")})
	q = append(q, "n0=2", "n0=3", "n1=4", "n100=9")
	ex.RawQuery = []byte(strings.Join(q, "&"))
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := out.Req.Get("headers")
	qv, _ := out.Req.Get("query")
	for name, v := range map[string]ttjson.Value{"headers": h, "query": qv} {
		if len(v.Obj) != 65 {
			t.Fatalf("%s: %d keys", name, len(v.Obj))
		}
		tr, ok := v.Get("{trunc}")
		b, _ := ttjson.Encode(tr)
		if !ok || string(b) != `["trunc:keys:l128"]` {
			t.Errorf("%s trunc: %s", name, b)
		}
	}
	h0, _ := h.Get("h0")
	if b, _ := ttjson.Encode(h0); string(b) != `["drop:str:l8"]` {
		t.Errorf("h0 merged: %s", b)
	}
	n0, _ := qv.Get("n0")
	if b, _ := ttjson.Encode(n0); string(b) != `["drop:str:digits","drop:str:digits","trunc:n:l8"]` {
		t.Errorf("n0 values: %s", b)
	}
	if _, ok := h.Get("h64"); ok {
		t.Error("h64 should be truncated")
	}
}

const outAuthor = `{` + pol + `,
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T00:00:00Z","hosts_allow":["api.other.example:8443"]},
 "services":{
  "shipping-ext":{"match":{"base":"https://API.carrier.example:443"},"ops":{"POST /v1/shipments":{},"GET /v1/shipments/{id}":{"request":{"path":{"id":"hmac(shipment)"}}}}},
  "carrier-v2":{"match":{"base":"https://api.carrier.example/v2"},"ops":{"GET /labels/{id}":{}}},
  "local":{"match":{"base":"http://local.example:8080"},"ops":{}}
 }}`

func TestOutbound(t *testing.T) {
	e := engine(t, outAuthor)
	cases := []struct{ base, method, path, svc, op, rpath, src string }{
		{"https://api.carrier.example", "POST", "/v1/shipments", "shipping-ext", "POST /v1/shipments", "/v1/shipments", "policy"},
		{"HTTPS://API.carrier.example:443", "POST", "/v1/shipments", "shipping-ext", "POST /v1/shipments", "/v1/shipments", "policy"},
		{"https://api.carrier.example", "GET", "/v2/labels/L1", "carrier-v2", "GET /labels/{id}", "/v2/labels/{drop:str:l8}", "policy"},
		{"https://api.carrier.example", "POST", "/v2/labels", "carrier-v2", "POST /labels", "/v2/labels", "raw"},
		{"https://api.carrier.example", "POST", "/v2%2Flabels", "shipping-ext", "POST /{drop:str:l32}", "/{drop:str:l32}", "raw"},
		{"https://api.carrier.example", "POST", "/v2x/labels", "shipping-ext", "POST /{drop:str:l8}/labels", "/{drop:str:l8}/labels", "raw"},
		{"https://api.carrier.example", "POST", "/v2", "carrier-v2", "POST /", "/v2", "raw"},
		{"http://api.carrier.example", "POST", "/x", "host:api.carrier.example", "POST /x", "/x", "raw"},
		{"https://api.other.example:8443", "POST", "/x", "host:api.other.example:8443", "POST /x", "/x", "raw"},
		{"http://local.example:8080", "POST", "/", "local", "POST /", "/", "raw"},
		{"http://local.example", "POST", "/", "host:local.example", "POST /", "/", "raw"},
		{"https://[::1]:443", "POST", "/", "host:ip:private", "POST /", "/", "raw"},
		{"https://t-3912345678.tenant.example:9443", "POST", "/", "host:{*}.tenant.example:9443", "POST /", "/", "raw"},
		{"http://10.1.2.3:8080", "POST", "/", "host:ip:private:8080", "POST /", "/", "raw"},
		{"https://bücher.example", "POST", "/", "host:invalid", "POST /", "/", "raw"},
		{"https://a.example:0", "POST", "/", "host:invalid", "POST /", "/", "raw"},
		{"https://a.example:99999", "POST", "/", "host:invalid", "POST /", "/", "raw"},
		{"https://user:pw@a.example", "POST", "/", "host:invalid", "POST /", "/", "raw"},
		{"https://a.example/", "POST", "/", "host:invalid", "POST /", "/", "raw"},
		{"nonsense", "POST", "/", "host:invalid", "POST /", "/", "raw"},
	}
	for _, c := range cases {
		ex := &Exchange{Dir: Outbound, URLBase: c.base, Method: c.method, RawPath: []byte(c.path), Status: 200}
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := out.Req.Get("path")
		if out.Service != c.svc || out.Op != c.op || p.Str != c.rpath || out.RouteSource != c.src {
			t.Errorf("%s%s: got %q %q %q %q", c.base, c.path, out.Service, out.Op, p.Str, out.RouteSource)
		}
	}
	ex := &Exchange{Dir: Outbound, URLBase: "https://api.carrier.example", Method: "GET", RawPath: []byte("/v1/shipments/SH-9"), Status: 200}
	out, _ := e.Sanitize(ex, t0, ByRandom)
	p, _ := out.Req.Get("path")
	if out.Op != "GET /v1/shipments/{id}" || p.Str != "/v1/shipments/{"+specToken("shipment", "SH-9")+"}" {
		t.Errorf("outbound template: %s %s", out.Op, p.Str)
	}
	// Discovery shows unlisted hosts, as patterns even in strict mode.
	d := engine(t, author(`"discovery":{"enabled":true,"expires_at":"2026-10-22T00:00:00Z"},"hosts":{"discovery":"off"}`))
	out, _ = d.Sanitize(&Exchange{Dir: Outbound, URLBase: "https://x.example:443", Method: "GET", RawPath: []byte("/"), Status: 200}, t0, ByRandom)
	if out.Service != "host:x.example" {
		t.Errorf("discovery host: %s", out.Service)
	}
	out, _ = d.Sanitize(&Exchange{Dir: Outbound, URLBase: "https://a3912345678.x.example", Method: "GET", RawPath: []byte("/"), Status: 200}, t0, ByRandom)
	if out.Service != "host:{*}.x.example" {
		t.Errorf("discovery host pattern: %s", out.Service)
	}
	// Strict mode (hosts.discovery off) keeps host:unlisted.
	s := engine(t, author(`"hosts":{"discovery":"off"}`))
	for _, base := range []string{"https://x.example", "http://10.0.0.1", "http://[::1]"} {
		out, _ = s.Sanitize(&Exchange{Dir: Outbound, URLBase: base, Method: "GET", RawPath: []byte("/"), Status: 200}, t0, ByRandom)
		if out.Service != "host:unlisted" {
			t.Errorf("strict %s: %s", base, out.Service)
		}
	}
}

func TestNetErrorAndValidation(t *testing.T) {
	e := engine(t, author(""))
	ex := in("/x")
	ex.Status = 0
	ex.NetError = "timeout"
	ex.RespHeaders = hdr("content-type", "text/plain")
	got := canon(t, e, ex, t0)
	if got != `{"op":"GET /{drop:str:l8}","req":{"path":"/{drop:str:l8}","size":"l8"},"route_source":"raw","sampled_by":"random","service":"shop-api"}` {
		t.Errorf("net error: %s", got)
	}
	for _, bad := range []*Exchange{
		{Dir: "sideways", ServiceName: "a", Method: "GET"},
		{Dir: Inbound, ServiceName: "Shop API", Method: "GET"},
		{Dir: Inbound, ServiceName: "a", Method: "GET", NetError: "boom"},
	} {
		if _, err := e.Sanitize(bad, t0, ByRandom); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	if _, err := e.Sanitize(in("/"), t0, "magic"); err == nil {
		t.Error("bad sampled_by accepted")
	}
}

func jwtFor(payload string) string {
	enc := func(s string) string { return b64url(s) }
	return enc(`{"alg":"none"}`) + "." + enc(payload) + ".c2ln"
}

func TestSubject(t *testing.T) {
	a := func(subject string) string { return author(`"identity":{"subject":` + subject + `}`) }
	hdrJWT := `{"from":"header","name":"Authorization","jwt_claim":"sub"}`
	cases := []struct {
		subject string
		hdrs    []Header
		want    string // raw subject or "" for absent
	}{
		{hdrJWT, hdr("authorization", "Bearer "+jwtFor(`{"sub":"user-42","sub":"user-43"}`)), "user-43"},
		{hdrJWT, hdr("Authorization", "bEaReR \t "+jwtFor(`{"sub":42.0}`)), "42"},
		{hdrJWT, hdr("Authorization", "Bearer "+jwtFor(`{"sub":true}`)), ""},
		{hdrJWT, hdr("Authorization", "Bearer "+jwtFor(`{"sub":""}`)), ""},
		{hdrJWT, hdr("Authorization", "Bearer "+jwtFor(`{"a.b":"x"}`)), ""},
		{`{"from":"header","name":"authorization","jwt_claim":"a.b"}`, hdr("Authorization", "Bearer "+jwtFor(`{"a.b":"x","a":{"b":"y"}}`)), "x"},
		{hdrJWT, hdr("Authorization", "Bearer "+b64url(`{}`)+"."+b64url(`{"sub":"pad"}`)+"=.x"), ""},
		{hdrJWT, hdr("Authorization", "Bearer x."+strings.TrimRight(b64url("{\"sub\":\"pad1\"}"), "=")+"=.y"), "pad1"},
		{hdrJWT, hdr("Authorization", "Bearer a.b"), ""},
		{hdrJWT, hdr("Authorization", "Bearer a.b.c.d"), ""},
		{hdrJWT, hdr("Authorization", "Bearer x."+b64url("\xef\xbb\xbf{\"sub\":\"bom\"}")+".y"), ""},
		{hdrJWT, hdr("Authorization", "garbage"), ""},
		{`{"from":"header","name":"x-user"}`, hdr("X-User", "u1", "X-User", "u2"), "u1, u2"},
		{`{"from":"header","name":"x-user"}`, hdr("X-User", "Bearer  u9"), "u9"},
		{`{"from":"header","name":"x-user"}`, hdr("X-User", "Bearer"), "Bearer"},
		{`{"from":"header","name":"x-user"}`, hdr("X-User", "  "), ""},
		{`{"from":"header","name":"x-user"}`, hdr("X-User", strings.Repeat("u", 8193)), ""},
		{`{"from":"cookie","name":"uid"}`, hdr("Cookie", "a=1; uid=c-7; uid=c-8"), "c-7"},
		{`{"from":"cookie","name":"uid"}`, hdr("Cookie", "uid=Bearer c"), "Bearer c"},
		{`{"from":"cookie","name":"uid"}`, hdr("Cookie", "a=1"), ""},
	}
	for _, c := range cases {
		e := engine(t, a(c.subject))
		ex := in("/x")
		ex.ReqHeaders = c.hdrs
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if c.want != "" {
			want = specToken("subject", c.want)
		}
		if out.Subject != want {
			t.Errorf("%s %v: subject %q want token of %q", c.subject, c.hdrs, out.Subject, c.want)
		}
	}
}

func sampleBit(domain, v string, rate int) bool {
	m := specMAC(domain, v)
	return int((uint32(m[0])<<24|uint32(m[1])<<16|uint32(m[2])<<8|uint32(m[3]))%10000) < rate
}

func TestSampling(t *testing.T) {
	a := func(extra, svc string) string {
		return `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},` +
			`"identity":{"subject":{"from":"header","name":"x-user"}},"sampling":{"rate":0.5` + extra + `},"services":{"shop-api":{"match":` + svc + `}}}`
	}
	internal := engine(t, a(`,"trust_baggage":true`, `{"inbound":true,"internal":true}`))
	edge := engine(t, a(`,"trust_baggage":true`, `{"inbound":true}`))
	notTrusted := engine(t, a(``, `{"inbound":true,"internal":true}`))
	mk := func(dir Direction, h []Header, trace string, inh *bool) *Exchange {
		return &Exchange{Dir: dir, ServiceName: "shop-api", URLBase: "https://x.example", Method: "GET", RawPath: []byte("/"), ReqHeaders: h, TraceID: trace, Inherited: inh}
	}
	no := false
	yes := true
	trace := "4bf92f3577b34da6a3ce929d0e0e4736"
	cases := []struct {
		name string
		e    *Engine
		ex   *Exchange
		want Decision
	}{
		{"baggage internal", internal, mk(Inbound, hdr("baggage", "k=v, tt.s = 0 ;p=1", "x-user", "u1"), trace, nil), Decision{false, ByBaggage}},
		{"baggage first valid", internal, mk(Inbound, hdr("Baggage", "tt.s=2,tt.s=1", "baggage", "tt.s=0"), "", nil), Decision{true, ByBaggage}},
		{"baggage edge ignored", edge, mk(Inbound, hdr("baggage", "tt.s=1", "x-user", "u1"), "", nil), Decision{sampleBit("sample", "u1", 5000), BySubject}},
		{"baggage not trusted", notTrusted, mk(Inbound, hdr("baggage", "tt.s=1"), trace, nil), Decision{sampleBit("sample-trace", trace, 5000), ByTrace}},
		{"subject before trace", edge, mk(Inbound, hdr("x-user", "u2"), trace, nil), Decision{sampleBit("sample", "u2", 5000), BySubject}},
		{"trace", edge, mk(Inbound, nil, trace, nil), Decision{sampleBit("sample-trace", trace, 5000), ByTrace}},
		{"inherited no", edge, mk(Outbound, hdr("x-user", "u1"), trace, &no), Decision{false, ByInherited}},
		{"inherited yes", edge, mk(Outbound, nil, "", &yes), Decision{true, ByInherited}},
		{"outbound ignores subject", edge, mk(Outbound, hdr("x-user", "u1"), trace, nil), Decision{sampleBit("sample-trace", trace, 5000), ByTrace}},
		{"random", edge, mk(Inbound, nil, strings.Repeat("0", 32), nil), Decision{true, ByRandom}},
	}
	for _, c := range cases {
		if got := c.e.Sample(c.ex, SampleOptions{RateBP: -1, Rand: func() int { return 4999 }}); got != c.want {
			t.Errorf("%s: %+v want %+v", c.name, got, c.want)
		}
	}
	if d := edge.Sample(mk(Inbound, nil, "", nil), SampleOptions{RateBP: 0, Rand: func() int { return 0 }}); d.Sampled {
		t.Error("override to 0 still sampled")
	}
	// Capture: not sampled ⇒ no output.
	out, d, err := edge.Capture(mk(Outbound, nil, "", &no), t0, nil)
	if out != nil || d.Sampled || err != nil {
		t.Errorf("capture not sampled: %v %+v %v", out, d, err)
	}
	out, d, _ = edge.Capture(mk(Outbound, nil, "", &yes), t0, nil)
	if out == nil || out.SampledBy != ByInherited {
		t.Errorf("capture inherited: %+v", d)
	}
}

func TestDiscovery(t *testing.T) {
	a := author(`"discovery":{"enabled":true,"expires_at":"2026-10-20T00:00:00Z"},"global":{"request":{"$.k":"keep","$.x":"drop"}}`)
	e := engine(t, a)
	ex := in("/orders/ORD-1")
	ex.RawQuery = []byte("q=zz&q=aa&550e8400-e29b-41d4-a716-446655440000=1&nameless")
	ex.ReqHeaders = hdr("Content-Type", "application/json", "X-Bin", "\xff", "Cookie", "c=v")
	ex.ReqBody = []byte(`{"a":"x","k":"kept","x":"explicit","n":12.50,"big":1e10000,"items":[{"s":"b"},{"s":"a"}],"d":1,"d":2,"1":"dyn","bad":"\ud800","t":true}`)
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"req.body.a":               specDisc("req.body.a", "x"),
		"req.body.n":               specDisc("req.body.n", "12.5"),
		"req.body.items[*].s":      specDisc("req.body.items[*].s", "a"),
		"req.body.d":               specDisc("req.body.d", "2"),
		"req.body.*":               specDisc("req.body.*", "dyn"),
		"req.body.t":               specDisc("req.body.t", "true"),
		"req.query.q":              specDisc("req.query.q", "aa"),
		"req.query.{*}":            specDisc("req.query.{*}", "1"),
		"req.headers.content-type": specDisc("req.headers.content-type", "application/json"),
		"req.cookies.c":            specDisc("req.cookies.c", "v"),
		"req.path.0":               specDisc("req.path.0", "orders"),
		"req.path.1":               specDisc("req.path.1", "ORD-1"),
	}
	got := map[string]string{}
	for _, m := range out.Disc {
		got[m.Key] = m.Value.Str
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("disc keys: %v", got)
	}
	for _, now := range []time.Time{time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), {}} {
		out, _ = e.Sanitize(ex, now, ByRandom)
		if len(out.Disc) != 0 {
			t.Errorf("disc at %v: %v", now, out.Disc)
		}
	}
	ex.ReqBody = []byte(`{"a":"x",}`)
	out, _ = e.Sanitize(ex, t0, ByRandom)
	for _, m := range out.Disc {
		if strings.HasPrefix(m.Key, "req.body") {
			t.Errorf("disc from invalid body: %s", m.Key)
		}
	}
}

func TestDeterminism(t *testing.T) {
	e := engine(t, shopAuthor)
	ex := &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"), Status: 201,
		RespHeaders: hdr("Content-Type", "application/json"),
		RespBody:    []byte(`{"b":{"z":1,"a":[1,2]},"a":"x","id":"o"}`)}
	first := canon(t, e, ex, t0)
	for i := 0; i < 20; i++ {
		if got := canon(t, e, ex, t0); got != first {
			t.Fatalf("non deterministic: %s vs %s", got, first)
		}
	}
	if !ttjson.IsCanonical([]byte(first)) {
		t.Fatalf("not canonical: %s", first)
	}
}

func TestKeyHandling(t *testing.T) {
	sec := b64nopad(testSecret())
	for _, bad := range []string{"", "\n\n", "k1", "K1:" + sec, "k1:" + b64nopad(testSecret()[:31]), "k1:" + sec + "=", "k1:a\tb",
		"toolongkid:" + sec, " k1:" + sec, "k1:" + sec + " ", "k1:" + sec + "\nbad", "k1:+" + sec} {
		if _, err := ParseKeys(bad); err != ErrKeyMissing {
			t.Errorf("accepted %q (%v)", bad, err)
		}
	}
	ks, err := ParseKeys("k1:" + sec + "\r\n\r\nk2:" + sec + "\n")
	if err != nil || ks.Len() != 2 {
		t.Fatalf("multi-line: %v", err)
	}
	p := compileJSON(t, author(""))
	k2, _ := NewKey("k2", testSecret())
	if _, err := NewEngine(p, NewKeySet(k2)); err != ErrKeyMismatch {
		t.Errorf("mismatch: %v", err)
	}
	if _, err := NewEngine(p, KeySet{}); err != ErrKeyMissing {
		t.Errorf("missing: %v", err)
	}
	// Rotation: kid k9 in policy, k2 accepted.
	p2 := compileJSON(t, `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k9","epoch":"2026-10","accept_kids":["k3","k2"]},"sampling":{"rate":1}}`)
	k3, _ := NewKey("k3", append([]byte{1}, testSecret()[1:]...))
	e, err := NewEngine(p2, NewKeySet(k2, k3))
	if err != nil || e.Kid() != "k2" {
		t.Errorf("accept_kids selection: %v %s", err, e.Kid())
	}
}

func TestEventSizeLimit(t *testing.T) {
	e := engine(t, `{`+pol+`,"limits":{"max_body_bytes":2000000,"max_array":1024,"keep_max_bytes":1024},"services":{"shop-api":{"match":{"inbound":true},"request":{"$[*]":"keep"}}}}`)
	big := `["` + strings.Repeat("x", 1000) + `"` + strings.Repeat(`,"`+strings.Repeat("y", 1000)+`"`, 1023) + `]`
	ex := in("/x")
	ex.ReqHeaders = hdr("content-type", "application/json")
	ex.ReqBody = []byte(big)
	out, err := e.Sanitize(ex, t0, ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	m := EventMeta{PolicyID: "p", PolicyVersion: 1, PolicyHash: "sha256:" + strings.Repeat("0", 64), SourceKind: "sdk-go",
		SourceVersion: "0.1.0", SourceID: "src-1", TS: t0, Status: 200}
	b, err := BuildEvent(m, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxEventBytes || !strings.Contains(string(b), `"body":"trunc:size"`) {
		t.Errorf("event size %d", len(b))
	}
	if v, _ := out.Req.Get("body"); v.Str != "trunc:size" {
		t.Error("the sanitizer output was not reduced (A-EVENT-SIZE-BASE)")
	}
}
