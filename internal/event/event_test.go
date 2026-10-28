package event

import (
	"bytes"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// specExample is the canonical event of docs/spec/event.md section 3.
const specExample = `{"dir":"inbound","latency_ms":184,"op":"POST /orders","policy":{"hash":"sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d","id":"p-shop","version":7},"req":{"body":{"email":"drop:str:email","items":[{"qty":"drop:int","sku":"drop:str:l32"}],"note":"drop:str:l8"},"ct":"application/json","headers":{"content-type":["keep:application/json"]},"path":"/orders","size":"l128"},"resp":{"body":{"id":"tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg","status":"keep:CREATED","total":"num:50-100"},"ct":"application/json","headers":{"content-type":["keep:application/json; charset=utf-8"]},"size":"l128"},"route_source":"policy","sampled_by":"subject","schema":"tt.http.exchange/v1","service":"shop-api","source":{"id":"src-01JB7Q2W","kind":"sdk-node","version":"0.1.0"},"span_id":"00f067aa0ba902b7","status":201,"subject":"tk1:k1:7Hq2nB5sKe9dXo3uLw1cRf","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","ts":"2026-10-19T10:00:00.412Z"}`

func TestDecodeSpecExampleRoundTrip(t *testing.T) {
	e, err := Decode([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	if e.Op != "POST /orders" || e.Status != 201 || e.Source.ID != "src-01JB7Q2W" || e.Policy.Version != 7 {
		t.Fatalf("unexpected decode: %+v", e)
	}
	if got := string(e.Canonical()); got != specExample {
		t.Fatalf("round trip differs:\n got %s\nwant %s", got, specExample)
	}
	if e.Time.UnixMilli() != 1792404000412 {
		t.Fatalf("ts parsed as %v (%d)", e.Time, e.Time.UnixMilli())
	}
}

// bsu returns a backslash-u escape (kept out of string literals so that
// tooling cannot decode it).
func bsu(hex string) string { return "\\" + "u" + hex }

func mutate(s, old, repl string) string {
	if !strings.Contains(s, old) {
		panic("mutation target not found: " + old)
	}
	return strings.Replace(s, old, repl, 1)
}

func TestDecodeRejections(t *testing.T) {
	cases := []struct {
		name string
		in   string
		code string
	}{
		{"space after colon", mutate(specExample, `"dir":"inbound"`, `"dir": "inbound"`), CodeNonCanonical},
		{"trailing newline", specExample + "\n", CodeNonCanonical},
		{"leading space", " " + specExample, CodeNonCanonical},
		{"key order", mutate(specExample, `{"dir":"inbound","latency_ms":184,`, `{"latency_ms":184,"dir":"inbound",`), CodeNonCanonical},
		{"duplicate key", mutate(specExample, `"dir":"inbound",`, `"dir":"inbound","dir":"inbound",`), CodeNonCanonical},
		{"needless unicode escape", mutate(specExample, `"op":"POST /orders"`, `"op":"POST `+bsu("002f")+`orders"`), CodeNonCanonical},
		{"escaped slash", mutate(specExample, `"POST /orders"`, `"POST \/orders"`), CodeNonCanonical},
		{"uppercase hex escape", mutate(specExample, `"keep:CREATED"`, `"keep:`+bsu("00E9")+`"`), CodeNonCanonical},
		{"raw non-ascii", mutate(specExample, `"keep:CREATED"`, "\"keep:é\""), CodeNonCanonical},
		{"short escape", mutate(specExample, `"keep:CREATED"`, `"keep:a\nb"`), CodeNonCanonical},
		{"number 1.0 style", mutate(specExample, `"latency_ms":184`, `"latency_ms":184.0`), CodeNonCanonical},
		{"number exponent", mutate(specExample, `"latency_ms":184`, `"latency_ms":1.84e2`), CodeNonCanonical},
		{"minus zero", mutate(specExample, `"latency_ms":184`, `"latency_ms":-0`), CodeNonCanonical},
		{"not json", `{"dir":`, CodeJSON},
		{"lone surrogate", mutate(specExample, `"keep:CREATED"`, `"keep:\ud800"`), CodeJSON},
		{"empty", ``, CodeJSON},
		{"trailing garbage", specExample + "x", CodeJSON},
		{"unknown top-level field", mutate(specExample, `{"dir":"inbound",`, `{"dir":"inbound","extra":"x",`), CodeSchema},
		{"unknown req field", mutate(specExample, `"size":"l128"},"resp"`, `"size":"l128","zzz":"x"},"resp"`), CodeSchema},
		{"unknown source field", mutate(specExample, `"version":"0.1.0"}`, `"version":"0.1.0","x":1}`), CodeSchema},
		{"wrong schema id", mutate(specExample, `tt.http.exchange/v1`, `tt.http.exchange/v2`), CodeSchema},
		{"bad hash", mutate(specExample, `sha256:9c1e`, `sha256:9C1E`), CodeSchema},
		{"bad ts", mutate(specExample, `2026-10-19T10:00:00.412Z`, `2026-13-19T10:00:00.412Z`), CodeSchema},
		{"ts without millis", mutate(specExample, `2026-10-19T10:00:00.412Z`, `2026-10-19T10:00:00Z`), CodeSchema},
		{"status out of range", mutate(specExample, `"status":201`, `"status":99`), CodeSchema},
		{"negative latency", mutate(specExample, `"latency_ms":184`, `"latency_ms":-1`), CodeSchema},
		{"bad dir", mutate(specExample, `"inbound"`, `"sideways"`), CodeSchema},
		{"bad sampled_by", mutate(specExample, `"subject","schema"`, `"nothing","schema"`), CodeSchema},
		{"bad subject", mutate(specExample, `tk1:k1:7Hq2nB5sKe9dXo3uLw1cRf`, `tk1:k1:short`), CodeSchema},
		{"bad trace id", mutate(specExample, `4bf92f3577b34da6a3ce929d0e0e4736`, `4BF92F3577B34DA6A3CE929D0E0E4736`), CodeSchema},
		{"token outside grammar in body", mutate(specExample, `"drop:str:email"`, `"alice@example.com"`), CodeSchema},
		{"token outside grammar in header", mutate(specExample, `["keep:application/json"]`, `["application/json"]`), CodeSchema},
		{"invalid drop form", mutate(specExample, `"drop:int"`, `"drop:int:l8"`), CodeSchema},
		{"old length class", mutate(specExample, `"drop:str:l32"`, `"drop:str:l16"`), CodeSchema},
		{"bad size", mutate(specExample, `"size":"l128"}`, `"size":"l0"}`), CodeSchema},
		{"bad path", mutate(specExample, `"path":"/orders"`, `"path":"/or ders"`), CodeSchema},
		{"path without slash", mutate(specExample, `"path":"/orders"`, `"path":"orders"`), CodeSchema},
		{"net_error with status", mutate(specExample, `"latency_ms":184,`, `"latency_ms":184,"net_error":"timeout",`), CodeSchema},
		{"missing status", mutate(specExample, `"status":201,`, ``), CodeSchema},
		{"missing required policy", mutate(specExample, `"policy":{"hash":"sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d","id":"p-shop","version":7},`, ``), CodeSchema},
		{"empty headers map", mutate(specExample, `"headers":{"content-type":["keep:application/json"]},`, `"headers":{},`), CodeSchema},
		{"uppercase header name", mutate(specExample, `"content-type":["keep:application/json"]`, `"Content-Type":["keep:application/json"]`), CodeSchema},
		{"number-like body key", mutate(specExample, `"email":"drop:str:email"`, `"e1234567":"drop:str:email"`), CodeSchema},
		{"hex body key", mutate(specExample, `"email":"drop:str:email"`, `"deadbeefdeadbeef":"drop:str:email"`), CodeSchema},
		{"body key with space", mutate(specExample, `"email":"drop:str:email"`, `"e mail":"drop:str:email"`), CodeSchema},
		{"too deep", `{"a":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`, CodeSchema},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := Decode([]byte(c.in))
			if err == nil {
				t.Fatalf("accepted an invalid event: %+v", e)
			}
			if err.Code != c.code {
				t.Fatalf("code = %s (%s), want %s", err.Code, err.Detail, c.code)
			}
		})
	}
}

func TestDecodeNetErrorEvent(t *testing.T) {
	in := `{"dir":"outbound","latency_ms":3000,"net_error":"timeout","op":"POST /v1/shipments","policy":{"hash":"sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d","id":"p-shop","version":7},"req":{"ct":"application/json","path":"/v1/shipments","size":"l128"},"route_source":"policy","sampled_by":"inherited","schema":"tt.http.exchange/v1","service":"shipping-ext","source":{"id":"src-01JB7Q2W","kind":"sdk-node","version":"0.1.0"},"ts":"2026-10-19T10:00:01.000Z"}`
	e, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if e.NetError != "timeout" || e.Resp != nil || e.Status != 0 || !e.IsError() {
		t.Fatalf("%+v", e)
	}
	if string(e.Canonical()) != in {
		t.Fatalf("round trip differs: %s", e.Canonical())
	}
}

func TestDecodeDiscAndNoDisc(t *testing.T) {
	in := mutate(specExample, `{"dir":"inbound",`, `{"dir":"inbound","disc":{"req.body.items[*].sku":"tkd:AbC123","req.query.promo":"tkd:Zz9_-A"},`)
	e, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Disc) != 2 || e.Disc[0].Path != "req.body.items[*].sku" {
		t.Fatalf("%+v", e.Disc)
	}
	if string(e.Canonical()) != in {
		t.Fatal("round trip with disc differs")
	}
	if string(e.AppendCanonicalNoDisc(nil)) != specExample {
		t.Fatal("canonical without disc differs from the original")
	}
	bad := mutate(in, `tkd:AbC123`, `tkd:AbC12`)
	if _, err := Decode([]byte(bad)); err == nil || err.Code != CodeSchema {
		t.Fatalf("short tkd accepted: %v", err)
	}
}

func TestStringEscapingRoundTrip(t *testing.T) {
	for _, s := range []string{"", "plain", `quote"back\slash`, "tab\tnl\n", "\x7f", "é", "日本語", "😀", " ", "a/b"} {
		enc := AppendString(nil, s)
		in := `{"x":` + string(enc) + `}`
		v, err := ParseCanonical([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v (%s)", s, err, in)
		}
		if v.O[0].V.S != s {
			t.Fatalf("round trip of %q gave %q", s, v.O[0].V.S)
		}
		if bytes.ContainsAny(enc, "\x7f") || !isPrintableASCII(string(enc)) {
			t.Fatalf("encoding of %q is not printable ASCII: %s", s, enc)
		}
	}
	if got := string(AppendString(nil, "😀")); got != `"`+bsu("d83d")+bsu("de00")+`"` {
		t.Fatalf("surrogate pair: %s", got)
	}
	if got := string(AppendString(nil, "\x01\x7f")); got != `"`+bsu("0001")+bsu("007f")+`"` {
		t.Fatalf("control: %s", got)
	}
}

func TestCanonicalNumber(t *testing.T) {
	cases := map[string]string{
		"184": "184", "1.50": "1.5", "15e-1": "1.5", "-0.0": "0", "1E3": "1000", "73.40": "73.4",
		"0.0015": "0.0015", "1000000": "1000000", "1e21": "1e+21", "1e20": "100000000000000000000",
		"1.5e-7": "1.5e-7", "0.000001": "0.000001", "0.0000001": "1e-7", "-0": "0", "0": "0",
		"123456789012345678901234567890": "1.2345678901234567890123456789e+29",
		"100":                            "100", "0.5": "0.5", "-12.5e1": "-125", "1e0": "1", "10e-1": "1",
	}
	for in, want := range cases {
		got, ok := CanonicalNumber(in)
		if !ok || got != want {
			t.Errorf("CanonicalNumber(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "-", "01", "1.", ".5", "1e", "1e+", "+1", "0x10", "NaN", "1 ", "--1"} {
		if _, ok := CanonicalNumber(bad); ok {
			t.Errorf("CanonicalNumber(%q) accepted", bad)
		}
	}
}

func TestSplitPath(t *testing.T) {
	good := []string{
		"/", "/orders", "/orders/{tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg}/items", "/v1/{drop:str:l32}", "/{drop:bytes}",
		"/a/{keep:ORD-1}/{time:2026-10-19}/{trunc}", "/x/{num:1e+21}", "/{drop:str:email}/orders",
	}
	for _, p := range good {
		if !ValidPath(p) {
			t.Errorf("path %q rejected", p)
		}
	}
	bad := []string{"", "orders", "//a", "/a/", "/a b", "/{drop:str:bogus}", "/{keep:a b}", "/{keep:}", "/{time:2026-13}",
		"/{tk1:k1:short}", "/{foo}", "/{drop:str:l8", "/a{drop:int}", "/{drop:int}x", "/é", "/%41", "/" + strings.Repeat("a", 65)}
	for _, p := range bad {
		if ValidPath(p) {
			t.Errorf("path %q accepted", p)
		}
	}
	segs, _ := SplitPath("/orders/{tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg}")
	if len(segs) != 2 || !segs[0].Literal || segs[1].Literal || segs[1].Inner != "tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg" {
		t.Fatalf("%+v", segs)
	}
}

func TestOpParsing(t *testing.T) {
	for _, op := range []string{"GET /", "POST /orders/{id}", "OTHER /x", "DELETE /a/{drop:str:l8}"} {
		if !ValidOp(op) {
			t.Errorf("op %q rejected", op)
		}
	}
	for _, op := range []string{"", "get /x", "GET x", "GET  /x", "GET /a b", "TOOLONGMETHODNAME12 /x", "GET"} {
		if ValidOp(op) {
			t.Errorf("op %q accepted", op)
		}
	}
	m, p, ok := ParseOp("GET /orders/{id}")
	if !ok || m != "GET" || p != "/orders/{id}" {
		t.Fatal(m, p, ok)
	}
	segs, ok := OpSegments("/orders/{id}")
	if !ok || len(segs) != 2 || segs[1].Literal || segs[1].Inner != "id" {
		t.Fatalf("%+v", segs)
	}
}

func TestTimeTokens(t *testing.T) {
	good := map[string]string{"time:2026": "year", "time:2026-10": "month", "time:2026-10-19": "day", "time:2026-10-19T10": "hour", "time:2028-02-29": "day"}
	for s, u := range good {
		if got, ok := TimeTokenUnit(s); !ok || got != u {
			t.Errorf("%s: %q %v", s, got, ok)
		}
	}
	for _, s := range []string{"time:", "time:0000", "time:2026-00", "time:2026-13", "time:2027-02-29", "time:2026-10-19T24", "time:2026-10-19T1", "time:2026-10-19X10", "time:202", "time:2026/10"} {
		if ValidTimeToken(s) {
			t.Errorf("%s accepted", s)
		}
	}
}

// The hand-written grammar matchers must agree with the regular expressions
// of the schema (docs/spec/sanitizer.md 6.3 and schemas/event.v1.schema.json).
func TestFormatsAgreeWithSpecRegexps(t *testing.T) {
	res := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"uuid", regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)},
		{"jwt", regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)},
		{"email", regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)},
		{"datetime", regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$`)},
		{"date", regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)},
		{"url", regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+$`)},
		{"ipv4", regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$`)},
		{"phone", regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)},
		{"digits", regexp.MustCompile(`^-?[0-9]{1,19}$`)},
		{"hex", regexp.MustCompile(`^[0-9A-Fa-f]{16,}$`)},
	}
	want := func(s string) string {
		for _, r := range res {
			if r.re.MatchString(s) {
				return r.name
			}
		}
		return ""
	}
	fixed := []string{
		"550e8400-e29b-41d4-a716-446655440000", "eyJhbGciOi.eyJzdWIi.sig", "eyJa.b.", "a@b.co", "mario.rossi@example.com",
		"2026-10-19T10:00:00Z", "2026-10-19 10:00:00.123456789+02:00", "2026-10-19", "https://x.example/a", "ftp://", "10.0.0.1", "256.1.1.1", "01.1.1.1",
		"+393331234567", "+0123456", "12345", "-123", "12345678901234567890", "deadbeefdeadbeef", "DEADBEEF", "0123456789abcdef0",
		"1234567890123456", "orders", "", "a@b", "x@y.z.", "http://a b",
	}
	for _, s := range fixed {
		if g := Format(s); g != want(s) {
			t.Errorf("Format(%q) = %q, regexp says %q", s, g, want(s))
		}
	}
	alphabet := []byte("0123456789abcdefABCDEF-.:@+_%/ TtZzeyJ")
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		n := rnd.Intn(24)
		b := make([]byte, n)
		for k := range b {
			b[k] = alphabet[rnd.Intn(len(alphabet))]
		}
		s := string(b)
		if g := Format(s); g != want(s) {
			t.Fatalf("Format(%q) = %q, regexp says %q", s, g, want(s))
		}
	}
	// Structured generators for the longer formats.
	gen := []func(r *rand.Rand) string{
		func(r *rand.Rand) string { // uuid-ish
			h := "0123456789abcdefABCDEFg"
			var sb strings.Builder
			for i := 0; i < 36; i++ {
				if i == 8 || i == 13 || i == 18 || i == 23 {
					sb.WriteByte('-')
				} else {
					sb.WriteByte(h[r.Intn(len(h))])
				}
			}
			return sb.String()
		},
		func(r *rand.Rand) string { // datetime-ish
			p := []string{"2026-10-19", "2026-1-19"}
			sep := []string{"T", "t", " ", "x"}
			frac := []string{"", ".1", ".123456789", ".1234567890", "."}
			zone := []string{"Z", "z", "+02:00", "-05:30", "+0200", ""}
			return p[r.Intn(2)] + sep[r.Intn(4)] + "10:00:00" + frac[r.Intn(5)] + zone[r.Intn(6)]
		},
		func(r *rand.Rand) string { // ipv4-ish
			parts := make([]string, 4)
			for i := range parts {
				parts[i] = []string{"0", "1", "10", "099", "255", "256", "25", "300", "00", "1000", ""}[r.Intn(11)]
			}
			return strings.Join(parts, ".")
		},
		func(r *rand.Rand) string { // email-ish
			loc := strings.Repeat("a", r.Intn(70))
			dom := []string{"example.com", "a.b.c", "x", "-.-", ".com", "ex..com", strings.Repeat("a", 64) + ".com"}[r.Intn(7)]
			return loc + "@" + dom
		},
	}
	for i := 0; i < 20000; i++ {
		s := gen[i%len(gen)](rnd)
		if g := Format(s); g != want(s) {
			t.Fatalf("Format(%q) = %q, regexp says %q", s, g, want(s))
		}
	}
}

func TestTokenClassification(t *testing.T) {
	re := []*regexp.Regexp{
		regexp.MustCompile(`^drop:(null|bool|int|dec|bytes|str:(invalid|uuid|jwt|email|datetime|date|url|ipv4|phone|digits|hex|l8|l32|l128|l1024|lmax)|(obj|arr|bytes):(l8|l32|l128|l1024|lmax))$`),
		regexp.MustCompile(`^keep:`),
		regexp.MustCompile(`^tk1:[a-z0-9]{1,8}:[A-Za-z0-9_-]{22}$`),
		regexp.MustCompile(`^num:(<|>=)?-?[0-9][0-9.e+-]*$`),
		regexp.MustCompile(`^time:[0-9]{4}(-[0-9]{2}(-[0-9]{2}(T[0-9]{2})?)?)?$`),
		regexp.MustCompile(`^trunc:(depth|invalid-json|size|(n|keys):(l8|l32|l128|l1024|lmax))$`),
	}
	kinds := []TokenKind{TokDrop, TokKeep, TokHMAC, TokNum, TokTime, TokTrunc}
	samples := []string{
		"drop:null", "drop:bool", "drop:int", "drop:dec", "drop:bytes", "drop:bytes:l8", "drop:str:email", "drop:str:l8", "drop:obj:lmax", "drop:arr:l32",
		"drop:str:l16", "drop:str:", "drop:", "drop:int:l8", "drop:obj", "keep:", "keep:x", "keep:é", "tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg", "tk1:K1:Zx81mQ4pLr0aVb7cYt2eWg",
		"tk1:k1:Zx81mQ4pLr0aVb7cYt2eW", "tk1::Zx81mQ4pLr0aVb7cYt2eWg", "tk1:abcdefghi:Zx81mQ4pLr0aVb7cYt2eWg", "num:50-100", "num:<0", "num:>=250", "num:-5--1", "num:1e+21-2e+21",
		"num:", "num:x", "num:<>5", "time:2026", "time:2026-10", "time:2026-10-19", "time:2026-10-19T10", "time:2026-1", "trunc:size", "trunc:depth", "trunc:n:l8", "trunc:keys:lmax",
		"trunc:n:l16", "trunc:", "tkd:AbC123", "", "x", "drop", "KEEP:x",
	}
	for _, s := range samples {
		want := TokInvalid
		for i, r := range re {
			if r.MatchString(s) {
				want = kinds[i]
				break
			}
		}
		// time: tokens additionally need a valid calendar date.
		if want == TokTime && !ValidTimeToken(s) {
			want = TokInvalid
		}
		if got := ClassifyToken(s); got != want {
			t.Errorf("ClassifyToken(%q) = %v, regexp says %v", s, got, want)
		}
	}
}

func TestDropFormAndLenClass(t *testing.T) {
	cases := map[string]string{
		"": "drop:str:l8", "Roma": "drop:str:l8", "Roma Capitale": "drop:str:l32", "mario@example.com": "drop:str:email",
		"550e8400-e29b-41d4-a716-446655440000": "drop:str:uuid", "2026-10-19": "drop:str:date", "\xff": "drop:str:invalid",
		"12345": "drop:str:digits", strings.Repeat("x", 129): "drop:str:l1024", strings.Repeat("x", 1025): "drop:str:lmax",
		"è": "drop:str:l8",
	}
	for in, want := range cases {
		if got := DropForm(in); got != want {
			t.Errorf("DropForm(%q) = %q want %q", in, got, want)
		}
	}
	for n, want := range map[int]string{0: "l8", 8: "l8", 9: "l32", 32: "l32", 33: "l128", 128: "l128", 129: "l1024", 1024: "l1024", 1025: "lmax"} {
		if LenClass(n) != want {
			t.Errorf("LenClass(%d) = %s", n, LenClass(n))
		}
	}
}

func TestDynamicName(t *testing.T) {
	for _, n := range []string{"order123456", "550e8400-e29b-41d4-a716-446655440000", "deadbeefdeadbeef", "x-3912345678", "eyJabc.def.ghi", "12345", "a@b.co"} {
		if !DynamicName(n) {
			t.Errorf("%q should be dynamic", n)
		}
	}
	for _, n := range []string{"email", "order_id", "x-request-id", "a12345", "content-type", "_private"} {
		if DynamicName(n) {
			t.Errorf("%q should be literal", n)
		}
	}
}

func TestWalkBodyAndTokens(t *testing.T) {
	e, err := Decode([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	WalkBody(e.Req.Body, func(p string, l *Value) { paths = append(paths, p) })
	want := []string{"$.email", "$.items[*].qty", "$.items[*].sku", "$.note"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths %v", paths)
	}
	var toks []HMACToken
	e.HMACTokens(func(t HMACToken) { toks = append(toks, t) })
	if len(toks) != 2 || toks[0].Where != "subject" || toks[1].Where != "resp.body$.id" {
		t.Fatalf("%+v", toks)
	}
}

func TestDecodeNeverPanics(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	base := []byte(specExample)
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), base...)
		for k := 0; k < 1+rnd.Intn(4); k++ {
			switch rnd.Intn(3) {
			case 0:
				b[rnd.Intn(len(b))] = byte(rnd.Intn(256))
			case 1:
				j := rnd.Intn(len(b))
				b = append(b[:j], b[j+1:]...)
			default:
				j := rnd.Intn(len(b))
				b = append(b[:j], append([]byte{byte(rnd.Intn(256))}, b[j:]...)...)
			}
		}
		if e, err := Decode(b); err == nil {
			// Whatever is accepted must be exactly canonical.
			if !bytes.Equal(e.Canonical(), b) {
				t.Fatalf("accepted bytes differ from their canonical form:\n%s\n%s", b, e.Canonical())
			}
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(specExample))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Decode(b)
		if err == nil && !bytes.Equal(e.Canonical(), b) {
			t.Fatalf("accepted non-canonical bytes")
		}
	})
}
