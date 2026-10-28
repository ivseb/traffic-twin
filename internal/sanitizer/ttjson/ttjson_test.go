package ttjson

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCanonicalNumber(t *testing.T) {
	cases := map[string]string{
		// Section 10.2 examples.
		"1.50": "1.5", "15e-1": "1.5", "-0.0": "0", "1E3": "1000",
		"123456789012345678901234567890": "1.2345678901234567890123456789e+29",
		"184":                            "184", "73.4": "73.4", "0.0015": "0.0015", "1000000": "1000000",
		"1e21": "1e+21", "1.5e-7": "1.5e-7",
		// Boundaries of the plain range -6 < e <= 21.
		"0.000001": "0.000001", "0.0000001": "1e-7", "100000000000000000000": "100000000000000000000",
		"1000000000000000000000": "1e+21", "999999999999999999999": "999999999999999999999",
		"0.00000123": "0.00000123", "0.000000123": "1.23e-7",
		// Misc.
		"0": "0", "-0": "0", "0e10": "0", "-0.000e-5": "0", "1": "1", "-1": "-1", "10": "10",
		"184.0": "184", "1.84e2": "184", "18400e-2": "184", "0.1": "0.1", "-12.50": "-12.5",
		"1e-0": "1", "1E+2": "100", "5e-324": "5e-324", "1e400": "1e+400", "-1e-400": "-1e-400",
		"12e1000000000000000000000":                   "1.2e+1000000000000000000001",
		"1e00000000000000000000000000003":             "1000",
		"1.5e-00000000000000000000000000000000000007": "1.5e-7",
		"0.0000000000000000000000000001e28":           "1",
	}
	for in, want := range cases {
		got, err := CanonicalNumber([]byte(in))
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v) want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-", "01", "1.", ".1", "+1", "1e", "1e+", "NaN", "0x1", "1 "} {
		if _, err := CanonicalNumber([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEncodeStrings(t *testing.T) {
	v := Obj(
		Member{Key: "b", Value: Str("q\"\\/\n\t\x00\x1f\x7f é€😀")},
		Member{Key: "a", Value: Arr(BoolV(true), BoolV(false), Value{Kind: Null}, Num("1.50"))},
		Member{Key: "B", Value: Obj()},
	)
	got, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"B":{},"a":[true,false,null,1.5],"b":"q\"\\/\u000a\u0009\u0000\u001f\u007f \u00e9\u20ac\ud83d\ude00"}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if _, err := Encode(Str("\xff")); err == nil {
		t.Error("invalid utf8 encoded")
	}
	if _, err := Encode(Obj(Member{Key: "a"}, Member{Key: "a"})); err == nil {
		t.Error("duplicate key encoded")
	}
	if _, err := Encode(Num("01")); err == nil {
		t.Error("bad number encoded")
	}
}

func TestParse(t *testing.T) {
	v, err := Parse([]byte(` {"a":1,"b":[true,null,"x\u00e9"],"a":2} `), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Encode(v)
	if string(out) != `{"a":2,"b":[true,null,"x\u00e9"]}` {
		t.Fatalf("%s", out)
	}
	if _, err := Parse([]byte(`{"a":1,"a":2}`), ParseOptions{RejectDuplicates: true}); err != ErrDuplicateKey {
		t.Errorf("dup: %v", err)
	}
	if _, err := Parse([]byte(`[[[1]]]`), ParseOptions{MaxDepth: 2}); err != ErrDepth {
		t.Errorf("depth: %v", err)
	}
	if _, err := Parse([]byte(`"\ud800"`), ParseOptions{}); err != ErrLoneSurrogate {
		t.Errorf("surrogate: %v", err)
	}
	if !IsCanonical([]byte(`{"a":[1,"x"],"b":{}}`)) || IsCanonical([]byte(`{"b":1,"a":2}`)) || IsCanonical([]byte(`{"a":1.0}`)) || IsCanonical([]byte(`{"a": 1}`)) {
		t.Error("IsCanonical")
	}
}

func TestSkipValue(t *testing.T) {
	deep := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	end, n, err := SkipValue([]byte(deep), 0, nil)
	if err != nil || end != len(deep) || n != 1 {
		t.Fatalf("deep: %d %d %v", end, n, err)
	}
	var keys []string
	end, n, err = SkipValue([]byte(`{"a":{"x":1},"b":[1,2],"a":3} tail`), 0, func(k []byte, _ bool) { keys = append(keys, string(k)) })
	if err != nil || end != 29 || n != 3 || strings.Join(keys, ",") != "a,b,a" {
		t.Fatalf("obj: %d %d %v %v", end, n, err, keys)
	}
	if _, _, err := SkipValue([]byte(`[1,{"a":]`), 0, nil); err == nil {
		t.Error("accepted invalid")
	}
}

// FuzzParseAgainstStdlib checks that the strict parser accepts exactly the
// documents that encoding/json accepts (for valid UTF-8 input) and that
// canonical output is stable.
func FuzzParseAgainstStdlib(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `[1,2.5e3,"xé",null,true]`, `"\ud800"`, `{"a":{"b":[]}}`, `1e400`, `-0`, `[1,]`, ` "x" `} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, d []byte) {
		v, err := Parse(d, ParseOptions{MaxDepth: 1000})
		std := json.Valid(d) && utf8.Valid(d)
		if err == nil && !std {
			t.Fatalf("accepted invalid %q", d)
		}
		if err == ErrSyntax && std {
			t.Fatalf("rejected valid %q", d)
		}
		if _, _, serr := SkipValue(d, 0, nil); serr == nil && utf8.Valid(d) {
			end, _, _ := SkipValue(d, 0, nil)
			if SkipWS(d, end) == len(d) && !json.Valid(d) {
				t.Fatalf("SkipValue accepted invalid %q", d)
			}
		}
		if err != nil {
			return
		}
		out, err := Encode(v)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !IsCanonical(out) {
			t.Fatalf("not canonical: %s", out)
		}
		v2, err := Parse(out, ParseOptions{MaxDepth: 1000})
		if err != nil {
			t.Fatal(err)
		}
		out2, _ := Encode(v2)
		if !bytes.Equal(out, out2) {
			t.Fatalf("unstable: %s vs %s", out, out2)
		}
	})
}

// FuzzCanonicalNumber checks that the canonical form denotes exactly the
// same rational value and is a fixed point.
func FuzzCanonicalNumber(f *testing.F) {
	for _, s := range []string{"0", "-0.0", "1.50", "1e21", "1.5e-7", "123456789012345678901234567890", "0.000001", "9e-7"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := CanonicalNumber([]byte(s))
		if err != nil {
			return
		}
		c2, err := CanonicalNumber([]byte(c))
		if err != nil || c2 != c {
			t.Fatalf("%q -> %q -> %q (%v)", s, c, c2, err)
		}
		if len(s) > 200 {
			return
		}
		// Compare exact values when the exponent is small enough for big.Rat.
		if i := strings.IndexAny(s, "eE"); i >= 0 && len(s)-i > 5 {
			return
		}
		a, ok1 := new(big.Rat).SetString(s)
		b, ok2 := new(big.Rat).SetString(c)
		if !ok1 || !ok2 || a.Cmp(b) != 0 {
			t.Fatalf("%q -> %q changes value", s, c)
		}
	})
}
