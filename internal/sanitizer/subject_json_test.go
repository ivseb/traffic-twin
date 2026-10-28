package sanitizer

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestSubjectJSONPath: identity.subject.json_path (spec v1.18, C14) reads a
// member of a header whose value is a JSON object or base64 of one.
func TestSubjectJSONPath(t *testing.T) {
	a := func(subject string) string { return author(`"identity":{"subject":` + subject + `}`) }
	ctx := `{"from":"header","name":"x-user-context","json_path":"user.id"}`
	std := base64.StdEncoding.EncodeToString([]byte(`{"user":{"id":"u-std"},"pad":"??>>"}`))
	cases := []struct {
		subject string
		hdrs    []Header
		want    string
	}{
		{ctx, hdr("X-User-Context", `{"user":{"id":"u-1","name":"n"}}`), "u-1"},
		{ctx, hdr("X-User-Context", `  {"user":{"id":42.50}}  `), "42.5"},
		{ctx, hdr("X-User-Context", `{"user":{"id":"a"},"user":{"id":"last"}}`), "last"},
		{ctx, hdr("X-User-Context", b64url(`{"user":{"id":"u-b64"}}`)), "u-b64"},
		{ctx, hdr("X-User-Context", strings.TrimRight(b64url(`{"user":{"id":"u-raw"}}`), "=")), "u-raw"},
		{ctx, hdr("X-User-Context", std), "u-std"},
		{`{"from":"header","name":"x-auth-ctx","json_path":"sub"}`, hdr("X-Auth-Ctx", `{"sub":"s-9"}`), "s-9"},
		// a dot is a separator, never part of a name
		{ctx, hdr("X-User-Context", `{"user.id":"flat"}`), ""},
		// negatives
		{ctx, hdr("X-User-Context", `{"user":{"id":""}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":true}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":null}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":["a"]}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":{"x":1}}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":["id"]}`), ""},
		{ctx, hdr("X-User-Context", `{"user":"id"}`), ""},
		{ctx, hdr("X-User-Context", `[{"user":{"id":"x"}}]`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":"x"}} trailing`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":"x"}`), ""},
		{ctx, hdr("X-User-Context", "Bearer "+b64url(`{"user":{"id":"x"}}`)), ""},
		{ctx, hdr("X-User-Context", "not json at all"), ""},
		{ctx, hdr("X-User-Context", "\xef\xbb\xbf{\"user\":{\"id\":\"bom\"}}"), ""},
		{ctx, hdr("X-User-Context", b64url("\xef\xbb\xbf{\"user\":{\"id\":\"bom\"}}")), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":"`+strings.Repeat("u", 8200)+`"}}`), ""},
		{ctx, hdr("X-User-Context", `{"user":{"id":1e99999}}`), ""},
		{ctx, hdr("X-User-Context", "   "), ""},
		{ctx, hdr("X-Other", `{"user":{"id":"x"}}`), ""},
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
			t.Errorf("%v: subject %q want token of %q", c.hdrs, out.Subject, c.want)
		}
	}
}

func TestDecodeB64Any(t *testing.T) {
	for _, bad := range []string{"", "=", "ab+_", "a b", "abc==="} {
		if _, ok := decodeB64Any([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if out, ok := decodeB64Any([]byte("e30=")); !ok || string(out) != "{}" {
		t.Errorf("padded std: %q %v", out, ok)
	}
}
