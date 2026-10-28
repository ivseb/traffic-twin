package fleet

import (
	"strings"
	"testing"
)

func TestK8sInjectTokenEnrollsAnySDKLanguage(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()

	// A pod-template token is shared by every replica: group tokens only.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "k8s-inject", "group": "shop", "token_type": "one_time"}), 422)

	var nt NewToken
	e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "k8s-inject", "group": "shop", "token_type": "group"}), 201).json(t, &nt)
	var secret, annotation string
	for _, s := range nt.Snippets {
		switch {
		case strings.Contains(s.Text, "create secret generic tt-enroll"):
			secret = s.Text
		case strings.Contains(s.Text, "traffic-twin.io/inject"):
			annotation = s.Text
		}
	}
	// The Secret has the keys the injector reads (url, token) and the
	// annotation names that Secret; one token serves every language.
	if !strings.Contains(secret, "--from-literal=url="+e.fleet.publicURL) || !strings.Contains(secret, "--from-literal=token="+nt.Token) {
		t.Fatalf("secret snippet: %q", secret)
	}
	if !strings.Contains(annotation, "traffic-twin.io/enroll-secret: tt-enroll") || !strings.Contains(annotation, "node | python | java | dotnet | go | php") {
		t.Fatalf("annotation snippet: %q", annotation)
	}
	for _, s := range nt.Snippets {
		if strings.Contains(s.Text, "enroll-token-secret") || strings.Contains(s.Text, "enroll-url") {
			t.Errorf("annotation the injector does not read: %q", s.Text)
		}
	}

	// Any SDK language enrolls with it, many times; other kinds do not.
	for _, kind := range []string{"sdk-node", "sdk-python", "sdk-java", "sdk-dotnet", "sdk-go", "sdk-php"} {
		r, err := e.enroll(nt.Token, map[string]any{"source": srcInfo(kind, "shop-api")})
		if err != nil || r.code != 201 {
			t.Fatalf("%s: %v %d %s", kind, err, r.code, r.body)
		}
	}
	for _, kind := range []string{"egress", "obi", "import-har", "k8s-inject"} {
		r, _ := e.enroll(nt.Token, map[string]any{"source": srcInfo(kind, "shop-api")})
		if r.code != 422 {
			t.Errorf("%s enrolled with a k8s-inject token: %d %s", kind, r.code, r.body)
		}
	}

	// An SDK token still enrolls only its own language, and says so in its snippets.
	node := e.newToken(TokenGroup, "sdk-node")
	if r, _ := e.enroll(node.Token, map[string]any{"source": srcInfo("sdk-python", "shop-api")}); r.code != 422 || r.errCode() != "kind_mismatch" {
		t.Fatalf("sdk-node token enrolled a Python source: %d %s", r.code, r.body)
	}
	if !strings.Contains(strings.Join(snippetTexts(node.Snippets), "\n"), "traffic-twin.io/enroll-secret: tt-enroll") {
		t.Errorf("SDK snippets must use the annotations the injector reads: %+v", node.Snippets)
	}

	var list []TokenInfo
	e.must(e.as("olivia", "GET", "/api/v1/fleet/enrollment-tokens", nil), 200).json(t, &list)
	found := false
	for _, ti := range list {
		found = found || (ti.TokenID == nt.TokenID && ti.Kind == "k8s-inject" && ti.TokenType == TokenGroup)
	}
	if !found {
		t.Errorf("k8s-inject token not listed: %+v", list)
	}
}

func snippetTexts(ss []Snippet) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Text
	}
	return out
}
