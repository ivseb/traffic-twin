package fleet

import (
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// RT4-YAML (red team round 4): what a reviewer reads in the author YAML
// and the body keyguard signs must not disagree. YAML features that make a
// document mean something else than it shows (duplicate keys, anchors,
// aliases, merge keys, explicit tags such as !!binary) are refused; names
// with look-alike characters never compile.

const yamlHead = `format: tt.policy/v1
policy_id: p-shop
default: drop
hmac: {kid: k1, epoch: "2026-10"}
sampling: {rate: 0.1}
`

func compileYAML(doc string) error {
	a, err := ParseAuthor([]byte(doc))
	if err != nil {
		return err
	}
	_, _, err = policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), Groups: []string{"shop"}})
	return err
}

func TestR4AuthorYAMLAmbiguitiesRefused(t *testing.T) {
	// The base document compiles.
	ok := yamlHead + "services:\n  shop-api:\n    match: {inbound: true}\n    response:\n      $.status: drop\n"
	if err := compileYAML(ok); err != nil {
		t.Fatalf("base document: %v", err)
	}
	for name, doc := range map[string]string{
		"duplicate rule key": yamlHead + "services:\n  shop-api:\n    match: {inbound: true}\n    response:\n      $.email: drop\n      $.email: keep\n",
		"duplicate top key":  yamlHead + "default: drop\n",
		"merge key override": yamlHead + "global:\n  request: &r\n    $.email: drop\n  response:\n    <<: *r\n    $.email: keep\n",
		"alias of a rule set": yamlHead + "global:\n  request: &r\n    $.status: keep\n" +
			"services:\n  shop-api:\n    match: {inbound: true}\n    response: *r\n",
		"anchor on a scalar":   yamlHead + "global:\n  response:\n    $.status: &a drop\n",
		"binary tag on action": yamlHead + "global:\n  response:\n    $.status: !!binary a2VlcA==\n",
		"str tag on a number":  yamlHead + "limits: {keep_max_bytes: !!str 64}\n",
		"custom tag":           yamlHead + "global:\n  response:\n    $.status: !keep drop\n",
		"two documents":        yamlHead + "---\n" + yamlHead,
		"cyrillic e in a path": yamlHead + "global:\n  response:\n    $.еmail: keep\n",
		"cyrillic in a field":  strings.Replace(yamlHead, "default:", "dеfault:", 1),
		"zero width in a name": yamlHead + "global:\n  response:\n    $.em​ail: keep\n",
		"fullwidth service":    yamlHead + "services:\n  ｓhop-api:\n    match: {inbound: true}\n",
		"lookalike header":     yamlHead + "global:\n  request:\n    headers:\n      x-user-іd: keep\n",
		"yaml 1.1 boolean":     yamlHead + "sampling: {rate: 0.1, trust_baggage: yes}\n",
	} {
		if strings.HasPrefix(name, "duplicate top") || name == "yaml 1.1 boolean" {
			doc = strings.Replace(doc, "sampling: {rate: 0.1}\n", "", strings.Count(doc, "sampling:")-1)
		}
		if err := compileYAML(doc); err == nil {
			t.Errorf("%s: the document must be refused:\n%s", name, doc)
		}
	}
}
