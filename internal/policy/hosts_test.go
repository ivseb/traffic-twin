package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func authorErr(s string) (*Author, error) {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	return AuthorFromGeneric(doc)
}

// Spec v1.5: hosts.discovery is written into the body only for off.
func TestCompileHosts(t *testing.T) {
	for _, c := range []struct {
		block, want string
		auto        bool
	}{
		{"", "", true},
		{`"hosts":{"discovery":"auto"},`, "", true},
		{`"hosts":{},`, "", true},
		{`"hosts":{"discovery":"off"},`, `"hosts":{"discovery":"off"}`, false},
	} {
		a := author(t, strings.Replace(shopAuthor, `"global":`, c.block+`"global":`, 1))
		body, p, err := Compile(a, meta(1, 1))
		if err != nil {
			t.Fatalf("%s: %v", c.block, err)
		}
		has := bytes.Contains(body, []byte(`"hosts":`))
		if (c.want == "") == has || (c.want != "" && !bytes.Contains(body, []byte(c.want))) || p.Hosts.Auto() != c.auto {
			t.Errorf("%s: body %s, auto %v", c.block, body, p.Hosts.Auto())
		}
		d, err := DecodeBody(body)
		if err != nil || d.Hosts.Auto() != c.auto {
			t.Errorf("%s: decode %v %+v", c.block, err, d)
		}
		again, err := EncodeBody(d)
		if err != nil || !bytes.Equal(again, body) {
			t.Errorf("%s: re-encoding differs", c.block)
		}
	}
	for _, bad := range []string{`"hosts":{"discovery":"on"},`, `"hosts":{"mode":"off"},`, `"hosts":"off",`} {
		gen := strings.Replace(shopAuthor, `"global":`, bad+`"global":`, 1)
		if a, err := authorErr(gen); err == nil {
			if _, _, err := Compile(a, meta(1, 1)); err == nil {
				t.Errorf("%s accepted", bad)
			}
		}
	}
	// A body with "auto" written out is accepted too; other values are not.
	a := author(t, shopAuthor)
	body, _, _ := Compile(a, meta(1, 1))
	withAuto := bytes.Replace(body, []byte(`"identity":`), []byte(`"hosts":{"discovery":"auto"},"identity":`), 1)
	if d, err := DecodeBody(withAuto); err != nil || !d.Hosts.Auto() {
		t.Errorf("explicit auto: %v", err)
	}
	for _, v := range []string{`{"discovery":"on"}`, `{}`, `{"discovery":"off","x":1}`} {
		b := bytes.Replace(body, []byte(`"identity":`), []byte(`"hosts":`+v+`,"identity":`), 1)
		if _, err := DecodeBody(b); err == nil {
			t.Errorf("hosts %s accepted", v)
		}
	}
}
