package packwriter

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/world"
)

// Security review r4: at_least in a pack is the pack's size class (k_min or
// a power of ten), never an exact count, whatever k_min the contract used;
// a class below the pack's k_min drops the combination. Invented values.
func TestFilterContractRewritesSizeClasses(t *testing.T) {
	doc := `{"type":"object","properties":{"category":{"type":"string"},"macro":{"type":"string"}},
	"x-tt-dependencies":[
	 {"fields":["category","macro"],"combinations":[
	   {"at_least":25,"values":["Forni","Grandi elettrodomestici"]},
	   {"at_least":37,"values":["Frigoriferi","Grandi elettrodomestici"]},
	   {"at_least":1000,"values":["Smartphone","Telefonia"]},
	   {"at_least":10,"values":["Tablet","Telefonia"]}]}]}`
	var v map[string]any
	if err := world.DecodeGeneric([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	declared := map[string]int64{"Forni": 50, "Frigoriferi": 50, "Smartphone": 50, "Tablet": 50, "Grandi elettrodomestici": 50, "Telefonia": 50}
	filterContract(v, declared, nil, 20, false)
	b, err := world.CanonicalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`{"at_least":20,"values":["Forni"`, `{"at_least":20,"values":["Frigoriferi"`, `{"at_least":1000,"values":["Smartphone"`, `"partial":true`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	for _, bad := range []string{"Tablet", `"at_least":25`, `"at_least":37`, `"at_least":10,`} {
		if strings.Contains(s, bad) {
			t.Errorf("%s left in %s", bad, s)
		}
	}
}
