package fleet

import (
	"os"
	"slices"
	"strings"
	"testing"
)

var snippetKinds = []string{"sdk-node", "sdk-python", "sdk-java", "sdk-dotnet", "sdk-go", "sdk-php", "egress", "obi", "import-har", "import-otlp", KindK8sInject}

func TestSnippetsCarryTheHMACKeyFile(t *testing.T) {
	for _, kind := range []string{"sdk-node", "sdk-python", "sdk-java", "sdk-dotnet", "sdk-go", "sdk-php", "egress", "obi"} {
		all := strings.Join(snippetTexts(Snippets(kind, "https://tt.example:4318", "tte_x", "bookings-api")), "\n")
		if !strings.Contains(all, "TT_HMAC_KEY_FILE") || !strings.Contains(all, commentKey1) {
			t.Errorf("%s: no TT_HMAC_KEY_FILE with its explanation:\n%s", kind, all)
		}
	}
	node := Snippets("sdk-node", "https://tt.example:4318", "tte_x", "bookings-api")
	if !strings.Contains(node[0].Title, "20+") || !strings.Contains(node[0].Title, "24+") || !strings.Contains(node[0].Text, "traffic-twin-sdk-<version>.tgz") {
		t.Errorf("node snippet: %+v", node[0])
	}
	k8s := strings.Join(snippetTexts(Snippets(KindK8sInject, "https://tt.example:4318", "tte_x", "bookings-api")), "\n")
	if !strings.Contains(k8s, "create secret generic tt-hmac --from-file=hmac-key=") || !strings.Contains(k8s, "traffic-twin.io/hmac-secret: tt-hmac") {
		t.Errorf("k8s snippets without the HMAC secret:\n%s", k8s)
	}
}

// Every comment of every snippet has an id and a translation in the console.
func TestSnippetCommentsHaveATranslation(t *testing.T) {
	ui, err := os.ReadFile("../../ui/src/lib/api/rest/snippets.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range SnippetComments {
		if !strings.Contains(string(ui), "'"+c+"'") && !strings.Contains(string(ui), `"`+c+`"`) {
			t.Errorf("comment without a console translation: %q", c)
		}
	}
	for _, kind := range snippetKinds {
		for _, s := range Snippets(kind, "https://tt.example:4318", "tte_x", "svc") {
			if s.ID == "" || !strings.Contains(string(ui), "'"+s.ID+"'") {
				t.Errorf("%s: snippet %q has no id known to the console", kind, s.Title)
			}
			for _, line := range strings.Split(s.Text, "\n") {
				i := strings.Index(line, "# ")
				if i < 0 || s.Language == "text" {
					continue
				}
				if c := line[i:]; !slices.Contains(SnippetComments, c) && !strings.HasPrefix(c, "#   ") {
					t.Errorf("%s: untranslatable comment %q", kind, c)
				}
			}
		}
	}
}
