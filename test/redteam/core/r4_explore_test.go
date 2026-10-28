package core_rt

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// Security review r4: the world explorer (?q=) and the Postman export
// (?base_url=) on the composed tt-core. Roles as the OpenAPI says, input
// bounded, nothing of the query reflected, and no URL scheme other than
// http(s) planted in a collection.
func TestR4WorldExplorerAndPostmanExport(t *testing.T) {
	e := getEnv(t)
	olga := e.users["olga"]
	cust := "/api/v1/worlds/" + e.worldID + "/customers"

	for _, who := range []string{"eve", "pia", "nora"} {
		if code, _ := e.users[who].do("GET", cust, nil); code != 403 {
			t.Errorf("%s reads the world explorer: %d", who, code)
		}
		if code, _ := e.users[who].do("GET", "/api/v1/contracts/shop-api/postman", nil); code != 403 {
			t.Errorf("%s downloads a Postman collection: %d", who, code)
		}
	}
	for _, q := range []string{strings.Repeat("a", 101), "x"} {
		code, body := olga.do("GET", cust+"?q="+url.QueryEscape(q)+"&limit=100000&offset=0", nil)
		if len(q) > 100 {
			if code != 400 {
				t.Errorf("q of %d bytes: %d", len(q), code)
			}
			continue
		}
		var page struct {
			Limit int `json:"limit"`
		}
		if code != 200 || json.Unmarshal(body, &page) != nil || page.Limit != 200 {
			t.Errorf("limit not capped: %d %s", code, body)
		}
	}
	for _, bad := range []string{"-1", "1e3", "99999999999999999999999"} {
		if code, _ := olga.do("GET", cust+"?offset="+bad, nil); code != 400 {
			t.Errorf("offset %s: %d", bad, code)
		}
	}
	probe := `<img src=x onerror=alert(1)>`
	if code, body := olga.do("GET", cust+"?q="+url.QueryEscape(probe), nil); code != 200 || strings.Contains(string(body), "onerror") {
		t.Errorf("q reflected or refused: %d %s", code, body)
	}

	for _, bad := range []string{"javascript:alert(1)", "https://user:pw@mock.example", "file:///etc/passwd"} {
		if code, _ := olga.do("GET", "/api/v1/contracts/shop-api/postman?base_url="+url.QueryEscape(bad), nil); code != 422 {
			t.Errorf("base_url %q: %d", bad, code)
		}
	}
	if code, body := olga.do("GET", "/api/v1/contracts/shop-api/postman?base_url="+url.QueryEscape("http://tt-mock-shop.mocks.svc.cluster.local:8480/__svc/shop-api"), nil); code != 200 ||
		!strings.Contains(string(body), "tt-mock-shop.mocks.svc.cluster.local") {
		t.Errorf("mock base_url: %d", code)
	}
}
