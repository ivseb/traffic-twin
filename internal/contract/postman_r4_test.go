package contract_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

// Security review r4: ?base_url= of the Postman export only takes a plain
// http(s) URL. A crafted link to the export cannot plant a javascript:,
// file: or credential-carrying URL in a collection a colleague imports.
func TestPostmanBaseURLValidation(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 700, contracttest.Variant{})
	h.Wait()
	now := day1.Add(48 * time.Hour)
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	op := asRoles(contract.Handler(contract.APIDeps{Engine: eng}), auth.RoleOperator)
	for _, ok := range []string{"http://mock.ci:8480/__svc/carrier", "https://tt-mock-shop.apps.cluster.example/__svc/shipping-ext",
		"http://localhost:8480", "http://[::1]:8480/__svc/x"} {
		if rec := get(t, op, "GET", "/api/v1/contracts/shipping-ext/postman?base_url="+url.QueryEscape(ok)); rec.Code != 200 {
			t.Errorf("base_url %q: %d %s", ok, rec.Code, rec.Body)
		}
	}
	for _, bad := range []string{"javascript:alert(1)", "file:///etc/passwd", "https://user:pw@mock.example", "https://mock.example/?token=x",
		"https://mock.example/#x", "//mock.example", "mock.example:8480", "https://", "http://mock.example/a b", "http://mock.example/é",
		`a"b`, "http://mock.example/<x>", "http://mock.example/a\nb", "https://" + strings.Repeat("a", 200) + ".example"} {
		if rec := get(t, op, "GET", "/api/v1/contracts/shipping-ext/postman?base_url="+url.QueryEscape(bad)); rec.Code != 422 {
			t.Errorf("base_url %q accepted: %d", bad, rec.Code)
		}
	}
}
