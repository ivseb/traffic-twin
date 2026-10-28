package packwriter

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/gate"
)

func apiError(t *testing.T, err error) *gate.APIError {
	t.Helper()
	var ae *gate.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("not an API error: %v", err)
	}
	return ae
}

// A pack without a service its rules use is refused with the service and the rules by name, so
// the console can say "include the service X or leave out the rule Y" instead of a generic error.
func TestMissingServiceNamesTheServiceAndTheRules(t *testing.T) {
	in := demoWorldInput(t, 1, 10)
	// Only the contract of shop-api: the rules also use shipping-ext (the order relates to the shipment).
	in.Contracts = in.Contracts[1:]
	_, err := selectContracts(in, nil, nil)
	ae := apiError(t, err)
	if ae.Status != http.StatusUnprocessableEntity || ae.Code != "missing_service" || len(ae.Details) != 1 {
		t.Fatalf("error: %+v", ae)
	}
	d := ae.Details[0]
	rules, _ := d["rules"].([]string)
	if d["service"] != "shipping-ext" || !slices.Contains(rules, "r-0007") || !slices.Contains(rules, "r-0008") {
		t.Fatalf("details: %+v", d)
	}
	for _, want := range []string{"shipping-ext", "r-0007", "include the service"} {
		if !strings.Contains(ae.Message, want) {
			t.Errorf("message lacks %q: %s", want, ae.Message)
		}
	}

	// All the services in the pack: fine.
	in = demoWorldInput(t, 1, 10)
	if cs, err := selectContracts(in, nil, nil); err != nil || len(cs) != 2 {
		t.Fatalf("complete pack: %v %d", err, len(cs))
	}

	// A requested service without a contract is named too.
	_, err = selectContracts(in, []string{"shop-api", "pizza-payments"}, nil)
	ae = apiError(t, err)
	if ae.Code != "unknown_service" || len(ae.Details) != 1 || ae.Details[0]["service"] != "pizza-payments" || !strings.Contains(ae.Message, "pizza-payments") {
		t.Fatalf("unknown service: %+v", ae)
	}
}
