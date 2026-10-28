package core

import "testing"

func TestDeclaredForMergesOlderHostPatterns(t *testing.T) {
	decl := map[string]*declaredHost{
		"payments-ext": {service: "payments-ext", host: "127.0.0.1:9101"},
		"weather-ext":  {service: "weather-ext", host: "127.0.0.1:9102"},
		"carrier":      {service: "carrier", host: "api.carrier.example"},
	}
	for pattern, want := range map[string]string{
		"ip:private:9101":         "payments-ext",
		"ip:private:9102":         "weather-ext",
		"ip:public:9101":          "",
		"ip:private:9999":         "",
		"{*}.carrier.example":     "carrier",
		"api.carrier.example:443": "",
	} {
		if got := declaredFor(pattern, decl); got != want {
			t.Errorf("%s: %q, want %q", pattern, got, want)
		}
	}
}
