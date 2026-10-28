package mock

import (
	"fmt"
	"math"
	"regexp"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// FaultRule is one injection rule of a custom fault configuration.
type FaultRule struct {
	Service   string  `json:"service"`
	Op        string  `json:"op"`
	Status    int     `json:"status,omitempty"`
	NetError  string  `json:"net_error,omitempty"`
	LatencyMs *int    `json:"latency_ms,omitempty"`
	P         float64 `json:"p"`
	Times     *int    `json:"times,omitempty"`
	// Example names an example of the contract for the status; Body is an
	// error body typed by a person, which wins (docs/spec/mock.md 4.1).
	Example string `json:"example,omitempty"`
	Body    any    `json:"body,omitempty"`
}

// FaultsConfig is the fault configuration of a session.
type FaultsConfig struct {
	Mode  string      `json:"mode"`
	Rules []FaultRule `json:"rules,omitempty"`
}

func cloneFaults(f FaultsConfig) FaultsConfig {
	out := FaultsConfig{Mode: f.Mode}
	for _, r := range f.Rules {
		c := r
		if r.LatencyMs != nil {
			v := *r.LatencyMs
			c.LatencyMs = &v
		}
		if r.Times != nil {
			v := *r.Times
			c.Times = &v
		}
		out.Rules = append(out.Rules, c)
	}
	return out
}

var faultOpRE = regexp.MustCompile(`^[A-Z]{1,16} /[!-~]*$`)

const maxLatencyMs = 60000

// fieldError is a validation error with the JSON Pointer of the offending
// field in the request body.
type fieldError struct {
	ptr string
	msg string
}

func (e *fieldError) Error() string { return e.msg }

// validateFaults checks a configuration against the loaded pack. Pointers are
// relative to the Faults object ("/rules/0/p").
func (m *model) validateFaults(f FaultsConfig) error {
	switch f.Mode {
	case "observed", "off", "custom":
	default:
		return &fieldError{"/mode", "mode must be observed, off or custom"}
	}
	if len(f.Rules) > 256 {
		return &fieldError{"/rules", "too many rules"}
	}
	for i, r := range f.Rules {
		bad := func(field, msg string) error {
			return &fieldError{fmt.Sprintf("/rules/%d/%s", i, field), msg}
		}
		var svcs []*service
		if r.Service == "*" {
			svcs = m.services
		} else if s := m.byName[r.Service]; s != nil {
			svcs = []*service{s}
		} else if s := m.byAlias(r.Service); s != nil {
			svcs = []*service{s}
		} else {
			return bad("service", "unknown service")
		}
		if r.Op != "*" {
			if !faultOpRE.MatchString(r.Op) {
				return bad("op", "malformed op")
			}
			found := false
			for _, s := range svcs {
				if s.c.byKey[r.Op] != nil {
					found = true
				}
			}
			if !found {
				return bad("op", "operation is not in the contract")
			}
		}
		if math.IsNaN(r.P) || r.P < 0 || r.P > 1 {
			return bad("p", "p must be within 0..1")
		}
		if r.Status != 0 && (r.Status < 100 || r.Status > 599) {
			return bad("status", "status out of range")
		}
		if r.Status != 0 && r.NetError != "" {
			return bad("net_error", "status and net_error are mutually exclusive")
		}
		switch r.NetError {
		case "", "timeout", "reset", "refused", "dns", "tls", "other":
		default:
			return bad("net_error", "unknown net_error")
		}
		if r.LatencyMs != nil && (*r.LatencyMs < 0 || *r.LatencyMs > maxLatencyMs) {
			return bad("latency_ms", "latency_ms out of range")
		}
		if r.Status == 0 && r.NetError == "" && r.LatencyMs == nil {
			return bad("", "needs status, net_error or latency_ms")
		}
		if r.Times != nil && *r.Times < 1 {
			return bad("times", "times must be >= 1")
		}
		if (r.Example != "" || r.Body != nil) && r.Status == 0 {
			return bad("status", "example and body need a status")
		}
		if r.Example != "" {
			found := false
			for _, s := range svcs {
				for _, op := range s.c.ops {
					if (r.Op == "*" || op.key == r.Op) && op.responses[r.Status].hasExample(r.Example) {
						found = true
					}
				}
			}
			if !found {
				return bad("example", "no example with this name for the status")
			}
		}
		if r.Body != nil {
			if err := pack.ValidateErrorBody(r.Body); err != nil {
				return bad("body", err.Error())
			}
		}
	}
	return nil
}

// faultDecision is what to do with one request before serving it.
type faultDecision struct {
	latencyMs int
	status    int
	example   string
	netErr    string
	// body is an error body typed by a person (fault rule or respond
	// effect): it wins over the example.
	body any
	// rule is set when a response effect of that rule decided the status.
	rule string
}

func (d faultDecision) kind() string {
	switch {
	case d.netErr != "":
		return "net_error"
	case d.status != 0:
		return "status"
	case d.latencyMs > 0:
		return "latency"
	}
	return ""
}

// decideFault consumes the session's fault stream. A request that matches an
// observed operation always consumes exactly two draws, so the stream does not
// depend on which faults fired.
func (s *session) decideFault(svc *service, opKey string) faultDecision {
	d := s.decideFaultRaw(svc, opKey)
	// Response effects of approved rules (rules v1.4) answer before the
	// observed faults; a fault forced by the test (custom mode) wins.
	if !(s.faults.Mode == "custom" && (d.status != 0 || d.netErr != "")) {
		if rd, rule, ok := s.ruleResponseFor(svc, opKey); ok {
			rd.latencyMs, rd.rule = d.latencyMs, rule
			d = rd
		}
	}
	switch d.netErr {
	case "timeout", "refused", "dns", "tls":
		d.latencyMs = 0 // no latency before these (docs/spec/mock.md section 4)
	}
	return d
}

func (s *session) decideFaultRaw(svc *service, opKey string) faultDecision {
	var d faultDecision
	switch s.faults.Mode {
	case "observed":
		fo := s.m.model.faults[svc.name+"\x00"+opKey]
		if fo == nil {
			return d
		}
		u := s.rngFault.Float64()
		z := s.rngFault.NormFloat64()
		if fo.Latency != nil {
			d.latencyMs = sampleLatency(fo.Latency.Lognormal, fo.Latency.P50, fo.Latency.P95, z)
		}
		cum := 0.0
		for _, st := range fo.Statuses {
			cum += st.P
			if u < cum {
				d.status, d.example = st.Status, st.Example
				return d
			}
		}
		for _, ne := range fo.NetErrors {
			cum += ne.P
			if u < cum {
				d.netErr = ne.Kind
				return d
			}
		}
	case "custom":
		for i := range s.faults.Rules {
			r := &s.faults.Rules[i]
			if (r.Service != "*" && r.Service != svc.name && (svc.alias == "" || r.Service != svc.alias)) || (r.Op != "*" && r.Op != opKey) {
				continue
			}
			if r.Times != nil && s.faultUsed[i] >= *r.Times {
				continue
			}
			if s.rngFault.Float64() >= r.P {
				continue
			}
			s.faultUsed[i]++
			if r.LatencyMs != nil {
				d.latencyMs += *r.LatencyMs
			}
			if r.Status != 0 {
				d.status, d.example, d.body = r.Status, r.Example, r.Body
				return d
			}
			if r.NetError != "" {
				d.netErr = r.NetError
				return d
			}
		}
	}
	return d
}

func sampleLatency(ln *struct {
	Median float64 `json:"median"`
	Sigma  float64 `json:"sigma"`
}, p50, p95 *int, z float64) int {
	var median, sigma float64
	switch {
	case ln != nil:
		median, sigma = ln.Median, ln.Sigma
	case p50 != nil && p95 != nil && *p50 > 0 && *p95 > *p50:
		median = float64(*p50)
		sigma = math.Log(float64(*p95)/float64(*p50)) / 1.6449
	case p50 != nil:
		median = float64(*p50)
	default:
		return 0
	}
	ms := median * math.Exp(sigma*z)
	if ms > maxLatencyMs {
		ms = maxLatencyMs
	}
	if ms < 0 || math.IsNaN(ms) {
		ms = 0
	}
	return int(math.Round(ms))
}

func (m *model) byAlias(name string) *service {
	for _, s := range m.services {
		if s.alias != "" && s.alias == name {
			return s
		}
	}
	return nil
}
