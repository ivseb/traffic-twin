package pack

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	identRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	opRE        = regexp.MustCompile(`^[A-Z]{1,16} /[!-~]*$`)
	durationRE  = regexp.MustCompile(`^([0-9]{1,6})(s|m|h|d)$`)
	fieldPathRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
	idFieldRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	idPrefixRE  = regexp.MustCompile(`^[A-Z]{2,5}-SYN-$`)
	idDomainRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	bindNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	ttPathRE    = regexp.MustCompile(`^\$(\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\])*$`)
	refNameRE   = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
	scheduleRE  = regexp.MustCompile(`^[0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+$`)
	worldIDRE   = regexp.MustCompile(`^[A-Z]{2,5}-SYN-[0-9]{4,}$`)
	// entityIDRE: a synthetic id or an id of an id format (checkWorld
	// verifies the format of the entity's domain).
	entityIDRE   = regexp.MustCompile(`^[A-Za-z0-9._:/+=#@ -]{1,256}$`)
	archetypeRE  = regexp.MustCompile(`^arch-[0-9A-Za-z-]{1,32}$`)
	worldTimeRE  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	exampleKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// ParseDuration parses a rules duration "^[0-9]{1,6}(s|m|h|d)$".
func ParseDuration(s string) (time.Duration, error) {
	m := durationRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

func parseContract(data []byte) (map[string]any, error) {
	var doc map[string]any
	if err := decodeStrictAny(data, &doc); err != nil {
		return nil, err
	}
	v, _ := doc["openapi"].(string)
	if !strings.HasPrefix(v, "3.1") {
		return nil, errors.New("openapi must be 3.1.x")
	}
	if _, ok := doc["paths"].(map[string]any); !ok {
		return nil, errors.New("paths is missing")
	}
	return doc, nil
}

// ---- faults and gate report ----

func parseFaults(data []byte, services map[string]bool) (*Faults, error) {
	var f Faults
	if err := decodeStrict(data, &f); err != nil {
		return nil, err
	}
	if f.Format != "tt.faults/v1" {
		return nil, errors.New("format must be tt.faults/v1")
	}
	for _, op := range f.Ops {
		if !services[op.Service] {
			return nil, fmt.Errorf("unknown service %q", op.Service)
		}
		if !opRE.MatchString(op.Op) {
			return nil, fmt.Errorf("malformed op %q", op.Op)
		}
		var sum float64
		for _, s := range op.Statuses {
			if s.Status < 100 || s.Status > 599 || s.P < 0 || s.P > 1 || (s.Example != "" && !exampleKeyRE.MatchString(s.Example)) {
				return nil, fmt.Errorf("malformed status entry for %s", op.Op)
			}
			sum += s.P
		}
		for _, n := range op.NetErrors {
			switch n.Kind {
			case "timeout", "reset", "refused", "dns", "tls", "other":
			default:
				return nil, fmt.Errorf("unknown net error kind %q", n.Kind)
			}
			if n.P < 0 || n.P > 1 {
				return nil, fmt.Errorf("malformed net error entry for %s", op.Op)
			}
			sum += n.P
		}
		if sum > 1+1e-9 {
			return nil, fmt.Errorf("fault probabilities of %s exceed 1", op.Op)
		}
		if l := op.Latency; l != nil && l.Lognormal != nil && (l.Lognormal.Median <= 0 || l.Lognormal.Sigma < 0) {
			return nil, fmt.Errorf("malformed lognormal for %s", op.Op)
		}
	}
	return &f, nil
}

func parseGateReport(data []byte, m *Manifest) (*GateReport, error) {
	var g GateReport
	if err := decodeStrict(data, &g); err != nil {
		return nil, err
	}
	if g.Format != "tt.gate-report/v1" {
		return nil, errors.New("format must be tt.gate-report/v1")
	}
	if g.PackID != m.PackID {
		return nil, errors.New("gate report belongs to another pack")
	}
	if g.Verdict != "pass" {
		return nil, errors.New("gate verdict is not pass")
	}
	for _, c := range g.Checks {
		if c.Status != "pass" && !(c.Status == "warn" && c.ID == "rules-approved") {
			return nil, fmt.Errorf("gate check %s did not pass", c.ID)
		}
	}
	return &g, nil
}
