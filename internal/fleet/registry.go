package fleet

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

// IntakeSources returns Fleet as an intake.SourceRegistry. A source under
// the kill switch (global, group or source) is reported as revoked, so the
// intake rejects its events while the switch is on (admin-api setKillSwitch:
// "intake also starts rejecting").
func (f *Fleet) IntakeSources() intake.SourceRegistry { return intakeSources{f} }

type intakeSources struct{ f *Fleet }

func (s intakeSources) LookupSource(id string) (intake.SourceInfo, bool) {
	v, ok := s.f.Source(id)
	if !ok {
		return intake.SourceInfo{}, false
	}
	return intake.SourceInfo{ID: v.ID, Group: v.Group, ServiceName: v.ServiceName, AllowedServices: v.AllowedServices, Revoked: v.Revoked || v.Killed}, true
}

// IntakePolicies returns Fleet as an intake.PolicyRegistry: only versions
// signed by keyguard are returned (every signed version is kept, events
// produced under an older one can still arrive). Parsed policies are
// cached; signed bodies are immutable.
func (f *Fleet) IntakePolicies() intake.PolicyRegistry {
	return &intakePolicies{f: f, cache: map[string]*intake.Policy{}}
}

type intakePolicies struct {
	f     *Fleet
	mu    sync.RWMutex
	cache map[string]*intake.Policy
}

func (l *intakePolicies) LookupPolicy(hash string) (*intake.Policy, bool) {
	l.mu.RLock()
	p, ok := l.cache[hash]
	l.mu.RUnlock()
	if ok {
		return p, true
	}
	body, ok := l.f.SignedPolicyBody(hash)
	if !ok {
		return nil, false
	}
	p, err := intake.ParsePolicy(body)
	if err != nil || p.Hash != hash {
		l.f.log.Error("fleet: signed policy cannot be parsed by the intake", "hash", hash, "err", err)
		return nil, false
	}
	l.mu.Lock()
	l.cache[hash] = p
	l.mu.Unlock()
	return p, true
}

// IntakeEventCounter adapts the intake's per-source counters to
// EventCounter (onboarding step "first events").
func IntakeEventCounter(in *intake.Intake) EventCounter { return intakeCounter{in} }

type intakeCounter struct{ in *intake.Intake }

func (c intakeCounter) AcceptedEvents(id string) uint64 { return c.in.SourceStats(id).Accepted }

func (c intakeCounter) DoubleCaptured(id string) bool { return c.in.DoubleCaptured(id) }

func (c intakeCounter) RecentRejections(id string, window time.Duration) []Rejection {
	var out []Rejection
	for _, r := range c.in.RecentRejections(id, window) {
		out = append(out, Rejection{Reason: r.Reason, Count: r.Count, First: r.First, Last: r.Last})
	}
	return out
}

// ShapeAt returns the drop shape found at a discovery path of an event
// ("" when the leaf is not a drop shape or cannot be found).
func ShapeAt(ev *event.Event, path string) string {
	side, rest, _ := strings.Cut(path, ".")
	var body *event.Value
	var named map[string]event.Multi
	switch side {
	case "req":
		body = ev.Req.Body
		named = map[string]event.Multi{"query": ev.Req.Query, "headers": ev.Req.Headers, "cookies": ev.Req.Cookies}
	case "resp":
		if ev.Resp == nil {
			return ""
		}
		body = ev.Resp.Body
		named = map[string]event.Multi{"headers": ev.Resp.Headers, "cookies": ev.Resp.Cookies}
	default:
		return ""
	}
	part, name, _ := strings.Cut(rest, ".")
	switch {
	case part == "path" && side == "req":
		segs := strings.Split(strings.TrimPrefix(ev.Req.Path, "/"), "/")
		i, err := strconv.Atoi(name)
		if err != nil || i < 0 || i >= len(segs) {
			return ""
		}
		return dropShape(strings.TrimSuffix(strings.TrimPrefix(segs[i], "{"), "}"))
	case strings.HasPrefix(rest, "body"):
		if body == nil {
			return ""
		}
		return dropShape(walkBody(*body, strings.TrimPrefix(rest, "body")))
	}
	if m, ok := named[part]; ok {
		if vs, ok := m.Get(name); ok && len(vs) > 0 {
			return dropShape(vs[0])
		}
	}
	return ""
}

func dropShape(s string) string {
	if strings.HasPrefix(s, "drop:") {
		return s
	}
	return ""
}

// walkBody follows ".name", ".*" (collapsed keys, "{*}") and "[*]" steps
// and returns the first string leaf.
func walkBody(v event.Value, p string) string {
	for p != "" {
		switch {
		case strings.HasPrefix(p, "[*]"):
			if v.Kind != event.Array || len(v.A) == 0 {
				return ""
			}
			v, p = v.A[0], p[3:]
		case strings.HasPrefix(p, "."):
			p = p[1:]
			end := strings.IndexAny(p, ".[")
			if end < 0 {
				end = len(p)
			}
			name := p[:end]
			p = p[end:]
			if name == "*" {
				name = "{*}"
			}
			if v.Kind != event.Object {
				return ""
			}
			found := false
			for _, m := range v.O {
				if m.K == name {
					v, found = m.V, true
					break
				}
			}
			if !found {
				return ""
			}
			if name == "{*}" && v.Kind == event.Array && len(v.A) > 0 {
				v = v.A[0]
			}
		default:
			return ""
		}
	}
	if v.Kind == event.String {
		return v.S
	}
	return ""
}
