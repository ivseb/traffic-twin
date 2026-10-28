package mockreg

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Limits of what the registry keeps per mock (in memory: a restart of
// tt-core forgets it, the mocks report again within seconds).
const (
	maxCalls     = 500
	maxQueued    = 50
	commandTTL   = 10 * time.Minute
	forgetAfter  = 24 * time.Hour
	maxInstances = 500
	// maxInstancesPerToken: one token (often in CI, zone C) cannot fill
	// the registry and lock out the mocks of the other groups.
	maxInstancesPerToken = 50
	// maxResultBody bounds a command result kept by the registry (the mock
	// sends at most 64 KiB, mock.md 6.3).
	maxResultBody    = 64 << 10
	offlineIntervals = 4
)

// instance is one mock that reports to the console.
type instance struct {
	ID       string
	TokenID  string
	Group    string
	Instance string

	Version   string
	Status    string
	PackID    string
	PackError string
	PublicURL string
	Services  []mock.ServiceURL
	Sessions  []mock.SessionSummary
	StartedAt string
	FirstSeen time.Time
	LastSeen  time.Time
	revoked   bool

	calls      []CallView
	callSeq    int
	callsTotal int
	dropped    int

	queued  []mock.Command
	results map[string]*commandState
	// notify wakes the held report (long poll).
	notify chan struct{}
}

// wake signals the held report of the instance (g.mu held).
func (in *instance) wake() {
	select {
	case in.notify <- struct{}{}:
	default:
	}
}

// waker is the channel that wakes the held report of a mock.
func (g *Registry) waker(id string) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if in := g.instances[id]; in != nil {
		return in.notify
	}
	return nil
}

type commandState struct {
	at     time.Time
	cmd    mock.Command
	done   bool
	result *mock.CommandResult
}

// CallView is one call of a mock, numbered for ?since=.
type CallView struct {
	Seq int `json:"seq"`
	mock.Call
}

// ServiceView is a simulated service: its mock URL and, when the policy
// declares it, the real endpoint it replaces.
type ServiceView struct {
	Name     string `json:"name"`
	Alias    string `json:"alias,omitempty"`
	MockURL  string `json:"mock_url"`
	RealBase string `json:"real_base,omitempty"`
}

// MockView is a mock as listed by GET /api/v1/mocks.
type MockView struct {
	MockID    string                `json:"mock_id"`
	Group     string                `json:"group"`
	Instance  string                `json:"instance"`
	TokenID   string                `json:"token_id"`
	Managed   bool                  `json:"managed"`
	Online    bool                  `json:"online"`
	Status    string                `json:"status"`
	Version   string                `json:"version"`
	PackID    string                `json:"pack_id"`
	LatestID  string                `json:"latest_pack_id"`
	UpToDate  bool                  `json:"up_to_date"`
	PackError string                `json:"pack_error,omitempty"`
	PublicURL string                `json:"public_url"`
	Services  []ServiceView         `json:"services"`
	Sessions  []mock.SessionSummary `json:"sessions"`
	Calls     int                   `json:"calls_total"`
	Dropped   int                   `json:"dropped_calls"`
	StartedAt string                `json:"started_at"`
	LastSeen  time.Time             `json:"last_seen"`
}

var reMockID = regexp.MustCompile(`^mtk-[0-9a-f]{24}\.[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// online reports whether the mock reported recently.
func (g *Registry) online(in *instance, now time.Time) bool {
	return !in.revoked && now.Sub(in.LastSeen) <= offlineIntervals*g.o.ReportInterval+5*time.Second
}

// view renders an instance (g.mu held).
func (g *Registry) view(in *instance, now time.Time, managed bool, latest string) MockView {
	v := MockView{MockID: in.ID, Group: in.Group, Instance: in.Instance, TokenID: in.TokenID, Managed: managed, Online: g.online(in, now),
		Status: in.Status, Version: in.Version, PackID: in.PackID, LatestID: latest, PackError: in.PackError, PublicURL: in.PublicURL,
		Services: []ServiceView{}, Sessions: in.Sessions, Calls: in.callsTotal, Dropped: in.dropped, StartedAt: in.StartedAt, LastSeen: in.LastSeen}
	if in.revoked {
		v.Status = "revoked"
	}
	v.UpToDate = latest != "" && latest == in.PackID
	if v.Sessions == nil {
		v.Sessions = []mock.SessionSummary{}
	}
	var real map[string]string
	if g.o.RealBases != nil {
		real = g.o.RealBases(in.Group)
	}
	for _, s := range in.Services {
		sv := ServiceView{Name: s.Name, Alias: s.Alias, MockURL: s.BaseURL}
		if b, ok := real[s.Name]; ok {
			sv.RealBase = b
		} else if h, ok := strings.CutPrefix(s.Name, "host:"); ok && reHostPort.MatchString(h) {
			sv.RealBase = "https://" + h
		}
		v.Services = append(v.Services, sv)
	}
	return v
}

// report stores a report and returns the commands to run.
func (g *Registry) report(tok *TokenInfo, rep *mock.Report, now time.Time) ([]mock.Command, error) {
	if rep.Group != tok.Group {
		return nil, apiErr(http.StatusForbidden, "wrong_group", "this mock token belongs to another group")
	}
	name := rep.Instance
	if !instanceRE.MatchString(name) {
		return nil, apiErr(http.StatusBadRequest, "bad_request", "malformed instance name")
	}
	id := tok.TokenID + "." + name
	g.mu.Lock()
	defer g.mu.Unlock()
	in := g.instances[id]
	if in == nil {
		g.gc(now)
		if len(g.instances) >= maxInstances {
			return nil, apiErr(http.StatusTooManyRequests, "too_many_mocks", "too many mocks report to this console")
		}
		n := 0
		for _, o := range g.instances {
			if o.TokenID == tok.TokenID {
				n++
			}
		}
		if n >= maxInstancesPerToken {
			return nil, apiErr(http.StatusTooManyRequests, "too_many_mocks", "too many mocks report with this token: give each mock its own instance name and reuse it")
		}
		in = &instance{ID: id, TokenID: tok.TokenID, Group: tok.Group, Instance: name, FirstSeen: now, results: map[string]*commandState{}, notify: make(chan struct{}, 1)}
		g.instances[id] = in
	}
	if in.revoked {
		// The token was revoked after this request authenticated: a
		// revocation is final for the instance (its id carries the token).
		return nil, errUnauthorized
	}
	in.LastSeen = now
	// What a mock reports is shown in the console and reused (Postman
	// export, "replace X with Y"): bounded, without control or bidi
	// characters, URLs only http(s) without credentials.
	in.Version, in.Status, in.PackID, in.PackError = cleanText(rep.Version, 32), cleanText(rep.Status, 16), cleanText(rep.PackID, 64), cleanText(rep.PackError, 300)
	in.PublicURL, in.StartedAt = cleanURL(rep.PublicURL), cleanText(rep.StartedAt, 40)
	if len(rep.Services) > 200 {
		rep.Services = rep.Services[:200]
	}
	in.Services = make([]mock.ServiceURL, 0, len(rep.Services))
	for _, s := range rep.Services {
		in.Services = append(in.Services, mock.ServiceURL{Name: cleanText(s.Name, 128), Alias: cleanText(s.Alias, 64), BaseURL: cleanURL(s.BaseURL)})
	}
	if len(rep.Sessions) > 100 {
		rep.Sessions = rep.Sessions[:100]
	}
	in.Sessions = make([]mock.SessionSummary, 0, len(rep.Sessions))
	for _, s := range rep.Sessions {
		in.Sessions = append(in.Sessions, mock.SessionSummary{ID: cleanText(s.ID, 64), Scenario: cleanText(s.Scenario, 64), Clock: cleanText(s.Clock, 40),
			Calls: max(s.Calls, 0), Faults: cleanText(s.Faults, 32)})
	}
	if len(rep.Calls) > maxCalls {
		in.dropped += len(rep.Calls) - maxCalls
		rep.Calls = rep.Calls[len(rep.Calls)-maxCalls:]
	}
	in.dropped += max(rep.Dropped, 0)
	for _, c := range rep.Calls {
		in.callSeq++
		in.callsTotal++
		in.calls = append(in.calls, CallView{Seq: in.callSeq, Call: cleanCall(c)})
	}
	if n := len(in.calls) - maxCalls; n > 0 {
		in.calls = append([]CallView(nil), in.calls[n:]...)
	}
	for _, r := range rep.Results {
		if st, ok := in.results[r.ID]; ok && !st.done {
			rr := r
			if len(rr.Body) > maxResultBody {
				rr.Body = json.RawMessage(`{"code":"too_large","message":"the answer is too large to show in the console"}`)
			}
			st.done, st.result = true, &rr
		}
	}
	for k, st := range in.results {
		if now.Sub(st.at) > commandTTL {
			delete(in.results, k)
		}
	}
	cmds := in.queued
	in.queued = nil
	return cmds, nil
}

// cleanText bounds s to n bytes (on a rune boundary) and drops invalid
// UTF-8, control characters and bidirectional formatting characters (which
// could make a name read differently in the console).
func cleanText(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// cleanURL keeps an absolute http(s) URL without credentials, query or
// fragment, at most 512 bytes; anything else becomes "".
func cleanURL(s string) string {
	if s == "" || len(s) > 512 || cleanText(s, 512) != s || strings.ContainsAny(s, " \"<>`\\") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	return s
}

func cleanCall(c mock.Call) mock.Call {
	c.Wall, c.At = cleanText(c.Wall, 40), cleanText(c.At, 40)
	c.Session, c.Scenario = cleanText(c.Session, 64), cleanText(c.Scenario, 64)
	c.Service, c.Op = cleanText(c.Service, 128), cleanText(c.Op, 300)
	c.Method, c.Path = cleanText(c.Method, 16), cleanText(c.Path, 256)
	c.Reason, c.Fault = cleanText(c.Reason, 64), cleanText(c.Fault, 32)
	if i := strings.IndexAny(c.Path, "?#"); i >= 0 {
		c.Path = c.Path[:i] // never a query string (mock.md 6.3)
	}
	c.LatencyMS = max(c.LatencyMS, 0)
	return c
}

// reHostPort is a host[:port] the console may show as the real endpoint.
var reHostPort = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,252})(:[0-9]{1,5})?$`)

var instanceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// gc forgets mocks not seen for a day (g.mu held).
func (g *Registry) gc(now time.Time) {
	for id, in := range g.instances {
		if now.Sub(in.LastSeen) > forgetAfter {
			delete(g.instances, id)
		}
	}
}

// Mocks lists the known mocks, online first.
func (g *Registry) mocks(now time.Time, managedTokens map[string]bool, latest map[string]string) []MockView {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gc(now)
	out := make([]MockView, 0, len(g.instances))
	for _, in := range g.instances {
		out = append(out, g.view(in, now, managedTokens[in.TokenID], latest[in.Group]))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].MockID < out[j].MockID
	})
	return out
}

func (g *Registry) groupsOfInstances() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, in := range g.instances {
		if !seen[in.Group] {
			seen[in.Group] = true
			out = append(out, in.Group)
		}
	}
	return out
}

// calls returns the calls of a mock after since.
func (g *Registry) calls(id string, since int) ([]CallView, int, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	in := g.instances[id]
	if in == nil {
		return nil, 0, "", errNotFound
	}
	i := sort.Search(len(in.calls), func(i int) bool { return in.calls[i].Seq > since })
	out := append([]CallView{}, in.calls[i:]...)
	return out, in.callSeq, in.Group, nil
}

// enqueue queues a control command for a mock.
func (g *Registry) enqueue(id string, cmd mock.Command, now time.Time) (string, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	in := g.instances[id]
	if in == nil {
		return "", "", errNotFound
	}
	if !g.online(in, now) {
		return "", in.Group, apiErr(http.StatusConflict, "mock_offline", "the mock is not reporting: start it again, then retry")
	}
	if len(in.queued) >= maxQueued {
		return "", in.Group, apiErr(http.StatusTooManyRequests, "too_many_commands", "too many commands are waiting for this mock")
	}
	cmd.ID = httpx.NewID("cmd_")
	in.queued = append(in.queued, cmd)
	in.wake()
	in.results[cmd.ID] = &commandState{at: now, cmd: cmd}
	return cmd.ID, in.Group, nil
}

// CommandView is the state of a queued command.
type CommandView struct {
	CommandID string      `json:"command_id"`
	Status    string      `json:"status"` // pending, done
	Method    string      `json:"method"`
	Path      string      `json:"path"`
	Result    *ResultView `json:"result,omitempty"`
}

// ResultView is the control API answer of a command.
type ResultView struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

func (g *Registry) command(id, cmdID string) (*CommandView, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	in := g.instances[id]
	if in == nil {
		return nil, "", errNotFound
	}
	st := in.results[cmdID]
	if st == nil {
		return nil, in.Group, errNotFound
	}
	v := &CommandView{CommandID: cmdID, Status: "pending", Method: st.cmd.Method, Path: st.cmd.Path}
	if st.done {
		v.Status = "done"
		v.Result = &ResultView{Status: st.result.Status, Body: st.result.Body}
	}
	return v, in.Group, nil
}
