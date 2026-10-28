package mock

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Third-party pages (docs/spec/mock.md 9): flows where the application under
// test sends the user's browser to a third party (payment gateway,
// e-signature) and the third party calls the application back. The mock
// serves a simple page at /__pages/<id> with configurable buttons; a click
// performs the server-to-server callback (method, URL, headers, body
// template, optional HMAC signature) and redirects the browser to the
// application's return URL. Tests without a browser complete a page through
// the control API. Nothing here is specific to an application: pages,
// buttons, URLs and bodies are configuration.

const pagesPrefix = "/__pages"

// PagesConfig is the configuration of the third-party pages.
type PagesConfig struct {
	Pages []Page `json:"pages"`
}

// Page is one third-party page.
type Page struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Ref is the template of the reference of a visit (the payment or
	// signature id), default the "ref" query parameter, else a generated
	// REF-SYN-NNNN.
	Ref string `json:"ref,omitempty"`
	// Show lists query parameters shown on the page (amount, order...).
	Show []string `json:"show,omitempty"`
	// ReturnURL is the template of the URL the browser goes back to; with
	// a placeholder before the path, ReturnHosts must list the hosts it
	// may name. Empty: the page shows the outcome and stays.
	ReturnURL   string    `json:"return_url,omitempty"`
	ReturnHosts []string  `json:"return_hosts,omitempty"`
	Buttons     []Button  `json:"buttons"`
	Callback    *Callback `json:"callback,omitempty"`
	// Links are operations of the contracts whose answer carries the URL
	// of the page: the mock writes it at Path of the body (a tt-path).
	Links []PageLink `json:"links,omitempty"`
	// Auto completes a visit at once, without showing the page: by
	// scenario preset id, "*" for every session.
	Auto map[string]string `json:"auto,omitempty"`
}

// Button is one choice of a page.
type Button struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	// Values are extra placeholders of this choice ({value.<name>}).
	Values map[string]string `json:"values,omitempty"`
	// NoCallback skips the callback for this choice (a cancel button).
	NoCallback bool `json:"no_callback,omitempty"`
	// Set gives fields of the linked object (the entity or static object
	// of the answer that carried the page URL, PageLink) for this choice:
	// a payment AUTHORISED, a signature SIGNED. Values are scalars;
	// strings take the placeholders.
	Set map[string]any `json:"set,omitempty"`
}

// Callback is the server-to-server call of a completed visit.
type Callback struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// BodyType says how placeholders are escaped in Body: json (inside
	// JSON strings), form (URL encoded) or text (as they are).
	BodyType string `json:"body_type,omitempty"`
	HMAC     *HMAC  `json:"hmac,omitempty"`
}

// HMAC signs the callback body.
type HMAC struct {
	Header    string `json:"header"`
	Key       string `json:"key"`
	Algorithm string `json:"algorithm,omitempty"` // sha256 (default), sha1, sha512
	Encoding  string `json:"encoding,omitempty"`  // hex (default), base64
	Prefix    string `json:"prefix,omitempty"`    // e.g. "sha256="
}

// PageLink makes the answer of an operation carry the page URL.
type PageLink struct {
	Service string `json:"service"`
	Op      string `json:"op"`
	Path    string `json:"path"`
	// RefPath is where the answer carries the reference of the visit
	// (e.g. $.paymentId); default a generated one.
	RefPath string `json:"ref_path,omitempty"`
	// BaseURL is the address the browser uses to reach the mock (default
	// http://<Host of the request>).
	BaseURL string `json:"base_url,omitempty"`
	// ReturnFrom is where the request of the operation carries the URL the
	// application wants the browser back at ({link.return}).
	ReturnFrom *PageFrom `json:"return_from,omitempty"`
	// Entity names the entity of the rules whose object (id: the value at
	// RefPath) the buttons' Set changes; empty: the object the operation
	// created in static mode (docs/spec/mock.md 2.5), if any.
	Entity string `json:"entity,omitempty"`
}

// PageFrom is a value of the request of a linked operation: a member of the
// JSON body (From "req.body", Path), a query parameter ("req.query", Name)
// or a header ("req.headers", Name).
type PageFrom struct {
	From string `json:"from"`
	Path string `json:"path,omitempty"`
	Name string `json:"name,omitempty"`
}

// pageLinkRec is what an answer that carried a page URL leaves for its
// visits: the application's return URL and the object the buttons change.
type pageLinkRec struct {
	key    string
	page   string
	ref    string
	ret    string
	entity string // rules entity, or "" with coll
	coll   string // static collection (service\x00/template)
	id     string
}

var (
	pageIDRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	actionRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	setFieldRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
	entityNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	placeholdRE  = regexp.MustCompile(`\{([a-z]+(?:\.[A-Za-z0-9_-]{1,64})?)\}`)
	headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
	runIDRE      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

const maxPageTemplate = 16 << 10

// LoadPages reads a pages file (--pages).
func LoadPages(path string) (*PagesConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mock: pages: %w", err)
	}
	var c PagesConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("mock: pages: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("mock: pages: %w", err)
	}
	return &c, nil
}

// fixedOrigin reports whether a URL template starts with a literal
// http(s)://host/ (no placeholder before the path).
func fixedOrigin(t string) bool {
	i := strings.Index(t, "{")
	head := t
	if i >= 0 {
		head = t[:i]
	}
	u, err := url.Parse(head)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return false
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(head, u.Scheme+"://"), u.Host)
	return i < 0 || strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "?")
}

func checkPlaceholders(t string) error {
	for _, m := range placeholdRE.FindAllStringSubmatch(t, -1) {
		name, sub, _ := strings.Cut(m[1], ".")
		switch name {
		case "ref", "action", "session", "uuid":
			if sub != "" {
				return fmt.Errorf("placeholder {%s} takes no name", m[1])
			}
		case "now":
			if sub != "" && sub != "date" && sub != "unix" {
				return fmt.Errorf("placeholder {%s}: now, now.date or now.unix", m[1])
			}
		case "query", "value":
			if sub == "" {
				return fmt.Errorf("placeholder {%s} needs a name", m[1])
			}
		case "customer":
			if sub != "id" && sub != "name" {
				return fmt.Errorf("placeholder {%s}: customer.id or customer.name", m[1])
			}
		case "link":
			if sub != "return" {
				return fmt.Errorf("placeholder {%s}: link.return", m[1])
			}
		default:
			return fmt.Errorf("unknown placeholder {%s}", m[1])
		}
	}
	return nil
}

// Validate checks a configuration. Errors name the page and the field.
func (c *PagesConfig) Validate() error {
	if len(c.Pages) > 32 {
		return errors.New("at most 32 pages")
	}
	seen := map[string]bool{}
	for i := range c.Pages {
		p := &c.Pages[i]
		at := func(f string, a ...any) error {
			return fmt.Errorf("pages[%d] (%s): %s", i, p.ID, fmt.Sprintf(f, a...))
		}
		if !pageIDRE.MatchString(p.ID) || seen[p.ID] {
			return at("id must be a lower-case name, unique (a-z, 0-9, -)")
		}
		seen[p.ID] = true
		if len(p.Title) > 120 || len(p.Description) > 1000 || strings.TrimSpace(p.Title) == "" {
			return at("title is required (at most 120 characters), description at most 1000")
		}
		if len(p.Buttons) == 0 || len(p.Buttons) > 6 {
			return at("one to six buttons")
		}
		actions := map[string]bool{}
		for _, b := range p.Buttons {
			if !actionRE.MatchString(b.Action) || actions[b.Action] {
				return at("button action %q must be a lower-case name, unique", b.Action)
			}
			actions[b.Action] = true
			if strings.TrimSpace(b.Label) == "" || len(b.Label) > 60 {
				return at("button %s: label is required (at most 60 characters)", b.Action)
			}
			for k, v := range b.Values {
				if !actionRE.MatchString(k) || len(v) > 200 {
					return at("button %s: value names are lower-case names, values at most 200 characters", b.Action)
				}
			}
			if len(b.Set) > 32 {
				return at("button %s: set has at most 32 fields", b.Action)
			}
			for k, v := range b.Set {
				if !setFieldRE.MatchString(k) {
					return at("button %s: set: %q is not a field path (a.b.c)", b.Action, k)
				}
				switch x := v.(type) {
				case nil, bool, float64, json.Number, int:
				case string:
					if len(x) > 1024 {
						return at("button %s: set %s: at most 1024 characters", b.Action, k)
					}
					if err := checkPlaceholders(x); err != nil {
						return at("button %s: set %s: %v", b.Action, k, err)
					}
				default:
					return at("button %s: set %s: values are scalars (text, number, true/false, null)", b.Action, k)
				}
			}
		}
		for _, s := range p.Show {
			if !headerNameRE.MatchString(s) {
				return at("show: %q is not a parameter name", s)
			}
		}
		for _, t := range []string{p.Ref, p.ReturnURL} {
			if len(t) > 2048 {
				return at("templates are at most 2048 characters")
			}
			if err := checkPlaceholders(t); err != nil {
				return at("%v", err)
			}
		}
		if p.ReturnURL != "" && !fixedOrigin(p.ReturnURL) {
			if len(p.ReturnHosts) == 0 {
				return at("return_url takes its host from the request: list the allowed hosts in return_hosts")
			}
			if !placeholdRE.MatchString(p.ReturnURL) {
				return at("return_url must be an absolute http(s) URL")
			}
		}
		for _, h := range p.ReturnHosts {
			if h == "" || strings.ContainsAny(h, "/:@ ") {
				return at("return_hosts: %q is not a host name", h)
			}
		}
		if cb := p.Callback; cb != nil {
			switch cb.Method {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
			default:
				return at("callback method must be GET, POST, PUT, PATCH or DELETE")
			}
			if !fixedOrigin(cb.URL) {
				return at("callback url must start with a fixed http(s)://host/ (placeholders only in path and query)")
			}
			if len(cb.Body) > maxPageTemplate || len(cb.URL) > 2048 {
				return at("callback body at most 16 KiB, url at most 2048 characters")
			}
			for _, t := range []string{cb.URL, cb.Body} {
				if err := checkPlaceholders(t); err != nil {
					return at("callback: %v", err)
				}
			}
			for k, v := range cb.Headers {
				if !headerNameRE.MatchString(k) || strings.ContainsAny(v, "\r\n") || len(v) > 1024 {
					return at("callback header %q is not valid", k)
				}
				if err := checkPlaceholders(v); err != nil {
					return at("callback header %s: %v", k, err)
				}
			}
			switch cb.BodyType {
			case "", "json", "form", "text":
			default:
				return at("callback body_type must be json, form or text")
			}
			if h := cb.HMAC; h != nil {
				if !headerNameRE.MatchString(h.Header) || len(h.Key) < 8 || len(h.Key) > 256 || len(h.Prefix) > 32 || strings.ContainsAny(h.Prefix, "\r\n") {
					return at("hmac needs a header name and a key of 8 to 256 characters")
				}
				switch h.Algorithm {
				case "", "sha256", "sha1", "sha512":
				default:
					return at("hmac algorithm must be sha256, sha1 or sha512")
				}
				switch h.Encoding {
				case "", "hex", "base64":
				default:
					return at("hmac encoding must be hex or base64")
				}
			}
		}
		for _, l := range p.Links {
			if l.Service == "" || !faultOpRE.MatchString(l.Op) {
				return at("links need service and op (\"POST /v1/sessions\")")
			}
			if _, err := parseTTPath(l.Path); err != nil || !strings.HasPrefix(l.Path, "$.") {
				return at("links: path must be a body path like $.redirectUrl")
			}
			if l.RefPath != "" {
				if _, err := parseTTPath(l.RefPath); err != nil {
					return at("links: ref_path must be a body path like $.paymentId")
				}
			}
			if l.BaseURL != "" && !fixedOrigin(l.BaseURL) {
				return at("links: base_url must be an absolute http(s) URL")
			}
			if rf := l.ReturnFrom; rf != nil {
				switch rf.From {
				case "req.body":
					if _, err := parseTTPath(rf.Path); err != nil || !strings.HasPrefix(rf.Path, "$.") || rf.Name != "" {
						return at("links: return_from with from req.body needs a body path like $.returnUrl")
					}
				case "req.query", "req.headers":
					if !headerNameRE.MatchString(rf.Name) || rf.Path != "" {
						return at("links: return_from with from %s needs a name", rf.From)
					}
				default:
					return at("links: return_from.from must be req.body, req.query or req.headers")
				}
			}
			if l.Entity != "" {
				if !entityNameRE.MatchString(l.Entity) {
					return at("links: entity %q is not an entity name", l.Entity)
				}
				if l.RefPath == "" {
					return at("links: entity needs ref_path, where the answer carries the object's id")
				}
			}
		}
		for k, a := range p.Auto {
			if k != "*" && !pageIDRE.MatchString(k) {
				return at("auto: %q is not a scenario id or *", k)
			}
			if !actions[a] {
				return at("auto: %q is not a button of the page", a)
			}
		}
	}
	return nil
}

// Masked is the configuration with the HMAC keys hidden (control API).
func (c *PagesConfig) Masked() *PagesConfig {
	if c == nil {
		return &PagesConfig{Pages: []Page{}}
	}
	b, _ := json.Marshal(c)
	var out PagesConfig
	_ = json.Unmarshal(b, &out)
	for i := range out.Pages {
		if cb := out.Pages[i].Callback; cb != nil && cb.HMAC != nil {
			cb.HMAC.Key = ""
		}
	}
	if out.Pages == nil {
		out.Pages = []Page{}
	}
	return &out
}

// SetPages replaces the third-party pages (nil: none).
func (m *Mock) SetPages(c *PagesConfig) error {
	if c != nil {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	m.pages.Store(c)
	return nil
}

func (m *Mock) page(id string) *Page {
	c := m.pages.Load()
	if c == nil {
		return nil
	}
	for i := range c.Pages {
		if c.Pages[i].ID == id {
			return &c.Pages[i]
		}
	}
	return nil
}

// ---- visits ----

// pageRun is one visit of a page in a session.
type pageRun struct {
	id       string
	page     string
	ref      string
	query    url.Values
	done     string // action, "" while open
	returnTo string
	callback *callbackResult
	// linked is what the answer that carried the page URL left (nil: the
	// visit was opened some other way); changed names the object the
	// chosen button changed ("entity id").
	linked  *pageLinkRec
	changed string
}

type callbackResult struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	// Body is the start of the answer (at most 4 KiB).
	Body string `json:"body,omitempty"`
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// placeholders are the values of one completion.
func (s *session) placeholders(run *pageRun, action string, values map[string]string) func(name string) string {
	return func(name string) string {
		kind, sub, _ := strings.Cut(name, ".")
		switch kind {
		case "ref":
			return run.ref
		case "action":
			return action
		case "session":
			return s.id
		case "uuid":
			h := sha256.Sum256([]byte(s.id + "/" + run.id))
			x := hex.EncodeToString(h[:16])
			return x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-8" + x[17:20] + "-" + x[20:32]
		case "now":
			switch sub {
			case "date":
				return s.now.UTC().Format("2006-01-02")
			case "unix":
				return strconv.FormatInt(s.now.Unix(), 10)
			}
			return s.now.UTC().Format(time.RFC3339)
		case "query":
			return run.query.Get(sub)
		case "value":
			return values[sub]
		case "link":
			if run.linked != nil && sub == "return" {
				return run.linked.ret
			}
			return ""
		case "customer":
			if s.customer == nil {
				return ""
			}
			if sub == "id" {
				return *s.customer
			}
			if c := s.m.model.custByID[*s.customer]; c != nil {
				return profileName(c.Profile)
			}
		}
		return ""
	}
}

// fill replaces the placeholders of a template, escaping each value with
// esc.
func fill(t string, get func(string) string, esc func(string) string) string {
	return placeholdRE.ReplaceAllStringFunc(t, func(m string) string {
		return esc(get(m[1 : len(m)-1]))
	})
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

func noCRLF(s string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(s) }

// fillURL fills a URL template: a template that is one placeholder takes the
// value as a URL, otherwise values are query-escaped.
func fillURL(t string, get func(string) string) string {
	if m := placeholdRE.FindStringSubmatch(t); m != nil && m[0] == t {
		return get(m[1])
	}
	return fill(t, get, url.QueryEscape)
}

// returnURL computes the return URL of a completion, "" when the page has
// none or the URL is not allowed.
func (p *Page) returnURL(get func(string) string) (string, error) {
	if p.ReturnURL == "" {
		return "", nil
	}
	u := fillURL(p.ReturnURL, get)
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || pu.User != nil {
		return "", errors.New("the return URL is not an absolute http(s) URL")
	}
	if !fixedOrigin(p.ReturnURL) {
		ok := false
		for _, h := range p.ReturnHosts {
			if strings.EqualFold(pu.Hostname(), h) {
				ok = true
			}
		}
		if !ok {
			return "", errors.New("the return URL names a host that is not in return_hosts")
		}
	}
	return u, nil
}

// complete finishes a visit: callback (unless the button skips it), then
// the return URL. The callback runs outside the session lock.
func (m *Mock) complete(ctx context.Context, s *session, p *Page, run *pageRun, action string) (*pageRun, error) {
	var btn *Button
	for i := range p.Buttons {
		if p.Buttons[i].Action == action {
			btn = &p.Buttons[i]
		}
	}
	if btn == nil {
		return nil, fmt.Errorf("the page has no button %q", action)
	}
	s.mu.Lock()
	if run.done != "" {
		s.mu.Unlock()
		return run, errAlreadyDone
	}
	run.done = action
	get := s.placeholders(run, action, btn.Values)
	ret, retErr := p.returnURL(get)
	if len(btn.Set) > 0 {
		run.changed = s.applyPageSet(run, btn, get)
	}
	var req *http.Request
	var cbBody []byte
	if cb := p.Callback; cb != nil && !btn.NoCallback {
		u := fill(cb.URL, get, url.QueryEscape)
		switch cb.BodyType {
		case "form":
			cbBody = []byte(fill(cb.Body, get, url.QueryEscape))
		case "text":
			cbBody = []byte(fill(cb.Body, get, func(v string) string { return v }))
		default:
			cbBody = []byte(fill(cb.Body, get, jsonEscape))
		}
		var err error
		req, err = http.NewRequestWithContext(ctx, cb.Method, u, bytes.NewReader(cbBody))
		if err == nil {
			for k, v := range cb.Headers {
				req.Header.Set(k, noCRLF(fill(v, get, noCRLF)))
			}
			if req.Header.Get("Content-Type") == "" && len(cbBody) > 0 {
				req.Header.Set("Content-Type", map[string]string{"form": "application/x-www-form-urlencoded", "text": "text/plain"}[cb.BodyType])
				if cb.BodyType == "" || cb.BodyType == "json" {
					req.Header.Set("Content-Type", "application/json")
				}
			}
			if h := cb.HMAC; h != nil {
				req.Header.Set(h.Header, h.Prefix+sign(h, cbBody))
			}
		} else {
			run.callback = &callbackResult{Method: cb.Method, URL: u, Error: "invalid callback URL"}
		}
	}
	run.returnTo = ret
	s.mu.Unlock()

	if req != nil {
		res := &callbackResult{Method: req.Method, URL: req.URL.String()}
		resp, err := m.httpClient().Do(req)
		if err != nil {
			res.Error = "callback failed: " + err.Error()
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			res.Status, res.Body = resp.StatusCode, string(bytes.ToValidUTF8(b, nil))
		}
		s.mu.Lock()
		run.callback = res
		s.journalPage(p.ID, "callback", req.Method, req.URL.EscapedPath(), req.URL.RawQuery, res.Status, map[string]any{"body": string(cbBody)}, map[string]any{"body": res.Body, "error": res.Error})
		s.mu.Unlock()
	}
	if retErr != nil {
		return run, retErr
	}
	return run, nil
}

var errAlreadyDone = errors.New("this visit is already completed")

func sign(h *HMAC, body []byte) string {
	var f func() hash.Hash
	switch h.Algorithm {
	case "sha1":
		f = sha1.New
	case "sha512":
		f = sha512.New
	default:
		f = sha256.New
	}
	mac := hmac.New(f, []byte(h.Key))
	mac.Write(body)
	sum := mac.Sum(nil)
	if h.Encoding == "base64" {
		return base64.StdEncoding.EncodeToString(sum)
	}
	return hex.EncodeToString(sum)
}

func (m *Mock) httpClient() *http.Client {
	if m.cfg.HTTPClient != nil {
		return m.cfg.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// journalPage records a page event (service "pages", op "<event> <page>").
func (s *session) journalPage(page, event, method, path, query string, status int, req, resp map[string]any) {
	svc, op := "pages", event+" "+page
	e := &journalEntry{At: fmtTime(s.now), Wall: wallNow(s.m), Method: method, Path: path, Query: query, Service: &svc, Op: &op,
		Matched: true, Request: req, Response: resp}
	if status != 0 {
		e.Status = &status
	}
	s.appendJournal(e)
}

// newRun opens a visit of a page.
func (s *session) newRun(p *Page, q url.Values) *pageRun {
	if s.pageRuns == nil {
		s.pageRuns = map[string]*pageRun{}
	}
	if len(s.pageRuns) >= 1000 {
		// the oldest completed visits go first
		for id, r := range s.pageRuns {
			if r.done != "" {
				delete(s.pageRuns, id)
			}
		}
	}
	run := &pageRun{id: newRunID(), page: p.ID, query: q}
	if k := q.Get("tt_link"); k != "" {
		run.linked = s.pageLinked[k]
		q.Del("tt_link")
	}
	get := s.placeholders(run, "", nil)
	switch {
	case p.Ref != "":
		run.ref = fill(p.Ref, get, func(v string) string { return v })
	case q.Get("ref") != "":
		run.ref = q.Get("ref")
	case run.linked != nil && run.linked.page == p.ID:
		run.ref = run.linked.ref
	}
	if run.linked == nil && run.ref != "" {
		run.linked = s.pageLinked[p.ID+"\x00"+run.ref]
	}
	if run.linked != nil && run.linked.page != p.ID {
		run.linked = nil
	}
	if run.ref == "" {
		s.counters["__pages/"+p.ID]++
		run.ref = fmt.Sprintf("REF-SYN-%04d", s.counters["__pages/"+p.ID])
	}
	if len(run.ref) > 256 {
		run.ref = run.ref[:256]
	}
	s.pageRuns[run.id] = run
	return run
}

// autoAction is the button a session completes a page with at once ("":
// show the page).
func (s *session) autoAction(p *Page) string {
	if a, ok := s.pageAuto[p.ID]; ok {
		return a
	}
	if a, ok := p.Auto[s.scenario]; ok && s.scenario != "" {
		return a
	}
	return p.Auto["*"]
}

// ---- data plane: the page in the browser ----

// pageStyle is the only style of the pages, allowed by its hash.
const pageStyle = `body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;color:#1d2433;background:#f6f7f9}
main{background:#fff;border:1px solid #d5dae3;border-radius:8px;padding:1.5rem}h1{font-size:1.3rem;margin-top:0}
.note{font-size:.85rem;color:#5b6577;border-top:1px solid #e3e6ec;margin-top:1.5rem;padding-top:.75rem}
dl{display:grid;grid-template-columns:auto 1fr;gap:.25rem 1rem}dt{color:#5b6577}dd{margin:0;word-break:break-all}
button{font:inherit;padding:.6rem 1rem;margin:.25rem .5rem .25rem 0;border-radius:6px;border:1px solid #2f5fd0;background:#2f5fd0;color:#fff;cursor:pointer}
button.alt{background:#fff;color:#2f5fd0}`

// pageCSP is the policy of the pages: nothing external, no script, the one
// style by hash; the form posts to the page itself (the redirect that
// follows goes to the return URL, added by pageCSPFor).
var pageCSP = func() string {
	h := sha256.Sum256([]byte(pageStyle))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}()

var pageTpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}}</title>
<style>` + pageStyle + `</style></head>
<body><main><h1>{{.Title}}</h1>{{if .Description}}<p>{{.Description}}</p>{{end}}
<dl><dt>Riferimento / Reference</dt><dd>{{.Ref}}</dd>{{range .Shown}}<dt>{{.Name}}</dt><dd>{{.Value}}</dd>{{end}}</dl>
{{if .Done}}<p><strong>Completato / Completed: {{.Done}}</strong></p>{{if .Callback}}<p>Callback: {{.Callback}}</p>{{end}}
{{else}}<form method="post" action="{{.Action}}">{{range $i, $b := .Buttons}}<button type="submit" name="action" value="{{$b.Action}}"{{if $i}} class="alt"{{end}}>{{$b.Label}}</button>{{end}}</form>{{end}}
<p class="note">Pagina simulata da traffic-twin per i test: nessun pagamento o firma reale. / Page simulated by traffic-twin for tests: no real payment or signature.</p>
</main></body></html>`))

type shownValue struct{ Name, Value string }

// pageCSPFor is pageCSP with the origins of the return URL in form-action:
// browsers check the redirect after the form against it.
func pageCSPFor(p *Page) string {
	srcs := []string{"'self'"}
	if p.ReturnURL != "" && fixedOrigin(p.ReturnURL) {
		head := p.ReturnURL
		if i := strings.Index(head, "{"); i >= 0 {
			head = head[:i]
		}
		if u, err := url.Parse(head); err == nil {
			srcs = append(srcs, u.Scheme+"://"+u.Host)
		}
	}
	for _, h := range p.ReturnHosts {
		srcs = append(srcs, "http://"+h, "https://"+h)
		srcs = append(srcs, "http://"+h+":*", "https://"+h+":*")
	}
	return strings.Replace(pageCSP, "form-action 'self'", "form-action "+strings.Join(srcs, " "), 1)
}

func writePage(w http.ResponseWriter, status int, p *Page, run *pageRun, action string) {
	shown := []shownValue{}
	for _, n := range p.Show {
		if v := run.query.Get(n); v != "" {
			shown = append(shown, shownValue{n, v})
		}
	}
	cb := ""
	if run.callback != nil {
		if run.callback.Error != "" {
			cb = run.callback.Error
		} else {
			cb = strconv.Itoa(run.callback.Status)
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pageCSPFor(p))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = pageTpl.Execute(w, map[string]any{"Title": p.Title, "Description": p.Description, "Ref": run.ref, "Shown": shown,
		"Buttons": p.Buttons, "Action": action, "Done": run.done, "Callback": cb})
}

func pageError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Security-Policy", pageCSP)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

// servePage serves GET /__pages/<id>?... (a visit) and
// POST /__pages/<id>/<visit> (a click).
func (m *Mock) servePage(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, pagesPrefix), "/")
	id, runID, _ := strings.Cut(rest, "/")
	p := m.page(id)
	if p == nil {
		pageError(w, http.StatusNotFound, "unknown page")
		return
	}
	if sid := r.URL.Query().Get("tt_session"); sid != "" && r.Header.Get(hdrSession) == "" {
		r.Header.Set(hdrSession, sid)
	}
	sess := m.requestSession(w, r)
	if sess == nil {
		return
	}
	switch {
	case runID == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		q := r.URL.Query()
		q.Del("tt_session")
		sess.mu.Lock()
		sess.lastUsed.Store(m.cfg.Wall().UnixNano())
		run := sess.newRun(p, q)
		auto := sess.autoAction(p)
		sess.journalPage(p.ID, "view", r.Method, r.URL.EscapedPath(), "", http.StatusOK, map[string]any{}, map[string]any{"body": "page " + p.ID + ", ref " + run.ref})
		sess.mu.Unlock()
		if auto != "" {
			m.finishInBrowser(w, r, sess, p, run, auto)
			return
		}
		writePage(w, http.StatusOK, p, run, pagesPrefix+"/"+p.ID+"/"+run.id+"?tt_session="+url.QueryEscape(sess.id))
	case runID != "" && r.Method == http.MethodPost:
		if !runIDRE.MatchString(runID) {
			pageError(w, http.StatusNotFound, "unknown visit")
			return
		}
		if err := r.ParseForm(); err != nil {
			pageError(w, http.StatusBadRequest, "invalid form")
			return
		}
		sess.mu.Lock()
		run := sess.pageRuns[runID]
		sess.mu.Unlock()
		if run == nil || run.page != p.ID {
			pageError(w, http.StatusNotFound, "unknown visit")
			return
		}
		m.finishInBrowser(w, r, sess, p, run, r.PostForm.Get("action"))
	default:
		w.Header().Set("Allow", "GET, POST")
		pageError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (m *Mock) finishInBrowser(w http.ResponseWriter, r *http.Request, sess *session, p *Page, run *pageRun, action string) {
	run, err := m.complete(r.Context(), sess, p, run, action)
	if run == nil {
		pageError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess.mu.Lock()
	sess.journalPage(p.ID, "complete", r.Method, r.URL.EscapedPath(), "", http.StatusSeeOther, map[string]any{"body": "action " + action}, completeJournal(run))
	sess.mu.Unlock()
	switch {
	case errors.Is(err, errAlreadyDone) || (err == nil && run.returnTo == ""):
		writePage(w, http.StatusOK, p, run, "")
	case err != nil:
		pageError(w, http.StatusBadRequest, err.Error())
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, run.returnTo, http.StatusSeeOther)
	}
}

// completeJournal is the journaled answer of a completion.
func completeJournal(run *pageRun) map[string]any {
	out := map[string]any{"body": "return " + run.returnTo}
	if run.changed != "" {
		out["changed"] = run.changed
	}
	return out
}

// ---- links in the answers of the contracts ----

// pageLinks writes the URL of the pages linked to an operation into its
// answer (a successful one).
func (s *session) pageLinks(svc *service, op *operation, in *inbound, body any) {
	c := s.m.pages.Load()
	if c == nil || body == nil {
		return
	}
	for i := range c.Pages {
		p := &c.Pages[i]
		for li := range p.Links {
			l := &p.Links[li]
			if l.Op != op.key || (l.Service != svc.name && l.Service != svc.alias) {
				continue
			}
			q := url.Values{}
			if l.RefPath != "" {
				if segs, err := parseTTPath(l.RefPath); err == nil {
					if v, ok := first(evalPath(body, segs)); ok {
						if str, ok := scalarString(v); ok {
							q.Set("ref", str)
						}
					}
				}
			}
			if rec := s.linkRecord(p, l, svc, op, in, q.Get("ref")); rec != nil {
				q.Set("tt_link", rec.key)
			}
			q.Set("tt_session", s.id)
			base := l.BaseURL
			if base == "" {
				base = "http://" + in.host
			}
			u := strings.TrimSuffix(base, "/") + pagesPrefix + "/" + p.ID + "?" + q.Encode()
			if segs, err := parseTTPath(l.Path); err == nil {
				setAtPath(body, segs, u)
			}
		}
	}
}

// maxPageLinks bounds the link records of a session (the oldest are
// forgotten all at once beyond it).
const maxPageLinks = 2000

// linkRecord keeps, for the visits of the page URL an answer carries, the
// return URL the request asked for and the object the answer created: an
// entity of the rules (Entity, id at RefPath) or the static object of a
// create on a collection with that id. nil when there is neither.
func (s *session) linkRecord(p *Page, l *PageLink, svc *service, op *operation, in *inbound, ref string) *pageLinkRec {
	rec := &pageLinkRec{page: p.ID, ref: ref}
	if l.ReturnFrom != nil {
		rec.ret = requestValue(in, l.ReturnFrom)
	}
	if ref != "" {
		if l.Entity != "" {
			rec.entity, rec.id = l.Entity, ref
		} else if n := len(op.segs); n > 0 && op.method == http.MethodPost && !isParamSeg(op.segs[n-1]) {
			coll := svc.name + "\x00/" + strings.Join(op.segs, "/")
			if _, ok := s.static.get(coll, ref); ok {
				rec.coll, rec.id = coll, ref
			}
		}
	}
	if rec.ret == "" && rec.id == "" {
		return nil
	}
	if s.pageLinked == nil || len(s.pageLinked) >= maxPageLinks {
		s.pageLinked = map[string]*pageLinkRec{}
	}
	rec.key = newRunID()
	s.pageLinked[rec.key] = rec
	if ref != "" {
		s.pageLinked[p.ID+"\x00"+ref] = rec
	}
	return rec
}

// requestValue reads a value of the request (at most 2048 bytes, "" when
// absent or not a scalar).
func requestValue(in *inbound, f *PageFrom) string {
	var v string
	switch f.From {
	case "req.body":
		var body any
		if json.Unmarshal(in.body, &body) != nil {
			return ""
		}
		segs, err := parseTTPath(f.Path)
		if err != nil {
			return ""
		}
		x, ok := first(evalPath(body, segs))
		if !ok {
			return ""
		}
		v, _ = scalarString(x)
	case "req.query":
		q, _ := url.ParseQuery(in.rawQuery)
		v = q.Get(f.Name)
	case "req.headers":
		v = in.header.Get(f.Name)
	}
	if len(v) > 2048 {
		return ""
	}
	return v
}

// applyPageSet writes the Set of the chosen button into the linked object
// (under the session lock) and names it ("" when there is none).
func (s *session) applyPageSet(run *pageRun, btn *Button, get func(string) string) string {
	l := run.linked
	if l == nil || l.id == "" {
		return ""
	}
	var obj map[string]any
	label := ""
	if l.entity != "" {
		rec := s.ents[l.entity][l.id]
		if rec == nil {
			return ""
		}
		obj, label = rec.state, l.entity+" "+l.id
		rec.updated = s.now
	} else {
		o, ok := s.static.get(l.coll, l.id)
		if !ok {
			return ""
		}
		obj, label = o, "static "+l.id
	}
	for _, k := range sortedKeys(btn.Set) {
		v := btn.Set[k]
		if str, ok := v.(string); ok {
			v = fill(str, get, func(x string) string { return x })
		}
		setDotted(obj, k, v)
	}
	return label
}

// ---- control API ----

type pageCompleteReq struct {
	Action string            `json:"action"`
	Query  map[string]string `json:"query,omitempty"`
	Visit  string            `json:"visit,omitempty"`
}

type pageCompleteView struct {
	Visit     string          `json:"visit"`
	Page      string          `json:"page"`
	Ref       string          `json:"ref"`
	Action    string          `json:"action"`
	ReturnURL string          `json:"return_url,omitempty"`
	Callback  *callbackResult `json:"callback,omitempty"`
	// Changed names the object the button changed ("<entity> <id>",
	// "static <id>").
	Changed string `json:"changed,omitempty"`
	Error   string `json:"error,omitempty"`
}

// controlPages serves /__tt/pages (GET, PUT).
func (m *Mock) controlPages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, m.pages.Load().Masked())
		return
	}
	var c PagesConfig
	if _, ok := m.decodeBody(w, r, &c); !ok {
		return
	}
	// a key left empty keeps the current one (GET masks the keys)
	if cur := m.pages.Load(); cur != nil {
		for i := range c.Pages {
			if cb := c.Pages[i].Callback; cb != nil && cb.HMAC != nil && cb.HMAC.Key == "" {
				if old := m.page(c.Pages[i].ID); old != nil && old.Callback != nil && old.Callback.HMAC != nil {
					cb.HMAC.Key = old.Callback.HMAC.Key
				}
			}
		}
	}
	if err := m.SetPages(&c); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, 200, m.pages.Load().Masked())
}

// controlSessionPages serves /__tt/sessions/{s}/pages/{page}/complete
// (POST) and /__tt/sessions/{s}/pages/{page}/auto (PUT, DELETE).
func (m *Mock) controlSessionPages(w http.ResponseWriter, r *http.Request, sid, page, verb string) {
	p := m.page(page)
	if p == nil {
		writeError(w, http.StatusNotFound, "page_not_found", "unknown third-party page")
		return
	}
	s := m.lookup(sid)
	if s == nil {
		writeError(w, http.StatusNotFound, "session_not_found", "unknown session")
		return
	}
	switch verb {
	case "auto":
		if r.Method == http.MethodDelete {
			s.mu.Lock()
			delete(s.pageAuto, page)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		if _, ok := m.decodeBody(w, r, &req); !ok {
			return
		}
		found := false
		for _, b := range p.Buttons {
			found = found || b.Action == req.Action
		}
		if !found {
			writeErrorP(w, http.StatusBadRequest, "bad_request", "the page has no such button", "/action")
			return
		}
		s.mu.Lock()
		if s.pageAuto == nil {
			s.pageAuto = map[string]string{}
		}
		s.pageAuto[page] = req.Action
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"page": page, "action": req.Action})
	case "complete":
		var req pageCompleteReq
		if _, ok := m.decodeBody(w, r, &req); !ok {
			return
		}
		if len(req.Query) > 64 {
			writeErrorP(w, http.StatusBadRequest, "bad_request", "at most 64 query values", "/query")
			return
		}
		s.mu.Lock()
		var run *pageRun
		if req.Visit != "" {
			run = s.pageRuns[req.Visit]
			if run == nil || run.page != page {
				s.mu.Unlock()
				writeError(w, http.StatusNotFound, "visit_not_found", "unknown visit of this page")
				return
			}
		} else {
			q := url.Values{}
			keys := make([]string, 0, len(req.Query))
			for k := range req.Query {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				q.Set(k, req.Query[k])
			}
			run = s.newRun(p, q)
		}
		s.mu.Unlock()
		run, err := m.complete(r.Context(), s, p, run, req.Action)
		if run == nil {
			writeErrorP(w, http.StatusBadRequest, "bad_request", err.Error(), "/action")
			return
		}
		s.mu.Lock()
		v := pageCompleteView{Visit: run.id, Page: page, Ref: run.ref, Action: run.done, ReturnURL: run.returnTo, Callback: run.callback, Changed: run.changed}
		s.journalPage(page, "complete", r.Method, r.URL.EscapedPath(), "", http.StatusOK, map[string]any{"body": "action " + req.Action}, completeJournal(run))
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, errAlreadyDone) {
				writeError(w, http.StatusConflict, "visit_completed", err.Error())
				return
			}
			v.Error = err.Error()
		}
		writeJSON(w, 200, v)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown control path")
	}
}
