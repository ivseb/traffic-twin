package mock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type seenCallback struct {
	method, path, sig, ctype string
	body                     string
}

// appServer plays the application under test: it records the callbacks.
func appServer(t *testing.T) (*httptest.Server, func() []seenCallback) {
	var mu sync.Mutex
	var got []seenCallback
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seenCallback{r.Method, r.URL.RequestURI(), r.Header.Get("X-Signature"), r.Header.Get("Content-Type"), string(b)})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seenCallback { mu.Lock(); defer mu.Unlock(); return append([]seenCallback(nil), got...) }
}

func payPage(app string) PagesConfig {
	return PagesConfig{Pages: []Page{{
		ID: "pay", Title: "Pagamento simulato", Show: []string{"amount"},
		ReturnURL: app + "/return?ref={ref}&outcome={action}&code={value.code}",
		Buttons: []Button{
			{Action: "approve", Label: "Approva", Values: map[string]string{"code": "AUTHORISED"}},
			{Action: "decline", Label: "Rifiuta", Values: map[string]string{"code": "REFUSED"}},
			{Action: "cancel", Label: "Annulla", NoCallback: true},
		},
		Callback: &Callback{Method: "POST", URL: app + "/api/payments/{ref}/notify",
			Body: `{"ref":"{ref}","status":"{value.code}","amount":"{query.amount}","customer":"{customer.id}"}`,
			HMAC: &HMAC{Header: "X-Signature", Key: "test-secret-key", Prefix: "sha256="}},
		Links: []PageLink{{Service: "shop-api", Op: "POST /orders", Path: "$.note", RefPath: "$.id"}},
		Auto:  map[string]string{"pay-declined": "decline"},
	}}}
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestThirdPartyPageInBrowser(t *testing.T) {
	app, calls := appServer(t)
	pc := payPage(app.URL)
	e := newEnv(t, withConfig(func(c *Config) { c.Pages = &pc }))
	sid := e.newSession(map[string]any{"seed": 1, "customer": "CUS-SYN-0001"})

	// the app asks its "gateway" (a contract operation) and gets the page URL
	r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
	if r.status != 201 {
		t.Fatalf("order: %d %s", r.status, r.body)
	}
	o := r.json()
	link, _ := o["note"].(string)
	if !strings.Contains(link, "/__pages/pay?") || !strings.Contains(link, "ref="+url.QueryEscape(o["id"].(string))) || !strings.Contains(link, "tt_session="+sid) {
		t.Fatalf("link: %q", link)
	}
	// the browser opens it (no X-TT-Session: the link carries the session)
	res, err := http.Get(link + "&amount=19.90")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(res.Body)
	res.Body.Close()
	csp := res.Header.Get("Content-Security-Policy")
	if res.StatusCode != 200 || !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "form-action 'self' "+app.URL) {
		t.Fatalf("page: %d csp %q", res.StatusCode, csp)
	}
	page := string(html)
	if strings.Contains(page, "<script") || strings.Contains(page, "http://") && strings.Contains(page, "src=") || !strings.Contains(page, "19.90") || !strings.Contains(page, ">Approva<") {
		t.Fatalf("html: %s", page)
	}
	action := between(page, `action="`, `"`)
	action = strings.ReplaceAll(action, "&amp;", "&")
	resp, err := noRedirect().PostForm(e.srv.URL+action, url.Values{"action": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 303 || !strings.HasPrefix(loc, app.URL+"/return?ref="+url.QueryEscape(o["id"].(string))) || !strings.Contains(loc, "outcome=approve&code=AUTHORISED") {
		t.Fatalf("redirect: %d %q", resp.StatusCode, loc)
	}
	cb := calls()
	if len(cb) != 1 || cb[0].method != "POST" || cb[0].path != "/api/payments/"+o["id"].(string)+"/notify" || cb[0].ctype != "application/json" {
		t.Fatalf("callback: %+v", cb)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(cb[0].body), &body); err != nil || body["status"] != "AUTHORISED" || body["amount"] != "19.90" || body["customer"] != "CUS-SYN-0001" {
		t.Fatalf("callback body: %s", cb[0].body)
	}
	mac := hmac.New(sha256.New, []byte("test-secret-key"))
	mac.Write([]byte(cb[0].body))
	if cb[0].sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature %q", cb[0].sig)
	}
	// a second click does nothing more
	resp, _ = noRedirect().PostForm(e.srv.URL+action, url.Values{"action": {"decline"}})
	resp.Body.Close()
	if resp.StatusCode != 200 || len(calls()) != 1 {
		t.Fatalf("second click: %d, callbacks %d", resp.StatusCode, len(calls()))
	}
	// the journal shows view, callback and completion
	j := string(e.ctl("GET", "/sessions/"+sid+"/journal", nil).body)
	for _, want := range []string{`"op":"view pay"`, `"op":"callback pay"`, `"op":"complete pay"`} {
		if !strings.Contains(j, want) {
			t.Fatalf("journal misses %s", want)
		}
	}
}

func TestThirdPartyPageControlAPI(t *testing.T) {
	app, calls := appServer(t)
	pc := payPage(app.URL)
	e := newEnv(t, withConfig(func(c *Config) { c.Pages = &pc }))
	sid := e.newSession(map[string]any{"seed": 1})

	// complete without a browser
	r := e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "decline", "query": map[string]any{"ref": "PAY-77", "amount": "5"}})
	if r.status != 200 {
		t.Fatalf("complete: %d %s", r.status, r.body)
	}
	v := r.json()
	if v["ref"] != "PAY-77" || !strings.Contains(v["return_url"].(string), "outcome=decline") || v["callback"].(map[string]any)["status"].(json.Number).String() != "204" {
		t.Fatalf("complete view: %v", v)
	}
	if c := calls(); len(c) != 1 || !strings.Contains(c[0].body, `"status":"REFUSED"`) {
		t.Fatalf("callbacks: %+v", c)
	}
	// cancel skips the callback
	if r := e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "cancel"}); r.status != 200 || len(calls()) != 1 {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "nope"}); r.status != 400 {
		t.Fatalf("unknown action: %d", r.status)
	}
	// auto: the browser is sent back at once
	if r := e.ctl("PUT", "/sessions/"+sid+"/pages/pay/auto", map[string]any{"action": "approve"}); r.status != 200 {
		t.Fatalf("auto: %d %s", r.status, r.body)
	}
	resp, err := noRedirect().Get(e.srv.URL + "/__pages/pay?tt_session=" + sid + "&ref=PAY-78")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "ref=PAY-78&outcome=approve") || len(calls()) != 2 {
		t.Fatalf("auto visit: %d %q %d", resp.StatusCode, resp.Header.Get("Location"), len(calls()))
	}
	// the configuration hides the key and is validated
	g := e.ctl("GET", "/pages", nil)
	if g.status != 200 || strings.Contains(string(g.body), "test-secret-key") {
		t.Fatalf("get pages: %d %s", g.status, g.body)
	}
	bad := payPage(app.URL)
	bad.Pages[0].Callback.URL = "{query.callback}"
	if r := e.ctl("PUT", "/pages", bad); r.status != 400 || !strings.Contains(string(r.body), "fixed http(s)://host/") {
		t.Fatalf("callback host from the request: %d %s", r.status, r.body)
	}
	bad = payPage(app.URL)
	bad.Pages[0].ReturnURL = "{query.back}"
	if r := e.ctl("PUT", "/pages", bad); r.status != 400 || !strings.Contains(string(r.body), "return_hosts") {
		t.Fatalf("open redirect: %d %s", r.status, r.body)
	}
	// a key left empty keeps the current one
	keep := payPage(app.URL)
	keep.Pages[0].Callback.HMAC.Key = ""
	keep.Pages[0].ReturnURL = "{query.back}"
	keep.Pages[0].ReturnHosts = []string{"127.0.0.1"}
	if r := e.ctl("PUT", "/pages", keep); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	if e.m.page("pay").Callback.HMAC.Key != "test-secret-key" {
		t.Fatal("key lost")
	}
	r = e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "approve", "query": map[string]any{"back": "https://evil.example/x"}})
	if v := r.json(); v["error"] == nil || v["return_url"] != nil {
		t.Fatalf("return host not allowed: %v", v)
	}
}

// The button chosen on the page changes the object the linked answer
// created, and the return URL comes from the request that created it.
func TestThirdPartyPageLinkedObjectAndReturn(t *testing.T) {
	app, _ := appServer(t)
	pc := payPage(app.URL)
	p := &pc.Pages[0]
	p.ReturnURL = "{link.return}"
	p.ReturnHosts = []string{"127.0.0.1"}
	p.Buttons[0].Set = map[string]any{"service": "EXPRESS-{value.code}"}
	p.Links = []PageLink{{Service: "shop-api", Op: "POST /orders", Path: "$.note", RefPath: "$.shipmentId", Entity: "shipment",
		ReturnFrom: &PageFrom{From: "req.body", Path: "$.returnUrl"}}}
	e := newEnv(t, withConfig(func(c *Config) { c.Pages = &pc }))
	sid := e.newSession(map[string]any{"seed": 1, "customer": "CUS-SYN-0001"})

	body := map[string]any{"items": orderBody["items"], "email": orderBody["email"], "returnUrl": app.URL + "/back?from=pay"}
	r := e.req("POST", "/__svc/shop-api/orders", body, sess(sid))
	if r.status != 201 {
		t.Fatalf("order: %d %s", r.status, r.body)
	}
	o := r.json()
	link, _ := o["note"].(string)
	if !strings.Contains(link, "tt_link=") || !strings.Contains(link, "ref="+url.QueryEscape(o["shipmentId"].(string))) {
		t.Fatalf("link: %q", link)
	}
	res, err := noRedirect().Get(link)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(html), "tt_link") {
		t.Fatal("the link id is shown on the page")
	}
	action := strings.ReplaceAll(between(string(html), `action="`, `"`), "&amp;", "&")
	if bad, err := noRedirect().PostForm(e.srv.URL+action, url.Values{"action": {"nope"}}); err != nil || bad.StatusCode != 400 {
		t.Fatalf("unknown button: %v %v", bad, err)
	}
	resp, err := noRedirect().PostForm(e.srv.URL+action, url.Values{"action": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != 303 || loc != app.URL+"/back?from=pay" {
		t.Fatalf("redirect: %d %q", resp.StatusCode, loc)
	}
	s := e.m.lookup(sid)
	s.mu.Lock()
	rec := s.ents["shipment"][o["shipmentId"].(string)]
	got := rec.state["service"]
	s.mu.Unlock()
	if got != "EXPRESS-AUTHORISED" {
		t.Fatalf("linked shipment: %v", got)
	}
	// without a browser: the reference finds the same link
	r = e.req("POST", "/__svc/shop-api/orders", body, sess(sid))
	ship := r.json()["shipmentId"].(string)
	v := e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "approve", "query": map[string]any{"ref": ship}}).json()
	if v["changed"] != "shipment "+ship || v["return_url"] != app.URL+"/back?from=pay" {
		t.Fatalf("complete: %v", v)
	}
	// a return URL whose host is not listed is refused
	bad := map[string]any{"items": orderBody["items"], "email": orderBody["email"], "returnUrl": "https://elsewhere.example/x"}
	r = e.req("POST", "/__svc/shop-api/orders", bad, sess(sid))
	ship = r.json()["shipmentId"].(string)
	v = e.ctl("POST", "/sessions/"+sid+"/pages/pay/complete", map[string]any{"action": "decline", "query": map[string]any{"ref": ship}}).json()
	if v["error"] == nil || v["return_url"] != nil {
		t.Fatalf("host not allowed: %v", v)
	}
	// validation
	for _, mut := range []func(p *Page){
		func(p *Page) { p.Buttons[0].Set = map[string]any{"a..b": 1} },
		func(p *Page) { p.Buttons[0].Set = map[string]any{"a": map[string]any{}} },
		func(p *Page) { p.Buttons[0].Set = map[string]any{"a": "{nope}"} },
		func(p *Page) { p.Links[0].Entity, p.Links[0].RefPath = "shipment", "" },
		func(p *Page) { p.Links[0].ReturnFrom = &PageFrom{From: "req.cookie", Name: "x"} },
		func(p *Page) { p.Links[0].ReturnFrom = &PageFrom{From: "req.body", Path: "returnUrl"} },
	} {
		c := payPage(app.URL)
		c.Pages[0].Links[0].ReturnFrom = &PageFrom{From: "req.query", Name: "back"}
		mut(&c.Pages[0])
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted: %+v", c.Pages[0])
		}
	}
}
