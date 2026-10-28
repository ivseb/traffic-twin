package mock

import "testing"

func TestConsolePagesApplied(t *testing.T) {
	e := newEnv(t)
	r := &consoleRunner{cfg: e.m.cfg}
	r.cur.Store(e.m)
	pc := payPage("https://app.test")
	r.applyPages(&pc)
	if e.m.page("pay") == nil || r.cfg.Pages == nil {
		t.Fatal("pages from the console not applied")
	}
	bad := PagesConfig{Pages: []Page{{ID: "x"}}}
	r.applyPages(&bad)
	if e.m.page("pay") == nil {
		t.Fatal("an invalid configuration replaced the pages")
	}
}
