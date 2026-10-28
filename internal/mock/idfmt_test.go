package mock

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// withIDFormats writes id formats into the demo contracts (as the world
// service does for a pack, docs/spec/pack.md 4.3). The formats are only
// examples of the general templates: a composite numeric id, and an id
// that carries a segment of another field.
func withIDFormats(formats map[string]string) envOpt {
	return withSpec(func(sp *packtest.Spec) {
		for path, b := range sp.Files {
			if !strings.HasPrefix(path, "contracts/") {
				continue
			}
			out, _, err := idfmt.Annotate(b, formats)
			if err != nil {
				panic(err)
			}
			sp.Files[path] = packtest.Canon(string(out))
		}
	})
}

func TestIDFormatsInSessions(t *testing.T) {
	e := newEnv(t, exact(), withIDFormats(map[string]string{
		"order":    "NN-NNNNNN",
		"shipment": "'SH'.{orderId#2}-NNNN",
	}))
	sid := e.newSession(map[string]any{"customer": "CUS-SYN-0007"})
	orderRE := regexp.MustCompile(`^[0-9]{2}-[0-9]{6}$`)
	a, b := e.order(sid), e.order(sid)
	if !orderRE.MatchString(a) || !orderRE.MatchString(b) || a == b {
		t.Fatalf("order ids %q %q: want two different ids of the format NN-NNNNNN", a, b)
	}
	// The same object keeps its id everywhere.
	r := e.req("GET", "/__svc/shop-api/orders/"+a, nil, sess(sid))
	if r.status != 200 || r.json()["id"] != a {
		t.Fatalf("GET order: %d %s", r.status, r.body)
	}
	e.advance(sid, "10m") // the shipment is created after 5m, visible once CREATED
	items := e.shipments(sid, a)
	if len(items) != 1 {
		t.Fatalf("shipments of %s: %v", a, items)
	}
	shp := items[0].(map[string]any)["shipmentId"].(string)
	// A join by a copied segment: the shipment carries segment 2 of its order.
	if want := "SH." + strings.Split(a, "-")[1] + "-"; !strings.HasPrefix(shp, want) || len(shp) != len(want)+4 {
		t.Fatalf("shipment id %q, want %sNNNN", shp, want)
	}
	if got := e.req("GET", "/__svc/shop-api/orders/"+a, nil, sess(sid)).json()["shipmentId"]; got != shp {
		t.Fatalf("order.shipmentId = %v, want %s", got, shp)
	}
	e.conforms("shop-api", "GET /orders/{id}", 200, e.req("GET", "/__svc/shop-api/orders/"+a, nil, sess(sid)))

	// Same sequence in another session (sessions are isolated, ids are
	// deterministic), and never one of the world's ids.
	other := e.newSession(nil)
	if c := e.order(other); c != a {
		t.Fatalf("the first order of a new session is %q, want %q as in the first session", c, a)
	}
	for _, we := range e.m.model.pack.World.Entities {
		if we.ID == a || we.ID == b {
			t.Fatalf("a session id repeats a world id: %s", we.ID)
		}
	}
}

func TestPackWorldIDsFollowTheFormat(t *testing.T) {
	tpl := idfmt.MustParse("NNNN.NNNN")
	id := tpl.ID(1, "order", nil)
	rewrite := withSpec(func(sp *packtest.Spec) {
		sp.Files["world.jsonl"] = []byte(strings.ReplaceAll(string(sp.Files["world.jsonl"]), "ORD-SYN-0042", id))
	})
	// With the format declared, the world's id is accepted and served.
	e := newEnv(t, withIDFormats(map[string]string{"order": tpl.String()}), rewrite)
	if r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, nil); r.status != 200 || r.json()["id"] != id {
		t.Fatalf("world order %s: %d %s", id, r.status, r.body)
	}
	// Without it, an id that is not <PREFIX>-SYN-NNNN is refused.
	spec := packtest.DemoSpec()
	spec.Files["world.jsonl"] = []byte(strings.ReplaceAll(string(spec.Files["world.jsonl"]), "ORD-SYN-0042", id))
	built, err := packtest.Build(t.TempDir()+"/pack", spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Pack: built.Dir, GatePubKeys: built.Keys, MaxPackAge: -1}); err == nil || !strings.Contains(err.Error(), "id format") {
		t.Fatalf("want a refused pack, got %v", err)
	}
}

func TestIDFormatSkipsWorldIDs(t *testing.T) {
	// The world already uses the first ids of the sequence: a session
	// continues after them.
	tpl := idfmt.MustParse("NNNNNN")
	e := newEnv(t, withIDFormats(map[string]string{"order": tpl.String()}))
	id := e.order("default")
	for n := uint64(1); n <= 3; n++ {
		if id == tpl.ID(n, "order", nil) {
			t.Fatalf("session reuses id #%d of the sequence (the world has 3 orders)", n)
		}
	}
	if id != tpl.ID(4, "order", nil) {
		t.Fatalf("got %s, want id #4 %s", id, tpl.ID(4, "order", nil))
	}
}
