package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

func TestInferTemplates(t *testing.T) {
	keys := []string{
		"GET /bookings/{drop:str:uuid}",
		"GET /bookings/{drop:str:l16}",
		"POST /bookings",
		"POST /bookings/{drop:str:uuid}/cancel",
		"GET /users/{tk1:k1:0000000000000000000001}/bookings",
		"GET /orders/{id}", // declared by a policy: untouched
		"GET /orders/export",
		"GET /health",
		"GET /v2/items",
		"GET /v3/items",
	}
	// Literal ids kept as words by auto_words: many distinct values.
	for i := 0; i < templateMinDistinct; i++ {
		keys = append(keys, fmt.Sprintf("GET /promo/%s", strings.Repeat(string(rune('a'+i)), 6)))
	}
	// Numeric ids next to each other.
	keys = append(keys, "GET /rooms/101", "GET /rooms/102")
	// Two parameters.
	keys = append(keys, "GET /users/{drop:str:s}/bookings/{drop:str:uuid}")
	got := inferTemplates(keys)
	for k, v := range got {
		if k == v {
			delete(got, k) // literal-only ops map to themselves
		}
	}
	want := map[string]string{
		"GET /bookings/{drop:str:uuid}":                       "GET /bookings/{id}",
		"GET /bookings/{drop:str:l16}":                        "GET /bookings/{id}",
		"POST /bookings/{drop:str:uuid}/cancel":               "POST /bookings/{id}/cancel",
		"GET /users/{tk1:k1:0000000000000000000001}/bookings": "GET /users/{id}/bookings",
		"GET /rooms/101":                                      "GET /rooms/{id}",
		"GET /rooms/102":                                      "GET /rooms/{id}",
		"GET /users/{drop:str:s}/bookings/{drop:str:uuid}":    "GET /users/{userId}/bookings/{bookingId}",
	}
	for i := 0; i < templateMinDistinct; i++ {
		want[fmt.Sprintf("GET /promo/%s", strings.Repeat(string(rune('a'+i)), 6))] = "GET /promo/{id}"
	}
	if !reflect.DeepEqual(got, want) {
		var lines []string
		for k, v := range got {
			if want[k] != v {
				lines = append(lines, fmt.Sprintf("%s -> %s (want %q)", k, v, want[k]))
			}
		}
		for k, v := range want {
			if _, ok := got[k]; !ok {
				lines = append(lines, fmt.Sprintf("missing %s -> %s", k, v))
			}
		}
		sort.Strings(lines)
		t.Fatalf("templates:\n%s", strings.Join(lines, "\n"))
	}
}

func TestParamNames(t *testing.T) {
	for in, want := range map[string]string{"bookings": "bookingId", "line-items": "lineItemId", "categories": "categoryId", "addresses": "addressId", "status": "statusId"} {
		if got := paramFromLiteral([]string{in, wildcard}, 1); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// memSource is an in-memory EventSource.
type memSource struct{ evs []*event.Event }

func (m *memSource) Scan(_ context.Context, q intake.Query, fn func(*intake.StoredEvent) error) error {
	for i, e := range m.evs {
		if (q.Service != "" && e.Service != q.Service) || (q.Op != "" && e.Op != q.Op) || (q.Status != 0 && e.Status != q.Status) {
			continue
		}
		if q.TraceID != "" && e.TraceID != q.TraceID {
			continue
		}
		if err := fn(&intake.StoredEvent{ID: int64(i + 1), Event: e}); err != nil {
			if err == intake.ErrStop {
				return nil
			}
			return err
		}
	}
	return nil
}

func (m *memSource) OpSummaries(context.Context, time.Time, time.Time) ([]intake.OpSummary, error) {
	by := map[[3]string]*intake.OpSummary{}
	for _, e := range m.evs {
		k := [3]string{e.Service, e.Op, fmt.Sprint(e.Status)}
		s := by[k]
		if s == nil {
			s = &intake.OpSummary{Service: e.Service, Op: e.Op, Dir: e.Dir, Status: e.Status, FirstTS: e.Time, LastTS: e.Time}
			by[k] = s
		}
		s.Count++
	}
	var out []intake.OpSummary
	for _, s := range by {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Op+fmt.Sprint(out[i].Status) < out[j].Op+fmt.Sprint(out[j].Status) })
	return out, nil
}

// A service whose policy declares no operation (every op is raw) gets a
// contract with templated paths.
func TestContractFromRawTraffic(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 60; i++ {
		id := []string{"{drop:str:uuid}", "{drop:str:l16}"}[i%2]
		e := mkEv(t, evSpec{service: "bookings-api", op: "GET /bookings/" + id, status: 200, subject: tok(i % 30),
			resBody: `{"id":"drop:str:uuid","status":"keep:CONFIRMED"}`, at: t0.Add(time.Duration(i) * time.Second)})
		e.RouteSource = event.RouteRaw
		evs = append(evs, e)
		p := mkEv(t, evSpec{service: "bookings-api", op: "POST /bookings", status: []int{201, 201, 201, 402}[i%4], subject: tok(i % 30),
			reqBody: `{"nights":"drop:int"}`, at: t0.Add(time.Duration(i) * time.Second)})
		p.RouteSource = event.RouteRaw
		evs = append(evs, p)
	}
	cs, err := InferFromStore(context.Background(), &memSource{evs}, InferOptions{Config: DefaultConfig()})
	if err != nil || len(cs) != 1 {
		t.Fatalf("contracts: %v %v", cs, err)
	}
	c := cs[0]
	var get *Op
	for _, op := range c.Ops {
		if op.Key == "GET /bookings/{id}" {
			get = op
		}
	}
	if get == nil || get.Calls != 60 || get.RouteSource != RouteInferred {
		t.Fatalf("templated op: %+v (ops %d)", get, len(c.Ops))
	}
	doc, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var oa struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(doc, &oa); err != nil {
		t.Fatal(err)
	}
	if _, ok := oa.Paths["/bookings/{id}"]["get"]; !ok {
		t.Fatalf("OpenAPI paths: %v", keysOf(oa.Paths))
	}
	if _, ok := oa.Paths["/bookings"]["post"]; !ok {
		t.Fatalf("POST /bookings (no parameter) must be in the contract too: %v", keysOf(oa.Paths))
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
