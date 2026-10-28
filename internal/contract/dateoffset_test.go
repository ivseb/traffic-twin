package contract

import (
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/event"
)

// renewals builds GET /policies/{id} exchanges whose renewalDate bucket is
// 30 to 365 days after the exchange, for n subjects.
func renewals(t *testing.T, events, subjects int) []*event.Event {
	var evs []*event.Event
	for i := 0; i < events; i++ {
		at := t0.Add(time.Duration(i) * 7 * time.Hour)
		off := 30 + (i*37)%336 // 30..365
		bucket := at.AddDate(0, 0, off).Format("2006-01-02")
		evs = append(evs, mkEv(t, evSpec{service: "policy-api", op: "GET /policies/{id}", dir: event.Inbound, status: 200,
			subject: tok(1000 + i%subjects), path: "/policies/" + tok(i), at: at,
			resBody: `{"renewalDate":"time:` + bucket + `","status":"keep:ACTIVE"}`}))
	}
	return evs
}

func TestDateOffsetLearned(t *testing.T) {
	c := inferAll(t, DefaultConfig(), nil, renewals(t, 400, 60))
	s := c.Op("GET /policies/{id}").Response(200).Body[0].Schema.Prop("renewalDate").Schema
	if s.DateOffset == nil {
		t.Fatalf("no offset learned: %+v", s)
	}
	lo, hi, err := s.DateOffset.Parse()
	if err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	if lo < 14*day || lo > 63*day || hi < 330*day || hi > 400*day {
		t.Fatalf("range %+v", s.DateOffset)
	}
	b, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"date_offset":{"max":"`+s.DateOffset.Max+`","min":"`+s.DateOffset.Min+`"}`) {
		t.Fatalf("render: %.1200s", b)
	}
}

func TestDateOffsetNeedsKSubjects(t *testing.T) {
	// 400 exchanges of 5 subjects: no end has k_min subjects, nothing is published
	c := inferAll(t, DefaultConfig(), nil, renewals(t, 400, 5))
	if s := c.Op("GET /policies/{id}").Response(200).Body[0].Schema.Prop("renewalDate").Schema; s.DateOffset != nil {
		t.Fatalf("offset published with 5 subjects: %+v", s.DateOffset)
	}
}

func TestRoundOutAndCoarse(t *testing.T) {
	if lo, hi := roundOut(3, 45, "d"); lo != 3 || hi != 49 {
		t.Fatalf("%d %d", lo, hi)
	}
	if lo, hi := roundOut(-400, 400, "d"); lo != -420 || hi != 420 {
		t.Fatalf("%d %d", lo, hi)
	}
	if coarse(400, "d") != 399 || coarse(-400, "d") != -406 || coarse(10, "d") != 10 {
		t.Fatal("coarse")
	}
	if dateoff.FormatOffset(-36*time.Hour) != "-36h" || dateoff.FormatOffset(48*time.Hour) != "+2d" {
		t.Fatal("format")
	}
}
