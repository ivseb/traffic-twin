package contract

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Documents in base64 (sanitizer shape drop:doc:<type>:<class>) become a
// document schema: x-tt-value format doc with its type and class, the JSON
// Schema content keywords, and a valid synthetic example (mock.md 2.9).
func TestDocumentShape(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 60; i++ {
		evs = append(evs, mkEv(t, evSpec{service: "docs-api", op: "GET /policies/{id}/document", dir: event.Inbound, status: 200,
			subject: tok(1000 + i%30), path: "/policies/" + tok(i) + "/document", at: t0.Add(time.Duration(i) * time.Second),
			resBody: fmt.Sprintf(`{"content":"drop:doc:pdf:%s","name":"drop:str:l32"}`, []string{"l16k", "l16k", "l128k"}[i%3])}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	s := c.Op("GET /policies/{id}/document").Response(200).Body[0].Schema.Prop("content").Schema
	if s.Shape != "doc" || s.DocType != "pdf" || s.DocClass != "l16k" {
		t.Fatalf("content: %+v", s)
	}
	b, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"contentEncoding":"base64"`, `"contentMediaType":"application/pdf"`, `"doc_class":"l16k"`, `"doc_type":"pdf"`, `"format":"doc"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("render misses %s: %.1500s", want, b)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(docExample("pdf"))
	if err != nil || !strings.HasPrefix(string(raw), "%PDF-") {
		t.Fatalf("example is not a pdf: %v", err)
	}
}
