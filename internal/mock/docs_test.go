package mock

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// withDocuments adds to shop-api a PDF download, a PNG download with a
// declared Content-Disposition, and a JSON answer carrying a document in
// base64 (x-tt-value format doc) and one with the JSON Schema content keywords.
func withDocuments(sp *packtest.Spec) {
	var doc map[string]any
	if err := json.Unmarshal(sp.Files["contracts/shop-api.openapi.json"], &doc); err != nil {
		panic(err)
	}
	obj := func(v string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			panic(err)
		}
		return m
	}
	paths := doc["paths"].(map[string]any)
	paths["/invoices/{id}/pdf"] = obj(`{"get":{"operationId":"invoicePdf",
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","content":{"application/pdf":{"schema":{"type":"string","format":"binary",
			"x-tt-value":{"kind":"shape","format":"doc","doc_type":"pdf","doc_class":"l16k"}}}}}}}}`)
	paths["/labels/{id}"] = obj(`{"get":{"operationId":"label",
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","headers":{"Content-Disposition":{"schema":{"type":"string"},"example":"inline; filename=\"x.bin\""}},
			"content":{"image/png":{"schema":{"type":"string","format":"binary"}}}}}}}`)
	paths["/policies/{id}/documents"] = obj(`{"get":{"operationId":"policyDocs",
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["name","content","scan"],
			"properties":{"name":{"type":"string"},
				"content":{"type":"string","x-tt-value":{"kind":"shape","format":"doc","doc_type":"pdf","doc_class":"l16k"}},
				"scan":{"type":"string","contentEncoding":"base64","contentMediaType":"image/png"}}},
			"example":{"name":"synthetic","content":"c3ludGhldGlj","scan":"c3ludGhldGlj"}}}}}}}`)
	b, _ := json.Marshal(doc)
	sp.Files["contracts/shop-api.openapi.json"] = packtest.Canon(string(b))
}

func TestDocumentResponses(t *testing.T) {
	e := newEnv(t, withSpec(withDocuments))
	sid := e.newSession(map[string]any{"seed": 1, "customer": "CUS-SYN-0001"})

	r := e.req("GET", "/__svc/shop-api/invoices/INV-SYN-0042/pdf", nil, sess(sid))
	if r.status != 200 || r.header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf: %d %v", r.status, r.header)
	}
	if !bytes.HasPrefix(r.body, []byte("%PDF-")) || !bytes.HasSuffix(r.body, []byte("%%EOF\n")) {
		t.Fatalf("not a pdf: %q", r.body[:20])
	}
	if n := len(r.body); n <= 1024 || n > 16384 {
		t.Fatalf("pdf of class l16k has %d bytes", n)
	}
	if r.header.Get("Content-Length") != itoaT(len(r.body)) {
		t.Fatalf("content-length %s for %d bytes", r.header.Get("Content-Length"), len(r.body))
	}
	if d := r.header.Get("Content-Disposition"); !strings.HasPrefix(d, "attachment;") || !strings.Contains(d, ".pdf") {
		t.Fatalf("disposition %q", d)
	}
	for _, want := range []string{"Reference: INV-SYN-0042", "Reference: CUS-SYN-0001", "Customer: "} {
		if !bytes.Contains(r.body, []byte(want)) {
			t.Fatalf("pdf text misses %q", want)
		}
	}

	r = e.req("GET", "/__svc/shop-api/labels/LBL-1", nil, sess(sid))
	if r.status != 200 || r.header.Get("Content-Type") != "image/png" {
		t.Fatalf("png: %d %v", r.status, r.header)
	}
	if _, err := png.Decode(bytes.NewReader(r.body)); err != nil {
		t.Fatalf("png: %v", err)
	}
	if d := r.header.Get("Content-Disposition"); !strings.HasPrefix(d, "inline;") || !strings.Contains(d, ".png") {
		t.Fatalf("declared disposition type kept, extension fixed: %q", d)
	}

	r = e.req("GET", "/__svc/shop-api/policies/POL-7/documents", nil, sess(sid))
	if r.status != 200 {
		t.Fatalf("json: %d %s", r.status, r.body)
	}
	body := r.json()
	pdf, err := base64.StdEncoding.DecodeString(body["content"].(string))
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf, []byte("POL-7")) {
		t.Fatalf("content is not a synthetic pdf: %v %q", err, pdf)
	}
	img, err := base64.StdEncoding.DecodeString(body["scan"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(img)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if body["name"] != "synthetic" {
		t.Fatalf("other fields from the example: %v", body["name"])
	}
	// the journal keeps a description, not the bytes
	j := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if !bytes.Contains(j.body, []byte("synthetic pdf document")) {
		t.Fatalf("journal: %s", j.body)
	}
}

func itoaT(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
