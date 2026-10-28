package mock

import (
	"encoding/base64"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

// Synthetic documents (docs/spec/mock.md 2.9): a response declared with a
// document media type, or a JSON string field that the contract marks as a
// document in base64, gets a valid synthetic file of that type with the
// synthetic text of synthdoc.Lines.

// docMedia is a document response of the contract.
type docMedia struct {
	kind      string // synthdoc kind (pdf, png, ...)
	class     string // size class (x-tt-value.doc_class), "" if unknown
	mediaType string // the declared media type, as the contract writes it
}

// documentMedia picks the first document media type of a content map: a
// known document type (application/pdf, image/png, ...) or any media type
// whose schema names a document type in x-tt-value.doc_type.
func documentMedia(sc *schemaCtx, content any) *docMedia {
	cm, _ := content.(map[string]any)
	keys := make([]string, 0, len(cm))
	for k := range cm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		mt := strings.ToLower(strings.TrimSpace(strings.SplitN(k, ";", 2)[0]))
		media := sc.resolve(cm[k])
		var xv map[string]any
		if media != nil {
			if s := sc.flat(media["schema"], 0); s != nil {
				xv, _ = s["x-tt-value"].(map[string]any)
			}
		}
		kind := synthdoc.KindOfMedia(mt)
		if t, _ := xv["doc_type"].(string); kind == "" && synthdoc.Known(t) {
			kind = t
		}
		if kind == "" {
			continue
		}
		class, _ := xv["doc_class"].(string)
		return &docMedia{kind: kind, class: class, mediaType: mt}
	}
	return nil
}

// docSchema reports whether a string schema is a document in base64:
// x-tt-value.format "doc" with a known doc_type, or contentEncoding base64
// with a document contentMediaType.
func docSchema(s map[string]any) (kind, class string, ok bool) {
	if s == nil {
		return "", "", false
	}
	xv, _ := s["x-tt-value"].(map[string]any)
	class, _ = xv["doc_class"].(string)
	if f, _ := xv["format"].(string); f == "doc" {
		if t, _ := xv["doc_type"].(string); synthdoc.Known(t) {
			return t, class, true
		}
	}
	if enc, _ := s["contentEncoding"].(string); strings.EqualFold(enc, "base64") {
		if mt, _ := s["contentMediaType"].(string); synthdoc.KindOfMedia(mt) != "" {
			return synthdoc.KindOfMedia(mt), class, true
		}
	}
	return "", "", false
}

// docText is the synthetic text of the documents of one request: the
// session customer (name from the world profile, id), the parameters of the
// path (the ids the test asked for) and the virtual date.
func (s *session) docText(params map[string]string) synthdoc.Text {
	t := synthdoc.Text{Date: s.now}
	if s.customer != nil {
		t.Refs = append(t.Refs, *s.customer)
		if c := s.m.model.custByID[*s.customer]; c != nil {
			t.Customer = profileName(c.Profile)
		}
	}
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Refs = append(t.Refs, params[n])
	}
	return t
}

// profileName is the synthetic name of a world profile ("" if none).
func profileName(p map[string]any) string {
	if n, _ := p["name"].(string); n != "" {
		return n
	}
	return ""
}

// docBase64 generates a document for a JSON field.
func (b *builder) docBase64(kind, class string) any {
	t := synthdoc.Text{Date: b.now}
	if b.doc != nil {
		t = b.doc()
	}
	data, err := synthdoc.Generate(kind, class, t)
	if err != nil {
		return "c3ludGhldGlj"
	}
	return base64.StdEncoding.EncodeToString(data)
}

// documentResponse writes a synthetic file as the body of a document
// response, with consistent Content-Type, Content-Length and
// Content-Disposition.
func (s *session) documentResponse(r *response, hdr http.Header, t synthdoc.Text) []byte {
	data, err := synthdoc.Generate(r.doc.kind, r.doc.class, t)
	if err != nil {
		return nil
	}
	hdr.Set("Content-Type", r.doc.mediaType)
	hdr.Set("Content-Length", strconv.Itoa(len(data)))
	name := "document-" + t.Date.UTC().Format("20060102") + "." + synthdoc.Ext(r.doc.kind)
	disp := "attachment"
	if v := hdr.Get("Content-Disposition"); v != "" {
		// keep the declared disposition type, with a file name of the
		// right extension
		if d, _, err := mime.ParseMediaType(v); err == nil {
			disp = d
		}
	}
	hdr.Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	return data
}

// withDocs replaces, in a value taken from a contract example, the document
// fields of the schema with generated documents: an example carries a
// placeholder, never the document of this request.
func (b *builder) withDocs(schema any, v any, depth int) any {
	if depth > maxSchemaDepth || !b.sc.docs {
		return v
	}
	s := b.sc.flat(schema, 0)
	if kind, class, ok := docSchema(s); ok {
		if _, isStr := v.(string); isStr {
			return b.docBase64(kind, class)
		}
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for k, pv := range x {
			if ps, ok := props[k]; ok {
				x[k] = b.withDocs(ps, pv, depth+1)
			}
		}
	case []any:
		if items, ok := s["items"]; ok {
			for i := range x {
				x[i] = b.withDocs(items, x[i], depth+1)
			}
		}
	}
	return v
}

// hasDocSchema reports whether a contract document contains a document schema.
func hasDocSchema(v any, depth int) bool {
	if depth > 64 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		if _, _, ok := docSchema(x); ok {
			return true
		}
		for _, e := range x {
			if hasDocSchema(e, depth+1) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if hasDocSchema(e, depth+1) {
				return true
			}
		}
	}
	return false
}
