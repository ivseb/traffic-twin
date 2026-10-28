package gate

import (
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

// maxDocCustomers bounds the customers whose document text is checked.
const maxDocCustomers = 50

// documentFindings checks the text the mock writes into the synthetic
// documents (docs/spec/mock.md 2.9) when a contract declares one: the fixed
// template of synthdoc.Lines filled with the world's customers (name and id)
// must use only synthetic values and must not trip the personal data
// detectors. Findings use file "documents" and the pointer of the customer
// line ("/<line>"), never the value.
func documentFindings(files []*parsed, in *Input, f *findings) {
	if !packHasDocuments(files) {
		return
	}
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	checked := 0
	for _, p := range files {
		if p.bad || p.kind != "world" {
			continue
		}
		for i, l := range p.lines {
			if checked >= maxDocCustomers {
				return
			}
			if t, _ := l.Get("type"); t.Str != "customer" {
				continue
			}
			checked++
			id, _ := l.Get("id")
			name := ""
			if prof, ok := l.Get("profile"); ok {
				if n, ok := prof.Get("name"); ok && n.Kind == ttjson.String {
					name = n.Str
				}
			}
			t := synthdoc.Text{Customer: name, Refs: []string{id.Str}, Date: date}
			ptr := "/" + strconv.Itoa(i+1)
			for _, v := range synthdoc.Values(t) {
				if !in.Prov.Synthetic[v] && !reSynID.MatchString(v) {
					f.add("documents", ptr, "document text value is not synthetic")
				}
			}
			for _, line := range synthdoc.Lines(t) {
				for _, r := range detect(line) {
					f.add("documents", ptr, "document text: "+r)
				}
			}
		}
	}
}

// packHasDocuments reports whether a contract of the pack declares a
// document: a document media type or a document schema in base64.
func packHasDocuments(files []*parsed) bool {
	found := false
	for _, p := range files {
		if p.bad || p.kind != "contract" || found {
			continue
		}
		walk(p.doc, "", nil, func(v ttjson.Value, _ string, keys []string, isKey bool) {
			if found {
				return
			}
			switch {
			case isKey && last(keys) == "content" && synthdoc.KindOfMedia(v.Str) != "":
				found = true
			case !isKey && v.Kind == ttjson.String && last(keys) == "contentMediaType" && synthdoc.KindOfMedia(v.Str) != "":
				found = true
			case !isKey && v.Kind == ttjson.String && last(keys) == "doc_type" && synthdoc.Known(strings.TrimSpace(v.Str)):
				found = true
			}
		})
	}
	return found
}
