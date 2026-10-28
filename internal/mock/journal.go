package mock

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// journalEntry is one call received by the mock (control-api JournalEntry).
type journalEntry struct {
	Seq       int            `json:"seq"`
	At        string         `json:"at"`
	Wall      string         `json:"wall"`
	Service   *string        `json:"service"`
	Op        *string        `json:"op"`
	Method    string         `json:"method"`
	Path      string         `json:"path"`
	Query     string         `json:"query,omitempty"`
	Status    *int           `json:"status"`
	Matched   bool           `json:"matched"`
	Reason    string         `json:"reason,omitempty"`
	Pointer   string         `json:"pointer,omitempty"`
	NearestOp string         `json:"nearest_op,omitempty"`
	Fault     map[string]any `json:"fault,omitempty"`
	Triggered []triggered    `json:"triggered,omitempty"`
	Request   map[string]any `json:"request,omitempty"`
	Response  map[string]any `json:"response,omitempty"`
}

const maxJournalBody = 64 << 10

// Request headers recorded in the journal. Credentials (Authorization,
// Cookie) are never recorded.
var journalReqHeaders = []string{"Accept", "Content-Type", "Idempotency-Key", "Traceparent", "Tracestate", "User-Agent", "X-Request-Id", "X-Tt-Session"}

// skip is the identity header of identity sessions (never journaled, even
// when it is one of the recorded names).
func recordedRequestHeaders(h http.Header, skip string) map[string]any {
	out := map[string]any{}
	for _, name := range journalReqHeaders {
		if skip != "" && http.CanonicalHeaderKey(name) == skip {
			continue
		}
		if v := h.Values(name); len(v) > 0 {
			out[strings.ToLower(name)] = strings.Join(v, ", ")
		}
	}
	return out
}

func recordedResponseHeaders(h http.Header) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

// journalBody renders a captured body: parsed JSON when it is JSON, otherwise
// a (truncated) string.
func journalBody(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	if len(b) <= maxJournalBody {
		if v, err := decodeJSON(b); err == nil {
			return v
		}
	}
	if len(b) > maxJournalBody {
		b = b[:maxJournalBody]
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	return string(bytes.ToValidUTF8(b, nil))
}

func (s *session) appendJournal(e *journalEntry) {
	s.jseq++
	e.Seq = s.jseq
	if s.m.cfg.OnCall != nil {
		s.m.cfg.OnCall(s.callSummary(e))
	}
	size := int64(256)
	if b, err := json.Marshal(e); err == nil {
		size = int64(len(b))
	}
	s.journal = append(s.journal, e)
	s.jsizes = append(s.jsizes, size)
	s.jbytes += size
	drop := 0
	if max := s.m.cfg.JournalMax; max > 0 && len(s.journal) > max {
		drop = len(s.journal) - max
	}
	// Bound the bytes too (bodies up to 64 KiB each): oldest first, the
	// newest entry always stays.
	for i := 0; i < drop; i++ {
		s.jbytes -= s.jsizes[i]
	}
	for maxB := s.m.cfg.JournalMaxBytes; maxB > 0 && s.jbytes > maxB && drop < len(s.journal)-1; drop++ {
		s.jbytes -= s.jsizes[drop]
	}
	if drop > 0 {
		// Drop the oldest by reslicing (O(1)); append copies the live
		// entries when it grows the array, so a full journal no longer
		// copies all of its pointers on every request.
		clear(s.journal[:drop])
		s.journal = s.journal[drop:]
		s.jsizes = s.jsizes[drop:]
	}
}

// journalSince returns entries with seq greater than since (all when 0).
func (s *session) journalSince(since int) []*journalEntry {
	i := sort.Search(len(s.journal), func(i int) bool { return s.journal[i].Seq > since })
	return s.journal[i:]
}

func ndjson(entries []*journalEntry) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		_ = enc.Encode(e)
	}
	return buf.Bytes()
}

// har renders entries as a HAR 1.2 document. Timing is the injected latency
// (the mock does not measure wall-clock time, which keeps journals
// reproducible).
func har(entries []*journalEntry, version string) map[string]any {
	list := make([]any, 0, len(entries))
	for _, e := range entries {
		host := "mock"
		if e.Service != nil {
			host = *e.Service
		}
		url := "http://" + host + e.Path
		if e.Query != "" {
			url += "?" + e.Query
		}
		qs := []any{}
		if e.Query != "" {
			for _, kv := range strings.Split(e.Query, "&") {
				k, v, _ := strings.Cut(kv, "=")
				qs = append(qs, map[string]any{"name": k, "value": v})
			}
		}
		req := map[string]any{
			"method": e.Method, "url": url, "httpVersion": "HTTP/1.1",
			"cookies": []any{}, "headers": harHeaders(e.Request), "queryString": qs,
			"headersSize": -1, "bodySize": -1,
		}
		if body := e.Request["body"]; body != nil {
			req["postData"] = map[string]any{"mimeType": mimeOf(e.Request), "text": bodyText(body)}
			req["bodySize"] = len(bodyText(body))
		}
		resp := map[string]any{
			"status": 0, "statusText": "", "httpVersion": "HTTP/1.1",
			"cookies": []any{}, "headers": harHeaders(e.Response),
			"content":     map[string]any{"size": 0, "mimeType": "application/json"},
			"redirectURL": "", "headersSize": -1, "bodySize": -1,
		}
		if e.Status != nil {
			resp["status"] = *e.Status
			resp["statusText"] = http.StatusText(*e.Status)
		}
		if body := e.Response["body"]; body != nil {
			t := bodyText(body)
			resp["content"] = map[string]any{"size": len(t), "mimeType": mimeOf(e.Response), "text": t}
			resp["bodySize"] = len(t)
		}
		wait := 0
		if e.Fault != nil {
			if v, ok := e.Fault["latency_ms"].(int); ok {
				wait = v
			}
		}
		list = append(list, map[string]any{
			"startedDateTime": e.Wall, "time": wait, "request": req, "response": resp,
			"cache":   map[string]any{},
			"timings": map[string]any{"send": 0, "wait": wait, "receive": 0},
			"_tt": map[string]any{"seq": e.Seq, "at": e.At, "service": e.Service, "op": e.Op,
				"matched": e.Matched, "reason": e.Reason, "pointer": e.Pointer, "triggered": e.Triggered},
		})
	}
	return map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]any{"name": "traffic-twin mock", "version": version},
		"entries": list,
	}}
}

func harHeaders(m map[string]any) []any {
	out := []any{}
	h, _ := m["headers"].(map[string]any)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, _ := h[k].(string)
		out = append(out, map[string]any{"name": k, "value": v})
	}
	return out
}

func mimeOf(m map[string]any) string {
	if h, ok := m["headers"].(map[string]any); ok {
		if ct, ok := h["content-type"].(string); ok {
			return ct
		}
	}
	return "application/json"
}

func bodyText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return string(compactJSON(v))
}

func parseSince(q string) (int, bool) {
	if q == "" {
		return 0, true
	}
	n, err := strconv.Atoi(q)
	return n, err == nil && n >= 0
}

func wallNow(m *Mock) string { return m.cfg.Wall().UTC().Format(time.RFC3339Nano) }
