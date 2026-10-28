package audit

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strconv"
)

// ActorFunc extracts the authenticated actor and request id from a request.
// The server package supplies it (audit does not depend on auth).
type ActorFunc func(r *http.Request) (actor Actor, requestID string)

const maxExportLimit = 100000

// ExportHandler streams entries as JSON Lines (application/x-ndjson).
// Forward paging: after_seq (default 0) and limit (default and max 100000).
// Tail paging: last=N returns the newest N entries and before_seq=S the
// entries below S (at most limit, or last when given), always in ascending
// order, so that a reader can start from the end of a long log and walk
// backwards with before_seq = the first seq it received. Tail and forward
// paging cannot be combined. The export itself is audited before any entry
// is written. Mount it behind the auditor role.
func (l *Log) ExportHandler(actor ActorFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		q := r.URL.Query()
		after, err1 := parseInt(q.Get("after_seq"), 0)
		limit, err2 := parseInt(q.Get("limit"), maxExportLimit)
		last, err3 := parseInt(q.Get("last"), 0)
		before, err4 := parseInt(q.Get("before_seq"), 0)
		_, hasLast := q["last"]
		_, hasBefore := q["before_seq"]
		tail := hasLast || hasBefore
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || after < 0 || limit < 1 || limit > maxExportLimit ||
			(hasLast && (last < 1 || last > maxExportLimit)) || (hasBefore && before < 1) {
			writeError(w, http.StatusBadRequest, "invalid_query", "after_seq must be >= 0, before_seq >= 1, limit and last in [1, 100000]")
			return
		}
		if tail && q.Get("after_seq") != "" {
			writeError(w, http.StatusBadRequest, "invalid_query", "after_seq cannot be combined with last or before_seq")
			return
		}
		count := limit
		if hasLast {
			count = last
		}
		a, reqID := actor(r)
		details := map[string]string{"after_seq": strconv.FormatInt(after, 10), "limit": strconv.FormatInt(limit, 10)}
		if tail {
			details = map[string]string{"last": strconv.FormatInt(count, 10)}
			if hasBefore {
				details["before_seq"] = strconv.FormatInt(before, 10)
			}
		}
		if _, err := l.Record(r.Context(), Event{
			Actor: a, Action: "audit.export", Target: Target{Type: "audit_log"},
			Outcome: Success, RequestID: reqID, Details: details,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="tt-audit.jsonl"`)
		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		// Headers are sent with the first entry: an error after that point
		// can only truncate the stream; the verifier detects a short export
		// by comparing with /verify's head.
		emit := func(e Entry) error { return enc.Encode(e) }
		if tail {
			_ = l.IterateTail(r.Context(), before, int(count), emit)
		} else {
			_ = l.Iterate(r.Context(), after, int(limit), emit)
		}
		_ = bw.Flush()
	})
}

// VerifyHandler runs Verify and reports {ok, entries, head_seq, head_hash}.
func (l *Log) VerifyHandler(actor ActorFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		res, err := l.Verify(r.Context())
		ok := err == nil
		a, reqID := actor(r)
		outcome := Success
		if !ok {
			outcome = Failure
		}
		_, _ = l.Record(r.Context(), Event{Actor: a, Action: "audit.verify", Target: Target{Type: "audit_log"}, Outcome: outcome, RequestID: reqID})
		body := map[string]any{"ok": ok, "entries": res.Entries, "head_seq": res.HeadSeq, "head_hash": res.HeadHash, "archived": res.Archived, "segments": res.Segments}
		if !ok {
			body["error"] = err.Error() // describes positions only, never content
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}

func parseInt(s string, def int64) (int64, error) {
	if s == "" {
		return def, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}
