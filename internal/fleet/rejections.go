package fleet

import (
	"context"
	"sort"
	"strings"
	"time"
)

// maxLastErrorsShown bounds last_errors of a SourceStatus, as the heartbeat
// does.
const maxLastErrorsShown = 20

// windowedErrors turns the error list the source reported into a windowed
// view: only the errors seen within the last window, one entry per code with
// the time of the first and the last occurrence and their count, most recent
// last. The source's list is the last codes it saw, so an error that stopped
// leaves the view once the window passes; it never refreshes on a heartbeat
// (the time is the occurrence time given by the source). Codes only, never
// values.
func windowedErrors(errs []LastError, now time.Time, window time.Duration) []LastError {
	cutoff := now.Add(-window)
	byCode := map[string]*LastError{}
	var order []string
	for _, e := range errs {
		if e.At.Before(cutoff) {
			continue
		}
		at := e.At.UTC()
		le := byCode[e.Code]
		if le == nil {
			first, last := at, at
			le = &LastError{Code: e.Code, FirstSeen: &first, LastSeen: &last}
			byCode[e.Code] = le
			order = append(order, e.Code)
		}
		le.Count++
		if at.Before(*le.FirstSeen) {
			t := at
			le.FirstSeen = &t
		}
		if at.After(*le.LastSeen) {
			t := at
			le.LastSeen = &t
		}
	}
	out := make([]LastError, 0, len(order))
	for _, c := range order {
		le := byCode[c]
		le.At = *le.LastSeen
		out = append(out, *le)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.Before(*out[j].LastSeen) })
	return out
}

// appendIntakeRejections adds one entry per rejection reason the intake
// counted for the source within the window ("intake_rejected:resource_mismatch"
// with first_seen, last_seen and count), largest first. A source whose
// events are all rejected otherwise looks healthy: its heartbeat only says
// that something was rejected, not why. The totals since the source appeared
// are not repeated here (they are in the counters).
func appendIntakeRejections(errs []LastError, rejected []Rejection) []LastError {
	room := maxLastErrorsShown - len(errs)
	if room < 0 {
		room = 0
	}
	rs := append([]Rejection(nil), rejected...)
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Count != rs[j].Count {
			return rs[i].Count > rs[j].Count
		}
		return rs[i].Reason < rs[j].Reason
	})
	for _, r := range rs {
		if r.Count == 0 || room == 0 {
			continue
		}
		room--
		first, last := r.First.UTC(), r.Last.UTC()
		errs = append(errs, LastError{Code: "intake_rejected:" + r.Reason, At: last, FirstSeen: &first, LastSeen: &last, Count: int(r.Count)})
	}
	return errs
}

// EgressHosts maps the host names at which the applications reach tt-egress
// to the ids of the egress sources: the hostname each enrolled, non-revoked
// egress source reports as its instance, and the operator-declared
// Options.EgressHosts (which stand for every egress source). Lower case; a
// name may carry a port. The intake uses it to recognize an SDK call to the
// proxy (double capture).
func (f *Fleet) EgressHosts() map[string][]string {
	out := map[string][]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := f.db.QueryContext(ctx, `SELECT id, instance FROM fleet_sources WHERE kind = 'egress' AND revoked = 0`)
	if err != nil {
		return out
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id, inst string
		if rows.Scan(&id, &inst) != nil {
			continue
		}
		ids = append(ids, id)
		if inst = strings.ToLower(strings.TrimSpace(inst)); inst != "" {
			out[inst] = append(out[inst], id)
		}
	}
	for _, h := range f.opts.EgressHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out[h] = append(out[h], ids...)
		}
	}
	return out
}
