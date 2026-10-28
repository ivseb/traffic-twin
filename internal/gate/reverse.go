package gate

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

type candLoc struct {
	file, ptr string
	key       bool
}

// reverseHMAC is the pre-check of keyguard.md 3.4: every string, object key
// and number (canonical form) of every file goes to keyguard's match;
// keyguard answers one boolean per value and repeats the check when it signs.
func reverseHMAC(ctx context.Context, files []*parsed, in *Input) (Check, error) {
	type cand struct {
		c    client.Candidate
		locs []candLoc
	}
	byVal := map[string]*cand{}
	var total int64
	add := func(k string, c client.Candidate, l candLoc) {
		total++
		x := byVal[k]
		if x == nil {
			x = &cand{c: c}
			byVal[k] = x
		}
		if len(x.locs) < 3 {
			x.locs = append(x.locs, l)
		}
	}
	var f findings
	for _, p := range files {
		if p.bad {
			f.add(p.path, "", "file is not valid JSON and cannot be checked")
			continue
		}
		each(p, func(v ttjson.Value, ptr string, _ []string, isKey bool) {
			switch v.Kind {
			case ttjson.String:
				add("s"+v.Str, client.Str(v.Str), candLoc{p.path, ptr, isKey})
			case ttjson.Number:
				lex, err := ttjson.CanonicalNumber([]byte(v.Str))
				if err != nil {
					lex = v.Str
				}
				add("n"+lex, client.Num(lex), candLoc{p.path, ptr, false})
			}
		})
	}
	// Ids the mock generates at run time with the id formats (not in the
	// pack, so keyguard does not see them again when it signs).
	runtime := runtimeCandidates(packFormats(in), in)
	doms := make([]string, 0, len(runtime))
	for d := range runtime {
		doms = append(doms, d)
	}
	sort.Strings(doms)
	for _, d := range doms {
		for _, id := range runtime[d] {
			add("s"+id, client.Str(id), candLoc{idFormatsFile, "/" + escapePointer(d), false})
		}
	}
	keys := make([]string, 0, len(byVal))
	for k := range byVal {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	batch := in.MatchBatch
	if batch <= 0 {
		batch = 10000
	}
	for start := 0; start < len(keys); start += batch {
		end := min(start+batch, len(keys))
		cands := make([]client.Candidate, 0, end-start)
		for _, k := range keys[start:end] {
			cands = append(cands, byVal[k].c)
		}
		res, err := matchRetry(ctx, in, cands)
		if err != nil {
			return Check{}, err
		}
		for i, hit := range res.Matches {
			if !hit {
				continue
			}
			for _, l := range byVal[keys[start+i]].locs {
				reason := "matches a real token"
				if l.file == idFormatsFile {
					reason = "an id the mock would generate with this id format matches a real token: change the format"
				}
				if l.key {
					reason = "object key matches a real token"
				}
				f.add(l.file, l.ptr, reason)
			}
		}
	}
	c := f.check(CheckReverseHMAC, "keyguard")
	c.StringsChecked = &total
	return c, nil
}

// matchRetry calls keyguard, waiting on its rate limit (1 call/s by
// default) for up to two minutes.
func matchRetry(ctx context.Context, in *Input, cands []client.Candidate) (*client.MatchResult, error) {
	wait := 1100 * time.Millisecond
	for attempt := 0; ; attempt++ {
		res, err := in.Matcher.Match(ctx, in.Policies, cands)
		if err == nil {
			return res, nil
		}
		var ce *client.Error
		if !client.IsRateLimited(err) || attempt >= 100 || (errors.As(err, &ce) && ce.Code == "budget_exceeded") {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}
