package sanitizer

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"strings"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// maxSubjectBytes bounds the raw subject value (section 11).
const maxSubjectBytes = 8192

// extractSubject returns the raw subject value (section 11) or ok=false.
// The value never leaves the process: only its HMAC does.
func extractSubject(s *policy.Subject, n *normHeaders) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	var raw []byte
	found := false
	switch s.From {
	case "header":
		raw, found = n.get(asciiLower(s.Name))
	case "cookie":
		requestCookies(n, func(name, value []byte) {
			if !found && string(name) == s.Name {
				raw, found = value, true
			}
		})
	}
	if !found || len(raw) == 0 || len(raw) > maxSubjectBytes || !utf8.Valid(raw) {
		return nil, false
	}
	if s.From == "header" && s.JSONPath != "" {
		return jsonMember(raw, s.JSONPath)
	}
	if s.From == "header" {
		raw = stripBearer(raw)
		if len(raw) == 0 {
			return nil, false
		}
	}
	if s.JWTClaim == "" {
		return raw, true
	}
	return jwtClaim(raw, s.JWTClaim)
}

// stripBearer removes a case-insensitive "bearer" prefix followed by at
// least one space or tab, together with all following spaces and tabs.
func stripBearer(v []byte) []byte {
	if len(v) < 7 || !bytes.EqualFold(v[:6], []byte("bearer")) || (v[6] != ' ' && v[6] != '\t') {
		return v
	}
	return bytes.TrimLeft(v[6:], " \t")
}

// jwtClaim reads a top-level claim from an unverified compact JWS.
func jwtClaim(raw []byte, claim string) ([]byte, bool) {
	parts := bytes.Split(raw, []byte{'.'})
	if len(parts) != 3 {
		return nil, false
	}
	p := parts[1]
	// Optional padding: up to two '=', only at the end, and then the
	// padded length must be a multiple of 4.
	padded := len(p)
	for k := 0; k < 2 && len(p) > 0 && p[len(p)-1] == '='; k++ {
		p = p[:len(p)-1]
	}
	if padded != len(p) && padded%4 != 0 {
		return nil, false
	}
	for _, c := range p {
		if !isB64URL(c) {
			return nil, false
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(p))
	if err != nil {
		return nil, false
	}
	v, err := ttjson.Parse(payload, ttjson.ParseOptions{MaxDepth: 64})
	if err != nil || v.Kind != ttjson.Object {
		return nil, false
	}
	c, ok := v.Get(claim)
	if !ok {
		return nil, false
	}
	switch c.Kind {
	case ttjson.String:
		if c.Str == "" {
			return nil, false
		}
		return []byte(c.Str), true
	case ttjson.Number:
		if !numberUsable([]byte(c.Str)) {
			return nil, false
		}
		return ttjson.AppendCanonicalNumber(nil, []byte(c.Str)), true
	}
	return nil, false
}

// jsonMember reads the subject from a header whose value is a JSON object,
// or the base64/base64url encoding (padded or not) of one (spec v1.18):
// the members of the dotted path are walked from the root object (a dot
// separates members, it is never part of a name); a non-empty string or an
// in-range number at the end is the subject (numbers in canonical form,
// section 10.2). Parsed with the rules of section 9.2 (duplicates: the
// last wins); no bearer prefix is stripped.
func jsonMember(raw []byte, path string) ([]byte, bool) {
	doc := bytes.Trim(raw, " \t")
	if len(doc) == 0 {
		return nil, false
	}
	if doc[0] != '{' {
		dec, ok := decodeB64Any(doc)
		if !ok {
			return nil, false
		}
		doc = dec
	}
	// No nesting limit (section 9.2 validates the whole document): the raw
	// value is at most maxSubjectBytes long, so it cannot nest deeper.
	v, err := ttjson.Parse(doc, ttjson.ParseOptions{MaxDepth: maxSubjectBytes})
	if err != nil || v.Kind != ttjson.Object {
		return nil, false
	}
	for _, name := range strings.Split(path, ".") {
		if v.Kind != ttjson.Object {
			return nil, false
		}
		var ok bool
		if v, ok = v.Get(name); !ok {
			return nil, false
		}
	}
	switch v.Kind {
	case ttjson.String:
		if v.Str == "" {
			return nil, false
		}
		return []byte(v.Str), true
	case ttjson.Number:
		if !numberUsable([]byte(v.Str)) {
			return nil, false
		}
		return ttjson.AppendCanonicalNumber(nil, []byte(v.Str)), true
	}
	return nil, false
}

// decodeB64Any decodes standard or URL-safe base64, with or without
// padding (at most two '=' at the end, then a length multiple of 4); any
// other character, or both alphabets mixed, fails.
func decodeB64Any(p []byte) ([]byte, bool) {
	padded := len(p)
	for k := 0; k < 2 && len(p) > 0 && p[len(p)-1] == '='; k++ {
		p = p[:len(p)-1]
	}
	if len(p) == 0 || (padded != len(p) && padded%4 != 0) {
		return nil, false
	}
	url, std := false, false
	for _, c := range p {
		switch {
		case c == '-' || c == '_':
			url = true
		case c == '+' || c == '/':
			std = true
		case isB64URL(c):
		default:
			return nil, false
		}
	}
	if url && std {
		return nil, false
	}
	enc := base64.RawURLEncoding
	if std {
		enc = base64.RawStdEncoding
	}
	out, err := enc.DecodeString(string(p))
	if err != nil {
		return nil, false
	}
	return out, true
}

// SampledBy is the reason of a sampling decision.
type SampledBy string

// Sampling reasons.
const (
	ByBaggage   SampledBy = "baggage"
	BySubject   SampledBy = "subject"
	ByTrace     SampledBy = "trace"
	ByRandom    SampledBy = "random"
	ByInherited SampledBy = "inherited"
)

// Decision is the outcome of Sample.
type Decision struct {
	Sampled bool
	By      SampledBy
}

// SampleOptions configure Sample.
type SampleOptions struct {
	// RateBP overrides the policy rate when >= 0 and lower (Fleet
	// sampling_override_bp can only lower the rate). Use -1 for none.
	RateBP int
	// Rand returns a uniform integer in [0, 10000); nil uses math/rand/v2.
	Rand func() int
}

// Sample decides whether an exchange is sampled (section 12). It must be
// called before Sanitize; a non-sampled exchange is not sanitized at all.
func (e *Engine) Sample(ex *Exchange, o SampleOptions) Decision {
	rate := e.p.Sampling.RateBP
	if o.RateBP >= 0 && o.RateBP < rate {
		rate = o.RateBP
	}
	h := newHasher(e.key, e.epoch)
	if ex.Dir == Outbound {
		if ex.Inherited != nil {
			return Decision{Sampled: *ex.Inherited, By: ByInherited}
		}
	} else {
		n := normalizeHeaders(ex.ReqHeaders)
		if svc := e.byName[ex.ServiceName]; e.p.Sampling.TrustBaggage && svc != nil && svc.internal {
			if v, ok := baggageFlag(n); ok {
				return Decision{Sampled: v, By: ByBaggage}
			}
		}
		if subj, ok := extractSubject(e.p.Subject, n); ok {
			return Decision{Sampled: int(h.sample32(domainSample, subj)%10000) < rate, By: BySubject}
		}
	}
	if validTraceID(ex.TraceID) {
		return Decision{Sampled: int(h.sample32(domainSampleTrace, []byte(ex.TraceID))%10000) < rate, By: ByTrace}
	}
	var r int
	if o.Rand != nil {
		r = o.Rand()
	} else {
		r = rand.IntN(10000)
	}
	return Decision{Sampled: r < rate, By: ByRandom}
}

// validTraceID accepts 32 lower-case hex digits, not all zero.
func validTraceID(t string) bool {
	if len(t) != 32 {
		return false
	}
	zero := true
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(isDigit(c) || (c >= 'a' && c <= 'f')) {
			return false
		}
		if c != '0' {
			zero = false
		}
	}
	return !zero
}

// baggageFlag reads tt.s from the normalized baggage value: members split
// on ',', OWS trimmed, properties after ';' ignored, key and value trimmed;
// the first tt.s member with value 0 or 1 decides.
func baggageFlag(n *normHeaders) (bool, bool) {
	v, ok := n.get("baggage")
	if !ok {
		return false, false
	}
	for _, m := range bytes.Split(v, []byte{','}) {
		m = trimOWS(m)
		if i := bytes.IndexByte(m, ';'); i >= 0 {
			m = m[:i]
		}
		k, val, ok := bytes.Cut(m, []byte{'='})
		if !ok || string(trimOWS(k)) != "tt.s" {
			continue
		}
		switch string(trimOWS(val)) {
		case "1":
			return true, true
		case "0":
			return false, true
		}
	}
	return false, false
}
