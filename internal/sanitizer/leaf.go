package sanitizer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Reserved HMAC domains (sections 11, 12, 15).
const (
	domainSubject     = "subject"
	domainSample      = "sample"
	domainSampleTrace = "sample-trace"
	domainDiscovery   = "discovery"
)

// hasher computes HMAC-SHA256(key, epoch || 0x00 || domain || 0x00 || value).
// Not safe for concurrent use; one per sanitize run.
type hasher struct {
	mac   hash.Hash
	epoch []byte
	kid   string
	sum   [sha256.Size]byte
}

func newHasher(k Key, epoch []byte) *hasher {
	return &hasher{mac: hmac.New(sha256.New, k.secret), epoch: epoch, kid: k.Kid}
}

func (h *hasher) compute(domain string, val []byte) []byte {
	h.mac.Reset()
	h.mac.Write(h.epoch)
	h.mac.Write([]byte{0})
	h.mac.Write([]byte(domain))
	h.mac.Write([]byte{0})
	h.mac.Write(val)
	return h.mac.Sum(h.sum[:0])
}

// token returns "tk1:" + kid + ":" + base64url_nopad(mac[0:16]).
func (h *hasher) token(domain string, val []byte) string {
	m := h.compute(domain, val)
	b := make([]byte, 0, 5+len(h.kid)+22)
	b = append(b, "tk1:"...)
	b = append(b, h.kid...)
	b = append(b, ':')
	b = base64.RawURLEncoding.AppendEncode(b, m[:16])
	return string(b)
}

// discToken returns "tkd:" + base64url_nopad(HMAC(epoch||0||"discovery"||0||
// path||0||value)[0:4]) (section 15).
func (h *hasher) discToken(path string, val []byte) string {
	in := make([]byte, 0, len(path)+1+len(val))
	in = append(in, path...)
	in = append(in, 0)
	in = append(in, val...)
	m := h.compute(domainDiscovery, in)
	b := make([]byte, 0, 10)
	b = append(b, "tkd:"...)
	b = base64.RawURLEncoding.AppendEncode(b, m[:4])
	return string(b)
}

// sample32 returns the first 4 bytes of the MAC as a big-endian uint32.
func (h *hasher) sample32(domain string, val []byte) uint32 {
	m := h.compute(domain, val)
	return uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
}

// ---- Leaves ----

type leafKind uint8

const (
	leafNull leafKind = iota
	leafBool
	leafNum
	leafStr
)

// leaf is one scalar value. For strings s is valid UTF-8 unless lone is
// set (unpaired surrogate escape, always drop:str:invalid). For numbers s
// is the lexeme.
type leaf struct {
	kind  leafKind
	b     bool
	s     []byte
	isInt bool
	lone  bool
}

// Constant drop forms.
var (
	tokDropNull       = ttjson.Str("drop:null")
	tokDropBool       = ttjson.Str("drop:bool")
	tokDropInt        = ttjson.Str("drop:int")
	tokDropDec        = ttjson.Str("drop:dec")
	tokDropStrInvalid = ttjson.Str("drop:str:invalid")
	tokDropBytes      = ttjson.Str("drop:bytes")
	tokTruncDepth     = ttjson.Str("trunc:depth")
	tokTruncJSON      = ttjson.Str("trunc:invalid-json")
	tokTruncSize      = ttjson.Str("trunc:size")
)

// Number lexeme limits for keep, hmac, bucket and discovery (section 5.3).
const (
	maxNumLexeme   = 64
	maxNumExponent = 9999
)

// numberUsable reports a lexeme of at most 64 bytes whose written exponent
// (after e/E) has an absolute value <= 9999.
func numberUsable(lex []byte) bool {
	if len(lex) > maxNumLexeme {
		return false
	}
	i := bytes.IndexAny(lex, "eE")
	if i < 0 {
		return true
	}
	e := lex[i+1:]
	if len(e) > 0 && (e[0] == '+' || e[0] == '-') {
		e = e[1:]
	}
	v := 0
	for _, c := range e {
		v = v*10 + int(c-'0')
		if v > maxNumExponent {
			return false
		}
	}
	return true
}

var dropStrClass = map[string]ttjson.Value{}
var dropStrFormat = map[string]ttjson.Value{}

func init() {
	for _, c := range lenClassTable {
		dropStrClass[c.name] = ttjson.Str("drop:str:" + c.name)
	}
	dropStrClass["lmax"] = ttjson.Str("drop:str:lmax")
	for _, f := range []string{fmtUUID, fmtJWT, fmtEmail, fmtDatetime, fmtDate, fmtURL, fmtIPv4, fmtPhone, fmtDigits, fmtHex} {
		dropStrFormat[f] = ttjson.Str("drop:str:" + f)
	}
}

// dropStringForm returns the drop form of a valid UTF-8 string. With docs
// (bodies.docs, spec v1.19) a string that is the base64 of a document has
// the document shape drop:doc:<kind>:<class> (section 22.4).
func dropStringForm(s []byte, docs bool) ttjson.Value {
	if f := DetectFormat(s); f != "" {
		return dropStrFormat[f]
	}
	if docs {
		if d := base64Doc(s); d != "" {
			return ttjson.Str(d)
		}
	}
	return dropStrClass[LenClass(int64(len(s)))]
}

// dropForm returns the shape of a leaf (section 6.2, and 22.4 when
// bodies.docs is on).
func (r *run) dropForm(l *leaf) ttjson.Value {
	switch l.kind {
	case leafNull:
		return tokDropNull
	case leafBool:
		return tokDropBool
	case leafNum:
		if l.isInt {
			return tokDropInt
		}
		return tokDropDec
	}
	if l.lone {
		return tokDropStrInvalid
	}
	return dropStringForm(l.s, r.docs)
}

// applyLeaf applies action a (nil = default drop) to l. def reports whether
// the result is a drop by default (no rule), which is what discovery mode
// samples.
func (r *run) applyLeaf(l *leaf, a *policy.Action) (out ttjson.Value, def bool) {
	if l.kind == leafStr && l.lone {
		r.gqlUnusable(a)
		return tokDropStrInvalid, false
	}
	if a == nil {
		return r.dropForm(l), true
	}
	switch a.Kind {
	case policy.ActKeep:
		switch l.kind {
		case leafStr:
			if len(l.s) <= r.lim.KeepMaxBytes {
				return ttjson.Str("keep:" + string(l.s)), false
			}
		case leafNum:
			if numberUsable(l.s) {
				return ttjson.Num(string(l.s)), false
			}
		case leafBool:
			return ttjson.BoolV(l.b), false
		case leafNull:
			return ttjson.Value{Kind: ttjson.Null}, false
		}
	case policy.ActCode:
		// Section 5.6 (spec v1.11): a code-shaped string within
		// keep_max_bytes leaves as keep:, anything else as its shape.
		// Spec v1.19: the shape alnum is ^[A-Za-z0-9_.-]{1,16}$.
		if l.kind == leafStr && len(l.s) <= r.lim.KeepMaxBytes && policy.CodeShapeValue(a.Shape, l.s) {
			return ttjson.Str("keep:" + string(l.s)), false
		}
	case policy.ActGraphQL:
		if out, ok := r.graphqlLeaf(l); ok {
			return out, false
		}
	case policy.ActHMAC:
		switch l.kind {
		case leafStr:
			return ttjson.Str(r.h().token(a.Domain, l.s)), false
		case leafNum:
			if numberUsable(l.s) {
				return ttjson.Str(r.h().token(a.Domain, ttjson.AppendCanonicalNumber(nil, l.s))), false
			}
		}
	case policy.ActBucketNum:
		if l.kind == leafNum && numberUsable(l.s) {
			return ttjson.Str(numBucket(ttjson.ParseFloat(l.s), a.Bounds)), false
		}
	case policy.ActBucketTime:
		if l.kind == leafStr {
			if t := timeBucket(l.s, a.Unit); t != "" {
				return ttjson.Str(t), false
			}
		}
	}
	return r.dropForm(l), false
}

// numBucket implements bucket(num, bounds) on a double.
func numBucket(v float64, bounds []policy.Bound) string {
	if v < bounds[0].F { // bounds is never empty (policy.Validate)
		return "num:<" + bounds[0].Lexeme
	}
	for i := 0; i+1 < len(bounds); i++ {
		if v >= bounds[i].F && v < bounds[i+1].F {
			return "num:" + bounds[i].Lexeme + "-" + bounds[i+1].Lexeme
		}
	}
	return "num:>=" + bounds[len(bounds)-1].Lexeme
}

// canonicalRepr is the value representation of a leaf for HMAC and
// discovery (sections 7.2, 15). ok is false for values without one
// (invalid strings, numbers beyond the lexeme limits).
func canonicalRepr(l *leaf) (b []byte, ok bool) {
	switch l.kind {
	case leafStr:
		if l.lone {
			return nil, false
		}
		return l.s, true
	case leafNum:
		if !numberUsable(l.s) {
			return nil, false
		}
		return ttjson.AppendCanonicalNumber(nil, l.s), true
	case leafBool:
		return []byte(strconv.FormatBool(l.b)), true
	}
	return []byte("null"), true
}
