package world

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/fielddeps"
)

const timeLayout = "2006-01-02T15:04:05Z"

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// synth builds synthetic values from contract schemas. Every string it
// returns is registered as synthetic, except enum values (declared by the
// contract, k-filtered) which are not generated.
type synth struct {
	g    *generator
	cust *customer
	now  time.Time
	// relNow, when set, is the instant the relative dates count from
	// instead of now: t0 for the objects that exist before the window
	// (seeds), so a renewal "in 30 days" is still ahead when the mock
	// starts.
	relNow time.Time
}

func (s *synth) value(o *openapi, sch map[string]any, name string, depth int) (any, bool) {
	sch = o.resolve(sch)
	if sch == nil || depth > 6 {
		return nil, false
	}
	if c, ok := sch["const"]; ok {
		return c, true
	}
	if en, ok := sch["enum"].([]any); ok && len(en) > 0 {
		return en[s.g.r.intn(int64(len(en)))], true
	}
	xv, _ := sch["x-tt-value"].(map[string]any)
	if lo, hi, ok := dateoff.FromXTT(xv); ok {
		// a relative date (pack.md 4.4): the instant of the value + an
		// offset of the range
		base := s.now
		if !s.relNow.IsZero() {
			base = s.relNow
		}
		return s.g.tag(dateoff.Value(base, lo, hi, s.g.r.float(), dateFormat(sch, xv))), true
	}
	kind, _ := xv["kind"].(string)
	switch kind {
	case "enum":
		if en, ok := xv["enum"].([]any); ok && len(en) > 0 {
			return en[s.g.r.intn(int64(len(en)))], true
		}
		return nil, false
	case "id":
		dom, _ := xv["domain"].(string)
		return s.g.tag(s.g.opaqueID(dom)), true
	case "bucket":
		if u, _ := xv["unit"].(string); u != "" {
			// bucket(time): a date, the instant of the value
			return s.g.tag(dateoff.Value(s.now, 0, 0, 0, dateFormat(sch, xv))), true
		}
		return s.bucket(xv, sch), true
	}
	format, _ := sch["format"].(string)
	if f, _ := xv["format"].(string); f != "" {
		format = f
	}
	switch mainType(sch) {
	case "object":
		return s.object(o, sch, depth), true
	case "array":
		it, _ := sch["items"].(map[string]any)
		n := s.g.r.between(1, 2)
		if mi, ok := numOf(sch["minItems"]); ok && int64(mi) > n {
			n = int64(mi)
		}
		if mx, ok := numOf(sch["maxItems"]); ok && int64(mx) < n {
			n = int64(mx)
		}
		arr := []any{}
		for i := int64(0); i < n; i++ {
			if v, ok := s.value(o, it, name, depth+1); ok {
				arr = append(arr, v)
			}
		}
		return arr, true
	case "integer":
		lo, hi := int64(1), int64(5)
		if v, ok := numOf(sch["minimum"]); ok {
			lo = int64(math.Ceil(v))
			if hi < lo {
				hi = lo + 4
			}
		}
		if v, ok := numOf(sch["maximum"]); ok {
			hi = int64(math.Floor(v))
		}
		if hi < lo {
			hi = lo
		}
		return json.Number(strconv.FormatInt(s.g.r.between(lo, hi), 10)), true
	case "number":
		lo, hi := 1.0, 200.0
		if v, ok := numOf(sch["minimum"]); ok {
			lo = v
			if hi < lo {
				hi = lo + 100
			}
		}
		if v, ok := numOf(sch["maximum"]); ok {
			hi = v
		}
		cents := s.g.r.between(int64(math.Ceil(lo*100)), int64(math.Floor(hi*100)))
		return json.Number(strconv.FormatFloat(float64(cents)/100, 'f', -1, 64)), true
	case "boolean":
		return s.g.r.intn(2) == 1, true
	case "string":
		return s.g.tag(s.str(name, format)), true
	}
	return nil, false
}

// dateFormat is "date" for a date field, "date-time" otherwise.
func dateFormat(sch, xv map[string]any) string {
	if f, _ := sch["format"].(string); f == "date" {
		return "date"
	}
	if f, _ := xv["format"].(string); f == "date" {
		return "date"
	}
	return "date-time"
}

func (s *synth) bucket(xv, sch map[string]any) any {
	bounds, _ := xv["bounds"].([]any)
	ps, _ := xv["bucket_p"].([]any)
	var b []float64
	for _, x := range bounds {
		if f, ok := numOf(x); ok {
			b = append(b, f)
		}
	}
	if len(b) == 0 {
		return json.Number("1")
	}
	w := make([]float64, len(b)+1)
	for i := range w {
		w[i] = 1
		if i < len(ps) {
			w[i], _ = numOf(ps[i])
		}
	}
	// Bucket i: [b[i-1], b[i]); the open ends are clamped near the bounds.
	i := s.g.r.weighted(w)
	var lo, hi float64
	switch {
	case i == 0:
		lo, hi = b[0]-math.Max(1, math.Abs(b[0])/2), b[0]
	case i >= len(b):
		lo, hi = b[len(b)-1], b[len(b)-1]+math.Max(1, math.Abs(b[len(b)-1])/2)
	default:
		lo, hi = b[i-1], b[i]
	}
	if mainType(sch) == "integer" {
		top := int64(math.Ceil(hi)) - 1
		if top < int64(math.Ceil(lo)) {
			top = int64(math.Ceil(lo))
		}
		return json.Number(strconv.FormatInt(s.g.r.between(int64(math.Ceil(lo)), top), 10))
	}
	v := lo + (hi-lo)*s.g.r.float()
	v = math.Floor(v*100) / 100
	return json.Number(strconv.FormatFloat(v, 'f', -1, 64))
}

func (s *synth) object(o *openapi, sch map[string]any, depth int) map[string]any {
	out := map[string]any{}
	props, _ := sch["properties"].(map[string]any)
	req := map[string]bool{}
	if rl, ok := sch["required"].([]any); ok {
		for _, x := range rl {
			if n, ok := x.(string); ok {
				req[n] = true
			}
		}
	}
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ps, _ := props[n].(map[string]any)
		if !req[n] {
			p := 0.5
			if v, ok := numOf(o.resolve(ps)["x-tt-presence"]); ok {
				p = v
			}
			if s.g.r.float() >= p {
				continue
			}
		}
		if v, ok := s.special(n); ok {
			out[n] = v
			continue
		}
		if v, ok := s.value(o, ps, n, depth+1); ok {
			out[n] = v
		}
	}
	s.dependencies(o, sch, out, req)
	return out
}

// dependencies makes a generated object hold only observed combinations of
// its dependent fields (x-tt-dependencies): the values drawn first are kept
// when compatible, the others are drawn among the combinations that agree
// with them (conditional sampling).
func (s *synth) dependencies(o *openapi, sch, out map[string]any, req map[string]bool) {
	deps := fielddeps.Parse(sch)
	if len(deps) == 0 {
		return
	}
	props, _ := sch["properties"].(map[string]any)
	fielddeps.Enforce(deps, out, fielddeps.Options{
		Required: func(f string) bool { return req[f] },
		Choose:   func(n int) int { return int(s.g.r.intn(int64(n))) },
		Make: func(f string, v fielddeps.Value) any {
			if !v.Band {
				return v.Lit
			}
			ps, _ := props[f].(map[string]any)
			integer := mainType(o.resolve(ps)) == "integer"
			x := fielddeps.BandNumber(v, integer, s.g.r.float())
			if integer {
				return json.Number(strconv.FormatInt(int64(x), 10))
			}
			return json.Number(strconv.FormatFloat(x, 'f', -1, 64))
		},
	})
}

// special fills well-known customer fields from the synthetic customer.
func (s *synth) special(name string) (any, bool) {
	if s.cust == nil {
		return nil, false
	}
	switch strings.ToLower(name) {
	case "customerid", "customer_id":
		return s.cust.id, true
	case "email":
		return s.cust.p.email, true
	case "name", "fullname", "customername", "full_name":
		return s.cust.name, true
	case "firstname", "first_name":
		return s.cust.p.first, true
	case "lastname", "last_name":
		return s.cust.p.last, true
	case "phone", "phonenumber", "phone_number":
		return s.cust.p.phone, true
	}
	return nil, false
}

func (s *synth) str(name, format string) string {
	r := s.g.r
	switch format {
	case "email":
		if s.cust != nil {
			return s.cust.p.email
		}
		return fmt.Sprintf("user%04d@example.com", r.intn(10000))
	case "date-time", "datetime":
		return fmtTime(s.now)
	case "date":
		return s.now.UTC().Format("2006-01-02")
	case "uuid":
		a, b := r.next(), r.next()
		return fmt.Sprintf("%08x-%04x-4%03x-%04x-%012x", a>>32, (a>>16)&0xffff, a&0xfff, 0x8000|(b>>48)&0x3fff, b&0xffffffffffff)
	case "url", "uri":
		return fmt.Sprintf("https://shop.example/r/%04d", r.intn(10000))
	case "ipv4":
		return fmt.Sprintf("192.0.2.%d", 1+r.intn(254))
	case "phone":
		return fmt.Sprintf("+39 555 %03d %04d", r.intn(1000), r.intn(10000))
	case "digits":
		return fmt.Sprintf("%06d", r.intn(1000000))
	case "hex":
		return fmt.Sprintf("%016x", r.next())
	case "jwt":
		return fmt.Sprintf("syn-token-%04d", r.intn(10000))
	}
	if v, ok := s.special(name); ok {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return fmt.Sprintf("syn-%s-%04d", words[r.intn(int64(len(words)))], r.intn(10000))
}
