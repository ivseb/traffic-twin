package gate

import (
	"net"
	"regexp"
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// PII detectors, the last line of defence (ARCHITECTURE 9). Contacts are
// accepted only with the names reserved for examples (RFC 2606, RFC 5737,
// RFC 3849 and the +39 555 phone prefix of docs/spec/pack.md 5).

var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)`)
	reURL      = regexp.MustCompile(`(?i)\b(?:https?|ftp)://([^/\s:?#@]+)`)
	rePhone    = regexp.MustCompile(`\+?\(?[0-9][0-9 ().-]{6,}[0-9]`)
	reDate     = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)
	reIBAN     = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\b`)
	reCard     = regexp.MustCompile(`\b[0-9](?:[ -]?[0-9]){12,18}\b`)
	reCF       = regexp.MustCompile(`(?i)\b[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]\b`)
	reIPv4     = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	reIPv6     = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	reJWT      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	reDigits   = regexp.MustCompile(`[0-9]{10,}`)
	reSynID    = regexp.MustCompile(`^[A-Z]{2,5}-SYN-[0-9]{4,}$`)
	reSynPhone = regexp.MustCompile(`^\+39 555[0-9 ]*$`)
	reUUID     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

func reservedHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, d := range []string{"example.com", "example.org", "example.net"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return h == "example" || strings.HasSuffix(h, ".example")
}

func docIP(ip net.IP) bool {
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func luhn(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func ibanValid(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	r := s[4:] + s[:4]
	mod := 0
	for _, c := range r {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
			mod = (mod*10 + v) % 97
			continue
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		default:
			return false
		}
		mod = (mod*100 + v) % 97
	}
	return mod == 1
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// detect returns the reasons a string looks like personal data.
func detect(s string) []string {
	if reSynID.MatchString(s) || reSynPhone.MatchString(s) {
		return nil
	}
	// UUIDs are identifiers, not numbers: their groups are not digit runs.
	s = reUUID.ReplaceAllString(s, "uuid")
	var out []string
	for _, m := range reEmail.FindAllStringSubmatch(s, -1) {
		if !reservedHost(m[1]) {
			out = append(out, "e-mail address outside the reserved example domains")
			break
		}
	}
	for _, m := range reURL.FindAllStringSubmatch(s, -1) {
		if !reservedHost(m[1]) {
			out = append(out, "URL outside the reserved example domains")
			break
		}
	}
	for _, m := range reIBAN.FindAllString(s, -1) {
		if ibanValid(m) {
			out = append(out, "IBAN-like value")
			break
		}
	}
	for _, m := range reCard.FindAllString(s, -1) {
		if luhn(onlyDigits(m)) {
			out = append(out, "payment card number (Luhn valid)")
			break
		}
	}
	if reCF.MatchString(s) {
		out = append(out, "Italian fiscal code")
	}
	for _, m := range reIPv4.FindAllString(s, -1) {
		if ip := net.ParseIP(m); ip != nil && !docIP(ip) {
			out = append(out, "IP address outside documentation ranges")
			break
		}
	}
	for _, m := range reIPv6.FindAllString(s, -1) {
		if strings.Count(m, ":") < 2 {
			continue
		}
		if ip := net.ParseIP(m); ip != nil && ip.To4() == nil && !docIP(ip) {
			out = append(out, "IP address outside documentation ranges")
			break
		}
	}
	if reJWT.MatchString(s) {
		out = append(out, "JWT-like token")
	}
	for _, m := range rePhone.FindAllString(s, -1) {
		if reDate.MatchString(m) {
			continue
		}
		d := onlyDigits(m)
		if len(d) >= 9 && len(d) <= 15 && !strings.HasPrefix(strings.TrimSpace(m), "+39 555") {
			out = append(out, "phone number outside the reserved prefix")
			break
		}
	}
	if reDigits.MatchString(s) {
		out = append(out, "long digit run")
	}
	return out
}

func piiCheck(files []*parsed, in *Input) Check {
	var f findings
	fs := packFormats(in)
	for _, p := range files {
		if p.bad {
			continue
		}
		each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
			switch v.Kind {
			case ttjson.String:
				// A namespace pattern of an XML body (x-tt-xml, sanitizer.md
				// 22.2 point 9): structure the mock must answer with; the
				// source already replaced its value-like runs with {*}.
				if !isKey && p.kind == "contract" && has(keys, xmlKeys) && event.ValidNSToken(v.Str) {
					return
				}
				// A generated id in a declared id format (pack.md 4.3).
				if !isKey && len(fs) > 0 && in.Prov.Synthetic[v.Str] && formatShaped(fs, v.Str) {
					return
				}
				for _, r := range detect(v.Str) {
					if isKey {
						r = "object key: " + r
					}
					f.add(p.path, ptr, r)
				}
			case ttjson.Number:
				d := strings.TrimLeft(strings.SplitN(strings.TrimPrefix(v.Str, "-"), ".", 2)[0], "0")
				if !strings.ContainsAny(v.Str, "eE") && len(d) >= 10 {
					f.add(p.path, ptr, "long digit run in a number")
				}
			}
		})
	}
	documentFindings(files, in, &f)
	return f.check(CheckPII, "tt-core")
}
