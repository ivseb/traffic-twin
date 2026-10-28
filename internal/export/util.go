package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// outFile is one generated file, relative to the output directory.
type outFile struct {
	Path string
	Data []byte
}

// marshalJSON renders v as indented JSON with sorted object keys (Go sorts
// map keys), no HTML escaping and a trailing newline: same value, same bytes.
func marshalJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(fmt.Sprintf("export: marshal: %v", err)) // only unsupported types; programming error
	}
	return b.Bytes()
}

// marshalYAML renders v as YAML (yaml.v3 sorts map keys) after converting
// json.Number values to real numbers.
func marshalYAML(v any) []byte {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(normalize(v)); err != nil {
		panic(fmt.Sprintf("export: yaml: %v", err))
	}
	_ = enc.Close()
	return b.Bytes()
}

// normalize converts json.Number into int64 or float64 so YAML emits numbers.
func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = normalize(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x)
		}
		return out
	}
	return v
}

// deepCopy copies JSON-like values.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	}
	return v
}

func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return deepCopy(m).(map[string]any)
}

// setPath sets a dotted path (rules.md 2.1) creating intermediate objects.
func setPath(m map[string]any, path string, val any) {
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = val
}

// getPath reads a dotted path.
func getPath(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// stringify renders a scalar JSON value the way it appears in a URL.
func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// detUUID derives a stable RFC 4122 style (version 5 layout) id from a name.
func detUUID(parts ...string) string {
	h := sha256.Sum256([]byte("tt-export\x00" + strings.Join(parts, "\x00")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// round4 limits a float to four decimals so the output is short and stable.
func round4(f float64) float64 { return math.Round(f*1e4) / 1e4 }

// lognormalOf returns the log-normal parameters of a latency profile and
// whether they were derived (from p50/p95) rather than fitted by the gate.
func lognormalOf(l *Latency) (median, sigma float64, derived, ok bool) {
	if l == nil {
		return 0, 0, false, false
	}
	if l.Lognormal != nil && l.Lognormal.Median > 0 {
		return l.Lognormal.Median, l.Lognormal.Sigma, false, true
	}
	if l.P50 > 0 && l.P95 > l.P50 {
		// z(0.95) = 1.6449: p95 = median * exp(1.6449 * sigma)
		return float64(l.P50), round4(math.Log(float64(l.P95)/float64(l.P50)) / 1.6449), true, true
	}
	if l.P50 > 0 {
		return float64(l.P50), 0, true, true
	}
	return 0, 0, false, false
}

// safeName reduces a string to [A-Za-z0-9._-] for example and file names.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// fileEntry is a line of export-report "files".
type fileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
