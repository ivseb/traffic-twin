// Package dateoff implements the relative dates of docs/spec/pack.md 4.4:
// a date field of a contract may carry x-tt-value.date_offset, the range of
// offsets between the field's date and the instant of the exchange
// ({"min": "+30d", "max": "+365d"}). The world generator and the mock then
// generate the field as clock + an offset drawn in that range, so a renewal
// stays "in a year" and a withdrawal window "within 15 days" whatever day
// the test runs.
//
// The range is learned by the contract inference from the bucket(time)
// values and the event timestamps (no new value leaves the sources), or set
// by a person in the console (Store), which wins.
package dateoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Key is the x-tt-value field of the range.
const Key = "date_offset"

// Range is a range of offsets, both ends included.
type Range struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

var offsetRE = regexp.MustCompile(`^[+-]?[0-9]{1,6}(h|d)$`)

// MaxOffset bounds an offset (about 100 years).
const MaxOffset = 36600 * 24 * time.Hour

// ParseOffset parses "+30d", "-12h", "0d".
func ParseOffset(s string) (time.Duration, error) {
	if !offsetRE.MatchString(s) {
		return 0, errors.New("an offset looks like +30d, -2d or +12h")
	}
	sign := time.Duration(1)
	switch s[0] {
	case '-':
		sign, s = -1, s[1:]
	case '+':
		s = s[1:]
	}
	n, _ := strconv.Atoi(s[:len(s)-1])
	unit := time.Hour
	if s[len(s)-1] == 'd' {
		unit = 24 * time.Hour
	}
	d := sign * time.Duration(n) * unit
	if d > MaxOffset || d < -MaxOffset {
		return 0, errors.New("an offset is at most 36600 days")
	}
	return d, nil
}

// Parse checks a range and returns its ends.
func (r Range) Parse() (lo, hi time.Duration, err error) {
	if lo, err = ParseOffset(r.Min); err != nil {
		return 0, 0, fmt.Errorf("min: %v", err)
	}
	if hi, err = ParseOffset(r.Max); err != nil {
		return 0, 0, fmt.Errorf("max: %v", err)
	}
	if lo > hi {
		return 0, 0, errors.New("min is after max")
	}
	return lo, hi, nil
}

// FormatOffset writes an offset in days when it is a whole number of days,
// otherwise in hours, always with its sign.
func FormatOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	if d%(24*time.Hour) == 0 {
		return sign + strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return sign + strconv.FormatInt(int64(d/time.Hour), 10) + "h"
}

// FromXTT reads the range of an x-tt-value annotation.
func FromXTT(xv map[string]any) (lo, hi time.Duration, ok bool) {
	m, _ := xv[Key].(map[string]any)
	if m == nil {
		return 0, 0, false
	}
	mn, _ := m["min"].(string)
	mx, _ := m["max"].(string)
	lo, hi, err := Range{Min: mn, Max: mx}.Parse()
	return lo, hi, err == nil
}

// Pick chooses an offset in [lo, hi] from frac in [0, 1): whole days when
// both ends are whole days, whole hours otherwise.
func Pick(lo, hi time.Duration, frac float64) time.Duration {
	if frac < 0 || frac >= 1 || math.IsNaN(frac) {
		frac = 0
	}
	unit := time.Hour
	if lo%(24*time.Hour) == 0 && hi%(24*time.Hour) == 0 {
		unit = 24 * time.Hour
	}
	steps := int64((hi - lo) / unit)
	return lo + time.Duration(int64(frac*float64(steps+1)))*unit
}

// Value is the generated date: now + an offset of the range, as a date
// ("2006-01-02") when format is "date", else as an RFC 3339 instant.
func Value(now time.Time, lo, hi time.Duration, frac float64, format string) string {
	t := now.Add(Pick(lo, hi, frac)).UTC()
	if format == "date" {
		return t.Format("2006-01-02")
	}
	return t.Format(time.RFC3339)
}

// DateLike reports whether a schema is a date field: format date or
// date-time, a bucket(time) value, or the date/datetime shape.
func DateLike(s map[string]any) bool {
	switch f, _ := s["format"].(string); f {
	case "date", "date-time":
		return true
	}
	xv, _ := s["x-tt-value"].(map[string]any)
	if u, _ := xv["unit"].(string); xv["kind"] == "bucket" && u != "" {
		return true
	}
	switch f, _ := xv["format"].(string); f {
	case "date", "datetime":
		return true
	}
	return false
}

// Annotate returns a copy of a contract document with the ranges chosen in
// the console written into x-tt-value.date_offset of every date property
// with one of those names (ranges keyed by property name). A property that
// has no x-tt-value gets one ({"kind": "shape"}).
func Annotate(doc []byte, ranges map[string]Range) ([]byte, error) {
	if len(ranges) == 0 {
		return doc, nil
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the contract")
	}
	var walk func(x any, depth int)
	walk = func(x any, depth int) {
		if depth > 64 {
			return
		}
		switch n := x.(type) {
		case map[string]any:
			if props, ok := n["properties"].(map[string]any); ok {
				names := make([]string, 0, len(props))
				for k := range props {
					names = append(names, k)
				}
				sort.Strings(names)
				for _, name := range names {
					r, ok := ranges[name]
					ps, isMap := props[name].(map[string]any)
					if !ok || !isMap || !DateLike(ps) {
						continue
					}
					xv, _ := ps["x-tt-value"].(map[string]any)
					if xv == nil {
						xv = map[string]any{"kind": "shape"}
						ps["x-tt-value"] = xv
					}
					xv[Key] = map[string]any{"min": r.Min, "max": r.Max}
				}
			}
			for _, e := range n {
				walk(e, depth+1)
			}
		case []any:
			for _, e := range n {
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
