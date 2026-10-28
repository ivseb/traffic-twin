package obi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The types below are the part of the OTLP/HTTP JSON trace encoding the
// adapter needs (opentelemetry-proto, trace/v1 and common/v1). Unknown
// fields are ignored. OTLP/JSON writes 64-bit integers as strings, and some
// exporters write numbers: both are accepted.

// flexInt is an integer that is encoded as a JSON number or as a string.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer %q", s)
	}
	*f = flexInt(n)
	return nil
}

// Span kinds (SpanKind enum).
const (
	kindInternal = 1
	kindServer   = 2
	kindClient   = 3
)

// flexKind is an enum written as a number or as its name.
type flexKind int

func (k *flexKind) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	switch strings.TrimPrefix(strings.ToUpper(s), "SPAN_KIND_") {
	case "INTERNAL":
		*k = kindInternal
	case "SERVER":
		*k = kindServer
	case "CLIENT":
		*k = kindClient
	case "PRODUCER":
		*k = 4
	case "CONSUMER":
		*k = 5
	case "", "NULL", "UNSPECIFIED", "UNSET":
		*k = 0
	case "OK":
		*k = 1
	case "ERROR":
		*k = 2
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid enum %q", s)
		}
		*k = flexKind(n)
	}
	return nil
}

type anyValue struct {
	StringValue *string    `json:"stringValue"`
	IntValue    *flexInt   `json:"intValue"`
	BoolValue   *bool      `json:"boolValue"`
	DoubleValue *float64   `json:"doubleValue"`
	ArrayValue  *arrayVals `json:"arrayValue"`
}

type arrayVals struct {
	Values []anyValue `json:"values"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// str returns the value as a string (strings, integers, booleans), or false.
func (v anyValue) str() (string, bool) {
	switch {
	case v.StringValue != nil:
		return *v.StringValue, true
	case v.IntValue != nil:
		return strconv.FormatInt(int64(*v.IntValue), 10), true
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue), true
	}
	return "", false
}

// strs returns a string or an array of strings as a list.
func (v anyValue) strs() []string {
	if v.ArrayValue != nil {
		out := make([]string, 0, len(v.ArrayValue.Values))
		for _, e := range v.ArrayValue.Values {
			if s, ok := e.str(); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if s, ok := v.str(); ok {
		return []string{s}
	}
	return nil
}

// int returns the value as an integer, or false.
func (v anyValue) int() (int64, bool) {
	switch {
	case v.IntValue != nil:
		return int64(*v.IntValue), true
	case v.DoubleValue != nil:
		return int64(*v.DoubleValue), true
	case v.StringValue != nil:
		n, err := strconv.ParseInt(strings.TrimSpace(*v.StringValue), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// Span is one OTLP span.
type Span struct {
	TraceID      string     `json:"traceId"`
	SpanID       string     `json:"spanId"`
	ParentSpanID string     `json:"parentSpanId"`
	Name         string     `json:"name"`
	Kind         flexKind   `json:"kind"`
	StartNano    flexInt    `json:"startTimeUnixNano"`
	EndNano      flexInt    `json:"endTimeUnixNano"`
	Attributes   []keyValue `json:"attributes"`
	Status       struct {
		Code flexKind `json:"code"` // 2 = error
	} `json:"status"`
}

// ResourceSpans is the unit of the export request that carries the resource.
type ResourceSpans struct {
	Resource struct {
		Attributes []keyValue `json:"attributes"`
	} `json:"resource"`
	ScopeSpans []struct {
		Spans []Span `json:"spans"`
	} `json:"scopeSpans"`
}

// ServiceName returns the resource attribute service.name ("" when absent).
func (r *ResourceSpans) ServiceName() string {
	for _, kv := range r.Resource.Attributes {
		if kv.Key == "service.name" {
			s, _ := kv.Value.str()
			return s
		}
	}
	return ""
}

type exportRequest struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

// Errors of ParseExport.
var (
	ErrTooLarge = errors.New("obi: otlp request too large")
	ErrNotJSON  = errors.New("obi: otlp request is not JSON")
)

// ParseExport decodes an OTLP/HTTP JSON trace export. gz tells that the body
// is gzip-compressed (Content-Encoding). Both the compressed and the
// decompressed size are bounded by limit.
func ParseExport(body io.Reader, gz bool, limit int64) ([]ResourceSpans, error) {
	var r io.Reader = io.LimitReader(body, limit+1)
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, errors.New("obi: bad gzip")
		}
		defer zr.Close()
		r = io.LimitReader(zr, limit+1)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.New("obi: reading request failed")
	}
	if int64(len(raw)) > limit {
		return nil, ErrTooLarge
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, ErrNotJSON
	}
	var req exportRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		// The decoder message may quote payload bytes: do not return it.
		return nil, errors.New("obi: malformed otlp json")
	}
	return req.ResourceSpans, nil
}
