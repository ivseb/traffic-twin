package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
)

// strictDecode decodes one JSON document into v rejecting unknown fields,
// wrong types and trailing data. ptr is the JSON Pointer (RFC 6901) of the
// offending field in the body when it can be identified, "" otherwise.
func strictDecode(data []byte, v any) (ptr string, err error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return "", fmt.Errorf("invalid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("trailing data after the JSON document")
	}
	if p, msg := checkShape(reflect.TypeOf(v), generic, ""); msg != "" {
		return p, fmt.Errorf("%s", msg)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return "", err
	}
	return "", nil
}

var shapeCache sync.Map // reflect.Type -> map[string]reflect.Type

func structFields(t reflect.Type) map[string]reflect.Type {
	if c, ok := shapeCache.Load(t); ok {
		return c.(map[string]reflect.Type)
	}
	m := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		m[name] = f.Type
	}
	shapeCache.Store(t, m)
	return m
}

// checkShape walks the decoded document next to the Go type and returns the
// first unknown field or type mismatch, in document order (keys sorted).
func checkShape(t reflect.Type, v any, ptr string) (string, string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if v == nil {
		return "", "" // null leaves the zero value
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return ptr, "expected an object"
		}
		fields := structFields(t)
		for _, k := range sortedKeys(m) {
			ft, known := fields[k]
			if !known {
				return ptr + "/" + escapePointer(k), "unknown field"
			}
			if p, msg := checkShape(ft, m[k], ptr+"/"+escapePointer(k)); msg != "" {
				return p, msg
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return ptr, "expected an array"
		}
		for i, e := range a {
			if p, msg := checkShape(t.Elem(), e, fmt.Sprintf("%s/%d", ptr, i)); msg != "" {
				return p, msg
			}
		}
	case reflect.String:
		if _, ok := v.(string); !ok {
			return ptr, "expected a string"
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return ptr, "expected a boolean"
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := v.(json.Number)
		if !ok || !isIntegral(n) {
			return ptr, "expected an integer"
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok || !isIntegral(n) || strings.HasPrefix(string(n), "-") {
			return ptr, "expected a non-negative integer"
		}
	case reflect.Float32, reflect.Float64:
		if _, ok := v.(json.Number); !ok {
			return ptr, "expected a number"
		}
	}
	return "", ""
}
