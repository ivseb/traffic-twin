package httpx

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	type in struct {
		A string `json:"a"`
	}
	cases := []struct {
		ct, body string
		ok       bool
	}{
		{"application/json", `{"a":"x"}`, true},
		{"application/json; charset=utf-8", `{"a":"x"}`, true},
		{"text/plain", `{"a":"x"}`, false},
		{"", `{"a":"x"}`, false},
		{"application/json", `{"a":"x","b":1}`, false},
		{"application/json", `{"a":"x"} {"a":"y"}`, false},
		{"application/json", `{"a":"` + strings.Repeat("x", 100) + `"}`, false},
		{"application/json", `{"a":`, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.body))
		r.Header.Set("Content-Type", c.ct)
		var v in
		err := DecodeJSON(httptest.NewRecorder(), r, 64, &v)
		if (err == nil) != c.ok {
			t.Errorf("%q %q: err = %v", c.ct, c.body, err)
		}
		if err != nil && (!errors.Is(err, ErrBadRequest) || strings.Contains(err.Error(), "xxx")) {
			t.Errorf("error leaks body or wrong type: %v", err)
		}
	}
}

func TestIDsAndClientIP(t *testing.T) {
	id := NewID("req_")
	if !ValidRequestID(id) || NewID("req_") == id {
		t.Errorf("id %q", id)
	}
	if RequestID(WithRequestID(context.Background(), id)) != id || RequestID(context.Background()) != "" {
		t.Error("request id context")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if ClientIP(r) != "2001:db8::1" {
		t.Errorf("client ip = %q (proxy headers must be ignored)", ClientIP(r))
	}
	rec := httptest.NewRecorder()
	WriteError(rec, 418, "teapot", "short and stout")
	if rec.Code != 418 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `"code":"teapot"`) {
		t.Errorf("WriteError: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
}
