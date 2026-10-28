// Package sanitizer is the Go reference implementation of tt.sanitizer/v1
// (docs/spec/sanitizer.md). It applies the deny-by-default policy to HTTP
// exchanges in zone A, before any value leaves the application process.
//
// Engine.Sanitize is a pure, deterministic function of the exchange, the
// verified compiled policy, the local HMAC key and the source clock (used
// only for discovery expiry). Engine.Sample implements the sampling
// decision, which happens before sanitizing; BuildEvent builds the canonical
// tt.http.exchange/v1 event. Any error means: emit no event.
//
// The JSON tokenizer, number canonicalization and canonical writer live in
// the ttjson subpackage; encoding/json is never used on the output path.
package sanitizer
