// Package event defines the tt.http.exchange/v1 event model shared by sources,
// intake, storage and the analyzers (docs/spec/event.md, schemas/event.v1.schema.json).
//
// The package is deliberately strict:
//
//   - [Decode] accepts only the exact canonical bytes of an event (tt-cjson,
//     docs/spec/sanitizer.md section 10). Spaces, alternative escapes, key
//     orders, number spellings, duplicate keys and empty maps are rejected,
//     because each of them would be a covert channel (threat model M21).
//   - Unknown fields are rejected everywhere (the schemas use
//     additionalProperties: false).
//   - Validation is a hand-written Go equivalent of the JSON schema plus the
//     token grammar of the sanitizer (section 6); no JSON-schema library.
//
// Errors never contain payload values: a [DecodeError] carries a stable Code
// and a static Detail naming the schema location.
//
// The helpers in helpers.go (body walking, token extraction, operation and
// path parsing) are meant for the downstream analyzers (contract inference,
// rule miner, drift).
package event
