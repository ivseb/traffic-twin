// Package export converts a twin pack into third-party mock formats
// (WireMock mappings, Microcks artifacts, Prism-ready OpenAPI) and reports,
// per target, what cannot be represented (time, probabilistic faults, latency
// distributions, state, batch calendars).
//
// The entry point is Run. Input comes from a Source; the exporter itself never
// verifies signatures or hashes (internal/pack does). Output is deterministic:
// the same Input always produces byte-identical files.
//
// Only public documentation of the target tools was used; see README.md.
package export
