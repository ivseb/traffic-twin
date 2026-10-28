// Package obi is the OpenTelemetry eBPF Instrumentation (OBI, formerly Grafana
// Beyla) adapter of traffic-twin: an optional capture source for applications
// that cannot carry an SDK. It is the process behind "tt obi".
//
// The bridge is deliberately small and sits next to OBI, on the same host:
//
//  1. it enrolls as a Fleet source of kind "obi" (internal/sourceclient), so
//     the policy, the kill switch and the heartbeat work as for every source;
//  2. it generates the OBI configuration from the signed policy
//     (GenerateConfig): OBI's own include/obfuscate rules are the FIRST filter
//     and deny everything the policy does not name;
//  3. it receives OBI's OTLP traces locally (OTLP/HTTP, JSON encoding) and
//     maps each HTTP span, with the header and body attributes OBI attached,
//     to the sanitizer input (Map);
//  4. the sanitizer (internal/sanitizer) is the second and authoritative
//     filter: only its canonical output leaves the process, as
//     tt.http.exchange events, through the source client's exporter.
//
// Raw span data is never forwarded, stored or logged: spans live in a bounded
// in-memory queue until a worker has sanitized them. The receiver binds to
// loopback by default because what it receives is raw.
package obi
