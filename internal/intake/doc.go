// Package intake receives sanitized tt.http.exchange events from sources over
// OTLP/HTTP JSON (POST /v1/logs on the mTLS intake listener), drops every
// event the specification says to drop, watches the cardinality of what
// leaves in clear, and stores what it accepts. It is the second line of
// defense in zone B (docs/spec/event.md section 5, threat model M1, M9, M19,
// M21, S9 and guarantee G4): it never trusts the source, and it never "fixes"
// an event, it drops and counts it.
//
// # Checks
//
// For every event: size (512 KiB); exact canonical bytes and schema (package
// event); source.id equal to the identity in the certificate; known signed
// policy assigned to the group of the source and valid at the event time;
// service among the names allowed for the group (and the one assigned at
// enrollment); op, route_source and req.path consistent with the policy (a
// template route must exist in the policy; a raw route may only carry literal
// segments allowed by segments.allow or by the automatic words while they are
// active); hosts only when listed, or as host patterns whose literal labels
// pass the safe-label rule (docs/spec/sanitizer.md 3.5) while
// hosts.discovery is auto or discovery is active; and for every value
// that is not a drop or trunc form, the effective rule of the sanitizer's
// precedence (docs/spec/sanitizer.md 5.0) must be of the right kind: keep only
// where the rule is keep (within keep_max_bytes), tk1 only where it is hmac
// (with an accepted kid), num only where it is bucket(num) with the exact
// bounds of the rule, time only where it is bucket(time) of the same unit.
// OTLP envelope fields (resource attributes, trace and span ids, time) must
// agree with the event: anything else would be a side channel.
//
// # Cardinality, quarantine, discovery
//
// HyperLogLog sketches (no values are kept) count the distinct keep values
// per field, the literal names per parent, the literal segments per path
// position, the registrable domains of the host patterns per source and the
// literal host labels per (registrable domain, position). Beyond the
// threshold (50 by default) the element is quarantined: stored events are
// rewritten to the form the sanitizer would have produced (keep ->
// drop:str:<class>, names -> {*}, segments -> {drop:str:<class>}, host
// labels -> {*}), future events
// are rewritten before they are stored, the write-ahead log is truncated so
// the old values do not survive in it, an alarm is raised (audit log and
// [AlarmSink]) and the element appears in [Intake.Quarantines]. Closing and
// releasing are explicit ([Intake.CloseQuarantine], [Intake.ReleaseQuarantine]);
// the approvals they require are enforced by the caller. Discovery tokens
// (disc) are reduced to sketches per field ([Intake.Discovery]) and never
// stored.
//
// # Backpressure
//
// A bounded queue (events and bytes) separates the HTTP handlers from the
// single database writer. When it is full the intake answers 429 with
// Retry-After; when storage fails or the intake is closing, 503 with
// Retry-After. A request is accepted or refused as a whole: capacity for all
// its records is reserved before any is processed.
//
// # Storage
//
// Accepted events go to SQLite (tables intake_*, registered with the store
// migration registry in namespace "intake"): the canonical event plus scalar
// columns indexed for contract inference by (service, op, status, time), for
// the miner by time, trace and subject, and a token index partitioned by
// hour of reception. Read access for the analyzers is [Store]; retention is a
// purge by age ([Intake.Purge], run periodically). Tokens of accepted events
// are delivered at least once to keyguard's Bloom filter through [TokenSink],
// from a durable outbox.
//
// # Collaborators
//
// The fleet package implements [SourceRegistry] (identity, group, allowed
// services) and [PolicyRegistry] (signed policies by hash, as [Policy] built
// with [ParsePolicy]); keyguard's client implements [TokenSink]. In-memory
// fakes (MemSourceRegistry, MemPolicyRegistry, MemTokenSink, MemAlarmSink)
// are provided for tests. The intake listener must allow request bodies of at
// least 4 MiB (intake.http.max_body_bytes).
package intake
