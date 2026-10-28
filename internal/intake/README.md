# internal/intake

OTLP/HTTP JSON intake (`POST /v1/logs`, mTLS) of tt-core. Package documentation: `doc.go`.
Event decoding: `internal/event`.

## Documented hardenings (stricter than `schemas/event.v1.schema.json`)

The checks of `docs/spec/event.md` 5.1 are all implemented. The following go beyond the schema
text, to close covert channels or to enforce rules the sanitizer spec already states. Every
`event` vector of `conformance/` (384 at the time of writing) is accepted unchanged with them
on (`conformance_test.go`).

| Hardening | Why |
|---|---|
| Empty `query`, `headers`, `cookies` maps and an empty `resp` object are rejected | The sanitizer omits them (sanitizer.md 2, 10.1 rule 7); present-vs-absent would be a 1-bit channel |
| Literal names (JSON keys, query, cookie and header names) must obey the name rule of sanitizer.md 9.3 point 3 (no uuid/email/hex/digits/jwt, no run of 6+ digits); header names must be lowercase | A conformant sanitizer collapses such names to `{*}`; a literal one means a non-conformant source or a value hidden in a name |
| A header has exactly one value (except `{*}` and `{trunc}`) | sanitizer.md 8.0 point 4 joins repeated headers |
| Inbound `service` must be the name assigned at enrollment (`SourceInfo.ServiceName`) when the registry provides it, not just any name allowed for the group | event.md 1.2: the name is fixed at enrollment (S8) |
| Event time must be inside the policy window (`created_at` - 5 min, `not_after` + 5 min) | Replay of events under an expired or not yet existing policy |
| `disc`, `host:<name>` and automatic words are accepted only while active at the event time (+5 min skew) | The source ignores them after expiry |
| OTLP envelope must agree with the event: resource attributes, `service.name`, scope version, `tt.schema`, `tt.policy.hash`, `traceId`, `spanId`, `timeUnixNano`; no extra attributes or unknown fields | Anything else is a side channel next to the canonical body |
| Body shape follows the content type (JSON tree / form name map / only drop and trunc markers otherwise); arrays, keys and nesting are bounded by the policy limits | sanitizer.md 9.1 and limits |
| Template routes must name an operation declared by the policy and a path consistent with its template and the service base; raw routes may carry only drop tokens and allowed literal segments | event.md 5.1 point 6 (S9) |
| `ReasonMonitorOverflow`: an event that needs a new cardinality monitor beyond `MaxMonitors` is rejected | Fail closed instead of unbounded memory |

## Behaviour notes

- Quarantine states: `open` -> `closed` (policy closed the field) keep rewriting; only `release`
  (2 approvals, enforced by the caller) stops it.
- Rewriting a quarantined header/query/cookie name moves its values under `{*}` as an array.
- Cardinality thresholds use HyperLogLog estimates: the 51st distinct value can count as 50.
- The intake listener needs `intake.http.max_body_bytes` >= 4 MiB (the default of `internal/config`).
