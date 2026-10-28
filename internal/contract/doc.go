// Package contract infers API contracts (OpenAPI 3.1 with x-tt-* extensions,
// docs/spec/pack.md section 4) from the tokenized events held by the intake
// store, keeps periodic versioned snapshots and diffs them.
//
// # Pipeline
//
//		intake.Store --Scan--> Inferrer --> []*Contract --> Snapshot (SQLite) --> Diff
//		                           |                              |
//		                           +- Render (OpenAPI JSON/YAML)  +- drift.Manager
//
//	  - An [Inferrer] aggregates events by (service, op, status) in a single
//	    streaming pass with bounded memory: schema trees with type unions,
//	    nullability, field presence, shape tokens (formats, length classes),
//	    keep values (enums), HMAC id fields, numeric and time buckets, array
//	    items, header, query and cookie parameters, status frequencies and
//	    latency quantiles. Path templates come from the events (policy
//	    templates or framework routes): nothing is re-templated here.
//	  - k-anonymity: a keep value is published in an enum only when it was seen
//	    for at least KMin distinct subjects (the event subject, or the subject
//	    of the inbound event of the same trace for outbound calls). Bucket
//	    bands follow the same rule. Hidden values set enum_partial.
//	  - [Contract.OpenAPI] renders the model deterministically (sorted keys,
//	    canonical JSON via [CanonicalJSON], YAML via [YAML]). Examples (OK and
//	    KO) are generated from annotations only, with invented placeholder
//	    values; stored events contain no values to copy anyway.
//	  - [Engine] produces a snapshot per window (default 24 h), stores it in
//	    the "contract" namespace and calls the registered snapshot hooks (the
//	    drift package registers one).
//	  - [Diff] classifies the differences between two contracts as breaking or
//	    non-breaking with a human-readable change list.
//	  - [Mount] mounts the admin API (services, contracts, snapshots, diffs,
//	    gaps); see README.md for the wiring in cmd/tt.
//
// Nothing in this package logs or returns payload values.
package contract
