// Package sourceclient is the reusable source-side Fleet client of
// traffic-twin (api/fleet-api.v1.openapi.yaml, docs/spec/policy.md section 4,
// docs/spec/event.md section 4). It is used by tt-egress and is meant to be
// reused by the Go SDK.
//
// It covers, with the standard library and the internal policy and sanitizer
// packages only:
//
//   - enrollment with a "tte_<secret>.<pin>" token: the root CA presented by
//     tt-core is pinned (SHA-256 of its DER) before anything is trusted, the
//     client key is generated locally (CSR) and stored with mode 0600;
//   - mTLS calls: heartbeat (kill switch, min_issued_seq, signing key
//     rotation and revocation, sampling override, certificate renewal), and
//     policy polling with ETag;
//   - fail-closed policy handling on top of policy.Store, with a persistent
//     cache (signed envelope, last accepted issued_seq, kill switch);
//   - an OTLP/HTTP JSON exporter over mTLS with a bounded queue, batching,
//     retry with exponential backoff and jitter, and drop counters.
//
// Nothing here ever sees a payload value: the capture layer hands in
// already sanitized, canonical event bytes. The application (or the proxy)
// is never made to wait for tt: every queue is bounded and drops events
// instead of blocking.
package sourceclient
