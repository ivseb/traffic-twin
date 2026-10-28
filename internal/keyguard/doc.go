// Package keyguard implements tt keyguard (docs/spec/keyguard.md,
// api/keyguard-api.v1.openapi.yaml): the only zone-B holder of the HMAC keys
// (every kid and epoch) and of the policy and pack signing keys.
//
// keyguard is a small, separate process. It answers tt-core only, over a
// Unix socket or over mTLS with tt-core's pinned client certificate, and
// offers:
//
//   - a feed of real tokens observed by the intake, kept as Bloom filters per
//     (epoch, kid) with a durable journal and periodic snapshots;
//   - match: the reverse-HMAC check, a yes/no answer per candidate string,
//     rate-limited, budgeted, audited, with an alert on every positive;
//   - policy signing: keyguard recomputes by itself whether a change opens
//     data (policy.md 5) against the policies it signed, enforces the
//     two-person rule, verifies approvers' OIDC ID tokens when configured,
//     and keeps issued_seq strictly increasing across restarts;
//   - policy renewal (not_after only, no approvals);
//   - pack signing: hashes, gate report and a full reverse-HMAC re-check of
//     every string and number of every file before signing;
//   - public keys, status and its own hash-chained audit log.
//
// No endpoint ever returns a key, a token or a candidate string, and none of
// them is ever logged.
package keyguard
