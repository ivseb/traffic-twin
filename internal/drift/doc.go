// Package drift compares consecutive contract snapshots, raises alerts when
// they change and delivers them to webhooks (docs/ARCHITECTURE.md section 10).
//
//   - [Manager.HandleSnapshot] is registered as a snapshot hook of the
//     contract engine ([Manager.Attach]): it diffs the new snapshot with the
//     previous one and stores one `contract.drift` alert per change, with
//     severity breaking or non-breaking, deduplicated while an identical
//     alert is open.
//   - [RuleStaleness] is the hook the rule miner calls when the confidence
//     of an approved rule falls (`rule.stale` alert). [RuleLookup] is the
//     reverse direction: the miner tells which rules an operation feeds, so
//     alerts carry affected_rules.
//   - Webhooks receive JSON payloads signed with HMAC-SHA256 under a
//     per-webhook secret (header X-TT-Signature: t=<unix>,v1=<hex>, see
//     [Sign] and [VerifySignature]). Delivery is queued in SQLite, retried
//     with exponential backoff and logged. Payloads carry kinds, counts and
//     identifiers, never data values. Destinations must match the allow list
//     (TT_WEBHOOK_ALLOW).
//   - [Mount] mounts the admin API endpoints for alerts and webhooks.
package drift
