# Security model

100% security cannot be promised. traffic-twin promises **verifiable properties** instead, and states openly what it does **not** guarantee. This page summarizes the [threat model](/it/docs/threat-model) (Italian, STRIDE for security and LINDDUN for privacy); read it in full before an installation on real traffic.

To report a vulnerability, see the [security policy](/it/docs/security): use GitHub's private vulnerability reporting, never a public issue.

## The main risks, stated plainly

1. **The Fleet console is target number one.** Whoever changes a policy can make real data leave every source, legitimately and signed. That is why signing lives in keyguard, which re-checks approvals and classification on its own, and not in tt-core.
2. **The event store in zone B is personal data.** HMAC tokens are pseudonyms, and timed sequences of events can make a person recognizable. A data protection impact assessment is almost certainly needed.
3. **The sanitizer does not look inside `keep` fields.** If a field declared `keep` sometimes carries free text, that text leaves. Cardinality quarantine reduces the risk but does not remove it.
4. **The SDK runs inside production.** A compromised package (ours or a dependency) sees all real data: the SDKs have no runtime dependencies.
5. **Business secrets.** Contracts and rules reveal processes, volumes and the behaviour of external partners.

## Zones and checks

| Zone | Where | Content | Check on the way out |
|---|---|---|---|
| A | Application processes, `tt egress` | Real values, for one call; the local HMAC key | Sanitizer + OTLP over mTLS |
| B | `tt-core` in the production network | Shapes, HMAC tokens, aggregates. **No keys** | Publication gate + keyguard signature |
| B\* | `tt keyguard`, a separate process | HMAC keys, signing keys, filter of real tokens | Minimal API, `tt-core` only |
| C | CI, laptops, test environments | Synthetic data only | — |

## Defences in depth

- **Deny-by-default in the process.** Every part of the exchange is `drop` unless the signed policy says otherwise; header values, cookies, query, path segments and non-JSON bodies included. Dynamic names that look like values collapse to `{*}`.
- **Signed, scoped, expiring policies.** Sources download policies over mTLS and refuse unsigned, expired, other-group or older ones (a global, increasing sequence prevents rollback). Without a reachable tt-core a source keeps the last valid policy until it expires, then stops capturing: it never falls back to a more open policy.
- **Fail-closed sources.** No valid policy, no HMAC key of at least 32 bytes, or no first heartbeat: nothing is captured, and the app works normally. A persistent kill switch is checked before the first capture.
- **The intake as second line.** Only events whose bytes are exactly the canonical form are accepted, with type checks against the effective policy rule; `keep` fields with too many distinct values go into **quarantine** and are rewritten.
- **Keyguard.** The only key holder in zone B. The reverse HMAC check answers only yes/no, is rate limited and raises an alert on every hit. Keyguard makes no outbound calls.
- **Approvals.** Policy changes that open data need **two different people**, re-checked by keyguard; with OIDC, keyguard verifies each approver's ID token obtained through a step-up for that specific change, and reads roles from the token. Changes that open no values (the *Observe* phase) can be signed without people, by design and in the audit log.
- **Administrators.** The `admin` role implies every other role. An admin can approve or release alone, but only with a reason, recorded as an override in the hash-chained audit log and raised as a webhook alert. Installers who do not accept this set `TT_KEYGUARD_ADMIN_OVERRIDE=false`.
- **Publication gate.** Provenance, reverse HMAC check on every string and number (repeated by keyguard at signing time), PII detectors and *k* thresholds. Packs are signed with Ed25519 and the mock refuses unsigned packs.
- **k-anonymity.** Every published or displayed cell must concern at least *k* distinct subjects (20 by default), otherwise it is suppressed or merged, in the UI too.
- **No outbound calls, no telemetry.** tt-core and keyguard call nothing on the internet except allow-listed webhooks (the resolved address is checked too; internal, link-local and cloud metadata addresses are refused).
- **Supply chain.** Releases signed with Sigstore cosign, SBOMs, SLSA provenance; SDKs without runtime dependencies; no automatic updates.

## Verifiable guarantees

| # | Guarantee | How it is verified |
|---|---|---|
| G1 | With an empty policy **no value** leaves any part of the exchange: only coarse shapes, structure names and safe host labels | Conformance vectors and generative tests in every SDK, in CI |
| G2 | All sanitizer implementations behave the same way | Same vectors, byte-identical output |
| G3 | Never an unkeyed hash | HMAC-SHA256 only; no capture without a key of at least 32 bytes |
| G4 | The intake accepts only shapes, tokens and values of the expected type | Schema, canonical form and type checks; rejection counters in Fleet |
| G5 | No pack without the gate | Keyguard's Ed25519 signature on the manifest; the mock refuses unsigned packs |
| G6 | No real value copied as is into a pack | Reverse HMAC check on 100% of strings and numbers, repeated by keyguard |
| G7 | Minimum *k* on archetypes, enums, outcomes and counts | *k* in the manifest and the `k-thresholds` check |
| G8 | Policy integrity | Keyguard signature, approvals verified by keyguard, append-only audit |
| G9 | No outbound calls | NetworkPolicy templates and tests on the binaries |
| G12 | No keys in tt-core | tt-core reads no key variables or files; keys appear only in keyguard's configuration |

The threat model lists all twelve, including overhead budgets and code integrity.

## What is not guaranteed

- **Coarse shapes leak a little.** Type, recognized format and one of five length classes: two enum values with lengths in different classes can be told apart even with `drop`.
- **Names leave in clear** when they follow the grammar (JSON keys, parameters, headers, safe host labels); values used as names are caught by quarantine only after a threshold.
- **Personal data in a low-cardinality `keep` field** (a city in a small country, for example).
- **Formal privacy for the synthetic world.** Residual risk is measured, not proved; a formal proof would need differential privacy.
- **Near copies.** The reverse HMAC check catches exact copies only; detectors are the last line.
- **A fully compromised tt-core** can use the reverse check as a slow, rate-limited, alerting oracle. Without OIDC (`approvals_unverified`) it can also declare approvers: acceptable only for single-host and development installs.
- **An administrator acting alone** is made visible, not prevented, unless the installer disables the override.
- **The identity provider itself**: whoever controls it controls verified approvals.

Accepted risks of later specification versions (codes without approval, GraphQL schemas, HMAC domain families, test groups with reduced *k*, XML/SOAP parsing at the source) are documented one by one in the threat model, §7.

## Read more (Italian)

- [Threat model](/it/docs/threat-model)
- [Sanitizer specification](/it/docs/spec/sanitizer), [policy](/it/docs/spec/policy), [keyguard](/it/docs/spec/keyguard), [hardening](/it/docs/spec/hardening)
- [Production security checklist](/it/docs/operations#9-checklist-di-sicurezza-per-la-produzione)
