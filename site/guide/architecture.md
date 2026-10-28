---
description: "How traffic-twin works: three trust zones, an in-process sanitizer, tt-core, the keyguard and the publication gate between production and CI."
---

# Architecture overview

traffic-twin observes the HTTP traffic of an application in production **without ever exporting real values**, infers **contracts** and **cause → effect rules** from it, and produces a **stateful mock** for tests, populated with consistent **synthetic customers**.

This page is a short English overview. The full design, with diagrams and examples, is in [Architettura](/it/docs/architecture) (Italian); the normative formats are in the [specifications](/it/docs/spec/). Where they differ, the specifications win.

## Three trust zones

The whole architecture rests on one rule: data becomes less sensitive as it moves away from the application, and every zone boundary has a check.

| Zone | Where it runs | What it holds | Boundary on the way out |
|---|---|---|---|
| **A** | Inside the application processes, or the egress proxy next to them | Real requests and responses, for the duration of one call; the local HMAC key | The sanitizer, then OTLP over mTLS to the intake (**check 1**) |
| **B** | `tt-core`, installed in the production network | Shapes, HMAC tokens, contracts, draft rules, archetypes. **No keys** | The publication gate and keyguard's signature (**check 2**) |
| **B\*** | `tt keyguard`, a separate process | HMAC keys, policy and pack signing keys, the filter of real tokens | A minimal API, reachable only by `tt-core` |
| **C** | Laptops, CI, test environments | Signed twin packs, mocks, exports: synthetic data only | — |

## Components

| Component | Zone | What it does |
|---|---|---|
| SDKs (Go, Node.js, Python, Java, .NET, PHP) | A | Capture inbound and outbound calls before encryption, sanitize, sample per user |
| `tt egress` | A | Outbound reverse proxy for stacks without an SDK, same sanitizer |
| OBI (eBPF, optional) | A | Capture through eBPF with OBI's native allow-list, through an adapter |
| intake | B | Receives OTLP, checks the policy hash, **rejects** any event with values the policy does not allow |
| event store | B | Tokenized events in SQLite (pure Go driver), limited retention, contract statistics updated on arrival |
| contract inference | B | Schemas, field presence, status codes, errors, latencies, path templates → OpenAPI 3.1 with `x-tt-*` |
| rule miner | B | Join keys, cause → effect, alternative outcomes, batch rules → draft rules for review |
| profiles | B | Groups users into archetypes of at least *k* people |
| world generator | B | Synthetic customers and their history, from approved rules, archetypes and a seed |
| publication gate | B → C | Blocks publication when it finds real data; keyguard does the reverse check and signs |
| `tt keyguard` | B\* | The only key holder in zone B: reverse HMAC check (yes/no only), policy signing after re-checking approvals, pack signing |
| drift | B | Compares contract snapshots over time, sends webhook alerts |
| Fleet | B | Guided onboarding, enrollment tokens, signed policy distribution, source health |
| UI | B | Onboarding, policy assistant, contracts and diffs, rule review, worlds and packs |
| `tt mock` | C | Stateful mock with virtual clock, faults, control API and call journal |
| exporters | C | Pack → WireMock, Microcks or Prism files, with a report of what is lost |

Everything except the SDKs ships as one static Go binary, `tt`, with subcommands (`core`, `keyguard`, `egress`, `mock`, `export`, `dev up`). The UI is Svelte, compiled and embedded in the binary.

## Capture

- **In-process SDKs are the main path**, also for outbound calls: the hook sits on the HTTP client and sees data before TLS. They use native extension points (`diagnostics_channel` in Node, ASGI/WSGI middleware in Python, `DelegatingHandler` in .NET, `http.Handler`/`RoundTripper` in Go, PSR-15 in PHP, a servlet filter or an OpenTelemetry agent extension in Java).
- **`tt egress`** for stacks without an SDK: change the external service's base URL, no certificates, no code changes.
- **No MITM proxy by default.** An interception CA that can read all encrypted traffic is only an explicit, documented option.
- **Coexistence with OpenTelemetry.** The SDKs never register a global tracer provider or propagator; they read the current context and export through a private OTLP exporter.
- **Sampling per user, not per request.** `HMAC(key, epoch ‖ "sample" ‖ user) mod 10000 < rate_bp`: a user is in or out for the whole epoch, across services. Under pressure an SDK drops whole events, never the request.

## The sanitizer

The sanitizer walks every part of the exchange (path, query, headers, cookies, body) and applies the policy. **The default is `drop`**: only the shape remains.

| Action | What leaves | Input | Output |
|---|---|---|---|
| `drop` (default) | Type, length class, recognized format | `"mario.rossi@example.com"` | `"drop:str:email"` |
| `keep` | The value, only for declared low-cardinality fields | `"CREATED"` | `"keep:CREATED"` |
| `hmac` | A stable token, equal for equal values | `"ORD-2026-000184"` | `"tk1:k1:Zx81…"` |
| `bucket` | The value generalized into ranges | `73.40` | `"num:50-100"` |

Later specification versions add `code` (short status-like codes) and closed parsers for GraphQL documents, XML/SOAP, multipart and large bodies. Lengths come in only five classes, dynamic names that look like values collapse to `{*}`, and header values are all dropped unless the policy says otherwise. The same HMAC domain on different fields yields the same token for the same value, which is what lets the miner discover join keys.

The policy is YAML (`tt.policy/v1`), compiled to JSON, signed with Ed25519 by keyguard and pinned by hash in every event. The same sanitizer exists in six languages; **conformance vectors** prove they produce byte-identical output.

## Contracts, rules, worlds

- **Contracts**: OpenAPI 3.1 per service, with `x-tt-*` extensions for frequencies, latencies, error rates, conditional fields and dependencies. Enum values appear only when seen for at least *k* subjects.
- **Rules** (`tt.rules/v1`): entities, cause → effect with delays and alternative outcomes, life cycles, batch rules. The miner proposes, a person approves; approved rules go stale when their confidence drops.
- **Archetypes**: each user (only a token in zone B) becomes a vector of generalized features; vectors are grouped into archetypes of at least *k* users (20 by default).
- **Worlds**: a synthetic customer is born from an archetype and a seed, with invented personal data and new ids, and its history is generated forward in time by the approved rules. The same seed always gives the same world.

## The twin pack and the gate

```
twin-pack/
  manifest.json          # versions, seed, k_min, hash of every file
  manifest.sig.json      # Ed25519 signature by tt keyguard
  contracts/*.json       # OpenAPI 3.1 + x-tt-*
  rules.json             # tt.rules/v1, approved rules only
  world.jsonl            # synthetic customers, orders, shipments (canonical JSON per line)
  faults.json            # error and latency frequencies per operation
  gate-report.json       # outcome of every gate check
```

The gate runs four checks before keyguard signs: **provenance** (every string is synthetic or a declared enum), the **reverse HMAC check** in keyguard (no string or number is a real token: exact copies are caught with certainty), **PII detectors** (a last line, heuristic) and **k thresholds**. `tt mock` refuses any pack without a valid gate signature.

## The stateful mock

- **Isolation**: each test run has its own session (`X-TT-Session`) with its own state, virtual clock and seed.
- **Writes** are validated against the contract, create objects and enqueue the effects of approved rules. **Reads** return the state at the current virtual time.
- **Faults and latencies** at the observed frequencies, reproducible with the seed, or switched off for deterministic tests.
- **Control API** (`/__tt/…`): sessions, customer choice, clock advance, fault injection, forced outcomes, journal of received calls and of calls that do not match the contract.
- **Several services in one mock**, told apart by `Host` or a path prefix. Also GraphQL, SOAP/XML operations and an S3-compatible API, see the [mock specification](/it/docs/spec/mock).
- **Console mode**: the mock can fetch the latest released pack of one group from the console with a mock token, instead of a file.

| Export target | What is lost |
|---|---|
| WireMock | The clock: effects become scenario steps; probabilistic faults become alternative stubs |
| Microcks | The clock, faults, variable latencies |
| Prism | All state, latencies, faults |

## Read more (Italian)

- [Architettura](/it/docs/architecture): the complete design.
- [Threat model](/it/docs/threat-model): assets, actors, threats and countermeasures.
- [Specifications](/it/docs/spec/): sanitizer, policy, event, rules, pack, mock, keyguard, hardening.
