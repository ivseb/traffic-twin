---
layout: home
title: traffic-twin
titleTemplate: Stateful mocks learned from production traffic

hero:
  name: traffic-twin
  text: Stateful mocks learned from production traffic
  tagline: traffic-twin watches the HTTP traffic of your application in production, infers contracts and cause → effect rules, and builds a stateful mock for your tests, populated with consistent synthetic customers. Real values never leave the application process.
  image:
    src: /logo.svg
    alt: ''
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Security model
      link: /guide/security
    - theme: alt
      text: View on GitHub
      link: https://github.com/ivseb/traffic-twin

features:
  - title: Sanitized inside the process
    details: An SDK or the tt-egress proxy applies a signed, deny-by-default policy before anything leaves the app. Every field is reduced to its shape unless the policy says keep, hmac, bucket or code.
  - title: Contracts from real traffic
    details: OpenAPI 3.1 contracts with x-tt-* extensions per operation, from shapes and counts only, with status codes, error rates and latencies. Contract drift raises webhook alerts.
  - title: Cause → effect rules
    details: The rule miner finds join keys, effects that follow a call and alternative outcomes (an order creates a shipment that moves through its states). People review and approve every rule.
  - title: k-anonymous synthetic worlds
    details: Users become archetypes of at least k people (k = 20 by default). Synthetic customers with invented data and fresh ids live forward in time under the approved rules. Same seed, same world.
  - title: A stateful mock for tests
    details: tt mock serves a signed twin pack with per-test sessions, a virtual clock, faults at the observed rates and a control API. Packs also export to WireMock, Microcks and Prism.
  - title: A console that explains itself
    details: Guided onboarding with ready-made commands, a policy assistant that proposes an action per field from shapes and counts, and the user manual built into the console (the console and the detailed docs are in Italian).
---

<div class="tt-home">

<p class="tt-status"><strong>Status: first public release, v0.1.0.</strong> The whole pipeline runs end to end, but formats, APIs and SDK options may still change. Read the <a href="./guide/operations#production-security-checklist">production checklist</a> before you point it at real traffic.</p>

## How it works

<p class="tt-lead">Data gets less sensitive as it moves away from the application, and every zone boundary has a check. Real values exist only inside the application, for the duration of one call.</p>

<PipelineDiagram lang="en" />

1. **Observe.** A native SDK (Go, Node.js, Python, Java, .NET, PHP) hooks the inbound handler and the outbound HTTP client, before TLS. For stacks without an SDK, `tt egress` is an outbound reverse proxy with the same sanitizer.
2. **Sanitize.** The signed policy decides what may leave: by default only the shape (`"drop:str:email"`), otherwise a stable HMAC token, a bucket or a declared low-cardinality value. Events travel as OTLP/HTTP JSON over mTLS to the intake, which rejects anything the policy does not allow.
3. **Infer.** tt-core builds OpenAPI contracts and mines cause → effect rules from tokens and shapes, never from values.
4. **Synthesize.** Archetypes of at least *k* users and the approved rules generate a deterministic synthetic world.
5. **Mock.** The publication gate checks the artifacts, keyguard signs the twin pack, and `tt mock` serves it in local tests and CI.

## Security model

<p class="tt-lead">traffic-twin promises verifiable properties, and states openly what it does not guarantee. Summary below; details in the <a href="./guide/security">security model</a> and the full <a href="./it/docs/threat-model">threat model</a> (Italian).</p>

<div class="tt-grid">
  <div class="tt-card">
    <h3>Three trust zones</h3>
    <p>Zone A is the app (real values), zone B is tt-core (shapes and HMAC tokens, no keys), zone C is dev and CI (synthetic data only).</p>
  </div>
  <div class="tt-card">
    <h3>Deny-by-default</h3>
    <p>With an empty policy no value leaves any part of the exchange, only coarse shapes and structure names. The same conformance vectors run byte for byte against every SDK.</p>
  </div>
  <div class="tt-card">
    <h3>Keyguard holds the keys</h3>
    <p>A separate process is the only holder of the HMAC and signing keys in zone B. It re-checks approvals before signing a policy: opening data takes two different people, or an administrator with a recorded reason and an alert (the installer can forbid that).</p>
  </div>
  <div class="tt-card">
    <h3>Publication gate</h3>
    <p>Provenance of every string, a reverse HMAC check that finds exact copies of real values, PII detectors and k thresholds. Keyguard signs the pack; the mock refuses unsigned packs.</p>
  </div>
  <div class="tt-card">
    <h3>k-anonymity</h3>
    <p>Archetypes, published enum values, outcomes and counts must each cover at least <em>k</em> distinct users, otherwise they are suppressed or merged.</p>
  </div>
  <div class="tt-card">
    <h3>Fail-closed sources</h3>
    <p>Without a valid signed policy, an HMAC key and a first heartbeat, a source captures nothing and the app keeps working. Under pressure it drops events, never requests.</p>
  </div>
</div>

## Overhead, as measured

<p class="tt-lead">Measurements from <a href="./it/docs/performance#36-deployment-multi-host-di-prova">docs/PERFORMANCE.md §3.6</a> on a multi-host test deployment (noisy, shared hardware). They describe that setup, not a guarantee for yours.</p>

| What was measured | Result |
|---|---|
| Latency added by `tt egress` (p50 / p99) | about +0.9 ms / +3 ms, within the noise |
| Node SDK, 5% sampling, worst-case 70 µs request | +1.6% req/s vs. SDK off, indistinguishable within the noise |
| Node SDK, cost of a *sampled* exchange | about 130–250 µs |
| tt-core intake on a 4 vCPU container | about 4,000 events/s sustained without loss |

## Quickstart

Requirements: Go 1.25+, Node.js 24+ for the demo (the Node SDK itself needs Node ≥ 20), make, curl, jq, openssl.

```sh
git clone https://github.com/ivseb/traffic-twin.git && cd traffic-twin
make build
./bin/tt dev up            # keyguard (Unix socket) + tt-core, keys generated in ./tt-dev
```

`tt dev up` prints the UI URL (`https://127.0.0.1:7070`, self-signed loopback certificate), the intake URL for sources (`https://localhost:4318`), the HMAC key file the sources need and a one-time setup token to create the first administrator. Then: create a source group in the onboarding wizard, start a source (an SDK or `tt egress`), approve a policy, and follow contracts → rules → world → signed pack. Run the pack with `tt mock --pack pack.ttpack`.

Want to see the whole product in a few seconds first?

```sh
go test ./internal/core -run TestProductEndToEnd -v
```

It starts keyguard and tt-core, enrolls a source, sends a simulated week of the demo shop over mTLS, mines the rules, builds and publishes a pack, runs it in the mock and exports it. The [getting started guide](./guide/getting-started) walks through the 15-minute tour.

## SDKs

<p class="tt-lead">Native capture SDKs with no runtime dependencies beyond the standard library. Packages are published to the registries by the release workflow: check the <a href="https://github.com/ivseb/traffic-twin/releases">release notes</a> for availability.</p>

| Language | Package | Minimum runtime |
|---|---|---|
| Go | `github.com/ivseb/traffic-twin/sdk/go` | Go 1.25 |
| Node.js | `@traffic-twin/sdk` (npm) | Node 20 (full `fetch` bodies from 24) |
| Python | `traffic-twin` (PyPI) | Python 3.9 |
| Java | `io.github.ivseb.traffictwin:sdk`, `sdk-servlet-javax`, `sdk-otel-extension`, `sdk-agent` (Maven Central) | Java 17 |
| .NET | `TrafficTwin.Sdk`, `TrafficTwin.Sdk.AspNetCore` (NuGet) | .NET 8 |
| PHP | `traffic-twin/sdk` (from source in `sdk/php`; Packagist coming later) | PHP 8.1 with ext-sodium |

No SDK for your stack? `tt egress` captures outbound calls as a reverse proxy: change the base URL of the external service, no code changes. More in [SDKs](./guide/sdks).

## Open source

traffic-twin is self-hosted and licensed under Apache-2.0. tt-core and keyguard make no outbound calls except to allow-listed webhooks, and there is no telemetry to the maintainers. This site loads no trackers, analytics or third-party resources.

<div class="tt-links">
  <a href="https://github.com/ivseb/traffic-twin">GitHub repository</a>
  <a href="https://github.com/ivseb/traffic-twin/releases">Releases</a>
  <a href="./it/docs/security">Report a vulnerability</a>
  <a href="./it/docs/contributing">Contributing</a>
  <a href="https://github.com/ivseb/traffic-twin/blob/main/LICENSE">License</a>
</div>

</div>
