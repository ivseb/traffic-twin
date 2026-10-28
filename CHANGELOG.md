# Changelog

All notable changes to traffic-twin are listed here. The specification has its own,
more detailed changelog in [`docs/spec/README.md`](docs/spec/README.md#changelog)
(in Italian); this file covers what matters when installing or upgrading a release.

The project follows [Semantic Versioning](https://semver.org/). Before 1.0.0, minor
versions may change interfaces; every such change is called out below.

## [0.1.1] — 2026-10-28

Maintenance release: no change to formats, APIs or the behaviour of the core and the SDKs.

### Fixed

- The self-contained `Dockerfile` now copies `go.sum` and the user manual the console
  embeds; `docker build .` works again.
- PHP SDK tests run on case-sensitive file systems (`tests/Support`).
- Flaky tests made deterministic: Python inbound grace period, Node OpenTelemetry
  coexistence, observe-phase end-to-end test; latency budgets are logged, not enforced, on
  shared CI runners.

### Changed

- npm packages are published with trusted publishing (OIDC) and provenance; no long-lived
  token is stored any more.
- README and documentation site: badges, install table, release verification, Mermaid
  diagrams, search-engine metadata.
- Helm charts and the SDK images point at 0.1.1.

## [0.1.0] — 2026-10-28

First public release. Interfaces are still evolving.

### What is in it

- **Capture without real values.** SDKs for Go, Node.js, Python, Java, .NET and PHP,
  plus `tt-egress` and OBI for services that cannot load an SDK. Values are sanitized
  inside the application process under a deny-by-default policy (drop, keep, hmac,
  bucket, `code`, `code(alnum)`, `graphql`); JSON, GraphQL, XML/SOAP, multipart,
  base64 documents and large bodies are covered. 827 conformance vectors keep the six
  SDKs byte-for-byte equivalent.
- **Policy lifecycle.** Policies are signed by the keyguard; changes that would open
  values need a reviewer's approval, changes that cannot open values are signed
  automatically in the observe phase. The admin is a superuser: traced, not limited.
- **Inference.** Observed OpenAPI contracts with drift alarms; cause → effect rules
  mined from traffic (creations, updates, toggles, removals, keyed state, conditional
  outcomes, aggregates, lists, preconditions, GraphQL and SOAP operations), reviewed
  as drafts before use.
- **Synthetic worlds.** k-anonymous synthetic customers and entities with the
  service's own id formats, valid synthetic documents and relative dates; every
  artifact passes the publication gate before it leaves the platform.
- **Stateful mock.** `tt mock` replays contracts and rules with per-user sessions:
  REST, GraphQL, SOAP/XML, an S3-compatible API, third-party pages with callbacks.
  It runs as a binary, a container, a Helm chart, or is started from the console on
  Kubernetes/OpenShift.
- **Console.** Svelte console with per-page and per-field help, glossary and an
  in-app user manual.
- **Supply chain.** Static binaries for linux/darwin/windows × amd64/arm64,
  multi-arch image `ghcr.io/ivseb/traffic-twin`, SPDX SBOMs, cosign keyless
  signatures and SLSA level 3 provenance.

### Defaults to know before installing

- `retention.events` is **7 days** and `miner.window` is **7 days**: raw events older
  than 7 days are summarised and then deleted at the first maintenance run.
- The audit log is archived after **180 days**.

### Observe phase

The keyguard signs, without people, the policy changes that cannot open values (hmac,
automatic identity, discovery windows up to 7 days, codes). This is an accepted and
documented risk (see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md));
`TT_KEYGUARD_OBSERVE_AUTO=false` turns it off.

### Codes in clear (compatibility)

- Status-like and code-shaped values leave the process **without approval** on
  status-like fields (`code` action). Sources older than spec v1.11 reject a policy
  containing `code`: upgrade the sources first, or set `fleet.observe.codes: false`.
- `code(alnum)` and the `bodies` object (XML/SOAP, multipart, documents, large
  bodies) are rejected by sources older than spec v1.19: upgrade the sources first,
  or set `fleet.observe.code_digits: false` and `fleet.sanitizer.bodies: false`.

### Memory

tt-core reads the cgroup memory limit (LXC included) and queues heavy jobs.
Sizing is in [`docs/OPERATIONS.md`](docs/OPERATIONS.md) §2.1: about 1.7–1.9 KB of disk per raw
event and about 3 KB of memory limit per event the miner must see; set `storage.max_bytes` and use sampling for very busy services.

### Upgrades

A sanitizer change shifts the observed contracts: expect drift alarms, and rules
that become stale until a reviewer confirms them again. This is intended.

### Known limits

- The PHP SDK is not on Packagist yet: install it from `sdk/php` in this repository
  (for example as a Composer `path` repository). The other SDKs are on their registries.
- OBI has not been tested on a privileged host (only unprivileged containers).
- OIDC is covered by automated tests only, not yet against a real identity provider.
- Mocks managed in Kubernetes/OpenShift were tested against a fake API server, not a
  real cluster.
- Dynamic runs for Laravel/PHP-FPM/Django/Flask and Windows ACLs are untested.
- Threat model residuals: an older signed pack of the same group is still servable;
  an empty mock namespace means tt-core's namespace; a real name typed by hand into a
  rule passes the detectors.

[0.1.1]: https://github.com/ivseb/traffic-twin/releases/tag/v0.1.1
[0.1.0]: https://github.com/ivseb/traffic-twin/releases/tag/v0.1.0
