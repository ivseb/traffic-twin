---
description: "Running traffic-twin in production: deployment layout, sizing, retention, upgrades, releases and how to verify signatures and provenance."
---

# Operations summary

For whoever installs and runs traffic-twin: layouts, sizing, backups and the checks to make before production. This is an English summary of the [operations guide](/it/docs/operations) (Italian), which has every configuration key and command; data retention is in [Ciclo di vita dei dati](/it/docs/data-lifecycle) and the performance budgets in [Prestazioni](/it/docs/performance).

## Installation layouts

| Layout | When | How |
|---|---|---|
| **Development, one host** | trial, demo, developing traffic-twin | `tt dev up` |
| **Production, separate hosts** | a real installation | `tt keyguard` on a dedicated host + `tt core -config core.yaml` |
| **Kubernetes** | clusters | Helm charts for tt-core, tt-keyguard (separate namespace), tt-egress, tt-mock and the SDK injector ([`deploy/README.md`](https://github.com/ivseb/traffic-twin/blob/main/deploy/README.md)) |

`tt dev up` runs keyguard and tt-core in one process on loopback with self-signed TLS. It is **not** a production layout: keyguard shares the host.

```
sources (SDK, tt-egress, OBI) ──mTLS──▶ tt-core (intake :4318, UI/API :7443)
                                          │ mTLS, minimal API, pinned certificates
                                          ▼
                                       tt keyguard (another host / pod / namespace)
```

In production:

1. On a **dedicated** host, generate the keys with `tt keyguard genkey` (`-type hmac`, `-type ed25519` for policies and packs) and start `tt keyguard` with the `TT_KEYGUARD_*` variables ([`keyguard.production.env`](https://github.com/ivseb/traffic-twin/blob/main/deploy/examples/keyguard.production.env)).
2. On the tt-core host, `tt core init` writes a starting configuration; complete it with [`core.production.yaml`](https://github.com/ivseb/traffic-twin/blob/main/deploy/examples/core.production.yaml) (keyguard pin, client certificate, admin TLS).
3. `tt core -config /var/lib/tt/core.yaml`. On first start it writes a one-time setup token to `setup-token` in the data directory (mode 0600), never to the console or the log: read it on the host, create the administrator, delete the file.

Constraints worth knowing:

- **One tt-core per keyguard (v1).** Keyguard refuses to sign a sequence that is not greater than the last one (rollback protection), so a second core on the same keyguard gets `409 keyguard_state_conflict`.
- **One writer process** (SQLite): no tt-core replicas. Availability relies on quick restarts and backups; sources retry and drop full queues, never block the app.
- **No outbound calls** from tt-core or keyguard, except allow-listed webhooks.

## Sizing

Figures measured on a multi-host test deployment (tt-core in a 4 vCPU, 4 GiB container), from the [operations guide §2](/it/docs/operations#2-dimensionamento) and [performance §3.6](/it/docs/performance#36-deployment-multi-host-di-prova):

| Item | Value |
|---|---|
| Sustained intake | about **4,000 events/s per tt-core** without loss; above that the intake applies backpressure and sources drop their oldest events |
| Light load (~25 events/s) | ~2% of a core and ~50 MiB RSS for tt-core, ~55 MiB for keyguard |
| Disk | about **1.7–1.9 KB per raw event**: 10 M events ≈ 18.8 GB |
| Retention | raw events 7 days by default, then hourly, daily and monthly rollups |
| Mining memory | about 1.3 KB per event in the window at peak; the window adapts to the memory limit |
| Long operations | mining, archetypes, worlds, packs and exports beyond ~20 s run as jobs |

## Runtime requirements of the SDKs

| SDK | Minimum | Note |
|---|---|---|
| Node | 20 | Full `fetch` response bodies only from Node 24 |
| Python | 3.9 | On 3.9 set `TT_ENROLL_CA_FILE` |
| Java | 17 | Also the `-javaagent` agent (Tomcat, Jetty, HttpClient, RestTemplate/RestClient, OkHttp) |
| .NET | 8 | Zero-code start with `DOTNET_STARTUP_HOOKS` |
| Go | 1.25 | |
| PHP | 8.1 with ext-sodium | Without sodium the policy signature cannot be verified: no capture |

## Backups

| What | Why |
|---|---|
| tt-core database (`storage.path`, with `-wal` and `-shm`) | events, contracts, rules, worlds, users, audit; take a consistent copy (`sqlite3 … ".backup …"`) |
| Fleet CA folder | without it every source must enroll again |
| Keyguard keys and database | lost HMAC keys mean issued tokens are no longer recognized; the database holds the anti-rollback state |
| Audit archives | older audit entries live only there; keep them on WORM storage |

Restore the tt-core and keyguard databases **from the same point in time**. Never keep keyguard's HMAC keys in the same backup set as the tt-core database or an event export: together they allow a dictionary attack on the tokens.

## Monitoring

Health endpoints (`/healthz`, `/readyz` on tt-core, `/__tt/health` on the mock), the **Sources** page for heartbeats, counters and recent errors, webhook alerts (drift, keyguard alerts, admin approvals, sensitive role grants, event exports), audit chain verification (`GET /api/v1/audit/verify`, keeping the head hash outside the database) and storage usage (`GET /api/v1/store/usage`).

## Production security checklist

The [full checklist](/it/docs/operations#9-checklist-di-sicurezza-per-la-produzione) has the exact settings. In short:

- Verify approvals with **OIDC** and a dedicated approval client; without it the UI shows `approvals_unverified`.
- Require **two people** to open data (`TT_KEYGUARD_OPENING_APPROVALS=2`) and decide whether an administrator may approve alone (`TT_KEYGUARD_ADMIN_OVERRIDE`).
- Decide on the **Observe phase** (`TT_KEYGUARD_OBSERVE_AUTO`): keyguard signs changes that open no values without people.
- **mTLS with pinned certificates** between tt-core and keyguard; keyguard reachable only from tt-core and without internet egress.
- **File permissions**: data directory `0700`, keyguard keys `0400`/`0600`, setup token deleted, SDK state `0700`; encrypted volumes and backups.
- Always set the mock's **`TT_CONTROL_TOKEN`** in CI, and trust only the gate's public keys (`TT_GATE_PUBKEYS`).
- Webhooks only to allow-listed hosts, preferably HTTPS; short-lived enrollment tokens.
- Separate **backups** and a tested restore; scheduled **audit verification** with the head hash kept elsewhere.

The gate's PII detectors are a second net, not the main guarantee: that is the deny-by-default policy applied in the source process.

## Releases

Releases are cut from a `vX.Y.Z` tag: the release workflow builds, signs, produces SBOMs and provenance, publishes the container image on `ghcr.io` and prepares a draft GitHub release; once the release is published, the `publish-sdks` workflow publishes the SDK packages to their registries. Details in [Come si rilascia](/it/docs/releasing) (Italian). Downloads: [GitHub releases](https://github.com/ivseb/traffic-twin/releases).
