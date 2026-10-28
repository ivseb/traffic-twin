# traffic-twin

## Hai ricevuto traffic-twin già installato? Leggi USER_GUIDE.md

Se il team piattaforma ti ha dato l'indirizzo di una console, un account e un kit
(il comando `tt`, l'SDK del tuo linguaggio, il file della chiave HMAC), **non ti
serve il resto di questo README**: apri [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)
(nel kit è il file `USER_GUIDE.md`; nella console: menu **Aiuto > Manuale
utente**). Tutto quello che serve per l'uso quotidiano è lì, in italiano:

1. collegare il tuo servizio (onboarding, SDK, chiave HMAC);
2. approvare la policy, in una sola bozza (utente → campionamento → campi);
3. contratti, regole (quando compaiono e cosa fare se non compaiono), mondo e pacchetto;
4. `tt mock` nei tuoi test (`tt mock -h` ha le opzioni e un esempio).

Le istruzioni di build (`make build`, `tt dev up`, Go 1.25) qui sotto sono per chi
**sviluppa traffic-twin** o prova la demo dal repository, non per chi usa una
console già installata. I file `GETTING_STARTED.md` e `OPERATIONS.md` citati più
sotto possono non essere nel kit: la guida non ne ha bisogno.

---

*Developer and evaluator documentation (English) starts here.*

traffic-twin watches the HTTP traffic of an application in production
**without ever exporting real values**, infers **contracts** and
**cause → effect rules** from it, and produces a **stateful mock** for tests,
populated with consistent **synthetic customers**.

It is open source, self-hosted and security-first: real values are sanitized
inside the application process under a deny-by-default policy, and every
artifact is checked by a publication gate before it reaches development or CI.

> **Status: first public release (v0.1.0).** The whole pipeline runs end to
> end and has been through red-team rounds, but interfaces are still evolving
> before 1.0. See [`CHANGELOG.md`](CHANGELOG.md) for defaults, compatibility notes
> and known limits. Documentation site: <https://ivseb.github.io/traffic-twin/>.

> **Which guide?** Using a console that your platform team already installed
> (connect your service, approve the policy, run `tt mock` in your tests):
> [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) (Italian, also in the console under
> *Aiuto > Manuale utente*). Trying the demo or developing traffic-twin from
> this repository: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).
> Installing and running the platform: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Quickstart (single host)

Requirements: Go 1.25+, Node.js 24+ for the demo (the Node SDK itself needs
Node ≥ 20; full `fetch` body capture needs Node ≥ 24), make, curl, jq, openssl.

```sh
make build
./bin/tt dev up            # keyguard (Unix socket) + tt-core, keys generated in ./tt-dev
```

`tt dev up` prints the UI URL (`https://127.0.0.1:7070`, self-signed loopback
certificate), the intake URL for sources (`https://localhost:4318`), the HMAC
key file the sources need, the keyguard socket and a one-time **setup token**:
open the UI and create the first administrator with it. Everything stays on
loopback; it is a trial layout, not a production one (keyguard shares the
host). `.gitignore` already covers `tt-dev/`.

Then: create a source group in the onboarding wizard (it gives an enrollment
token), start a source (an SDK or `tt egress`), approve a policy, and follow
contracts → rules → world → signed pack. Run the pack with
`tt mock --pack pack.ttpack` or convert it with `tt export` (WireMock,
Microcks, Prism).

> **New here?** A guided tour that takes about 15 minutes (the demo shop +
> `tt dev up` + the Node SDK → approved policy → rules → a signed pack → a mock
> answering the demo flow, and how to run it in CI) is in
> [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) (Italian). Things worth
> knowing before you start:
>
> - the starter policy of the wizard only discovers shapes; the demo ships its
>   own policy, [`demo/policy.yaml`](demo/policy.yaml), proposed through the
>   admin API (`api/admin-api.v1.openapi.yaml`) and approved by the admin with
>   a reason (the one-person override);
> - the rule miner wants at least one hour of captured traffic by default. For
>   the accelerated demo clock use `tt dev up -miner-horizon 5m` (config key
>   `miner.min_horizon` in `tt core`); never lower it on real traffic;
> - `tt mock` trusts only the gate's public keys (`TT_GATE_PUBKEYS`) and needs
>   a `TT_CONTROL_TOKEN`.
>
> Installing, sizing, backups and the production security checklist:
> [`docs/OPERATIONS.md`](docs/OPERATIONS.md). Performance budgets and the
> large-dataset harness (`make perf`): [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

## Demo

- **The whole product in a few seconds:**
  `go test ./internal/core -run TestProductEndToEnd -v` starts keyguard and
  tt-core, enrolls a source, sends a simulated week of the demo shop over
  mTLS, mines the rules, builds and publishes a pack, runs it in the mock
  and exports it.
- **A live shop:** [`demo/`](demo/) is an invented e-commerce + carrier with
  a known ground truth. Put `tt egress` between the shop and the carrier
  (`CARRIER_BASE_URL`, see `demo/README.md`) and enroll it in `tt dev up`.

## Production layout

`tt core -config core.yaml` with `tt keyguard` on another host over mTLS:
see [`deploy/examples/`](deploy/examples/) (`core.production.yaml`,
`keyguard.production.env`, and the single-host variants). `tt core init`
writes a starting configuration. Sources connect only to the intake (mTLS,
Fleet CA pinned by the enrollment token); keyguard accepts only tt-core.

In production, let keyguard verify approvals with OIDC
(`TT_KEYGUARD_OIDC_*` in `keyguard.production.env`). Register a second,
dedicated "approval" client at the identity provider: its client id is
keyguard's `TT_KEYGUARD_OIDC_AUDIENCE` and tt-core's
`auth.oidc.approval_client_id`, and its redirect is
`/api/v1/auth/oidc/stepup/callback`. Its ID tokens must carry the roles claim
and `auth_time`. Each approval then takes a step-up: the approver signs in
again for that one change, and keyguard reads the approver's roles from the
token, not from tt-core (docs/spec/keyguard.md §3.2). Without OIDC the UI
shows `approvals_unverified`: keyguard then trusts the identities and roles
tt-core declares. That is a reduced guarantee, fit only for single-host and
development installs.

- **First administrator.** The one-time setup token is **not** written to the
  console or the log (a service manager keeps stdout in its journal): `tt core`
  writes it to `setup-token` in the data directory (mode 0600) and prints only
  the path. Read it on the host, create the administrator, delete the file.
  `tt core -print-setup-token` prints it on stdout for a trial on your own
  terminal; `tt dev up` always prints it.
- **Administrators see and do everything.** The `admin` role implies every
  other role in tt-core: every page, action and API route is open to an
  admin, who can also grant itself roles. Nothing an admin does is hidden:
  whatever would normally need another role is recorded as an admin override
  in the hash-chained audit log (`authz.admin_override`), policy approvals and
  pack releases by an admin need a reason and raise `policy.admin_approval` /
  `pack.admin_approval`, and quarantine dismissals, event exports and grants
  of sensitive roles by an admin raise webhook alerts. The only way to limit
  admins is keyguard's `TT_KEYGUARD_ADMIN_OVERRIDE=false` (they can then no
  longer approve or release alone): the installer's choice. With OIDC,
  keyguard still requires the `admin` role in the approver's verified token
  (docs/spec/policy.md §5, docs/THREAT_MODEL.md M17).
- **One tt-core per keyguard (v1).** Keyguard refuses to sign a policy version or
  sequence that is not greater than the last one (rollback protection), so a
  second core on the same keyguard is refused (`409 keyguard_state_conflict`).
  Give every core, load-test cores included, its own keyguard.
- **SDK or tt-egress, per outbound call.** An outbound call is captured either
  by an SDK or by `tt egress`, not both; Fleet flags `double_capture` when it
  sees both (see `internal/egress/README.md`).

## Commands

| Command | What it does |
|---|---|
| `tt core` | zone-B server: intake, Fleet, contracts, drift, rules, worlds, gate, admin API and UI |
| `tt core init` | writes a configuration and the data directory |
| `tt dev up` | single-host trial: keyguard + core in one process |
| `tt keyguard` | key custodian: reverse-HMAC, policy and pack signing (`genkey`, `pin`) |
| `tt egress` | outbound reverse proxy that captures for stacks without an SDK |
| `tt mock` | serves a signed pack as a stateful mock |
| `tt export` | converts a pack to WireMock / Microcks / Prism |

`make test` runs the Go tests (the acceptance test included, about 4 s;
`go test -race ./...` also passes, about 40 s for it). Container image:
`docker build -t traffic-twin .` (mount a configuration at `/etc/tt/core.yaml`).

## Layout

| Path | Content |
|---|---|
| `cmd/tt` | the single `tt` binary |
| `internal/core` | composition root of tt-core (wiring, admin API glue, acceptance test) |
| `internal/` | the components (sanitizer, policy, fleet, intake, store, contract, drift, miner, world, gate, mock, ...) |
| `ui/` | review UI (Svelte + Vite), embedded into `tt` |
| `api/`, `schemas/`, `docs/spec/` | the contracts |
| `deploy/examples/` | example configurations |

## Documentation

See [`docs/`](docs/), starting from [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
(currently in Italian). For the users of an installed console:
[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) ("Manuale utente", also served by the console).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md), including the clean-room rule.
- [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.

## License

[Apache License 2.0](LICENSE).
