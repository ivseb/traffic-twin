---
description: "Install traffic-twin, connect a service through an SDK, approve the policy and run a stateful mock of your API in your tests."
---

# Getting started

From nothing to a **stateful mock running in CI**, starting from the traffic of a demo shop. This is an English summary of the 15-minute tour; every command and screen is described step by step in the full guide, [Primo giro in 15 minuti](/it/docs/getting-started) (Italian).

::: tip Which guide?
- **You were given a console that is already installed** (an address, an account, the `tt` command, an SDK and the HMAC key file): read the [user manual](/it/docs/user-guide) (Italian, also in the console under *Aiuto > Manuale utente*). You do not need to build anything.
- **You want to try the demo or develop traffic-twin from the repository**: this page.
- **You are installing the platform**: see [Operations](./operations).
:::

## What you need

Go 1.25+, Node.js 24+ (the Node SDK works from Node 20, but the full body of `fetch` responses is visible only from Node 24), `make`, `curl`, `jq`, `openssl`. Docker is optional. Everything stays on loopback and all data is invented.

The console is in Italian: below, its labels are quoted as they appear, with a translation where useful.

Ports used: `7070` (UI), `4318` (intake), `3000` (shop), `8080` (carrier), `8480` (mock). You need three terminals (A, B, C) and a browser; every command starts from the repository root.

```
 loadgen ──▶ shop (Node + SDK) ──▶ carrier        demo/ (invented data)
                  │ sanitized events, mTLS
                  ▼
              tt dev up  (tt-core + keyguard)  ──▶  contracts → rules → world → signed pack
                                                                              │
                                                       tt mock (CI) ◀─────────┘
```

## 1. Build and start (terminal A)

```sh
make build                          # builds the UI and bin/tt
./bin/tt dev up -miner-horizon 5m   # keyguard + tt-core on loopback
```

`-miner-horizon 5m` is for the demo only: by default the rule miner waits until the captured traffic covers at least one hour of real time. Never lower it on real traffic.

`tt dev up` prints the UI URL (`https://127.0.0.1:7070`, a self-signed loopback certificate), the intake URL (`https://localhost:4318`), the sources' HMAC key file (`tt-dev/keys/hmac.keys`), the keyguard socket and a one-time **setup token**. Open the UI, paste the token and create the first administrator.

## 2. Connect a source: the Node SDK in the demo shop

In the UI, **Onboarding → Aggiungi una sorgente** (add a source): choose the Node.js SDK, name the group `shop`, pick 100% discovery sampling (invented data) and copy the **enrollment token** (`tte_…`, single use, expires in an hour). Below the instructions is the starting policy (*Policy iniziale*): everything is `drop`, discovery only, no value leaves.

Then in terminal B start the demo carrier and the shop with the SDK attached, without touching the shop's code:

```sh
export TIME_SCALE=2880 CLOCK_ANCHOR=$(date +%s)        # one simulated day every 30 s

(cd sdk/node && npm ci --no-audit --no-fund --ignore-scripts && npm run build)
(cd demo && go run ./carrier) &                        # carrier on port 8080

export TT_ENROLL_URL=https://localhost:4318
export TT_ENROLL_TOKEN=tte_...                         # the token from the wizard
export TT_HMAC_KEY_FILE=$PWD/tt-dev/keys/hmac.keys     # values become tokens here, in the process
export TT_STATE_DIR=$PWD/tt-dev/shop-state
export TT_SERVICE_NAME=shop-api
export TT_DEBUG=1                                      # prints the SDK state (never values)
CARRIER_BASE_URL=http://localhost:8080 \
  node --import $PWD/sdk/node/dist/esm/register.js demo/shop/server.js
```

The source enrolls and prints `state capturing`.

## 3. Generate traffic (terminal C)

```sh
export TIME_SCALE=2880 CLOCK_ANCHOR=<the value from terminal B>
cd demo && SHOP_BASE_URL=http://localhost:3000 DURATION=15m go run ./loadgen
```

Two thousand invented customers place orders and track shipments for 15 minutes (about a simulated week).

## 4. Approve a policy (browser)

A policy says what may leave the process. Back in the wizard, the **policy assistant** lists the operations as templates (`POST /orders`, `GET /orders/{id}`, …) and, for every field, shows only its shape and counts, never values, and proposes an action: identifiers as `hmac` with their namespace (`order`, `shipment`, `customer`), states and codes as `keep`, amounts as `bucket`, dates as `bucket(time, day)`; names, emails and addresses stay `drop`. Review the YAML diff, request approval and approve (as administrator, with a reason).

Within 30 seconds the shop switches to the new policy version. The hand-written equivalent is [`demo/policy.yaml`](https://github.com/ivseb/traffic-twin/blob/main/demo/policy.yaml); the full guide shows how to propose it through the admin API instead.

## 5. Rules, world and pack (browser)

1. **Regole → Cerca nuove regole** (rules → find new rules). The miner finds the cause → effect the demo hides: `POST /v1/shipments` at the carrier creates a shipment (`r-0001`), and `POST /orders` at the shop creates an order and its shipment (`r-0002`). Open each rule, check the evidence (counts, outcomes, the `PENDING → CREATED → IN_TRANSIT → DELIVERED` life cycle) and approve it. Only approved rules go into the pack.
2. **Mondi → Genera** (worlds → generate; seed `42`, 100 customers). The first time, tt-core builds the archetypes from the real customers: tokens only, in groups of at least 20.
3. **Pacchetti twin → Nuovo pacchetto → Avvia il gate** (twin packs → new pack → run the gate). The gate checks provenance, PII, k-anonymity and keys; if everything passes, keyguard signs. A blocked pack reports the file and field path, never the value. Then **Rilascia ai test** (release to tests) and **Scarica il pacchetto** (download): you get `<pack_id>.ttpack`.

The same steps exist in the admin API, for a CI job that builds the pack (`api/admin-api.v1.openapi.yaml`).

## 6. The mock, locally and in CI

The mock trusts only the gate's public keys. In the UI, **Pacchetti twin > Come usarlo nei test** (how to use it in tests) shows the command with the value of `TT_GATE_PUBKEYS`.

```sh
export TT_GATE_PUBKEYS='pack-dev-1:<public_key>'
export TT_CONTROL_TOKEN="$(openssl rand -hex 24)"      # always, locally and in CI
./bin/tt mock --pack ~/Downloads/<pack_id>.ttpack --addr 127.0.0.1:8480 --latency record &

AUTH="Authorization: Bearer $TT_CONTROL_TOKEN"
SID=$(curl -s -H "$AUTH" -X POST localhost:8480/__tt/sessions -d '{}' | jq -r .id)

# the carrier creates a shipment in this session (the body must match the contract)
curl -s -H "$AUTH" -H "X-TT-Session: $SID" -H 'Content-Type: application/json' -X POST \
  localhost:8480/__svc/carrier/v1/shipments -d '{"orderId":"ORD-NEW-1","service":"STANDARD","parcels":1,
  "recipient":{"fullName":"Anna Leone","email":"anna@example.org"},
  "address":{"line1":"Via Roma 1","city":"Bologna","postcode":"40121","country":"IT"}}'

# the clock is virtual: advance it and the shipment moves on
curl -s -H "$AUTH" -X POST localhost:8480/__tt/sessions/$SID/clock/advance -d '{"by":"5m"}'
curl -s -H "$AUTH" -H "X-TT-Session: $SID" 'localhost:8480/__svc/carrier/v1/shipments?orderId=ORD-NEW-1'
```

State is per session: every test asks for its own (`POST /__tt/sessions`) and sends `X-TT-Session`, so one test's writes are visible only to it. A typical CI job does not need tt-core at all: it fetches `tt` and the signed pack, starts the mock and runs the app's tests with the external service's base URL pointing at it.

```yaml
- name: carrier mock
  run: |
    echo "TT_CONTROL_TOKEN=$(openssl rand -hex 24)" >> "$GITHUB_ENV"
    TT_GATE_PUBKEYS="${{ vars.TT_GATE_PUBKEYS }}" ./tt mock --pack twin/shop.ttpack --addr 127.0.0.1:8480 --latency record &
    curl --retry 10 --retry-connrefused -s localhost:8480/__tt/health
- name: test
  env:
    CARRIER_BASE_URL: http://127.0.0.1:8480/__svc/carrier
  run: npm test
```

Always set `TT_CONTROL_TOKEN`: without it the control API is open to anyone who reaches the port (allowed only on loopback). `tt export` converts a pack to WireMock mappings, Microcks examples or an OpenAPI document for Prism, with a report of what each format loses.

## 7. Clean up

`Ctrl+C` in terminals A, B and C (and stop the background carrier and mock). To start over, delete `tt-dev/`.

## Next

- How it works: [Architecture overview](./architecture) and [Security model](./security).
- Other languages: [SDKs](./sdks).
- A real installation with keyguard on its own host, backups and the security checklist: [Operations](./operations).
