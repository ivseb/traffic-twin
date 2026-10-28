# Demo di traffic-twin

Un piccolo e-commerce **inventato** con un corriere esterno **inventato**, il cui comportamento è noto in anticipo. Serve a due cose:

1. **provare traffic-twin** senza avere traffico di produzione;
2. fare da **banco di prova automatico** per l'inferenza dei contratti e per il miner delle regole: quello che devono ritrovare è scritto in [GROUND_TRUTH.md](GROUND_TRUTH.md) e i conteggi esatti di ogni prova si leggono da `GET /__truth`.

Tutti i dati sono finti: email `@example.com`, telefoni `+39 555 …`, nomi di host locali o `.example`. Nessuna azienda reale.

```
 loadgen ──▶ shop (Node.js, :3000) ──▶ carrier (Go, :8080)
 2000 clienti      shop-api                carrier.example
 finti                                     verità: carrier/truth.json
                           ▲
                           └── qui, in futuro, tt-egress (vedi sotto)
```

| Cartella | Cosa è |
|---|---|
| [`shop/`](shop/) | API dell'e-commerce. Node.js ≥ 20, **zero dipendenze** (`node:http`, `fetch`). Stato in memoria. |
| [`carrier/`](carrier/) | Corriere esterno finto, Go solo libreria standard. Il comportamento viene da [`carrier/truth.json`](carrier/truth.json). |
| [`loadgen/`](loadgen/) | Clienti finti con profili di comportamento, seed deterministico. Ordinano e poi controllano la spedizione periodicamente, come farebbe un'app. |
| [`truthcheck/`](truthcheck/) | Confronta i conteggi di `/__truth` con la verità, entro tolleranze statistiche. |
| [`internal/simclock/`](internal/simclock/) | Orologio accelerato condiviso. |
| [`smoke.sh`](smoke.sh) | Smoke test completo con Docker. |

I programmi Go stanno nel modulo `github.com/ivseb/traffic-twin/demo` ([`go.mod`](go.mod)), separato da quello del progetto principale.

## Avvio rapido

Serve Docker con Compose v2.

```sh
cd demo
docker compose up --build
```

Partono `carrier`, `shop` e `loadgen`. Con i default (`TIME_SCALE=60`) un secondo reale vale un minuto simulato: una spedizione compare dopo pochi secondi, va in transito dopo qualche minuto, il batch notturno scatta ogni 24 minuti reali.

Per vedere la verità e i conteggi prodotti finora:

```sh
curl -s localhost:8080/__truth | jq .counts      # corriere
curl -s localhost:3000/__truth | jq .            # shop
docker compose run --rm truthcheck               # controlli automatici
```

`truthcheck` ha senso dopo almeno un paio di giorni simulati e qualche centinaio di spedizioni (a scala 60: circa un'ora reale); prima segnala giustamente "campione troppo piccolo". Lo smoke test qui sotto fa tutto in 90 secondi.

Per fermare tutto: `docker compose down`.

### Chiamare lo shop a mano

Il token è un JWT **non firmato** (`alg: none`): lo shop legge solo `sub`, che è l'id del cliente.

```sh
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJDVVMtMDAwMDAxIn0.'   # sub = CUS-000001

curl -s -X POST localhost:3000/orders \
  -H "Authorization: Bearer $TOKEN" -H 'Idempotency-Key: prova-1' \
  -d '{"items":[{"sku":"SKU-MUG-001","qty":2}],
       "email":"giulia.neri.1@example.com",
       "shippingAddress":{"fullName":"Giulia Neri","line1":"Via delle Rose 12",
                          "city":"Bologna","postcode":"40121","country":"IT"},
       "note":"Citofonare Neri"}'

curl -s localhost:3000/customers/CUS-000001/orders -H "Authorization: Bearer $TOKEN"
curl -s localhost:3000/orders/<id>/shipment        -H "Authorization: Bearer $TOKEN"
curl -s 'localhost:8080/v1/shipments?orderId=<id>'
```

## Endpoint

**shop** (`:3000`)

| Metodo e percorso | Cosa fa |
|---|---|
| `POST /orders` | Crea un ordine e registra la spedizione presso il corriere (`POST /v1/shipments`, con ritentativi sui 503). Supporta `Idempotency-Key`. |
| `GET /orders/{id}` | Legge un proprio ordine. |
| `GET /customers/{id}/orders` | Elenca i propri ordini (`403` se l'id non è quello del token). |
| `GET /orders/{id}/shipment` | Stato della spedizione, chiesto al corriere (`GET /v1/shipments?orderId=`). |
| `GET /__truth`, `GET /__health` | Conteggi esatti e stato; non fanno parte dell'API. |

**carrier** (`:8080`)

| Metodo e percorso | Cosa fa |
|---|---|
| `POST /v1/shipments` | Registra una spedizione: `202` con `status: PENDING`. |
| `GET /v1/shipments?orderId=` | Spedizioni visibili dell'ordine (`items` vuoto finché è `PENDING`). |
| `GET /__truth` | Configurazione della verità + conteggi esatti prodotti (esiti estratti, transizioni, consegne timer/batch, esecuzioni del batch, presenza di `eta`, status per operazione, quantili di latenza). |
| `GET /__health` | Stato. Senza guasti né latenza, non conteggiato. |

## Configurazione

Tutte le variabili si possono passare a `docker compose` dall'ambiente.

| Variabile | Default | Effetto |
|---|---|---|
| `TIME_SCALE` | `60` | Secondi simulati per secondo reale. `2880` = un giorno ogni 30 s. |
| `SIM_EPOCH` | `2026-10-19T06:00:00Z` | Ora simulata all'istante `CLOCK_ANCHOR`. |
| `CLOCK_ANCHOR` | vuoto = oggi 00:00 UTC | Istante reale (unix, secondi) da cui parte l'orologio. Deve essere uguale per tutti i servizi: compose lo passa a tutti. |
| `SEED` | `42` | Seed di corriere, shop e clienti. |
| `CUSTOMERS` | `2000` | Numero di clienti finti. |
| `MAX_RPS` | `300` | Tetto di richieste al secondo del loadgen. |
| `DURATION` | `0s` | Durata del loadgen; `0s` = finché non lo si ferma. |
| `SHOP_PORT`, `CARRIER_PORT` | `3000`, `8080` | Porte sull'host (`0` = porta libera a caso). |
| `CARRIER_BASE_URL` | `http://carrier:8080` | Dove lo shop trova il corriere. È lo slot per tt-egress. |
| `TRUTH_FILE` | vuoto = `truth.json` incorporato | Solo corriere: un file di verità alternativo. |

L'orologio è lo stesso in tutti i processi: `sim = SIM_EPOCH + (ora_reale − CLOCK_ANCHOR) × TIME_SCALE`. I timestamp nei corpi (`createdAt`, `updatedAt`, `eta`) sono simulati.

## Slot per tt-egress

Lo shop parla col corriere **solo** tramite `CARRIER_BASE_URL`. Per catturare il traffico in uscita basta mettere `tt-egress` in mezzo e cambiare quella variabile, senza toccare il codice:

```
shop ──▶ tt-egress (:9090) ──▶ carrier (:8080)
```

1. scommentare il servizio `tt-egress` in [`docker-compose.yml`](docker-compose.yml) (oggi è un segnaposto: tt-egress non esiste ancora);
2. avviare con `CARRIER_BASE_URL=http://tt-egress:9090 docker compose up`.

Lo shop propaga anche l'header `traceparent`, così le chiamate in ingresso e in uscita della stessa richiesta hanno lo stesso `trace-id` (ARCHITECTURE §5).

## Smoke test

```sh
./smoke.sh
```

Costruisce le immagini, avvia lo stack con orologio accelerato (`TIME_SCALE=2880`, quindi 90 s reali = 3 giorni simulati), lascia girare i 2000 clienti per 90 secondi, poi lancia `truthcheck` che controlla tramite `/__truth`:

- che siano comparsi tutti gli esiti (happy, cancelled, never-shipped), tutte le transizioni, consegne sia da timer sia dal batch;
- che le frequenze (esiti, 503, presenza di `eta`) siano entro 4 deviazioni standard dalla verità, e la mediana delle latenze entro il 15%;
- che il batch abbia spostato esattamente `round(0,6 × idonee)` spedizioni a ogni esecuzione;
- che ogni ordine creato dallo shop corrisponda a una e una sola spedizione;
- che lo shop abbia prodotto tutti gli status attesi (201, 400, 409, 404, 401, 403, 503).

Alla fine smonta tutto, anche in caso di errore. Usa un nome di progetto proprio e porte casuali, quindi non disturba uno stack già avviato. Si può allungare con `DURATION=180s ./smoke.sh`.

## Senza Docker

```sh
cd demo
go run ./carrier                                            # :8080
CARRIER_BASE_URL=http://localhost:8080 node shop/server.js  # :3000
SHOP_BASE_URL=http://localhost:3000 go run ./loadgen
go run ./truthcheck
```

Senza `CLOCK_ANCHOR` i processi usano la mezzanotte UTC di oggi, quindi sono d'accordo tra loro anche se partono in momenti diversi.
