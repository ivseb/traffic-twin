# Verità di riferimento della demo

Questo file elenca **cosa traffic-twin deve riscoprire** osservando il traffico della demo. È il banco di prova di due componenti:

- il **miner delle regole** (ARCHITECTURE §7) deve ritrovare le regole della sezione 2;
- l'**inferenza dei contratti** (ARCHITECTURE §6) deve riprodurre i fatti della sezione 3.

Tutti i numeri del corriere vengono da un unico file, [`carrier/truth.json`](carrier/truth.json). Se cambia quel file, cambia la verità: questo documento descrive i valori di default. Le frequenze lato shop dipendono dal comportamento dei clienti finti, descritto in [`loadgen/main.go`](loadgen/main.go) e [`loadgen/people.go`](loadgen/people.go).

Durante una prova, `GET /__truth` sul corriere e sullo shop restituisce i **conteggi esatti** di ciò che è stato prodotto (non stime). Per giudicare il miner si confrontano le sue stime con quei conteggi, non con le probabilità teoriche.

## 1. Tempo

- Tutti i tempi qui sotto sono **simulati**. L'orologio è condiviso da tutti i processi:
  `sim = SIM_EPOCH + (ora_reale − CLOCK_ANCHOR) × TIME_SCALE`.
- `TIME_SCALE` = secondi simulati per secondo reale. Default 60 (1 s reale = 1 min simulato); lo smoke test usa 2880 (30 s reali = 1 giorno).
- I timestamp nei corpi (`createdAt`, `updatedAt`, `eta`) sono in tempo simulato. I timestamp di cattura di uno strumento esterno sono invece reali: per convertire un ritardo reale in simulato si moltiplica per `TIME_SCALE`.
- Riproducibilità: il destino di ogni spedizione (esito, ritardi, `eta`, motivo di annullamento, id) dipende solo da `(SEED, orderId)`, non dall'ordine di arrivo delle richieste. Gli id degli ordini dello shop e il comportamento dei clienti dipendono da `SEED`. Guasti e latenze del corriere vengono da un flusso unico con seed, quindi dipendono anche dall'ordine delle richieste.

## 2. Regole che il miner deve ritrovare

### R1 · Chiavi di legame

| Valore | Dove compare |
|---|---|
| id ordine | shop `POST /orders` → `resp.id`, header `Location`; corriere `POST /v1/shipments` → `req.orderId`, `resp.orderId`; corriere `GET /v1/shipments` → query `orderId`, `items[].orderId`; shop path `/orders/{id}`, `/orders/{id}/shipment` → `resp.orderId`; shop `GET /customers/{id}/orders` → `items[].id` |
| id spedizione | corriere `POST /v1/shipments` → `resp.shipmentId`; shop `POST /orders` → `resp.shipmentId`; corriere `GET /v1/shipments` → `items[].shipmentId`; shop `GET /orders/{id}/shipment` → `resp.shipmentId` |
| id cliente | `sub` del token Bearer; path `/customers/{id}/orders`; `resp.customerId` di ordini e liste |
| trace | lo shop propaga il `trace-id` del `traceparent` in ingresso alla chiamata in uscita verso il corriere |

Campi a bassa cardinalità da **non** usare come chiave: `status`, `service`, `currency`, `country`, `cancelReason`, `sku`.

### R2 · Un ordine creato genera una spedizione presso il corriere (sincrono)

- **Causa**: shop `POST /orders` → `201`, `bind: order = $.resp.id`.
- **Effetto immediato**, nella stessa richiesta e nello stesso trace: corriere `POST /v1/shipments` con `req.orderId == order`, risposta `202` con `status: PENDING`.
- **Invariante esatto**: ogni `201` di `POST /orders` corrisponde a **esattamente un** `202` di `POST /v1/shipments` (verificato dallo smoke test: `shop.carrier_calls["POST /v1/shipments"]["202"] == carrier.shipments`).
- **Ritentativi**: se il corriere risponde `503`, lo shop ripete la stessa chiamata fino a 3 tentativi in tutto (attese 50 ms, 100 ms). Un `503` non crea mai la spedizione. Se falliscono tutti e tre (probabilità ≈ 10⁻⁶) lo shop risponde `503 CARRIER_UNAVAILABLE` e l'ordine non esiste.

### R3 · Ciclo di vita della spedizione (r-0007 dell'architettura)

```yaml
cause:   { service: shop-api, op: POST /orders, when: { status: 201 }, bind: { order: $.resp.id } }
effects:
  - id: shipment-created          # compare in GET /v1/shipments?orderId=order
    set: { status: CREATED }
    after: 2m..10m                # uniforme; magnitude_hint: minutes
  - id: shipment-in-transit
    after_effect: shipment-created
    set: { status: IN_TRANSIT }
    after: 1h..6h                 # uniforme; magnitude_hint: hours
  - id: shipment-delivered
    after_effect: shipment-in-transit
    set: { status: DELIVERED }
    after: 6h..36h                # uniforme, OPPURE prima per il batch R4
outcomes:
  - { name: happy,         p: 0.93, effects: [shipment-created, shipment-in-transit, shipment-delivered] }
  - { name: cancelled,     p: 0.04, effects: [shipment-created], then: { set: { status: CANCELLED }, after: 30m..4h } }
  - { name: never-shipped, p: 0.03, effects: [] }
```

Dettagli che il miner deve rispettare:

- Finché è `PENDING` la spedizione **non è visibile**: `GET /v1/shipments?orderId=…` risponde `200 { "items": [] }` e lo shop `GET /orders/{id}/shipment` risponde `404 SHIPMENT_NOT_FOUND`. "Comparire" significa passare da lista vuota a un elemento con `status: CREATED`.
- `never-shipped`: la spedizione resta `PENDING` per sempre, quindi la lista resta vuota per sempre. Il cliente finto smette di controllare dopo 4 giorni.
- `cancelled`: `CREATED → CANCELLED`, mai `IN_TRANSIT`. Solo in questo stato compare il campo `cancelReason` (`ADDRESS_UNREACHABLE` o `DAMAGED_IN_WAREHOUSE`, 50/50).
- Gli stati non tornano mai indietro. `DELIVERED` e `CANCELLED` sono finali.
- Il campo `updatedAt` è l'istante simulato esatto della transizione.

### R4 · Consolidamento notturno delle consegne (regola batch, r-0012 dell'architettura)

```yaml
schedule: "0 2 * * *"            # 02:00 UTC simulate, ogni giorno
select: { service: shipping-ext, object: shipment, where: { status: IN_TRANSIT } }
set: { status: DELIVERED }
fraction: 0.6                    # esatta: round(0.6 × spedizioni IN_TRANSIT in quel momento)
```

- Nessuna richiesta dell'utente precede questi cambi: sono "spontanei" e tutti con `updatedAt` = `…T02:00:00Z`.
- La scelta delle spedizioni è un rimescolamento con seed (`SEED`, istante del batch).
- Una spedizione consegnata dal batch non viene consegnata una seconda volta dal suo timer (R3).
- In tempo reale il batch scatta ogni `86400 / TIME_SCALE` secondi (24 min a scala 60, 30 s a scala 2880). `/__truth` → `counts.batch_runs` riporta per ogni esecuzione `sim_at`, `real_at`, `eligible`, `moved`.
- `counts.delivered_by` separa le consegne `timer` (R3) da quelle `batch` (R4). Con i default circa metà delle consegne avviene alle 02:00.

### R5 · Comportamento dei client (per profili e archetipi, ARCHITECTURE §8)

| Profilo | Quota clienti | Ordini (media, esponenziale) | Visite "i miei ordini" |
|---|---|---|---|
| `frequent_buyer` | 15% | 1 al giorno | ogni 12 h |
| `occasional_buyer` | 45% | 1 ogni 6 giorni | ogni 2 giorni |
| `browser_only` | 40% | mai | ogni 12 h |

Dopo un `201` il cliente segue la spedizione: primo controllo 1–20 min dopo, poi ogni 2–4 h, finché vede `DELIVERED`/`CANCELLED` o sono passati 4 giorni. Il 30% dei controlli rilegge anche `GET /orders/{id}`.

## 3. Fatti di contratto che l'inferenza deve riprodurre

Le percentuali "presenza" sono la quota di risposte (o richieste) in cui il campo c'è. Quelle marcate *per cliente* sono un attributo fisso del cliente finto: la quota attesa è la stessa, ma i campioni sono correlati.

### 3.1 Corriere `carrier.example` (in uscita dallo shop)

**`POST /v1/shipments`**

| Status | Frequenza | Corpo |
|---|---|---|
| `202` | 99% | `{ shipmentId, orderId, status: "PENDING", service, createdAt }` + header `Location` |
| `503` | 1% | `{ error: { code: "CARRIER_UNAVAILABLE", message } }` |
| `400` | 0% (esiste: `INVALID_REQUEST` con `field`) | lo shop manda sempre corpi validi |
| `409` | 0% (esiste: `SHIPMENT_EXISTS`) | lo shop non duplica mai |

Richiesta: `orderId` (sempre), `service` (sempre; `EXPRESS` se l'ordine ha 4 righe, cioè 25%, altrimenti `STANDARD`), `parcels` (intero ≥ 1), `recipient.fullName` (sempre), `recipient.email` (sempre), `recipient.phone` (≈60%, per cliente), `address.line1/city/postcode/country` (sempre), `address.line2` (≈25%, per cliente).

Latenza iniettata: log-normale, mediana 140 ms, σ 0,5 → p95 ≈ 318 ms, p99 ≈ 448 ms (massimo 2 s).

**`GET /v1/shipments?orderId=…`**

| Status | Frequenza | Corpo |
|---|---|---|
| `200` | 99% | `{ items: [] }` oppure `{ items: [ { shipmentId, orderId, status, service, updatedAt, eta?, cancelReason? } ] }` |
| `503` | 1% | `{ error: { code: "CARRIER_UNAVAILABLE", message } }` |

- `items` ha 0 o 1 elemento. `status` ∈ {`CREATED`, `IN_TRANSIT`, `DELIVERED`, `CANCELLED`}: `PENDING` **non** compare mai qui (vedi R3).
- `eta`: stringa date-time, presente nel **37%** delle spedizioni (attributo fisso della spedizione, quindi ≈37% anche degli elementi serviti).
- `cancelReason`: presente se e solo se `status == CANCELLED`.
- Latenza: log-normale, mediana 80 ms, σ 0,6 → p95 ≈ 215 ms, p99 ≈ 323 ms.

Il 503 viene estratto prima di tutto il resto, con probabilità 0,01 su ogni chiamata a `/v1/*`.

### 3.2 Shop `shop-api` (in ingresso)

Header comuni delle richieste: `Authorization: Bearer <JWT non firmato, alg none>` (sempre, salvo i casi 401), `traceparent` (sempre), `Idempotency-Key` (sempre su `POST /orders`). Tutti gli errori hanno la forma `{ error: { code, message, field?, retryable? } }`.

**`POST /orders`**

| Status | Frequenza | `error.code` |
|---|---|---|
| `201` | ≈95–97% | — |
| `400` | 3% | `VALIDATION_ERROR` (`field` = `email` o `items[0].qty`), `UNKNOWN_SKU`, `INVALID_COUPON`: un quarto ciascuno |
| `409` | fino a 1,94% (0,97 × 2%), solo per clienti che hanno già ordinato; in uno smoke di 90 s ≈ 0,8% | `IDEMPOTENCY_KEY_REUSED` |
| `503` | ≈ 10⁻⁶ | `CARRIER_UNAVAILABLE` |

Corpo della richiesta valida: `items[]` (1–4 righe, `sku` tra 8 codici `SKU-…`, `qty` 1–3), `email` (sempre, `@example.com`), `phone` (≈60%, per cliente), `shippingAddress{fullName, line1, line2?, city, postcode, country}` (`line2` ≈25%, per cliente; `country` sempre `IT`), `note` (30%, testo libero con dati personali finti), `couponCode` (15%, `WELCOME10`/`AUTUMN15`), `giftWrap` (10%, booleano).

Risposta `201` (header `Location: /orders/{id}`): `id`, `customerId`, `status: "CONFIRMED"`, `items[]{sku, qty, unitPrice}`, `currency: "EUR"`, `subtotal`, `total`, `email`, `shippingAddress`, `shipmentId`, `createdAt` sempre; `phone` ≈60%; `shippingAddress.line2` ≈25%; `note` 30%; `couponCode` e `discount` 15% (sempre insieme); `giftWrap` 10%. I campi opzionali della risposta compaiono **se e solo se** c'erano nella richiesta.

**`GET /orders/{id}`** — `200` con lo stesso corpo del `201`; `404 ORDER_NOT_FOUND` (id inesistente, oppure ordine di un altro cliente: non si rivela che esiste). Il 404 nasce solo dai clienti che aprono un id inventato: il 5% delle loro visite.

**`GET /orders/{id}/shipment`**

| Status | Quando | Corpo / `error.code` |
|---|---|---|
| `200` | la spedizione è visibile | `{ orderId, shipmentId, status, updatedAt, eta?, cancelReason? }`, stesse regole di presenza del corriere |
| `404` | spedizione ancora `PENDING` (primo controllo troppo presto) o `never-shipped` | `SHIPMENT_NOT_FOUND` |
| `503` | esattamente quando il `GET` al corriere risponde `503` (≈1%, nessun ritentativo) | `TRACKING_UNAVAILABLE`, `retryable: true` |

**`GET /customers/{id}/orders`**

| Status | Frequenza | Corpo / `error.code` |
|---|---|---|
| `200` | ≈96,8% | `{ customerId, count, items[]{id, status, total, currency, createdAt} }` |
| `401` | ≈1,05% (1% delle visite, senza token) | `UNAUTHENTICATED` |
| `403` | ≈2,1% (2% delle visite, cliente altrui) | `FORBIDDEN` |

Altri errori esistenti ma non generati dai clienti finti: `400 INVALID_JSON`, `405 METHOD_NOT_ALLOWED`, `413 PAYLOAD_TOO_LARGE`, `502 CARRIER_REJECTED`, `404 NOT_FOUND` (rotta sconosciuta).

### 3.3 Dati personali finti (per il sanitizer)

Tutti inventati: nomi e cognomi italiani comuni, email `nome.cognome.N@example.com`, telefoni `+39 555 …`, indirizzi con vie inventate, note libere come "Citofonare Neri, interno 4" o "Consegna dopo le 18, chiamare il +39 555 …". Campi da **eliminare** secondo una policy deny-by-default: `email`, `phone`, `shippingAddress.*`, `recipient.*`, `address.*`, `note`, il token `Authorization`.

## 4. Numeri di uno smoke test (riferimento)

`./smoke.sh` con `TIME_SCALE=2880`, `DURATION=90s`, `CUSTOMERS=2000`, `SEED=42` (3 giorni simulati):

| Misura | Valore |
|---|---|
| spedizioni | 1316 |
| esiti happy / cancelled / never-shipped | 1229 / 47 / 40 (93,4% / 3,6% / 3,0%) |
| consegne timer / batch | 409 / 521 |
| esecuzioni batch | 3, ognuna con `moved = round(0,6 × eligible)` |
| `eta` per spedizione / per elemento servito | 37,5% / 37,6% |
| 503 del corriere | 91 su 9290 chiamate (0,98%) |
| p50 latenza GET / POST | 80 ms / 137 ms |

I conteggi esatti cambiano un poco tra un'esecuzione e l'altra (concorrenza e tempi reali), mai le probabilità.
