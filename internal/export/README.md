# internal/export: `tt export`

Converte un pacchetto twin (già verificato) in mock per strumenti di terzi e dice, per ogni
destinazione, **che cosa si è perso**. Specifica: [ARCHITECTURE §12](../../docs/ARCHITECTURE.md),
formato di ingresso: [pack.md](../../docs/spec/pack.md), [rules.md](../../docs/spec/rules.md).

Clean room: per scrivere gli exporter sono state lette **solo le pagine di documentazione
pubblica** degli strumenti (URL in fondo), mai il loro codice sorgente.

## Uso

`export.Run(ctx, cfg)` legge un `Source`, costruisce le destinazioni richieste e scrive, per
ciascuna, una cartella `<out>/<target>/` (cancellata e riscritta a ogni esecuzione) con un
`export-report.json`. Stesso ingresso, stessi byte: JSON con chiavi ordinate, YAML con chiavi
ordinate, nessun orologio, UUID derivati da hash, ordine dei mapping fissato.

```go
res, err := export.Run(ctx, export.Config{
    Source: packSource,        // adattatore di internal/pack che implementa export.Source
    OutDir: "tt-export",
})
```

`export.Source` restituisce un `export.Input` (manifest, contratti OpenAPI, regole, mondo,
guasti). L'exporter **non verifica firme né hash**: lo fa `internal/pack`, che fornisce
l'adattatore di produzione. `export.DirSource` legge una cartella senza verificare nulla ed è
solo per fixture e prove; `go run ./internal/export/cmd/ttexport --pack <dir> --out <dir>` la
usa da riga di comando (strumento di sviluppo, non il comando del prodotto).

`Config.Now` (default `time.Now`) serve solo al controllo di `not_after`: un pacchetto scaduto è
rifiutato con `export.ErrPackExpired` (`pack_expired`). Il rifiuto vero è di `internal/pack`
(`tt export` passa da lì); `Run` lo ripete per le sorgenti che non lo fanno. L'orologio non entra mai
nei byte prodotti.

Entrano solo le regole `approved`; le regole `batch` non producono nulla di eseguibile e sono
dichiarate come perdita.

### Opzioni (`tt export`)

Il comando `tt export` le registra con `export.Flags.Register(fs)` e ottiene la configurazione con
`flags.Config(source)`.

| Flag | Default | Significato |
|---|---|---|
| `--pack` | (obbligatorio) | cartella o archivio `.ttpack`, aperto e verificato dal chiamante |
| `--out` | `tt-export` | cartella di uscita, una sottocartella per destinazione |
| `--target` | `all` | `wiremock`, `microcks`, `prism` (separati da virgola) o `all` |
| `--service` | tutti | limita l'export ai servizi indicati |
| `--wiremock-advance` | `poll` | `poll`: ogni lettura della prima operazione che espone l'entità fa avanzare lo scenario di un passo; `manual`: gli stati cambiano solo con `PUT /__admin/scenarios/{nome}/state` |
| `--wiremock-fault-header` | `X-TT-Fault` | header che seleziona gli stub di guasto |
| `--wiremock-example-header` | `X-TT-Example` | header che seleziona gli esempi nominati |
| `--wiremock-customer-header` | `X-TT-Customer` | header che porta il cliente della sessione per le letture con `scope: owner` |
| `--microcks-delay` | `median` | `median`: `delay` dell'operazione = mediana della latenza (ms); `none` |
| `--microcks-stateless` | `false` | niente `SCRIPT`/`store`: si serve solo l'ultimo stato osservato di ogni entità |
| `--microcks-state-ttl` | `3600` | secondi di vita della posizione di una entità nello `store` di Microcks |

## Come si legge il pacchetto

- **Esempi del contratto** (`examples` per risposta): sono i casi OK e KO (es. `503 CARRIER_UNAVAILABLE`).
- **Mondo + regole**: per ogni regola causale e per ogni entità sintetica creata da un effetto
  (`create`) si ricostruisce la **catena** esatta `Started → effetto 1 → effetto 2 → …` dalle righe
  `history` (con il loro `outcome`) seguite dalle righe `pending` (effetti già estratti con istante
  dopo `t0`, applicati in ordine `due_offset_s`, `seq`; `vars` ed `effect_ids` risolvono i
  riferimenti `${…}` / `${effect:…}`). I passi `pending` sono marcati `projected` nei metadati.
  Niente più ricostruzione dell'esito più probabile: resta solo per i mondi v1.1 senza `outcome`
  né `pending`. Se il primo effetto è **immediato** (`after: 0s`, es. la spedizione `PENDING`) è lui
  il passo `Started`; altrimenti `Started` è "non ancora visibile".
- **Effetti che aggiornano entità esistenti** (`target_id`, es. `order-linked`, tutta r-0008): non
  sono catene. Quelle entità si servono come fotografia a `t0` (che contiene già `shipmentId`) e il
  fatto è nel report (`state`).
- **Soggetti senza effetti** (mondi v1.1): le entità della causa senza alcuna spedizione producono
  l'esito senza effetti (`never-shipped`), se la regola ne ha uno.
- **Entità senza storia**: servite come fotografia dello stato a `t0` tramite `read_by`.
- **Relazioni** (`relations`): i valori dei campi di relazione sono controllati contro il mondo
  (anche contro gli id assegnati in anticipo dalle righe `pending`). Gli esempi esportati
  conservano i legami ordine ↔ spedizione perché gli stati vengono sempre dal mondo, mai
  inventati; il report elenca i legami verificati (`relation:order.shipmentId->shipment`) e,
  se ci sono, quelli rotti (`integrity`).
- **`read_by.service`**: l'operazione è cercata nel servizio indicato (lo shop che espone la
  spedizione del corriere). Una catena esposta da più servizi avanza separatamente in ciascuno (perdita `state`).
- **`hidden_when`**: un passo nascosto è una lista vuota (o il 404 di `not_found_example`) per quella
  operazione; la stessa entità resta visibile da un'altra operazione senza `hidden_when`.
- **`by.field` su path** (`GET /orders/{id}/shipment` con `field: orderId`): la chiave è il campo.
- **Collezioni per cliente** (`by.owner`, `list`): una lista per cliente, ordinata per `order_by`
  (poi id), con `count`/`total` e, se lo schema lo dichiara, `customerId`. Sono fotografie a `t0`
  (non seguono gli scenari). `default_limit` taglia la prima pagina; `limit`/`offset`/`page`/`cursor`
  non sono onorati (perdita `selection`). Le liste senza `by` (cliente della sessione) non si esportano.
- **Visibilità per cliente** (`scope: owner`, `foreign`, `foreign_example`, `not_found_example`):
  - WireMock: per ogni lettura con proprietario noto ci sono tre stub: header `X-TT-Customer` uguale al
    proprietario (priorità base), header diverso → risposta `foreign` (404 o 403, priorità 5), nessun
    header → risposta normale (priorità 6, come il mock senza cliente nella sessione).
  - Microcks e Prism non hanno sessioni: la risposta `foreign` è un esempio nominato
    (`<nome>--foreign`, Prism: `Prefer: code=404, example=…`), ma nessun cliente la fa scattare (perdita `scope`).
- **Esiti senza rappresentante** nel mondo non producono nulla e compaiono in `losses` (`coverage`).
- **Guasti** (`faults.json`) e **latenze** (`latency_ms`, altrimenti `x-tt-latency-ms` del contratto).

## Fedeltà per destinazione

| Elemento | WireMock | Microcks | Prism |
|---|---|---|---|
| Esempi OK/KO del contratto | stub (default a priorità 10; selezione con `X-TT-Example`) | esempi nominati correlati per nome | esempi nominati (`Prefer: example=`, KO con `code=`) |
| Catene di effetti per entità | scenari (`Started` → stati = id effetto) | dispatcher `SCRIPT` + `store` (posizione condivisa, TTL) | un esempio per passo, scelto a mano |
| Esiti alternativi | scenari separati, uno per soggetto | esempi separati, uno per soggetto | esempi separati |
| Ritardi figurativi (`after`), orologio | **persi** (un passo per lettura o `PUT` sullo stato) | **persi** | persi |
| Latenza | `delayDistribution` lognormal (mediana, sigma; sigma derivata da p50/p95 se manca) | `delay` fisso = mediana | persa |
| Guasti probabilistici | stub alternativi scelti da `X-TT-Fault` (la `p` è persa) | esempio KO scelto con valore "trigger" `tt-example-<nome>` (la `p` è persa) | `Prefer: code=…, example=…` (la `p` è persa) |
| Errori di rete (tabella normativa di [mock.md](../../docs/spec/mock.md) §4) | `timeout`→ ritardo di 30 s + `EMPTY_RESPONSE`; `reset`→`CONNECTION_RESET_BY_PEER` (con latenza); `refused`, `dns`→`CONNECTION_RESET_BY_PEER` (senza latenza); `tls`→`RANDOM_DATA_THEN_CLOSE`; `other`→`EMPTY_RESPONSE` (con latenza). `refused`/`dns`/`tls` sono approssimazioni dichiarate (`approximation`) | persi | persi |
| Ritardi a intervallo (`after: {min,max}`) | persi come ogni ritardo; l'intervallo resta nei metadati dello stub (`tt.after`) e il numero di intervalli nel report | persi | persi |
| Visibilità per cliente (`scope`, `foreign`) | header `X-TT-Customer` (vedi sopra) | persa (esempio `--foreign` non selezionabile) | persa (esempio `--foreign` con `Prefer`) |
| Preset (`scenarios.json`) | scenari/stub dell'esito forzato, header di guasto e di cliente; `seed`, `times`, `p<1`, `observed` persi | esempi e valori trigger; il resto perso | `Prefer`; il resto perso |
| Regole `batch` (calendario) | **perse** | **perse** | **perse** |
| Creazione di nuove entità da `POST` | **persa** (il `POST` risponde con l'esempio del contratto) | **persa** | **persa** |
| Isolamento per sessione | **perso** (stato globale per istanza) | **perso** (`store` per servizio) | n/d |

### Preset (`scenarios.json`)

Ogni preset è mappato, per destinazione, nel campo `presets[]` del report (`status`: `mapped`,
`partial`, `lost`; `how[]`: cosa fare; `lost[]`: cosa non si può) e ogni parte persa è anche una
perdita (`preset`):

- `outcomes[{rule, outcome, times}]` → gli scenari (WireMock) o le chiamate (Microcks, Prism) dei
  soggetti del mondo con quell'esito, preferendo quelli del cliente del preset; se il mondo ne ha
  meno di `times`, la differenza è una perdita.
- `customer` / `archetype` → i soggetti di quel cliente e, in WireMock, l'header `X-TT-Customer` se
  ci sono stub con visibilità per cliente.
- `faults.rules[{status}]` con `p = 1` → WireMock: `X-TT-Fault: <status>` (o `X-TT-Example`);
  Microcks: valore trigger dell'esempio con quello status; Prism: `Prefer: code=<status>`.
  `net_error`: solo WireMock, solo se `faults.json` ha il tipo. `times`, `p < 1`, `latency_ms`,
  `mode: observed` e `seed` sono perdite (nessun contatore di chiamate, nessuna scelta casuale).

Ogni perdita è elencata in `export-report.json` (`losses[]` con `kind`, `element`, `detail`,
`count`; `loss_by_kind` somma per categoria; `exported[]` e `counts` dicono cosa è passato; `files[]`
ha SHA-256 e dimensione di ogni file). Categorie: `time`, `state`, `probabilistic-fault`,
`latency-distribution`, `batch-schedule`, `selection`, `scope`, `preset`, `approximation`,
`integrity`, `coverage`, `outcome-unmatched`, `key-collision`, `contract-gap`, `no-example`.

## WireMock

Uscita: `wiremock/<servizio>/mappings/<servizio>.json`, un file `{"mappings":[…]}` per servizio
(un'istanza WireMock per servizio, così i path non si scontrano). Non serve `__files`: i corpi
sono `jsonBody` inline.

```sh
docker run --rm -p 8080:8080 -v "$PWD/tt-export/wiremock/shipping-ext/mappings:/home/wiremock/mappings" \
  wiremock/wiremock:3.13.2 --verbose
```

Campi usati (tutti documentati): `request.method`, `urlPath` / `urlPathTemplate` + `pathParameters`,
`queryParameters.equalTo`, `headers.equalTo|matches`, `response.status|headers|jsonBody|body`,
`delayDistribution` (`lognormal`: `median`, `sigma`), `fixedDelayMilliseconds`, `fault`,
`priority`, `metadata`, `scenarioName`, `requiredScenarioState`, `newScenarioState`, `id`, `name`.
`maxValue` del lognormal non si usa (richiede WireMock 3.13.0 o successivo).

Priorità (più bassa vince): 1 guasti, 2 esempi nominati, 3 passi di scenario, 4 fotografie
dell'entità, 5 risposte `foreign`, 6 copie senza header cliente, 10 esempio di default del contratto.

Uno scenario per soggetto: `r-0007-ORD-SYN-0042`. Stati: `Started`, poi gli id degli effetti.
In modalità `poll` la prima operazione di lettura dell'entità fa avanzare lo scenario; le altre
operazioni di lettura (es. per id) mostrano lo stato corrente senza farlo avanzare. Lo stato
finale resta. `POST /__admin/scenarios/reset` riporta tutto a `Started`.

I `metadata.tt` di ogni stub riportano regola, esito, effetto, `after` figurativo, se il passo è
proiettato e (per i guasti) la `p` osservata.

## Microcks

Uscita per servizio, in `microcks/<servizio>/`:

| File | Ruolo |
|---|---|
| `<servizio>-openapi.yaml` | artefatto **primario**: OpenAPI con esempi nominati correlati per nome tra `parameters`, `requestBody` e `responses` |
| `<servizio>-examples.yaml` | secondario `APIExamples`: gli scambi del mondo (uno per passo di catena) |
| `<servizio>-metadata.yaml` | secondario `APIMetadata`: `delay` e `dispatcher`/`dispatcherRules` per operazione |

Si importa **prima il primario**, poi i secondari (nome e versione devono coincidere: sono
`info.title` e `info.version` del contratto):

```sh
curl -F file=@shipping-ext-openapi.yaml  'http://localhost:8080/api/artifact/upload?mainArtifact=true'
curl -F file=@shipping-ext-examples.yaml 'http://localhost:8080/api/artifact/upload?mainArtifact=false'
curl -F file=@shipping-ext-metadata.yaml 'http://localhost:8080/api/artifact/upload?mainArtifact=false'
# mock: http://localhost:8080/rest/shipping-ext/<versione>/v1/shipments?orderId=ORD-SYN-0042
```

Scelta del dispatcher per operazione:

- operazione con stato (catene): `SCRIPT` (Groovy) con `store`. Lo script mappa il valore del
  parametro di selezione a una lista di nomi di risposta e a una posizione conservata nello
  `store` del servizio (`store.put(chiave, valore, ttl)`); ogni chiamata dell'operazione
  "avanzante" sposta la posizione di uno, fino all'ultimo stato. Valori sconosciuti → esempio di default.
  I valori `tt-example-<nome>` selezionano direttamente l'esempio nominato.
- parametri di path e/o query: `URI_PARTS`, `URI_PARAMS` o `URI_ELEMENTS`, avvolti in `FALLBACK`
  verso l'esempio di default. (La documentazione di Microcks assegna `QUERY_ARGS` a GraphQL/gRPC:
  per REST l'equivalente è `URI_PARAMS`.)
- corpo con esempi di richiesta che differiscono per una proprietà scalare: `JSON_BODY`
  (`operator: equals`, caso `default` verso l'esempio di default).
- altrimenti nessun dispatcher: Microcks risponde con il primo esempio, e la perdita è dichiarata.

**KO e valori "trigger"**: Microcks sceglie la risposta dai valori della richiesta, non per
probabilità. Ogni esempio nominato riceve quindi per ogni parametro di path/query il valore
`tt-example-<nome>` (es. `?orderId=tt-example-carrier-unavailable` → `503 CARRIER_UNAVAILABLE`).

Limiti dell'approssimazione a stato: la posizione sta nello `store` del servizio (condiviso da tutti
i client, perso al riavvio, con TTL), non c'è isolamento per sessione. `delay` è in millisecondi
(verificato in prova: `delay: 80` → ~90 ms).

## Prism

Uscita: `prism/<servizio>/<servizio>.openapi.yaml`: il contratto (senza `x-tt-*`) con gli esempi
nominati del contratto **per primi** (Prism risponde col primo esempio se non c'è `Prefer`) e dopo
gli esempi del mondo, uno per passo di catena (`r-0007-ORD-SYN-0042--shipment-in-transit`).

```sh
docker run --rm -p 4010:4010 -v "$PWD/tt-export/prism/shipping-ext:/specs:ro" stoplight/prism:5 \
  mock -h 0.0.0.0 /specs/shipping-ext.openapi.yaml
curl -H 'Prefer: example=r-0007-ORD-SYN-0042--shipment-in-transit' 'localhost:4010/v1/shipments?orderId=x'
curl -H 'Prefer: code=503, example=carrier-unavailable'           'localhost:4010/v1/shipments?orderId=x'
```

Un esempio sotto uno status diverso dal 200 si chiede con `code=<status>` **insieme** a `example=`.
Sui Mac con Apple silicon l'immagine `stoplight/prism:5` è amd64 e in emulazione va avviata con
`--multiprocess=false` (altrimenti termina con `isPrimary` non definito).

## Validazione con gli strumenti veri

`docker_test.go` esporta la fixture `testdata/carrier-pack-v12` (ordini → spedizioni → stati,
`PENDING` nascosto, `CANCELLED`, `never-shipped`, `503 CARRIER_UNAVAILABLE`, relazioni, clienti,
`pending`, intervalli, `scenarios.json`; `testdata/carrier-pack` resta la fixture v1.1) e la fa rispondere dagli strumenti veri in container
(solo immagini ufficiali). È lento, quindi è spento di default:

```sh
TT_EXPORT_DOCKER=1 go test ./internal/export -run Docker -v
```

Immagini: `wiremock/wiremock:3.13.2` (`TT_WIREMOCK_IMAGE`), `microcks/microcks-uber:latest`
(`TT_MICROCKS_IMAGE`; provata l'immagine del 2026-03-02, digest `sha256:f11b90ea…`),
`stoplight/prism:5` (`TT_PRISM_IMAGE`). Verifiche: caricamento di tutti i mapping/artefatti,
sequenza `PENDING nascosto → CREATED → IN_TRANSIT → DELIVERED` (l'ultimo passo viene da una riga
`pending`; stato finale stabile), ramo `CANCELLED`, ramo `never-shipped`, guasti e KO, `JSON_BODY`,
latenza, reset e `PUT` dello stato in WireMock, errori di rete (il client deve vedere un errore di
trasporto), visibilità per cliente (secondo container con le mappature dello shop: 404/403 e collezione
ordinata), lettura dello shop che espone la spedizione del corriere, `Prefer` in Prism. Senza Docker i test si saltano.

## Documentazione consultata (pubblica)

WireMock
- https://wiremock.org/docs/stubbing/ (campi dei mapping, `priority`, `metadata`, caricamento)
- https://wiremock.org/docs/request-matching/ (`urlPath`, `urlPathTemplate`, `queryParameters`, `headers`, `bodyPatterns`)
- https://wiremock.org/docs/simulating-faults/ (`fixedDelayMilliseconds`, `delayDistribution`, `fault`)
- https://wiremock.org/docs/stateful-behaviour/ (scenari, `Started`, API `/__admin/scenarios`)
- https://wiremock.org/docs/docker/ (immagine, `/home/wiremock/mappings`, `--verbose`)

Microcks
- https://microcks.io/documentation/references/artifacts/openapi-conventions/ (esempi nominati, correlazione per nome, `x-microcks-operation`)
- https://microcks.io/documentation/references/examples (formato `APIExamples`)
- https://microcks.io/documentation/references/metadata (formato `APIMetadata`)
- https://microcks.io/documentation/explanations/dispatching/ (`URI_PARTS`, `URI_PARAMS`, `URI_ELEMENTS`, `JSON_BODY`, `FALLBACK`, `SCRIPT`, `store`)
- https://microcks.io/documentation/explanations/multi-artifacts/ (artefatti primari e secondari)
- https://microcks.io/documentation/guides/usage/importing-content/ (`POST /api/artifact/upload`, `mainArtifact`)

Prism
- https://docs.stoplight.io/docs/prism/83dbbd75532cf-http-mocking (mock server, header `Prefer`, immagine Docker)
- https://raw.githubusercontent.com/stoplightio/prism/master/docs/guides/01-mocking.md (guida ufficiale al mocking: scelta degli esempi, `Prefer: example=`)
