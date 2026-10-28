# tt-mock: il mock con stato

Implementazione di `tt mock` (ARCHITECTURE §11): serve un pacchetto twin firmato come mock HTTP con
stato per sessione, orologio virtuale, regole causa → effetto, guasti e latenze alle frequenze osservate,
API di controllo e registro delle chiamate. Il comportamento normativo è in
[`docs/spec/mock.md`](../../docs/spec/mock.md), [`docs/spec/rules.md`](../../docs/spec/rules.md) §2 e §6,
[`docs/spec/pack.md`](../../docs/spec/pack.md) e [`api/control-api.v1.openapi.yaml`](../../api/control-api.v1.openapi.yaml)
(1.2.0): questo file riassume come lo realizza il codice.

Pacchetti: `internal/mock` (runtime) e `internal/pack` (lettura e verifica del pacchetto; la scrittura e
la firma restano a gate e keyguard; `Pack.Files` conserva i byte verificati per `tt export`).
`internal/pack/packtest` costruisce pacchetti firmati **solo per i test**: `DemoSpec()` modella la demo
(GROUND_TRUTH) con ritardi a intervallo, `ExactDemoSpec()` con intervalli degeneri (`min = max`) per test a istanti esatti.

## Integrazione nel comando `tt`

`tt mock` è già agganciato: `mock.RunCLI(ctx, args, stdout, stderr) int` interpreta i flag, legge le variabili
d'ambiente e restituisce il codice di uscita (0 ok, 1 errore, 2 uso errato). In alternativa `mock.Run(ctx, mock.Config{...})`
da codice, e `mock.New(cfg)` + `Handler()` per montarlo in un `httptest.Server`.

## Modalità console

`tt mock --console <url> --group <gruppo>` (con `TT_MOCK_TOKEN`) è il mock della pagina **Mock** della console
([`docs/spec/mock.md`](../../docs/spec/mock.md) §6, `console.go`): `RunConsole` ascolta subito (solo `/__tt/health` finché
non arriva un pacchetto), scarica l'ultimo pacchetto pubblicato del gruppo, lo verifica con `New` come un file, controlla
`manifest.group` e lo sostituisce senza riavvio (`atomic.Pointer[Mock]`). Il rapporto (`Report`) porta stato, URL dei
servizi (`ServiceURLs`), sessioni (`Sessions`) e il riassunto delle chiamate (`Config.OnCall` → `Call`: niente header,
corpi, query); la risposta della console porta l'ultimo `pack_id` e i comandi da eseguire sull'API di controllo
(elenco chiuso, mai il registro). Un `401` ferma il mock (`ErrTokenRefused`).

| Flag | Variabile | Significato |
|---|---|---|
| `--console <url>` | `TT_MOCK_CONSOLE` | URL della console (https; http solo sul loopback). Esclude `--pack` |
| `--group <g>` | `TT_MOCK_GROUP` | gruppo di cui servire i pacchetti |
| `--token` | `TT_MOCK_TOKEN` | token del mock (`ttm_...`); meglio la variabile |
| `--public-url` | `TT_MOCK_PUBLIC_URL` | indirizzo con cui i test raggiungono il mock, mostrato nella console |
| `--console-ca` | `TT_MOCK_CONSOLE_CA` | CA (PEM) del certificato della console, se non è pubblica |
| `--instance` | `TT_MOCK_INSTANCE` | nome del mock nella console (default: host name) |
| `--report-interval` | | pausa tra due rapporti quando la console non li trattiene (default 5s) |

## Flag e variabili d'ambiente

| Flag | Default | Significato |
|---|---|---|
| `--pack <percorso>` | (obbligatorio) | Cartella del pacchetto o archivio `.ttpack`. Vale anche come argomento posizionale |
| `--addr` | `127.0.0.1:8480` | Indirizzo di ascolto, unico per dati e controllo. Fuori dal loopback serve `TT_CONTROL_TOKEN`, altrimenti il mock **non parte** |
| `--seed <n>` | seed del pacchetto | Seed della sessione `default` e delle sessioni create senza `seed` |
| `--faults observed\|off` | `observed` | Guasti delle nuove sessioni: frequenze di `faults.json`, oppure nessuno |
| `--latency real\|record\|off` | `real` | `real` attende la latenza iniettata; `record` la scrive solo nel registro (test veloci); `off` la ignora |
| `--net-timeout <durata>` | `30s` | Quanto un timeout di rete simulato tiene aperta la connessione |
| `--max-pack-age <durata>` | `0` (nessun limite) | Politica locale: rifiuta pacchetti con `created_at` più vecchio di questo valore (si somma a `not_after`, vale il più stretto) |
| `--max-sessions <n>` | `1000` | Numero massimo di sessioni contemporanee |
| `--max-body <byte>` | `1048576` | Dimensione massima del corpo di una richiesta |
| `--journal-max <n>` | `10000` | Voci di registro conservate per sessione (le più vecchie escono) |
| `--max-advance <durata>` | `87840h` (3660 giorni) | Avanzamento massimo dell'orologio in una chiamata |
| `--quiet` | no | Solo avvisi nel log |

| Variabile | Significato |
|---|---|
| `TT_GATE_PUBKEYS` | **Obbligatoria.** Chiavi pubbliche del gate: voci `kid:base64url` separate da virgola, oppure il percorso di un file con una voce per riga (`#` per i commenti) |
| `TT_GATE_REVOKED_KIDS` | Facoltativa. `kid` di chiavi del gate da non fidare più (virgola o spazio), anche se sono ancora in `TT_GATE_PUBKEYS`: va impostata quando una chiave ritirata o trapelata resta nella lista durante una rotazione. Se `TT_GATE_PUBKEYS` è un file, non deve essere scrivibile da gruppo o altri |
| `TT_CONTROL_TOKEN` | Se impostata, ogni chiamata a `/__tt/` richiede `Authorization: Bearer <token>`, **tranne** `GET /__tt/health`, sempre pubblico. Non esiste un flag per non finire nell'elenco dei processi. **Vuota = API di controllo aperta** (vedi sotto) |

> **Attenzione: senza `TT_CONTROL_TOKEN` l'API di controllo è aperta a chiunque raggiunga la porta.** Il mock lo consente solo sul
> loopback (`127.0.0.1`, `::1`), ma anche lì ogni processo della macchina (e, in CI, ogni altro job dello stesso runner o ogni
> container in rete host) può creare e azzerare sessioni, forzare guasti ed esiti, spostare l'orologio e leggere il registro
> delle chiamate. **In CI imposta sempre `TT_CONTROL_TOKEN`**, anche sul loopback: un valore casuale per esecuzione
> (`export TT_CONTROL_TOKEN="$(openssl rand -hex 24)"`), passato ai test come segreto e mai scritto nel repository. Il
> token protegge anche `GET /__tt/pack` e il registro; solo `GET /__tt/health` resta pubblico.

```sh
export TT_GATE_PUBKEYS='gate-2026-1:Xz9kjHlb5S5NV-EPR09AZ3mQmxEJnC3cEK_trqAeaEE'
tt mock --pack ./twin-pack --addr 127.0.0.1:8480 --latency record
curl -s -X POST localhost:8480/__tt/sessions -d '{"scenario":"shipment-cancelled"}'
curl -s -X POST localhost:8480/__svc/shop-api/orders -H 'X-TT-Session: s-01' -d '{"items":[{"sku":"SKU-AAAA0001","qty":1}],"email":"a@example.com"}'
```

## Avvio e verifica del pacchetto

Prima di servire qualsiasi cosa (mock.md §1): firma Ed25519 su `"tt.pack/v1" || 0x00 || manifest.json` con una chiave
di `TT_GATE_PUBKEYS` (non firmato, `kid` sconosciuto, firma o hash errati → rifiuto); schema del manifest e
`not_after` (orologio ≥ `not_after` → `pack_expired`; un mock già avviato continua a servire ma scrive un avviso nel log alla scadenza);
`--max-pack-age` (default: 90 giorni per i pacchetti senza `not_after`; negativo = nessun controllo); `created_at` non nel futuro; forma canonica del manifest; SHA-256 e dimensione di ogni file, nessun file non elencato, nessun link simbolico; contratti OpenAPI 3.1;
regole (solo `approved`, probabilità che sommano a 1, rami chiusi, nessun ciclo di `after_effect`, riferimenti `${var}` / `${effect:id}`
interi e ben fondati, `read_by`/`list`/`scope`/`relations` validi); `world.jsonl` (ordine dei tipi di riga, ordinamento di ciascun tipo,
`meta` per prima, conteggio clienti, `seq` della storia per entità, righe `pending` ordinate per `(due_offset_s, seq)`);
**integrità del mondo** (campi di relazione che citano entità esistenti o create da una riga `pending`, `customer_id` esistenti,
righe `pending` che citano regola, ramo ed effetto coerenti e un'entità esistente o creata prima); `faults.json`;
`scenarios.json` (`tt.scenarios/v1`: clienti, archetipi, regole, esiti, servizi esistenti); `gate-report.json` con esito `pass`.
Infine ogni operazione citata da regole, `read_by`, guasti e preset deve esistere nei contratti. Un errore ferma l'avvio.

## Come risponde

**Servizio.** Prefisso `/__svc/{servizio}/...` (nome o `upstream_alias`), altrimenti header `Host` (nome, alias, parte host di
`host:...`, porta ignorata, prima etichetta DNS). Il prefisso vince.

**Sessione.** `X-TT-Session`; senza header vale `default`, creata all'avvio con il seed del pacchetto. Malformata o sconosciuta:
`400 bad_session_id` / `404 session_not_found`, mai ricaduta sulla `default` (non registrate nel registro).

**Validazione.** Primo errore nell'ordine path, query, header, cookie, paginazione, corpo. Parametri e corpo JSON contro lo schema
(`type`, `required`, `properties`, `additionalProperties: false`, `enum`, `const`, `pattern`, limiti, `items`, `allOf/anyOf/oneOf`, `$ref`
locali, `format` date-time/date). Una richiesta non valida riceve il `400`/`422` dichiarato dal contratto (primo esempio), altrimenti
l'involucro `{code: "invalid-request", message, pointer}`; il registro conserva `reason: invalid-request` e il `pointer` (JSON Pointer nel
documento virtuale `/path/..`, `/query/..`, `/headers/..` in minuscolo, `/cookies/..`, `/body/..`). Rotta sconosciuta: `404` (`405` con
`Allow`); servizio sconosciuto: `404 no-service`; corpo oltre `--max-body`: `413 payload_too_large` (registrata come non corrispondente).

**Ordine di una richiesta** (rules.md §6): decisione della risposta (guasto o normale) → creazione dell'entità (`created_by`) →
prima stesura del corpo → scatto delle regole (`bind` dalla richiesta e dalla stesura) e coda degli effetti → **applicazione immediata degli
effetti con istante = causa** (così `POST /orders` risponde con lo `shipmentId` appena creato) → corpo ricostruito se qualcosa è cambiato.

**Corpi di risposta** (mock.md §2): stato dell'entità per nome di proprietà (le facoltative solo se nello stato; le obbligatorie assenti
dall'esempio, da `x-tt-value`, da `enum`/`default`, dal tipo; campi non dichiarati dal contratto non escono); **campi di relazione mai
inventati** (obbligatori e assenti: `null` se lo schema lo ammette, altrimenti omessi); campi derivati `customerId`/`customer_id`
(proprietario, nelle liste con `by.owner` quello selezionato), `createdAt`/`updatedAt` (istanti virtuali; per le entità del mondo dalla
`history`); senza entità l'esempio o la generazione dallo schema, con `date-time` = orologio virtuale e id sintetici stabili per richiesta.

**Letture** (`read_by`, rules.md §2.3–§2.5): `by` per id, per campo (`field`), per proprietario (`owner: true`) o assente (entità del cliente della
sessione); `read_by[].service` per l'operazione di un altro servizio; `hidden_when` nasconde (lettura singola → come se mancasse); `scope: owner` con
cliente nella sessione filtra le liste in silenzio e risponde `foreign` (`404` o `403`, esempio `foreign_example`) alla risorsa o al proprietario altrui;
senza cliente nella sessione nessun filtro. Liste: ordinamento (`order_by`, valori mancanti in fondo, poi id), pagina (`limit` con `default_limit`/`max_limit`,
`offset` | `page` | `cursor`, cursori `c<offset>`), `count`/`total`/`next_cursor`. Parametri di paginazione non interi o negativi: `invalid-request`.
Gli esempi di errore vengono dal contratto; senza lo status dichiarato vale l'involucro con `not_found` / `forbidden`.
Le operazioni con `x-tt-entity` e senza `read_by` (pacchetti ≤ 1.1) restano servite come lista delle entità del cliente della sessione.

**Regole** (rules.md §3–§6): ramo forzato da scenario o estratto con il generatore con seed (l'estrazione si consuma sempre); poi un'estrazione
uniforme in secondi interi per ogni effetto del ramo con ritardo `{min, max}`, nell'ordine di `effects`; effetti `create`, `target`
(entità creata o aggiornata da un effetto precedente), `target_id` (`${var}`, non applicato se l'entità manca), valori `${var}` e `${effect:id}`
(solo stringa intera). Un effetto che non cambia nulla non è applicato e non compare in `applied`. Il proprietario di un'entità creata è il
cliente della sessione **all'istante della causa**. Batch: `round(fraction × n)` tra le entità che soddisfano `where`, con un rimescolamento il cui seed
dipende da (seed, regola, istante). A parità di istante: effetti pendenti del mondo (per `seq`), effetti della sessione, batch.

**Righe `pending` del mondo.** Alla creazione e al `reset` di ogni sessione le righe si mettono in coda a `t0 + due_offset_s`; gli id sintetici ripartono dopo quelli del
mondo, compresi quelli assegnati in anticipo.

**Guasti e latenze.** Per ogni operazione di `faults.json` ogni richiesta valida consuma due estrazioni (sorte e latenza). `status` → risposta del contratto
(esempio nominato in `example`); `net_error` secondo mock.md §4: `timeout` tiene la connessione `--net-timeout` e la chiude (senza latenza); `reset` RST dopo la latenza;
`refused` e `dns` RST subito; `tls` scrive il record di allarme `15 03 03 00 02 02 28` e chiude; `other` FIN senza risposta dopo la latenza. Su HTTP/2 lo stream viene azzerato.
Con la modalità `custom` valgono solo le regole date (`service` accetta nome, alias o `*`; `op` anche `*`; `times` limita le iniezioni).

**Determinismo.** Stesso seed + stessa sequenza di richieste → registri identici byte per byte (le latenze si registrano, non si misurano; `wall` si può iniettare con `Config.Wall`).

## Endpoint GraphQL (mock.md §7, v1.14)

`graphql.go` e `graphql_schema.go`, agganciati in `dispatch` (`data.go`) prima della scelta della rotta: una richiesta
`POST`/`GET` al path di un endpoint GraphQL (le operazioni `x-tt-graphql` del contratto, path `/graphql#Nome`) si legge
come GraphQL over HTTP, si sceglie l'operazione logica (nome, oppure `~` e l'hash della forma per un'operazione anonima,
lo stesso calcolo della sorgente) e si serve con il percorso normale (validazione nella forma JSON
`{query, variables, operationName}`, guasti, entità, regole, formati degli id, sessione per identità). Le variabili di
primo livello sono parametri delle letture (`by: {from: req.body, path: "$.variables.id"}`). Alla fine `graphqlFinish`
adatta la risposta: `data` secondo la selezione (alias, `__typename`), guasti come array `errors`. L'introspezione si
esegue sullo schema catturato (`x-tt-graphql-schemas`) o su uno ricostruito dalle operazioni (`synthSchema`).
Un'operazione mai osservata: errore GraphQL `OPERATION_NOT_OBSERVED`. Test: `graphql_test.go` (introspezione, mutation e
lettura per variabile, alias, GET, operazione anonima, sconosciuta, errore di sintassi, guasti, schema ricostruito), con
eventi sanificati veri da `internal/graphql/graphqltest`.

## Operazioni SOAP e XML (mock.md §10, v1.21)

`soap.go`, agganciato in `dispatch` dopo GraphQL: un `POST` al path di operazioni logiche con un corpo XML
(`x-tt-xml`, path `/ws/orders.asmx#Nome`) si legge con `sanitizer.ParseXML` (lo stesso analizzatore chiuso delle
sorgenti: niente DTD né entità, annidamento ≤ 256, valori in chiaro), si sceglie l'operazione da `SOAPAction`, dal
parametro `action` del `Content-Type` o dal primo elemento del `Body` (`sanitizer.SOAPActionName`, lo stesso calcolo
di `soap_action`) e si serve con il percorso normale: la richiesta è l'albero (`@nome`, `#text`, elementi ripetuti),
adattato allo schema (`coerceXML`) prima della validazione. Un'operazione HTTP con un corpo XML nel contratto (POX)
passa da `xmlRequest` in `validateRequest`. Alla fine `xmlFinish` scrive il corpo JSON come XML (`renderXML`: busta,
spazi dei nomi per percorso, attributi, ordine imposto da SOAP) oppure un SOAP Fault (`faultXML`). Test: `soap_test.go`,
con contratti inferiti da scambi XML veri passati per il sanitizer, la divisione logica dell'intake e l'inferenza.

## API di controllo (1.2.0)

Come in `api/control-api.v1.openapi.yaml` e mock.md §5. `GET /__tt/health` è sempre pubblico e risponde solo `{"status":"ok"}`; il pacchetto caricato si legge da `GET /__tt/pack`
(`pack_id`, `created_at`, `not_after`, servizi, regole, clienti, id dei preset). Corpi JSON stretti: campi sconosciuti, tipi o valori fuori schema danno `400 bad_request`
con il `pointer` nel corpo della chiamata (`/faults/rules/0/p`, `/sedd`). Codici: `409 session_exists`, `404 customer_not_found` / `preset_not_found` / `rule_not_found` / `outcome_not_found`,
`429 too_many_sessions`, `400` per `DELETE /sessions/default`, `400 clock_backwards` / `advance_too_large` / `too_many_steps`.

**Preset** (`scenarios.json`): `GET /__tt/scenarios`; `POST /__tt/sessions` con `scenario` (valori di seed, cliente, guasti che la richiesta non specifica, più esiti forzati); `POST /sessions/{s}/scenario`
con `{ "preset": id }` azzera la sessione e applica il preset (risposta `{pending, session}`); con `{ rule, outcome, times }` accoda esiti forzati. Il risultato è la **base** che `reset` ripristina
(mondo con righe `pending`, orologio, generatori, guasti ed esiti forzati della base, cliente della base); `Session.scenario` riporta il preset della base.

`clock.next_due` è il prossimo effetto in coda (del mondo o della sessione), non i batch. `pending_effects` riporta `rule`, `outcome`, `effect`, `due`, `source` (`world` | `session`).

## Limiti noti

- Un effetto `create` in coda nella sessione non ha ancora un id (si assegna all'applicazione): non compare in `pending_effects` di nessuna entità.
- I preset non possono ancora scegliere `t0` né il cliente per archetipo diverso dal primo per id.
- Il mock tiene lo stato in memoria: una sessione vive finché il processo.
