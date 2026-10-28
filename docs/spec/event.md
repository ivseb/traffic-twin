# Evento `tt.http.exchange` v1.1

> Formato: `tt.http.exchange/v1` · Schema: [`schemas/event.v1.schema.json`](../../schemas/event.v1.schema.json) · Revisione 1.1, pattern degli host della v1.5 (§1, §5.1, §5.2, §5.4), token `gql:` e operazioni logiche GraphQL della v1.14 (§5.1, §6), corpi XML/SOAP, multipart, documenti e corpi grandi della v1.19 (§2, §5.1, §6.1): vedi il changelog in [README.md](README.md).

Un evento descrive **uno scambio** richiesta/risposta già sanificato. È l'unica cosa che esce dalla zona A.

---

## 1. Campi

| Campo | Tipo | Obbl. | Descrizione |
|---|---|---|---|
| `schema` | `"tt.http.exchange/v1"` | sì | Versione del formato |
| `policy` | oggetto | sì | `{ "id", "version", "hash" }` della policy compilata usata |
| `source` | oggetto | sì | `{ "kind", "version", "id" }`: tipo di sorgente (`sdk-node`, `sdk-python`, `sdk-java`, `sdk-dotnet`, `sdk-go`, `sdk-php`, `egress`, `obi`, `import-har`, `import-otlp`), versione semver, id di iscrizione Fleet |
| `ts` | stringa | sì | Inizio della richiesta, RFC 3339 UTC con millisecondi (`2026-10-19T10:00:00.412Z`) |
| `latency_ms` | intero ≥ 0 | sì | Durata fino alla fine della risposta (o all'errore), arrotondata per difetto |
| `dir` | `inbound` \| `outbound` | sì | Direzione rispetto al servizio che cattura |
| `service` | stringa | sì | Servizio (§3.1 del [sanitizer](sanitizer.md)): nome di servizio, `host:<host>[:porta]` (host di `segments.hosts_allow`), `host:<pattern>` (v1.5, §3.5 del sanitizer: etichette sicure o `{*}`, `ip:private` / `ip:public`, porta non di default), `host:unlisted` o `host:invalid`; al più 518 byte |
| `op` | stringa | sì | `METODO /template-o-path-sanificato`; nel magazzino un'operazione GraphQL o SOAP è `METODO /path#Nome` (§6, v1.14; §6.1, v1.19), mai inviata da una sorgente |
| `route_source` | `framework` \| `policy` \| `raw` | sì | Da dove viene il template |
| `status` | intero 100–599 | no | Status HTTP; assente se c'è `net_error` |
| `net_error` | stringa | no | `timeout` \| `reset` \| `refused` \| `dns` \| `tls` \| `other` |
| `subject` | token `tk1:` | no | Soggetto (§11 del sanitizer) |
| `sampled_by` | `baggage` \| `subject` \| `trace` \| `random` \| `inherited` | sì | Motivo del campionamento (§12 del sanitizer) |
| `trace_id` | 32 esadecimali minuscoli | no | Dal contesto W3C, se presente |
| `span_id` | 16 esadecimali minuscoli | no | Span dello scambio, se noto |
| `parent_span_id` | 16 esadecimali minuscoli | no | Span padre |
| `req` | oggetto | sì | `path`, `query`, `headers`, `cookies`, `ct`, `size`, `body` e, dalla v1.19, `fmt`, `xmlns`, `soap_action` (§2) |
| `resp` | oggetto | no | `headers`, `cookies`, `ct`, `size`, `body` e, dalla v1.19, `fmt`, `xmlns`; assente se c'è `net_error` |
| `disc` | oggetto | no | Solo in modalità scoperta (§15 del sanitizer): `percorso → tkd:` |

I campi assenti si omettono, non si mettono a `null`. L'evento si serializza in **JSON canonico tt** (§10 del sanitizer) e non supera 512 KiB (§10.3 del sanitizer).

### 1.1 Correlazione tra ingresso e uscita

Una chiamata in uscita fatta mentre si serve una richiesta in ingresso DEVE avere lo stesso `trace_id`. Il suo `parent_span_id` DOVREBBE essere lo `span_id` dell'evento in ingresso. Se l'app non usa OpenTelemetry, l'SDK genera `trace_id` e `span_id` per conto proprio (casuali, formato W3C) e li tiene nel proprio contesto, **senza** iniettare `traceparent` nelle chiamate in uscita: tt non cambia il traffico dell'app. L'unica eccezione, opt-in, è il membro di baggage `tt.s` verso gli host di `sampling.propagate_to` (§12 del sanitizer).

Se l'app usa già OpenTelemetry, l'SDK **legge** il contesto attivo e non crea span propri.

### 1.2 Nome del servizio

Per gli eventi `inbound`, `service` è il nome assegnato alla sorgente all'**iscrizione** e legato al suo gruppo (vedi `api/fleet-api.v1.openapi.yaml`). La sorgente non lo ricava da `OTEL_SERVICE_NAME` né da altre dichiarazioni dell'app a runtime; l'onboarding può proporlo partendo da lì, in minuscolo.

## 2. Parti `req` e `resp`

| Campo | Contenuto |
|---|---|
| `path` | Solo `req`: path sanificato (`/orders/{tk1:k1:…}`) |
| `query` | Solo `req`: `nome → [token]`; assente se l'URL non ha `?` |
| `headers` | `nome → [token]` |
| `cookies` | `nome → [token]` |
| `ct` | Content-type normalizzato (`application/json`) o `invalid`; assente senza header |
| `size` | Classe di lunghezza del corpo decodificato (`l8`, `l32`, `l128`, `l1024`, `lmax`); assente solo con codifica non supportata |
| `body` | Albero sanificato, oppure `drop:bytes`, `drop:bytes:<classe>`, `trunc:size`, `trunc:invalid-json` e, dalla v1.19, `trunc:invalid-xml`, `trunc:invalid-multipart`; assente se il corpo è vuoto |
| `fmt` | (v1.19) `xml`, `soap11`, `soap12` o `multipart`: il trattamento del corpo ([sanitizer](sanitizer.md) §22.1); solo con `body`; assente per JSON, form e corpi non analizzati |
| `xmlns` | (v1.19) `tt-path dell'elemento → ns:<pattern>`: gli spazi dei nomi di un corpo XML ([sanitizer](sanitizer.md) §22.2 punto 9), al più 64 voci più `{trunc}` |
| `soap_action` | (v1.19) Solo `req`: il nome dell'operazione SOAP (ultimo pezzo di `SOAPAction` o del parametro `action`), oppure `{*}` ([sanitizer](sanitizer.md) §22.2 punto 11) |

**Corpi della v1.19.** Un corpo XML o SOAP è un albero come il JSON, con foglie solo stringa: gli attributi sono chiavi `@nome`, il testo misto `#text`, gli elementi ripetuti array. Un corpo multipart è una mappa `nome → [token]` come un form; le parti file sono `drop:file:<tipo>:<classe documento>`. Un documento base64 dentro una stringa è `drop:doc:<tipo>:<classe documento>` (tipi `pdf`, `png`, `jpeg`, `gif`, `webp`, `ole`, `zip`, `docx`, `xlsx`, `pptx`; per i file anche `text`, `csv`, `json`, `xml`, `bin`; classi `l1k`, `l16k`, `l128k`, `l1m`, `l8m`, `lmax`). Un corpo grande ([sanitizer](sanitizer.md) §22.5) ha `size` `lmax` e array più corti, chiusi da `trunc:n:<classe>` sul numero totale.

## 3. Esempio

Lunedì 19 ottobre 2026, 10:00:00.412 UTC: un utente crea un ordine (dati inventati).

```json
{"dir":"inbound","latency_ms":184,"op":"POST /orders","policy":{"hash":"sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d","id":"p-shop","version":7},"req":{"body":{"email":"drop:str:email","items":[{"qty":"drop:int","sku":"drop:str:l32"}],"note":"drop:str:l8"},"ct":"application/json","headers":{"content-type":["keep:application/json"]},"path":"/orders","size":"l128"},"resp":{"body":{"id":"tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg","status":"keep:CREATED","total":"num:50-100"},"ct":"application/json","headers":{"content-type":["keep:application/json; charset=utf-8"]},"size":"l128"},"route_source":"policy","sampled_by":"subject","schema":"tt.http.exchange/v1","service":"shop-api","source":{"id":"src-01JB7Q2W","kind":"sdk-node","version":"0.1.0"},"span_id":"00f067aa0ba902b7","status":201,"subject":"tk1:k1:7Hq2nB5sKe9dXo3uLw1cRf","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","ts":"2026-10-19T10:00:00.412Z"}
```

I token negli esempi in prosa sono **finti**: i valori veri si trovano nei vettori di conformità.

---

## 4. Trasporto: OTLP/HTTP JSON

Le sorgenti inviano gli eventi a `tt-core` come **log OTLP** sopra HTTP, codifica JSON. Non si usano librerie OpenTelemetry: il corpo si scrive a mano. I campi seguono la codifica JSON di OTLP (`traceId` e `spanId` in esadecimale, interi a 64 bit come stringhe).

### 4.1 Richiesta

- `POST https://<tt-core>:4318/v1/logs`, sul listener di intake di `tt-core` (lo stesso degli endpoint Fleet delle sorgenti; vedi `api/fleet-api.v1.openapi.yaml`).
- Header: `Content-Type: application/json`; facoltativo `Content-Encoding: gzip`.
- Connessione **mTLS** con il certificato rilasciato all'iscrizione (vedi `api/fleet-api.v1.openapi.yaml`). Nessuna modalità in chiaro.
- Al massimo 512 eventi o 4 MiB (prima della compressione) per richiesta; ogni evento al massimo 512 KiB.

### 4.2 Mappatura

| OTLP | Valore |
|---|---|
| `resourceLogs[].resource.attributes` | `service.name` = servizio assegnato all'iscrizione; `tt.source.kind`, `tt.source.version`, `tt.source.id` |
| `scopeLogs[].scope` | `name` = `traffic-twin`, `version` = versione della sorgente |
| `logRecords[].timeUnixNano` | `ts` in nanosecondi, come stringa |
| `logRecords[].observedTimeUnixNano` | Momento dell'invio, come stringa |
| `logRecords[].severityNumber` / `severityText` | `9` / `INFO` |
| `logRecords[].eventName` | `tt.http.exchange` |
| `logRecords[].traceId` / `spanId` | `trace_id` / `span_id` dell'evento, se presenti |
| `logRecords[].attributes` | `tt.schema` = `tt.http.exchange/v1`; `tt.policy.hash` = hash della policy |
| `logRecords[].body` | `{ "stringValue": <evento in JSON canonico tt> }` |

Il corpo del log è una **stringa** con l'evento canonico, non un `kvlistValue`. È una scelta voluta: tutti i linguaggi producono gli stessi byte e l'intake li valida in un passo solo.

### 4.3 Esempio completo

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "shop-api" } },
          { "key": "tt.source.kind", "value": { "stringValue": "sdk-node" } },
          { "key": "tt.source.version", "value": { "stringValue": "0.1.0" } },
          { "key": "tt.source.id", "value": { "stringValue": "src-01JB7Q2W" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": { "name": "traffic-twin", "version": "0.1.0" },
          "logRecords": [
            {
              "timeUnixNano": "1792404000412000000",
              "observedTimeUnixNano": "1792404000700000000",
              "severityNumber": 9,
              "severityText": "INFO",
              "eventName": "tt.http.exchange",
              "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
              "spanId": "00f067aa0ba902b7",
              "attributes": [
                { "key": "tt.schema", "value": { "stringValue": "tt.http.exchange/v1" } },
                { "key": "tt.policy.hash", "value": { "stringValue": "sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d" } }
              ],
              "body": {
                "stringValue": "{\"dir\":\"inbound\",\"latency_ms\":184,\"op\":\"POST /orders\",\"policy\":{\"hash\":\"sha256:9c1e0d4f8b2a7c6e5d3f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d\",\"id\":\"p-shop\",\"version\":7},\"req\":{\"body\":{\"email\":\"drop:str:email\",\"items\":[{\"qty\":\"drop:int\",\"sku\":\"drop:str:l32\"}],\"note\":\"drop:str:l8\"},\"ct\":\"application/json\",\"headers\":{\"content-type\":[\"keep:application/json\"]},\"path\":\"/orders\",\"size\":\"l128\"},\"resp\":{\"body\":{\"id\":\"tk1:k1:Zx81mQ4pLr0aVb7cYt2eWg\",\"status\":\"keep:CREATED\",\"total\":\"num:50-100\"},\"ct\":\"application/json\",\"headers\":{\"content-type\":[\"keep:application/json; charset=utf-8\"]},\"size\":\"l128\"},\"route_source\":\"policy\",\"sampled_by\":\"subject\",\"schema\":\"tt.http.exchange/v1\",\"service\":\"shop-api\",\"source\":{\"id\":\"src-01JB7Q2W\",\"kind\":\"sdk-node\",\"version\":\"0.1.0\"},\"span_id\":\"00f067aa0ba902b7\",\"status\":201,\"subject\":\"tk1:k1:7Hq2nB5sKe9dXo3uLw1cRf\",\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\",\"ts\":\"2026-10-19T10:00:00.412Z\"}"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### 4.4 Risposta e ripetizioni

| Risposta di `tt-core` | Cosa fa la sorgente |
|---|---|
| `200` (con eventuale `partialSuccess.rejectedLogRecords`) | Considera consegnato il lotto. I rifiuti si contano nell'heartbeat. |
| `400`, `401`, `403`, `413` | Scarta il lotto senza ripetere e lo conta |
| `429`, `502`, `503`, `504`, errori di rete | Ripete con attesa esponenziale (da 1 s fino a 30 s, con variazione casuale), al massimo 5 volte; rispetta `Retry-After` |

La coda di invio è **limitata** (default 10 000 eventi o 16 MiB). Quando è piena, la sorgente **scarta gli eventi più vecchi** e li conta. L'app non attende mai l'invio.

## 5. Controlli dell'intake

### 5.1 Rifiuto

L'intake DEVE rifiutare un evento (contandolo, senza correggerlo) se:

1. non è valido secondo lo schema;
2. i suoi byte non sono **esattamente** la forma canonica (§10 del sanitizer) del documento analizzato: spazi, escape o ordini alternativi sarebbero un canale nascosto;
3. il `policy.hash` non corrisponde a una policy firmata nota **e** assegnata al gruppo della sorgente;
4. `source.id` non coincide con l'identità (SAN) del certificato mTLS della connessione, o `service` di un evento `inbound` non è tra i nomi di servizio ammessi per il gruppo della sorgente;
5. una stringa fuori dai campi di servizio non rispetta la grammatica dei token (§6 del sanitizer);
6. un valore che non è `drop:*` né `trunc:*` non corrisponde a una regola **del tipo giusto** della policy per quel percorso, secondo la precedenza di §5.0 del sanitizer:
   - `keep:` stringa, numero, booleano o `null` solo dove la regola effettiva è `keep`, con stringhe ≤ `keep_max_bytes` byte e numeri con lessema ≤ 64 byte;
   - `tk1:` solo dove la regola è `hmac`, con `kid` uguale a `hmac.kid` o in `hmac.accept_kids`;
   - `num:` solo dove la regola è `bucket(num)` e i confini del token coincidono con una coppia di confini consecutivi della regola (o con `<b0` / `>=bn`);
   - `time:` solo dove la regola è `bucket(time)` con la stessa unità;
   - **(v1.14)** `gql:` solo dove la regola è `graphql` ([sanitizer](sanitizer.md) §5.7), mai sotto una chiave o un nome collassato in `{*}`: nella richiesta deve essere una forma valida senza letterali né nomi non sicuri (`graphql.ValidShape`); nella risposta deve essere un nome GraphQL che rispetta la regola dei nomi, e la richiesta dello stesso evento deve aprire il cancello di introspezione (almeno un valore con regola `graphql`, e ogni valore con regola `graphql` è un `gql:` di sola introspezione). Con il cancello aperto gli array del corpo della risposta possono avere fino a 4096 elementi (più il marcatore);
   - `keep:` sotto una regola `code` solo con la forma del codice ([sanitizer](sanitizer.md) §5.6): `^[A-Za-z_-]{2,32}$` e, dalla v1.19 con `shape: alnum`, `^[A-Za-z0-9_.-]{1,16}$`;
   - **(v1.19)** `fmt`, `xmlns` e `soap_action` solo con l'interruttore `bodies` corrispondente della policy e un `ct` coerente (`fmt` XML solo con un content-type XML e `bodies.xml`, `multipart` solo con `multipart/form-data` e `bodies.multipart`, `xmlns` solo con un `fmt` XML, `soap_action` solo con un corpo o un `ct` XML); le chiavi `@nome` e `#text` solo in un corpo XML; foglie non stringa e `num:` mai in un corpo XML; array oltre `max_array` solo con `size` `lmax` e al più `bodies.large_array` (`large_nested_array` dentro un elemento di array) elementi. Gli eventi senza `fmt` (sorgenti precedenti, interruttori spenti) seguono i controlli di prima;
   - `host:<nome>` in `service` solo se il nome è in `segments.hosts_allow`, oppure (v1.5) se è un **pattern** di §3.5 del sanitizer con ogni etichetta letterale conforme alle regole a–c dell'etichetta sicura e la policy ha `hosts.discovery: auto` (o il campo `hosts` assente) o la scoperta attiva. Un pattern con un'etichetta che sembra un valore, o qualsiasi `host:<nome>` con `hosts.discovery: off` e scoperta spenta, si rifiuta con `host_not_allowed`.

Il controllo 6 richiede la policy: per questo l'intake conosce tutte le policy firmate per versione.

L'intake applica inoltre controlli più severi dello schema (mappe vuote, nomi letterali, finestra della policy, coerenza della busta OTLP e altri): sono elencati in [hardening.md](hardening.md) §1. Un sanitizer conforme non li fa mai scattare.

### 5.2 Quarantena

L'intake sorveglia la **cardinalità** di ciò che esce in chiaro, con sketch HyperLogLog per finestra di conservazione:

| Cosa | Chiave dello sketch | Soglia (default) |
|---|---|---|
| Valori `keep:` | policy, servizio, operazione, parte, percorso | 50 distinti |
| Nomi letterali (chiavi JSON, nomi di query, cookie e header) | servizio, operazione, parte, percorso del contenitore padre | 50 distinti per padre |
| Segmenti di path letterali (da `auto_words` o da path `raw`) | servizio, metodo, posizione | 50 distinti per posizione |
| Domini registrabili (§5.4) dei pattern `host:<pattern>` (v1.5; prima: gli host) | sorgente | 50 distinti |
| Etichette letterali dei pattern `host:<pattern>` (v1.5) | dominio registrabile (§5.4), posizione a sinistra del dominio registrabile (1 = l'etichetta più vicina) | 50 distinte per posizione (la soglia `k`) |

Gli host di `segments.hosts_allow` e i pattern IP (`ip:private`, `ip:public`) non si contano: i primi sono una scelta esplicita, i secondi non hanno etichette.

Quando una soglia viene superata, l'elemento entra **in quarantena**:

1. negli eventi **già salvati**, i valori interessati si **riscrivono** nella loro forma (`keep:Roma` → `drop:str:l8`; nome di chiave → `{*}`; segmento → `{drop:str:<classe>}`; v1.5: etichetta dell'host nella posizione in quarantena → `{*}`, per esempio `host:mario-rossi.customers.example` → `host:{*}.customers.example`; domini registrabili di una sorgente in quarantena → l'etichetta registrabile diventa `{*}`, `host:api.acme.example` → `host:api.{*}.example`), calcolata con le regole del sanitizer; i valori originali si cancellano dal magazzino. Fino alla v1.4 un host in quarantena diventava `host:unlisted`;
2. negli eventi **futuri**, la stessa riscrittura avviene all'ingresso, prima della scrittura;
3. parte un allarme e l'elemento compare nella coda di quarantena della UI (API di amministrazione); per i due casi degli host l'allarme è `host_cardinality` (tipi `host` e `host-label` della coda); per i valori `keep:` (anche quelli di una regola `code`, v1.19) l'allarme è `value_cardinality`: un campo con più di 50 valori diversi è probabilmente un identificativo e la versione Osserva non gli propone più `code` ([policy.md](policy.md) §1.5);
4. la quarantena si chiude solo con una modifica di policy che **chiude** il campo (1 approvazione) oppure con uno scioglimento esplicito, che conta come apertura (**2 approvazioni**, [policy.md](policy.md) §5).

### 5.3 Modalità scoperta

L'intake riduce `disc` a sketch di cardinalità per percorso (HyperLogLog, precisione ≥ 12) e **non** conserva i token `tkd:`. Gli eventi si salvano senza il campo `disc`.

### 5.4 Dominio registrabile (v1.5)

Il dominio registrabile approssima l'eTLD+1 senza la Public Suffix List completa, in modo deterministico e solo con la libreria standard. Serve all'intake (§5.2) e al registro degli host dell'API di amministrazione (`listHosts`); **non** influisce sull'uscita del sanitizer, quindi le sorgenti non lo implementano.

Sul pattern senza porta (non un pattern IP), diviso in etichette (`{*}` conta come un'etichetta):

1. se le ultime due etichette sono uno dei suffissi a due etichette della tabella, il dominio registrabile sono le ultime **tre** etichette;
2. altrimenti sono le ultime **due**;
3. un pattern con meno etichette è il proprio dominio registrabile.

| Suffissi a due etichette (elenco chiuso) |
|---|
| `ac.uk`, `co.uk`, `gov.uk`, `ltd.uk`, `me.uk`, `net.uk`, `nhs.uk`, `org.uk`, `plc.uk`, `sch.uk` |
| `com.au`, `edu.au`, `gov.au`, `net.au`, `org.au`, `co.nz`, `govt.nz`, `net.nz`, `org.nz` |
| `ac.jp`, `co.jp`, `go.jp`, `ne.jp`, `or.jp`, `co.kr`, `or.kr`, `com.cn`, `gov.cn`, `net.cn`, `org.cn`, `com.hk`, `com.tw`, `com.sg`, `com.my`, `co.id`, `co.th`, `co.in`, `gov.in`, `net.in`, `org.in` |
| `com.br`, `gov.br`, `net.br`, `org.br`, `com.ar`, `com.mx`, `co.za`, `gov.za`, `org.za`, `com.tr`, `co.il`, `gov.it` |

Esempi: `{*}.api.carrier.example:8443` → `carrier.example`; `a.b.shop.co.uk` → `shop.co.uk`; `eu-west-1.compute.amazonaws.com` → `amazonaws.com`. Le **posizioni** si contano dal dominio registrabile verso sinistra: in `x.y.carrier.example` la posizione 1 è `y`, la 2 è `x`. L'elenco si estende solo con una revisione della specifica (cambia le chiavi degli sketch e dei gruppi, non l'uscita delle sorgenti).

## 6. Operazioni logiche GraphQL (v1.14)

Un endpoint GraphQL (`POST /graphql`, su qualsiasi servizio e path) porta molte operazioni diverse. Quando un evento accettato ha nella richiesta il `gql:` di un documento ([sanitizer](sanitizer.md) §5.7.5: il membro `query` di un corpo JSON, un corpo `application/graphql`, il parametro di query `query` con un solo valore), l'intake lo salva sotto l'**operazione logica**:

```
<op HTTP>#<nome>        es.  POST /graphql#GetOrder
```

- `<nome>` è il nome dell'operazione eseguita, se rispetta la regola dei nomi (§5.7.1 del sanitizer); altrimenti (operazione anonima, nome `*`) è `~` seguito dalle prime 10 cifre esadecimali (minuscole) dello SHA-256 della forma **dell'intero documento**: `POST /graphql#~3fa2b1c9d0`. La stessa forma dà lo stesso nome, anche con altri valori scritti nel documento (diventano placeholder).
- Con più operazioni nel documento (`operationName` è un valore e non esce dalla sorgente) si sceglie la prima le cui chiavi di risposta della selezione radice (alias compresi, frammenti espansi) coprono le chiavi di `resp.body.data`; altrimenti la prima.
- Il tipo (`query`, `mutation`, `subscription`) non fa parte della chiave: lo dicono il contratto (`x-tt-graphql.type`) e la console («QUERY GetOrder»).
- L'operazione logica esiste **solo** nel magazzino e in ciò che se ne ricava (contratti, regole, mondi, guasti, pacchetti, mock). Un evento di una sorgente con `#` nell'`op` è rifiutato (non corrisponde né a un template della policy né al path). I controlli di §5.1, le quarantene di §5.2 e le proposte della policy usano sempre l'**op HTTP** (la parte prima di `#`).
- Le operazioni logiche non partecipano all'inferenza dei template dei path grezzi (hanno un nome, non parametri).

Il contratto di un'operazione logica ha l'estensione `x-tt-graphql` ([pack.md](pack.md) §4) e, nel documento OpenAPI, il path `/graphql#GetOrder`; il risultato di introspezione catturato per l'endpoint sta in `x-tt-graphql-schemas`. Il mock risponde all'endpoint vero (`POST /graphql`) scegliendo l'operazione logica dal documento della richiesta ([mock.md](mock.md) §7).

### 6.1 Operazioni logiche SOAP (v1.19)

Un servizio SOAP espone molte operazioni sullo stesso path e metodo (`POST /ws/orders.asmx`). Quando un evento accettato ha `req.fmt` `soap11` o `soap12`, l'intake lo salva sotto l'operazione logica `<op HTTP>#<nome>`, come per GraphQL:

- `<nome>` è `req.soap_action`, se c'è e non è `{*}` ([sanitizer](sanitizer.md) §22.2 punto 11: l'ultimo pezzo di `SOAPAction` o del parametro `action` del `content-type`, già filtrato dalla regola dei nomi);
- altrimenti è il nome dell'**unico** elemento del `Body` della busta (`req.body.Envelope.Body`, attributi esclusi), se letterale;
- altrimenti (nessun nome, più elementi, nome collassato in `{*}`, corpo non valido) l'evento resta sotto l'op HTTP.

Valgono le stesse regole delle operazioni GraphQL: esistono solo nel magazzino e in ciò che se ne ricava, una sorgente non le invia mai, controlli, quarantene e proposte della policy usano l'op HTTP, non partecipano all'inferenza dei template. Il contratto le descrive con il path `/ws/orders.asmx#GetOrder` e porta sul tipo di contenuto l'estensione `x-tt-xml` ([pack.md](pack.md) §4: `fmt` e spazi dei nomi), così un mock può rispondere con la stessa busta.

