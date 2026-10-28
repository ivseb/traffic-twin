# @traffic-twin/sdk (Node.js)

SDK di cattura di traffic-twin per Node.js ≥ 20. Osserva le chiamate HTTP in ingresso e in
uscita del processo, le **sanifica nel processo** secondo la policy firmata (specifica
`docs/spec/sanitizer.md` v1.1.1) e invia a `tt-core` solo forme, token HMAC e valori
ammessi dalla policy, come log OTLP/HTTP JSON su mTLS.

- **Zero dipendenze a runtime**: solo la libreria standard di Node. Nessun pacchetto
  `@opentelemetry/*` tra le dipendenze.
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato; l'unica eccezione,
  opzionale e decisa dalla policy, è il membro di baggage `tt.s` verso gli host di
  `sampling.propagate_to` (mai verso un host esterno della policy).
- **Fail-closed**: senza policy valida, chiave HMAC o primo heartbeat non cattura nulla;
  l'app continua a funzionare normalmente. Senza chiave HMAC lo stato è `key_missing` (mai
  `no_policy`) e l'SDK lo scrive sempre su stderr, anche senza `TT_DEBUG`, con la causa. La
  chiave è un file dell'installazione distribuito dal team piattaforma (stesso kid di
  `hmac.kid` della policy, stessa chiave di keyguard): vedi [docs/USER_GUIDE.md](https://github.com/ivseb/traffic-twin/blob/main/docs/USER_GUIDE.md) §4.
- ESM e CommonJS (`dist/esm`, `dist/cjs`).

## Avvio senza codice

```bash
npm install @traffic-twin/sdk          # o, finché non è nel registro: npm install ./traffic-twin-sdk-x.y.z.tgz
TT_ENROLL_URL=https://tt-core.internal:4318 \
TT_ENROLL_TOKEN=tte_… \
TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key \
TT_SERVICE_NAME=shop-api \
  node --import @traffic-twin/sdk/register app.js
```

Per le app CommonJS si può usare anche `node --require @traffic-twin/sdk/register app.js`.
Gli hook si installano subito; iscrizione, heartbeat e download della policy avvengono in
background e non ritardano l'avvio dell'app.

| Variabile | Significato |
|---|---|
| `TT_ENROLL_URL` | URL del listener Fleet/intake di `tt-core` (sempre `https`) |
| `TT_ENROLL_TOKEN` | Token di iscrizione `tte_<segreto>.<impronta CA>`, monouso o di gruppo |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, una o più righe `<kid>:<base64url>` (§7.1). Non viaggia mai verso `tt-core` |
| `TT_SERVICE_NAME` | Nome di servizio richiesto all'iscrizione (altrimenti `OTEL_SERVICE_NAME` in minuscolo). Il nome usato negli eventi è quello **assegnato** da `tt-core` |
| `TT_STATE_DIR` | Cartella dello stato locale (default `~/.traffic-twin/<id>`): certificato, chiave privata, CA, policy firmata, interruttore. Cartella `0700`, file `0600` |
| `TT_ENROLL_CSR` | `0` per chiedere la chiave a `tt-core` invece di generare una CSR (default: CSR ECDSA P-256, la chiave privata non esce dal processo) |
| `TT_SANITIZER_THREADS` | Thread di sanificazione (`worker_threads`). Default: `min(2, core − 1)`, usati solo quando il campionamento della policy è ≥ 2 % (sotto, si sanifica nel thread principale: costa meno che svegliare un thread). `0` = sempre nel thread principale |
| `TT_DISABLED` | `1` disattiva completamente l'SDK |
| `TT_DEBUG` | `1` scrive su stderr solo codici di stato ed errore (mai valori) |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS` | Solo per test: sostituiscono gli intervalli ricevuti da `tt-core` |

## API programmatica

```js
import { start, stop, current } from '@traffic-twin/sdk';

const agent = await start({
  enrollUrl: 'https://tt-core.internal:4318',
  enrollToken: process.env.TT_ENROLL_TOKEN,
  hmacKeyFile: '/run/secrets/tt-hmac-key',
  serviceName: 'shop-api',
});
console.log(agent.status()); // { state: 'capturing', counters: {...}, queue: {...} }
```

`start()` non lancia mai eccezioni ed è idempotente (un solo agente per processo, anche se
l'app carica sia la build ESM sia quella CommonJS). La funzione di test dei vettori
(`runVector`, `parseVector`) e il sanitizer (`Sanitizer`, `Policy`) sono esportati.

## Cosa viene catturato

| Direzione | Punto di aggancio | Corpo |
|---|---|---|
| Ingresso | `diagnostics_channel` `http.server.request.start` / `http.server.response.finish` (node:http, node:https, Express e framework basati su node:http) | richiesta: copia dei byte già de-chunkati dal parser; risposta: copia di `write`/`end` |
| Uscita, node:http(s) | `http.client.request.created` (o `start` su Node meno recenti), `http.client.response.finish`, `http.client.request.error` | come sopra |
| Uscita, `fetch`/undici | canali `undici:request:*` | `bodyChunkSent` / `bodyChunkReceived` (byte ancora codificati: la decodifica gzip/deflate la fa il sanitizer) |

Gli unici "wrapper" sono installati sugli **oggetti** richiesta/risposta degli scambi
campionati (`push`, `write`, `end`): sono sincroni, non cambiano argomenti, valori di
ritorno né tempi, e non aggiungono listener `error` (che cambierebbero la gestione degli
errori dell'app). Il resto (normalizzazione, sanificazione, serializzazione, invio) avviene
dopo la risposta, a blocchi di pochi millisecondi con `setImmediate`.

Contesto: un `AsyncLocalStorage` lega le chiamate in uscita allo scambio in ingresso (stesso
`trace_id`, campionamento ereditato). Il `traceparent` in ingresso viene letto; se l'app usa
OpenTelemetry, l'SDK carica `@opentelemetry/api` **dall'albero dell'app** e ne legge solo il
contesto attivo, senza mai registrare provider, propagatori o context manager.

Sanificazione fuori dal thread delle richieste: con campionamento ≥ 2 % gli scambi
catturati vengono raggruppati (≈ 8 ms) e inviati a uno o due thread di lavoro, che producono
direttamente i `logRecord` OTLP già pronti; il thread principale esegue solo la copia dei
byte, il `postMessage` e l'invio. Il risultato è identico byte per byte a quello
dell'esecuzione nel thread principale (`test/unit/worker.test.mjs`); se un thread muore si
torna alla sanificazione in linea e gli scambi in volo vengono contati come scartati. Misure
e metodo: `BENCHMARKS.md`.

Pressione: code limitate (2 000 scambi da sanificare, 10 000 eventi / 16 MiB da inviare);
quando sono piene si scartano gli eventi più vecchi e si contano, l'app non aspetta mai.
Invio a lotti (≤ 512 eventi, ≤ 4 MiB), ripetizioni con attesa esponenziale e `Retry-After`
su 429/502/503/504 ed errori di rete.

### Host non dichiarati e scoperta automatica (spec v1.5)

Un host esterno che nessuna `base` della policy né `segments.hosts_allow` elenca non esce
più come `host:unlisted`: con `hosts.discovery: auto` (default, anche quando il campo
`hosts` manca) il `service` dell'evento è `host:` + **pattern** (sanitizer.md §3.5). Il
pattern è l'host in minuscolo, senza porta di default e senza un punto finale, in cui ogni
etichetta resta letterale solo se è `^[a-z][a-z0-9-]{0,62}$`, non ha sei cifre consecutive
né dodici esadecimali consecutivi, altrimenti diventa `{*}` (`t-3912345678.tenant.example` →
`host:{*}.tenant.example`). I letterali IP escono solo come `ip:private` / `ip:public`
(tabella chiusa di §3.6, con parser IPv6 proprio: nessuna funzione di libreria), con la porta
se non di default; un'etichetta vuota dà `host:invalid`. L'host è passato al sanitizer così
come lo vede il client (IPv6 tra parentesi, nessun IDN, nessun punto tolto).

`hosts.discovery: off` è la **modalità stretta**: gli host non dichiarati escono come
`host:unlisted`, byte per byte come prima della v1.5. Lo imposta la policy (`tt-core`, la
chiusura `auto` → `off` e l'apertura `off` → `auto` sono approvate come per ogni policy);
l'SDK non ha opzioni locali. Il dominio registrabile e la cardinalità delle etichette sono
controlli di `tt-core` (zona B): l'SDK non li implementa.

### Codici alfanumerici, XML/SOAP, multipart, documenti e corpi grandi (spec v1.19)

L'SDK implementa la v1.19 del sanitizer (sanitizer.md §5.6 e §22; vettori 2200–2453):

- `{"action":"code","shape":"alnum"}`: codici con cifre e punti, `^[A-Za-z0-9_.-]{1,16}$`
  entro `keep_max_bytes`; le guardie H1/H2 la trattano come `code`.
- L'oggetto `bodies` della policy (assente = tutto spento, uscita identica alle versioni precedenti):
  `xml` analizza i corpi XML e SOAP con un lettore scritto a mano, sottoinsieme rigoroso di
  XML 1.0 (`src/sanitizer/bodies.ts`: nessuna libreria XML, nessuna DTD né entità oltre le
  cinque predefinite, al massimo 256 elementi annidati) e aggiunge `fmt`, `xmlns` e
  `soap_action`; `multipart` analizza `multipart/form-data` (le parti file escono solo come
  `drop:file:<tipo>:<classe>`); `docs` dà la forma `drop:doc:<tipo>:<classe>` alle stringhe
  che sono il base64 di un documento; `max_large_body_bytes`, `large_array` e
  `large_nested_array` attivano la modalità «corpo grande».
- Con `max_large_body_bytes` > 0 la cattura (ingresso, `http`/`https` e `fetch`/undici in
  uscita) conserva `max(max_body_bytes, max_large_body_bytes) + 1` byte di ogni corpo
  campionato invece di `max_body_bytes + 1`.

## Fleet

- Iscrizione con token: prima connessione TLS senza fiducia, verifica che la radice della
  catena presentata da `tt-core` abbia l'impronta SHA-256 contenuta nel token, poi richiesta
  di iscrizione con quella radice come unica CA. Certificato e chiave restano nello stato
  locale e si riusano ai riavvii.
- Heartbeat **prima** di qualsiasi cattura; interruttore di emergenza, revoca e
  `min_issued_seq` sono salvati e restano validi dopo un riavvio.
- Policy: firma Ed25519 su `"tt.policy.body/v1" || 0x00 || corpo` con chiavi fissate e non
  revocate, schema completo del corpo, coerenza busta/corpo, gruppo, `not_after`,
  `issued_seq` crescente e ≥ `min_issued_seq`. Una policy rifiutata non sostituisce mai la
  precedente valida. Nuove chiavi di firma solo se approvate da una chiave già fissata.

## Limiti noti

- Versioni: Node ≥ 20; il corpo completo delle risposte di `fetch` solo da Node ≥ 24.
  Node 20 e 22: il corpo delle risposte di `fetch` non è visibile (i canali `bodyChunk*` di
  undici mancano) e l'evento riporta `trunc:size`; per le richieste node:http create e
  chiuse prima dell'assegnazione del socket il corpo risulta di lunghezza ignota.
- `framework_route` si passa solo per Express e solo per le route definite direttamente
  sull'app (senza router montati, il cui prefisso non è ricostruibile come template);
  altrimenti valgono i template della policy (§3.3 punto 2).
- HTTP/2 (`node:http2`) non è ancora agganciato.

- **SDK oppure tt-egress per ogni chiamata in uscita.** Se l'app chiama un servizio esterno attraverso [tt-egress](https://github.com/ivseb/traffic-twin/blob/main/internal/egress/README.md), l'SDK registra anche il salto verso il proxy (servizio `host:…`) e la chiamata è catturata due volte. Non mettere l'indirizzo del proxy in `hosts_allow`; la Fleet segnala `double_capture` quando lo vede.

## Sviluppo

```bash
npm ci
npm run vectors     # vettori di conformità (conformance/vectors), confronto byte per byte
npm test            # unit test + integrazione (app, carrier finto, tt-core finto con mTLS)
node bench/hooks.mjs  # costo del solo percorso degli hook (opz. --subject none|cookie|jwt, --out 1)
npm run bench       # overhead con SDK spento/acceso (opzioni: --rate-bp, --steady-rps, --seconds, --rounds, --threads, --endpoint orders|health, --io-ms)
```

Le dipendenze di sviluppo (TypeScript, `@types/node`, OpenTelemetry per il test di
convivenza) sono fissate a versioni esatte.
