# Overhead dell'SDK Node.js: misure e metodo

Obiettivo: p50 aggiunto ≤ 1 ms;
throughput a saturazione −≤ 5 % con campionamento 5 %, −≤ 15 % al 100 %. Le uscite
dell'SDK non cambiano: 509 vettori di conformità byte per byte (`npm run vectors`) e
`npm test` (41 test) restano verdi.

## Metodo

- Banco: `npm run bench` (`bench/overhead.mjs`). Una app senza framework
  (`test/fixtures/app.mjs`) riceve `POST /orders`; ogni richiesta produce **3 scambi**
  (1 in ingresso, 1 `fetch`, 1 `node:http`) verso un carrier locale. Con SDK acceso tutti e
  tre vengono catturati, sanificati ed esportati su mTLS verso un tt-core finto nello stesso
  processo del generatore di carico.
- Ogni giro (`--rounds 5`) esegue **spento e acceso uno dopo l'altro** e due misure:
  *steady* (ciclo aperto a 300 req/s, sotto saturazione: latenza e CPU per richiesta) e
  *saturazione* (ciclo chiuso, 16 client: richieste/s massime e CPU per richiesta).
  I delta sono calcolati **per giro** (accoppiati) e riassunti con **mediana [min..max]** su
  5 giri da 5 s (`--seconds 5`).
- CPU del processo app: `process.threadCpuUsage()` per il solo thread delle richieste
  (quello che il cliente sente) e `process.cpuUsage()` per tutti i thread (compresi i thread
  di sanificazione). `--threads 0` forza la sanificazione nel thread principale.
- Profilo: `node bench/overhead.mjs --profile <dir>` (`--cpu-prof` sull'app) e analisi per
  funzione/file dei campioni.
- Prima/dopo: la versione "prima" è quella precedente alle ottimizzazioni (sorgenti `sdk/node/src`
  originali) con lo stesso banco e la stessa app; le due versioni sono state eseguite una dopo
  l'altra sulla stessa macchina.

**Limite del banco.** Macchina di sviluppo (Mac15,12, 8 core) condivisa con altri processi;
generatore di carico, carrier, tt-core finto e app competono per gli stessi core. Il
throughput a saturazione varia anche del 30 % da un giro all'altro con SDK spento
(vedi gli intervalli). Le misure più stabili sono i delta di CPU del thread delle richieste;
il throughput è indicativo. Carico medio della macchina: 25–28 nelle prime misure (baseline
iniziale, sotto), 4–10 in quelle della tabella. **La verifica del budget va ripetuta su una
macchina dedicata.**

## Cosa è stato cambiato

Profilo iniziale (100 %): il 13 % del tempo totale era sanificazione + assemblaggio evento
nel thread principale, ≈ 4 % codifica OTLP e invio, il resto hook e copia dei corpi; in
totale il codice dell'SDK pesava circa il 38 % del tempo CPU occupato del thread delle
richieste (≈ +80 % rispetto all'app senza SDK).

1. **Sanificazione fuori dal thread delle richieste** (`src/worker/*`, `src/export/pipeline.ts`).
   Con campionamento della policy ≥ 2 % (`TT_SANITIZER_THREADS`, default `min(2, core−1)`,
   `0` = in linea) gli scambi finiti sono raggruppati ≈ 8 ms e passati a un `worker_threads`
   (secondo thread solo se il primo ha arretrato). Il thread principale fa solo la copia
   dei byte, un `postMessage` per lotto e l'accodamento di record già pronti. Corpi in
   buffer propri (non fette del pool di Node), quindi nessun clone di 8 KiB per corpo. Coda
   limitata come prima (2 000 scambi / 64 MiB, conteggiando anche quelli in volo): quando è
   piena si scarta e si conta; se il thread muore si torna in linea; kill/revoca scartano i
   risultati in arrivo (epoca). La policy viaggia come byte firmati (`Policy.bodyBytes`) e la
   chiave HMAC vive anche nel worker, che non ha rete né file. Uscita identica byte per
   byte (`test/unit/worker.test.mjs`).
2. **Forma "wire" dello scambio** (`src/capture/wire.ts`): gli hook salvano solo stringhe e
   byte già in mano a Node; conversione in `Exchange` (buffer degli header, split del
   target, parse del blocco header) rimandata al worker o a dopo la risposta.
3. **Tee dei corpi più economico** (`src/capture/body.ts`): una sola copia, nessun
   `Buffer.concat` per corpi in un solo chunk, lista limitata a `maxBodyBytes + 1`.
4. **Decisione di campionamento prima del tee**: già così (soggetto dagli header); in più per
   gli scambi non campionati non si generano più trace/span id e si evita `delete` sugli
   oggetti req/res (che li mandava in modalità dizionario); scansione degli header con
   filtro sulla lunghezza.
5. **Codifica OTLP a lotti**: `logRecord` scritto a mano una volta sola (nel worker); il
   corpo della richiesta è una giunzione di record già pronti.
6. Micro-ottimizzazioni del sanitizer: indice delle op per metodo/numero di segmenti,
   memo (limitati) di `isLiteralName`/`headerOutName`, buffer zero statico.
   Sanitize + assemblaggio di uno scambio in ingresso, banco in linea: 22,4 → ≈ 20 µs.
7. Provate e **scartate** (nessun guadagno misurato): HMAC con due `crypto.hash` al posto di
   `createHmac` (1,27 vs 1,31 µs; `crypto.hash` non esiste in Node 20); impacchettare il
   lotto in un solo buffer invece del clone strutturato (−0,5 µs/scambio, trascurabile);
   riscrivere il tokenizer JSON (già a slice latin1/UTF-8, nessun hot spot nel profilo).

## Risultati (mediana [min..max] di 5 giri; delta accoppiati acceso vs spento)

| Misura | Campionamento | Prima | Dopo | Budget |
|---|---|---|---|---|
| CPU/richiesta sotto carico, thread richieste | 100 % | +79,7 % [44..120] | **+19,6 %** [8,6..24,9] | |
| CPU/richiesta sotto carico, tutti i thread | 100 % | +76 % | +74 % (il lavoro è nel worker) | |
| Throughput a saturazione | 100 % | −43,4 % [−54,7..−25,2] | **−20,4 %** [−33,2..+6,7] | −15 % |
| p50 aggiunto a 300 req/s | 100 % | −0,02 ms | −0,11 ms (rumore) | +1 ms: ok |
| CPU/richiesta sotto carico, thread richieste | 5 % | +14,8 % [8,4..35,9] | **+7,0 %** [−0,9..14,3] | |
| Throughput a saturazione | 5 % | −16,4 % [−25,9..−5,9] | **−9,1 %** [−16,7..+8,5] | −5 % |
| p50 aggiunto a 300 req/s | 5 % | −0,15 ms | −0,14 ms (rumore) | +1 ms: ok |
| Solo hook (campionamento 0,01 %) | 0,01 % | – | CPU +4,8 %, throughput −4,7 % [−17,5..−2,7] | |

Baseline iniziale (macchina molto carica, carico 25–28, 5 giri): throughput −46,9 %
[−51,0..−45,1] al 100 %; CPU app per richiesta +90 % (tutti i thread).

Valori assoluti tipici (carico basso): app senza SDK ≈ 135–140 µs CPU/richiesta sotto
carico, 7 000–7 400 req/s; con SDK 100 % ≈ 164 µs e 5 600 req/s.

**Esito rispetto al budget**: la latenza (p50 +≤ 1 ms) è rispettata con ampio margine; il
throughput **non** raggiunge ancora −5 % / −15 % su questa macchina (−9 % / −20 % mediani,
con intervalli molto larghi). Il costo che resta nel thread delle richieste è: hook
(≈ +5 % anche con campionamento ~0), `postMessage` e accodamento (≈ 3 %), invio HTTPS dei lotti
(TLS + scrittura, ≈ 3 %). A 100 % il worker consuma inoltre un core intero in più (CPU
"tutti i thread" +74 %), che su una macchina già satura sottrae risorse all'app: il guadagno
vero si vedrà con un core libero per il worker.

## Costo fisso per richiesta non campionata (misure su un deployment multi-host)

Il deployment multi-host di prova ([`test/lab/`](../../test/lab/README.md), container LXC, richiesta da ~70 µs, ciclo chiuso, policy con
soggetto JWT) ha misurato ≈ +30 µs fissi per richiesta anche a campionamento 0 % (−30 %
di capacità). Obiettivo: ≤ 5 µs. Cambiamenti sul percorso "non campionato":

- **Decisione dagli header grezzi, senza allocazioni** (`Sanitizer.decideRaw`): una sola
  scansione di `rawHeaders` con filtro sulla lunghezza del nome (niente `toLowerCase`, niente
  coppie `[nome, Buffer]`, niente oggetti per la decisione: costanti congelate). La decisione
  sul soggetto (cookie, header, JWT) è ricordata **per valore dell'header** (cache limitata a
  4 096 voci, per policy+chiave): HMAC, decodifica base64 e parsing JSON del JWT si fanno una
  volta per utente, non a ogni richiesta. Stessa decisione di `decide()` (test di
  equivalenza in `test/unit/decide.test.mjs`); casi particolari (baggage fidato, header
  soggetto ripetuto) passano dal percorso lento.
- **Nessun tee, wrapper, id o oggetto per richiesta**: lo scambio non campionato imposta il
  solo contesto condiviso `UNSAMPLED` (un oggetto congelato) in `AsyncLocalStorage`, che serve
  alle chiamate in uscita per ereditare "non campionato". Prima si allocava un contesto con
  traceId.
- **Chiamate in uscita ereditate non campionate**: se la policy non chiede `tt.s`
  (`propagate_to` vuoto) escono subito, prima di leggere host/protocollo e comporre
  `urlBase`; con `propagate_to` la verifica per host è memorizzata (era una normalizzazione
  con regex a ogni chiamata).
- **Orologio senza BigInt**: `performance.now()` al posto di `process.hrtime.bigint()` (4
  chiamate e allocazioni BigInt per richiesta; era il 30 % del costo dei nostri hook nel
  profilo); `response.finish` esce prima di leggere l'orologio se lo scambio non ha stato.
- Canali `diagnostics_channel`: sono già i meno costosi disponibili (`http.server.request.start`
  e `response.finish` per l'ingresso; `http.client.request.created` e `undici:request:create`
  per l'uscita, uno per scambio; i canali dei chunk di undici fanno solo una ricerca in
  `WeakMap` e solo per gli scambi campionati hanno stato).

### Micro-bench del solo percorso degli hook (`node bench/hooks.mjs`)

Server `node:http` nudo con gli hook su un host finto (nessun Fleet né export), client TCP in
un processo separato, 16 connessioni, 600 clienti diversi, CPU del thread principale per
richiesta, 5 giri da 3 s (mediana, delta accoppiati con "hook spenti"). Macchina condivisa
(carico 6–10): gli intervalli sono larghi, l'ordine di grandezza è affidabile.

| Soggetto della policy | Hook, non campionato (0 %) | 5 % | 100 % |
|---|---|---|---|
| nessuno | +0,1…0,6 µs | +0,2…1,9 µs | +2,2…2,9 µs |
| cookie | −0,6…1,5 µs | ≈ +1,4 µs | ≈ +0,5 µs |
| JWT in `Authorization` | +0,5…1,3 µs | ≈ +2 µs | ≈ +2 µs |

Decisione di campionamento per una richiesta con JWT (`node bench/decide.mjs`):
`decide()` su coppie di header **2,4–2,5 µs → `decideRaw` 0,13 µs** (con una CPU circa 2,5×
più lenta di questa, quella del laboratorio, 6 µs → 0,3 µs). Il costo fisso del percorso
non campionato è quindi **≈ 1 µs** su questa macchina (obiettivo ≤ 5 µs), prima ≈ 1,5–3,5 µs.

Attenzione: questo banco **non riproduce** i +30 µs del laboratorio (anche prima del
cambiamento il percorso degli hook costava ≈ 2–3,5 µs qui). Una parte è la CPU più lenta del
laboratorio (≈ ×2,5) e la decisione sul soggetto JWT a ogni richiesta (ora in cache); il
resto non è attribuibile con i soli dati qui disponibili: **rimisurare in laboratorio** con
questa versione e, se il costo fisso resta, profilare lì lo shop
(`node --cpu-prof --import @traffic-twin/sdk/register server.js`) e leggere i campioni per
file/funzione come descritto nel Metodo.

### Endpoint banale e endpoint realistico (banco completo con Fleet reale ed export)

`bench/overhead.mjs --endpoint health` è un `GET /health` da ~25 µs di lavoro (il caso peggiore
per le percentuali); `--io-ms 2` aggiunge al `POST /orders` (3 scambi catturati) un'attesa
asincrona di 2 ms prima della risposta, come una query a database. Mediana [min..max] di 5
giri da 5 s, delta accoppiati acceso vs spento; carico macchina 5–10.

| Scenario | Campionamento | CPU/richiesta sotto carico (thread richieste) | Throughput | p50 aggiunto a 300 req/s |
|---|---|---|---|---|
| `GET /health` (~26 µs) | 0 % | **+1,8 %** (≈ +0,5 µs) | −0,1 % | −0,01 ms |
| `GET /health` | 5 % | +5,8 % (≈ +1,5 µs) | −1,9 % [−3,6..−1,4] | +0,03 ms |
| `POST /orders` + 2 ms di I/O asincrono (~150 µs CPU, 3,9 ms di latenza) | 5 % | **+3,4 %** [+1,2..+6,3] | +5,9 % (rumore: ±) | −0,04 ms (−1 %) |
| `POST /orders` + 2 ms di I/O asincrono | 100 % | **+15,4 %** [+13,8..+26,6] (tutti i thread +62 %) | +1,8 % [−2,4..+6,0] | −0,5 ms (rumore) |
| `POST /orders` senza attesa (~135 µs CPU) | 5 % | +6,2 % | −5,7 % [−31,6..+41] | +0,02 ms |
| `POST /orders` senza attesa | 100 % | +21,7 % [+19,4..+27,9] (tutti i thread +80 %) | −22,6 % [−33,9..−19,3] | −0,26 ms (rumore) |

Lettura: con un endpoint che aspetta I/O (anche solo 2 ms) l'SDK non cambia né throughput né
latenza in modo misurabile (differenze entro il rumore, < 1 % della latenza), anche al
100 % di campionamento: l'overhead di CPU del thread delle richieste resta, ma è nascosto
dall'attesa; il worker usa un altro core. Il caso "senza attesa a 100 %" è l'unico in cui il
throughput scende oltre il budget (−22,6 %).

## Prossimi passi possibili

- Spostare nel worker anche l'invio HTTPS (mTLS) dei lotti: toglie TLS e scrittura dal
  thread principale (richiede condividere certificato/chiave e ripetizioni con il worker).
- Rimisurare su una macchina dedicata (carico noto, generatore di carico su un'altra macchina).
- Hook: evitare `process.hrtime.bigint()` (due chiamate per scambio) per il solo
  contatore di overhead.

## Riprodurre

```bash
cd sdk/node && npm ci
npm run bench                              # 100 %, 5 giri
node bench/overhead.mjs --rate-bp 500      # 5 %
node bench/overhead.mjs --rate-bp 1        # solo hook
node bench/overhead.mjs --threads 0        # sanificazione in linea
node bench/overhead.mjs --profile /tmp/prof
```
