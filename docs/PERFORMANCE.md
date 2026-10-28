# traffic-twin — Prestazioni

Budget di prestazione di tt-core, come si misurano, cosa è stato misurato con volumi reali e cosa resta da fare. Il dimensionamento per chi installa è in [OPERATIONS.md](OPERATIONS.md) §2; i costi degli SDK sono in [`sdk/node/BENCHMARKS.md`](../sdk/node/BENCHMARKS.md) e al §3.6. Il laboratorio multi-host con cui si rifanno le misure su host reali è in [`test/lab/`](../test/lab/README.md).

## 1. Come si misura

Il banco è [`test/perf/ttperf`](../test/perf/ttperf). In un solo processo avvia keyguard e tt-core (gli stessi componenti di `tt dev up`), poi:

1. **costruisce un database realistico.** Il traffico demo (negozio e corriere, `internal/core/demosim`) passa da una sorgente vera, iscritta tramite Fleet, sotto una policy firmata da keyguard. Gli eventi sanificati sono i modelli. Vengono poi replicati nel tempo, sui servizi (coppie `shop-api-NN` → `partner-NN-ext`), sugli host esterni (pattern `host:{*}.tenantNNNN.example`…) e sulle sorgenti. Ogni copia ha identificativi e trace propri, così i flussi restano interi. Le righe si scrivono con le stesse istruzioni del writer dell'intake. Si aggiungono le voci di audit, scritte dal log di audit vero con la catena di hash. Su questa base girano snapshot, mining, archetipi, mondo, pacchetto ed export. A tutto questo si aggiunge la storia di un anno: snapshot giornalieri, regole, allarmi, consegne di webhook, mondi e pacchetti;
2. **misura ogni GET dell'API di amministrazione** ([`api/admin-api.v1.openapi.yaml`](../api/admin-api.v1.openapi.yaml)) con parametri tipici: p50, p95, massimo e dimensione della risposta;
3. **misura ogni job.** Per ognuno registra durata, picco dell'heap Go e crescita del database. I job sono: snapshot dei contratti, mining, archetipi, mondo, gate e pacchetto, export, export degli eventi, verifica dell'audit, consegna dei webhook (con un endpoint lento), purge di retention (con l'intake che riceve 2 000 ev/s nel frattempo), una raffica di ingestione, il filtro di Bloom di keyguard (5 M token, 1 M distinti), il match di 10 000 candidati e il mock con migliaia di sessioni e un avanzamento del clock di un anno;
4. **traccia ogni istruzione SQL.** Ne registra chiamate, tempo totale e righe, poi esegue `EXPLAIN QUERY PLAN` sui dati generati e segnala le scansioni complete e gli ordinamenti in tabella temporanea.

Il rapporto esce in JSON e in Markdown.

| Scala | Eventi | Servizi | Pattern host | Sorgenti | Snapshot | Audit | Durata |
|---|---|---|---|---|---|---|---|
| `smoke` | 30 000 | 10 | 100 | 20 | 30 giorni | 5 000 | ~1 min |
| `lab` | 2 000 000 in 48 h | 50 | 2 000 | 200 | 30 giorni | 100 000 | dataset ~4 min (3,8 GB); `-only memory` ~8 min |
| `ci` | 300 000 | 50 | 2 000 | 200 | 365 giorni | 100 000 | ~3 min |
| `full` | 10 000 000 | 50 | 2 000 | 200 | 365 giorni | 1 000 000 | dataset ~8 min (18,8 GB), misure 20-40 min |

```sh
make perf                                  # scala ci, fallisce se un budget è superato
make perf PERF_SCALE=full PERF_OUT=/dati/perf-report
go run ./test/perf/ttperf -scale full -dir /dati/ttperf -keep -only none   # solo il dataset, riusabile
go run ./test/perf/ttperf -scale full -dir /dati/ttperf -skip services,services.ops,hosts
# memoria con il volume di un core da 4 GiB, su un host di 4 GiB emulato (§3.5)
TTPERF_BUDGET_PROFILE=lab go run ./test/perf/ttperf -scale lab -dir /dati/lab2m -keep -only memory \
  -memlimit 4GiB -miner-max-events 5000000 -budgets test/perf/budgets.json
```

Con `-dir` di un'esecuzione precedente il dataset si riusa (con APFS si clona all'istante con `cp -c -R`). In questo modo il "prima" e il "dopo" di una modifica si confrontano sugli stessi dati. I budget sono in [`test/perf/budgets.json`](../test/perf/budgets.json): il profilo `default` vale per la scala `ci`, `TTPERF_BUDGET_PROFILE=full` aggiunge quelli del dataset grande. Il job `perf` di GitHub Actions ([`.github/workflows/perf.yml`](../.github/workflows/perf.yml)) gira ogni lunedì e su richiesta. Usa la scala `ci`, si ferma se un budget è superato e pubblica il rapporto nel riepilogo del job.

Le misure di questo documento sono state prese su un portatile Apple M3 (8 core, 16 GB, SSD). Un runner di GitHub è circa 2-3 volte più lento; un core di prova in un container da 4 vCPU e 4 GiB ancora di più sulle letture da disco (§3.4).

## 2. Budget

| Classe | Budget | Note |
|---|---|---|
| **Liste** (`GET` di collezioni) | **p95 < 200 ms** | con 10 M eventi, 2 000 servizi con contratto, un anno di storia |
| **Dettagli** (`GET` di un oggetto) | **p95 < 100 ms** | |
| **Operazioni pesanti sincrone** (download di pacchetto, export di 100 000 voci di audit, verifica dell'audit) | p95 < 5 s (`ci`), < 10 s (`full`) | |
| **Job lunghi** (mining, archetipi, mondo, pacchetto, export) | **mai oltre ~20 s nella richiesta** | oltre, la risposta è il `Job` `running` e il risultato si legge su `GET /api/v1/jobs/{id}` (admin-api 1.9.0) |
| **Memoria del mining** | ~1,3 KB per evento della finestra al picco (RSS), ~0,7 KB di dati vivi | `miner.max_events` = metà del limite di memoria per posto dei lavori pesanti, a ~1,5 KB per evento (4 GiB → 1,43 M eventi); un valore esplicito più grande si abbassa (§3.5) |
| **Lavori pesanti** | mai due insieme sotto 16 GiB | mining, archetipi, mondi, pacchetti, export, snapshot e `prepareMock` aspettano in coda (`queued`); un secondo mining si unisce al primo |
| **Ingestione durante la purge** | nessun rifiuto per coda piena a 2 000 ev/s, blocco del writer < 1,5 s | |
| **Ingestione sostenuta** | ≥ 2 000 ev/s nella raffica di `ci` su un runner; un core da 4 vCPU regge ~4 000 ev/s su un database piccolo (§3.6, OPERATIONS §2) | |
| **Filtro di Bloom** | segmenti proporzionali ai token **distinti** | |
| **Risposte limitate** | nessuna lista senza limite, nessuna risposta che cresce con la durata di un'operazione | |

`GET /api/v1/services`, `GET /api/v1/services/{service}/ops` e `GET /api/v1/hosts` leggono gli aggregati mantenuti all'ingest (tabelle `intake_agg*`, lavoro parallelo) e sono sotto budget come le altre liste: alla scala `ci` 7, 8 e 18 ms (prima 479, 489 e 984 ms; su un core di prova da 4 vCPU 9,4 s, 6,5 s e 13,1 s). Il campione delle origini di route di `ops` legge nell'ordine dell'indice e si ferma alle prime 100 righe. Il banco ricostruisce aggregati e rollup degli eventi che scrive senza passare dal writer, come farebbe il backfill di un database precedente.

## 3. Risultati

### 3.1 Dataset `full` (10 M eventi), prima e dopo

"Prima" è il codice prima delle ottimizzazioni, "dopo" quello attuale, sugli stessi dati (dataset clonato).

| Misura | Prima | Dopo |
|---|---|---|
| Mining, finestra di 14 giorni (4,6 M eventi) | **529 s, heap 16,5 GB**, la risposta va persa (`write_timeout` di 30 s) | **28 s, 2,7 GB**: finestra ristretta automaticamente agli ultimi 1 M eventi (default senza limite di memoria noto); oltre 20 s la risposta è un job `running` |
| Archetipi (30 giorni, 5 M eventi in ingresso) | **152 s, 10,9 GB**, risposta persa | **23 s**, solo colonne (nessun corpo decodificato) |
| Snapshot di un servizio | ~1 s (legge la finestra di tutti i servizi) | 0,14 s in media, 0,3 s il più grande (solo i gruppi del servizio, dall'indice) |
| Snapshot dei 50 servizi uno per uno | 46,8 s | 6,9 s |
| Generazione del mondo | 457 s (contratti inferiti da tutta la finestra), risposta persa | 484 s, ma in background (job `running`); l'inferenza resta da rendere incrementale (§5) |
| Pacchetto subito dopo il mondo | 525 s (la stessa inferenza rifatta) | **17,6 s** (inferenza riusata) |
| `GET /api/v1/gaps` (2 000 servizi) | p95 476 ms, max 1,3 s | p95 94 ms |
| `GET /api/v1/contracts` | p95 138 ms | p95 101 ms |
| `GET /api/v1/audit/verify` (1 M voci) | 2,77 s | 2,15 s |
| Purge di 2 M eventi con ingestione a 2 000 ev/s | 439 s; **writer bloccato fino a 4,95 s, coda piena (50 000), 113 100 eventi respinti** | 609 s; blocco massimo 540 ms, coda al più 1 810, **nessun evento respinto** |
| Raffica di ingestione sul database da 10 M | 5 176 ev/s | 4 868 ev/s (invariata: §4.6) |
| Filtro di Bloom (5 M token, 1 M distinti, segmenti da 500 k) | 13 segmenti | 3 segmenti |
| Webhook: 200 notifiche, con un endpoint lento (5 × 2 s) | le veloci attendono 12,8 s | 1,7 s (misura di `ci`; nella corsa `full` il banco puntava al ricevitore di una corsa precedente, ora corretto) |
| Mock: 1 000 sessioni × 50 ordini | p95 1,0 ms | p95 0,7 ms |

### 3.2 Dataset `ci` (300 000 eventi), riferimento del job settimanale

Prima e dopo sugli stessi dati: 100 regole, 2 000 allarmi, 20 000 consegne, 40 mondi, 20 pacchetti. Il "prima" supera due budget (segmenti del Bloom, consegna dei webhook), il "dopo" li rispetta tutti.

| Misura | Prima | Dopo |
|---|---|---|
| `GET /api/v1/gaps` p95 | 41,5 ms | 19,0 ms |
| `GET /api/v1/audit/verify` (100 000 voci) | 242 ms | 188 ms |
| Pacchetto dopo il mondo | 3,6 s | 0,7 s |
| Webhook veloci con un endpoint lento | 12,2 s | 1,7 s |
| Purge con ingestione: blocco massimo del writer | 139 ms | 49 ms |
| Segmenti del Bloom (500 000 token, 100 000 distinti) | 12 | 3 |
| Mining (140 000 eventi) | 1,7 s, 307 MB | 2,1 s, 251 MB |
| Raffica di ingestione | 19 054 ev/s | 18 196 ev/s |
| Tutte le altre liste e dettagli | ≤ 20 ms | ≤ 20 ms |
| `/services`, `/services/{s}/ops`, `/hosts` | 479, 489, 984 ms | 7, 8, 18 ms (aggregati del lavoro parallelo, dopo l'unione) |

### 3.3 Dimensioni

10 M eventi occupano 18,8 GB, cioè ~1,9 KB per evento: corpo, quattro indici, ~3,5 token indicizzati per evento. Il resto del database pesa poco: 750 000 snapshot (un anno per 2 050 servizi) restano sotto 1 GB, perché i modelli sono compressi. Generare i 10 M eventi con gli indici costruiti alla fine richiede ~5 min. Con gli indici in linea l'inserimento scende da 37 000 a 13 000 ev/s già a 3 M eventi. È lo stesso effetto che rallenta l'intake di un database grande (§4.6).

### 3.4 Core di prova su host reale (container da 4 vCPU e 4 GiB, sola lettura)

Database da 4,7 GB per 340 000 eventi (retention 48 h). **3,9 GB sono pagine libere**: il database era stato creato prima di `auto_vacuum=INCREMENTAL` e non restituisce lo spazio (OPERATIONS §2, `tt compact`). Tutte le liste rispondevano in 2-9 ms, tranne `GET /api/v1/services/{service}/ops`, che impiegava **6,5 s** con la stessa aggregazione di `/services` (9,4 s) e `/hosts` (13,1 s). Il piano lo confermava: `SCAN intake_events USING INDEX intake_events_op` senza indice coprente. `dir` non è nell'indice, quindi ogni evento costa una lettura della riga. Il file frammentato e il disco del container peggiorano le cose: sul portatile, 300 000 eventi costano 0,5 s. Oggi queste liste leggono gli aggregati (§2).

### 3.5 Memoria: OOM di un core da 4 GiB

Su un core di prova in un container LXC da 4 GiB l'OOM killer ha ucciso tt-core. La finestra del miner conteneva 1,95 M eventi (retention 48 h, 60–96 000 chiamate/h). Due `POST /api/v1/rules/mine` a 49 s di distanza: il primo era finito, il secondo è partito subito dopo (il mutex del miner li metteva in fila) ed è stato ucciso durante il caricamento.

**Causa.** Tre fatti insieme:

1. **tt-core non vedeva nessun limite di memoria.** Nel container il limite di 4 GiB sta sopra il namespace dei cgroup: ogni `memory.max` visibile vale `max`. La unit ha `ProcSubset=pid`, che nasconde `/proc/meminfo` (dove lxcfs riporta i 4 GiB). Quindi niente `GOMEMLIMIT` (il log `memory limit` non compariva mai all'avvio) e niente finestra del miner adattata alla memoria.
2. **`miner.max_events: 5000000` nella configurazione**: la guardia della finestra non scattava, e una corsa caricava tutti gli 1,95 M eventi.
3. **Il picco di una corsa era già al limite.** Misurato dopo il riavvio, con una sola corsa e nient'altro: RSS da 45 MB a **4,0 GB** in 110 s (1,96 M eventi), 49 MB liberi nel container. Il GC con `GOGC=100` lascia crescere l'heap fino al doppio dei dati vivi (~1,4 GB di dati vivi per 2 M eventi, 2,8 GB di heap). Le corse precedenti erano passate per poco; l'ultima, partita sui rifiuti della precedente e con qualche migliaio di eventi in più, ha superato i 4 GiB.

Il risultato del job (diagnostica: 4 KB) e il wrapper `groupRules` (solo `GET`) non c'entrano; snapshot (giornalieri alle 00:05) e manutenzione (oraria, a pezzi) non si sovrapponevano.

**Correzioni.**

| Correzione | Dove |
|---|---|
| Limite di memoria dal cgroup **del processo** e di ogni genitore (`memory.max`, `memory.high`, v1 `memory.limit_in_bytes`), poi `/proc/meminfo`, poi `GOMEMLIMIT`; il più piccolo vince. Senza limite noto, un avviso all'avvio | `internal/core/memlimit.go` |
| `MemoryMax=3584M` nella unit (la via per un LXC con `ProcSubset=pid`) | `test/lab/units/tt-core.service`, OPERATIONS §2.1 |
| Coda dei lavori pesanti: un posto sotto 16 GiB (poi uno ogni 8 GiB, al più 4), in ordine di arrivo; chi aspetta è un Job `queued` (`GET /api/v1/jobs`). Mining (API e programmato), archetipi, mondi, pacchetti, export, export degli eventi, snapshot (API e programmati), `prepareMock` | `internal/core/heavy.go`, `longjobs.go` |
| Un `POST /api/v1/rules/mine` mentre un mining è in coda o in corso si unisce a quel Job (stesso `job_id`, leggibile da chi si è unito); il mining programmato salta il turno | `longjobs.go`, `core.go` (`scheduledMine`) |
| Finestra del miner dalla memoria: metà del limite per posto, ~1,5 KB per evento; un `miner.max_events` esplicito più grande si abbassa (log `miner.max_events lowered to what fits`) | `heavy.go` (`autoMinerEvents`), `core.go` (`sizeMinerWindow`) |
| Log del miner più compatto: id di trace numerati e id di span come hash (non tre stringhe per evento), alberi delle trace con array ordinati invece di due mappe con chiavi stringa (il picco transitorio alla fine del caricamento), slice di ogni evento senza capacità in più: −14 % di dati vivi, −20 % di RSS al picco | `internal/miner/olog.go` |
| Un Job per richiesta (prima il mining ne creava due), risultato limitato: 200 diagnostiche per tipo con i totali, lo `status` senza la sua copia della diagnostica, risposta oltre 16 MiB → `result_too_large` | `longjobs.go`, `api.go` (`mineResult`) |

**Misure** (banco `test/perf/ttperf -scale lab -only memory`: 2 M eventi in 48 h, 3,8 GB di database, portatile M3; processo intero del banco, keyguard compresa; "dopo" con `-memlimit 4GiB` e `-miner-max-events 5000000` come il core dell'incidente):

| Scenario | Prima: RSS di picco | Prima: heap | Dopo: RSS di picco | Dopo: heap (vivo) | Note |
|---|---|---|---|---|---|
| Una corsa | **3 191 MB**, 62 s | 2 944 MB | **1 965 MB**, 35 s | 1 886 MB (1 059) | dopo: finestra di 1,43 M eventi (i più recenti, ~34 h su 48) |
| Due `POST` a 1 s | **3 317 MB**, 153 s, due corse | 3 153 MB | **2 012 MB**, 35 s, una corsa | 1 943 MB (1 035) | il secondo `POST` riceve lo stesso Job |
| Mining + snapshot + pacchetto insieme | **3 467 MB**, 185 s | 3 060 MB | **2 156 MB**, 291 s | 2 016 MB (1 084) | dopo: uno alla volta, quindi più lento (il pacchetto, ~4 min, aspetta il mining; prima andava in parallelo); seconda misura 2 047 MB |
| Una corsa su tutti i 2 M eventi, solo limite morbido | — | — | 3 318 MB (codice di prima) → **2 637 MB** (log compatto) | 2 803 → 2 526 MB (1 410 vivi) | perché serve anche la finestra: i dati vivi da soli arrivano a 1,4 GB |

**Sul core di prova, dopo** (con `MemoryMax=3584M`). All'avvio il log dice `memory limit limit_mb=3584 source=cgroup go_soft_limit_mb=3046` e `heavy jobs slots=1 miner_max_events=1252698`. Poi la stessa sequenza dell'incidente: due `POST /api/v1/rules/mine` a un secondo, seguiti da uno snapshot di un servizio. Risultato: un solo Job di mining (il secondo `POST` ha ricevuto lo stesso `job_id`); lo snapshot `queued` (`GET /api/v1/jobs`: `heavy {slots 1, running 1, queued 1}`), poi `done`; la finestra ristretta a 1,25 M eventi. RSS da 37 MB a un picco di **2,41 GB** in 65 s (`memory.peak` del cgroup 2,45 GB su 3,5 GiB), `memory.events` tutto a zero, 1,6 GB liberi nel container. Gli eventi di quel core sono più ricchi di quelli del banco: ~1,9 KB per evento al picco contro ~1,3 (prima: 4,0 GB contro 3,2 GB a parità di eventi). Il traffico ora è ~90 000 eventi/h, quindi 1,25 M eventi coprono le ultime ~14 ore.

Regressioni: `internal/miner` `TestLogMemoryPerEvent` (memoria del log per evento sotto 800 B: 623 B, prima 724), `internal/core` `TestMemoryLimitAt` (LXC con e senza `MemoryMax`, `ProcSubset=pid`, Docker, cgroup v1), `TestHeavyGate*`, `TestLongJobsQueueAndJoin`, `TestLongJobResultTooLarge`, `TestLongJobOneJobPerRequest`, `TestMineResultBounded`, `TestSizeMinerWindow`; budget del profilo `lab` in `test/perf/budgets.json` (RSS di picco sotto 2,8 GB per ogni scenario, una sola corsa per i due `POST`).

### 3.6 Deployment multi-host di prova

Misure su tre host separati come in produzione ([`test/lab/`](../test/lab/README.md)): core da 4 vCPU e 4 GiB, keyguard da 2 vCPU e 1 GiB, demo da 4 vCPU e 6 GiB (Debian 12, container LXC su un processore di classe portatile condiviso con altre macchine: misure rumorose). Demo con orologio accelerato (un giorno simulato ogni 6 minuti), 600 clienti finti, al più 100 richieste/s.

**Eventi/s accettati dall'intake** (`bench-intake.sh`: un tt-core di prova con un keyguard dedicato; 6 sorgenti sull'host della demo emettono eventi sanificati a ritmo fissato, 20 s per gradino):

| Obiettivo ev/s | Emessi | **Accettati** | Scartati dalle sorgenti | Coda residua |
|---:|---:|---:|---:|---:|
| 1 000 | 1 000 | 991 | 0 | 0 |
| 2 000 | 2 000 | 1 983 | 0 | 0 |
| 4 000 | 4 000 | **3 972** | 0 | 0 |
| 8 000 | 8 000 | 4 318 | 0 | 70 569 |
| 12 000 | 12 000 | 1 843 | 171 618 | 64 197 |
| 16 000 | 16 002 | 1 997 | 242 206 | 102 087 |

**Capacità sostenuta senza perdite: circa 4 000 eventi/s** (un solo scrittore SQLite); oltre, l'intake risponde con contropressione e le sorgenti scartano i più vecchi (mai bloccano l'applicazione). Dopo il sovraccarico il tasso accettato scende a circa 2 000/s mentre le code si svuotano. Core di prova: picco RSS **301 MiB**, CPU media **78 % di un core** nei 135 s della prova.

**Con la demo in funzione** (circa 25 eventi/s): tt-core **2 % di un core**, RSS 48 MiB (picco 237 MiB dopo l'avvio e le analisi); keyguard 0,6 % di un core, RSS 54 MiB.

**Latenza aggiunta da tt-egress** (`bench-overhead.sh egress`: `GET` al corriere della demo con latenza iniettata log-normale, mediana 80 ms; 100 req/s per 60 s, 16 connessioni, campionamento 100 %):

| | p50 | p90 | p99 |
|---|---:|---:|---:|
| diretto | 80,2 ms | 176,9 ms | 328,3 ms |
| tramite tt-egress | 81,1 ms | 171,3 ms | 331,1 ms |

Aggiunta misurata: **≈ +0,9 ms a p50, +3 ms a p99**, dello stesso ordine del rumore (latenza propria dichiarata da tt-egress: 21 µs a p50, 54 µs a p99).

**SDK Node** sullo shop della demo (`bench-sdk-node.sh`, `GET /customers/{id}/orders` servita dalla memoria, richiesta da ~70 µs: il caso peggiore per l'overhead; ciclo chiuso a 16 connessioni, 5 giri da 20 s, mediana):

| Configurazione | req/s | Δ vs SDK spento | p50 / p99 ms |
|---|---:|---:|---|
| SDK spento | – | – | 1,20 / 2,80 |
| campionamento 0 % | 14 015 | +0,3 % | 1,10 / 2,57 |
| campionamento 5 % | 14 197 | +1,6 % | 1,09 / 2,55 |
| campionamento 100 % | 6 717 | −52 % | 1,97 / 7,41 |
| `TT_SANITIZER_THREADS=0`, 100 % | 3 580 | −74 % | 4,20 / 9,17 |

A 0 % e 5 % lo shop è indistinguibile da «SDK spento» entro il rumore; resta il costo delle richieste *campionate* (~130-250 µs per scambio), che pesa molto meno su richieste da 10 ms. Dettagli e banco dell'SDK: [`sdk/node/BENCHMARKS.md`](../sdk/node/BENCHMARKS.md).

## 4. Analisi

### 4.1 Piani delle query

Il banco ha tracciato 146 istruzioni distinte. Quelle con una scansione completa o un ordinamento temporaneo, con l'esito:

| Istruzione (chiamante) | Piano | Esito |
|---|---|---|
| `Scan` a finestra di tempo `ORDER BY id`, cioè profili degli archetipi e statistiche dei guasti del pacchetto | `SEARCH … intake_events_ts` + **`USE TEMP B-TREE FOR ORDER BY`** su milioni di righe col corpo | **corretto**: ordine per tempo (dall'indice) e solo colonne (`ScanMeta`) |
| `OpSummaries` della finestra per lo snapshot di **un** servizio | legge la finestra di tutti i servizi, con una lettura di riga per evento (`dir`) | **corretto**: `OpSummariesOf`, indice coprente `(service, op, status, ts_ms)` |
| Campionamento dei gruppi grandi nell'inferenza (oltre `SampleCap`) | leggeva e decodificava ogni evento, poi ne scartava la maggior parte | **corretto**: campione per hash dell'id valutato sull'indice (`SampleEvery`) |
| `OpSummaries`, `HostStats`, `HostLatencyP50` (tutto il magazzino) | scansione dell'indice con lettura della riga, `TEMP B-TREE FOR GROUP BY` | aggregati incrementali (lavoro parallelo, §5) |
| `services/{s}/ops`, campione di 100 eventi per operazione `ORDER BY id LIMIT 100` | `TEMP B-TREE` su tutti gli eventi dell'operazione | resta (stessa area degli aggregati: §5) |
| `world_worlds … ORDER BY created_at DESC LIMIT 500` | `SCAN` + ordinamento; le colonne dopo i blob costringono a leggerli | resta, basso: 110 ms con 200 mondi |
| `packwriter_packs … ORDER BY created_at` | `SCAN` + ordinamento | resta, basso (righe poche) |
| Ricerca del soggetto per trace nell'inferenza (`dir = 0 AND trace_id = ?`) | indice, ma **N+1**: 300 000 chiamate in una generazione di mondo | resta (con cache di 20 000): §5 |
| `GET /api/v1/gaps`: ultimi snapshot e poi un `Get` per servizio | **N+1** con decompressione e decodifica del modello a ogni chiamata | **corretto**: i gap si tengono in memoria per id di snapshot (gli snapshot non cambiano) |
| `drift_alerts WHERE kind = ? ORDER BY id DESC LIMIT`, `audit_entries` coda, `miner_runs ORDER BY id DESC LIMIT 1` | `SCAN` all'indietro sulla chiave con `LIMIT` | va bene (si ferma alle prime righe) |
| Tabelle piccole (`fleet_*`, `auth_*`, `core_*`, `intake_quarantine`) | `SCAN` | va bene |

Indici mancanti: nessuno da aggiungere oltre agli aggregati. I due indici a chiave casuale, `trace_id` e `subject`, sono la causa principale del rallentamento dell'ingestione sui database grandi (§4.6). Toglierli richiederebbe di ripensare l'inferenza del soggetto e l'export per soggetto: è annotato al §5.

### 4.2 Lavoro rifatto a ogni richiesta

- **Contratti per mondi e pacchetti.** Il mondo e il pacchetto inferivano ogni volta i contratti dai 14 giorni di eventi, cioè tutti i corpi della finestra. **Corretto**: l'inferenza si riusa per 10 minuti, quindi il pacchetto costruito subito dopo il mondo non la rifà. La prima inferenza resta lunga con molti eventi: ora è un job in background (§4.4).
- **Gap**: corretto (vedi sopra).
- **`/services`, `/hosts`, `/services/{s}/ops`**: lavoro parallelo.

### 4.3 Strutture in memoria senza limite

| Struttura | Prima | Dopo |
|---|---|---|
| Log del miner (tutti gli eventi della finestra) | fino a `max_events` = 5 M, ~3,5 KB/evento al picco: **16,5 GB** | finestra dalla memoria (metà del limite per posto dei lavori pesanti, ~1,5 KB/evento: 4 GiB → 1,43 M eventi; §3.5), anche quando `max_events` è più grande. Oltre, la finestra si restringe agli eventi più recenti invece di fallire. L'array degli eventi si dimensiona sul conteggio. Nomi e valori ripetuti dei corpi sono condivisi, id di trace e di span non sono più stringhe, alberi delle trace su array ordinati: ~0,7 KB vivi e ~1,3 KB di RSS al picco per evento |
| Lavori pesanti contemporanei | nessun limite: due mining, o mining e pacchetto, sommavano i picchi | una coda (§3.5): un posto sotto 16 GiB; un secondo mining si unisce al primo |
| Risultato dei job lunghi | la risposta intera in memoria per 24 h, due job per un mining | un job per richiesta, diagnostica limitata a 200 voci per tipo, oltre 16 MiB `result_too_large` |
| Limite della memoria del runtime Go | nessuno: l'heap può crescere al doppio dei dati vivi | `GOMEMLIMIT` all'85 % del limite del cgroup, oppure di `MemTotal` (in un LXC il cgroup dice `max` e lxcfs riporta il limite in `/proc/meminfo`) |
| Segmenti del filtro di Bloom di keyguard | uno nuovo ogni `capacity` **inserimenti**: i token ripetuti in ogni batch dell'outbox contano di nuovo | un token già presente non si aggiunge: i segmenti seguono i token distinti |
| Elenco `applied` di un avanzamento del clock del mock | senza limite (un anno di una regola batch ogni minuto ≈ 52 M effetti, GB di JSON) | i primi 1 000 più `applied_total` e `applied_truncated` (control-api) |
| Journal del mock pieno | ogni richiesta copiava 10 000 puntatori | rimozione in O(1) |
| Log delle consegne dei webhook | mai cancellato | le consegne concluse oltre 30 giorni si cancellano ogni ora |
| Rate limiter dell'API, tabella piena (100 000 client) | una scansione completa per ogni client nuovo | al più una scansione al secondo |
| Pool delle connessioni SQLite | 2 connessioni inattive: le richieste parallele di una pagina riaprono connessioni (pragma e cache fredda) | 8 inattive, nessun tetto alle aperte (un tetto potrebbe bloccare una richiesta che tiene un risultato aperto) |

### 4.4 Operazioni lunghe e `write_timeout`

Il listener di amministrazione chiude le connessioni dopo `admin.http.write_timeout` (30 s). Mining, archetipi, mondo, pacchetto ed export giravano dentro la richiesta. Con 10 M eventi durano minuti: l'utente vedeva un errore di rete (`tls: bad record MAC` nel banco) mentre il lavoro andava avanti. **Corretto** (admin-api 1.9.0). Queste operazioni si attendono al più ~20 s. Le operazioni brevi rispondono come prima; quelle lunghe rispondono con il `Job` `running`, che la UI segue su `GET /api/v1/jobs/{job_id}`. Il lavoro non si interrompe se il client chiude la connessione.

### 4.5 Contesa sul writer unico di SQLite

Dopo l'unione con il ciclo di vita dei dati la purge conta prima gli eventi nelle sintesi (rollup) e non cancella oltre il loro cursore; ogni pezzo sottrae anche gli aggregati nella stessa transazione. Il recupero dei rollup arretrati e il backfill degli aggregati seguono la stessa regola delle pause (a `ci`, con 300 000 eventi da sintetizzare in una volta, il blocco del writer era salito a 4,35 s; con le pause torna a 50 ms).

La purge cancellava 5 000 eventi (più 4 indici) per transazione senza pause, e la partizione oraria dei token in una sola transazione (centinaia di migliaia di righe). Il writer dell'intake, che trovava il lock occupato, aspettava con back-off fino a 100 ms tra un tentativo e l'altro, e la transazione successiva della purge lo anticipava. Risultato misurato: blocco del writer fino a 4,95 s, coda piena (50 000) e 113 100 eventi respinti con contropressione, cioè scartati dalle sorgenti. **Corretto**: 1 000 eventi e 5 000 token per transazione. Ogni pezzo è seguito da una pausa lunga quanto il pezzo stesso, quindi la purge usa al più metà del tempo del writer. Lo stesso vale per il recupero dello spazio (`incremental_vacuum` a passi di 1 000 pagine). La purge dura di più, ma è un job in background con avanzamento: 609 s invece di 439 s per 2 M eventi. In cambio il writer resta bloccato al più 540 ms invece di 4,95 s e nessun evento viene respinto.

Sotto carico, anche il recapito dell'outbox a keyguard (`DELETE FROM intake_outbox WHERE id = ?`) subisce la contesa: 40 ms a riga in media durante la purge di `ci`. Non perde dati (consegna almeno una volta).

### 4.6 Ingestione e dimensione del database

Il writer passa da 13 400 ev/s su 300 000 eventi a 5 200 ev/s su 10 M (raffica, portatile). Gli indici `intake_events_trace` e `intake_events_subject` hanno chiavi casuali: oltre la cache del writer (64 MB) ogni inserimento tocca una pagina a caso. Va tenuto presente nel dimensionamento: i ~4 000 ev/s del core di prova sono misurati su un database piccolo (§3.6, OPERATIONS §2).

### 4.7 Goroutine, ticker, WAL

Nessuna goroutine per richiesta senza limite; ogni ticker è fermato. Le nuove goroutine:

- i worker dei webhook, uno per webhook e al più uno alla volta;
- i job lunghi, uno per richiesta, che finisce con il lavoro.

Il WAL del writer fa checkpoint ogni 8 000 pagine. La purge e il recupero dello spazio fanno `wal_checkpoint(TRUNCATE)` alla fine. Con letture lunghe in corso (un export) il checkpoint può slittare: il WAL va sorvegliato (OPERATIONS §8).

### 4.8 UI

- **Polling.** La pagina Pubblicazioni ricaricava lista e dettaglio ogni 900 ms, anche con la scheda nascosta. Con un endpoint più lento dell'intervallo le richieste si accavallavano e i dati non si aggiornavano più. **Corretto**: una richiesta alla volta, ripetuta un secondo dopo la risposta, sospesa con la scheda nascosta; la lista si ricarica una volta, quando arriva il verdetto.
- **Richieste duplicate.** La stessa pagina chiedeva più volte `/hosts`, `/services` e `/gaps` (servizi, suggerimento sugli host nuovi, palette dei comandi). **Corretto**: le GET identiche in corso condividono una richiesta (ogni chiamante riceve una propria copia).
- **Retry dei 504.** Una richiesta lenta interrotta da un proxy si ripeteva tre volte: **corretto**, il 504 non si ripete più.
- **Tabelle.** Ogni tasto della ricerca riordinava tutte le righe con `localeCompare` e ricostruiva il testo di ricerca di ogni riga. **Corretto**: l'ordinamento si rifà solo quando cambiano righe o ordine (chiavi calcolate una volta, un `Intl.Collator`), il testo di ricerca si calcola una volta per riga. Il conteggio delle sorgenti per servizio era quadratico: **corretto**.
- **Diff.** Il diff alloca una tabella LCS (n+1)×(m+1): con due documenti da 20 000 righe sono ~1,6 GB, e la scheda si blocca. **Corretto**: testa e coda uguali si saltano, la tabella copre solo la parte cambiata, e oltre 4 M celle il diff diventa una sostituzione.
- **Job lunghi**: mining, mondo, archetipi, pacchetto ed export seguono il job `running`.
- **Pacchetto JS**: 390 KB all'avvio (136 KB compressi). Swagger, Redoc e Scalar si caricano solo nel visualizzatore.

## 5. Cosa resta

| Priorità | Problema | Proposta |
|---|---|---|
| fatto (lavoro parallelo, unito) | `/services`, `/hosts`, `/services/{s}/ops`, `PUT /services/{s}/twin` sugli aggregati incrementali; il campione di `ops` ora senza ordinamento | `OpSummaries` con una finestra (non coperta dagli aggregati) legge ancora la riga per `min(dir)`: per un servizio c'è `OpSummariesOf` (solo indice) |
| alta | Prima inferenza dei contratti per mondo e pacchetto: ~7-8 min con 4,6 M eventi nella finestra | inferenza incrementale (accumulatori per giorno, come gli snapshot) o `SampleCap` più basso per i contratti dei pacchetti. Ora è un job in background, non più un errore |
| alta | Ingestione più lenta sui database grandi (indici a chiave casuale `trace_id`, `subject`) | `cache_size` del writer proporzionale alla memoria; valutare un indice per trace solo sugli eventi in ingresso, o una tabella trace→soggetto |
| media | Memoria del miner ~1,3 KB per evento al picco (§3.5) | tempi in ms invece di `time.Time` (32 B per evento), record dei corpi in un'arena; log a pezzi (per giorno) per non tenere tutta la finestra |
| media | Archetipi, mondo e pacchetto non hanno una finestra dalla memoria come il mining: la coda impedisce che si sommino, non che uno solo superi il limite su un host piccolo | stessa misura per evento e stessa riduzione della finestra (`world.profiles` `MaxEvents`) |
| media | Mock: sessioni senza scadenza (1 000 × journal da 10 000 voci con i corpi decodificati) | scadenza per inattività, corpi del journal come byte, budget di memoria per sessione |
| media | Quarantena dell'intake: con molte quarantene sulla stessa operazione, una passata di riscrittura e un `wal_checkpoint(TRUNCATE)` per ciascuna; i monitor in quarantena non si liberano mai | accorpare le riscritture, tenere un segnaposto al posto dei bucket |
| media | Sorgenti di Fleet mai rimosse dalla mappa in memoria; `ListSources` senza paginazione, ripetuto ogni minuto | scadenza delle sorgenti revocate e ferme; paginazione (API) |
| media | Liste senza paginazione nell'API (sorgenti, regole, pacchetti, quarantena, host) | `limit`/cursore nell'API (cambio di specifica) |
| bassa | N+1 della ricerca del soggetto per trace nell'inferenza | query a blocchi di trace |
| bassa | `world_worlds`: le colonne della lista sono dopo i blob | spostare i blob in una tabella a parte |
| bassa | UI: ricerca senza debounce nelle pagine Host, Regole e Operazioni; le due lingue caricate all'avvio | debounce di 200 ms, `import()` della lingua non attiva |

## 6. Test di regressione

Ogni correzione ha un test o un benchmark:

| Correzione | Test |
|---|---|
| finestra del mining ristretta agli eventi più recenti | `internal/miner` `TestMineClampsWindowToMaxEvents` |
| solo colonne, conteggio della finestra, riassunti di un servizio, campione per hash, purge dei token a pezzi | `internal/intake` `TestScanMetaMatchesScan`, `TestOpSummariesOfMatchesOpSummaries`, `TestNewestSince`, `TestScanSampleEvery`, `TestPurgeTokenHourChunks` |
| un webhook lento non blocca gli altri; pulizia del log delle consegne | `internal/drift` `TestSlowWebhookDoesNotBlockOthers`, `TestPruneDeliveries` |
| filtro di Bloom e token ripetuti | `internal/keyguard` `TestFilterRepeatsDoNotGrow`, `TestFilterRepeatRefreshesUpdated`, `BenchmarkFilterAddRepeats` |
| verifica parallela dell'audit | `internal/audit` `TestVerifyBlocksFindTampering`, `BenchmarkVerify` |
| job lunghi e `write_timeout`; limite di memoria | `internal/core` `TestLongJob*`, `TestSyncWaitUnderWriteTimeout`, `TestParseMemoryLimit`, `TestParseMemTotal`, `TestMemoryLimitAt`, `TestAutoMinerEvents`, `TestSizeMinerWindow` |
| coda dei lavori pesanti, mining unito, risultati limitati, memoria del log (§3.5) | `internal/core` `TestHeavyGateFIFO`, `TestHeavyGateCancel`, `TestLongJobsQueueAndJoin`, `TestLongJobResultTooLarge`, `TestLongJobOneJobPerRequest`, `TestMineResultBounded`; `internal/miner` `TestLogMemoryPerEvent`; budget `lab` di `make perf` (`-only memory`) |
| risposta dell'avanzamento del clock limitata, journal | `internal/mock` `TestAdvanceListsBoundedApplied`, `TestJournalTrimKeepsNewest` |
| rate limiter con tabella piena | `internal/server` `TestFullTableSweepsAtMostOncePerInterval`, `BenchmarkAllowFullTable` |
| diff, GET condivise, niente retry dei 504, `followJob` | `ui/src/lib/perf.test.ts` |
| tempi per endpoint e per job, memoria, stallo del writer, segmenti del Bloom, consegne veloci, throughput dell'ingestione | budget di `make perf` |
