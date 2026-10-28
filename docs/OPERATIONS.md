# traffic-twin — Guida operativa

Per chi installa e gestisce traffic-twin: come disporre i componenti, quanto dimensionarli, cosa serve agli SDK, come fare backup, cosa controllare prima di andare in produzione. Chi vuole solo provarlo parte da [GETTING_STARTED.md](GETTING_STARTED.md); gli sviluppatori che usano la console installata hanno il [manuale utente](USER_GUIDE.md) (da dare loro insieme al kit: CLI `tt`, pacchetto dell'SDK, CA aziendale, file della chiave HMAC; vedi anche la pagina della console *Aiuto > Chiavi HMAC*). L'architettura è in [ARCHITECTURE.md](ARCHITECTURE.md), il modello delle minacce in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Topologie di installazione

| Topologia | Quando | Come |
|---|---|---|
| **Sviluppo, un solo host** | prova, demo, sviluppo di traffic-twin | `tt dev up` |
| **Produzione, host separati** | installazione vera | `tt keyguard` su un host dedicato + `tt core -config core.yaml` |
| **Kubernetes** | cluster | chart Helm in [`deploy/helm/`](../deploy/README.md) |

### 1.1 Sviluppo: `tt dev up`

```sh
make build
./bin/tt dev up            # chiavi e database in ./tt-dev
```

Avvia nello stesso processo keyguard (socket Unix, chiavi generate in `tt-dev/keys`) e `tt-core` su **loopback** con TLS autofirmato. Stampa l'URL della UI (`https://127.0.0.1:7070`), l'URL dell'intake (`https://localhost:4318`), il file della chiave HMAC per le sorgenti e il token monouso per creare il primo amministratore. **Non è una disposizione di produzione**: keyguard condivide l'host, quindi chi legge il disco legge anche le chiavi. Rifiuta di ascoltare fuori dal loopback.

### 1.2 Produzione: tt-core e keyguard separati

```
sorgenti (SDK, tt-egress, OBI) ──mTLS──▶ tt-core (intake :4318, UI/API :7443)
                                           │ mTLS, API minimale, certificati fissati (pin)
                                           ▼
                                        tt keyguard (altro host / pod / namespace)
```

1. Su un host **dedicato** (accessibile solo a chi gestisce le chiavi): genera le chiavi con `tt keyguard genkey` (`-type hmac`, `-type ed25519` per policy e per pacchetti), poi avvia `tt keyguard` con le variabili `TT_KEYGUARD_*` ([`deploy/examples/keyguard.production.env`](../deploy/examples/keyguard.production.env)).
2. Sull'host di tt-core: `tt core init -dir /var/lib/tt -keyguard-url https://keyguard.interno:7443 -public-url https://tt-core.interno:4318` scrive una configurazione di partenza; completala con [`deploy/examples/core.production.yaml`](../deploy/examples/core.production.yaml) (pin di keyguard, certificato client, TLS dell'amministrazione).
3. `tt core -config /var/lib/tt/core.yaml`. Al primo avvio scrive il token monouso in `setup-token` nella cartella dati (modo 0600): leggilo sull'host, crea l'amministratore dalla UI, **cancella il file**.

Note:

- **Un solo tt-core per keyguard (v1).** Keyguard rifiuta di firmare una policy con sequenza non maggiore dell'ultima (protezione dal rollback): un secondo core sulla stessa keyguard riceve `409 keyguard_state_conflict`. Ogni core, anche quello di un collaudo di carico, ha la sua keyguard.
- **Un solo processo scrittore** (SQLite): niente repliche di tt-core. Per la disponibilità si fa affidamento su riavvio rapido e backup (§7); le sorgenti ripetono l'invio e scartano le code piene, mai bloccano l'app.
- Senza `-config`, `tt core` usa `data/tt-core.db` **relativo alla cartella corrente**: in produzione imposta sempre `storage.path` (`tt core init` lo scrive assoluto).
- tt-core e keyguard **non fanno chiamate in uscita** verso Internet; l'unica eccezione sono i webhook in lista ammessa (`drift.webhook_allow`).

### 1.3 Kubernetes (Helm)

Chart per tt-core, tt-keyguard (namespace separato), tt-egress, tt-mock (CI) e tt-injector (webhook che aggiunge l'SDK ai pod annotati): [`deploy/README.md`](../deploy/README.md) descrive ordine di installazione, segreti (le chiavi non passano mai dai `values`), NetworkPolicy e le garanzie dei pod. In breve: `kubectl create` dei segreti, `helm install tt-keyguard`, poi `helm install tt-core`, poi le sorgenti. Una replica per tt-core e per keyguard, ciascuna con PVC (usa una StorageClass cifrata).

## 2. Dimensionamento

Misure su un deployment multi-host di prova (core in un container da 4 vCPU, un tt-core di prova più una keyguard dedicata; [PERFORMANCE.md](PERFORMANCE.md) §3.6):

| Voce | Valore |
|---|---|
| **Intake sostenuto** | circa **4 000 eventi/s per tt-core**, senza perdite (un solo scrittore SQLite; ~78 % di un core, RSS di picco ~300 MiB). A 8 000 ev/s l'intake risponde con contropressione e le sorgenti scartano gli eventi più vecchi |
| Carico leggero | ~25 ev/s: ~2 % di un core, ~50 MiB di RSS per tt-core, ~55 MiB per keyguard |
| **Disco** | circa **1,7-1,9 KB per evento grezzo** (eventi sanificati, indici, token): 10 M eventi = 18,8 GB ([PERFORMANCE.md](PERFORMANCE.md) §3.3) |
| Retention | eventi grezzi `retention.events`, default **168 h (7 giorni)**, poi solo **sintesi** (rollup orari 30 giorni → giornalieri 1 anno → mensili per sempre); la manutenzione gira ogni `retention.purge_interval` ([DATA_LIFECYCLE.md](DATA_LIFECYCLE.md)) |
| Liste Servizi e Host esterni | leggono aggregati mantenuti all'ingest (tabelle `intake_agg*`), non gli eventi: rispondono in pochi millisecondi anche con milioni di eventi. Su un database creato da una versione precedente, all'avvio tt-core aggrega in background gli eventi già presenti (log `intake: aggregating the events stored before this version` e poi `aggregate backfill done`); fino ad allora le due liste usano la scansione degli eventi |
| **Ingestione su un database grande** | il writer rallenta quando gli indici superano la sua cache: sul portatile del banco 13 000-19 000 ev/s con 300 000 eventi, ~5 000 ev/s con 10 M. Su un core da 4 vCPU come quello di prova conta su **circa metà dei 4 000 ev/s** quando il database supera qualche milione di eventi |
| **Memoria del mining** | circa **1,3 KB per evento della finestra** al picco di una corsa (~0,7 KB di dati vivi, il resto è il margine del garbage collector). La finestra si dimensiona sul limite di memoria: metà del limite per posto dei lavori pesanti, a ~1,5 KB per evento (4 GiB → 1,43 M eventi, 3,5 GiB → 1,25 M); se ne ha di più si minano i più recenti (log `miner: window narrowed`). Dettagli in §2.1 |
| **Limite di memoria del processo** | tt-core legge il limite del proprio cgroup e dei genitori (`MemoryMax=`/`MemoryHigh=` di systemd, Docker, Kubernetes), poi `/proc/meminfo`, poi `GOMEMLIMIT`, e imposta il limite morbido del runtime Go all'85 %. Log all'avvio: `memory limit` (con `source`), oppure l'avviso `memory limit unknown` (§2.1) |
| **Operazioni lunghe** | mining, archetipi, mondi, pacchetti, export e snapshot oltre ~20 s rispondono con un job `running`, oppure `queued` se un altro lavoro pesante sta girando (la UI lo segue). Con 10 M eventi: mining ~30 s, archetipi ~25 s, **primo mondo ~8 min** (inferenza dei contratti della finestra), pacchetto subito dopo ~20 s |

Regola pratica per il disco: `eventi/s × 86 400 × giorni di retention.events × 1,7 KB` (eventi grezzi e indice dei token) **più** una parte quasi fissa per le sintesi e la storia, che non dipende dagli eventi al secondo ma dal numero di servizi e operazioni. Gli eventi sono scambi HTTP (ingresso **e** uscita), quindi un servizio con 50 richieste/s che fa due chiamate esterne per richiesta, campionato al 100 %, produce circa 150 ev/s.

| Traffico | Eventi/giorno | Grezzi, 7 giorni (default) | Grezzi, 48 h | Prima (30 giorni) |
|---|---|---|---|---|
| 5 ev/s | 0,43 M | ≈ 5 GB | ≈ 1,5 GB | ≈ 22 GB |
| 16 ev/s (il deployment di prova) | 1,4 M | ≈ 16 GB | **≈ 4,7 GB** | ≈ 70 GB |
| 25 ev/s | 2,2 M | ≈ 26 GB | ≈ 7,3 GB | ≈ 110 GB |
| 100 ev/s | 8,6 M | ≈ 103 GB | ≈ 29 GB | ≈ 440 GB |

Parte quasi fissa, per 20 servizi con 10 operazioni ciascuno: sintesi (rollup) ≈ 100–150 MB (30 giorni orari, un anno giornaliero, pochi MB l'anno di mesi); storia dei contratti ≈ 60 snapshot per servizio dopo la compattazione (30 giornalieri, ~20 settimanali, uno al mese), qualche decina di MB; pacchetti e mondi limitati dal numero tenuto (20 + quelli pubblicati); audit nel database limitato a 180 giorni, il resto in archivio gzip (~10–20 volte più piccolo). Dopo i primi 7 giorni **il database smette di crescere** con il traffico: cresce solo di qualche MB al mese.

Per un tetto rigido imposta `storage.max_bytes` (con un margine del 20–30 % sotto lo spazio del volume, perché la `incremental_vacuum` e il WAL hanno bisogno di respiro): sopra il 90 % la manutenzione scarta prima gli eventi grezzi oltre la finestra del miner, poi dimezza la finestra fino a `storage.min_events_retention`, e segnala con il webhook `storage.high_watermark`; l'intake non si ferma mai. Esempio, il laboratorio con 16 ev/s su un volume da 20 GB: `retention.events: 168h` e `storage.max_bytes: 14GiB` (7 giorni ≈ 16 GB non entrano: la manutenzione terrà circa 5–6 giorni e lo dirà), oppure `retention.events: 96h` per stare comodi.

```yaml
retention:
  events: 168h                  # eventi grezzi (1-365 giorni)
  purge_interval: 1h            # ogni quanto gira la manutenzione
  exports: 24h
  rollups: { hourly: 720h, daily: 8760h }        # poi mensili per sempre
  snapshots: { keep_all: 720h, weekly: 4320h }   # poi uno al mese; protetti quelli di avvisi e pacchetti pubblicati
  audit: { archive_after: 4320h, archive_dir: /var/lib/tt/audit-archive, segment_entries: 50000 }   # 0 = mai
  deliveries: 720h
  resolved_alerts: 8760h
  miner_runs: 2160h
  keep_miner_runs: 50
  packs: { keep_built: 20, unpublished: 4320h }
  worlds: { keep: 20, ttl: 720h }
  fleet: { revoked_sources: 2160h, expired_tokens: 720h, expired_certs: 720h }
  released_quarantines: 8760h
storage:
  max_bytes: 0                  # es. 20GiB; 0 = nessun budget
  high_watermark_pct: 80
  critical_watermark_pct: 90
  min_events_retention: 24h
  quotas: {}                    # es. { events: 12GiB, rollups: 1GiB }
```

Tutte le chiavi hanno un valore di default sicuro, sono validate all'avvio (un valore fuori intervallo è un errore, mai un default silenzioso) e, tranne `storage.quotas`, si possono dare anche come variabili d'ambiente (`TT_CORE_RETENTION_ROLLUPS_HOURLY=720h`, `TT_CORE_STORAGE_MAX_BYTES=20GiB`). Lo stato si vede in **Impostazioni → Dati** (spazio per dataset, conservazione, ultima e prossima manutenzione, byte restituiti) e in `GET /api/v1/store/usage`; `POST /api/v1/store/maintenance` la esegue subito.

SQLite non restituisce da solo lo spazio dopo una purge. I database **nuovi** usano `auto_vacuum=INCREMENTAL` e tt-core libera le pagine da sé. I database **creati prima** di questa modifica si convertono una volta, con tt-core fermo e spazio libero pari alla dimensione del database:

```sh
systemctl stop tt-core
tt compact -confirm-core-stopped -config /etc/tt/core.yaml     # oppure: -db /var/lib/tt/tt-core.db
systemctl start tt-core
```

Se serve più di ~4 000 ev/s, la via è campionare meno (§3) o catturare con più core separati (ognuno con la sua keyguard); partizionare l'intake non è previsto in v1.

**Regole pratiche per la memoria e per la retention** (misure in [PERFORMANCE.md](PERFORMANCE.md)):

- **RAM**: ~3 KB di limite di memoria per evento che il mining deve vedere (`miner.window`, default 7 giorni, limitata dagli eventi conservati): una corsa usa al più metà del limite, a ~1,5 KB per evento, e l'altra metà resta a intake, SQLite e margine. Con 4 GiB una corsa vede ~1,4 M eventi, cioè ~16 ev/s su 24 h o ~2,4 ev/s su 7 giorni; con più traffico il mining guarda le ore più recenti della finestra. Per vedere tutta la finestra serve più memoria (tabella in §2.1): `miner.max_events` più grande di quello che entra nel limite viene abbassato.
- **Eventi grezzi nel database**: oltre ~10 M eventi le liste restano sotto i budget, ma la prima generazione di un mondo legge tutti i corpi della finestra del miner (minuti) e l'ingestione rallenta. Una `retention.events` più corta (o `storage.max_bytes`) costa meno di un disco più grande.
- **Purge**: conta prima gli eventi nelle sintesi, poi li cancella in pezzi piccoli cedendo il writer all'intake; con 2 M eventi da cancellare dura ~10 minuti senza rifiutare eventi a 2 000 ev/s. Il recupero dello spazio a seguire funziona solo sui database incrementali (sotto).
- **Database del deployment di prova** (creato prima di `auto_vacuum=INCREMENTAL`): 4,7 GB, di cui 3,9 GB di pagine libere. Un `tt compact` una tantum lo riduce a ~0,8 GB e rende più veloci le letture.

### 2.1 Memoria e limiti

tt-core è un solo processo: intake, API, analisi. Se il kernel lo uccide per memoria (OOM) si fermano anche l'ingestione e la console. Per questo le analisi pesanti si regolano sulla memoria disponibile invece di chiederne di più:

- **un limite noto.** All'avvio tt-core cerca il limite nel cgroup del processo e dei genitori (`memory.max`, `memory.high`; cgroup v1 `memory.limit_in_bytes`), poi in `/proc/meminfo`, poi in `GOMEMLIMIT`, e prende il più piccolo. Il runtime Go riceve l'85 % come limite morbido. Il log dice da dove viene: `memory limit limit_mb=3584 source=cgroup go_soft_limit_mb=3046`. Senza limite: `memory limit unknown`, e le finestre usano i default (1 M eventi per il mining). In questo caso le analisi non si adattano;
- **un lavoro pesante alla volta** sotto 16 GiB (poi uno ogni 8 GiB, al più 4). Sono lavori pesanti mining, archetipi, mondi, pacchetti, export, export degli eventi, snapshot dei contratti e "Prepara e avvia il mock", anche quelli programmati. Gli altri aspettano in ordine con lo stato `queued` (`GET /api/v1/jobs`). Un secondo mining chiesto mentre uno è in coda o in corso si unisce a quello (stesso job);
- **la finestra del mining entra nella memoria**: metà del limite per posto, a ~1,5 KB per evento. Un `miner.max_events` più grande viene abbassato (log `miner.max_events lowered to what fits`), e si minano gli eventi più recenti.

**Systemd dentro un container LXC.** Il limite del container sta sopra il namespace dei cgroup: dentro, ogni `memory.max` vale `max`. Inoltre la unit con `ProcSubset=pid` (indurimento consigliato) non vede `/proc/meminfo`. Senza un limite nella unit, tt-core non ne trova nessuno: è il caso dell'OOM descritto in [PERFORMANCE.md](PERFORMANCE.md) §3.5. Nella unit metti quindi `MemoryMax=` a ~85-90 % della memoria del CT, lasciando il resto a sshd, journald e alla cache delle pagine:

```ini
[Service]
MemoryMax=3584M        # container da 4 GiB (test/lab/units/tt-core.service)
# MemoryHigh=3200M     # facoltativo: sopra, il kernel rallenta e recupera invece di uccidere; tt-core usa il più piccolo dei due
```

Un `GOMEMLIMIT` nell'ambiente (`Environment=GOMEMLIMIT=3000MiB`) sostituisce il limite morbido, e senza altri limiti serve anche a dimensionare le finestre (vale come l'85 % del limite). In Kubernetes basta `resources.limits.memory` (chart `tt-core`); in Docker `--memory`.

| Memoria (limite) | Eventi per corsa del mining | Traffico coperto da una corsa, finestra di 48 h | RSS di picco atteso |
|---|---|---|---|
| 1 GiB | ~360 000 | ~2 ev/s | ~0,8 GB |
| 2 GiB | ~715 000 | ~4 ev/s | ~1,2 GB |
| 3,5 GiB (container da 4 GiB con `MemoryMax=3584M`) | ~1,25 M | ~7 ev/s | ~1,9 GB |
| 4 GiB | ~1,43 M | ~8 ev/s | ~2,0 GB |
| 8 GiB | ~2,86 M | ~16 ev/s | ~3,9 GB |
| 16 GiB | ~2,86 M (2 posti: due lavori pesanti insieme) | ~16 ev/s | ~3,9 GB per lavoro |

Per memoria: circa **1,3 GB di RSS al picco per milione di eventi della finestra** (banco, eventi del negozio demo; nel deployment di prova gli eventi sono più ricchi, ~1,9 GB per milione), più ~0,3 GB per il resto di tt-core. Il core di prova, con `MemoryMax=3584M`, mina 1,25 M eventi con un picco di 2,4 GB. Con ~90 000 eventi/h sono le ultime ~14 ore delle 48 conservate. Per vedere tutta la finestra servirebbero ~8 GiB per 2,9 M eventi, e di più se il traffico cresce. In alternativa basta una `retention.events` più corta, o un campionamento più basso (§3).

## 3. Campionamento consigliato

Il campionamento è deciso per utente (stesso utente, stessa decisione) e fa parte della policy firmata (`sampling.rate`, multiplo di 0,0001).

| Situazione | Indicazione |
|---|---|
| Percorsi molto caldi (migliaia di richieste/s per processo) | **≤ 5 %** |
| Servizi a traffico basso (decine di richieste/s o meno) | si può arrivare al **100 %** |
| Servizi ad altissimo throughput | non catturare tutto con l'SDK: **`tt-egress`** davanti ai servizi esterni, oppure **OBI**, con campionamento basso |

Perché: nel deployment di prova il costo dell'SDK Node è di circa 130-250 µs per scambio **campionato**; a campionamento 0 % o 5 % il throughput di un endpoint da 70 µs resta entro il rumore o perde ~10 %, al 100 % perde 30-50 % in saturazione. Su richieste da 10 ms il peso è dell'ordine dell'1-2 % a 5 %. Parti basso (1-5 %), guarda i contatori della sorgente in **Sorgenti**, alza solo se i contratti restano troppo poveri. I numeri completi: [`sdk/node/BENCHMARKS.md`](../sdk/node/BENCHMARKS.md).

## 4. Requisiti di runtime

### 4.1 SDK

| SDK | Minimo | Note |
|---|---|---|
| Node | **≥ 20** | Il corpo delle risposte di `fetch` è visibile **solo da Node ≥ 24** (i canali `bodyChunk*` di undici mancano su 20 e su 22 recenti: l'evento riporta `trunc:size`). `framework_route` solo per Express; `node:http2` non agganciato |
| Python | **≥ 3.9** | Su 3.9 serve `TT_ENROLL_CA_FILE` (PEM della CA radice): 3.9 non sa leggere la catena TLS presentata dal server |
| Java | **≥ 17** | Anche l'agente `-javaagent` (Tomcat, Jetty, HttpClient, RestTemplate/RestClient, OkHttp); non coperti Undertow/WildFly/WebLogic/Liberty e WebFlux |
| .NET | **8** | Avvio senza codice con `DOTNET_STARTUP_HOOKS` e `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`; un `new HttpClient()` semplice dà solo metadati |
| Go | **1.25** | |
| PHP | **8.1** con **ext-sodium** | Senza sodium non si può verificare la firma della policy: l'SDK non cattura |

Tutti gli SDK sono **fail-closed**: senza policy valida firmata, chiave HMAC e primo heartbeat riuscito nel processo corrente non catturano nulla (l'app funziona normalmente). Una policy in cache non basta se tt-core è irraggiungibile all'avvio.

### 4.2 OBI (eBPF)

Opzionale, per le app che non possono montare un SDK ([`internal/obi/README.md`](../internal/obi/README.md)). Servono **Linux** e un **host privilegiato o una VM** (kernel con BTF, permesso di sonde eBPF). **Non funziona in un LXC non privilegiato**: `setrlimit(memlock)` viene rifiutato (`kernel.unprivileged_bpf_disabled=2`). Solo body JSON, pochi KB. La copertura del TLS in uscita dipende dallo stack (ARCHITECTURE §3.1): va verificata sullo stack reale prima di contarci.

### 4.3 Sorgenti sullo stesso servizio

Per una data chiamata in uscita usa o l'SDK o `tt-egress`, non entrambi: tt-core segnala `double_capture` nella Fleet quando vede la stessa chiamata catturata due volte.

## 5. Aggiornamenti

- **Cambi del sanitizer o della specifica spostano i contratti osservati.** Dopo l'aggiornamento delle sorgenti aspettati allarmi di **contract drift**, e le **regole approvate passano a `stale`** (motivo `contract-drift`): è voluto. Un revisore le riconferma in **Regole** (`POST /api/v1/rules/{id}/approve` funziona anche su una regola `stale`); finché non lo fa, il pacchetto successivo esce senza quelle regole (firmato comunque). Pianifica la riconferma nella stessa finestra dell'aggiornamento.
- **Specifica v1.5 (host esterni).** Il default è `hosts.discovery: auto`: gli host esterni non dichiarati escono come **pattern** (`host:{*}.tenant.example`, `ip:private`), non più come `host:unlisted`, e la pagina **Host esterni** li raggruppa per dominio con "gemella questo host". La modalità stretta `hosts.discovery: off` ripristina l'uscita precedente, byte per byte. Le sorgenti più vecchie continuano a emettere `host:unlisted`, che l'intake accetta; non sono conformi alla v1.5 ma non aprono dati. Aggiorna le sorgenti con calma, ma tutte lo stesso, per non avere contratti con due forme.
- **Ordine consigliato:** keyguard, poi tt-core, poi le sorgenti. Una sola replica: il riavvio interrompe per poco l'intake (le sorgenti riprovano).
- Database creati prima del `auto_vacuum` incrementale: `tt compact` (§2).
- **Ciclo di vita dei dati** ([DATA_LIFECYCLE.md](DATA_LIFECYCLE.md) §7): i default di `retention.events` e `miner.window` scendono a 7 giorni (prima 30 e 14). Alla prima manutenzione gli eventi grezzi esistenti vengono contati nelle sintesi e poi cancellati oltre i 7 giorni: se vuoi la durata di prima scrivila nella configurazione. Le voci di audit più vecchie di 180 giorni escono come archivi firmati in `retention.audit.archive_dir`: prepara lo storage WORM prima, o metti `archive_after: 0`.
- **Rotazione della chiave di firma delle policy** senza fermare le sorgenti: runbook in [`deploy/README.md`](../deploy/README.md#rotazione-della-chiave-di-firma-delle-policy) e regole in [`docs/spec/policy.md`](spec/policy.md) §3.1 (codici d'errore delle sorgenti inclusi).

## 6. Sviluppo locale con TLS

I cookie di sessione sono sempre `Secure` (e `__Host-` quando possibile). **Safari scarta i cookie `Secure` su HTTP semplice anche su loopback**: l'accesso sembra riuscire e la sessione sparisce. Non esiste un flag per spegnere `Secure`: usa `tt dev up`, che serve la UI in **HTTPS** con un certificato autofirmato su loopback (accettalo una volta nel browser). Per sviluppare tt-core stesso, `tt core` con `admin.tls.cert_file`/`key_file` (anche un certificato di `mkcert`) dà lo stesso risultato.

## 7. Backup e ripristino

| Cosa | Dove | Perché |
|---|---|---|
| **Database di tt-core** | `storage.path` (`tt-core.db` più `-wal` e `-shm`) | eventi, contratti, regole, mondi, utenti, audit. Fai una copia **coerente**: `sqlite3 tt-core.db ".backup copia.db"` a caldo, oppure a core fermo. Non copiare il solo file principale mentre gira |
| **Cartella della CA di Fleet** | `<cartella dati>/fleet-ca` (nei chart: `/data/fleet-ca`) | senza, ogni sorgente deve iscriversi di nuovo con un token nuovo |
| **Chiavi di keyguard** | file `TT_KEYGUARD_HMAC_KEYS_FILE`, `..._POLICY_SIGNING_KEY_FILE`, `..._PACK_SIGNING_KEY_FILE` | perse le chiavi HMAC, i token già emessi non si riconoscono più; perse le chiavi di firma, le sorgenti rifiutano le policy nuove |
| **Database di keyguard** | `TT_KEYGUARD_DB` | stato anti-rollback (ultima sequenza), approvazioni |
| **Archivi dell'audit** | `retention.audit.archive_dir` (default `<cartella dati>/audit-archive`) e `audit-archive.key`; per keyguard `TT_KEYGUARD_AUDIT_ARCHIVE_DIR` | le voci vecchie del registro non sono più nel database: senza gli archivi la storia prima dell'ancora è persa. Su storage WORM, separati dagli altri backup |

**Ripristina database di tt-core e di keyguard dallo stesso istante.** Se tt-core torna indietro e keyguard no, tt-core propone sequenze che keyguard ha già superato e le firme sono rifiutate (`keyguard_state_conflict`).

**Cosa non deve mai stare nello stesso insieme di backup:** le **chiavi HMAC di keyguard** insieme al **database di tt-core** (o a un export di eventi). Chi ha entrambi può fare un attacco a dizionario sui token `tk1:` e risalire ai valori reali: è proprio la separazione che il progetto garantisce (THREAT_MODEL M3). Tieni quindi i backup di keyguard (chiavi e database) in un luogo e con permessi diversi da quelli di tt-core, e mai in una copia sola con quelli. Lo stesso vale per le copie della chiave HMAC che stanno sulle sorgenti: non vanno nei backup del core. Cifra tutti i backup.

## 8. Monitoraggio

| Controllo | Come |
|---|---|
| Salute di tt-core | `GET /healthz` e `GET /readyz` sul listener di amministrazione (HTTPS) e `GET /healthz` sull'intake. È ciò che usano le sonde dei chart |
| Salute degli altri | keyguard: connessione TCP (le sue API chiedono il certificato client); tt-egress `/_tt/health`; mock `/__tt/health` (sempre pubblico) |
| Stato delle sorgenti | **Sorgenti** (Fleet): stato, ultimo heartbeat, contatori (`events_dropped_queue`, `sanitizer_errors`), `last_errors` degli ultimi minuti, `double_capture`, versioni delle chiavi di firma |
| Miner | `GET /api/v1/rules/status` e diagnostica per regola: avvisa su `state` diverso da `ok` e su regole `stale` |
| **Webhook** | allarmi di drift, `keyguard.alert`, `policy.admin_approval`, `pack.admin_approval`, concessione di ruoli sensibili, esportazioni di eventi. Destinazioni solo in `drift.webhook_allow` (nei chart: `webhooks`, che genera anche le regole di rete). Gestiti con `/api/v1/webhooks` |
| **Integrità dell'audit** | `GET /api/v1/audit/verify` (ruolo `auditor`) controlla la catena di hash: rileva modifiche, cancellazioni e inserimenti. Un troncamento delle voci più recenti si vede **solo** confrontando `head_hash` con un valore conservato **fuori** dal database: salvalo periodicamente (per esempio ogni notte) in un sistema separato e confrontalo |
| Disco | spazio libero del volume dati; `GET /api/v1/store/usage` (livello `ok`/`high`/`critical`/`over`, byte per dataset, ultima manutenzione); webhook `storage.high_watermark`; voci di audit `store.maintenance` (righe tolte, byte restituiti, gradini di scarto); dimensione del WAL |
| Archivio dell'audit | copia fuori dall'host (WORM) di ogni nuovo `audit-*.json`/`.jsonl.gz`; `tt audit verify-archive -dir … -head <last_seq>:<head_hash>` sulla copia ([DATA_LIFECYCLE.md](DATA_LIFECYCLE.md) §6) |
| Memoria e carico | log `miner: window narrowed to the newest events` (la finestra del mining non entra nella memoria: §2), `memory limit` all'avvio; per stimare il proprio hardware, `make perf PERF_SCALE=full` (dataset sintetico da 10 M eventi, ~20 GB; [PERFORMANCE.md](PERFORMANCE.md)) |

## 9. Checklist di sicurezza per la produzione

- [ ] **Approvazioni verificate con OIDC.** Imposta `TT_KEYGUARD_OIDC_*` (issuer, JWKS, audience, `ROLES_CLAIM`, `ROLE_MAPPING`) e un client "di approvazione" **dedicato** all'IdP (`auth.oidc.approval_client_id` di tt-core, redirect `/api/v1/auth/oidc/stepup/callback`; token con claim dei ruoli e `auth_time`). Senza OIDC la UI mostra `approvals_unverified`: keyguard si fida di identità e ruoli dichiarati da tt-core; è una garanzia ridotta, ammessa solo per sviluppo.
- [ ] **`TT_KEYGUARD_OPENING_APPROVALS=2`** (due persone per aprire dati). Decidi `TT_KEYGUARD_ADMIN_OVERRIDE`: con `true` un amministratore può approvare da solo, con motivo, e il fatto è tracciato (`authz.admin_override`, allarme `policy.admin_approval`); con `false` no. L'amministratore vede e fa tutto in tt-core: limita chi lo è.
- [ ] **Fase Osserva** ([policy.md](spec/policy.md) §7). Con `TT_KEYGUARD_OBSERVE_AUTO=true` (default) keyguard firma senza persone le modifiche che non aprono valori (policy di partenza, `hmac` sugli identificativi, identità automatica, finestre di scoperta ≤ 7 giorni); ogni firma è nell'audit di keyguard con `approval_mode=observe`. Con `false` ogni policy torna ad avere bisogno delle approvazioni. In tt-core `fleet.observe.enabled` (default `true`), `after` (15m), `min_events` (200) e `interval` (1m) regolano la versione Osserva automatica; `codes` (default `true`) le fa mettere `code` sui campi da stato (sanitizer.md §5.6). **Aggiornamento:** una sorgente precedente alla v1.11 rifiuta una policy con `code` e resta sulla precedente: aggiorna prima le sorgenti, oppure tieni `codes: false` finché non lo sono. Allo stesso modo `graphql` (default `true`) le fa mettere `graphql` sul documento degli endpoint GraphQL riconosciuti e sui nomi della loro introspezione (sanitizer.md §5.7): una sorgente precedente alla v1.14 rifiuta quella policy, quindi `graphql: false` finché non sono aggiornate.
- [ ] **mTLS tra core e keyguard con certificati fissati**: `TT_KEYGUARD_CLIENT_PINS` (impronta del certificato client di tt-core) in keyguard, `keyguard.server_pin` e `ca_file` in tt-core. Keyguard accetta solo tt-core.
- [ ] **Keyguard raggiungibile solo da tt-core** e senza uscita verso Internet. In Kubernetes: le NetworkPolicy dei chart (ingress di keyguard dai soli pod tt-core; egress di tt-core e keyguard senza Internet; solo DNS, keyguard e i webhook elencati).
- [ ] **Permessi dei file.** Cartella dati `0700`; chiavi di keyguard `0400`/`0600` (keyguard rifiuta file leggibili da gruppo o altri); `setup-token` cancellato dopo l'uso; stato degli SDK (`TT_STATE_DIR`) `0700` con file `0600`. Volumi e backup cifrati.
- [ ] **Token del mock** (`TT_CONTROL_TOKEN`) sempre impostato in CI, un valore casuale per esecuzione, mai nel repository. Senza, l'API di controllo `/__tt/` è aperta a chiunque raggiunga la porta (ammesso solo su loopback).
- [ ] **Pacchetti**: il mock e i test si fidano solo delle chiavi pubbliche del gate (`TT_GATE_PUBKEYS`); usa `TT_GATE_REVOKED_KIDS` quando ritiri una chiave.
- [ ] **Account locali**: se usi OIDC per le persone, valuta `auth.local.enabled: false` dopo aver creato l'amministratore; imposta `auth.session` e `auth.rate_limit` su valori adatti.
- [ ] **Webhook** solo verso host in `drift.webhook_allow`, preferibilmente HTTPS (`webhook_allow_http: false`).
- [ ] **Fleet**: token di iscrizione a scadenza breve, un token di **gruppo** per i processi che si riavviano (egress come sidecar), `fleet.key_rotation.min_confirmed: 1` salvo emergenza.
- [ ] **Backup** separati come al §7, e prova di ripristino fatta almeno una volta.
- [ ] **Audit**: `GET /api/v1/audit/verify` pianificato e `head_hash` conservato altrove.

### Cosa il gate non garantisce

I rilevatori PII del gate (`pii-detectors`, non disattivabili) sono una **seconda rete**, non la garanzia principale: questa è la policy chiusa per default applicata nel processo della sorgente. I rilevatori sono euristici e **non** garantiscono di trovare ogni forma: per esempio non riconoscono gli indirizzi IPv4 con zeri iniziali (`010.001.002.003`) e alcuni formati di telefono con separatori insoliti. Quello che non entra nella policy non arriva mai al magazzino; quello che la policy apre come valore va rivisto da chi approva, non delegato al gate.
