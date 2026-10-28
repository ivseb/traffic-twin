# traffic-twin — Ciclo di vita dei dati

> Requisito di prodotto: «dobbiamo pensare alla rotazione dei dati per evitare di far esplodere il db e ad una sintesi. Quello che diventa inutile va eliminato o gestito in modo aggregato.»
>
> Contesto: in un deployment di prova il database di tt-core ha raggiunto **4,7 GB con soli 48 h** di eventi grezzi. Gli eventi grezzi sono di gran lunga il dato più grande e quello che perde valore più in fretta.

Questo documento elenca **ogni** struttura che cresce in tt-core, keyguard e tt-mock, quanto cresce, quanto vale nel tempo e la politica scelta. La configurazione e il dimensionamento sono in [OPERATIONS.md §2](OPERATIONS.md#2-dimensionamento); le API in [`admin-api.v1.openapi.yaml`](../api/admin-api.v1.openapi.yaml) (`/api/v1/store/*`).

## 1. Principi

1. **Grezzo breve, sintesi lunga.** Gli eventi grezzi servono al miner (dentro la sua finestra), all'inferenza dei contratti della finestra corrente, agli archetipi e all'export di eventi: restano pochi giorni (`retention.events`, default **7 giorni**). Prima di essere cancellato ogni evento è contato nelle **sintesi temporali** (rollup), che restano: orarie per 30 giorni, giornaliere per un anno, mensili per sempre.
2. **Niente sparisce in silenzio.** Ogni passo di manutenzione è registrato nell'audit (`store.maintenance`, con i conteggi), visibile in `/api/v1/jobs/{id}`, in **Impostazioni → Dati** e in `/api/v1/store/usage`. Il registro di audit non si cancella mai: i suoi segmenti vecchi diventano **archivi firmati e verificabili**.
3. **Mai bloccare l'ingestione.** Sopra la soglia critica del budget la manutenzione scarta prima i dati meno preziosi; se non basta, segnala (`storage.high_watermark` con livello `over`, UI in rosso) ma l'intake continua ad accettare eventi.
4. **Cancellazioni a piccoli blocchi.** Ogni politica cancella in transazioni brevi (da 200 a 5 000 righe), poi la `incremental_vacuum` restituisce le pagine al file system qualche migliaio alla volta: l'intake, l'unico scrittore, non resta mai fermo a lungo.
5. **Idempotente e sicuro ai riavvii.** Ogni passo riparte da dove si era fermato (cursori nel database, stati `exported → pruned` per l'audit); rieseguire la manutenzione non fa danni.

## 2. Il lavoro di manutenzione

`internal/lifecycle` esegue, ogni `retention.purge_interval` (default 1 h) o su richiesta (`POST /api/v1/store/maintenance`, ruolo admin), un **lavoro** `store.maintenance`:

1. le politiche dei dataset, in quest'ordine: eventi (rollup e purge), rollup (compattazione), indice dei token, aggregati, sketch e quarantene, consegne dei webhook, avvisi di drift, snapshot dei contratti, miner, pacchetti, mondi, Fleet, sessioni, audit (archivio), export;
2. la restituzione dello spazio (`PRAGMA incremental_vacuum` a passi, poi checkpoint del WAL);
3. la **misura per dataset** (tabella virtuale `dbstat`: pagine di ogni tabella e dei suoi indici; legge tutto il file, per questo gira solo in background) e dei file fuori dal database (archivio dell'audit, export);
4. il **budget**: livello `ok`, `high` (≥ `storage.high_watermark_pct`, 80 %), `critical` (≥ `storage.critical_watermark_pct`, 90 %), `over` (oltre il budget anche dopo lo scarto); le quote per dataset (`storage.quotas`);
5. lo **scarto** (sezione 5) se il livello è critico o un dataset scartabile è oltre la quota;
6. il resoconto: riga in `lifecycle_runs` (le ultime 200), voce di audit `store.maintenance`, webhook `storage.high_watermark` se il livello cambia o qualcosa è stato scartato.

Il progresso (`{phase, done, total}`) e il resoconto completo sono in `GET /api/v1/jobs/{job_id}`; un solo lavoro alla volta (`409 maintenance_running`).

## 3. Sintesi temporali (rollup)

Schema intake v3 (`internal/intake/rollup.go`). Tre tabelle, per **tempo dell'evento**:

| Tabella | Chiave | Valori | A cosa serve |
|---|---|---|---|
| `intake_rollup` | (livello, bucket, servizio, op, status, direzione) | chiamate, somma e massimo della latenza, primo e ultimo istante | storico dei contratti, grafici del traffico (`/api/v1/store/traffic`) |
| `intake_rollup_src` | (livello, bucket, servizio, sorgente, policy, direzione) | chiamate, errori 5xx/rete, errori 4xx | registro degli host su un periodo vecchio (`/api/v1/hosts?from&to`) |
| `intake_rollup_lat` | (livello, bucket, servizio, direzione, classe di latenza) | chiamate | mediana e p95 dei periodi vecchi (4 classi per raddoppio, errore ~9 %) |

- **Livelli:** orario (bucket di un'ora) per `retention.rollups.hourly` (30 giorni), poi **giornaliero** per `retention.rollups.daily` (365 giorni), poi **mensile per sempre**. La compattazione sposta un giorno (o un mese) intero in una transazione: i totali sono identici prima e dopo. Un punto della serie porta il livello da cui viene (`tier`): chiedere passi orari su un periodo vecchio restituisce punti giornalieri o mensili.
- **Esattezza:** il rollup conta gli eventi dopo il suo cursore (`intake_agg_state.rollup_next`) a blocchi di 20 000 id per transazione. La purge **prima** fa il rollup e **non cancella mai oltre il cursore**: nessun evento esce dal database senza essere stato contato. Una riscrittura di quarantena di un evento già contato sposta la chiamata dalla vecchia (servizio, op) alla nuova nello stesso livello: un letterale messo in quarantena non sopravvive nelle sintesi.
- **Nessun valore:** solo forme (servizio, operazione, status), identificatori di sorgente e policy, conteggi e tempi; nessun token, nessun campo.
- **Gli aggregati di ingest** (`intake_agg`, `intake_agg_lat`, aggiunti per le liste servizi/host) restano diversi: descrivono **gli eventi conservati** e scendono con la purge; i rollup descrivono **tutto il traffico mai ricevuto**.
- **Dimensione:** non dipende dagli eventi al secondo ma dal numero di combinazioni (servizi × operazioni × status per ora). Con 20 servizi, 10 operazioni e 3 status: ~600 righe l'ora, in tutto **~100–150 MB** (30 giorni orari + un anno giornaliero), più qualche MB l'anno per i mesi.

Il miner lavora sugli eventi grezzi della sua finestra (`miner.window`, default 7 giorni) e salva solo l'evidenza delle regole (conteggi, confidenza): per questo la finestra del miner dovrebbe stare dentro `retention.events` (tt-core avvisa nel log se non è così).

## 4. Inventario

Legenda: **crescita** per il traffico (ev = eventi ricevuti), **valore** nel tempo, **politica** scelta. Le dimensioni sono ordini di grandezza misurati o stimati.

### 4.1 tt-core — intake

| Dati | Tabelle | Crescita | Valore nel tempo | Politica |
|---|---|---|---|---|
| Eventi grezzi | `intake_events`, `intake_fields` | ~1,7 KB/ev (con gli indici); la parte più grande | alto per giorni (miner, contratti correnti, archetipi, export), poi nullo: la sintesi basta | `retention.events` (7 giorni), purge a blocchi da 5 000 dopo il rollup; scarto fino alla finestra del miner e poi fino a `storage.min_events_retention` (24 h) sotto pressione |
| Indice dei token | `intake_tokens` (partizioni orarie) | proporzionale ai token per evento | solo con gli eventi | cancellato per ora intera insieme agli eventi |
| Outbox verso keyguard | `intake_outbox` | piccolo; cresce solo se keyguard è irraggiungibile | finché non è consegnato | riga cancellata alla consegna (at-least-once); visibile nel dataset `tokens` |
| Aggregati di ingest | `intake_agg*`, `intake_source_counts` | combinazioni, non eventi | quanto gli eventi conservati | esatti: sottratti dalla purge |
| Sintesi temporali | `intake_rollup*` | combinazioni per ora | alto per sempre (storia) | orarie 30 giorni → giornaliere 365 giorni → mensili per sempre |
| Sketch HLL (cardinalità) | `intake_sketch` (`kind` ≠ discovery) | un bucket al giorno per monitor | quanto la finestra degli eventi | cancellati con la purge (giorni più vecchi della retention) |
| Sketch di discovery | `intake_sketch` (`kind` = discovery) | uno per campo osservato | finché la policy è in discovery | limitati da `MaxMonitors` (200 000); restano |
| Quarantene | `intake_quarantine` | rare | aperte/chiuse sempre; rilasciate solo come storia | rilasciate tolte dopo `retention.released_quarantines` (365 giorni); le approvazioni restano nell'audit |

### 4.2 tt-core — analisi e pubblicazione

| Dati | Tabelle | Crescita | Valore nel tempo | Politica |
|---|---|---|---|---|
| Snapshot dei contratti (+ conteggi delle differenze) | `contract_snapshots` | uno per servizio per finestra (un giorno), modello gzip | alto di recente, poi «com'era a ottobre» | tutti per `retention.snapshots.keep_all` (30 giorni), poi uno a settimana fino a `weekly` (180 giorni), poi uno al mese; **sempre** l'ultimo, quelli citati da avvisi di drift e la base contrattuale dei pacchetti pubblicati; `contract.keep_snapshots` resta il tetto (che salta anch'esso i protetti) |
| Avvisi di drift | `drift_alerts` | pochi al giorno | aperti: alto; risolti: storia | aperti e riconosciuti sempre; risolti tolti dopo `retention.resolved_alerts` (365 giorni) |
| Webhook (definizioni) | `drift_webhooks` | manuale | sempre | restano |
| Log delle consegne | `drift_deliveries` (con il payload) | una riga per notifica | debug di un ricevitore | consegnate/fallite tolte dopo `retention.deliveries` (30 giorni); le pendenti mai |
| Regole del miner (con lo storico delle modifiche) | `miner_rules` | per firma di regola, non per evento | alto; le rifiutate evitano di riproporre lo stesso candidato | restano (sono l'evidenza persistita: conteggi e confidenza) |
| Esecuzioni del miner e diagnostica | `miner_runs` | una per run (ogni 6 h), diagnostica fino a centinaia di KB | le ultime | tolte dopo `retention.miner_runs` (90 giorni), le ultime `keep_miner_runs` (50) restano |
| Archetipi | `world_builds` | una per build | quelle usate dai mondi | restano quelle citate da un mondo rimasto e le ultime 10 |
| Mondi | `world_worlds` (mondo e record sintetici) | uno per generazione, MB | quelli dei pacchetti | sempre quelli citati da un pacchetto; altrimenti gli ultimi `retention.worlds.keep` (20) o più giovani di `ttl` (30 giorni) |
| Pacchetti | `packwriter_packs` (manifest, report, **archivio**, firma) | uno per build, MB | pubblicati: per sempre; non pubblicati: poco | pubblicati interi per sempre; non pubblicati: archivio tenuto per gli ultimi `keep_built` (20) e finché non scadono (`not_after`), poi tolto (pubblicarli risponde `410 pack_pruned`: ricostruire); righe non pubblicate tolte dopo `unpublished` (180 giorni) |
| File di export ed export di eventi | `<dati>/exports` | uno per richiesta | ore | `retention.exports` (24 h), file e lavoro tolti insieme (esistente) |
| Registro dei lavori | in memoria | uno per lavoro | ore | `retention.exports` (esistente) |
| Registro di audit (catena di hash) | `audit_entries`, `audit_segments` | ogni azione amministrativa, ogni manutenzione | legale/forense: per sempre, ma non nel database caldo | **archivio a segmenti** (sezione 6) dopo `retention.audit.archive_after` (180 giorni); mai cancellato in silenzio |
| Utenti e ruoli | `auth_users`, `auth_user_roles` | manuale | sempre (l'audit li cita) | restano (si disabilitano, non si cancellano) |
| Sessioni, stati OIDC, token di setup | `auth_sessions`, `auth_oidc_states`, `auth_setup` | uno per login | fino alla scadenza | scaduti tolti (janitor ogni 5 min e manutenzione) |
| Sorgenti di Fleet | `fleet_sources` | una per iscrizione | attive: alto; revocate: storia | revocate e non viste da `retention.fleet.revoked_sources` (90 giorni) **archiviate**: voce di audit `fleet.source.archive` con identità e date, poi riga e certificati tolti |
| Certificati client | `fleet_certs` | uno per rinnovo (ogni `client_cert_ttl`) | fino alla scadenza | scaduti da `expired_certs` (30 giorni) tolti |
| Token di enrollment | `fleet_tokens` | manuale | fino alla scadenza | scaduti o revocati da `expired_tokens` (30 giorni) e non usati da sorgenti rimaste tolti |
| Versioni delle policy | `fleet_policy_versions`, `fleet_policy_approvals`, `fleet_signing_keys` | per proposta | ogni versione firmata può essere citata da eventi, pacchetti e dal log di keyguard | restano (piccole) |
| Impostazioni, preset, approvazioni di quarantena | `core_*` | manuale | sempre | restano |
| Registro della manutenzione | `lifecycle_runs`, `lifecycle_state` | una riga per run | le ultime | le ultime 200 |

### 4.3 keyguard

| Dati | Tabelle | Crescita | Valore nel tempo | Politica |
|---|---|---|---|---|
| Audit (stessa catena di tt-core) | `audit_entries`, `audit_segments` | una voce per firma, match, consegna di token (ogni pochi secondi sotto traffico) | forense | archivio a segmenti dopo `TT_KEYGUARD_AUDIT_ARCHIVE_AFTER` (180 giorni) in `TT_KEYGUARD_AUDIT_ARCHIVE_DIR` (default `audit-archive` accanto al database); `0` lo disattiva |
| Registro delle firme e approvazioni | `kg_signed`, `kg_approvals` | una per firma o rinnovo di policy | custodia: per sempre | append-only, restano (trigger) |
| Impronte dei token di approvazione | `kg_token_fps` | una per approvazione OIDC | solo finché un token potrebbe essere riusato (età massima 10 min + scarto d'orologio) | tolte 7 giorni dopo l'uso (`FingerprintMargin`), ogni ora |
| Filtri di Bloom | `kg_bloom` (snapshot), `kg_bloom_journal` | per epoca e chiave | quanto i token reali possono comparire | filtri non aggiornati da `TT_KEYGUARD_FILTER_RETENTION` (90 giorni) tolti; il journal è riassorbito a ogni snapshot (esistente) |
| Stato | `kg_state` | costante | sempre | resta |

### 4.4 tt-mock (in memoria)

| Dati | Crescita | Politica |
|---|---|---|
| Sessioni | una per `POST /__tt/sessions` | massimo `--max-sessions` (1000); **nuovo:** le sessioni (tranne `default`) inattive da `--session-idle-ttl` (24 h) sono tolte, anche al momento di crearne una nuova al limite |
| Journal per sessione | una voce per chiamata (corpi fino a 64 KiB) | ultime `--journal-max` (10 000) voci **e**, nuovo, al massimo `--journal-max-bytes` (32 MiB) per sessione: le più vecchie escono prima, l'ultima resta sempre |
| Entità della sessione | create dalle chiamate | tolte con la sessione o con il reset |

## 5. Budget e guard rail

```yaml
storage:
  path: /var/lib/tt/tt-core.db
  max_bytes: 20GiB              # 0 = nessun budget
  high_watermark_pct: 80        # webhook storage.high_watermark, UI in giallo
  critical_watermark_pct: 90    # scarto
  min_events_retention: 24h     # sotto non si scende mai
  quotas:                       # facoltative, per dataset (nomi in config.Datasets)
    events: 12GiB
    rollups: 1GiB
```

- **Cosa si misura:** `file + WAL − pagine libere`. Su un database vecchio (senza `auto_vacuum` incrementale) le pagine liberate restano nel file ma vengono riusate, quindi contano come spazio disponibile; la UI suggerisce `tt compact`.
- **Ordine dello scarto** (dal meno al più prezioso), un gradino alla volta finché il livello torna sotto la soglia critica o la quota è rispettata:
  1. `events_beyond_miner_window`: eventi grezzi oltre la finestra del miner;
  2. `events_keep_<N>`: eventi grezzi dimezzando la finestra, fino a `storage.min_events_retention`;
  3. `rollups_hourly_7d`: dettaglio orario dei rollup oltre 7 giorni compattato in giorni.

  Contratti, regole, avvisi, pacchetti, mondi e audit **non si scartano mai** per il budget. Gli eventi scartati restano nelle sintesi (lo scarto passa dalla stessa purge, che fa prima il rollup).
- **Allarmi:** webhook `storage.high_watermark` (`level`, `previous`, `peak`, `used_bytes`, `max_bytes`, `used_pct`, `datasets_over_quota`, `shed`, `ingestion_active: true`) a ogni cambio di livello e a ogni scarto; voce di audit `store.maintenance` con `level` e `shed`; log `warn` (`error` se `over`).
- **Mai bloccata in silenzio:** l'intake continua ad accettare. Se anche dopo lo scarto si è oltre il budget, il livello è `over` e la UI (Impostazioni → Dati) lo dice in rosso con cosa fare (aumentare il budget, ridurre `retention.events`, campionare meno).

## 6. Audit: archivio a segmenti

Il registro di audit è append-only con catena di hash (G8). Dalla versione 2 dello schema:

1. un **segmento** è una sequenza di voci consecutive dello stesso mese (UTC), al massimo `retention.audit.segment_entries` (50 000), tutte più vecchie del limite, mai la voce di testa;
2. viene scritto in `audit-<primo>-<ultimo>.jsonl.gz` (una voce per riga, lo stesso formato di `/api/v1/audit/export`) con un manifest firmato `audit-<primo>-<ultimo>.json`: intervallo, `prev_hash` della prima voce, **head hash** (hash dell'ultima), SHA-256 del file, firma Ed25519 (`audit-archive.key` accanto al database, creata al primo uso); file e directory sincronizzati su disco, poi rinominati;
3. il segmento entra in `audit_segments` (stato `exported`) e nella catena viva viene aggiunta la voce `audit.archive` con intervallo, head hash e digest del file: la testa del log impegna l'archivio;
4. solo allora le voci escono dal database, a blocchi: un trigger rifiuta la cancellazione di qualsiasi voce non coperta da un segmento registrato, e i segmenti non si cancellano né si modificano (solo `exported → pruned`).

Un'interruzione in qualsiasi punto riprende al giro dopo (il file viene ricontrollato prima di cancellare). **Verifica:**

- `GET /api/v1/audit/verify` (ruolo auditor) controlla che i segmenti si concatenino dalla genesi e che la prima voce rimasta si agganci all'head hash dell'ultimo segmento; risponde anche `archived` e `segments`;
- `tt audit verify-archive -dir <cartella> [-key ed25519:<id>] [-head <seq>:<hash>]` controlla offline (per esempio sulla copia WORM) firme, digest e catena dentro e tra i file; con `-head` anche che l'archivio finisca dove dice l'ancora del database (`audit_archive` in `/api/v1/store/usage`).

**Conservazione degli archivi:** la chiave di firma sta sullo stesso host del database, quindi la firma prova l'integrità dei file, non l'onestà dell'host. Per questo:

- metti `retention.audit.archive_dir` su **storage WORM** (bucket con object lock in modalità compliance, oppure un mount append-only) o copia ogni nuova coppia di file fuori dall'host subito dopo la manutenzione;
- conserva fuori dal database, come già per l'head hash (OPERATIONS §8), anche l'ultimo `last_seq`/`head_hash` dell'archivio;
- tieni gli archivi per il periodo legale richiesto: tt-core non li cancella mai;
- `retention.audit.archive_after: 0` disattiva l'archivio: il registro resta intero nel database (come prima).

Lo stesso vale per keyguard (`TT_KEYGUARD_AUDIT_ARCHIVE_*`), con la sua chiave e la sua cartella.

## 7. Migrazione dei database esistenti

Le migrazioni sono automatiche all'avvio:

- **intake v3** crea le tabelle dei rollup e mette il cursore sul primo evento presente: la prima manutenzione conta gli eventi esistenti (20 000 per transazione) prima di cancellarne qualcuno;
- **audit v2** crea `audit_segments` e sostituisce il trigger di cancellazione;
- **lifecycle v1** crea il registro della manutenzione.

Cosa cambia all'aggiornamento:

- il default di `retention.events` passa da 30 a **7 giorni** e quello di `miner.window` da 14 a **7 giorni**: un'installazione senza valori espliciti cancella alla prima manutenzione gli eventi grezzi oltre 7 giorni (dopo averli sintetizzati). Per tenere la vecchia durata scrivi `retention.events: 720h` nella configurazione (o usa Impostazioni → Dati);
- un database creato prima di `auto_vacuum` incrementale non si riduce da solo: fermare tt-core ed eseguire una volta `tt compact` (OPERATIONS §2);
- le voci di audit più vecchie di 180 giorni cominciano a uscire in archivi: prepara la cartella WORM **prima** dell'aggiornamento, o metti `retention.audit.archive_after: 0`.

## 8. Test

- `internal/intake/rollup_test.go`: rollup uguale agli eventi grezzi, purge che conta prima di cancellare, compattazione oraria → giornaliera → mensile con totali invariati, riscrittura di quarantena che non lascia letterali nelle sintesi;
- `internal/audit/archive_test.go`: segmenti per mese, verifica attraverso l'archivio, ripresa di una cancellazione interrotta, manomissioni e buchi rilevati;
- `internal/contract/retention_test.go`, `internal/lifecycle/lifecycle_test.go`, `internal/keyguard/retention_test.go`, `internal/mock/lifecycle_test.go`;
- `internal/core/lifecycle_test.go` (integrazione): quattro mesi di traffico con orologio virtuale su un tt-core vero; il database resta nel budget, i rollup danno i numeri degli eventi grezzi prima e dopo la loro cancellazione, contratti/drift/host rispondono sui periodi vecchi, un picco di traffico viene scartato oltre la finestra del miner senza fermare nulla, `audit/verify` e `tt audit verify-archive` passano attraverso i segmenti archiviati.
