# internal/core: composizione di tt-core

`internal/core` è la radice di composizione di `tt core` e `tt dev up`: costruisce e collega tutti i componenti
della zona B, monta le parti dell'API di amministrazione che non appartengono a un solo pacchetto e gestisce avvio,
prontezza e arresto. Il test di accettazione del prodotto (`e2e_test.go`) vive qui.

## Ordine di costruzione (`core.New`)

1. Listener admin e intake (una porta occupata fallisce prima di toccare lo stato).
2. Client di keyguard (`internal/keyguard/client`): nessuna chiave, solo l'identità TLS di tt-core (mTLS) oppure il
   socket Unix.
3. `store.Open`: il pacchetto importa tutti i pacchetti con migrazioni (audit, auth, fleet, intake, contract, drift,
   miner, world, gate/packwriter, core), quindi le migrazioni sono già registrate.
4. Audit, auth, `server.New`.
5. Fleet (`fleet.New` + `Register`) con l'adattatore `fleet.Signer` sul client di keyguard; intake (`intake.New` +
   `Mount`) con i registri di Fleet, i token reali verso keyguard (`AddTokens`) e gli allarmi di quarantena verso i
   webhook; `SetEventCounter`, `SetDiscoverySource(fleet.IntakeDiscovery(in))`.
6. Inferenza dei contratti (`contract.New` + `Mount`, con i buchi del miner), drift (`drift.New`, `Attach`, `Mount`).
7. Miner (`miner.New`): staleness verso drift, `RuleLookup`/`RuleMarker` di drift sul repository delle regole.
8. Mondi (`world.New`), pack writer (`packwriter.New`) e gate (`gate.Mount`): gli ingressi sono adattatori su
   contratti (contratti inferiti sulla finestra del miner, resi `PackSafe`, con valori osservati e sintetici
   etichettati), regole approvate, policy firmate (tutte le versioni), guasti osservati e preset di scenario.
9. API composte qui (sotto) e controlli di prontezza.

Un osservatore delle policy (`policyWatcher`) segue le versioni firmate note a Fleet e aggiorna, a ogni nuova firma,
i suggerimenti dei contratti (`Engine.SetHints(contract.PolicyHints(...))`), i domini del miner e l'elenco delle
policy usato dal gate.

Allarmi: `quarantine.opened` (intake), `kill.changed` e `keyguard.alert` (Fleet: `fleet.kill`,
`policy.admin_approval`), `source.problem` (problemi nuovi delle sorgenti, controllati ogni minuto), `keyguard.alert`
anche per ogni export di eventi. Solo tipi, conteggi e identificatori.

## Arresto e prontezza

`Core.Run` serve fino alla cancellazione del contesto, poi chiude in quest'ordine: listener (le richieste in corso
finiscono entro `admin.shutdown_timeout`), lavori in background (Fleet, fotografie, webhook, osservatore delle policy,
miner programmato, scadenza dei lavori), intake (svuota la coda), client di keyguard, database.

`GET /readyz` controlla: database, keyguard raggiungibile (`/keyguard/v1/health`, 3 s), Fleet con almeno una chiave di
firma nota, listener dell'intake in servizio.

## API composte qui

| Rotta | Ruoli | Note |
|---|---|---|
| `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}` | admin (lettura anche auditor) | `DELETE` risponde `409 use_disable`: gli utenti restano per l'audit, si disabilitano. Nessuno può togliersi `admin` o disabilitarsi |
| `POST /api/v1/exports`, `GET /api/v1/exports/{id}`, `GET …/download` | publisher (lettura anche auditor) | pacchetto pubblicato → verifica con `internal/pack` e le chiavi di keyguard → `internal/export` → zip |
| `POST /api/v1/events/export`, `GET /api/v1/events/export/{job}/download` | event-exporter | OCEL 2.0 (`miner.ExportOCEL`) o JSONL; registrato nell'audit e annunciato ai webhook; lo scarica solo chi l'ha prodotto. La rotta di scarico è un'estensione |
| `GET /api/v1/quarantine`, `POST …/{id}/resolve` | lettura operator, policy-approver, auditor; risoluzione policy-approver | `close`: un'approvazione, la riscrittura resta per sempre; `dismiss`: apre dati, servono due policy-approver distinti (`dismiss-pending` dopo il primo); con OIDC in keyguard ognuno con uno step-up legato all'elemento, verificato da tt-core |
| `GET /api/v1/hosts`, `POST /api/v1/hosts/{pattern}/twin` | operator, admin | v1.5: registro degli host outbound per dominio registrabile (`intake.Store.HostStats`, `HostLatencyP50`, servizi dichiarati dalle policy firmate, chiamanti dal registro delle sorgenti); `twin` crea una bozza di policy con un servizio `match.base` (`fleet.ProposeHostTwin`, origine `host-twin`, approvazioni normali), audit `host.twin` |
| `GET /api/v1/mocks`, `POST …/prepare`, `GET/POST/DELETE …/tokens`, `POST/DELETE …/managed[/{group}[/restart]]`, `GET …/{mock_id}/calls`, `POST/GET …/{mock_id}/commands` | lettura operator, publisher, auditor; scrittura operator | pagina Mock (`internal/mockreg`, `mock.go`): mock collegati (in memoria), token del mock (SHA-256, audit), «Prepara e avvia il mock» come lavoro `mock.prepare` con i passi in `progress` (archetipi del gruppo, mondo, pacchetto con gate e firma, rilascio, mock), mock gestiti in Kubernetes con `mock.kubernetes` (API REST in-cluster, server-side apply) |
| `GET /api/v1/mock-agent/pack`, `POST …/report` | token del mock (montaggio pubblico, nessuna sessione) | per `tt mock --console`: ultimo pacchetto pubblicato del gruppo del token, rapporto trattenuto fino a un comando o a un pacchetto nuovo |
| `GET/POST /api/v1/scenario-presets`, `PUT/DELETE …/{id}` | lettura operator, publisher, auditor; scrittura operator | salvati in `core_scenario_presets`, usati da `POST /api/v1/packs` con `scenario_presets` |
| `GET/PUT /api/v1/store/retention`, `POST /api/v1/store/purge` | admin (lettura anche auditor) | `events_days` sovrascrive `retention.events` (salvato nel database); `aggregates_days` segue `contract.keep_snapshots`; la purge per servizio non c'è ancora |
| `GET /api/v1/store/usage`, `POST /api/v1/store/maintenance`, `GET /api/v1/store/traffic` | usage admin, auditor; maintenance admin; traffic admin, operator, auditor | ciclo di vita dei dati (`internal/lifecycle`, `lifecycle.go`, [DATA_LIFECYCLE.md](../../docs/DATA_LIFECYCLE.md)): spazio per dataset, budget e soglie, ultima/prossima manutenzione; manutenzione come lavoro `store.maintenance`; serie del traffico dai rollup. `GET /api/v1/hosts?from&to` legge i rollup per i periodi vecchi |
| `GET /api/v1/keyguard/status`, `GET /api/v1/keyguard/audit` | operator, policy-approver, auditor / auditor | solo lettura, identificatori e conteggi |
| `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `GET /api/v1/version` | qualsiasi utente | un lavoro finito entro l'attesa (~20 s) risponde con lo stato finale; oltre risponde `queued` (in coda per un posto dei lavori pesanti, `heavy.go`) o `running` (`longjobs.go`); `jobs` conserva per `retention.exports` export, export di eventi, purge, mining e i lavori lunghi; la lista non porta i risultati |
| `POST /api/v1/rules/mine` | operator | **estensione**: un giro del miner subito; mentre un mining è in coda o in corso la richiesta si unisce a quel lavoro (stesso `job_id`) |

`archetypes/build` rifiuta `k_min` sotto `world.k_min` (`422`) e, se manca, usa quello della configurazione;
`POST /api/v1/packs` senza `valid_days` usa `gate.valid_days`.

## Configurazione

Le chiavi nuove (`keyguard`, `fleet`, `contract`, `drift`, `miner`, `world`, `gate`, `retention`) sono descritte con i
default in [`deploy/examples/core.production.yaml`](../../deploy/examples/core.production.yaml). In breve:
`keyguard.url` è obbligatorio (`https://` con certificato client e CA o pin del server, oppure `unix:///percorso`
assoluto); l'intake è attivo di default su `127.0.0.1:4318` con certificato gestito da Fleet; fuori dal loopback serve
`fleet.public_url`; tutte le soglie k valgono almeno 2 e `world.k_min ≥ gate.k_min`; i rilevatori di PII del gate non
si possono spegnere; i webhook non hanno destinazioni finché `drift.webhook_allow` è vuoto.

## Prova locale e primo avvio

- `tt dev up`: keyguard nello stesso processo su socket Unix (chiavi generate in `<dir>/keys`, 0600), tt-core con
  certificato autofirmato su loopback, URL, file della chiave HMAC per le sorgenti e token di setup stampati sulla
  console. Non è una disposizione di produzione.
- `tt core init`: scrive una configurazione (0600, mai sovrascritta) e crea la cartella dei dati. Il token di setup lo
  stampa `tt core` al primo avvio: `internal/auth` lo rigenera a ogni avvio finché non viene usato, quindi uno stampato
  da `init` sarebbe già scaduto.

## Test di accettazione

`go test ./internal/core -run TestProductEndToEnd -v` (circa 4 s, 40 s con `-race`): keyguard reale in processo,
tt-core reale; setup dell'amministratore e del gruppo di lavoro tramite l'API; gruppo, token, policy iniziale e policy
demo approvate dall'amministratore con motivazione; sorgente `internal/sourceclient` iscritta con il token e in mTLS;
una settimana simulata del negozio demo (`internal/core/demosim`, orologio virtuale) sanificata alla sorgente;
fotografie dei contratti, mining, approvazione delle regole, archetipi, mondo, pacchetto firmato e pubblicato,
`pack.Load`, `internal/mock` con ordini, avanzamento dell'orologio e stati delle spedizioni; export WireMock, Microcks,
Prism; export OCEL; quarantena aperta e tolta da due approvatori; arresto ordinato.
