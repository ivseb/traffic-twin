# Laboratorio multi-host

Un deployment **multi-host reale**, come in produzione, e uno script che ne dimostra il funzionamento dall'inizio alla fine.
Servono tre host Linux (VM, container o macchine fisiche; Debian 12 o simile con systemd) raggiungibili in SSH dalla macchina
dell'operatore, con un utente che abbia i diritti di root (installa utenti di sistema, unit systemd e pacchetti). L'host della
demo ha bisogno anche di Docker con il plugin `compose`.

```
 demo      LAB_HOST_DEMO       Docker: loadgen -> shop (Node + SDK) -> tt-egress -> carrier
                               systemd: tt-mock (:8480)      Docker: WireMock (:8089, a richiesta)
 keyguard  LAB_HOST_KEYGUARD   systemd: tt keyguard (mTLS :7443, accetta solo tt-core)
 core      LAB_HOST_CORE       systemd: tt core (admin+UI https :7443, intake mTLS :4318)
```

## Configurazione

Tutto si imposta con variabili d'ambiente; i valori predefiniti sono segnaposto di documentazione e vanno sostituiti.

| Variabile | Default | Cosa |
|---|---|---|
| `LAB_HOST_DEMO` | `demo.lab.example` | host della demo (nome DNS o indirizzo IPv4) |
| `LAB_HOST_KEYGUARD` | `keyguard.lab.example` | host di keyguard |
| `LAB_HOST_CORE` | `core.lab.example` | host di tt-core |
| `LAB_CORE_ALLOW_IP` | `192.0.2.12` | indirizzo IP (o prefisso) di tt-core, l'unico che la unit di keyguard lascia entrare (`IPAddressAllow=`) |
| `LAB_SSH_USER` | `root` | utente SSH sugli host |
| `LAB_SSH_JUMP` | (vuoto) | host di salto facoltativo (`ssh -J`), per esempio `ops@bastion.lab.example` |
| `LAB_KNOWN_HOSTS` | `~/.ssh/known_hosts_tt_lab` | file `known_hosts` dedicato al laboratorio |
| `LAB_STATE` | `test/lab/.state` | stato locale: CA del laboratorio, binari, file di lavoro (ignorato da Git) |

Esempio:

```sh
export LAB_HOST_DEMO=192.0.2.10 LAB_HOST_KEYGUARD=192.0.2.11 LAB_HOST_CORE=192.0.2.12 LAB_CORE_ALLOW_IP=192.0.2.12
```

| Cosa | Dove |
|---|---|
| UI e API admin | `https://$LAB_HOST_CORE:7443` (certificato firmato dalla CA del laboratorio: `test/lab/.state/pki/lab-ca.crt`) |
| Demo shop (con SDK) | `http://$LAB_HOST_DEMO:3000` |
| Mock `tt mock` con l'ultimo pacchetto | `http://$LAB_HOST_DEMO:8480` (controllo: `Authorization: Bearer` da `/etc/tt-mock/mock.env` sull'host della demo) |
| Credenziali admin e utenti | host del core, `/etc/tt-lab/credentials.env` (0600, mai stampate dagli script) |

## Sicurezza del deployment

- **keyguard**: utente di sistema `tt-keyguard`, chiavi (HMAC, firma policy, firma pacchetti, chiave TLS) generate sull'host con
  `tt keyguard genkey`, file `0400` in una cartella `0500`; accetta solo il certificato client di tt-core (pin SPKI: un altro host arriva al
  TLS e riceve `certificate required`). La unit dichiara anche `IPAddressDeny=any` + `IPAddressAllow=<tt-core>`; in un container LXC non
  privilegiato il filtro cgroup/eBPF **non viene applicato**: lì resta solo il pin mTLS.
- **core**: utente `tt-core`, chiavi TLS `0400`, configurazione `0640`, database e CA Fleet in `/var/lib/tt-core` (`0700`);
  tt-core fissa il certificato di keyguard (CA del laboratorio + pin).
- Le unit systemd (`units/`) usano `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp/Devices`, filtro delle chiamate di sistema,
  `CapabilityBoundingSet=` vuoto, ecc.
- La CA del laboratorio vive **solo** sulla macchina dell'operatore (`test/lab/.state/pki`, ignorata da Git); ogni chiave privata nasce sull'host che la usa.

## Script

| Script | Cosa fa |
|---|---|
| `deploy-infra.sh [build\|pki\|keyguard\|core\|all]` | compila `tt` (linux/amd64), crea la CA del laboratorio, installa keyguard e core con unit systemd. Idempotente. |
| `deploy-demo.sh prepare` / `up` / `restart-shop` / `down` / `status` | prepara l'host della demo (sorgenti della demo, SDK Node impacchettato con `npm pack`, immagini, `tt-mock`) e governa lo stack. |
| `put.sh <ruolo> <locale> <remoto> [modo]` | copia un file su un host (`demo`, `keyguard`, `core`). |
| `../e2e/lab-e2e.sh` | **la prova end to end** via API admin (vedi sotto). |
| `../e2e/lab-api.sh` | chiamata API ad hoc come uno degli utenti del laboratorio. |
| `bench-intake.sh`, `bench-overhead.sh`, `bench-sdk-node.sh`, `bench-sdk-node-own.sh` | misure (eventi/s, overhead SDK, latenza di tt-egress). Usano un tt-core e un keyguard di prova separati (`bench-core-lib.sh`) o fermano il generatore di carico per la durata della misura. |

```sh
test/lab/deploy-infra.sh all          # keyguard + core
test/lab/deploy-demo.sh prepare       # immagini, SDK, tt-mock
test/e2e/lab-e2e.sh                   # la prova (la prima volta attende > 75 min di traffico)
test/lab/bench-intake.sh              # eventi/s
test/lab/bench-sdk-node.sh 5 20       # SDK Node con oha (ferma la demo prima: deploy-demo.sh stop)
test/lab/bench-overhead.sh egress     # tt-egress
```

## Prova end to end (`test/e2e/lab-e2e.sh`)

Fasi: `bootstrap users fleet policy events hosts contracts rules world mock wiremock admin restart` (`PHASES="mock wiremock" ./test/e2e/lab-e2e.sh`
per ripeterne alcune). Admin di bootstrap con il token di setup, un utente per ruolo (`e2e_operator`, `e2e_reviewer`, `e2e_publisher`,
`e2e_approver`, `e2e_auditor`), gruppo, token di iscrizione, policy iniziale e policy della demo approvate con *admin override* e motivazione,
attesa del traffico, snapshot dei contratti, miner e approvazione delle regole, archetipi, mondo, pacchetto (gate + firma di keyguard),
pubblicazione, download, `tt mock` sull'host della demo con asserzioni (ordine → stati della spedizione con avanzamento dell'orologio,
scenario annullato, 503 forzato) ed export WireMock con il vero contenitore WireMock. Si può rilanciare: riusa utenti, gruppo, sorgenti e
policy attiva; a ogni giro rigenera pacchetto e mock. Codice di uscita 0 solo se tutte le asserzioni passano.

Il miner decide un esito solo per le cause più vecchie del suo orizzonte (≥ 1 h): anche con l'orologio accelerato della demo il traffico deve
coprire più di un'ora (`EVENTS_MIN_MINUTES`, default 75). Con un orologio accelerato il miner non trova regole batch (cerca lo stesso orario
reale su più giorni): la prova lo segnala come avviso.

## OBI

OBI (`otel/ebpf-instrument`) ha bisogno di `CAP_BPF`/`CAP_SYS_ADMIN` nel namespace iniziale del kernel: in un container LXC non privilegiato
(`kernel.unprivileged_bpf_disabled=2` sul nodo) si ferma con `failed to set memlock rlimit: operation not permitted`. Serve una VM o una
macchina fisica.
