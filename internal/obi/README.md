# Adattatore OBI (`tt obi`)

Sorgente **opzionale** di traffic-twin per le app che non possono montare un SDK. Si appoggia a
[OpenTelemetry eBPF Instrumentation (OBI)](https://opentelemetry.io/docs/zero-code/obi/), l'ex Grafana Beyla:
OBI osserva il processo dell'app dal kernel, senza toccarne il codice, e `tt obi` trasforma quello che
OBI vede in eventi `tt.http.exchange` già sanificati.

> Solo Linux. Solo body JSON (gli altri escono come forma). Pochi KB per body. Per le app con un SDK
> disponibile resta preferibile l'SDK ([ARCHITECTURE.md](../../docs/ARCHITECTURE.md) §3.1, D2).

## Come funziona

```
 app ──(sonde eBPF)── OBI ──OTLP/JSON, solo locale──▶ tt obi ──eventi sanificati, mTLS──▶ tt-core
                       ▲                                │
                       └── file di configurazione ◀─────┘  (generato dalla policy firmata)
```

`tt obi` è un piccolo processo che sta **accanto a OBI**, sullo stesso host (o nella stessa rete di container):

1. **Si iscrive** a tt-core come sorgente di tipo `obi` (pacchetto `internal/sourceclient`, come `tt egress`):
   policy firmata, interruttore di emergenza, heartbeat, chiave HMAC locale. Senza policy valida, o con
   l'interruttore attivo, non cattura nulla e **non legge nemmeno** quello che OBI manda.
2. **Genera la configurazione di OBI** dalla policy ([primo filtro](#doppio-filtro)).
3. **Riceve le tracce OTLP di OBI** (`POST /v1/traces`, OTLP/HTTP in **JSON**, anche gzip) su un indirizzo locale.
4. **Mappa gli span HTTP** (con gli header e i body che OBI ha allegato) all'ingresso del sanitizer e
   applica `internal/sanitizer` ([secondo filtro, autorevole](#doppio-filtro)): campionamento, policy, HMAC.
5. **Esporta** i soli eventi canonici con l'esportatore della sorgente (coda limitata, ripetizioni, contatori).

Gli span grezzi non vengono mai inoltrati, salvati né scritti nei log: vivono in una coda in memoria
limitata finché un worker non li ha sanificati. Se la coda è piena lo span si scarta e si conta
(`events_dropped_queue`); chi manda gli span non aspetta mai. Un errore o un panic del sanitizer scarta lo
scambio e incrementa `sanitizer_errors`.

### Doppio filtro

| Filtro | Dove | Che cosa fa |
|---|---|---|
| **1. OBI** | configurazione generata | Header e body **esclusi di default**. Entrano negli span solo gli header che la policy nomina (più `content-type`, `content-encoding`, `content-length`, che servono al sanitizer), i body delle sole operazioni con regole sul corpo, e i campi che la policy scarta esplicitamente (`drop`) escono già oscurati (`***`). |
| **2. Sanitizer** | `tt obi` | **Autorevole.** Qualunque cosa OBI lasci passare, esce solo la forma che la policy ammette (`drop:*`, `keep:`, `tk1:`, `num:`…). Se la configurazione di OBI fosse vecchia o sbagliata, il sanitizer chiude comunque. |

Il primo filtro **può solo restringere**: serve a non far nemmeno uscire dal kernel/dal processo osservato
dati che la policy non userà. La sicurezza non dipende da lui.

## Uso

```sh
export TT_ENROLL_URL=https://tt-core.example:4318      # listener sorgenti di tt-core
export TT_ENROLL_TOKEN=tte_...                         # solo da ambiente
export TT_HMAC_KEY="k1:<base64url, almeno 32 byte>"    # o TT_HMAC_KEY_FILE

tt obi --service-name shop-api --open-ports 3000 --config-out /etc/tt-obi/obi.yaml
```

| Flag | Variabile | Default | Significato |
|---|---|---|---|
| `--enroll-url`, `--service-name` | `TT_ENROLL_URL`, `TT_SERVICE_NAME` | (obbligatori) | Iscrizione; `TT_ENROLL_TOKEN` solo da ambiente |
| `--state-dir` | `TT_STATE_DIR` | derivato | Iscrizione, chiave client, cache della policy (0600) |
| `--listen` | `TT_OBI_LISTEN` | `127.0.0.1:4318` | Ricevitore OTLP/JSON. **Tienilo su loopback o in una rete privata**: quello che riceve è traffico grezzo |
| `--config-out` | `TT_OBI_CONFIG_OUT` | — | Scrive qui la configurazione di OBI a ogni nuova policy accettata |
| `--open-ports`, `--exe-path` | `TT_OBI_OPEN_PORTS`, `TT_OBI_EXE_PATH` | — | Quale processo strumenta OBI (`discovery.instrument`) |
| `--capture-bytes` | `TT_OBI_CAPTURE_BYTES` | `8192` | Buffer HTTP di OBI (`ebpf.buffer_sizes.http`), al massimo 262144 |
| `--service-filter` | `TT_OBI_SERVICE_FILTER` | il nome iscritto | Accetta solo span con `service.name` uguale; `*` = tutti |
| `--obi-endpoint` | `TT_OBI_ENDPOINT` | `http://<listen>` | Endpoint OTLP scritto nella configurazione di OBI |
| `--log-level` | `TT_OBI_LOG_LEVEL` | `info` | |

`GET /healthz` sul ricevitore mostra stato di cattura e contatori (mai valori).

**Un ponte = un servizio.** Il nome di servizio è quello assegnato all'iscrizione, non quello che OBI deduce:
la configurazione generata dà a OBI lo stesso nome (`discovery.instrument[].name`) e il ponte scarta gli span
di altri servizi (un solo avviso nel log). Più servizi sullo stesso host = più coppie OBI + `tt obi`.

Per generare la configurazione **senza iscriversi** (revisione, CI):

```sh
tt obi config --policy policy.body.json --service-name shop-api --open-ports 3000 > obi.yaml
```

accetta il corpo compilato (`tt.policy.body/v1`) o la busta firmata; **non** verifica la firma (l'output
può solo far consegnare meno dati a OBI; il ponte in esecuzione verifica la policy che applica davvero).

### Quando cambia la policy

OBI legge la configurazione **solo all'avvio**. Quando una nuova policy viene accettata `tt obi` riscrive il
file (atomicamente) e lo scrive nel log; per applicarlo si riavvia OBI (`docker compose restart obi`,
`systemctl restart obi`). Nel frattempo il sanitizer applica già la policy nuova:

- policy che **chiude** qualcosa: OBI consegna ancora di più del necessario, il sanitizer lo scarta;
- policy che **apre** qualcosa: i nuovi campi mancano (solo forma) finché OBI non viene riavviato. Fallisce chiuso.

## Cosa genera `tt obi` per OBI

Configurazione v1 di OBI (`otel_traces_export`, `discovery`, `ebpf.payload_extraction.http.enrichment`):

- `otel_traces_export`: `protocol: http/json` (OBI esporta le tracce anche in JSON), solo `instrumentations: [http]`;
- `ebpf.buffer_sizes.http` e `payload_extraction.http.enrichment` con `default_action: {headers: exclude, body: exclude}`;
- header: `include` per i nomi in regole `headers`/`cookies` della policy (cookie → `cookie`/`set-cookie`),
  per l'header del soggetto (§11 sanitizer) e per `baggage` se `trust_baggage`; `obfuscate` esplicito per
  `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key` quando nulla li richiede;
  i nomi con caratteri jolly si escludono;
- body: `include` solo per i `METODO /template` della policy (con `{param}` → `*` e il prefisso della `base`
  per i servizi esterni) e solo per la parte (`request`/`response`) che ha regole;
  le regole di servizio o globali (per esempio `errors.body`) valgono per ogni operazione e producono un
  `include` con il jolly `/*` per quella parte;
- `obfuscate` dei percorsi JSON che la policy scarta esplicitamente (`drop`), tranne i contenitori sotto
  cui un'altra regola vuole un valore (altrimenti si distruggerebbe il campo da tenere);
- l'output è ordinato: la stessa policy dà sempre lo stesso file.

Esempio completo: [`example/`](example/) (policy della demo, `docker-compose.yml`).

## Mappatura degli span

| Sanitizer (§1) | Da dove |
|---|---|
| Direzione | `kind` SERVER → `inbound`, CLIENT → `outbound`; gli altri span (e quelli senza metodo HTTP: SQL, `CONNECT`, "in queue", "processing") si ignorano |
| Metodo, path, query | `http.request.method` (o `http.method`), `url.path` / `http.target` / `url.full`, `url.query` |
| Servizio inbound | il nome assegnato all'iscrizione |
| `url_base` outbound | `url.full`, altrimenti `url.scheme` + `server.address` + `server.port` (senza schema: porta 443 → `https`) |
| Status | `http.response.status_code` (o `http.status_code`) |
| Errore di rete | senza status, con span in errore o `error.type`: `timeout`, `refused`, `reset`, `dns`, `tls`, `other` |
| Header | `http.request.header.<nome>` / `http.response.header.<nome>` (stringa o array) |
| Body | `http.request.body.content` / `http.response.body.content` (anche `http.{request,response}.body`) |
| Lunghezza del body | `http.*.body.size` o `content-length` (vedi sotto) |
| `trace_id`, `span_id`, `parent_span_id` | dallo span (OBI scrive l'esadecimale **maiuscolo**: si porta a minuscolo; zero o malformato → assente) |
| `ts`, `latency_ms` | `startTimeUnixNano`, `end - start` |
| Template del framework | **non usato** (`http.route` di OBI non è un template di framework riconosciuto): la scelta dell'operazione passa dai template della policy |
| Campionamento | `Engine.Sample`: soggetto, poi `trace_id`, poi casuale (§12) |

La prova che la mappatura è fedele: i test confrontano, byte per byte, l'evento ottenuto da uno span con quello che
il sanitizer produce direttamente per lo stesso scambio (`bridge_test.go`, `real_test.go`).

## Cosa si perde (leggere prima di scegliere OBI)

| Limite | Effetto sull'evento |
|---|---|
| **Body più grande del buffer** (`--capture-bytes`, default 8 KiB, massimo 256 KiB) | Se la lunghezza nota (`content-length`) supera il buffer, o se il testo riempie il buffer e la lunghezza è ignota: `body: trunc:size`, `size` dalla classe nota (o `lmax`). Nessun campo del body. |
| **Body non JSON** (compresi i form) | Solo la forma: `drop:bytes:<classe>`. Con `content-type` assente o diverso, nessun albero. |
| **Body oscurato da OBI** (`***` su un `drop` della policy) | Il valore è già perso; il sanitizer vede una stringa corta e applica la sua regola (`drop`). Non è un errore. |
| **Header e cookie** | Solo quelli nominati dalla policy (più i tre di servizio). Gli altri non esistono per il sanitizer: negli eventi mancano le forme `drop:*` degli header che un SDK invece vedrebbe. |
| **Template di framework** | Non disponibile: operazioni dedotte dai template della policy; i path non in policy escono come `raw` con segmenti collassati. |
| **Soggetto e baggage** | Letti solo se l'header è nell'allowlist di OBI. Se il soggetto è in `authorization`, quell'header **entra nello span**, in locale, fino al ponte (non esce). |
| **Coerenza del campionamento in/out** | Le chiamate in uscita non ereditano la decisione dell'ingresso (gli span client terminano prima del server): ogni evento si campiona per `trace_id` (stabile per traccia) o a caso. Con campionamento per soggetto, le uscite di una richiesta in ingresso campionata possono non esserlo. |
| **TLS** | OBI aggancia le librerie TLS in-process (OpenSSL, Go `crypto/tls`, …): la copertura **dipende dal linguaggio e dalla versione**. Osservato (OBI v0.15.2): lato server, Node in HTTP e Python con OpenSSL danno body in chiaro; lato client, **Python/OpenSSL non ha dato status né body** per le chiamate in uscita (span senza status: si scartano, "niente da descrivere") e ha dato `server.port` incoerente. Verificare per ogni stack. |
| **Porta/host in uscita** | `url.full` di OBI non sempre porta la porta; `server.port` talvolta è effimera. Se host o porta non coincidono con la `base` della policy, il servizio diventa il pattern dell'host (`host:<pattern>`, sanitizer §3.5; `host:unlisted` con `hosts.discovery: off`): nessun valore esce, ma l'operazione non usa i template della base. |
| **Altre porte dello stesso processo** | OBI strumenta il **processo**: porte di debug (per esempio l'ispettore di Node su 9229) e health check producono span. Il sanitizer li riduce alla forma (`GET /{drop:str:l8}`), ma contano nella cardinalità e nelle code. Restringi con `--open-ports` e una policy senza regole globali sul body. |
| **Solo Linux** | Serve il kernel con BTF e permessi per le sonde eBPF (container `privileged` o capability mirate). Non funziona su macOS/Windows nativi. |
| **Non intercetta mai** | Nessuna CA, nessuna modifica al traffico. Nota: OBI stesso, per la propagazione del contesto, può iniettare uno script nei processi Node (messaggio `Script successfully injected` nei suoi log); è un comportamento di OBI, da valutare per la tua installazione. |

I valori restano comunque protetti dal sanitizer: i nomi delle chiavi JSON escono in chiaro (§9.3) e sono
sorvegliati dalla quarantena di cardinalità dell'intake (event.md §5.2).

## Docker Compose di esempio

[`example/docker-compose.yml`](example/docker-compose.yml): app della demo (`shop`, `carrier`, `loadgen`) +
`tt-obi` + OBI (`otel/ebpf-instrument:v0.15.2`, `pid: host`, `privileged`). OBI condivide la rete di `tt-obi`
(`network_mode: service:tt-obi`), quindi l'endpoint OTLP è `127.0.0.1:4318` e non esce dal container;
la configurazione passa per un volume. Prima: in tt-core crea il gruppo con il servizio `shop-api` e assegna la
policy [`example/policy.demo-shop.yaml`](example/policy.demo-shop.yaml) (2 approvazioni). Poi:

```sh
export TT_ENROLL_URL=https://<tt-core>:4318 TT_ENROLL_TOKEN=tte_... TT_HMAC_KEY="k1:..."
docker compose -f internal/obi/example/docker-compose.yml up --build
# dopo ogni cambio di policy:
docker compose -f internal/obi/example/docker-compose.yml restart obi
```

## Stato della verifica

Provato su **Docker Desktop per macOS** (VM linuxkit, kernel 6.12, arm64) con OBI v0.15.2, `privileged`:
le sonde si caricano e OBI funziona. Con l'app della demo (Node + `carrier` in Go, HTTP semplice) un ciclo
reale OBI → ponte → tt-core finto ha prodotto eventi `inbound` e `outbound` con token HMAC coerenti tra
ingresso e uscita (`POST /orders` → `POST /v1/shipments`), nessun valore in chiaro, `sanitizer_errors = 0`.
Si rifà con `TT_OBI_LAB=1 go test -run TestLab ./internal/obi` (vedi `lab_test.go`).

**Da fare su un host Linux reale (kernel e container runtime di produzione):**

1. `docker compose … up` come sopra contro un tt-core reale; controllare in UI "Servizi scoperti" e i contatori della sorgente `obi`.
2. Verificare le scelte che OBI non documenta, già confermate in OBI v0.15.2 sul Mac e da riconfermare sul Linux
   di produzione: nomi degli attributi del body (`http.request.body.content`, `http.response.body.content`), glob di
   `url_path_patterns` (`/orders/*` per `{id}`, `/*` per tutto il resto, anche su più segmenti), `OTEL_EBPF_CONFIG_PATH`,
   `discovery.instrument[].name`. Resta da osservare che la **Config v1** sia ancora accettata dalle versioni future
   (OBI ≥ 0.11 propone la Config v2: `file_format` + `extensions.obi`; il generatore produce la v1).
3. Un'app con TLS in uscita (Java, Python, Node) per misurare la copertura reale lato client.
4. Overhead: p50/p99 su carico (l'esportatore li riporta in heartbeat).

## Test

```sh
go test ./internal/obi/...
```

Span realistici costruiti sugli attributi documentati (`testdata/server_*.json`, `client_*.json`) e **due
batch reali** esportati da OBI v0.15.2 (`testdata/real_obi_*.json`, app inventate). Coprono: span → evento
uguale all'uscita diretta del sanitizer (in ingresso, in uscita, errore di rete, body troncato, non JSON),
ricevitore (JSON, gzip, protobuf → 415, JSON malformato senza eco del contenuto, altro servizio, interruttore),
saturazione senza blocco, panic del sanitizer, iscrizione e interruttore con il tt-core finto, e la
generazione della configurazione (deny by default, determinismo, nessun jolly oltre alle regole globali).
