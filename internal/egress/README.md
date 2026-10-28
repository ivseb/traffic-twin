# tt-egress: il proxy di uscita

`tt egress` è il reverse proxy per gli stack **senza SDK** (ARCHITECTURE §3.1, decisione D2). L'app non cambia codice: cambia la base URL del servizio esterno, di solito una variabile d'ambiente, da `https://api.carrier.example` a `http://tt-egress:9090/carrier`. Il proxy prosegue verso il servizio vero e cattura una copia sanificata dello scambio.

```
app ──HTTP──▶ tt-egress :9090 ──HTTPS──▶ api.carrier.example
                  │
                  └── evento sanificato ──OTLP/mTLS──▶ tt-core
```

Codice: `internal/egress` (proxy, cattura, CLI) e `internal/sourceclient` (client Fleet riusabile: iscrizione, policy, heartbeat, esportatore OTLP). Il client Fleet è pensato per essere riusato dall'SDK Go.

## Cosa fa e cosa non fa

- **Instrada** `/<alias>/...` verso la base URL configurata per l'alias. Metodo, path (anche con `%2F`), query, header, corpo e risposta passano **così come sono**. Non aggiunge header (niente `X-Forwarded-*`, `Via`, `traceparent`, `Accept-Encoding`), non decodifica le risposte, non riprova le richieste. Gli unici header non inoltrati sono quelli hop-by-hop della RFC 9110 e il membro `tt.s` del `baggage` (la spec lo impone: sanitizer §12).
- **Streaming**: i corpi non sono mai tenuti in memoria per intero. Si copiano al massimo `max_body_bytes + 1` byte (della policy) per la sanificazione, il resto si conta e basta. Le risposte con lunghezza ignota (SSE, chunked) sono inoltrate subito, senza attendere la fine.
- **TLS verso il servizio**: radici di sistema, più una CA aggiuntiva facoltativa (`--ca-file` o `ca_file` per upstream). Il certificato del servizio è sempre verificato; non esiste un'opzione "insecure". Le base URL `http://` sono ammesse per servizi dentro una rete fidata (è il caso della demo).
- **Cattura** (solo se la sorgente può catturare): campionamento come un servizio interno in ingresso (sanitizer §12: baggage `tt.s` se la policy ha un servizio `internal` con il nome assegnato all'iscrizione e `trust_baggage`; poi soggetto dall'header indicato dalla policy; poi `trace_id` da `traceparent`; poi caso). `traceparent` si **legge**, non si scrive mai. La sanificazione è asincrona, fuori dal percorso della richiesta, e produce lo stesso evento che produce `internal/sanitizer` chiamato direttamente (c'è un test che lo verifica byte per byte).
- **Fail-closed**: senza policy valida, senza chiave HMAC, senza heartbeat, con policy scaduta o interruttore di emergenza attivo, il proxy **continua a inoltrare** e non cattura nulla. L'interruttore è persistente (sopravvive al riavvio finché un heartbeat non dice il contrario).
- **Sotto carico** scarta eventi, mai richieste: coda dei lavori limitata, tetto di byte copiati in attesa, tetto di scambi in copia contemporanea, coda di esportazione limitata (10 000 eventi / 16 MiB, scarta i più vecchi). Tutto è contato nell'heartbeat (`events_dropped_queue`).
- **MITM: non implementato.** Un proxy con CA interna che legge il TLS senza cambiare le URL è un'opzione esplicita del threat model (M15), disattivata di default e fuori ambito in questa versione. `CONNECT` risponde `405`.
- Non c'è un fallback "in chiaro" verso `tt-core`: l'iscrizione e tutto il resto passano da TLS con la CA fissata dal token.

## SDK **oppure** tt-egress, per ogni chiamata in uscita

Per una data chiamata in uscita si usa **o** l'SDK **o** tt-egress, non entrambi. Se l'app ha l'SDK e chiama il servizio esterno attraverso tt-egress, l'SDK registra anche il salto verso il proxy (un servizio `host:tt-egress:9090` o `host:unlisted`, circa un quinto degli eventi dell'SDK nel laboratorio) e tt-egress registra la chiamata vera: la stessa chiamata è catturata due volte, con rumore nei contratti.

- Per evitarlo, **non** mettere l'indirizzo di tt-egress in `hosts_allow` della policy dell'SDK (gli eventi verso host non ammessi sono rifiutati dall'intake) oppure non usare l'SDK per quelle chiamate.
- Per scoprirlo, tt-core usa tre segnali (gli SDK non iniettano `traceparent`, quindi spesso le due catture non sono nella stessa traccia). Quando uno scatta, entrambe le sorgenti mostrano nella Fleet il problema `double_capture` ("usa o l'SDK o tt-egress per questa chiamata"). È un avviso, non un filtro: gli eventi restano salvati.
  1. **Span**: un evento in uscita di tt-egress ha come span padre lo span di un evento in uscita di un SDK della stessa traccia.
  2. **Host**: un evento in uscita di un SDK ha come destinazione l'host di una sorgente tt-egress nota (l'hostname riportato dalla sorgente all'iscrizione, più gli indirizzi dichiarati in `fleet.egress_hosts`, per esempio `tt-egress:9090`). Basta un evento.
  3. **Tempo e forma**: un evento in uscita di un SDK e uno di tt-egress hanno stesso metodo e stesso stato, e la chiamata di tt-egress cade dentro quella dell'SDK (entro 2 s di scarto di orologio); se l'SDK nomina un servizio, è lo stesso. Una coincidenza non prova nulla: la coppia di sorgenti è segnalata dopo 3 abbinamenti in 10 minuti. È il segnale che funziona anche quando la destinazione è `host:unlisted`.

## Avvio

```bash
export TT_ENROLL_URL=https://tt-core.internal:4318
export TT_ENROLL_TOKEN=tte_...        # solo da ambiente, mai da flag
export TT_SERVICE_NAME=egress-shop    # deve essere ammesso per il gruppo del token
export TT_HMAC_KEY_FILE=/run/secrets/tt-hmac   # righe "<kid>:<base64url>"
tt egress --listen :9090 --upstream carrier=https://api.carrier.example
```

Senza `TT_ENROLL_URL` il proxy parte in **modalità solo inoltro** (nessuna cattura) e lo scrive nel log.

| Flag | Variabile | Significato |
|---|---|---|
| `--config` | `TT_EGRESS_CONFIG` | File YAML (vedi sotto). Precedenza: file < ambiente < flag |
| `--listen` | `TT_EGRESS_LISTEN` | Indirizzo di ascolto, default `127.0.0.1:9090`. Nei container serve `:9090` |
| `--upstream alias=URL` (ripetibile) | `TT_EGRESS_UPSTREAMS` (`a=u,b=u`) | Servizio esterno raggiungibile a `/<alias>/` |
| `--capture-origin alias=ORIGIN` | | Origine con cui la **policy** conosce il servizio (`scheme://host[:porta]`), se diversa da quella raggiunta |
| `--ca-file` | `TT_EGRESS_CA_FILE` | CA PEM aggiuntiva per gli upstream |
| `--alias-from-policy` | `TT_EGRESS_ALIAS_FROM_POLICY` | Instrada anche `/<servizio>/` verso la `match.base` dei servizi esterni della policy accettata. Spento di default: una policy decide cosa esce, non dove vanno le credenziali dell'app |
| `--enroll-url`, `--service-name`, `--state-dir` | `TT_ENROLL_URL`, `TT_SERVICE_NAME`, `TT_STATE_DIR` | Iscrizione. Le stesse variabili degli SDK |
| `--log-level` | `TT_EGRESS_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| | `TT_ENROLL_TOKEN`, `TT_HMAC_KEY`, `TT_HMAC_KEY_FILE` | Token di iscrizione e chiavi HMAC (mai da flag) |

File YAML:

```yaml
listen: ":9090"
upstreams:
  - alias: carrier
    url: https://api.carrier.example
    capture_origin: https://api.carrier.example   # facoltativo
    ca_file: /etc/tt/carrier-ca.pem                # facoltativo
dial_timeout: 5s
tls_handshake_timeout: 10s
response_header_timeout: 60s
idle_conn_timeout: 90s
max_idle_conns_per_host: 64
capture: { workers: 4, queue_size: 1024, max_pending_bytes: 67108864, max_inflight: 512 }
```

Ogni upstream ha il **proprio pool di connessioni** (HTTP/2 verso i servizi che lo offrono).

### Come la policy riconosce il servizio

Per il sanitizer il servizio è la `match.base` della policy che corrisponde all'origine **e** ai primi segmenti di path della richiesta in uscita. Il proxy passa `capture_origin` (o, in mancanza, l'origine dell'upstream) più il path completo verso l'upstream, quindi una base con path (`https://host/api`) funziona se l'URL dell'upstream contiene lo stesso prefisso. Se nessuna base corrisponde, lo scambio esce come `host:unlisted` (solo forma).

## Salute e metriche

- `GET /_tt/health` sul listener del proxy: JSON con stato (`capturing`, `no_policy`, `policy_rejected`, `expired_policy`, `key_missing`, `key_mismatch`, `killed`, `starting`, oppure `disabled` in solo inoltro), contatori, eventi al minuto, coda, e la latenza aggiunta stimata (`overhead_us_p50/p99`). Non contiene mai valori dei payload.
- L'**heartbeat** a `tt-core` porta gli stessi contatori (`exchanges_seen`, `exchanges_sampled`, `events_sent`, `events_dropped_queue`, `events_rejected`, `send_errors`, `sanitizer_errors`), `overhead_us` e gli ultimi codici di errore. La latenza aggiunta misura il tempo speso da tt per scambio: preparazione, copia dei corpi e consegna alla coda.

Misure di riferimento (Apple M3, upstream HTTP locale, ~200 byte per verso, `go test -bench Proxy ./internal/egress`): diretto p50 ≈ 67 µs; proxy con cattura spenta p50 ≈ 150 µs, p99 ≈ 210 µs; con cattura accesa p50 ≈ 160 µs, p99 ≈ 0,5 ms. Il costo della cattura sul percorso della richiesta è dell'ordine di 10 µs a p50 (il resto è il salto in più).

## Come inserire tt-egress nella demo

La demo (`demo/`) non va modificata da qui: ecco cosa fare nel proprio `docker-compose.override.yml` o nel compose. Lo shop parla col corriere **solo** tramite `CARRIER_BASE_URL`.

1. Aggiungere il servizio (immagine costruita dal `Dockerfile` della radice, entrypoint `tt`):

```yaml
services:
  tt-egress:
    image: traffic-twin:local
    command: ["egress", "--listen", ":9090", "--upstream", "carrier=http://carrier:8080",
              "--capture-origin", "carrier=https://carrier.example"]
    environment:
      TT_ENROLL_URL: https://tt-core:4318
      TT_ENROLL_TOKEN: ${TT_ENROLL_TOKEN}
      TT_SERVICE_NAME: egress-shop
      TT_HMAC_KEY_FILE: /run/secrets/tt-hmac
    depends_on: [carrier]
```

2. Avviare lo shop puntato al proxy:

```bash
CARRIER_BASE_URL=http://tt-egress:9090/carrier docker compose up
```

Il corriere della demo è `http://carrier:8080` in chiaro e rappresenta `carrier.example`: per questo `--capture-origin carrier=https://carrier.example`, così che la policy con `match: { base: "https://carrier.example" }` riconosca il servizio. Le chiamate dello shop diventano `http://tt-egress:9090/carrier/v1/shipments` e arrivano al corriere come `/v1/shipments`.

Nota sull'host: i campi `Host` verso il corriere sono quelli dell'upstream (`carrier:8080`), non quelli del proxy.

## Test

`go test -race ./internal/egress/ ./internal/sourceclient/...`. I test di integrazione usano un servizio finto TLS (`httptest`) e un `tt-core` finto (`internal/sourceclient/fakecore`: CA di prova con intermedia, iscrizione con pin, policy con ETag, heartbeat, rinnovo, intake OTLP in mTLS). Coprono: inoltro trasparente, evento uguale a quello del sanitizer, risposta gzip, streaming di 64 MiB senza bufferizzare, flush incrementale, interruttore di emergenza, policy/chiave non valide, sovraccarico, baggage `tt.s`. I benchmark: `go test -run xxx -bench Proxy ./internal/egress/`.
