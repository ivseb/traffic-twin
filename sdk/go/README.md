# traffic-twin (Go)

SDK di cattura di traffic-twin per Go. Osserva le chiamate HTTP in ingresso (un
`http.Handler`) e in uscita (un `http.RoundTripper`), le **sanifica nel processo** secondo la
policy firmata (specifica `docs/spec/sanitizer.md`) e invia a `tt-core` solo forme, token HMAC
e valori ammessi dalla policy, come log OTLP/HTTP JSON su mTLS.

```
go get github.com/ivseb/traffic-twin/sdk/go
```

- **Nessuna dipendenza esterna a runtime**: il pacchetto importa solo la libreria standard e i
  pacchetti condivisi del modulo `github.com/ivseb/traffic-twin` (sanitizer di riferimento,
  policy, client di sorgente), che a loro volta usano solo la libreria standard. Lo verifica un
  test (`TestZeroRuntimeDependencies`). Richiede Go 1.25 (versione del modulo principale).
- **Niente codice di sicurezza duplicato**: sanificazione, campionamento, verifica delle firme,
  iscrizione ed esportazione sono gli stessi pacchetti del sanitizer di riferimento (che passa
  tutti i 422 vettori di conformità) e di `tt-egress`.
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato; l'unica eccezione,
  opzionale e decisa dalla policy, è il membro di baggage `tt.s` verso gli host di
  `sampling.propagate_to` (mai verso un servizio esterno della policy).
- **Non rallenta l'app**: sul percorso della richiesta ci sono solo la decisione di
  campionamento e la copia dei primi `max_body_bytes + 1` byte dei corpi; sanificazione,
  serializzazione e invio avvengono su goroutine in background con code limitate. Quando una
  coda è piena si scartano eventi interi (e si contano), mai richieste.
- **Fail-closed**: senza policy valida, chiave HMAC o primo heartbeat, o con l'interruttore di
  emergenza attivo, non si cattura nulla e l'app continua a funzionare. Un errore o un panic
  interno del sanitizer scarta lo scambio e incrementa `sanitizer_errors`.

## Avvio senza codice

```bash
export TT_ENROLL_URL=https://tt-core.internal:4318
export TT_ENROLL_TOKEN=tte_…                 # token di iscrizione (contiene l'impronta della CA)
export TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key
export TT_SERVICE_NAME=shop-api
```

```go
mux := http.NewServeMux()
mux.HandleFunc("POST /orders", createOrder)
mux.HandleFunc("GET /orders/{id}", getOrder)

srv := &http.Server{Addr: ":8080", Handler: ttsdk.Handler(mux)}  // ingresso
client := &http.Client{Transport: ttsdk.Transport(nil)}           // uscita (nil = DefaultTransport)
```

`ttsdk.Handler` e `ttsdk.Transport` usano l'agente di default, creato alla prima chiamata
dall'ambiente: iscrizione, heartbeat e download della policy partono in background e **non
ritardano l'avvio** dell'app. Senza `TT_ENROLL_URL` (o con `TT_DISABLED=1`) l'SDK è inerte:
le due funzioni restituiscono il loro argomento invariato e non parte nessuna goroutine.
In uscita, alla chiusura dell'app: `ttsdk.Shutdown(ctx)` svuota la coda di esportazione.

| Variabile | Significato |
|---|---|
| `TT_ENROLL_URL` | URL del listener Fleet/intake di `tt-core` (sempre `https`) |
| `TT_ENROLL_TOKEN` | Token di iscrizione `tte_<segreto>.<impronta CA>`, monouso o di gruppo |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, una o più righe `<kid>:<base64url>`. Non viaggia mai verso `tt-core` |
| `TT_SERVICE_NAME` | Nome di servizio richiesto all'iscrizione (altrimenti `OTEL_SERVICE_NAME` in minuscolo). Il nome usato negli eventi è quello **assegnato** da `tt-core` |
| `TT_STATE_DIR` | Cartella dello stato locale (default `~/.traffic-twin/<id>`): certificato, chiave privata, policy firmata, interruttore. Cartella `0700`, file `0600` |
| `TT_DISABLED` | `1` disattiva completamente l'SDK |
| `TT_DEBUG` | `1` scrive su stderr solo codici di stato ed errore (mai valori) |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS` | Solo per test: sostituiscono gli intervalli ricevuti da `tt-core` |

Se `TT_ENROLL_URL` è impostata ma la configurazione è sbagliata (per esempio manca il nome del
servizio) l'SDK stampa una riga su stderr, si disattiva e l'app parte lo stesso. Senza una
chiave HMAC valida l'agente gira ma non cattura (`key_missing` nell'heartbeat).

Per un controllo esplicito: `agent, err := ttsdk.New(ttsdk.Config{…})` (oppure
`ttsdk.New(ttsdk.ConfigFromEnv())`), poi `agent.Handler(next)`, `agent.Transport(base)`,
`agent.Stats()`, `agent.Close(ctx)`.

## Cosa viene catturato

### Ingresso: `Handler`

- **`framework_route` da `net/http` 1.22+**: il pattern che il `ServeMux` ha scelto
  (`r.Pattern`, per esempio `GET /orders/{id}`) è passato al sanitizer come route del
  framework `nethttp` (§3.4: `{nome}` resta, un `{$}` finale si elimina, `{nome...}` non è
  normalizzabile e si ricade sui template della policy). Usare `ttsdk.Handler(mux)` fuori
  dal mux: se il pattern lo imposta un mux annidato (`http.StripPrefix` + mux interno) la
  route sarebbe incompleta e non viene passata.
- I middleware **fuori** dall'SDK vedono ancora `r.Pattern` (per esempio `otelhttp` lo usa per
  dare il nome allo span del server): l'SDK lo ricopia sulla richiesta originale.
- Cosa vede la sanificazione: metodo, path e query **non decodificati** (da `RequestURI`),
  header (con `Host` e `Transfer-Encoding` rimessi, perché Go li toglie dalla mappa), corpi
  (prefisso di `max_body_bytes + 1` byte e lunghezza totale), status e header di risposta
  fotografati al momento di `WriteHeader`/primo `Write`. Se il handler non imposta
  `Content-Type`, l'SDK riproduce il `Content-Type` che il server Go aggiunge per sniffing,
  così l'evento descrive ciò che il client ha ricevuto. Non sono visibili gli header che il
  server genera dopo (`Date`, `Content-Length`).
- `Flush`, `Hijack`, `Push` e `http.ResponseController` continuano a funzionare. Le
  connessioni dirottate (WebSocket) e gli scambi interrotti da un panic non producono eventi.

### Uscita: `Transport`

Vede la richiesta **prima della cifratura**, quindi anche le chiamate HTTPS. Non altera
richiesta né risposta. L'evento si chiude quando il corpo della risposta arriva a EOF o viene
chiuso; errori di rete sono classificati (`timeout`, `reset`, `refused`, `dns`, `tls`,
`other`). Una chiamata fatta con il **contesto della richiesta in ingresso**
(`http.NewRequestWithContext(r.Context(), …)`) **eredita** la decisione di campionamento di
quella richiesta (`sampled_by: inherited`) e ne usa il `trace_id`, con `parent_span_id` uguale
allo `span_id` dell'evento in ingresso. Una chiamata senza quel contesto (job, timer) si
campiona per `trace_id` o a caso.

### Campionamento e baggage (D-M8)

La decisione è del sanitizer di riferimento (§12), presa **prima** di sanificare:

1. baggage `tt.s=0|1`, solo se la policy ha `trust_baggage` **e** il servizio è dichiarato
   `internal`: così un client esterno non può forzare né evitare la cattura;
2. **soggetto** (`identity.subject`): `HMAC(chiave, epoch ‖ "sample" ‖ soggetto) mod 10000 <
   rate_bp`, stabile per tutta l'epoch e uguale in tutti i servizi;
3. `trace_id` (da `traceparent` o dallo span OpenTelemetry attivo);
4. casuale.

In uscita, solo verso gli host elencati in `sampling.propagate_to` e mai verso la base di un
servizio esterno della policy, l'SDK antepone `tt.s=<0|1>` al baggage della chiamata (senza
toccare gli altri membri: chi legge prende il primo `tt.s` valido, quindi un `tt.s` inoltrato
per errore dall'app non può scavalcarlo). Non si propaga senza una richiesta in ingresso.

## Gin e chi

Gli adattatori sono **moduli separati**, così `github.com/ivseb/traffic-twin/sdk/go` non
dipende né da Gin né da chi:

```go
// Gin — go get github.com/ivseb/traffic-twin/sdk/go/gin
r := gin.New()
r.Use(ttgin.Middleware())            // c.FullPath(): "/api/orders/:id", prefissi dei gruppi inclusi

// chi — go get github.com/ivseb/traffic-twin/sdk/go/chi
r := chi.NewRouter()
r.Use(ttchi.Middleware)              // RoutePattern(): "/api/v1/orders/{id}", sub-router montati inclusi
```

Un catch-all (`/files/*path` in Gin, `/files/*` in chi) non è normalizzabile (§3.4): il
sanitizer usa i template della policy. In Gin il middleware va dopo `gin.Recovery()`.
Per altri router si può usare `agent.Handler(next, ttsdk.WithRoute(func(r) (framework, route)))`
o, per un controllo totale, `agent.Begin(r)` / `Inbound.End()` (la base degli adattatori).

## Convivenza con OpenTelemetry

L'SDK **non importa OpenTelemetry**, non registra mai un `TracerProvider` né un propagatore
globale (`otel.Set…`), non crea span e non inietta `traceparent`. Legge `traceparent` dalla
richiesta; per leggere anche lo **span attivo** nel contesto c'è il modulo opzionale
`otelctx` (dipende solo da `go.opentelemetry.io/otel/trace`):

```go
// go get github.com/ivseb/traffic-twin/sdk/go/otelctx
cfg := ttsdk.ConfigFromEnv()
cfg.TraceContext = otelctx.FromContext   // oppure otelctx.Use() prima del primo uso dell'agente di default
agent, _ := ttsdk.New(cfg)

h := otelhttp.NewHandler(agent.Handler(mux), "shop")        // l'SDK dentro: lo span è già nel contesto
c := &http.Client{Transport: otelhttp.NewTransport(agent.Transport(base))}
```

Gli eventi usano allora gli id dello span del server (`span_id`, con `parent_span_id` preso da
`traceparent`) e dello span client (in uscita, con `parent_span_id` = span del server). Il
test `otelctx/coexist_test.go` (l'SDK OpenTelemetry è dipendenza di soli test) esegue la stessa
app strumentata con `otelhttp` con e senza traffic-twin e verifica che **gli span siano
identici** (nomi, tipi, genitori, stato, attributi), che gli header ricevuti a valle siano gli
stessi, che il baggage dell'app sia intatto e che i provider e propagatori globali non siano
stati toccati. Il test ha già trovato e fatto correggere un caso reale: il mux scrive
`r.Pattern` sulla copia della richiesta che l'SDK gli passa, e `otelhttp` perdeva il nome della
route.

## Limiti di risorse

`Config` (campi non-env): `Workers` (default `min(4, GOMAXPROCS)`), `QueueSize` (1024 scambi in
attesa), `MaxPendingBytes` (64 MiB di corpi copiati in attesa), `MaxInflight` (512 scambi con
corpi in copia). Oltre un limite gli scambi vengono scartati e contati
(`events_dropped_queue`). La coda di esportazione ha i suoi limiti (10 000 eventi / 16 MiB):
quando è piena si scartano i più vecchi.

## Test e benchmark

Il modulo principale contiene il pacchetto e i suoi test; gli adattatori sono moduli annidati.

```bash
go test -race ./sdk/go/...                       # dalla radice del repository
(cd sdk/go/gin && go test -race ./...)
(cd sdk/go/chi && go test -race ./...)
(cd sdk/go/otelctx && go test -race ./...)       # include la convivenza con l'SDK OpenTelemetry
go test ./sdk/go -run xxx -bench . -benchmem     # overhead
```

(oppure `make -C sdk/go test`). Cosa coprono:

- **Vettori di conformità**: `TestSDKPathMatchesConformanceVectors` riesegue **tutti i vettori
  esprimibili su HTTP** (370 su 422 negli ultimi giri) attraverso il percorso reale dell'SDK —
  un server `net/http` dietro `Handler` con richieste scritte byte per byte su TCP, oppure un
  `RoundTripper` dietro `Transport`, con worker ed event builder — e confronta la parte del
  sanitizer dell'evento con l'uscita canonica attesa, byte per byte. Gli altri 52 non sono
  esprimibili: policy da rifiutare (33, riguardano lo store e sono coperti da
  `internal/sourceclient`), byte che `net/http` stesso rifiuta, header gestiti dallo stack
  (`Content-Length`…), corpi «già decodificati» in ingresso, lunghezze ignote. (Il sanitizer
  condiviso passa comunque tutti i 422 in `internal/sanitizer`.)
- **Integrazione** con `internal/sourceclient/fakecore`: iscrizione con token e impronta CA,
  policy firmata, heartbeat, esportazione mTLS, interruttore di emergenza, flush alla chiusura,
  chiave mancante.
- Convivenza, baggage, campionamento per soggetto, coda piena, panic, corpi grandi, streaming,
  Gin (gruppi, catch-all), chi (sub-router montati, wildcard).

Overhead misurato (Apple M-series, `go test -bench`, `-benchmem`; handler che legge 100 byte e
risponde 33 byte, sanificazione fuori dal percorso della richiesta):

| Caso | ns/op | extra rispetto alla base |
|---|---|---|
| Handler base (senza SDK) | 394 | — |
| Handler, SDK inerte | 410 | ≈ 0 (restituisce `next`) |
| Handler, richiesta non campionata (con soggetto HMAC) | 1 710 | ≈ 1,3 µs |
| Handler, richiesta campionata (copia dei corpi + coda) | 2 940 | ≈ 2,5 µs |
| Transport base | 523 | — |
| Transport, non campionata | 789 | ≈ 0,3 µs |
| Transport, campionata | 2 520 | ≈ 2,0 µs |

## Scelta architetturale: modulo principale, non copia del codice

Il codice di sicurezza (sanitizer, policy, client di sorgente) sta in `internal/`, che un
modulo esterno non può importare. Opzioni valutate:

- (a) promuoverlo a `pkg/` e fare importare `internal/`: tocca molti pacchetti degli altri
  agenti e allarga la superficie pubblica di codice non pensato come API;
- (b) **fare di `sdk/go` un pacchetto del modulo principale** (scelta fatta): il percorso di
  import `github.com/ivseb/traffic-twin/sdk/go` sta sotto la radice di `internal/`, quindi può
  importarlo, nessun file esistente cambia e `go get` funziona con un solo comando.

Costo: `go get` scarica il modulo `github.com/ivseb/traffic-twin` (non solo la cartella
`sdk/go`) e il suo `go.mod` entra nel grafo dei moduli, anche se la **compilazione** usa solo
la libreria standard e i pacchetti interni citati. Per non allargare il `go.mod` principale con
Gin, chi e OpenTelemetry, gli adattatori `gin`, `chi` e `otelctx` sono **moduli annidati** con
il loro `go.mod`; in sviluppo puntano al repository con `replace … => ../../..`. Al rilascio
vanno fissati i tag (`require github.com/ivseb/traffic-twin vX.Y.Z` e rimozione del `replace`).
