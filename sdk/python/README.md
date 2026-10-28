# traffic-twin (Python)

SDK di cattura di traffic-twin per Python ≥ 3.9. Osserva le chiamate HTTP in ingresso
(Flask, FastAPI/Starlette, Django, qualunque app WSGI o ASGI) e in uscita
(`requests`, `httpx`, `urllib`, `http.client`), le **sanifica nel processo** secondo la
policy firmata (specifica `docs/spec/sanitizer.md`, fino alla v1.19) e invia a `tt-core` solo forme,
token HMAC e valori ammessi dalla policy, come log OTLP/HTTP JSON su mTLS.

- **Zero dipendenze a runtime**: solo la libreria standard (`pyproject.toml` ha
  `dependencies = []`). Né `opentelemetry-*` né librerie crittografiche: la verifica delle
  firme Ed25519 (RFC 8032) è scritta in Python puro (`traffic_twin/ed25519.py`, provata con i
  vettori della RFC).
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato; l'unica eccezione,
  opzionale e decisa dalla policy, è il membro di baggage `tt.s` verso gli host di
  `sampling.propagate_to` (mai verso un host esterno della policy). Il membro è messo **in testa**
  al baggage (chi legge prende il primo `tt.s` valido): un `tt.s` falsificato da un client e
  inoltrato dall'app non può mai prevalere.
- **Non rallenta l'app**: sulla strada della richiesta ci sono solo la decisione di
  campionamento e la copia dei byte del corpo; sanificazione, serializzazione e invio
  avvengono in thread in background con code limitate. Quando le code sono piene si scartano
  gli eventi più vecchi (e si contano), mai le richieste.
- **Fail-closed**: senza policy valida, chiave HMAC o primo heartbeat non cattura nulla;
  l'app continua a funzionare normalmente. Un errore interno del sanitizer scarta lo
  scambio e incrementa `sanitizer_errors`.

## Avvio senza codice

```bash
pip install ./traffic_twin-x.y.z-py3-none-any.whl     # dal kit; dal registro interno: pip install traffic-twin
export TT_ENROLL_URL=https://tt-core.internal:4318
export TT_ENROLL_TOKEN=tte_…                 # token di iscrizione (contiene l'impronta della CA)
export TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key
export TT_SERVICE_NAME=shop-api
python -m traffic_twin run -- uvicorn app:app         # o gunicorn app:app, flask --app app run, python manage.py runserver, …
```

Il comando cattura da solo **sia le chiamate in ingresso sia quelle in uscita**, senza toccare il codice
(`traffic_twin/autocapture.py`): la prima volta che un modulo noto viene importato, una piccola patch fa sì che
gli oggetti che crea catturino il traffico.

| Cosa | Come si avvolge |
|---|---|
| FastAPI / Starlette | `build_middleware_stack` restituisce lo stack avvolto nel middleware ASGI (una volta per app, mai se l'app ha già `install()` o il middleware) |
| Flask | `Flask.__init__` avvolge `wsgi_app` |
| Django | `get_wsgi_application()` / `get_asgi_application()` restituiscono l'oggetto avvolto |
| uvicorn (`uvicorn app:app`, `uvicorn.run(app)`) | l'app caricata, se è una semplice funzione/oggetto ASGI (o WSGI con `--interface wsgi`) che nessuna patch di framework copre; con `--factory` l'app che la factory crea è avvolta solo se è Starlette/FastAPI/Flask |
| gunicorn (WSGI o `-k uvicorn.workers.UvicornWorker`) | l'app che `gunicorn.util.import_app` restituisce, se è una semplice funzione/oggetto WSGI o ASGI |
| `requests`, `httpx`, `urllib` | in uscita, appena `requests`/`httpx` sono importati (`TT_OUTBOUND=auto`, il default di questo avvio); `TT_OUTBOUND=off` spegne la parte in uscita, una lista (`httpx`, `requests,urllib`, `http.client`) sceglie quali |

Un'app montata dentro un'altra già catturata (Starlette `Mount`, `DispatcherMiddleware`) non si cattura due volte.

**Quando non si riesce ad avvolgere nessuna app** (un server o un framework che non si conosce) l'SDK non resta in
silenzio: dopo 20 secondi scrive **una volta sola** su stderr `inbound not captured: ... add traffic_twin.install(app)`
e segnala a `tt-core` l'errore `inbound_not_captured` nell'heartbeat; la console mostra sulla sorgente il problema
**Ingresso non catturato** (e, senza ingresso, non c'è `identity.subject`). Rimedio: `app = traffic_twin.install(app)`
(sotto). Il controllo si ripete ogni 5 minuti finché nessuna app è avvolta.

`python -m traffic_twin run -- <comando>` mette `traffic_twin/bootstrap/sitecustomize.py` in
testa a `PYTHONPATH`: Python lo importa all'avvio, esso esegue prima l'eventuale
`sitecustomize` già presente nell'app e poi avvia l'agente. L'agente parte in background:
iscrizione, heartbeat e download della policy non ritardano l'avvio dell'app. Senza
`TT_ENROLL_URL` l'SDK resta inerte.

Alternative equivalenti: `import traffic_twin.auto` (una riga all'inizio dell'app) oppure
`traffic_twin.start()`.

| Variabile | Significato |
|---|---|
| `TT_ENROLL_URL` | URL del listener Fleet/intake di `tt-core` (sempre `https`) |
| `TT_ENROLL_TOKEN` | Token di iscrizione `tte_<segreto>.<impronta CA>`, monouso o di gruppo |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, una o più righe `<kid>:<base64url>` (§7.1). Non viaggia mai verso `tt-core` |
| `TT_SERVICE_NAME` | Nome di servizio richiesto all'iscrizione (altrimenti `OTEL_SERVICE_NAME` in minuscolo). Il nome usato negli eventi è quello **assegnato** da `tt-core` |
| `TT_STATE_DIR` | Cartella dello stato locale (default `~/.traffic-twin/<id>`): certificato, chiave privata, CA, policy firmata, interruttore. Cartella `0700`, file `0600`. Se non è scrivibile, o è di un altro utente, si usa una cartella temporanea privata (l'iscrizione non sopravvive al riavvio); una cartella propria più larga (anche `~/.traffic-twin`) viene riportata a `0700`. I file di stato si leggono solo se regolari, dell'utente e non scrivibili da gruppo/altri (`state_file_untrusted`). L'interruttore di emergenza scarta anche i batch in retry e gli scambi in sanificazione (generazione) |
| `TT_OUTBOUND` | Hook in uscita **globali** da attivare, separati da virgola: `requests`, `httpx`, `urllib`, `http.client`, oppure `auto` (requests/httpx se già importati, più urllib). Con `python -m traffic_twin run` e `import traffic_twin.auto` il default è `auto` applicato **all'import** di `requests`/`httpx` (`off` lo spegne); con `traffic_twin.start()` / `install()` il default è nessuno (vedi sotto) |
| `TT_ENROLL_CA_FILE` | PEM della CA radice. Obbligatorio solo su Python 3.9, che non sa leggere la catena presentata dal server: l'impronta del token viene verificata su questo file |
| `TT_DISABLED` | `1` disattiva completamente l'SDK (nessun thread, nessun hook) |
| `TT_DEBUG` | `1` scrive su stderr solo codici di stato ed errore (mai valori) |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS`, `TT_INBOUND_GRACE_MS` | Solo per test: sostituiscono gli intervalli ricevuti da `tt-core` e l'attesa (20 s) prima dell'avviso `inbound not captured` |

## Installazione nelle app

```python
import traffic_twin

# Flask (modifica app.wsgi_app sul posto)
app = traffic_twin.install(app)

# FastAPI / Starlette (add_middleware, il più esterno)
app = traffic_twin.install(app)

# Django: si installa sull'oggetto WSGI/ASGI e si riassegna
application = traffic_twin.install(get_wsgi_application())      # oppure get_asgi_application()

# qualunque app WSGI o ASGI (rilevata dalla firma; kind="wsgi"|"asgi" per forzare)
application = traffic_twin.install(application)
```

`install()` è idempotente: su un'app già avvolta (da un'altra `install()` o dal comando `run`) non fa nulla. Avvia l'agente dall'ambiente (o dai parametri: `install(app, enroll_url=…,
service_name=…, outbound="requests,httpx")`) e **non lancia mai eccezioni**: se non riesce a
installarsi emette un `RuntimeWarning` e lascia l'app com'è. Si possono usare anche i
middleware direttamente: `traffic_twin.capture.asgi.ASGIMiddleware`,
`traffic_twin.capture.wsgi.WSGIMiddleware`.

### `framework_route` (§3.3, §3.4)

Il template della route si risolve **dopo** la risposta, nel thread di sanificazione, chiedendo
al router del framework quale route corrisponde alla richiesta (senza eseguire codice
dell'app), sempre completo dei prefissi di montaggio:

| Framework | Fonte | Note |
|---|---|---|
| Flask | `app.url_map.bind_to_environ(...).match(return_rule=True)` | Blueprint e `SCRIPT_NAME` inclusi; `<path:x>` non si normalizza |
| FastAPI / Starlette | `route.matches(scope)` sul router, anche dentro `Mount` | `{x:path}` non si normalizza |
| Django | `django.urls.resolve(...).route` | `re_path` non si normalizza: vale il template della policy |

Se la route non si può ricostruire non si passa `framework_route` e vale il punto 2 di §3.3.

## Chiamate in uscita

Prima i **punti di estensione**, senza patch globali:

```python
import requests, httpx, urllib.request
from traffic_twin.capture.outbound import make_requests_adapter, make_httpx_transports, make_urllib_handler

s = requests.Session(); s.mount("https://", make_requests_adapter()())
T, AT = make_httpx_transports()
c = httpx.Client(transport=T(httpx.HTTPTransport()))          # sincrono
a = httpx.AsyncClient(transport=AT(httpx.AsyncHTTPTransport()))  # asincrono
opener = urllib.request.build_opener(make_urllib_handler()())
```

Per le app che costruiscono i client altrove, una patch è inevitabile: è **opt-in**
(`TT_OUTBOUND` o `outbound=`) e **reversibile** (ogni `install_*` di
`traffic_twin.capture.outbound` restituisce la funzione che ripristina gli originali):

| Valore | Cosa fa |
|---|---|
| `requests` | le nuove `requests.Session` ricevono l'adattatore (usa il punto di estensione) |
| `httpx` | avvolge `handle_request` / `handle_async_request` dei trasporti predefiniti |
| `urllib` | installa un opener predefinito con l'handler (`install_opener`, API ufficiale) |
| `http.client` | patch di `HTTPConnection` (`putrequest`, `putheader`, `endheaders`, `send`, `getresponse`): non esiste un punto di estensione a questo livello. Copre anche `urllib3`/`requests` e tutto ciò che sta sopra `http.client` |

Se due livelli vedono la stessa chiamata (adattatore `requests` e patch `http.client`) la
registra solo il più esterno (`contextvars`). Le chiamate fatte dall'SDK stesso (Fleet,
intake) non si catturano mai.

I corpi si copiano mentre l'app li legge (tee con limite `max_body_bytes + 1`, il resto si
conta): il corpo di una risposta che l'app non legge fino alla fine esce come `trunc:size`.
La codifica `gzip`/`deflate` la decodifica il sanitizer (§9.0), partendo dai byte ancora
codificati.

### Host non dichiarati e scoperta automatica (spec v1.5)

Un host esterno che nessuna `base` della policy né `segments.hosts_allow` elenca non esce
più come `host:unlisted`: con `hosts.discovery: auto` (default, anche quando il campo
`hosts` manca) il `service` dell'evento è `host:` + **pattern** (sanitizer.md §3.5). Il
pattern è l'host in minuscolo, senza porta di default e senza un punto finale, in cui ogni
etichetta resta letterale solo se è `^[a-z][a-z0-9-]{0,62}$`, non ha sei cifre consecutive
né dodici esadecimali consecutivi, altrimenti diventa `{*}` (`t-3912345678.tenant.example` →
`host:{*}.tenant.example`). I letterali IP escono solo come `ip:private` / `ip:public`
(tabella chiusa di §3.6, parser IPv6 proprio in `traffic_twin/hostpat.py`: né `ipaddress` né
`is_private`), con la porta se non di default; un'etichetta vuota dà `host:invalid`. Gli
adattatori passano l'host così come lo vede il client (IPv6 tra parentesi, nessun IDN,
nessun punto tolto, nessun `str.lower()` Unicode).

`hosts.discovery: off` è la **modalità stretta**: gli host non dichiarati escono come
`host:unlisted`, byte per byte come prima della v1.5. Lo imposta la policy (`tt-core`:
`auto` → `off` chiude, `off` → `auto` apre, con le approvazioni normali); l'SDK non ha
opzioni locali. Il dominio registrabile e la cardinalità delle etichette sono controlli di
`tt-core` (zona B): l'SDK non li implementa.

### Corpi XML e SOAP, multipart, documenti e corpi grandi (spec v1.19)

Con l'oggetto `bodies` della policy (sanitizer.md §22; assente = tutto spento, uscita
identica alle versioni precedenti) il sanitizer analizza anche:

- **XML e SOAP** (`application/xml`, `text/xml`, `*+xml`): lettore XML scritto a mano
  (`traffic_twin/bodies.py`), sottoinsieme rigoroso di XML 1.0 + Namespaces, **senza**
  `xml.etree`/`expat`: nessuna DTD, nessuna entità oltre alle cinque predefinite e ai
  riferimenti numerici, iterativo e con al più 256 elementi annidati (`trunc:invalid-xml`
  altrimenti). Escono anche `fmt` (`xml`/`soap11`/`soap12`), `xmlns` e, per la richiesta,
  `soap_action`; le regole usano i passi `.@nome` e `.#text`.
- **`multipart/form-data`**: i campi come un form, le parti file sempre come
  `drop:file:<tipo>:<classe>` (`trunc:invalid-multipart` se il corpo non è conforme).
- **Documenti base64** (`bodies.docs`): `drop:doc:<tipo>:<classe>` al posto della classe di
  lunghezza.
- **Corpi grandi** (`bodies.max_large_body_bytes`): la copia del corpo conserva
  `max(limits.max_body_bytes, bodies.max_large_body_bytes) + 1` byte (WSGI, ASGI e client
  in uscita) e gli array si tagliano a `large_array` / `large_nested_array`.

L'azione `code` accetta anche la forma `{"action":"code","shape":"alnum"}` (§5.6).

## Contesto, OpenTelemetry e campionamento

- Un `contextvars.ContextVar` lega ogni chiamata in uscita allo scambio in ingresso (stesso
  `trace_id`, `parent_span_id` = `span_id` dell'evento in ingresso, decisione di campionamento
  **ereditata**): vale anche per `asyncio.create_task` e per i thread dei pool che copiano il
  contesto (Starlette/anyio). I thread avviati a mano dall'app non ereditano il contesto: lì
  valgono le regole "job" di §12 (trace OpenTelemetry, poi caso).
- Si legge `traceparent`. Se `opentelemetry-api` è importabile se ne legge **solo** il contesto
  dello span corrente (`trace.get_current_span().get_span_context()`): l'SDK **non** crea né
  registra mai provider, propagatori o contesti, e non crea span. Il test
  `tests/test_otel.py` esegue la stessa app con e senza l'SDK e confronta gli span esportati
  (nome, tipo, attributi, struttura), il provider e il propagatore globali.
- Campionamento per soggetto (§11, §12): `HMAC(chiave, epoch ‖ "sample" ‖ soggetto)`;
  baggage `tt.s` considerato solo con `trust_baggage` su servizi `internal`; l'override
  dell'heartbeat può solo **abbassare** il tasso.

## Fleet e stato locale

- **Iscrizione**: connessione TLS senza fiducia, ricerca nella catena presentata da
  `tt-core` del certificato con l'impronta SHA-256 contenuta nel token, richiesta di iscrizione
  con quel certificato come unica CA. La libreria standard non sa costruire una CSR PKCS#10:
  si usa il percorso **senza CSR** dell'API (`tt-core` genera la coppia di chiavi, restituisce
  `client_key` una sola volta sul canale appena fissato e non la salva). La chiave si scrive
  subito con modo `0600` in `TT_STATE_DIR` (le API `ssl` di Python vogliono dei file per
  `load_cert_chain`) e si riusa ai riavvii. Più processi (gunicorn con più worker) condividono
  lo stato e si serializzano con un lock su file: un token monouso si consuma una volta sola.
- **Heartbeat prima di qualsiasi cattura**; interruttore di emergenza, revoca e
  `min_issued_seq` sono salvati e restano validi dopo un riavvio.
- **Policy**: firma Ed25519 su `"tt.policy.body/v1" ‖ 0x00 ‖ corpo` con chiavi fissate e non
  revocate (verifica in Python puro, circa 30 ms, una volta per policy), schema completo del
  corpo, coerenza busta/corpo, gruppo, `not_after`, `issued_seq` crescente e ≥
  `min_issued_seq`. Una policy rifiutata non sostituisce mai la precedente valida. Nuove
  chiavi di firma solo se approvate (firma di endorsement) da una chiave già fissata.
- Server con `fork` (gunicorn `--preload`, uWSGI): i thread non sopravvivono al `fork`; il
  processo figlio ricrea l'agente con `os.register_at_fork`.

## Limiti noti

- **WSGI**: `PATH_INFO` e i nomi degli header arrivano già decodificati dal server. Il path
  grezzo si prende da `RAW_URI`/`REQUEST_URI` (gunicorn, uWSGI, mod_wsgi); altrimenti il path
  decodificato si ricodifica (un `%2F` originale non si distingue da `/`, con `wsgiref` e
  Werkzeug). I nomi degli header si ricostruiscono da `HTTP_*` con `_` → `-`: un header che
  contiene davvero un underscore compare con il trattino. Più header con lo stesso nome
  arrivano già uniti dal server (con `, `, anche per `Cookie`).
- **Python 3.9**: manca l'accesso alla catena TLS presentata dal server; per l'iscrizione serve
  `TT_ENROLL_CA_FILE`. Da 3.10 a 3.12 si usa l'API privata `_sslobj.get_unverified_chain()`,
  da 3.13 quella pubblica.
- File serviti con `wsgi.file_wrapper` / `http.response.pathsend`: i byte non passano
  dall'app, la risposta esce come `trunc:size`.
- Gli errori di rete di `urllib` senza la patch `http.client` si classificano `other`; con
  l'adattatore `requests` o i trasporti `httpx` si distinguono `timeout`, `refused`, `dns`,
  `tls`, `reset`.
- WebSocket e altri scope ASGI non `http` non si catturano.
- I `latency_ms` includono il tempo di streaming della risposta (fino alla chiusura).

## Sviluppo

```bash
cd sdk/python
make vectors     # python -m traffic_twin.conformance : tutti i vettori di conformità (726 con la v1.19), byte per byte
make test        # unittest: vettori, Ed25519 (RFC 8032), JSON, G1, WSGI, ASGI, uscita, Fleet, OTel, install
make bench       # overhead (python bench/overhead.py)
pip install -r requirements-dev.txt    # solo per i test opzionali (httpx, requests, Flask, …)
```

I test usano solo `unittest`; quelli che richiedono una dipendenza di sviluppo
(`requirements-dev.txt`, versioni fissate) si saltano se manca. Un finto `tt-core` con
intake OTLP e API Fleet su mTLS (`tests/fakecore.py`) usa una PKI costruita in Python puro
(certificati Ed25519 in DER, `tests/pki.py`): non serve il binario `openssl`. Provato su
Python 3.9, 3.11, 3.12 e 3.13.
