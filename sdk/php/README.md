# traffic-twin/sdk (PHP)

SDK di cattura di traffic-twin per PHP ≥ 8.1. Osserva le richieste HTTP in ingresso (PSR-15, Laravel,
Symfony) e in uscita (Guzzle), le **sanifica dentro il processo PHP** secondo la policy firmata
(specifica `docs/spec/sanitizer.md` v1.1.1, fino alla **v1.19**: azione `code` anche con la forma `alnum`, corpi XML e
SOAP, `multipart/form-data`, documenti base64 e corpi grandi, §22) e le consegna a `tt-core` come log OTLP/HTTP JSON su
mTLS. Fuori dal processo escono solo forme, token HMAC e valori ammessi dalla policy.

- **Nessuna dipendenza a runtime** oltre a PHP e alle sue estensioni standard: `json`, `hash`, `pcre`
  per catturare; `sodium` (verifica Ed25519 delle policy) e `openssl` (iscrizione, mTLS) per lo
  shipper; `zlib` facoltativa (corpi `gzip`/`deflate`). Guzzle, PSR-7/15, OpenTelemetry,
  Laravel e Symfony sono solo dipendenze di sviluppo o suggerite.
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato; l'unica eccezione,
  voluta dalla policy, è il membro di baggage `tt.s` verso gli host di `sampling.propagate_to`.
- **Fail-closed**: senza policy valida, chiave HMAC, primo heartbeat o `ext-sodium` non si cattura nulla
  e l'app continua a funzionare normalmente.
- **Sanitizer conforme**: i 583 vettori di `conformance/vectors` passano byte per byte su PHP 8.1, 8.3 e 8.4.

## Come funziona (PHP non condivide nulla tra le richieste)

Un worker PHP-FPM serve una richiesta e dimentica tutto. Non ha timer, non ha thread, non ha una
connessione che sopravvive alla richiesta: heartbeat, riconnessioni, ripetizioni con attesa
esponenziale, interruttore di emergenza e rotazione delle chiavi non possono vivere lì. Per questo l'SDK
ha **due metà** che parlano attraverso file in una cartella di stato:

```
 richiesta HTTP ──► worker PHP (FPM / Apache / CLI server / worker di lungo periodo)
                    │ 1. legge status.json + policy firmata, le riverifica (firma Ed25519, schema,
                    │    gruppo, scadenza, min_issued_seq) e legge la chiave HMAC dal proprio ambiente
                    │ 2. decide il campionamento (per utente, poi trace, poi casuale)
                    │ 3. se campionata: copia i primi max_body_bytes+1 byte dei corpi (tee)
                    │ 4. DOPO la risposta (shutdown function + fastcgi_finish_request):
                    │    sanifica ──► evento canonico ──► append a spool/seg-*.ndjson (0600)
                    ▼
        TT_STATE_DIR/  spool/  status.json  policy.envelope.json  counters/  ...
                    ▲
                    │ legge lo spool, spedisce, scrive status.json
        tt-shipper (processo lungo: systemd, sidecar, supervisord, o `--once` da cron)
                    │ iscrizione (token + impronta CA + CSR), heartbeat, policy, rinnovo certificato,
                    │ invio OTLP/HTTP JSON su mTLS con ripetizioni, interruttore persistito
                    ▼
                 tt-core
```

**Scelta e alternative.** L'alternativa "invio in linea" (aprire una connessione mTLS a `tt-core` dalla
richiesta, magari dopo `fastcgi_finish_request()`) è stata scartata: ogni richiesta pagherebbe una
negoziazione TLS con certificato client, un worker lento terrebbe occupato il processo FPM, non ci
sarebbero ripetizioni né interruttore persistito, e ogni worker dovrebbe tenere la chiave privata del
certificato. Con lo spool locale la richiesta paga solo un `fopen/flock/fwrite` (qualche decina di
microsecondi) e solo per gli scambi campionati; tutta la rete sta in un processo solo. Il costo è un
processo in più da avviare. Se lo shipper si ferma, i worker smettono di catturare da soli (vedi
"Fail-closed") invece di riempire il disco.

**Cosa non va mai su disco**: l'evento sanificato è l'unica cosa che entra nello spool, e solo dopo la
sanificazione. I valori grezzi vivono in memoria per la durata della richiesta (e dei corpi trattenuti
fino al `shutdown`). Lo spool è `0600` in una cartella `0700`; è comunque dato pseudonimo da trattare
come tale (cifratura del volume, ritenzione breve).

## Installazione

```bash
composer require traffic-twin/sdk
```

Cartella di stato (una per servizio, scrivibile dall'utente dei worker **e** dello shipper):

```bash
install -d -m 0700 -o www-data /var/lib/traffic-twin/shop-api
```

### 1. Lo shipper

```bash
TT_STATE_DIR=/var/lib/traffic-twin/shop-api \
TT_ENROLL_URL=https://tt-core.internal:4318 \
TT_ENROLL_TOKEN=tte_… \
TT_SERVICE_NAME=shop-api \
TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key \
  vendor/bin/tt-shipper
```

| Comando | Effetto |
|---|---|
| `tt-shipper` | Processo lungo; esce pulito su `SIGTERM`/`SIGINT` (con `ext-pcntl`). Un secondo shipper sulla stessa cartella esce con codice 3 |
| `tt-shipper --once` | Un ciclo (iscrizione, heartbeat, policy, invio di tutto lo spool) e poi esce: per cron ogni minuto o per i test |
| `tt-shipper status` | Stampa `status.json` |
| `--verbose` / `TT_DEBUG=1` | Righe su stderr con soli codici di stato ed errore, mai valori |

Senza processo lungo (hosting condiviso, nessun systemd) basta un cron ogni minuto:
`* * * * * www-data /srv/shop/vendor/bin/tt-shipper --once`. Ogni esecuzione fa un ciclo completo e manda tutto lo
spool. Le esecuzioni `--once` non azzerano la conoscenza dell'ultimo heartbeat (l'interruttore e `min_issued_seq`
sono persistiti e la scadenza `policy_max_age_s` continua a correre), così la cattura non si ferma a ogni minuto;
un processo lungo, invece, riparte da "non catturo finché non ho un heartbeat" a ogni avvio.

Esempio systemd:

```ini
[Service]
User=www-data
EnvironmentFile=/etc/traffic-twin/shop-api.env
ExecStart=/srv/shop/vendor/bin/tt-shipper
Restart=always
```

Lo shipper legge la chiave HMAC solo per sapere se c'è (`key_missing`/`key_mismatch`) e per
dichiarare gli id (`hmac_kids`) all'iscrizione: la chiave **non** viaggia mai verso `tt-core`.
Dategli la stessa `TT_HMAC_KEY(_FILE)` dei worker, altrimenti lo stato riportato in Fleet sarà `key_missing`
anche se i worker catturano.

### 2. I worker

Basta che vedano `TT_STATE_DIR` e la chiave. Con PHP-FPM le variabili vanno dichiarate nel pool
(`clear_env = yes` è il default e nasconde l'ambiente ai worker):

```ini
; pool.d/shop.conf
env[TT_STATE_DIR] = /var/lib/traffic-twin/shop-api
env[TT_HMAC_KEY_FILE] = /run/secrets/tt-hmac-key
```

| Variabile | Significato |
|---|---|
| `TT_STATE_DIR` | **Obbligatoria.** Stato locale: certificato, chiave privata, CA, policy firmata, interruttore, spool, contatori. Senza, l'SDK è inerte |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, righe `<kid>:<base64url>` (sanitizer §7.1). Senza o non valida: non si cattura |
| `TT_ENROLL_URL`, `TT_ENROLL_TOKEN`, `TT_SERVICE_NAME` | Solo shipper. Token `tte_<segreto>.<impronta CA>`; il nome usato negli eventi è quello **assegnato** da `tt-core` (default `OTEL_SERVICE_NAME` in minuscolo) |
| `TT_SPOOL_DIR`, `TT_SPOOL_MAX_BYTES` | Spool altrove (default `$TT_STATE_DIR/spool`); tetto in byte, oltre il quale lo shipper scarta i segmenti più vecchi (default 64 MiB) |
| `TT_ENROLL_CSR=0` | Chiede la chiave a `tt-core` invece di generare una CSR ECDSA P-256 locale |
| `TT_DISABLED=1` | Disattiva l'SDK |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS` | Solo per test |

## Integrazioni

### PSR-15 (Slim, Mezzio, ecc.)

```php
use TrafficTwin\Integration\Psr15Middleware;

$app->add(new Psr15Middleware());               // il più esterno possibile
```

Mettilo dopo il gestore degli errori se vuoi catturare anche le risposte 500: un'eccezione che esce
dalla pipeline non produce risposta, quindi nemmeno evento. I corpi seekable (`php://input`, stringhe,
file) si leggono senza spostare la posizione; i corpi non seekable si avvolgono in un decoratore che
passa i byte invariati (`TeeStream`) e si leggono dopo l'emissione. Un corpo di richiesta che l'app non ha
letto fino in fondo esce come `trunc:size` (sanitizer §9.0), mai come contenuto parziale.

**`framework_route`.** Il router di un framework di solito lavora *dopo* il middleware e PSR-7 è
immutabile: gli attributi aggiunti più in basso non si vedono. Il middleware accetta quindi un
resolver, chiamato dopo il gestore, che restituisce `[framework, route]` con la route **completa dei
prefissi di montaggio** o `null` (allora vale il template della policy, §3.3 punto 2):

```php
new Psr15Middleware(null, fn ($req) => Routes::symfonyByName($router, $req->getAttribute('_route')));
```

### Laravel

Laravel non usa PSR-15: c'è un middleware nativo (tipizzato per duck typing, nessuna dipendenza da Laravel).

```php
// bootstrap/app.php (Laravel 11)
->withMiddleware(fn (Middleware $m) => $m->prepend(\TrafficTwin\Integration\LaravelMiddleware::class))
```

`framework_route` è `$request->route()->uri()`, che include i prefissi dei gruppi (`api/v1/orders/{id}`).
I parametri opzionali (`{id?}`) non sono normalizzabili (§3.4): si ricade sul template della policy.

### Symfony

```yaml
# config/services.yaml
TrafficTwin\Integration\SymfonySubscriber:
    arguments: ['@router']
    tags: ['kernel.event_subscriber']
```

`framework_route` è il pattern completo della rotta (`RouteCollection::get($_route)->getPath()`), con i
prefissi delle collezioni importate. Symfony conserva `{id?}` come `{id}` più un valore di default: il
pattern è quindi quello della policy.

### Guzzle (chiamate in uscita)

```php
$stack = \GuzzleHttp\HandlerStack::create();
$stack->push(\TrafficTwin\Integration\GuzzleMiddleware::create());
$client = new \GuzzleHttp\Client(['handler' => $stack]);
```

Vede i dati prima della cifratura TLS. Con `push()` il middleware sta vicino al trasporto: vede ogni salto
di un redirect e ogni status HTTP come risposta; solo i guasti di trasporto sono `net_error`
(`timeout`, `reset`, `refused`, `dns`, `tls`, `other`, dal codice cURL). Le chiamate fatte mentre
si serve una richiesta ereditano campionamento e `trace_id` (`sampled_by: inherited`); fuori da una
richiesta (code, cron) il campionamento usa il trace di OpenTelemetry se c'è, altrimenti il caso. Con
`decode_content` Guzzle toglie `Content-Encoding` e lo lascia in `x-encoded-content-encoding`: l'SDK ricostruisce la
vista sul filo e dichiara il corpo già decodificato.

#### Host non dichiarati (spec v1.5)

Una chiamata verso un host che nessuna `base` della policy né `segments.hosts_allow` copre esce con
`service: host:<pattern>`: etichette minuscole che passano la regola dell'etichetta sicura
(`^[a-z][a-z0-9-]{0,62}$`, senza 6 cifre né 12 esadecimali consecutivi), altrimenti `{*}`; porta solo se non di default;
IPv4 e IPv6 tra parentesi escono solo come `ip:private` / `ip:public` (tabella chiusa della spec, parser IPv6 proprio in
`TrafficTwin\Sanitizer\HostPattern`, niente `inet_pton` né `filter_var`). Esempi: `host:api.carrier.example`,
`host:{*}.tenant.example`, `host:ip:private:8080`. Il middleware Guzzle passa l'host com'è nell'URI (parentesi per IPv6,
punto finale incluso, nessuna conversione IDN): un host Unicode resta `host:invalid`.

`hosts.discovery` della policy: `auto` (default, anche se il campo manca) o `off`, **modalità stretta**, dove ogni host non
dichiarato esce come `host:unlisted` (byte per byte come prima della v1.5). Il blocco `hosts` è scritto nel corpo compilato
solo per `off`; un valore diverso o un campo in più rifiuta la policy (`policy_rejected`). Il dominio registrabile
(event.md §5.4) è solo zona B: l'SDK non lo calcola.

### PHP semplice (senza framework né PSR-7)

```php
// public/index.php, prima di qualsiasi output
\TrafficTwin\Integration\Native::install();
```

Legge la richiesta dal SAPI (`getallheaders()` o `$_SERVER`, `php://input`) e la risposta con un output buffer
che passa ogni byte invariato a blocchi di 8 KiB (download grandi e `flush()` continuano a funzionare), più
`headers_list()` e `http_response_code()` alla chiusura. Niente `framework_route`: i template vengono dalla policy.

## Header grezzi: cosa vede PHP

PHP non mostra i byte esatti inviati dal client (sanitizer §8.0). L'SDK usa, in ordine:

1. le mappe di header dei messaggi PSR-7 / di Symfony HttpFoundation (nomi e valori separati come li ha
   tenuti la factory);
2. `getallheaders()` (Apache, FPM da 7.3, FrankenPHP, server CLI) e, dove manca, `$_SERVER`.

Differenze note rispetto alle altre sorgenti — tutte *tolgono* informazione, nessuna apre dati:

- con FastCGI i nomi arrivano come `HTTP_X_FOO_BAR`: `X-Foo-Bar` e `X_Foo_Bar` sono indistinguibili e
  il nome ricostruito è `x-foo-bar` (nginx scarta già gli header con `_`);
- i valori ripetuti possono essere già uniti dal web server con `, ` (equivale al punto 4 di §8.0);
- `Authorization` manca in `$_SERVER` con Apache/CGI se il server non lo inoltra
  (`SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1`, `fastcgi_param HTTP_AUTHORIZATION`): senza,
  un soggetto letto da quell'header non si trova e il campionamento ricade su trace/casuale;
- con `multipart/form-data` PHP consuma il corpo prima dell'app (`php://input` è vuoto salvo
  `enable_post_data_reading = Off`, e `$_POST`/`$_FILES` non sono i byte grezzi): in ingresso (nativo, PSR-15,
  Laravel, Symfony) l'evento riporta `trunc:size` (corpo non consumato) e, con `bodies.multipart`, `fmt: "multipart"`,
  mai il contenuto. Il sanitizer analizza il multipart (§22.3) **solo sui byte grezzi** che riceve: in uscita con
  Guzzle (`MultipartStream`) e in ingresso solo se il runtime passa il corpo grezzo (per esempio
  `enable_post_data_reading = Off`) il trattamento è completo. Non si usa mai il parsing multipart di PHP.

## Corpi della spec v1.19 (§22)

Gli interruttori arrivano nella policy firmata (`bodies`, assente = tutto spento, comportamento precedente byte per byte):

- **XML e SOAP** (`bodies.xml`): `application/xml`, `text/xml`, `*+xml`. Analizzatore scritto a mano sul sottoinsieme
  rigoroso di §22.2 (`src/Sanitizer/XmlParser.php`): **mai** `ext-xml`, SimpleXML, DOM o XMLReader, quindi niente
  DTD, entità esterne o espansione di entità (`<!DOCTYPE`, entità sconosciute, più di 256 elementi annidati →
  `trunc:invalid-xml`). Escono anche `fmt` (`xml`/`soap11`/`soap12`), `xmlns` e, nella richiesta, `soap_action`.
- **multipart/form-data** (`bodies.multipart`): sui byte grezzi del corpo (vedi il limite sopra per l'ingresso);
  le parti file escono sempre `drop:file:<tipo>:<classe>`.
- **Documenti base64** (`bodies.docs`): la forma `drop:doc:<tipo>:<classe>` per PDF, immagini, Office, zip.
- **Corpi grandi** (`bodies.max_large_body_bytes`): la cattura tiene `max(max_body_bytes, max_large_body_bytes) + 1`
  byte del corpo (tee, `Policy::bodyCaptureLimit()`) e il sanitizer applica `large_array` / `large_nested_array`.
  Attenzione alla memoria: in PHP il prefisso resta in RAM fino alla sanificazione.

## Contesto, campionamento, OpenTelemetry

- `traceparent` si **legge** dalla richiesta; se manca e l'app usa OpenTelemetry per PHP
  (`open-telemetry/api`), si legge lo span attivo (`Span::getCurrent()`), sola lettura. L'SDK non registra
  mai un `TracerProvider`, un propagatore, un contesto o un globale (c'è un test che lo verifica), non crea
  span e non inietta `traceparent`.
- Il contesto della richiesta in corso è una proprietà statica: va bene per PHP-FPM, Apache, il server CLI
  e i worker sincroni (RoadRunner, FrankenPHP in modalità worker). **Non** per runtime che intercalano più
  richieste nello stesso processo (Swoole/OpenSwoole con coroutine): lì le chiamate in uscita non
  erediterebbero la decisione giusta.
- Campionamento per utente: HMAC con la chiave locale, stabile per tutta l'epoch; baggage `tt.s` solo con
  `trust_baggage` e servizi `internal`; propagazione solo verso gli host di `propagate_to`, mai verso una
  `base` della policy (sanitizer §12).

## Runtime di lungo periodo (RoadRunner, FrankenPHP worker, Swoole)

Lì `shutdown` non c'è a ogni richiesta. L'SDK sceglie da solo (`Runtime::$deferMode`): `shutdown` sotto FPM,
Apache, litespeed e server CLI; `now` per il resto, cioè sanifica dentro il middleware (il costo sta sul percorso
della richiesta, circa 100 µs). Per spostarlo dopo l'invio della risposta:

```php
$rt = \TrafficTwin\Runtime::get();
$rt->deferMode = 'manual';          // le richieste si accodano
while ($req = $worker->waitRequest()) {
    $worker->respond($app->handle($req));
    $rt->processPending();          // sanifica e scrive nello spool, a risposta già inviata
}
```

La coda per processo è limitata (2 000 scambi / 64 MiB): oltre, gli scambi si scartano e si contano.

## Modello di fiducia della cartella di stato

`TT_STATE_DIR` è zona A: contiene la chiave privata del certificato (solo lo shipper la legge), la policy e lo spool.
La firma Ed25519 e il pinning proteggono da `tt-core` compromesso o da chi sta sulla rete; **non** da chi può
scrivere nella cartella (può comunque leggere la chiave HMAC dall'ambiente e i corpi dalla memoria dell'app). Per
questo la cartella è `0700` e i file `0600`, e vanno assegnati all'utente dei worker. Se più applicazioni condividono
il pool FPM, usate una cartella e un utente per applicazione.

Una cartella di stato o di spool **già esistente** e più aperta (per esempio `0755` o `0777` creata dal deploy) viene
ristretta a `0700` all'avvio, se appartiene all'utente del processo; altrimenti è rifiutata: lo shipper esce con
codice 2 e i worker non scrivono nulla (nessuna cattura). Anche un segmento di spool più aperto di `0600` è ristretto
prima di scriverci.

**TLS (red team round 2, RT-PHP-1).** All'iscrizione la catena del server deve verificarsi contro la sola radice
fissata nel token (nessun archivio di sistema, nessun certificato autofirmato accettato, nome host verificato);
dopo l'iscrizione contro la sola catena della Fleet CA ricevuta, i cui certificati e il certificato client devono
risalire alla radice fissata. Le risposte compresse sono decompresse a pezzi con lo stesso tetto in byte della
risposta (8 MiB per policy e heartbeat, 64 KiB per l'intake): oltre, la risposta si rifiuta (`response_too_large`).

## Fail-closed, interruttore, scadenza

Il worker cattura **solo se** tutte queste condizioni valgono (`Runtime::state()` dice quale manca):

| Condizione | Stato se manca |
|---|---|
| `TT_STATE_DIR` presente e SDK non disattivato | `not_configured`, `disabled` |
| `ext-sodium` disponibile (senza non si verifica nessuna firma) | `sodium_missing` |
| `status.json` presente | `no_status` |
| nessun interruttore né revoca | `killed` |
| lo shipper ha ricevuto un heartbeat in questa esecuzione | `starting` |
| ultimo contatto con `tt-core` più recente di `policy_max_age_s` (24 h) | `expired_policy` |
| policy firmata presente, firma valida con una chiave fissata e non revocata, schema, gruppo, `not_after`, `issued_seq ≥ min_issued_seq` | `no_policy`, `policy_rejected`, `expired_policy` |
| chiave HMAC valida con il `kid` della policy | `key_missing`, `key_mismatch` |

Lo shipper, che ha la storia, aggiunge il controllo che `issued_seq` cresca e scarta le policy
riprodotte. Se si ferma, `last_contact` invecchia e dopo `policy_max_age_s` i worker smettono da soli. Lo
stato dell'interruttore è in `state.json` e resta valido dopo un riavvio finché un heartbeat non dice il
contrario; con l'interruttore (o la revoca) lo spool viene svuotato. Una policy rifiutata non sostituisce
mai la precedente valida.

Il verdetto si memoizza per un secondo nei processi che vivono più di una richiesta; un worker FPM lo
ricalcola a ogni richiesta (vedi "Overhead").

## Overhead

Misure in processo (nessuna rete), PSR-7 di `guzzlehttp/psr7`, policy con 6 regole di corpo, richiesta
JSON da ~280 byte e risposta da ~130, opcache attiva, container Docker su Apple silicon. Riproducibile con
`scripts/test.sh 8.3 php -d opcache.enable_cli=1 bench/overhead.php`.

Microsecondi per richiesta, PHP 8.3 (8.1 e 8.4 differiscono di meno del 5%; `p50` / `p99`):

| Scenario | Costo aggiunto alla richiesta | Note |
|---|---|---|
| SDK installato, non cattura (nessuna policy, interruttore, ecc.) | ~0 µs (p50 -0,1) | Un worker FPM paga in più la lettura di `status.json`: ~5 µs |
| Cattura attiva, scambio **non** campionato | +9 µs (p99 +17) | Decisione di campionamento (un HMAC), contesto |
| Scambio campionato, **sul percorso della richiesta** | +13 µs (p99 +32) | Decisione, lettura del prefisso dei corpi senza spostarli, passaggio alla coda |
| Scambio campionato, **dopo la risposta** | ~100 µs di CPU | Sanificazione, serializzazione canonica, `fopen/flock/fwrite` nello spool. Sotto PHP-FPM gira in una shutdown function dopo `fastcgi_finish_request()`: il client ha già la risposta |
| Chiamata in uscita (Guzzle) campionata | +8 µs sulla chiamata, ~65 µs dopo | Il resto come sopra |
| **Primo uso del verdetto in un processo** | ~245 µs (p99 261) | Legge `status.json` e la policy firmata, verifica la firma Ed25519 (39 µs), valida lo schema, costruisce la policy, legge la chiave. Ogni richiesta PHP-FPM è un processo "nuovo" per le variabili statiche, quindi lo paga **ogni richiesta**, campionata o no; i worker di lungo periodo lo pagano al più una volta al secondo |

Quindi, sotto PHP-FPM e per una richiesta tipica: **~0,26 ms** prima della risposta (verdetto + decisione: circa il 2% di una
richiesta da 12 ms, per fare un esempio) e ~0,1 ms dopo la risposta solo per gli scambi campionati. Il costo del verdetto è la voce da ridurre
se serve: l'ottimizzazione prevista (non fatta, perché sposterebbe la fiducia in una cache condivisa tra richieste) è
una cache APCu del `Policy` già verificato, chiavi dalla somma SHA-256 di busta e chiavi fissate. Con opcache
attiva il costo del codice dell'SDK è già incluso; senza opcache le cifre salgono molto (ogni richiesta ricompila ~60
file): **usate opcache**.

## Sviluppo e test

Tutto gira nelle immagini Docker ufficiali `php:*-cli` (PHP non serve sulla macchina):

```bash
sdk/php/scripts/test.sh 8.3             # composer install + tutta la suite (unit + integrazione)
sdk/php/scripts/test.sh 8.1 vectors     # solo i vettori di conformità (726 con la spec v1.19)
sdk/php/scripts/test.sh 8.4 php -d opcache.enable_cli=1 bench/overhead.php
```

| Suite | Cosa prova |
|---|---|
| `tests/Unit/VectorsTest` | Tutti i vettori di `conformance/vectors`, byte per byte |
| `tests/Unit/BodiesTest` | Spec v1.19: XML ostile (DOCTYPE, entità, annidamento, riferimenti), casi limite del multipart, documenti base64, validazione di `bodies`, `code(alnum)` e dei passi `.@nome` / `.#text` |
| `tests/Unit/HostPatternTest` | Host (spec v1.5): esempi di sanitizer.md §3.5, parser IPv6, tabella delle classi, modalità stretta, rifiuto del blocco `hosts`, G1 con le etichette degli host |
| `tests/Unit/GateTest` | Matrice fail-closed: interruttore, scadenza, firma, gruppo, chiave, `min_issued_seq`… |
| `tests/Unit/Psr15Test`, `GuzzleTest`, `HeadersTest`, `OtelTest`, `SpoolTest`, `ShipperTest`, `JsonTest` | Cattura PSR-15 e Guzzle, tee dei corpi, header, OpenTelemetry senza globali, scritture concorrenti nello spool, tokenizzatore JSON |
| `tests/Integration/FrameworkRouteTest` | `framework_route` da router veri: Laravel (gruppi annidati) e Symfony (collezioni con prefisso) |
| `tests/Integration/EndToEndTest` | Server built-in PHP (app PSR-15 con Guzzle, script PHP semplice) + carrier + `tt-core` finto (TLS con la radice nella catena, mTLS, CSR vera): iscrizione con e senza CSR, policy, cattura, invio, interruttore, replay, revoca, rinnovo del certificato, rotazione e revoca delle chiavi, pin sbagliato, ripetizioni, SIGTERM |
| `tests/Integration/PackageTest` | `composer install` da consumatore: nessuna dipendenza a runtime, `vendor/bin/tt-shipper` |

Il `tt-core` finto è `tests/support/fake-core.php` (solo PHP: `openssl_csr_sign`, `stream_socket_server`
con TLS, firme Ed25519 con sodium); il suo certificato server ha SAN `localhost`.

## Limiti noti e deviazioni

- **Un processo in più** (lo shipper) o un cron `--once`. Con `--once` la latenza di consegna è quella del cron.
- `Authorization`, header con `_` e `multipart`: vedi sopra.
- Runtime a coroutine: contesto non supportato (vedi sopra).
- Corpi di risposta non seekable (`StreamedResponse`, generatori) con la modalità di sanificazione immediata
  (CLI, RoadRunner, Swoole): non si aspetta il flusso, l'evento riporta `trunc:size`. Con FPM/Apache la
  sanificazione avviene dopo l'emissione e il flusso si legge.
- `deflate` grezzo (RFC 1951) non è decodificabile da `ext-zlib` come zlib: `drop:bytes` (nota di §9.0).
- Senza `ext-zlib` i corpi compressi escono `drop:bytes` (una sorgente con zlib darebbe la forma); senza
  `ext-sodium` non si cattura.
- Nessun controllo di coerenza HTTP/2 (PHP non vede pseudo-header).
- I contatori dell'heartbeat sono approssimati: ogni worker scrive il proprio file ogni ~2 s e a ogni evento.
- Non c'è un adattatore per `curl_*` / `file_get_contents` / il client HTTP di Symfony: solo Guzzle (la strada
  decisa in ARCHITECTURE §3.1). Per gli altri client servirebbe un decoratore equivalente.
