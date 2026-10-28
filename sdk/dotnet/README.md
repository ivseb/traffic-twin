# TrafficTwin.Sdk (.NET)

SDK di cattura di traffic-twin per .NET 8 o successivo (provato su .NET 8, 9 e 10). Osserva le chiamate HTTP in ingresso
(ASP.NET Core) e in uscita (`HttpClient`) del processo, le **sanifica nel processo** secondo la policy firmata (specifica
`docs/spec/sanitizer.md` v1.1.1, fino alla v1.19) e invia a `tt-core` solo forme, token HMAC e valori ammessi dalla policy, come log
OTLP/HTTP JSON su mTLS.

Due pacchetti NuGet:

| Pacchetto | Contenuto | Dipendenze |
|---|---|---|
| `TrafficTwin.Sdk` | sanitizer, verifica della policy, Ed25519, client Fleet, esportatore OTLP, `TrafficTwinAgent`, `TrafficTwinHandler` | **nessuna** (solo la BCL) |
| `TrafficTwin.Sdk.AspNetCore` | middleware in ingresso, `AddTrafficTwin()`, servizio ospitato | `TrafficTwin.Sdk` e il framework condiviso `Microsoft.AspNetCore.App` |

- **Zero dipendenze a runtime** oltre alla BCL e al framework condiviso ASP.NET Core. Nessun pacchetto OpenTelemetry (lo
  verifica un test sugli assembly referenziati).
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato, nessun nuovo `Activity`, nessun `ActivityListener`,
  nessun `TracerProvider`. L'unica eccezione, opzionale e decisa dalla policy, è il membro di baggage `tt.s` verso gli host di
  `sampling.propagate_to` (mai verso un host esterno della policy).
- **Fail-closed**: senza policy valida, chiave HMAC o primo heartbeat non cattura nulla; l'app continua a funzionare.
- **Nessun payload nei log**: con `TT_DEBUG=1` si scrivono su stderr solo codici di stato e di errore.

## ASP.NET Core

```csharp
using TrafficTwin.Sdk.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddTrafficTwin();          // legge TT_* dall'ambiente; AddTrafficTwin(o => o.ServiceName = "shop-api") per il codice
builder.Services.AddHttpClient("carrier");  // ogni client della IHttpClientFactory passa da TrafficTwinHandler

var app = builder.Build();
app.UseTrafficTwin();                       // PER PRIMO nella pipeline: vede ciò che viaggia sul filo
app.MapPost("/orders", ...);
app.Run();
```

`AddTrafficTwin()` avvia in background iscrizione, heartbeat e download della policy (l'avvio dell'app non aspetta) e, allo
spegnimento, svuota le code. Se usi `UsePathBase`, metti `UseTrafficTwin()` **dopo** `UsePathBase`: il prefisso fa parte della
route del framework (sanitizer.md 3.4); altrimenti la route non coincide per numero di segmenti e vale il template della policy
(3.3 punto 2), che è sicuro.

## Iniezione senza codice (`DOTNET_STARTUP_HOOKS`)

Nessuna modifica all'applicazione, nessun riferimento ai pacchetti NuGet: bastano due variabili d'ambiente e la cartella con gli
assembly (su Kubernetes la copia l'init container `sdk-dotnet` e le imposta il webhook con `traffic-twin.io/inject: dotnet`).

```bash
dotnet publish src/TrafficTwin.StartupHook -c Release -o /opt/traffic-twin     # hook + TrafficTwin.Sdk + TrafficTwin.Sdk.AspNetCore
TT_ENROLL_URL=https://tt-core.internal:4318 TT_ENROLL_TOKEN=tte_… TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key TT_SERVICE_NAME=shop-api \
DOTNET_STARTUP_HOOKS=/opt/traffic-twin/TrafficTwin.StartupHook.dll \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore \
  dotnet app.dll
```

Due pezzi, entrambi **inerti senza `TT_ENROLL_URL` o con `TT_DISABLED=1`**:

| Pezzo | Cosa fa |
|---|---|
| `TrafficTwin.StartupHook.dll` (`DOTNET_STARTUP_HOOKS`) | gira prima del `Main`: registra su `AssemblyLoadContext.Default.Resolving` la cartella dell'hook (l'app non ha `TrafficTwin.*` nel suo `deps.json`) e avvia l'agente di processo (`TrafficTwinAgent.Start()`, in background, non blocca). L'agente sottoscrive `HttpHandlerDiagnosticListener`: ogni `HttpClient` del processo è visto (metadati; vedi "Come cattura") |
| `TrafficTwin.Sdk.AspNetCore` (`ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`) | `IHostingStartup` (`TrafficTwinHostingStartup`): un `IStartupFilter` mette `TrafficTwinMiddleware` **per primo** nella pipeline, ogni client di `IHttpClientFactory` riceve `TrafficTwinHandler` (corpi inclusi), e lo svuotamento delle code allo spegnimento |

Non imposta `ActivityListener`, `TracerProvider`, propagatori né altri default di processo; non aggiunge `traceparent` (test sul filo).
L'ordine dei `DOTNET_STARTUP_HOOKS` è quello della variabile: il webhook accoda il nostro dopo gli esistenti (per esempio
quello di OpenTelemetry .NET Automatic Instrumentation), che quindi girano prima. Il separatore è `:` su Linux (`;` su Windows;
l'init image e il webhook sono solo Linux).

**Limiti.**

- Solo ASP.NET Core (Kestrel, IIS in-process, HTTP.sys): un worker senza web host ha solo la cattura in uscita da `DiagnosticListener`.
- `HttpClient` creati a mano (`new HttpClient()`) escono come metadati: i corpi sono `trunc:size` (il listener non vede i byte).
  Quelli di `IHttpClientFactory` passano da `TrafficTwinHandler` e hanno i corpi.
- Con `UsePathBase` la route del framework non coincide (il middleware sta fuori dalla pipeline dell'app): vale il template della policy,
  che è sicuro (§3.3 punto 2). Per la route esatta usare `UseTrafficTwin()` dopo `UsePathBase` e non l'iniezione.
- Non combinare con `AddTrafficTwin()` nel codice: l'iniezione si fa da parte (middleware e handler non si aggiungono due volte),
  ma resterebbero due agenti, uno per l'hook e uno per il codice.
- App NativeAOT o con `StartupHookSupport=false` (trimming): il runtime non esegue gli startup hook.

## Senza ASP.NET Core

```csharp
var agent = TrafficTwinAgent.Start();                       // idempotente, non lancia, non blocca
using var http = new HttpClient(new TrafficTwinHandler());  // oppure new TrafficTwinHandler(innerHandler)
```

Anche i `HttpClient` creati **senza** il nostro handler (`new HttpClient()`) sono visti dall'agente: tramite i
`DiagnosticListener` `HttpHandlerDiagnosticListener` (eventi `System.Net.Http.Request/Response/Exception`) si cattura la
chiamata con metodo, URL, header, stato ed errori di rete; i **corpi** non sono visibili da lì e escono come `trunc:size`.

## Host non dichiarati (spec v1.5)

Una chiamata verso un host che nessuna `base` della policy né `segments.hosts_allow` copre esce con
`service: host:<pattern>`: etichette minuscole che passano la regola dell'etichetta sicura
(`^[a-z][a-z0-9-]{0,62}$`, senza 6 cifre né 12 esadecimali consecutivi), altrimenti `{*}`; porta solo se non di default;
IPv4 e IPv6 tra parentesi escono solo come `ip:private` / `ip:public` (tabella chiusa della spec, parser IPv6 proprio in
`HostPattern`, niente `IPAddress.TryParse`). Esempi: `host:api.carrier.example`, `host:{*}.tenant.example`, `host:ip:private:8080`.
L'host è quello che vede il client (`Uri.Host`: parentesi per IPv6, punto finale incluso, nessuna conversione IDN); un host Unicode
resta `host:invalid`. Vale per `TrafficTwinHandler`, per il `DiagnosticListener` e quindi per l'iniezione senza codice (hook di avvio).

`hosts.discovery` della policy: `auto` (default, anche se il campo manca) o `off`, **modalità stretta**, dove ogni host non
dichiarato esce come `host:unlisted` (byte per byte come prima della v1.5). Il blocco `hosts` è scritto nel corpo compilato
solo per `off`; un valore diverso o un campo in più rifiuta la policy (`policy_rejected`). Il dominio registrabile
(event.md §5.4) è solo zona B: l'SDK non lo calcola.

## Codici alfanumerici, XML/SOAP, multipart, documenti e corpi grandi (spec v1.19)

L'SDK implementa la v1.19 del sanitizer (sanitizer.md §5.6 e §22; vettori 2200–2453). Senza `bodies` e senza `code(alnum)`
l'uscita è identica alle versioni precedenti, byte per byte.

- `{"action":"code","shape":"alnum"}`: il valore esce come `keep:` se rispetta `^[A-Za-z0-9_.-]{1,16}$` (ed entro
  `keep_max_bytes`); qualsiasi altra `shape`, o una `shape` su un'altra azione, rifiuta la policy. H1/H2 la trattano come `code`.
- `tt-path` con i passi `.@nome` (attributi XML) e `.#text` (testo misto).
- `bodies` (tutti e sei i campi obbligatori; assente = tutto spento):
  - `xml`: `application/xml`, `text/xml` e `*+xml` (anche SOAP 1.1/1.2) con un parser **scritto a mano** sul sottoinsieme
    rigoroso di §22.2 (niente `System.Xml`: nessuna DTD, nessuna entità oltre le cinque predefinite, al massimo 256 livelli);
    fuori dal sottoinsieme `trunc:invalid-xml`. In uscita `fmt` (`xml`/`soap11`/`soap12`), `xmlns` e, nella richiesta, `soap_action`;
  - `multipart`: `multipart/form-data` come un form, le parti file come `drop:file:<tipo>:<classe>`; errori `trunc:invalid-multipart`;
  - `docs`: le stringhe che sono il base64 (anche url, senza `=`, o `data:…;base64,`) di un documento escono come
    `drop:doc:<tipo>:<classe>` (decoder base64 proprio: `Convert.FromBase64String` rifiuta l'alfabeto url e l'assenza di `=`);
  - `max_large_body_bytes`, `large_array`, `large_nested_array`: corpi analizzabili oltre `max_body_bytes` (fino al limite
    grande) con tetti propri sugli array esterni e annidati. La cattura conserva `max(max_body_bytes, max_large_body_bytes) + 1`
    byte del corpo (`Policy.CaptureLimit`), anche la decodifica gzip/deflate.

## Variabili d'ambiente

| Variabile | Significato |
|---|---|
| `TT_ENROLL_URL` | URL del listener Fleet/intake di `tt-core` (sempre `https`) |
| `TT_ENROLL_TOKEN` | Token di iscrizione `tte_<segreto>.<impronta CA>`, monouso o di gruppo |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, una o più righe `<kid>:<base64url>` (§7.1). Non viaggia mai verso `tt-core` |
| `TT_SERVICE_NAME` | Nome di servizio richiesto all'iscrizione (altrimenti `OTEL_SERVICE_NAME` in minuscolo). Negli eventi compare quello **assegnato** da `tt-core` |
| `TT_STATE_DIR` | Stato locale (default `~/.traffic-twin/<id>`): certificato, chiave privata, CA, policy firmata, interruttore. Cartella `0700` (anche `~/.traffic-twin`; una cartella propria più larga viene riportata a `0700`, una di un altro utente è rifiutata e si usa una cartella temporanea privata), file `0600` e letti solo se non symlink e non scrivibili da gruppo/altri (su Unix; su Windows valgono le ACL del profilo) |
| `TT_ENROLL_CSR` | `0` per far generare la chiave a `tt-core` (default: CSR ECDSA P-256 con `CertificateRequest`, la chiave privata non esce dal processo) |
| `TT_DISABLED` | `1` disattiva completamente l'SDK |
| `TT_DEBUG` | `1` scrive su stderr solo codici di stato ed errore |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS` | Solo per test: sostituiscono gli intervalli ricevuti da `tt-core` |

## Come cattura

| Direzione | Aggancio | Corpo |
|---|---|---|
| Ingresso | middleware ASP.NET Core | per gli scambi **campionati** `Request.Body` e `Response.Body` sono sostituiti da flussi pass-through che copiano i primi `max(max_body_bytes, bodies.max_large_body_bytes) + 1` byte e contano il resto (§9.0, §22.5) |
| Uscita (factory o `new TrafficTwinHandler()`) | `DelegatingHandler` | `HttpContent` di richiesta e risposta incapsulati: la risposta resta **in streaming** (nessun buffering), un ripetizione dell'invio azzera la copia |
| Uscita (qualsiasi `HttpClient`) | `HttpHandlerDiagnosticListener` | solo metadati (vedi sopra) |

La sottoscrizione al listener abilita **solo** gli eventi `System.Net.Http.Request/Response/Exception` e mai
`System.Net.Http.HttpRequestOut`: così il runtime non crea Activity né aggiunge `traceparent` per colpa nostra (c'è un test che
lo verifica sul filo). Normalizzazione, sanificazione, serializzazione e invio avvengono dopo la risposta, in task di
background; la coda di sanificazione è un `Channel<T>` limitato (2 000 scambi / 64 MiB) e quella di invio scarta i più vecchi
(10 000 eventi / 16 MiB): l'app non aspetta mai.

**Contesto.** Un `AsyncLocal` lega le chiamate in uscita allo scambio in ingresso (stesso `trace_id`, campionamento ereditato,
`parent_span_id` = `span_id` dell'evento in ingresso). Il `traceparent` in ingresso e `Activity.Current` (OpenTelemetry o
quello di ASP.NET Core) sono solo **letti**: se esiste un `Activity`, il `span_id` dell'evento in ingresso è quello del suo
span server e il `trace_id` quello della sua traccia.

**Route del framework.** Dal `RouteEndpoint.RoutePattern.RawText` (completo di gruppi `MapGroup`, `[Route]` dei controller e
`PathBase`), normalizzata secondo la riga "ASP.NET Core" di §3.4 (`{id:int:min(1)}` → `{id}`; `{id?}`, `{id=5}`, `{*rest}`
non normalizzabili → si passa ai template della policy).

## Fleet

- **Iscrizione**: prima connessione TLS che non si fida di nulla, il server deve presentare la catena fino alla **radice**
  (come fa `tt-core`); la radice deve essere una CA autofirmata con SHA-256 uguale al pin del token e il certificato del
  server deve risalire a essa e corrispondere al nome host. Poi richiesta di iscrizione con CSR PKCS#10 (`CertificateRequest`).
  Certificato e chiave restano nello stato locale (scrittura atomica, permessi `0600`) e si riusano ai riavvii. Il token non
  viene mai salvato.
- **mTLS**: unica ancora di fiducia la catena CA ricevuta all'iscrizione (non l'archivio di sistema); certificato client con
  `SslClientAuthenticationOptions.ClientCertificateContext`.
- **Heartbeat prima di qualsiasi cattura**; interruttore di emergenza, revoca e `min_issued_seq` sono salvati in `state.json` e
  restano validi dopo un riavvio. La cattura parte solo dopo un heartbeat riuscito in questo processo (anche con policy in cache).
- **Policy**: firma Ed25519 su `"tt.policy.body/v1" || 0x00 || corpo` con chiavi fissate e non revocate (Ed25519 scritto per
  RFC 8032, verificato con i vettori della RFC e con 128 vettori di riferimento), schema completo del corpo, coerenza
  busta/corpo, gruppo, `not_after`, `issued_seq` crescente e ≥ `min_issued_seq`. Una policy rifiutata non sostituisce mai la
  precedente valida. Nuove chiavi di firma solo se approvate da una chiave già fissata; `revoke_signing_keys` scarta subito la
  policy firmata con la chiave revocata.
- **Invio**: OTLP/HTTP JSON a lotti (≤ 512 eventi, ≤ 4 MiB), ripetizioni con attesa esponenziale e `Retry-After` su
  429/502/503/504 ed errori di rete (al massimo 5), scarto senza ripetere su 400/401/403/413.

## Parti normative scritte da zero

- **JSON**: tokenizzatore iterativo proprio che conserva i lessemi dei numeri, rifiuta BOM, UTF-8 non valido (RFC 3629 stretto),
  virgole finali, commenti, `NaN`, valori multipli; valida l'intero corpo anche oltre `max_depth`; segnala gli escape
  `\uD800`–`\uDFFF` spaiati. (`Utf8JsonReader` non è usato: non distingue gli escape spaiati in modo uniforme.)
- **gzip/deflate**: inflate (RFC 1951) proprio con tetto di uscita, per avere lo stesso risultato su ogni runtime: un flusso
  troncato, con byte dopo la fine, con CRC/Adler/ISIZE errati o a più membri è un errore (A-GZIP-STRICT, come il sanitizer
  Go di riferimento); raggiungere il tetto non lo è (`trunc:size`).
- **Ed25519** (solo verifica) su `System.Numerics.BigInteger`; .NET non ha Ed25519 nativo.

## Test

```sh
sdk/dotnet/scripts/dotnet-docker.sh test                      # immagine mcr.microsoft.com/dotnet/sdk:8.0, .NET non è installato sul Mac
TT_DOTNET_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0 TT_DOCKER_ARGS="-e DOTNET_ROLL_FORWARD=LatestMajor" \
  sdk/dotnet/scripts/dotnet-docker.sh test --artifacts-path /tmp/art10   # stessi test su .NET 10 (idem con 9.0)
```

975 test (xUnit):

- **tutti i 726 vettori di conformità** (v1.19) (`conformance/vectors/*.json`), confronto byte per byte;
- Ed25519: RFC 8032 e 128 vettori di riferimento, firme alterate, malleabili (S ≥ L), chiavi e lunghezze errate;
- decoder gzip/zlib (round trip su tutti i livelli, troncamenti, byte in coda, checksum, bomba da 200 MB), parser JSON,
  numeri canonici, tabella di normalizzazione delle route dei 14 framework, verifica delle buste firmate, chiavi HMAC;
- test generativo G1 (policy vuota: nessun valore esce, e ogni etichetta letterale del `service` rispetta la regola degli host) su 1 500 scambi casuali;
- corpi v1.19 (`BodiesTests`): XML ostile (DOCTYPE/XXE, espansione di entità, annidamento, riferimenti), multipart
  (confini, preambolo ed epilogo, intestazioni, virgolette), documenti base64 (alfabeto url, bit di riempimento), limite di cattura;
- host (`HostPatternTests`): esempi di sanitizer.md §3.5, parser IPv6, tabella delle classi, modalità stretta, rifiuto del blocco `hosts`;
- ingresso su `TestServer` e su Kestrel (route, `PathBase`, `traceparent`, baggage, soggetto, limiti, corpi non letti, `HEAD`,
  gzip, 200 richieste concorrenti, risposta da 5 MiB identica byte per byte);
- uscita (handler, listener, streaming, errori di rete, propagazione di `tt.s`);
- **iniezione senza codice** (`ZeroCodeTests`, app `tests/TrafficTwin.TestApp` che non conosce traffic-twin): `WebApplicationFactory<Program>`
  con il solo hosting startup; un **vero processo Kestrel** avviato con `DOTNET_STARTUP_HOOKS` + `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`
  (cartelle `testapp/` e `hook/` pubblicate dal build dei test): eventi in ingresso e in uscita (factory con corpi, `new HttpClient()` come
  metadati), nessun `traceparent`/`baggage` iniettato, cartella dell'app senza `TrafficTwin.*`; inerte senza `TT_ENROLL_URL` o con `TT_DISABLED=1`;
- **tt-core finto su Kestrel reale con mTLS** (`Helpers/FakeCore.cs`): iscrizione con pin, CSR, heartbeat, policy con ETag,
  rinnovo, OTLP, interruttore, revoca, rotazione e revoca delle chiavi di firma, policy riprodotte o scadute;
- **convivenza con OpenTelemetry .NET** (pacchetti OpenTelemetry solo nei test): la stessa app con e senza SDK produce
  gli stessi span (nome, tipo, padre, chiavi dei tag) e le stesse `ActivitySource`; il `traceparent` visto dal corriere è quello
  di OpenTelemetry; gli eventi leggono gli id di `Activity.Current`; i sorgenti dell'SDK non contengono `ActivitySource`,
  `ActivityListener`, `TracerProvider`, propagatori.

## Overhead (`bench/TrafficTwin.Bench`)

```sh
sdk/dotnet/scripts/dotnet-docker.sh run -c Release --project bench/TrafficTwin.Bench -- --seconds 6 --rounds 3
```

Misure su un contenitore Docker con 3 vCPU (Apple Silicon), app minima su Kestrel che risponde in ~7 µs, generatore di carico
in un altro processo, tt-core finto nello stesso processo dell'app. È il **caso peggiore**: l'app non fa nulla, quindi ogni
microsecondo dell'SDK si vede.

| Misura | Risultato |
|---|---|
| Sanificazione + serializzazione di uno scambio con corpo da 2 KB (un thread, in background) | ~47 µs |
| Idem con corpo da 64 KB | ~0,4 ms |
| Tempo sul thread della richiesta (p50 / p99) con campionamento 5 % | 5 µs / 45 µs |
| Idem con campionamento 100 % | 11 µs / 63 µs |
| Latenza p50 aggiunta a 300 richieste/s (anello aperto) | +0,008 ms (5 %), +0,004 ms (100 %) |
| Throughput a saturazione (16 connessioni, anello chiuso) | −13 % (5 %), −69 % (100 %) |

Il −69 % a saturazione con il 100 % di campionamento nasce dal lavoro di sanificazione ed esportazione che compete per le
stesse 3 CPU con un'app che non fa nulla (140 000 richieste/s): per un'app che impiega 1 ms a richiesta il costo di ~50–60 µs
di CPU di background per scambio campionato vale circa il 5 % di una CPU. Il budget di G10 va rimisurato su un laboratorio
dedicato; qui i numeri servono a vedere dove va il tempo.

## Limiti noti e differenze

- Target `net8.0` (LTS): funziona su .NET 8, 9 e 10 (provato). Nessun target `netstandard`/.NET Framework.
- `SendFile` e simili passano dal flusso della risposta per gli scambi campionati (nessuna ottimizzazione `sendfile` per quelli).
- Una richiesta annullata o con timeout di `HttpClient` arriva all'handler come annullamento: esce `net_error: timeout`.
- Il `Host` e gli header aggiunti dal trasporto (`Content-Length` calcolato, `Accept-Encoding` automatico) non sono visibili
  all'handler in uscita; i valori degli header sono ricodificati in Latin-1 (la codifica predefinita di Kestrel e `HttpClient`).
- I corpi richiesti/risposti da `HttpClient` senza il nostro handler non sono catturati (vedi sopra).
- Un `deflate` grezzo (RFC 1951, senza intestazione zlib) è trattato come errore di decodifica (`drop:bytes`); il caso non è
  coperto dai vettori (§9.0).
- Con l'iscrizione "senza CSR" la chiave arriva da `tt-core` e deve essere ECDSA o RSA (`CreateFromPem`).
