# traffic-twin SDK per Java

SDK di cattura di traffic-twin per la JVM. Osserva le chiamate HTTP in ingresso (filtro servlet)
e in uscita (`java.net.http.HttpClient`, Spring `RestTemplate`/`RestClient`, OkHttp), le
**sanifica nel processo** secondo la policy firmata (specifica `docs/spec/sanitizer.md`
fino alla v1.19) e invia a `tt-core` solo forme, token HMAC e valori ammessi dalla policy, come log
OTLP/HTTP JSON su mTLS.

- **Java 17 o successivo.** La firma Ed25519 delle policy usa `java.security`, che la offre
  dal JDK 15; per non scrivere né importare una propria implementazione di RFC 8032 la base è
  Java 17 (LTS). Il bytecode è compilato con `--release 17`; testato su JDK 17 e 21.
- **Zero dipendenze a runtime**: solo il JDK (`javax.crypto`, `java.security`, `java.net.http`,
  `java.util.zip`). Servlet, JAX-RS, Spring e OkHttp sono dipendenze `provided` (solo per
  compilare): le classi che le usano si caricano solo se l'applicazione le ha. JUnit, Jetty,
  OpenTelemetry SDK e OkHttp compaiono solo nei test.
- **Non modifica il traffico dell'app**: nessun `traceparent` iniettato; l'unica eccezione,
  opzionale e decisa dalla policy, è il membro di baggage `tt.s` verso gli host di
  `sampling.propagate_to` (mai verso un host che corrisponde a una `base` della policy).
- **Non registra mai** `GlobalOpenTelemetry`, un `TracerProvider`, un propagatore o un
  `SSLContext`/`Authenticator` predefinito: legge soltanto il contesto OpenTelemetry attivo.
- **Fail-closed**: senza policy valida, chiave HMAC o primo heartbeat non cattura nulla;
  l'app continua a funzionare normalmente.

## Moduli

| Artefatto | Contenuto |
|---|---|
| `io.github.ivseb.traffictwin:sdk` | Sanificatore, client Fleet, esportatore OTLP, filtro servlet **Jakarta** (Servlet 5/6), `TrafficTwinHttpClient`, intercettori Spring e OkHttp, filtro JAX-RS |
| `io.github.ivseb.traffictwin:sdk-servlet-javax` | Lo stesso filtro per `javax.servlet` (Tomcat 8.5-9, Jetty 9-10, WildFly fino alla 26). Generato dalla variante Jakarta con `scripts/gen-javax.sh` |
| `io.github.ivseb.traffictwin:sdk-otel-extension` | Estensione dell'agent OpenTelemetry Java: hook di sola lettura, nessuna dipendenza |
| `io.github.ivseb.traffictwin:sdk-agent` | Agent `-javaagent` per l'iniezione senza codice: un solo jar senza dipendenze (vedi "Iniezione senza codice") |

## Avvio

Le variabili d'ambiente bastano; non serve scrivere codice per avviare l'agente.

```bash
TT_ENROLL_URL=https://tt-core.internal:4318 \
TT_ENROLL_TOKEN=tte_… \
TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key \
TT_SERVICE_NAME=shop-api \
  java -jar app.jar
```

| Variabile | Significato |
|---|---|
| `TT_ENROLL_URL` | URL del listener Fleet/intake di `tt-core` (sempre `https`) |
| `TT_ENROLL_TOKEN` | Token di iscrizione `tte_<segreto>.<impronta CA>`, monouso o di gruppo |
| `TT_HMAC_KEY` / `TT_HMAC_KEY_FILE` | Chiave HMAC locale, una o più righe `<kid>:<base64url>` (§7.1). Non viaggia mai verso `tt-core` |
| `TT_SERVICE_NAME` | Nome di servizio richiesto all'iscrizione (altrimenti `OTEL_SERVICE_NAME` in minuscolo). Negli eventi esce il nome **assegnato** da `tt-core` |
| `TT_STATE_DIR` | Cartella dello stato locale (default `~/.traffic-twin/<id>`), `0700` |
| `TT_KEYSTORE_PASSWORD` | Password del PKCS#12 con la chiave client (se assente se ne genera una casuale, salvata in `keystore.pass` `0600`) |
| `TT_DISABLED` | `1` disattiva completamente l'SDK |
| `TT_DEBUG` | `1` scrive su stderr solo codici di stato ed errore (mai valori) |
| `TT_EXPORT_GZIP` | `1` comprime con gzip i corpi OTLP |
| `TT_HEARTBEAT_INTERVAL_MS`, `TT_POLICY_POLL_INTERVAL_MS`, `TT_EXPORT_FLUSH_MS` | Solo per test: sostituiscono gli intervalli ricevuti da `tt-core` |

L'iscrizione, l'heartbeat e il download della policy avvengono su un thread in background (daemon):
non ritardano l'avvio dell'app.

### Filtro servlet (ingresso)

Va registrato **per primo** nella catena, per i dispatcher `REQUEST` e `ASYNC`.

```xml
<!-- web.xml -->
<filter><filter-name>traffic-twin</filter-name><filter-class>io.github.ivseb.traffictwin.servlet.TrafficTwinFilter</filter-class></filter>
<filter-mapping><filter-name>traffic-twin</filter-name><url-pattern>/*</url-pattern>
  <dispatcher>REQUEST</dispatcher><dispatcher>ASYNC</dispatcher></filter-mapping>
```

```java
// Spring Boot 3
@Bean FilterRegistrationBean<TrafficTwinFilter> tt() {
    var r = new FilterRegistrationBean<>(new TrafficTwinFilter());
    r.setOrder(Ordered.HIGHEST_PRECEDENCE);
    r.addUrlPatterns("/*");
    r.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ASYNC);
    return r;
}
```

Con `TT_ENROLL_URL` impostata il filtro avvia da solo l'agente (`init`), e l'inizializzatore
(`ServletContainerInitializer`, in entrambi i jar) lo registra da solo nelle applicazioni web: senza la
variabile non fa nulla. Per `javax.servlet` usa `io.github.ivseb.traffictwin.servlet.javax.TrafficTwinFilter`
(modulo `sdk-servlet-javax`).

Il filtro avvolge richiesta e risposta **solo degli scambi campionati**: copia i primi
`max_body_bytes + 1` byte e conta il resto (tee, §9.0) senza mai alterare i byte; gli scambi non
campionati passano senza wrapper. Sanificazione ed esportazione avvengono dopo la risposta su un
esecutore limitato (coda di 2 000 scambi, 64 MiB); se è pieno lo scambio si scarta e si conta,
l'app non aspetta mai. Gli scambi asincroni (`startAsync`) si chiudono su `onComplete`.

`framework_route` (§3.4):

- **Spring MVC**: attributo `HandlerMapping.bestMatchingPattern`, completato con il context path
  e, per un `DispatcherServlet` mappato a prefisso (`/api/*`), con il servlet path. I pattern con
  `*`, `**` o `{*nome}` non si normalizzano e si usano i template della policy (§3.3 punto 2).
- **JAX-RS** (Jersey, RESTEasy, CXF): registra `io.github.ivseb.traffictwin.integration.TrafficTwinJaxrsFilter`
  come provider; compone base URI + `@Path` della classe + `@Path` del metodo.
- **Agent OpenTelemetry**: vedi sotto.

### Chiamate in uscita

```java
HttpClient http = TrafficTwinHttpClient.wrap(HttpClient.newHttpClient());   // java.net.http
restTemplate.getInterceptors().add(new TrafficTwinClientInterceptor());      // Spring
new OkHttpClient.Builder().addInterceptor(new TrafficTwinOkHttpInterceptor()).build(); // OkHttp
```

Le chiamate fatte mentre un thread serve una richiesta in ingresso ereditano la decisione di
campionamento e il `trace_id` di quella richiesta (`sampled_by: inherited`, `parent_span_id` = span
dell'ingresso); fuori da una richiesta (job, timer) valgono trace o caso. Se la cattura fallisce per
qualsiasi motivo la chiamata prosegue senza wrapper. Il client dell'SDK stesso (heartbeat, policy,
esportatore) è un `HttpClient` semplice, mai avvolto: non si cattura da solo.

### Host non dichiarati (spec v1.5)

Una chiamata verso un host che nessuna `base` della policy né `segments.hosts_allow` copre esce con
`service: host:<pattern>`: etichette minuscole che passano la regola dell'etichetta sicura
(`^[a-z][a-z0-9-]{0,62}$`, senza 6 cifre né 12 esadecimali consecutivi), altrimenti `{*}`; porta solo se non di default;
IPv4 e IPv6 tra parentesi escono solo come `ip:private` / `ip:public` (tabella chiusa della spec, parser IPv6 proprio in
`HostPattern`, niente `InetAddress`). Esempi: `host:api.carrier.example`, `host:{*}.tenant.example`, `host:ip:private:8080`.
Gli host sono quelli che vede il client: le integrazioni passano l'host così com'è (parentesi per IPv6, punto finale
incluso, nessuna conversione IDN); un host Unicode resta `host:invalid`.

`hosts.discovery` della policy: `auto` (default, anche se il campo manca) o `off`, **modalità stretta**, dove ogni host non
dichiarato esce come `host:unlisted` (byte per byte come prima della v1.5). Il blocco `hosts` è scritto nel corpo compilato
solo per `off`; un valore diverso o un campo in più rifiuta la policy (`policy_rejected`). Il dominio registrabile
(event.md §5.4) è solo zona B: l'SDK non lo calcola.

### Corpi XML/SOAP, multipart, documenti e corpi grandi (spec v1.19)

Con l'oggetto `bodies` della policy (assente = tutto spento, uscita identica alle versioni precedenti):

- `xml`: i corpi `application/xml`, `text/xml` e `*+xml` diventano un albero (attributi `@nome`, testo misto
  `#text`, elementi ripetuti come array) letto da un analizzatore proprio, sottoinsieme rigoroso di XML 1.0
  (classe `Bodies`, nessun `javax.xml`/SAX/StAX): niente DTD né entità diverse dalle cinque predefinite e dai
  riferimenti numerici, al massimo 256 livelli; qualsiasi altra cosa dà `trunc:invalid-xml`. Escono anche `fmt`
  (`xml`/`soap11`/`soap12`), `xmlns` (pattern degli spazi dei nomi) e, per la richiesta, `soap_action`.
- `multipart`: i corpi `multipart/form-data` escono come un form; le parti file solo come
  `drop:file:<tipo>:<classe>`.
- `docs`: una stringa che è il base64 (anche `data:…;base64,`) di un PDF, un'immagine o un documento Office
  esce come `drop:doc:<tipo>:<classe>`.
- `max_large_body_bytes`: i corpi analizzabili oltre `max_body_bytes` e fino a questo limite si analizzano con
  `large_array` / `large_nested_array` elementi per array. Filtri servlet, `TrafficTwinHttpClient`, intercettori e
  agent conservano quindi `max(max_body_bytes, max_large_body_bytes) + 1` byte di ogni corpo campionato.

L'azione `code` accetta anche la forma `{"action":"code","shape":"alnum"}` (`^[A-Za-z0-9_.-]{1,16}$`) e le regole sul
corpo i passi `.@nome` e `.#text`. Un SDK precedente rifiuta una policy con questi campi (`policy_rejected`).

## Convivenza con OpenTelemetry

- L'SDK legge `Span.current()` per riflessione (nessuna dipendenza): `trace_id` e `span_id` degli
  eventi sono quelli dello span server dell'app; senza OpenTelemetry legge `traceparent` e, in
  mancanza, genera ids propri **senza iniettarli** nelle chiamate.
- Il test `OtelCoexistenceTest` confronta gli span esportati da un'app con SDK OpenTelemetry
  privato con e senza l'agente: stessi nomi, tipi, attributi e struttura; `GlobalOpenTelemetry` resta
  non impostato.

### Estensione dell'agent OpenTelemetry (`sdk-otel-extension`)

```bash
java -javaagent:opentelemetry-javaagent.jar \
     -Dotel.javaagent.extensions=sdk-otel-extension-0.1.0.jar \
     -jar app.jar          # con TT_* come sopra e il filtro servlet registrato
```

Un `AutoConfigurationCustomizerProvider` aggiunge uno `SpanProcessor` **di sola lettura** al
provider dell'agent. Non imposta globali, non registra propagatori, non aggiunge né cambia span,
attributi, link o eventi, non esporta e non apre connessioni. Fa due cose:

1. dice all'SDK quale span server sta servendo il thread corrente, anche se l'applicazione **non**
   ha il jar `opentelemetry-api` (l'agent aggancia solo l'API che l'app porta con sé);
2. espone l'attributo `http.route` dello span, che l'SDK usa come `framework_route` quando né Spring
   né JAX-RS lo hanno fornito.

L'estensione vive nel class loader dell'agent e l'SDK in quello dell'app: non condividono classi,
si incontrano attraverso un `java.util.logging.Logger` con nome fisso (oggetto del JDK visibile a
tutti), il cui `Filter` risponde alle richieste senza mai scrivere log. L'agent riscrive i riferimenti
a `java.util.logging.Logger` nel codice delle estensioni, per questo l'estensione lo raggiunge per
riflessione. Verificato con l'agent 2.10.0 reale (vedi "Sviluppo"). `TT_DISABLED=1` o
`-Dtt.otel.hints=false` la spengono.

## Iniezione senza codice (`-javaagent`)

`sdk-agent` produce **un solo jar senza dipendenze** (`traffic-twin-agent-0.1.0.jar`) con `Premain-Class` e `Agent-Class`.
Basta avviare la JVM con il flag e le variabili `TT_*`: nessuna modifica all'applicazione, nessun filtro da registrare.

```bash
TT_ENROLL_URL=https://tt-core.internal:4318 TT_ENROLL_TOKEN=tte_… TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key TT_SERVICE_NAME=shop-api \
  java -javaagent:/opt/traffic-twin/traffic-twin-agent.jar -jar app.jar
```

Su Kubernetes lo aggiunge il webhook di iniezione (`traffic-twin.io/inject: java`): accoda
`-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar` a `JAVA_TOOL_OPTIONS` senza mai toccare un `-javaagent` già presente.
**Senza `TT_ENROLL_URL`, o con `TT_DISABLED=1`, l'agente non installa nulla.**

**Cosa installa.** Un solo `ClassFileTransformer`, **senza ASM** (`ClassPatcher`, ~400 righe): per ognuno dei pochi metodi
elencati sotto *rinomina* l'originale in `metodo$tt` (privato, sintetico; il suo bytecode non viene toccato) e ne aggiunge uno
nuovo con la stessa firma che chiama un hook e poi l'originale. Il metodo aggiunto è codice lineare (niente salti, niente
`StackMapTable` da ricalcolare); l'hook può sostituire gli argomenti. Il trasformatore è **non** retransform-capable: la JVM
passa alle ritrasformazioni (quelle dell'agent OpenTelemetry) i byte già con i nostri metodi, quindi nessuno cambia lo schema
della classe.

| Aggancio | Metodo con hook | Effetto |
|---|---|---|
| Tomcat 9/10/11 (anche incorporato, Spring Boot) | `StandardContext.startInternal()` | registra per primo il filtro servlet (`jakarta` o `javax`, scelto guardando l'API del contenitore) |
| Jetty 9.4–12 | `ServletContextHandler.doStart()` | idem |
| `java.net.http.HttpClient` | `HttpClientFacade.send/sendAsync` | sostituisce richiesta e `BodyHandler` con quelli con tee |
| Spring `RestTemplate` / `RestClient` | `InterceptingHttpAccessor.getRequestFactory()`, `DefaultRestClientBuilder.build()` | mette `TrafficTwinClientInterceptor` in testa alla lista |
| OkHttp 3/4 (anche `new OkHttpClient()`) | `OkHttpClient.newCall` | sostituisce, una volta per client, la lista (immutabile) degli interceptor |

**Class loader.** L'agent jar viene aggiunto al *bootstrap class path* (come fa l'agent OpenTelemetry) ma vi restano in chiaro
solo poche classi che usano solo il JDK (installer, patcher, hook). Tutto il resto è dato (`tt/core/**.classdata`, `tt/ext/**.classdata`):
l'SDK vive in un `CoreLoader` isolato (genitore: il platform class loader, perché il bootstrap non vede `java.net.http`), e le classi
scritte contro un'API di terzi (filtro servlet, intercettori Spring e OkHttp) sono definite, una volta per class loader, in un
`ExtLoader` figlio di quello che definisce quell'API: si collegano alle classi servlet/Spring/OkHttp *effettive* del contenitore, in
qualunque struttura di class loader (common/shared/webapp di Tomcat, `LaunchedClassLoader` di Spring Boot). L'applicazione non
vede mai classi dell'SDK sul proprio class path.

**Convivenza con l'agent OpenTelemetry 2.x.** Possono esserci entrambi i `-javaagent`, **in entrambi gli ordini** (test di
integrazione con l'agent 2.10.0 reale: l'app risponde come prima, OpenTelemetry continua a produrre gli span server e client, e
gli eventi di traffic-twin portano il `trace_id`/`span_id` dello span server di OpenTelemetry quando è presente l'estensione
`sdk-otel-extension`). L'agente non imposta mai `GlobalOpenTelemetry`, un `TracerProvider`, un propagatore, un `SSLContext` o
altri default globali (un test scorre i byte del jar).

**Limiti dell'iniezione senza codice** (con la libreria nel `classpath` e il codice di §"Avvio" restano disponibili):

- Solo i contenitori elencati. Undertow, WildFly/JBoss, WebLogic, WebSphere/Liberty, Netty/Reactor (WebFlux, `WebClient`),
  Vert.x, Quarkus/Micronaut con server proprio: nessun aggancio (l'`Initializer` `ServletContainerInitializer` della libreria
  funziona dove il contenitore lo scopre dal class path).
- Le classi già caricate prima dell'agent non si agganciano (con `TT_DEBUG=1` l'agente lo scrive su stderr); con
  `-javaagent` da riga di comando non succede. Un'attach dinamica (`agentmain`) a un contenitore già avviato non registra il
  filtro nei contesti già partiti.
- Il filtro dell'agente lavora a livello servlet: non vede ciò che il contenitore risponde prima della catena dei filtri
  (per esempio errori del connettore).
- `java.net.http` in modalità agent: **le chiamate che falliscono prima di una risposta (DNS, rifiuto, timeout)** non
  producono evento, perché l'hook non può avvolgere l'originale in un `try/catch` (con `TrafficTwinHttpClient.wrap` sì).
- JAX-RS (`TrafficTwinJaxrsFilter`) non si registra da solo: senza di esso `framework_route` per Jersey/RESTEasy viene dalla policy.
- Non combinare l'agente con la libreria nel `classpath`: le chiamate `HttpClient` avvolte a mano non si duplicano (guardia per
  thread) e il filtro servlet ha una guardia per richiesta, ma resterebbero due agenti SDK (uno per class loader).
- Costo: gli hook sul percorso caldo sono una lettura volatile; `TT_ENROLL_URL` assente = nessun trasformatore.

## Fleet, chiavi e stato locale

- Iscrizione con token: prima connessione TLS senza fiducia **solo** per leggere la catena
  presentata; la radice deve avere l'impronta SHA-256 contenuta nel token, altrimenti non si invia
  nulla (nemmeno il token). Poi la richiesta di iscrizione con quella radice come unica CA.
- **Percorso senza CSR**: il JDK non ha un'API pubblica per costruire una PKCS#10, quindi
  `tt-core` genera la coppia di chiavi e restituisce la chiave **una sola volta** sul canale
  fissato. L'SDK la salva subito in un **PKCS#12 `0600`** (`client.p12`, cartella `0700`) e non
  la scrive mai in chiaro. La password del PKCS#12 è `TT_KEYSTORE_PASSWORD` o, se assente, una
  password casuale in `keystore.pass` (`0600`): la protezione effettiva sono i permessi del
  file, come per le chiavi private PEM; per una protezione vera usa un segreto montato.
  Con `TT_KEYSTORE_PASSWORD` impostata la password non viene mai scritta su disco.
- **Cartella di stato fidata (POSIX)**: `~/.traffic-twin` e la cartella dello stato sono create
  `0700`; una cartella preesistente più larga e di proprietà dell'utente viene riportata a `0700`,
  una di un altro utente viene rifiutata (stato in una cartella temporanea privata,
  errore `state_dir_untrusted`). I file di stato si leggono solo se regolari (no symlink), di
  proprietà dell'utente e non scrivibili da gruppo/altri (altrimenti `state_file_untrusted`).
- **Risposte Fleet limitate**: la lettura si interrompe (e la connessione è annullata) a `max+1`
  byte, anche dopo la decompressione gzip, e ha un timeout complessivo anche sul corpo.
- I task periodici (`heartbeat`, polling della policy) catturano ogni `Throwable`, compresi
  `OutOfMemoryError`/`StackOverflowError`: un'eccezione non deve fermare per sempre il polling
  (l'interruttore di emergenza e le policy di chiusura non sarebbero più applicati) né rompere
  l'applicazione; l'errore è solo contato (`fleet_task_failed`).
- Interruttore di emergenza: i batch già estratti dalla coda e in attesa di retry e gli scambi in
  sanificazione al momento del kill vengono scartati (generazione), mai inviati.
- Heartbeat **prima** di qualsiasi cattura. Interruttore di emergenza, revoca e `min_issued_seq`
  sono salvati in `state.json` e restano validi dopo un riavvio.
- Policy: firma Ed25519 (`java.security`) su `"tt.policy.body/v1" || 0x00 || corpo` con chiavi
  fissate e non revocate, schema completo del corpo, coerenza busta/corpo, gruppo, `not_after`,
  `issued_seq` crescente e ≥ `min_issued_seq`. Una policy rifiutata non sostituisce mai la
  precedente valida e non viene messa in cache. Nuove chiavi di firma solo se approvate da una
  chiave già fissata.
- Invio: lotti ≤ 512 eventi / 4 MiB, ripetizioni con attesa esponenziale e `Retry-After` su
  429/502/503/504 ed errori di rete (al massimo 5), coda di 10 000 eventi / 16 MiB che scarta i più
  vecchi.

## Limiti noti

- Se l'app legge i parametri di un form `application/x-www-form-urlencoded` con
  `getParameter()`, il contenitore consuma il corpo senza passare dal tee: l'evento riporta
  `trunc:size` (corpo non consumato, §9.0). Nessun valore esce.
- Dopo il ritorno del filtro il contenitore può aggiungere header alla risposta (`Date`,
  `Content-Length`, `Transfer-Encoding`): non sono visibili e non compaiono nell'evento.
- Le chiamate in uscita fatte da thread diversi da quello della richiesta (esecutori, `CompletableFuture`
  senza propagazione del contesto) non ereditano il campionamento: valgono trace o caso.
- Il filtro JAX-RS è solo per `jakarta.ws.rs`; per `javax.ws.rs` serve una copia (non fornita).
- `startAsync()` senza argomenti passa all'applicazione la richiesta e la risposta avvolte
  (altrimenti l'app scriverebbe aggirando il tee): `AsyncContext.hasOriginalRequestAndResponse()`
  vale `false`.
- La chiave client è nel PKCS#12 con password in un file accanto: vedi sopra.
- HTTP/2 lato server dipende dal contenitore (il filtro lavora sulle API servlet, quindi vale);
  il client `java.net.http` con HTTP/2 funziona, il server push non è catturato.

## Sviluppo

```bash
cd sdk/java
./mvnw verify                 # vettori di conformità + unit + integrazione + benchmark breve
./mvnw -pl sdk test -Dtest=ConformanceTest      # solo i 583 vettori (conformance/vectors)
./mvnw -pl sdk test -Dtest=OverheadBenchTest -Dtt.bench.seconds=10   # overhead, durata per fase
./scripts/gen-javax.sh        # rigenera sdk-servlet-javax dalla variante Jakarta
```

Il wrapper Maven è fissato a Maven 3.9.9. Plugin: solo quelli standard di Apache
(compiler, surefire, jar, resources, install). Maven Central serve per JUnit, Jetty e
OpenTelemetry (solo test) e per le API servlet/JAX-RS/Spring/OkHttp (solo compilazione).

Test: `ConformanceTest` esegue tutti i vettori confrontando i byte; `SanitizerUnitTest`
include il controllo generativo di G1 (con la policy vuota nessun valore in ingresso compare in
uscita; le etichette degli host che compaiono nel `service` rispettano la regola); `HostPatternTest` gli esempi di sanitizer.md §3.5,
il parser IPv6, la tabella delle classi e la modalità stretta; `CaptureIntegrationTest` usa Jetty, un corriere finto e un `tt-core` finto
(`com.sun.net.httpserver` con mTLS, PKI costruita con `keytool`); `FleetTest` copre pin della CA,
stati fail-closed e riavvio; `OtelCoexistenceTest` la convivenza; `OverheadBenchTest` il costo.

**Agent (`sdk-agent`).** `ClassPatcherTest` prova il riscrittore di class file su una classe con metodi di istanza, statici,
protetti, con `tableswitch` e ritorno `long`. Gli `*IT` (failsafe, fase `verify`) avviano in una JVM figlia un'app che non conosce
traffic-twin, con solo `-javaagent`: `AgentIT` con Tomcat 10.1 (jakarta), Tomcat 9 (javax) e Jetty 11 incorporati e i quattro client
(`java.net.http`, `RestTemplate`, `RestClient`, `new OkHttpClient()`); `OtelAgentIT` con **l'agent OpenTelemetry 2.10.0 come risorsa
di test** (scaricato da Maven in `target/it-libs`) in entrambi gli ordini dei flag. Il tt-core e il corriere finti stanno nella JVM
di test. `./mvnw verify` esegue tutto (anche il solo `-Dit.test=OtelAgentIT`).

Verifica manuale con l'agent reale in modalità libreria (non è nella suite, scarica 21 MB): avviare un'app Jetty con
`-javaagent:opentelemetry-javaagent-2.10.0.jar -Dotel.javaagent.extensions=sdk-otel-extension-0.1.0.jar`
e controllare che `OtelContext.active()` restituisca gli id dello span server.
