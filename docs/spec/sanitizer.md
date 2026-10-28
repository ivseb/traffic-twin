# Sanitizer v1.1 — specifica normativa

> Formato: `tt.sanitizer/v1` · Revisione: **1.1**, con i pattern degli host della **v1.5** (§3.1, §3.5, §3.6, §13, §15) la nota sulla fase Osserva della **v1.6** (§18; nessun byte di uscita cambia) e l'azione `code` della **v1.11** (§5.6, §19; nessun byte di uscita cambia per le policy senza `code`) e l'azione `graphql` della **v1.14** (§5.7, §9.1, §20; nessun byte di uscita cambia per le policy senza `graphql`) e, dalla **v1.18**, il soggetto da un header JSON (§11 passo 4 bis, §21) e, dalla **v1.19**, la forma `alnum` di `code` (§5.6) e i corpi XML/SOAP, multipart, documenti base64 e corpi grandi (§22; nessun byte di uscita cambia per le policy senza `bodies` e senza `code(alnum)`); vedi il changelog in [README.md](README.md) · Lingua: prosa in italiano, identificatori in inglese.
>
> Le parole **DEVE**, **NON DEVE**, **DOVREBBE** e **PUÒ** hanno il significato di MUST, MUST NOT, SHOULD e MAY della RFC 2119.

Questo documento definisce **byte per byte** cosa fa il sanitizer. Ogni implementazione (SDK Node, Python, Java, .NET, Go, PHP, `tt-egress`, adattatore OBI, importatore HAR) DEVE produrre lo **stesso output** a parità di ingresso normalizzato (§1) e policy compilata. La prova è il pacchetto di vettori di conformità (§16, `conformance/`).

Principio guida: **in caso di dubbio, si scarta**. Ogni situazione non prevista produce una forma (`drop:*`) o un marcatore di troncamento (`trunc:*`), mai un valore. Un **errore interno** del sanitizer (eccezione, limite di memoria, stato inatteso) NON DEVE produrre un evento: la sorgente scarta lo scambio e incrementa il contatore `sanitizer_errors` dell'heartbeat.

---

## 0. Regole generali

### 0.1 Espressioni regolari

Ogni espressione regolare di questo documento e degli schemi:

- si valuta come corrispondenza dell'**intera** stringa: `^` e `$` nelle tabelle indicano solo i confini dell'ingresso, **non** fine riga. Equivalenti: `\A…\z` in PCRE/.NET, `re.fullmatch` in Python, `Matcher.matches()` in Java, `^…$` con flag `D` in PHP, `regexp.MatchString` con `^…$` in Go (RE2 non ha modalità multiline per default);
- non usa modalità multiline, dotall, case-insensitive né classi Unicode: tutte le classi sono **solo ASCII** (in Python serve `re.ASCII`, in .NET `RegexOptions.ECMAScript` o `CultureInvariant` con classi esplicite);
- si applica a stringhe di **byte ASCII**: una stringa che contiene byte fuori da 0x20–0x7E non corrisponde mai, salvo dove indicato.

Esempio: `"orders\n"` **non** corrisponde a `^[a-z]+$`, in nessun linguaggio.

### 0.2 UTF-8

"UTF-8 valido" significa conforme alla RFC 3629 in modo stretto: niente forme sovralunghe, niente surrogati codificati (CESU-8), niente punti di codice oltre U+10FFFF, niente BOM trattato come spazio.

### 0.3 Classi di lunghezza

Le classi di lunghezza (sui byte UTF-8 per le stringhe, sul numero di elementi per oggetti, array e mappe) sono **cinque**:

| Lunghezza | Classe |
|---|---|
| 0–8 | `l8` |
| 9–32 | `l32` |
| 33–128 | `l128` |
| 129–1024 | `l1024` |
| oltre 1024 | `lmax` |

La classe `l8` copre anche la stringa vuota: "vuoto" e "corto" non si distinguono (decisione di progetto D-S1, vedi [threat model](../THREAT_MODEL.md) §7).

---

## 1. Ingresso

Il sanitizer riceve uno **scambio** (una coppia richiesta/risposta), una **policy compilata** già verificata (vedi [policy.md](policy.md)), la **chiave HMAC** locale (§7.1) e l'istante corrente `now` (orologio della sorgente, usato solo per le scadenze di §4.3 e §15).

| Campo | Tipo | Note |
|---|---|---|
| `dir` | `inbound` \| `outbound` | Direzione rispetto al servizio che cattura |
| `service_name` | stringa | Solo `inbound`: nome del servizio **assegnato all'iscrizione** (vedi `api/fleet-api.v1.openapi.yaml`), non un valore dichiarato dall'app |
| `url_base` | stringa | Solo `outbound`: `scheme://host[:port]` della richiesta |
| `method` | stringa | Metodo HTTP così come ricevuto |
| `raw_path` | byte | Path **non decodificato**, senza query (es. `/v1/shipments/ORD%2D1`) |
| `raw_query` | byte \| assente | Query **non decodificata**, senza `?` iniziale; assente se l'URL non ha `?` |
| `framework_route` | stringa opzionale | Solo `inbound`: template della route **completo dei prefissi di montaggio** (§3.3) |
| `trace_id` | stringa opzionale | 32 esadecimali minuscoli, già estratto dalla sorgente da `traceparent` o dal contesto OpenTelemetry (§12) |
| `inherited` | booleano opzionale | Solo `outbound`: decisione di campionamento ereditata dallo scambio inbound in corso nel processo (§12); assente se non c'è contesto |
| `req_headers` | lista di coppie (nome, valore-byte) | Nell'ordine in cui la sorgente li vede, duplicati inclusi; la normalizzazione (§8.0) rende l'uscita indipendente da come il runtime li presenta |
| `req_body` | byte \| assente | Il corpo, o il prefisso conservato (§9.0); assente = vuoto |
| `req_body_total` | intero \| `unknown` | Lunghezza totale **dopo la rimozione del chunking**, contata fino alla fine (§9.0); assente = lunghezza di `req_body`; `unknown` = ignota alla fine dello scambio |
| `req_body_consumed` | booleano | Default `true`; `false` se l'app non ha letto il corpo |
| `req_body_decoded` | booleano | Default `false`; `true` se il runtime ha già rimosso il `content-encoding` (es. `fetch` di Node) |
| `status` | intero opzionale | Status HTTP della risposta; assente se e solo se c'è `net_error` |
| `net_error` | stringa opzionale | `timeout` \| `reset` \| `refused` \| `dns` \| `tls` \| `other` |
| `resp_headers`, `resp_body`, `resp_body_total`, `resp_body_consumed`, `resp_body_decoded` | | Come per la richiesta |

Il `content-type` e il `content-encoding` si ricavano dagli header normalizzati (§8.0, §8.1). Con `net_error`, le parti di risposta si ignorano anche se la sorgente le ha passate.

Ordine dei controlli prima della sanificazione: prima la **policy** (assente → `no_policy`; corpo non valido, dominio HMAC riservato, gruppo, scadenza → `policy_rejected` o `expired_policy`), poi la **chiave** (§7.1), poi il **campionamento** (§12).

---

## 2. Uscita

Il sanitizer produce un oggetto con le parti sanificate dell'evento `tt.http.exchange` (vedi [event.md](event.md)). È lo stesso oggetto che i vettori di conformità confrontano byte per byte:

- `service`, `op`, `route_source` (§3);
- `sampled_by` (§12): la decisione si prende **prima** della sanificazione, ma il suo motivo fa parte dell'uscita;
- `subject` (§11), se presente;
- `req`: `{ "path", "query", "headers", "cookies", "ct", "size", "body" }`, più `fmt`, `xmlns` e `soap_action` (v1.19, §22);
- `resp`: `{ "headers", "cookies", "ct", "size", "body" }`, più `fmt` e `xmlns` (v1.19, §22); assente con `net_error`;
- `disc` (§15), solo in modalità scoperta.

Le mappe `query`, `headers` e `cookies` **vuote si omettono**, come ogni campo assente (§10.1). Gli altri campi dell'evento (`schema`, `policy`, `source`, `ts`, `latency_ms`, `dir`, `status`, `net_error`, `trace_id`, gli id di span) li aggiunge la sorgente e **non** fanno parte dell'uscita del sanitizer.

Ogni **stringa** in uscita appartiene alla grammatica dei token (§6), salvo i campi di servizio con grammatica propria (`service`, `op`, `req.path`, `ct`, `size`). Gli unici valori non-stringa ammessi sono numeri, booleani e `null` provenienti da un'azione `keep` (§5.3).

---

## 3. Servizio, operazione e template

### 3.1 Scelta del servizio

**Inbound.** Il servizio è `service_name` (assegnato all'iscrizione, già conforme a `^[a-z0-9][a-z0-9._-]{0,62}$`). Se la policy ha un servizio con `match.inbound = true` e lo stesso `name`, si usano le sue regole; altrimenti valgono solo le regole globali.

**Outbound.** Si normalizza `url_base` (forma attesa `scheme://host[:port]`):

1. se contiene `@` (credenziali `user:pass@`), un path, una query o un frammento, l'host è **non valido**;
2. lo schema e l'host si portano in minuscolo ASCII;
3. la porta, se presente, deve essere di 1–5 cifre con valore 1–65535, altrimenti l'host è non valido; gli zeri iniziali si tolgono (A-PORT-ZEROS); si elimina se è quella di default dello schema (`80` per `http`, `443` per `https`);
4. **niente** conversione IDNA: un host con byte non ASCII o che non corrisponde a `^[a-z0-9.-]{1,253}$` (dopo il punto 2) è **non valido**;
5. **(v1.5)** un host che inizia con `[` è un **letterale IPv6**: deve esserci una `]`, dopo la quale c'è la fine o `:porta` (punto 3), altrimenti l'host è non valido. Il testo tra le parentesi, in minuscolo, deve essere un indirizzo IPv6 nella forma testuale della RFC 4291 §2.2: gruppi di 1–4 cifre esadecimali separati da `:`, al più un `::` che sta per **almeno un** gruppo di zeri (quindi al più 7 gruppi scritti con `::`, esattamente 8 senza), con gli ultimi 32 bit facoltativamente scritti come IPv4 (formato `ipv4` di §6.3) in fondo; nessun identificatore di zona (`%`), nessun altro carattere. Un letterale IPv6 non corrisponde mai a una `base` (il compilatore rifiuta le basi tra parentesi) né a `segments.hosts_allow`. Prima della v1.5 i letterali IPv6 erano non validi.

Una `base` della policy (già normalizzata dal compilatore) **corrisponde** se:

- la sua origine `scheme://host[:port]` è uguale, byte per byte, all'origine normalizzata della richiesta;
- i suoi segmenti di path sono uguali, uno per uno, ai primi segmenti **decodificati** del path della richiesta (§4.1). Il confronto è per segmento: un `%2F` dentro un segmento non è mai una `/`.

Vince la `base` con più segmenti di path. Se una `base` corrisponde, il servizio è il suo `name`.

Se nessuna `base` corrisponde, si sceglie la prima riga che vale:

| Caso | `service` |
|---|---|
| Host non valido | `host:invalid` |
| Host (con `:porta` se non di default) presente in `segments.hosts_allow` | `host:` + host normalizzato, **esattamente** come elencato (es. `host:api.carrier.example`) |
| **(v1.5)** `hosts.discovery` è `auto` (default, anche quando il campo `hosts` manca) **oppure** la modalità scoperta è attiva (§15) | `host:` + **pattern** dell'host (§3.5), es. `host:api.carrier.example`, `host:{*}.tracking.example:8443`, `host:ip:private`; `host:invalid` se il pattern non esiste (etichetta vuota) |
| Tutti gli altri casi (`hosts.discovery: off`, modalità stretta) | `host:unlisted` |

`hosts.discovery` è un campo del corpo compilato ([policy.md](policy.md) §2): `auto` o `off`. Con `off` (modalità stretta) nessun host non dichiarato esce, come prima della v1.5 (decisione D-S3); con `auto` ogni host esce come pattern, che per costruzione non contiene valori (§3.5) e che l'intake sorveglia ([event.md](event.md) §5.2). È la decisione di prodotto della v1.5: un servizio che chiama qualcosa che nessuno ricorda DEVE essere visibile e intercettabile.

### 3.2 Path dell'operazione

- **Inbound**: il path dell'operazione è l'intero path decodificato.
- **Outbound con `base`**: il path dell'operazione è il **resto** dopo i segmenti di path della `base`. I template delle operazioni di quel servizio sono relativi a questo resto.
- `req.path` nell'evento è **sempre l'intero path sanificato** (i segmenti della `base` escono come letterali, perché sono dichiarati nella policy).

### 3.3 Scelta del template

Le operazioni della policy hanno chiavi `METODO /template`, dove il template è una sequenza di segmenti letterali (`^[A-Za-z0-9._~-]{1,64}$`) o parametri `{nome}` (`^[A-Za-z_][A-Za-z0-9_]{0,63}$`).

Il **metodo** in uscita è il metodo in maiuscolo ASCII se corrisponde a `^[A-Z]{1,16}$` dopo la conversione, altrimenti `OTHER`. Uno scambio con metodo `OTHER`, o con un path troncato (§4.1, punto 4), **non** corrisponde mai a un template: va direttamente al punto 3.

1. **Route del framework.** Se `framework_route` è presente, si normalizza secondo §3.4. Se la normalizzazione riesce, il numero di segmenti del template è uguale al numero di segmenti del path dell'operazione (§4.1), ed esiste nella policy un'operazione con lo stesso metodo e un template **strutturalmente uguale** (stessi letterali per byte nelle stesse posizioni, parametri nelle stesse posizioni; i **nomi** dei parametri non contano), si usa quella: `route_source = "framework"`. Contano i nomi dei parametri della **policy** (per le regole `path.<nome>`) e i suoi letterali escono nelle posizioni letterali, anche se il segmento della richiesta fosse diverso (il routing l'ha già fatto il framework). In ogni altro caso si passa al punto 2. Il template del framework **non** compare mai in uscita se non è nella policy.
2. **Template della policy.** Si cercano i template della policy con lo stesso metodo e lo stesso numero di segmenti; un letterale corrisponde se è **uguale** (per byte) al segmento decodificato, `{nome}` corrisponde a qualsiasi segmento valido. Tra più candidati vince quello con più letterali; a parità, quello con la chiave minore per byte. `route_source = "policy"`.
3. **Nessun template.** `route_source = "raw"`, e l'operazione è `METODO` + spazio + path dell'operazione sanificato (§4.2).

L'`op` in uscita è `METODO /template` (casi 1 e 2) oppure `METODO /path-sanificato` (caso 3); per l'outbound il template o il path sono quelli **relativi alla base**.

### 3.4 Normalizzazione di `framework_route`

La sorgente DEVE passare la route **completa** dei prefissi di montaggio (router annidati, `app.use('/api', router)`, `@RequestMapping` di classe, `Route` di controller, gruppi). Se non è in grado di ricostruirla, NON DEVE passare `framework_route`.

Normalizzazione:

1. si divide la route su `/`, si eliminano i segmenti vuoti;
2. ogni segmento si riscrive con la tabella seguente; un segmento letterale resta uguale;
3. se un segmento rientra nei casi "non normalizzabile", o se il risultato non rispetta la grammatica delle chiavi di operazione, la normalizzazione **fallisce** (si passa al punto 2 di §3.3).

| Framework | Parametro → `{nome}` | Non normalizzabile |
|---|---|---|
| Express, Koa-router, Fastify | `:nome`, `:nome(regex)` | `:nome?`, `:nome*`, `:nome+`, `*`, `(.*)`, segmenti con più parametri (`:a-:b`) |
| Flask | `<nome>`, `<conv:nome>` con `conv` ≠ `path` | `<path:nome>` |
| FastAPI / Starlette | `{nome}`, `{nome:conv}` con `conv` ≠ `path` | `{nome:path}` |
| Django | `<nome>`, `<conv:nome>` con `conv` ≠ `path` | `<path:nome>`, route da `re_path` |
| Spring MVC / WebFlux | `{nome}`, `{nome:regex}` | `*`, `**`, `{*nome}` |
| JAX-RS | `{nome}`, `{ nome : regex }` (spazi ignorati) | parametri che coprono più segmenti (regex con `/`) |
| ASP.NET Core | `{nome}`, `{nome:vincolo}` (anche più vincoli) | `{nome?}`, `{nome=default}`, `{*nome}`, `{**nome}` |
| Gin | `:nome` | `*nome` |
| chi | `{nome}`, `{nome:regex}` | `*` |
| Go `net/http` (1.22+) | `{nome}` | `{nome...}`; un `{$}` finale si **elimina** (indica solo la corrispondenza esatta) |
| Laravel | `{nome}` | `{nome?}` |
| Symfony | `{nome}`, `{nome<regex>}` | `{nome?}`, `{nome?default}`, `{nome<regex>?default}` |

Esempi: Express `/api/orders/:id(\\d+)` → `/api/orders/{id}`; ASP.NET `/orders/{id:int:min(1)}` → `/orders/{id}`; Gin `/files/*path` → fallisce.

### 3.5 Pattern dell'host (v1.5)

Il pattern si calcola dall'host normalizzato di §3.1 (minuscolo, al più 253 byte di `[a-z0-9.-]`, oppure un letterale IPv6) e dalla sua porta normalizzata (assente se di default):

1. **IPv6.** Un letterale IPv6 dà `ip:private` o `ip:public` secondo §3.6; l'indirizzo non esce mai.
2. **Punto finale.** Se l'host termina con `.` (nome completamente qualificato), quel **solo** punto si toglie.
3. **IPv4.** Se il risultato corrisponde al formato `ipv4` di §6.3 (quattro parti 0–255 senza zeri iniziali), il pattern è `ip:private` o `ip:public` secondo §3.6. Altre forme numeriche (`010.0.0.1`, `127.1`, `0x7f.0.0.1`, `2130706433`) **non** sono letterali IPv4: seguono il punto 4, e le loro etichette diventano `{*}` perché non iniziano con una lettera.
4. **Etichette.** Si divide sul byte `.`. Se un'etichetta è vuota (punto iniziale, due punti consecutivi, due punti finali, host composto solo da `.`), il servizio è `host:invalid`. Ogni etichetta resta **letterale** solo se rispetta **tutte** le regole dell'etichetta sicura:
   - a. corrisponde a `^[a-z][a-z0-9-]{0,62}$` (ASCII, inizia con una lettera, al più 63 byte; quindi niente `@`, niente `_`);
   - b. **non** contiene sei o più cifre consecutive (`[0-9]{6}`), come la regola dei nomi di §9.3;
   - c. **non** contiene dodici o più caratteri esadecimali consecutivi (`[0-9a-f]{12}`, lettere comprese: `deadbeefcafe` è un valore);
   - d. **non** è riconosciuta da nessuno dei formati di §6.3 (`uuid`, `hex` e gli altri: per una stringa che rispetta la regola a, d è già implicata da c, perché `uuid` e `hex` contengono 12 esadecimali consecutivi; un'implementazione PUÒ quindi non valutarla).
   Ogni altra etichetta diventa il segnaposto `{*}`. Le etichette `{*}` consecutive **restano una per una** (non si fondono: `ab12cd34ef56.0012345678.cdn.example` → `{*}.{*}.cdn.example`), così il numero di etichette resta visibile. Le etichette punycode (`xn--…`) seguono le stesse regole: restano letterali solo se le rispettano.
5. Il pattern è l'unione delle etichette con `.`, seguita da `:` + porta se la porta non è di default.

Il servizio è `host:` + pattern. Esempi (host non elencati, `hosts.discovery: auto`):

| `url_base` | `service` |
|---|---|
| `https://api.carrier.example` | `host:api.carrier.example` |
| `HTTPS://API.Carrier.example:443` | `host:api.carrier.example` |
| `https://api.carrier.example.:8443` | `host:api.carrier.example:8443` |
| `https://t-3912345678.tenant.example` | `host:{*}.tenant.example` (regola b) |
| `https://cdn-9f8e7d6c5b4a.assets.example` | `host:{*}.assets.example` (regola c) |
| `https://1password.example` | `host:{*}.example` (regola a) |
| `https://xn--bcher-kva.example` | `host:xn--bcher-kva.example` |
| `http://10.0.0.5:8080` | `host:ip:private:8080` |
| `https://[2606:4700::1111]` | `host:ip:public` |
| `https://api..carrier.example` | `host:invalid` |

Grammatica del pattern (nel campo `service` dell'evento, [event.md](event.md) §1): `ip:(private|public)(:porta)?` oppure `(\{\*\}|<etichetta>)(\.(\{\*\}|<etichetta>))*(:porta)?`, con al più 127 etichette e un host di partenza di al più 253 byte (ogni `{*}` vale almeno un byte). L'intake DEVE rifiutare (`host_not_allowed`) un pattern con un'etichetta letterale che non rispetta le regole a–c: la regola si verifica di nuovo in zona B.

Una `base` della policy e `segments.hosts_allow` vincono sempre sul pattern: un host dichiarato esce con il nome del servizio, uno elencato esattamente come elencato, anche se le sue etichette non rispettano le regole (è una scelta esplicita di una persona, approvata come apertura).

**Chiamate di prima di una dichiarazione (spec v1.6.1, `tt-core`).** Dichiarato un host (per esempio `ip:private:9301` come `catalog-api`), le chiamate nuove escono con il nome del servizio; quelle già salvate restano sotto `host:<pattern>` (lo storico non si riscrive). `tt-core` le collega al servizio dichiarato **nello stesso gruppo**, quando il pattern descrive l'host della sua `base`: l'assistente le fonde nel servizio dichiarato (un'operazione e un campo per riga), il registro degli host le segna con `now_declared_as`, le liste dei servizi e dei contratti con `replaced_by` («sostituito da catalog-api») e il pacchetto costruito senza un elenco esplicito di servizi le lascia fuori (il loro gemello sarebbe di nuovo il servizio dichiarato, sotto un altro nome: `ext-1` nel mock), salvo che qualcuno le abbia scelte esplicitamente (`twin: true`) o che regole approvate le usino. Una dichiarazione di un altro gruppo non rinomina mai le chiamate di questo.

**Rischio residuo.** Un'etichetta che rispetta le regole può comunque essere un dato personale scritto come sottodominio statico (`mario-rossi.customers.example`): la regola della sorgente la lascia passare. La mitigazione è la seconda linea dell'intake (cardinalità per posizione sotto il dominio registrabile, [event.md](event.md) §5.2) e, dove anche un solo evento è troppo, la modalità stretta `hosts.discovery: off` (vedi il [threat model](../THREAT_MODEL.md) §7).

### 3.6 Classi degli indirizzi IP (v1.5)

Un indirizzo è `ip:private` se cade in uno di questi intervalli, altrimenti è `ip:public`. La tabella è normativa e chiusa: le implementazioni NON DEVONO usare le funzioni "is private" delle librerie, che cambiano tra versioni.

| Famiglia | Intervalli `ip:private` |
|---|---|
| IPv4 | `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4` |
| IPv6 | `::/96` (non specificato, loopback, IPv4-compatibili), `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8` |
| IPv6 con IPv4 incorporato | `::ffff:0:0/96` (IPv4-mapped) e `64:ff9b::/96` (NAT64): la classe è quella dei 32 bit finali come IPv4 |

Per un indirizzo IPv6 si guardano **prima** i due intervalli con IPv4 incorporato, poi la riga IPv6. Le classi servono solo a riconoscere le chiamate verso reti interne o metadati del cloud (`169.254.169.254`): non sono un controllo di sicurezza sulla destinazione.

---

## 4. Path

### 4.1 Scomposizione

1. `raw_path` si divide sul byte `/`. I segmenti vuoti si eliminano (quindi `//a/` equivale a `/a`).
2. Ogni segmento si **decodifica**: `%XY` con due cifre esadecimali (maiuscole o minuscole) diventa il byte `0xXY`; un `%` non seguito da due cifre esadecimali resta letterale. Il `+` **non** si trasforma nel path.
3. Se i byte decodificati non sono UTF-8 valido (§0.2), il segmento è **non valido**.
4. Al massimo 32 segmenti: oltre, i segmenti in più si sostituiscono con un unico segmento `{trunc}`.

### 4.2 Sanificazione dei segmenti

Per ogni segmento, nell'ordine:

1. Se il segmento è non valido: esce `{drop:bytes}`.
2. Se il segmento appartiene alla `base` di un servizio outbound (§3.2): esce uguale.
3. Se il template scelto ha un **letterale** in quella posizione: il segmento esce uguale.
4. Se il template ha un **parametro** `{nome}`: si applica l'azione della policy per `path.nome` (§5) e il segmento esce come `{` + token + `}`. Senza regola, l'azione è `drop`. Un `keep` su un parametro di path si applica **solo** se il valore corrisponde a `^[A-Za-z0-9._~-]{1,64}$`; altrimenti si applica `drop`. Lo stesso vale per il valore originale da cui nasce un `time:` (che contiene comunque solo caratteri ammessi).
5. Senza template (`route_source = "raw"`): il segmento esce uguale **solo se** è nella lista `segments.allow` della policy (confronto per byte con il segmento decodificato; le voci della lista rispettano `^[A-Za-z0-9._~-]{1,64}$`, quindi un segmento con spazi, `+` o altri caratteri non è mai ammesso), oppure se la modalità "parole automatiche" è attiva (§4.3) **e** il segmento corrisponde a:

   ```
   ^([a-z]+([-_][a-z]+)*|v[0-9]{1,3})$
   ```

   e ha al massimo 40 byte. In tutti gli altri casi esce `{` + forma `drop` (§6.2) + `}`.

Il path sanificato è `/` + segmenti uniti da `/`; il path vuoto è `/`.

Esempi (policy senza template, parole automatiche attive):

| `raw_path` | Path sanificato |
|---|---|
| `/v1/shipments` | `/v1/shipments` |
| `/customers/mario.rossi%40example.com/orders` | `/customers/{drop:str:email}/orders` |
| `/orders/ORD-2026-000184` | `/orders/{drop:str:l32}` |
| `/orders/550e8400-e29b-41d4-a716-446655440000` | `/orders/{drop:str:uuid}` |
| `/orders%0A` | `/{drop:str:l8}` (il `\n` impedisce la corrispondenza, §0.1) |

Con un template `GET /orders/{id}` e la regola `path.id: hmac(order)`, il quarto esempio diventa `/orders/{id}` come `op` e `/orders/{tk1:k1:…}` come `req.path`.

### 4.3 Parole automatiche

La modalità "parole automatiche" (`segments.auto_words`) è **a tempo**, come la modalità scoperta: è attiva solo se `segments.auto_words = true` **e** `now < segments.auto_words_expires_at` **e** `now < created_at + 7 giorni` (secondo l'orologio della sorgente). Serve durante l'onboarding per vedere i path; poi si sostituisce con template o con `segments.allow`.

---

## 5. Azioni

### 5.0 Selezione della regola

#### Sintassi dei percorsi nel corpo (`tt-path`)

Le regole sul corpo usano un sottoinsieme minimo di JSONPath:

```
tt-path  = "$" *step
step     = "." name / ".*" / "[*]" / ".@" name / ".#text"
name     = ( ALPHA / "_" ) *63( ALPHA / DIGIT / "_" / "-" )
```

I passi `.@name` e `.#text` (v1.19) selezionano gli attributi e il testo misto dei corpi XML (§22.2); nei corpi JSON selezionano solo una chiave originale uguale (`"@type"`), che esce comunque collassata in `{*}` (§9.3).

- `.name` seleziona il membro con quella chiave **originale** (prima del collasso §9.3).
- `.*` seleziona qualsiasi membro di un oggetto, comprese le chiavi che usciranno collassate.
- `[*]` seleziona qualsiasi elemento di un array.
- Non esistono indici, filtri, discesa ricorsiva né nomi tra virgolette. Le chiavi con caratteri fuori da `name` (per esempio un punto) si raggiungono solo con `.*`.

Per header, cookie, query e parametri di path, la regola si indica con il **nome** (header in minuscolo); la grammatica dei nomi è in [policy.md](policy.md) §1.2.

#### Gruppi di precedenza

Le regole si dividono in gruppi, dal più forte al più debole:

| Gruppo | Regole |
|---|---|
| 1 | Regole dell'**operazione** scelta (§3.3), per la parte giusta (`request` o `response`) |
| 2a | Solo risposte con `status ≥ 400`: regole `errors` del **servizio** |
| 2b | Solo risposte con `status ≥ 400`: regole `errors` **globali** |
| 3 | Regole del **servizio** (`service.request` / `service.response`) |
| 4 | Regole **globali** della policy (`global.request` / `global.response`) |

**Foglie.** Per una foglia (valore scalare) vince il primo gruppo che contiene almeno una regola che corrisponde. Dentro un gruppo, se più `tt-path` corrispondono alla stessa foglia (hanno quindi tutti lo stesso numero di passi) vince quello con:

1. più passi `.name`;
2. a parità, la stringa del `tt-path` minore per byte.

**Query, cookie, header e form.** Le regole per nome si confrontano con il nome **originale decodificato** (per gli header, dopo il minuscolo), anche quando quel nome esce collassato in `{*}`. I valori delle parti di query o form **senza** `=` (§8.3) non hanno nome e ricevono sempre `drop`. In un corpo form, un campo corrisponde **solo** alle regole `$.<nome>` e `$.*`; nessun altro `tt-path` si applica.

**Contenitori.** Si dice che un `tt-path` P **può raggiungere un discendente** di un contenitore che si trova nella posizione concreta C (sequenza di passi `.chiave` e `[indice]`) se P ha più passi di C e i primi passi di P corrispondono a C (`.name` = stessa chiave, `.*` = qualsiasi membro, `[*]` = qualsiasi elemento). La valutazione è statica e non dipende dal contenuto.

Una regola `drop` esplicita che corrisponde a un contenitore, trovata nel gruppo *g*, si applica (collassando il contenitore, §5.1) **solo se** nessuna regola dei gruppi da 1 a *g* compresi può raggiungere un discendente del contenitore. Altrimenti si ignora e il contenitore si attraversa. Le regole `keep`, `code`, `graphql`, `hmac` e `bucket` che corrispondono a un contenitore si ignorano sempre.

Esempio: regola di operazione `$.items[*].orderId: hmac(order)` e regola globale `$.items: drop`. Il contenitore `$.items` è nel gruppo 4, ma una regola del gruppo 1 raggiunge un discendente: il `drop` si ignora, `orderId` riceve `hmac`, tutti gli altri campi degli elementi ricevono `drop` per default.

### 5.1 Tabella delle azioni

Ogni foglia riceve **una** azione. Il default è sempre `drop`.

| Azione | Uscita | Vincoli |
|---|---|---|
| `drop` | Forma (§6.2) | Nessuno |
| `keep` | Il valore (§5.3) | Solo foglie; vincoli di §5.3 |
| `code` | Il valore come `keep:` se ha la forma di un codice, altrimenti la forma (§5.6, v1.11; forma `alnum` dalla v1.19) | Solo foglie stringa |
| `graphql` | Richiesta: `gql:` e la forma del documento GraphQL, senza valori; risposta: `gql:` e un nome di un risultato di introspezione, solo con il cancello aperto; altrimenti la forma (§5.7, v1.14) | Solo foglie stringa |
| `hmac` | Token `tk1:` (§7) | Solo foglie stringa o numero; vincoli di §5.3 sui numeri |
| `bucket` | Fascia `num:`/`time:` (§5.5) | Solo foglie del tipo giusto |

Un `drop` esplicito su un contenitore, quando si applica (§5.0), lo **collassa** in una forma unica (`drop:obj:<classe>` o `drop:arr:<classe>`, §6.2) senza attraversarlo.

Se un'azione non è applicabile al tipo della foglia (es. `hmac` su un booleano, `bucket(num)` su una stringa, `code` su un numero), si applica `drop`.

### 5.2 drop

Vedi §6.2.

### 5.3 keep

- **Stringa**: esce `keep:` + stringa, se è UTF-8 valida e la sua lunghezza in byte è ≤ `limits.keep_max_bytes` (default 64, massimo 1024). Altrimenti `drop`.
- **Numero**: esce come **numero JSON** nella forma canonica (§10.2), purché il lessema abbia al massimo 64 byte e il valore assoluto dell'esponente scritto nel lessema (la parte dopo `e`/`E`, se presente) sia ≤ 9999. Altrimenti `drop`.
- **Booleano** e `null`: escono invariati.

### 5.4 hmac

Vedi §7. Il **dominio** dell'HMAC è quello indicato dalla regola (`hmac(order)` → dominio `order`); senza indicazione è `id`. Due campi con lo stesso dominio e lo stesso valore producono lo **stesso token**: è così che il miner trova le chiavi di legame. Per i numeri valgono gli stessi limiti di lessema di §5.3.

### 5.5 bucket

**`bucket(num, [b0, b1, …, bn])`** si applica solo a numeri JSON che rispettano i limiti di lessema di §5.3.

- Il valore `v` e ogni confine `bi` si convertono in double IEEE-754 binary64 con arrotondamento corretto (round-half-even) dal lessema; i valori oltre il massimo diventano ±infinito, quelli troppo piccoli ±0. I confini compilati sono strettamente crescenti **come double** (lo verifica `tt-core`, vedi [policy.md](policy.md) §1.3).
- Il confronto avviene tra double, con la semantica IEEE-754: `-0` è uguale a `0`. Quindi `-1e-400` (che diventa `-0`) cade nella fascia che contiene `0` (es. `num:0-50`), e `1e400` (che diventa +infinito) in `num:>=bn`. È voluto: la fascia descrive il double, non il lessema.
- Fasce:
  - `v < b0` → `num:<b0`
  - `bi ≤ v < bi+1` → `num:bi-bi+1`
  - `v ≥ bn` → `num:>=bn`
- I confini in uscita si scrivono nella forma canonica (§10.2) **del lessema compilato**, non del double.

Esempio: `73.40` con `[0, 50, 100, 250]` → `num:50-100`.

**`bucket(time, unit)`**, con `unit` ∈ `year | month | day | hour`, si applica solo a stringhe che corrispondono ai formati `datetime` o `date` (§6.3) **e** rappresentano un istante valido:

- anno da `0001` a `9999`; mese `01`–`12`; giorno valido per il mese (anni bisestili gregoriani); ora `00`–`23`; minuti e secondi `00`–`59` (il secondo `60` non è ammesso);
- offset `±HH:MM` con `HH` `00`–`23` e `MM` `00`–`59`; `Z`/`z` vale `+00:00`.

Il valore si converte in UTC (le date senza ora valgono `T00:00:00Z`); se il risultato esce dagli anni 0001–9999 si applica `drop`. Poi si tronca:

- `year` → `time:2026`
- `month` → `time:2026-10`
- `day` → `time:2026-10-19`
- `hour` → `time:2026-10-19T10`

### 5.6 code (v1.11)

**Decisione di progetto.** Gli stati e i codici (`DELIVERED`, `in_transit`, `card_declined`) devono uscire in chiaro **senza** approvazioni di persone, in modo strettamente limitato, perché senza di loro il miner non trova cicli di vita e il mock resta statico (test di usabilità n. 4, blocco B1). L'azione `code` è quel limite, applicato **alla sorgente**:

- **Stringa** UTF-8 valida che corrisponde a `^[A-Za-z_-]{2,32}$` (§0.1: solo byte ASCII; lettere, `_` e `-`; da 2 a 32 byte; niente cifre, spazi o altri caratteri) **e** con lunghezza ≤ `limits.keep_max_bytes`: esce `keep:` + stringa, esattamente come `keep` (§5.3). Le maiuscole restano quelle originali: `DELIVERED`, `in_transit`, `card_declined`, `Return-Requested` escono così come sono.
- **Qualsiasi altra stringa** (una cifra, uno spazio, un punto, un carattere non ASCII anche se somiglia a una lettera, meno di 2 o più di 32 byte, oltre `keep_max_bytes`): esce la **forma** che darebbe `drop` (§6.2), per esempio `drop:str:l32` per `in transit`. Non si ripiega su una regola più debole: la regola `code` è stata scelta (§5.0) e il suo risultato è la forma.
- **Numero, booleano, `null`**: la forma (`drop:int`, `drop:dec`, `drop:bool`, `drop:null`). `code` non si applica mai a valori che non sono stringhe.
- **Contenitori**: ignorata come `keep` (§5.0).
- Nella modalità scoperta (§15) una foglia con regola `code` non aggiunge voci a `disc`: ha una regola, come un `keep` che degrada a forma.

Il controllo si fa sul valore **decodificato** (escape JSON, percent-encoding del path e della query, `+` dei form, come per `keep`). La forma del codice è un sottoinsieme della grammatica dei segmenti di path (§4.2), quindi un `{keep:...}` di `code` in un parametro di path è sempre ammesso.

Esempi (vettori 1810–1828): `DELIVERED` → `keep:DELIVERED`; `card_declined` → `keep:card_declined`; `E404` → `drop:str:l8`; `in transit` → `drop:str:l32`; `DЕLIVERED` con una `Е` cirillica → `drop:str:l32`; `A` → `drop:str:l8`; 33 lettere → `drop:str:l128`; `true` → `drop:bool`.

**Forma `alnum` (v1.19).** La regola `{"action":"code","shape":"alnum"}` (forma autore `code(alnum)`) sostituisce l'espressione con `^[A-Za-z0-9_.-]{1,16}$`: lettere, cifre, `_`, `-` e `.`, da 1 a 16 byte ASCII (sempre entro `keep_max_bytes`). Serve per i codici con cifre o di un solo carattere (codici di prodotto `0000123450`, versioni `2.1`, classi `R`). Tutto il resto del paragrafo vale identico: valore decodificato, forma `drop` per ogni altra stringa, nessun ripiego, mai su numeri, booleani e `null` (un `123450` senza virgolette resta `drop:int`), ignorata sui contenitori, nessuna voce di scoperta. Anche la forma `alnum` è un sottoinsieme della grammatica dei segmenti di path. Il limite è più stretto della v1.11 sulla lunghezza (16 byte) perché le cifre rendono più probabile che un valore sia un identificativo: la guardia che lo ferma in zona B è in [policy.md](policy.md) §1.5. Esempi (vettori 2200–2209): `0000123450` → `keep:0000123450`; `2.1` → `keep:2.1`; `R` → `keep:R`; `2 1` → `drop:str:l8`; 17 cifre → `drop:str:l32`; `٣` (cifra araba) → `drop:str:l8`.

Su quali campi `code` si può scrivere lo decidono `tt-core` e keyguard (lista chiusa di nomi di stato e di codice, [policy.md](policy.md) §1.5): una sorgente applica la regola che riceve e ricontrolla solo il sottoinsieme di sicurezza di [hardening.md](hardening.md) §2 (`code` come `keep` su header di credenziali e su passi jolly globali).

### 5.7 graphql (v1.14)

**Perché.** Un servizio GraphQL ha un solo endpoint (per esempio `POST /graphql`) e la sua «operazione» vera è scritta nel corpo: `{"query": "query GetOrder($id: ID!) { order(id: $id) { id status } }", "variables": {"id": "…"}}`. Il testo di `query` è **codice** (nomi di campi, argomenti, tipi) ma può contenere **valori** scritti in linea (`order(id: "ORD-123")`). Senza questa azione il testo esce solo come forma (`drop:str:l128`) e né i contratti né il mock possono sapere quale operazione è stata chiamata. L'azione `graphql` fa uscire la **struttura** del documento e mai un valore: l'analisi si fa **nella sorgente**, perché solo lì il testo è in chiaro. Vale per qualsiasi servizio GraphQL, su qualsiasi path; il core riconosce gli scambi GraphQL dal contenuto (§5.7.5).

#### 5.7.1 Lato richiesta: forma del documento

Una foglia **stringa** con regola `graphql` nella **richiesta** (corpo JSON, form, query, corpo `application/graphql` di §9.1; il controllo si fa sul valore decodificato come per `keep`) è analizzata come **documento eseguibile** GraphQL ([GraphQL, ottobre 2021](https://spec.graphql.org/October2021/), §2) in tre passi. Qualsiasi errore, in qualsiasi passo, fa uscire la **forma** della stringa (§6.2), come `drop`.

**1. Analisi lessicale.** Si scorre la stringa byte per byte:

- si **ignorano**: spazio (0x20), tab (0x09), LF (0x0A), CR (0x0D), virgola (0x2C), il BOM U+FEFF (byte EF BB BF) e i commenti (da `#` alla fine della riga, esclusa: LF o CR);
- **punteggiatura**: `!` `$` `&` `(` `)` `...` `:` `=` `@` `[` `]` `{` `|` `}`; un `.` che non inizia `...` è un errore;
- **nome**: `[_A-Za-z][_0-9A-Za-z]*`, il più lungo possibile;
- **numero** (inizia con `-` o una cifra): `-?(0|[1-9][0-9]*)`, poi facoltativamente `\.[0-9]+`, poi facoltativamente `[eE][+-]?[0-9]+`; è **intero** se non ha né parte decimale né esponente, altrimenti **decimale**. Sono errori: uno zero seguito da una cifra (`01`), un `.` o un `e` senza cifre dopo, e un numero seguito subito da `.` o da un carattere che può iniziare un nome (`1abc`, `1.5.2`);
- **stringa a blocco**: da `"""` al primo `"""` che non fa parte di `\"""`; dentro sono ammessi tutti i byte tranne i caratteri di controllo < 0x20 diversi da tab, LF e CR; senza chiusura è un errore;
- **stringa**: da `"` al primo `"` non preceduto da escape; gli escape ammessi sono `\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t` e `\u` seguito da esattamente 4 cifre esadecimali; qualsiasi altro escape, un LF, un CR o un carattere di controllo < 0x20 diverso da tab dentro la stringa è un errore, come la mancanza della chiusura;
- qualsiasi altro byte fuori da stringhe e commenti (per esempio `?`, `*`, `%`, `"` isolate, un carattere non ASCII) è un errore.

Durante l'analisi lessicale si contano le parentesi **aperte** (`{`, `(`, `[` insieme, senza distinguere il tipo): se il numero supera **64** è un errore; se scende sotto zero, o non è zero alla fine, è un errore.

**2. Analisi sintattica.** I token devono formare un documento della grammatica seguente (sottoinsieme eseguibile della specifica GraphQL; le parole chiave sono nomi riconosciuti dalla posizione):

```
Document            = Definition+
Definition          = OperationDefinition / FragmentDefinition
OperationDefinition = SelectionSet
                    / OperationType [Name] [VariableDefinitions] [Directives] SelectionSet
OperationType       = "query" / "mutation" / "subscription"
FragmentDefinition  = "fragment" FragmentName "on" Name [Directives] SelectionSet
FragmentName        = Name, ma non "on"
SelectionSet        = "{" Selection+ "}"
Selection           = Field / FragmentSpread / InlineFragment
Field               = [Name ":"] Name [Arguments] [Directives] [SelectionSet]
FragmentSpread      = "..." FragmentName [Directives]
InlineFragment      = "..." ["on" Name] [Directives] SelectionSet
Arguments           = "(" (Name ":" Value)+ ")"
Directives          = ("@" Name [Arguments])+
VariableDefinitions = "(" ("$" Name ":" Type ["=" Value] [Directives])+ ")"
Type                = (Name / "[" Type "]") ["!"]
Value               = "$" Name / numero / stringa / Name / "[" Value* "]" / "{" (Name ":" Value)* "}"
```

Un documento vuoto, una definizione che non inizia con `{`, `query`, `mutation`, `subscription` o `fragment` (per esempio le definizioni di tipo `type`, `schema`, `extend`), o token che avanzano dopo l'ultima definizione sono errori. Non si verifica nient'altro (tipi, nomi di variabili, frammenti mancanti o ripetuti): la sorgente non conosce lo schema.

Un **nome in posizione di valore** (l'alternativa `Name` di `Value`) è un valore letterale: `true`/`false` (booleano), `null`, o un valore di enum.

**3. Emissione.** Si riemettono **tutti** i token nell'ordine originale (le virgole e i commenti sono già spariti), sostituendo:

| Token | Esce come |
|---|---|
| stringa o stringa a blocco | `?s` |
| numero intero | `?i` |
| numero decimale | `?f` |
| nome in posizione di valore `true` o `false` | `?b` |
| nome in posizione di valore `null` | `?n` |
| altro nome in posizione di valore | `?e` |
| nome che non rispetta la **regola dei nomi** qui sotto | `*` |
| ogni altro nome e la punteggiatura | invariato |

**Regola dei nomi**: un nome esce come scritto se è lungo al più **64** byte, **non** è composto solo da cifre esadecimali con lunghezza ≥ 16 e **non** contiene sei o più cifre consecutive. È la regola delle chiavi JSON di §9.3 applicata ai nomi GraphQL (gli altri formati di §9.3 non possono corrispondere a un nome): un alias come `p_4821553: order(…)` non dice nulla di più di quanto la chiave `p_4821553` della risposta direbbe già, e come lei diventa `*`.

I token si uniscono **senza spazi**, salvo uno spazio singolo tra due token consecutivi se l'ultimo byte del primo e il primo byte del secondo sono entrambi in `[A-Za-z0-9_?*]`. Se il risultato supera **32 768** byte è un errore. Altrimenti esce `gql:` + risultato.

Esempi (vettori 2010–2016):

| Documento | Uscita |
|---|---|
| `query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }` | `gql:query GetOrder($id:ID!){order(id:$id){id status items{sku}}}` |
| `{ order(id: "ORD-123", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }` | `gql:{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}` |
| `mutation M($in: [OrderIn!]! = [{note: "urgente"}]) { a: create(in: $in) { ...F } } fragment F on Order { id }` | `gql:mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}` |
| `{ o4821553: order(id: 1) { id } }` | `gql:{*:order(id:?i){id}}` |
| `ciao` / `type Query { a: Int }` / `{ a(x: 01) }` | la forma (`drop:str:l8`, `drop:str:l32`, `drop:str:l32`) |

La forma conserva i nomi delle variabili, dei campi, degli alias, degli argomenti, dei tipi, dei frammenti e delle direttive; dei valori in linea solo il **tipo** (che anche `drop` darebbe, §6.2), il numero degli elementi delle liste e i nomi dei campi degli oggetti in ingresso. Le **variabili** (`$.variables` nel corpo JSON) sono valori normali: seguono le loro regole (`hmac`, `code`, …) o `drop`.

Ogni altra foglia con regola `graphql` nella richiesta (numero, booleano, `null`, stringa non valida) esce come forma. Su un contenitore la regola si ignora come `keep` (§5.0). Una foglia con regola `graphql` non aggiunge voci a `disc` (§15).

#### 5.7.2 Lato risposta: nomi di un risultato di introspezione (cancello)

Il client di un servizio GraphQL federato o «cucito» (schema stitching) chiede prima lo **schema** con la query di introspezione standard (`__schema { types { name fields { name args { … } type { … } } } … }`). Il risultato descrive lo schema, non dati: per rispondere come il servizio vero il mock ha bisogno dei nomi in chiaro.

Una foglia **stringa** con regola `graphql` nella **risposta** esce come `gql:` + la stringa se e solo se:

1. il **cancello di introspezione** dello scambio è aperto: nella richiesta dello stesso scambio **almeno un** valore aveva una regola `graphql` e **ogni** valore della richiesta con una regola `graphql` è uscito come `gql:` con un documento **di sola introspezione**: ogni operazione del documento (almeno una) seleziona alla radice solo campi `__schema`, `__type` o `__typename`, **senza alias** e senza frammenti. Un valore con regola `graphql` che esce come forma, `drop:bytes` o `drop:str:invalid` chiude il cancello. Senza regole `graphql` nella richiesta il cancello è chiuso;
2. la stringa è un **nome** GraphQL (`^[_A-Za-z][_0-9A-Za-z]*$`) che rispetta la regola dei nomi di §5.7.1 (altrimenti non esce `*`, esce la forma).

In ogni altro caso (cancello chiuso, stringa che non è un nome, numero, booleano, `null`) esce la forma: le descrizioni, i valori di default e i motivi di deprecazione, che sono testo libero, non hanno regola ed escono sempre come forma. Con il cancello aperto il limite degli array del **corpo della risposta** è `max(limits.max_array, 4096)`, perché un elenco di tipi o di campi supera spesso 32 elementi; gli altri limiti non cambiano.

Il cancello è la difesa principale: le regole di risposta `graphql` stanno sotto `$.data.__schema` e `$.data.__type` (lo verificano `tt-core` e keyguard, [policy.md](policy.md) §1.6), ma un alias potrebbe portare dati sotto quei nomi (`__schema: order(id: 1) { types: items { name: buyerName } }`): un documento con alias alla radice non è di sola introspezione, e il cancello resta chiuso.

#### 5.7.3 Chi scrive le regole

Le regole `graphql` stanno solo sul documento della richiesta (`$.query` del corpo JSON, `$` del corpo `application/graphql`, parametro di query `query`) e sotto `$.data.__schema` / `$.data.__type` della risposta ([policy.md](policy.md) §1.6). Non aprono valori: la versione Osserva automatica le propone senza approvazioni sugli endpoint che il core riconosce come GraphQL dal contenuto (§5.7.5, [policy.md](policy.md) §7.4).

#### 5.7.4 Limiti dichiarati

- Le richieste a lotti (un array JSON di operazioni) e le sottoscrizioni via WebSocket non sono analizzate: i loro corpi escono come prima.
- Un valore oltre `limits.max_array` in una query o in un form non viene sanificato e non conta per il cancello: per sfruttarlo l'applicazione strumentata dovrebbe mandare essa stessa una richiesta costruita apposta (più di 32 parametri `query`), a cui il servizio risponde con alias `__schema`. È un rischio residuo del [threat model](../THREAT_MODEL.md) (M24).

#### 5.7.5 Riconoscimento nel core

Il core riconosce uno scambio GraphQL dal **contenuto**, su qualsiasi servizio e path: un `gql:` con un documento in `req.body.query`, in `req.body` (corpo `application/graphql`) o nel parametro di query `query`. Lo divide in operazioni logiche ([event.md](event.md) §6). Prima che esistano le regole `graphql` riconosce gli endpoint candidati dalla struttura degli eventi (un corpo JSON con la chiave `query`, e `variables` o `operationName`, o il content-type `application/graphql`; una risposta con `data` o `errors`) e li propone alla versione Osserva.

---

## 6. Grammatica dei token

### 6.1 Prefissi ammessi

Ogni stringa in uscita inizia con uno di questi prefissi. L'intake DEVE rifiutare gli eventi con stringhe fuori grammatica.

| Prefisso | Significato |
|---|---|
| `drop:` | Forma di un valore scartato |
| `keep:` | Valore conservato per policy (`keep`, oppure `code` con la forma di un codice, §5.6) |
| `tk1:` | Token HMAC |
| `num:` | Fascia numerica |
| `time:` | Fascia temporale |
| `trunc:` | Marcatore di troncamento |
| `tkd:` | Token corto della modalità scoperta, solo nel campo `disc` (§15) |
| `gql:` | (v1.14) Forma di un documento GraphQL o nome di un risultato di introspezione (§5.7); la stringa dopo il prefisso usa solo lettere ASCII, cifre, `_`, la punteggiatura GraphQL di §5.7.1, `?`, `*` e lo spazio, ed è lunga al più 32 768 byte |
| `ns:` | Pattern di uno spazio dei nomi XML, solo nel campo `xmlns` (v1.19, §22.2) |

Fanno eccezione i campi di servizio dell'evento (`service`, `op`, `req.path`, `ct`, `size` e, dalla v1.19, `fmt`, `soap_action` e le chiavi di `xmlns`), che hanno grammatiche proprie definite qui e in [event.md](event.md).

### 6.2 Forme (`drop:`)

| Valore in ingresso | Forma |
|---|---|
| `null` | `drop:null` |
| booleano | `drop:bool` |
| numero con lessema intero `-?(0\|[1-9][0-9]*)` | `drop:int` |
| altro numero | `drop:dec` |
| stringa non UTF-8 valida o con surrogati isolati | `drop:str:invalid` |
| stringa riconosciuta da un formato (§6.3) | `drop:str:<formato>` |
| altra stringa | `drop:str:<classe>` (§0.3) |
| oggetto collassato con `drop` esplicito | `drop:obj:<classe>` sul numero di chiavi distinte (§9.3) |
| array collassato con `drop` esplicito | `drop:arr:<classe>` sul numero di elementi |
| byte non decodificabili (header, query, cookie, segmento di path) | `drop:bytes` |
| corpo non analizzabile per tipo (§9.1) | `drop:bytes:<classe>` sulla lunghezza totale |
| corpo con codifica non supportata (§9.0) | `drop:bytes` |
| stringa che è il base64 di un documento, con `bodies.docs` (v1.19, §22.4) | `drop:doc:<tipo>:<classe documento>` |
| parte file di un corpo multipart, con `bodies.multipart` (v1.19, §22.3) | `drop:file:<tipo>:<classe documento>` |

### 6.3 Formati riconosciuti

Il riconoscimento si applica **solo** se la stringa è composta interamente da byte ASCII stampabili (0x20–0x7E). Le espressioni seguono §0.1. Si provano **in quest'ordine**; vince la prima che corrisponde.

| # | Formato | Espressione |
|---|---|---|
| 1 | `uuid` | `^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$` |
| 2 | `jwt` | `^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$` |
| 3 | `email` | `^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$` |
| 4 | `datetime` | `^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]\|[+-][0-9]{2}:[0-9]{2})$` |
| 5 | `date` | `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| 6 | `url` | `^[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+$` |
| 7 | `ipv4` | `^(25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])(\.(25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])){3}$` |
| 8 | `phone` | `^\+[1-9][0-9]{6,14}$` |
| 9 | `digits` | `^-?[0-9]{1,19}$` |
| 10 | `hex` | `^[0-9A-Fa-f]{16,}$` |

Le stringhe non ASCII o non riconosciute ricevono la classe di lunghezza. Il riconoscimento di un formato è solo sintattico: `datetime` e `date` non verificano la validità del calendario (lo fa solo `bucket(time)`, §5.5).

### 6.4 Marcatori di troncamento (`trunc:`)

| Marcatore | Dove | Quando |
|---|---|---|
| `trunc:size` | Al posto di `body` | Corpo oltre `limits.max_body_bytes`, corpo non consumato o di lunghezza ignota (§9.0), uscita oltre il limite (§10.3) |
| `trunc:depth` | Al posto di un contenitore | Profondità oltre `limits.max_depth` |
| `trunc:n:<classe>` | Ultimo elemento di un array o di una lista di valori | Oltre `limits.max_array`; la classe è sul numero totale di elementi |
| `trunc:keys:<classe>` | Valore della chiave `{trunc}` | Oggetto o mappa di nomi oltre il limite; la classe è sul numero totale di chiavi o nomi distinti |
| `trunc:invalid-json` | Al posto di `body` | Corpo dichiarato JSON ma non conforme (§9.2) |
| `trunc:invalid-xml` | Al posto di `body` | Corpo XML fuori dal sottoinsieme ammesso (v1.19, §22.2) |
| `trunc:invalid-multipart` | Al posto di `body` | Corpo multipart non conforme (v1.19, §22.3) |

---

## 7. HMAC

### 7.1 Chiave

- La chiave è **locale alla sorgente**: si legge da `TT_HMAC_KEY` oppure dal file indicato da `TT_HMAC_KEY_FILE`. Il contenuto è una o più righe nella forma `<kid>:<base64url-senza-padding>`, con `kid` che corrisponde a `^[a-z0-9]{1,8}$`.
- Lettura (uguale per variabile e file): si divide sul byte `\n`; da ogni riga si toglie un eventuale `\r` finale; le righe vuote si ignorano (quindi un a-capo finale è innocuo). Nessun altro spazio è ammesso. L'alfabeto base64url è stretto (`A–Z a–z 0–9 - _`), senza `=`: qualsiasi altro carattere rende **non valida** la riga.
- I byte decodificati DEVONO essere almeno 32. Una riga non valida o più corta rende non valida l'intera configurazione: stato `key_missing` (come per la chiave assente).
- **Scelta della chiave**: la sorgente usa la chiave con `kid` uguale a `hmac.kid` della policy; se non la possiede, la prima chiave in ordine di `hmac.accept_kids` che possiede. Senza chiave utilizzabile, la sorgente **NON DEVE** catturare nulla e DEVE segnalarlo nell'heartbeat (`key_missing` o `key_mismatch`).
- La chiave **non** viaggia mai nella policy né nel protocollo Fleet. In zona B le chiavi esistono **solo** dentro `tt keyguard` (vedi [keyguard.md](keyguard.md)).

Durante una rotazione (`accept_kids` non vuoto) i token prodotti con chiavi diverse sono diversi: la correlazione vale solo tra eventi con lo stesso `kid`.

### 7.2 Calcolo

```
mac   = HMAC-SHA256(key, epoch || 0x00 || domain || 0x00 || value)
token = "tk1:" + kid + ":" + base64url_nopad(mac[0:16])
```

- `epoch` è `hmac.epoch` della policy compilata (es. `2026-10`), in byte ASCII.
- `domain` è il dominio della regola (§5.4), in byte ASCII, `^[a-z][a-z0-9_-]{0,31}$`. I domini `subject`, `sample`, `sample-trace` e `discovery` sono **riservati** (§11, §12, §15): una policy NON DEVE usarli nelle regole.
- `value` è la rappresentazione canonica:
  - stringa: i suoi byte UTF-8, senza normalizzazione Unicode né trim;
  - numero: la forma canonica (§10.2) in ASCII. Quindi `184` e `"184"` producono lo stesso token, e `184.0` (numero) produce anch'esso il token di `184`. La stringa `"184.0"` invece usa i suoi byte e produce un token diverso.
- Il token ha sempre 22 caratteri dopo `tk1:<kid>:`.

### 7.3 Esempio

Con chiave `k1` = 32 byte `0x00 0x01 … 0x1f` (`k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`), epoch `2026-10`, dominio `order`, valore `ORD-2026-000184`, il token è quello riportato nel vettore `conformance/vectors/0002-hmac-equal-values.json`. Questo documento non riporta il valore per evitare che diverga: **i vettori sono la fonte di verità** per i byte.

---

## 8. Header, cookie e query

### 8.0 Normalizzazione degli header

Prima di ogni altra operazione, gli header di ciascuna direzione si normalizzano così, indipendentemente da come il runtime li presenta:

1. si eliminano gli **pseudo-header** HTTP/2 e HTTP/3 (nomi che iniziano con `:`);
2. i nomi si portano in minuscolo ASCII; un nome diventa `{*}` se non corrisponde a ``^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$`` **oppure** se viola la regola dei nomi di §9.3 punto 3 (formati riconosciuti o sei o più cifre consecutive, es. `x-3912345678`);
3. a ogni valore si tolgono gli spazi e i tab (OWS: byte 0x20 e 0x09) iniziali e finali;
4. i valori con lo **stesso nome** si uniscono nell'ordine di arrivo, in un unico valore:
   - `cookie`: separatore `"; "`;
   - `set-cookie`: **non** si uniscono (ogni valore resta separato);
   - tutti gli altri, compreso `{*}`: separatore `", "`;
5. l'ordine dei nomi è quello della **prima** comparsa.

Così `X-A: 1` + `X-A: 2` (Node, valori separati) e `X-A: 1, 2` (WSGI, già unito) producono lo stesso valore `1, 2`. Le sorgenti che vedono i nomi già trasformati dal runtime (es. PHP, che converte `-` in `_` nelle variabili `HTTP_*`) DEVONO ricostruire il nome originale se possibile (`getallheaders()` o equivalente); se non possono, la differenza è documentata come limite della sorgente nel suo README.

### 8.1 Header

1. Gli header `cookie` e `set-cookie` **non** compaiono in `headers`. Nella richiesta, `cookie` finisce in `cookies` (§8.2) e un eventuale `set-cookie` si **scarta** del tutto; nella risposta, `set-cookie` finisce in `cookies` e un eventuale `cookie` si scarta del tutto.
2. Ogni valore normalizzato: se UTF-8 valido, è una stringa e riceve l'azione della policy per `headers.<nome>` (default `drop`); altrimenti `drop:bytes`.
3. L'uscita è un oggetto `nome → [token]`: dopo la normalizzazione ogni nome ha **un solo** valore.
4. **Limite dei nomi** (vale identico per header, cookie e query): si contano i nomi distinti **in uscita** (dopo il collasso in `{*}`, che conta come un nome), nell'ordine di prima comparsa. Si tengono i primi 64; i valori dei nomi successivi si scartano e si aggiunge la chiave `{trunc}` con valore `["trunc:keys:<classe>"]` (array di un elemento) sul numero totale di nomi distinti in uscita.
5. Il `content-type` si legge dal valore normalizzato di `content-type`: si prende la parte prima del primo `;`, si tolgono spazi e tab ai bordi e si porta in minuscolo. Esce nel campo `ct` se corrisponde a `^[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}$`, altrimenti `ct = "invalid"` (anche quando l'header era ripetuto e quindi unito con `", "`). Senza header, `ct` è assente.
6. Il `content-encoding` si legge allo stesso modo (valore normalizzato, minuscolo, senza spazi ai bordi); vedi §9.0.

### 8.2 Cookie

- **Richiesta**: il valore normalizzato di `cookie` (già unito con `"; "`) si divide sul byte `;`; per ogni parte si tolgono spazi e tab ai bordi, si divide sul primo `=`; le parti senza `=` si **ignorano**.
- **Risposta**: per ogni valore `set-cookie` (separati, §8.0) si prende solo la parte prima del primo `;`, si tolgono spazi e tab ai bordi e si divide sul primo `=`; senza `=` il valore si ignora.
- I nomi seguono la regola dei nomi (§9.3 punto 3): fuori regola diventano `{*}`.
- I valori ricevono l'azione per `cookies.<nome>` (default `drop`, nome originale, §5.0). Le virgolette doppie esterne **non** si tolgono. Byte non UTF-8 → `drop:bytes`.
- L'uscita è un oggetto `nome → [token]`, con i valori nell'ordine di comparsa (anche sotto `{*}`: l'ordine di comparsa non rivela i nomi nascosti).
- Limiti: nomi come §8.1 punto 4; per ogni nome al massimo `limits.max_array` valori, poi `trunc:n:<classe>` sul numero totale di valori di quel nome.

### 8.3 Query

1. Se `raw_query` è assente, `query` è assente. Altrimenti si divide sul byte `&`; le parti vuote si ignorano.
2. Ogni parte si divide sul primo `=`. Una parte **senza** `=` ha nome `{*}` e valore uguale all'intera parte (così un valore scritto come nome, es. `?ORD2026000184`, non esce in chiaro).
3. Nome e valore si decodificano: prima `+` → spazio, poi `%XY` come in §4.1. Valore non UTF-8 → `drop:bytes`; nome non UTF-8 → `{*}`.
4. I nomi seguono la regola dei nomi (§9.3 punto 3): fuori regola diventano `{*}`.
5. I valori ricevono l'azione per `query.<nome>` (default `drop`, nome originale, §5.0); i valori delle parti senza `=` ricevono sempre `drop`.
6. L'uscita è un oggetto `nome → [token]`, nell'ordine di comparsa (anche sotto `{*}`). Limiti come per i cookie.

Per la query, i cookie, gli header e i corpi `application/x-www-form-urlencoded` i valori sono sempre **stringhe**: `hmac` e `keep` lavorano sulla stringa, `bucket(num)` non si applica (diventa `drop`).

---

## 9. Corpo

### 9.0 Lunghezza, codifica e streaming

La sorgente DEVE vedere il corpo **fino alla fine** senza bloccare l'app: tiene una copia dei primi `limits.max_body_bytes + 1` byte e **conta** il resto fino alla fine del corpo (tee). La lunghezza totale (`*_body_total`) si conta **dopo** la rimozione del chunking.

Si decide così, nell'ordine:

1. **Corpo non consumato** dall'app (`*_body_consumed = false`) o di lunghezza ignota alla fine dello scambio (`*_body_total = unknown`): `body = "trunc:size"`, `size = "lmax"`.
2. **Corpo assente o vuoto** (lunghezza totale 0): `body` assente, `size = "l8"`. Il campo `size` è quindi **sempre** presente, salvo il caso del punto 3 con codifica non supportata.
3. **Codifica.** Si guarda il `content-encoding` (§8.1):
   - assente o `identity`: il corpo è quello ricevuto;
   - `gzip` (anche `x-gzip`) o `deflate` (formato zlib, RFC 1950), **un solo livello**: se il runtime l'ha già decodificato (`*_body_decoded = true`) si usa il corpo così com'è; altrimenti la sorgente lo decodifica fermandosi a `limits.max_body_bytes + 1` byte di uscita;
   - qualsiasi altra codifica, o più codifiche (es. `gzip, br`), o un errore di decodifica: `body = "drop:bytes"`, `size` **assente**. Vale anche se il runtime avesse già decodificato il corpo: così tutte le sorgenti producono lo stesso risultato.
4. **Dimensione.** Si usa la lunghezza **totale** (`*_body_total`, non quella del prefisso conservato), decodificata se il punto 3 ha decodificato. Se supera `limits.max_body_bytes` (o la decodifica ha raggiunto il tetto): `body = "trunc:size"`, `size = "lmax"`, e il corpo **non** si analizza. Questo protegge anche dalle bombe di decompressione. **(v1.19)** Con `bodies.max_large_body_bytes` maggiore di zero vale invece §22.5: il tetto della decodifica è il maggiore dei due limiti e un corpo analizzabile entro il limite grande si analizza in modalità «corpo grande».
5. Altrimenti `size` è la classe (§0.3) della lunghezza decodificata e il corpo si tratta secondo §9.1.

Limite noto: un server che invia `deflate` grezzo (RFC 1951, senza intestazione zlib) può essere decodificato da alcuni runtime e non da altri; il caso non è coperto dai vettori.

### 9.1 Scelta del trattamento

In base a `ct`:

| `ct` | Trattamento |
|---|---|
| `application/json` o che termina con `+json` | JSON (§9.2) |
| `application/x-www-form-urlencoded` | Come la query (§8.3), con l'uscita `nome → [token]` al posto dell'albero; una regola `$.nome` (o `$.*`) si applica a **ogni** valore del nome `nome`, nessun altro `tt-path` si applica |
| `application/graphql` (v1.14) | Se la regola che vince per il percorso `$` (§5.0) è `graphql`, il corpo intero è **una foglia stringa** in `$` (non UTF-8 valido: `drop:str:invalid`) e l'uscita è il risultato di §5.7 (un `gql:` o la forma); altrimenti come la riga seguente |
| `application/xml`, `text/xml` o che termina con `+xml` (compreso `application/soap+xml`), solo con `bodies.xml` (v1.19) | XML (§22.2) |
| `multipart/form-data`, solo con `bodies.multipart` (v1.19) | Multipart (§22.3) |
| qualsiasi altro, o assente | `body = "drop:bytes:" + classe` sulla lunghezza decodificata |

Per i tipi analizzati (JSON, form e, dalla v1.19, XML e multipart) la sorgente DEVE avere il corpo intero: se conserva solo un prefisso più corto della lunghezza totale, `body = "trunc:size"` (con `size` della lunghezza totale).

### 9.2 Analisi JSON

Le implementazioni DEVONO usare un analizzatore che:

- preserva il **lessema** dei numeri;
- **valida l'intero corpo**, in modo iterativo, anche oltre `limits.max_depth`: qualsiasi errore in qualsiasi punto produce `trunc:invalid-json`, e solo un documento interamente valido può produrre `trunc:depth`;
- rifiuta il JSON non conforme alla RFC 8259 (virgole finali, commenti, `NaN`, spazi bianchi non ammessi, più valori di primo livello) → `trunc:invalid-json`;
- rifiuta il BOM iniziale → `trunc:invalid-json`;
- rifiuta i byte non UTF-8 validi (§0.2) in qualsiasi punto → `trunc:invalid-json`;
- tratta le **chiavi duplicate** secondo §9.3;
- applica `limits.max_depth` (default 32): un contenitore a profondità maggiore diventa `trunc:depth` (la radice ha profondità 1).

Una stringa JSON con un escape `\uD800`–`\uDFFF` non accoppiato vale come non valida: come **valore** esce `drop:str:invalid` qualunque sia l'azione; come **chiave** è sempre dinamica (§9.3).

### 9.3 Chiavi degli oggetti

Per ogni oggetto, nell'ordine:

1. **Duplicati**: per ogni chiave originale (confronto sui code unit dopo l'escape JSON) vale solo l'**ultima** occorrenza, nella posizione di quella.
2. **Selezione**: si ordinano i membri rimasti per posizione. Se sono più di `limits.max_keys` (default 256), si tengono i primi `max_keys` e si aggiunge la chiave `{trunc}` con valore `trunc:keys:<classe>` sul numero totale di chiavi distinte.
3. **Collasso (regola dei nomi)**: una chiave esce **letterale** se è ASCII, corrisponde a `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`, **non** è riconosciuta dai formati `uuid`, `email`, `hex`, `digits`, `jwt` (§6.3) e **non** contiene sei o più cifre consecutive (`[0-9]{6}`). Altrimenti è **dinamica**. La stessa regola vale per i nomi di query, cookie e (oltre alla grammatica dei token) header.
4. Le chiavi dinamiche dei membri tenuti escono sotto la chiave unica `{*}`, il cui valore è un **array** dei valori sanificati, ordinati per i **byte della loro forma canonica** (§10); a parità di byte l'ordine è irrilevante. Così l'ordine non rivela nulla delle chiavi nascoste.
5. Il valore della chiave `{trunc}` in un oggetto JSON è la **stringa** `trunc:keys:<classe>` (non un array: l'albero del corpo non è una mappa di nomi).

### 9.4 Array

Si sanificano i primi `limits.max_array` elementi (default 32). Se l'array è più lungo, si aggiunge come ultimo elemento `trunc:n:<classe>` sul numero totale.

### 9.5 Ordine di visita

L'ordine di visita non influisce sull'uscita, perché l'uscita si canonicalizza (§10). Le implementazioni POSSONO visitare in qualsiasi ordine.

---

## 10. Canonicalizzazione dell'uscita

L'uscita di ogni scambio è serializzata in **JSON canonico tt** (`tt-cjson`). Lo stesso formato serve per gli eventi (vedi [event.md](event.md)), per i corpi di policy e per i vettori di conformità.

### 10.1 Regole

1. Nessuno spazio bianco fuori dalle stringhe.
2. Chiavi degli oggetti ordinate per **byte** (tutte le chiavi in uscita sono ASCII).
3. Stringhe: si emettono come byte ASCII. Si fa l'escape solo di:
   - `"` → `\"`
   - `\` → `\\`
   - ogni carattere < 0x20, il carattere 0x7F e ogni carattere non ASCII → `\uXXXX` con **esadecimale minuscolo**; i caratteri oltre U+FFFF si scrivono come coppia di surrogati.

   Non si usano le forme brevi (`\n`, `\t`…) e `/` non si fa l'escape.
4. Numeri: solo in forma canonica (§10.2).
5. `true`, `false`, `null` in minuscolo.
6. Gli array mantengono l'ordine.
7. I campi assenti si **omettono** (non si emette `null` al loro posto).

### 10.2 Forma canonica dei numeri

Si calcola **dal lessema**, in aritmetica decimale esatta, senza passare dai double, e solo per lessemi entro i limiti di §5.3:

1. Si scompone il lessema in segno, cifre ed esponente decimale, così che valore = segno × cifre × 10^esponente.
2. Si tolgono gli zeri iniziali e finali dalle cifre (aggiustando l'esponente). Se non restano cifre, il numero è `0` (anche per `-0`).
3. Sia `n` il numero di cifre ed `e` = esponente + `n` (posizione della virgola).
   - Se `-6 < e ≤ 21`: notazione decimale semplice. Esempi: `184`, `73.4`, `0.0015`, `1000000`.
   - Altrimenti: notazione esponenziale `d[.ddd]e±k` con `k = e − 1`, segno sempre esplicito. Esempi: `1e+21`, `1.5e-7`.
4. Il segno `-` si emette solo per numeri diversi da zero.

Esempi: `1.50` → `1.5`; `15e-1` → `1.5`; `-0.0` → `0`; `1E3` → `1000`; `123456789012345678901234567890` → `1.2345678901234567890123456789e+29`.

### 10.3 Limite di dimensione dell'evento

Se l'evento canonico completo supera **524 288 byte** (512 KiB), la sorgente applica, in quest'ordine e ricalcolando ogni volta la dimensione:

1. `req.body` → `trunc:size` (se presente; `xmlns` e `fmt` restano);
2. `resp.body` → `trunc:size` (se presente);
3. rimozione del campo `disc`;
4. se la dimensione è ancora oltre il limite: nessun evento, contatore `sanitizer_errors`.

I campi `size` restano invariati.

---

## 11. Soggetto

La policy indica da dove leggere il soggetto (`identity.subject`): un header (`from: header`, `name` in minuscolo) o un cookie (`from: cookie`, `name`), opzionalmente con `jwt_claim`. Il soggetto si legge **solo dalla richiesta**.

Algoritmo:

1. **Valore grezzo.**
   - Header: il valore normalizzato (§8.0) di quel nome. Se l'header è ripetuto, il valore unito contiene `", "` e quasi sempre fallisce al passo 3: è voluto.
   - Cookie: il valore della **prima** occorrenza del nome nei cookie della richiesta (§8.2).
   - Assente, vuoto, non UTF-8 valido o più lungo di 8192 byte → nessun soggetto.
2. **Prefisso** (solo `from: header`, senza `json_path`): se il valore inizia con `bearer` senza distinzione di maiuscole, seguito da almeno uno spazio o tab, si toglie il prefisso con tutti gli spazi e tab che seguono. Il valore che resta non deve essere vuoto.
3. **Senza `jwt_claim` né `json_path`**: il soggetto è il valore così ottenuto.
4. **Con `jwt_claim`**:
   1. il valore deve avere **esattamente tre** parti separate da `.` (JWS compatto); altrimenti nessun soggetto;
   2. la seconda parte si decodifica in base64url con alfabeto stretto (`A–Z a–z 0–9 - _`), con o senza padding `=` finale (al massimo due, solo in fondo); qualsiasi altro carattere → nessun soggetto;
   3. i byte si analizzano come JSON con le regole di §9.2 (BOM e UTF-8 non valido rifiutati, duplicati: vince l'ultimo); il risultato deve essere un **oggetto**;
   4. `jwt_claim` è il **nome letterale** di un membro di primo livello (un punto fa parte del nome, non indica un percorso);
   5. se il membro è una stringa non vuota, il soggetto sono i suoi byte UTF-8; se è un numero entro i limiti di §5.3, il soggetto è la sua forma canonica (§10.2); in ogni altro caso nessun soggetto.

   **Nessuna verifica di firma**: serve solo come identificatore.
4. bis. **Con `json_path`** (v1.18, solo `from: header`, esclude `jwt_claim`; §21):
   1. si tolgono spazi e tab iniziali e finali (nessun prefisso `bearer`);
   2. se il valore comincia con `{` è JSON; altrimenti si decodifica in base64, alfabeto standard **oppure** URL (non mescolati), con o senza padding; un errore → nessun soggetto;
   3. i byte si analizzano come JSON con le regole di §9.2 (BOM e UTF-8 non valido rifiutati, duplicati: vince l'ultimo, dati in coda rifiutati, nessun limite di profondità: §21); il risultato deve essere un **oggetto**;
   4. `json_path` è un percorso puntato (1–8 membri `[A-Za-z0-9_-]{1,64}`; il punto separa sempre i membri): ogni membro intermedio deve essere un oggetto;
   5. se il membro finale è una stringa non vuota, il soggetto sono i suoi byte UTF-8; se è un numero entro i limiti di §5.3, la sua forma canonica (§10.2); in ogni altro caso (array, oggetto, booleano, `null`, stringa vuota, membro mancante) nessun soggetto.
5. Con un soggetto: `subject = token HMAC` con dominio `subject` (§7.2).

Il valore grezzo del soggetto NON DEVE mai comparire in uscita.

---

## 12. Campionamento

Il campionamento avviene **prima** della sanificazione: uno scambio non campionato non si sanifica affatto. La decisione usa la chiave locale (§7.1) e include l'epoch: è stabile per tutto il periodo di un'epoch, e cambia quando l'epoch cambia.

**Inbound**, nell'ordine:

1. **Baggage**, solo se `sampling.trust_baggage = true` **e** il servizio ha `match.internal = true` (cioè è dichiarato non raggiungibile da Internet): se il baggage W3C della richiesta contiene il membro `tt.s` con valore `1` o `0`, si segue quello (`sampled_by = "baggage"`). Sui servizi di confine (`internal` assente o `false`) il baggage **non** si considera mai, così un client esterno non può né forzare né evitare la cattura.
2. **Soggetto** (§11): si calcola `HMAC-SHA256(key, epoch || 0x00 || "sample" || 0x00 || soggetto)`, si leggono i primi 4 byte come intero senza segno big-endian `u`, e lo scambio è campionato se `u mod 10000 < sampling.rate_bp` (`sampled_by = "subject"`).
3. **Trace**: se c'è un `trace_id`, come al punto 2 con dominio `sample-trace` e valore = `trace_id` in esadecimale minuscolo (`sampled_by = "trace"`).
4. **Casuale**: probabilità `rate_bp / 10000` (`sampled_by = "random"`).

**Lettura del baggage**: il valore normalizzato dell'header `baggage` (§8.0, più header uniti con `", "`) si divide sul byte `,`; a ogni membro si tolgono OWS ai bordi; le proprietà dopo il primo `;` si ignorano; si divide sul primo `=` e si tolgono OWS dalla chiave e dal valore. Decide il **primo** membro con chiave esattamente `tt.s` e valore `0` o `1`; i membri `tt.s` con altri valori si ignorano.

**Outbound**:

- se la chiamata parte mentre il processo serve uno scambio inbound (ingresso `inherited`), **eredita** la decisione di quello scambio (`sampled_by = "inherited"`); se la decisione ereditata è "non campionato", lo scambio non si cattura;
- altrimenti (job, code, timer) si usano i punti 3 e 4.

**Propagazione.** Per default tt **non modifica** il traffico dell'app. La sorgente PUÒ aggiungere il membro `tt.s=1` o `tt.s=0` al baggage delle chiamate in uscita **solo** verso gli host elencati in `sampling.propagate_to` (servizi interni strumentati), e **mai** verso un host che corrisponde a una `base` della policy. Se l'app ha già un baggage, il membro si aggiunge senza toccare gli altri. `tt-egress` DEVE togliere il membro `tt.s` prima di inoltrare una richiesta a un servizio esterno.

`tt-egress` decide come un servizio inbound interno: baggage (se `trust_baggage`), soggetto (se la policy ne indica uno e la richiesta lo contiene), trace, casuale.

---

## 13. Policy vuota

Con la policy minima (nessun servizio, nessuna regola, parole automatiche spente, `segments.allow` e `segments.hosts_allow` vuote, scoperta spenta), per qualsiasi scambio:

- **nessun valore** in ingresso compare in uscita, con queste sole eccezioni di **struttura**: il metodo (§3.3), il `content-type` normalizzato (§8.1), i **nomi** di header, cookie, query e chiavi JSON che rispettano le regole dei nomi (§8, §9.3) e, dalla v1.5, le **etichette** degli host esterni che rispettano le regole dell'etichetta sicura (§3.5) con la porta non di default;
- ogni foglia esce come forma `drop:*`, ogni segmento di path come `{drop:*}`, ogni host esterno come pattern (§3.5: etichette sicure o `{*}`, IP solo come classe), oppure come `host:unlisted` con `hosts.discovery: off`.

I nomi e le etichette degli host possono a loro volta contenere valori (una chiave JSON uguale al nome di una persona, un nome di cookie per utente, un sottodominio per cliente): l'intake li sorveglia con il controllo di cardinalità dei nomi e delle etichette ([event.md](event.md) §5.2). Le forme rivelano informazioni grossolane (tipo, formato, classe di lunghezza): è il **rischio residuo dichiarato** nel [threat model](../THREAT_MODEL.md) §7.

Questa è la garanzia G1 ed è verificata dai vettori e dai test generativi di ogni SDK.

---

## 14. Esempio completo

Policy (estratto, forma autore):

```yaml
segments: { auto_words: true, auto_words_expires_at: "2026-10-22T00:00:00Z" }
services:
  shop-api:
    match: { inbound: true }
    ops:
      "POST /orders":
        response:
          $.id: hmac(order)
          $.status: keep
          $.total: bucket(num, [0, 50, 100, 250])
```

Scambio in ingresso (inventato):

```http
POST /orders?promo=AUTUMN10 HTTP/1.1
Content-Type: application/json
Cookie: sid=9f8e7d6c5b4a

{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":""}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{"id":"ORD-2026-000184","status":"CREATED","total":73.40}
```

Uscita (con `tk1:k1:…` al posto del token reale):

```json
{"op":"POST /orders","req":{"body":{"email":"drop:str:email","items":[{"qty":"drop:int","sku":"drop:str:l32"}],"note":"drop:str:l8"},"cookies":{"sid":["drop:str:l32"]},"ct":"application/json","headers":{"content-type":["drop:str:l32"]},"path":"/orders","query":{"promo":["drop:str:l8"]},"size":"l128"},"resp":{"body":{"id":"tk1:k1:…","status":"keep:CREATED","total":"num:50-100"},"ct":"application/json","headers":{"content-type":["drop:str:l32"]},"size":"l128"},"route_source":"policy","service":"shop-api"}
```

Note:

- `sid=9f8e7d6c5b4a` ha 12 caratteri: troppo corto per `hex` (≥16) e con lettere, quindi non è `digits`. Esce come classe `l32`.
- Il `content-type` compare anche in `headers`, ma solo come forma. Per vederlo come valore servirebbe la regola `headers.content-type: keep`.
- `size` è la classe della lunghezza del corpo: 86 byte → `l128`, 57 byte → `l128`.
- In caso di divergenza tra un esempio in prosa e i vettori di conformità, **fanno fede i vettori**.

---

## 15. Modalità scoperta (onboarding)

Durante l'onboarding l'assistente policy deve mostrare **quanti valori distinti** ha ogni campo, senza vedere i valori. La modalità scoperta risolve il problema in modo limitato e a tempo.

- Si attiva solo con `discovery.enabled = true` **e** `now < discovery.expires_at` **e** `now < created_at + 7 giorni`, secondo l'orologio della sorgente. Il compilatore rifiuta `expires_at` oltre 7 giorni dalla compilazione ([policy.md](policy.md) §1.3).
- Per ogni foglia che riceve `drop` **per default** (non per regola esplicita), oltre alla forma la sorgente aggiunge all'evento, nel campo `disc`, la coppia `percorso → token corto`.
- **Percorso** (chiave di `disc`):
  - corpo JSON e form: la parte seguita dal `tt-path` della foglia **senza** il `$` iniziale, con i membri come `.name` (le chiavi collassate come `.*`) e gli elementi come `[*]`: `req.body` (radice scalare), `req.body.items[*].sku`, `resp.body.id`, `req.body.*` (campo form con nome collassato);
  - parti con nome: `<lato>.<parte>.<nome in uscita>`, quindi un nome collassato compare come `{*}`: `req.query.orderId`, `req.query.{*}`, `req.headers.user-agent`, `req.cookies.sid`, `resp.headers.<nome>`, `resp.cookies.<nome>`;
  - path: `req.path.<i>`, con `i` = indice **da 0** del segmento nel `req.path` completo (§3.2).
- **Valore** usato nell'HMAC: per le stringhe i loro byte, per i numeri entro i limiti di §5.3 la forma canonica, per booleani e `null` i byte ASCII `true`, `false`, `null`. Le foglie senza valore valido (`drop:str:invalid`, `drop:bytes`, numeri oltre i limiti) **non** producono voci.
- **Token corto**: `tkd:` + `base64url_nopad(HMAC-SHA256(key, epoch || 0x00 || "discovery" || 0x00 || percorso || 0x00 || valore)[0:4])`, cioè 6 caratteri. Il percorso nell'ingresso dell'HMAC impedisce di collegare valori uguali tra campi o servizi diversi.
- Per ogni percorso si emette **un solo** token per evento: se il percorso corrisponde a più foglie (array, nomi ripetuti), si usa quella il cui valore (come sopra) è minore per byte.
- Al massimo 4096 percorsi per evento: oltre, si tengono i primi 4096 in ordine di byte del percorso e si **omettono** gli altri (l'evento non si rifiuta).
- Durante la modalità scoperta gli host esterni non elencati escono come **pattern** (§3.1, §3.5), anche con `hosts.discovery: off`, per mostrarli nella pagina "Servizi scoperti". Fino alla v1.4 uscivano in chiaro: dalla v1.5 un'etichetta che sembra un valore è `{*}` anche durante la scoperta.
- Il token corto (32 bit) basta per stimare la cardinalità, ma collide spesso: non serve per correlare. L'intake DEVE ridurre `disc` a **sketch di cardinalità** (HyperLogLog, precisione ≥ 12) per percorso e NON DEVE conservare i token corti.
- Il dominio `discovery` è riservato.

---

## 16. Vettori di conformità

Il formato **normativo** dei vettori è `tt.conformance.vector/v1`, descritto in [`conformance/format.md`](../../conformance/format.md) e [`conformance/README.md`](../../conformance/README.md), con lo schema `conformance/schema/vector.v1.schema.json`. Un vettore per file, `conformance/vectors/<id>.json`; la policy è il **corpo compilato** (mai YAML); i byte si codificano come descritto lì.

Punti confermati da questa specifica:

- l'oggetto confrontato (`expected.canonical`) è quello di §2: contiene `sampled_by`, omette le mappe vuote, non contiene `status`, `net_error`, id e istanti;
- `trace_id` è un ingresso esplicito (§1);
- l'esito è uno tra `event`, `not_sampled` (con il motivo) e `refused` (con lo stato dell'heartbeat), nell'ordine di controllo di §1.

Per la revisione 1.1 il formato aggiunge (lo aggiorna chi mantiene `conformance/`): `req_body_consumed`/`resp_body_consumed`, `req_body_decoded`/`resp_body_decoded`, `inherited`, più righe in `hmac_key` (§7.1), l'uso di `now` anche per §4.3 e per `not_after`, e il gruppo della sorgente per il controllo di `targets.groups`.

Per la v1.5 (§3.1, §3.5, §3.6) i vettori 0007, 1134, 1137, 1140, 1142, 1340, 1342 e 1343 sono riscritti per il default `hosts.discovery: auto`; le loro copie con `hosts.discovery: off` e i casi nuovi (regole dell'etichetta, porte, IPv4/IPv6, punycode, maiuscole, punto finale, host lunghi, molte etichette, rifiuti del campo `hosts`) sono nella sezione 1900 di [`conformance/README.md`](../../conformance/README.md).

Le sorgenti espongono una funzione di test che esegue un vettore; nessun vettore richiede rete, orologio reale o casualità.

## 17. Chiarimenti v1.1.1

Le letture scelte dalla suite di conformità per le ambiguità rimaste aperte dopo la v1.1 sono **normative**. Il testo completo di ciascuna, con i vettori che la fissano, è in [`conformance/AMBIGUITIES.md`](../../conformance/AMBIGUITIES.md):

| Id | Regola normativa (in breve) |
|---|---|
| A-FRAMEWORK-ID | L'ingresso di §1 include `framework` (identificatore della tabella di §3.4); senza `framework` la `framework_route` non si usa e si passa al punto 2 |
| A-EVENT-SIZE-BASE | Il limite di §10.3 si misura sull'uscita del sanitizer (oggetto di §2), non sull'evento completo; il passo 4 corrisponde all'esito `refused` con motivo `event_too_large` |
| A-HDR-COLLAPSED-RULE | Una regola per nome si applica a un `{*}` solo se in quella parte è collassato un solo nome originale; altrimenti vale `drop` |
| A-CONTAINER-KEEP | Un `keep` ignorato su un contenitore non nasconde un `drop` più debole: il contenitore collassa |
| A-NOEQ-DISC, A-PATH-TIME, A-SUBJECT-OUTBOUND, A-GZIP-STRICT, A-FORM-TRUNC, A-PORT-ZEROS, A-KEY-DUPLICATE, A-CE-EMPTY | Come descritto in `conformance/AMBIGUITIES.md` |

In caso di differenza fra il testo di questa specifica e un vettore, prevale il vettore e si corregge il testo.

## 18. Fase Osserva (v1.6): nessun cambiamento per le sorgenti

La v1.6 ([policy.md](policy.md) §7) cambia **chi approva** una policy, non cosa fa il sanitizer: nessuna regola, nessun vettore e nessun byte di uscita cambia, gli identificatori dei formati restano `v1`. Le sorgenti continuano a verificare firma, coerenza, gruppo, scadenza, sequenza e il sottoinsieme di sicurezza di [hardening.md](hardening.md) §2 su **ogni** policy, anche su quelle firmate da keyguard senza approvazioni (`approval_mode: observe`): una sorgente non vede né usa il modo di approvazione.

Una policy della fase Osserva usa solo ciò che questa specifica già definisce:

- la policy di partenza è la policy di §13 più scoperta (§15) e parole automatiche (§4.3) a tempo, con i servizi propri dichiarati: escono solo forme, pattern degli host e token corti della scoperta;
- la versione Osserva aggiunge regole `hmac` (§5.4) sugli identificativi e `identity.subject` (§11) dal `sub` del JWT bearer o dall'header che il rilevamento automatico riconosce come utente ([policy.md](policy.md) §7.4): escono token `tk1:` al posto degli identificativi e il soggetto come token; il campionamento per soggetto (§12) comincia da quel momento;
- `keep` e `bucket` non compaiono mai in una policy firmata senza approvazioni; dalla v1.11 può comparire `code` (§5.6) sui campi di stato e di codice ([policy.md](policy.md) §1.5).

La garanzia G1 di §13 vale quindi anche per la fase Osserva, con i token HMAC al posto delle forme dei campi mascherati e, dalla v1.11, i codici (`keep:` con la forma di §5.6) sui campi di stato.

## 19. Valori di codice (v1.11)

La v1.11 aggiunge l'azione `code` (§5.6). Non cambia nessun byte di uscita per le policy che non la usano: tutti i vettori precedenti restano identici e gli identificatori dei formati restano `v1` (è un nuovo valore di enum del corpo compilato, cambiamento minor). I vettori nuovi sono nella sezione 1800 di [`conformance/README.md`](../../conformance/README.md): forme accettate, limiti di lunghezza, cifre, spazi e punteggiatura, caratteri Unicode simili alle lettere, valori non stringa, percorsi annidati e array, contenitori, `keep_max_bytes`, query, header, parametri di path, form, regole `errors`, precedenza, escape, scoperta (1810–1828) e i rifiuti H1/H2 con `code` (1850–1857).

**Compatibilità.** Una sorgente precedente alla v1.11 non conosce `code`: rifiuta il corpo (`policy_rejected`, schema) e continua con la policy precedente. Prima di lasciare che la versione Osserva automatica proponga `code` ([policy.md](policy.md) §7.4) si aggiornano le sorgenti; `fleet.observe.codes: false` in `tt-core` lo spegne finché non lo sono.

## 20. Documenti GraphQL (v1.14)

La v1.14 aggiunge l'azione `graphql` (§5.7) e il trattamento del corpo `application/graphql` (§9.1). Non cambia nessun byte di uscita per le policy che non la usano: tutti i vettori precedenti restano identici e gli identificatori dei formati restano `v1` (nuovo valore di enum del corpo compilato e nuovo prefisso di token, cambiamento minor). I vettori nuovi sono nella sezione 2000 di [`conformance/README.md`](../../conformance/README.md): forme dei documenti (operazioni con nome e anonime, variabili, frammenti, direttive, alias), valori in linea di ogni tipo, nomi che diventano `*`, errori lessicali e sintattici, limiti di annidamento e di lunghezza, parametro di query e corpo `application/graphql`, cancello di introspezione aperto e chiuso (alias, campi misti, documento non valido, nessuna regola nella richiesta), limite degli array con il cancello aperto, scoperta.

**Compatibilità.** Una sorgente precedente alla v1.14 non conosce `graphql`: rifiuta il corpo (`policy_rejected`, schema) e continua con la policy precedente, come per `code` (§19). Prima di lasciare che la versione Osserva automatica proponga `graphql` ([policy.md](policy.md) §7.4) si aggiornano le sorgenti; `fleet.observe.graphql: false` in `tt-core` lo spegne finché non lo sono.

## 21. Soggetto da un header JSON (v1.18)

La v1.18 aggiunge `identity.subject.json_path` (§11, passo 4 bis; [policy.md](policy.md) §7.1): gateway e backend intermedi passano spesso l'utente in un header il cui valore è un oggetto JSON (anche in base64), non un JWT. Non cambia nessun byte di uscita per le policy che non lo usano: tutti i vettori restano identici e gli identificatori dei formati restano `v1` (campo facoltativo nuovo del corpo compilato, cambiamento minor).

**Sorgenti.** Lo implementano tutte le sorgenti (dalla v1.18.1): le sorgenti Go (core, SDK Go, egress, OBI) e gli SDK node, python, java, dotnet e php, con gli stessi limiti e lo stesso comportamento in caso di errore (nessun soggetto, mai un errore). I vettori di conformità sono nella sezione 2100 di [`conformance/README.md`](../../conformance/README.md). Una sorgente precedente alla v1.18.1 che non lo conosce rifiuta un corpo con `json_path` (`policy_rejected`, schema) e continua con la policy precedente (§4 di [policy.md](policy.md), come per `code` e `graphql`). La versione Osserva automatica non propone mai `json_path`: lo sceglie una persona (`PUT /api/v1/fleet/groups/{group}/identity`).

**Profondità.** Il valore grezzo è lungo al più 8192 byte e si analizza per intero come in §9.2, senza un limite di profondità: un annidamento fuori dal percorso, comunque profondo, non cambia il risultato; il documento deve però essere tutto valido. (Dalla v1.18.1 anche le sorgenti Go: il limite di 64 livelli che avevano nell'analisi del `json_path` era una svista.)

## 22. Corpi XML e SOAP, multipart, documenti e corpi grandi (v1.19)

**Decisione di progetto.** traffic-twin deve coprire le casistiche comuni delle applicazioni reali restando **generico**: servizi SOAP/XML, caricamenti multipart, documenti in base64 dentro il JSON e liste grandi devono diventare contratti e mock senza aprire valori. Il comportamento è lo stesso per ogni applicazione; cambiano solo gli interruttori e i limiti della policy.

### 22.1 Interruttori e campi nuovi

Il corpo compilato PUÒ contenere l'oggetto `bodies` ([policy.md](policy.md) §2), con tutti i campi obbligatori:

| Campo | Tipo | Effetto |
|---|---|---|
| `xml` | booleano | Analisi dei corpi XML e SOAP (§22.2) |
| `multipart` | booleano | Analisi dei corpi `multipart/form-data` (§22.3) |
| `docs` | booleano | Forma dei documenti base64 (§22.4) |
| `max_large_body_bytes` | intero 0–67108864 | Limite dei corpi grandi (§22.5); 0 = spento |
| `large_array` | intero 0–1024 | Elementi tenuti negli array esterni di un corpo grande |
| `large_nested_array` | intero 0–1024 | Elementi tenuti negli array annidati in un elemento di array di un corpo grande |

`bodies` assente equivale a tutti gli interruttori spenti: il comportamento è quello delle versioni precedenti, byte per byte (tutti i vettori precedenti restano identici).

Nell'uscita compaiono tre campi nuovi, omessi quando non si applicano:

- `fmt` (in `req` e `resp`): `xml`, `soap11`, `soap12` o `multipart`, presente quando la parte ha un campo `body` e il trattamento scelto da §9.1 è XML o multipart (anche se il corpo è `trunc:size`, `drop:bytes` o un marcatore di errore). I corpi JSON, form e non analizzati non hanno `fmt`: il `ct` basta.
- `xmlns` (in `req` e `resp`): mappa `tt-path dell'elemento → ns:<pattern>` degli spazi dei nomi XML (§22.2 punto 9).
- `soap_action` (solo in `req`): il nome dell'operazione SOAP (§22.2 punto 11).

### 22.2 XML e SOAP

Il trattamento XML (§9.1) trasforma il documento in un **albero** con la stessa forma dei corpi JSON e poi applica §5, §9.3 e §9.4 come per il JSON. Il sanitizer NON DEVE usare un analizzatore XML generico: DEVE applicare esattamente le regole seguenti (sottoinsieme rigoroso di XML 1.0 + Namespaces), così tutte le sorgenti producono lo stesso albero e nessuna risolve entità o DTD.

1. **Byte.** Un BOM UTF-8 iniziale (`EF BB BF`) si toglie. Il resto DEVE essere UTF-8 valido (§0.2) e non contenere caratteri di controllo C0 (sotto U+0020) diversi da tab, LF e CR, surrogati, né U+FFFE o U+FFFF (DEL e i controlli C1 sono ammessi, come in XML 1.0). Poi `CR LF` e ogni `CR` isolato diventano `LF` (fini riga di XML 1.0 §2.11). Lo spazio XML è uno tra spazio, tab e LF.
2. **Prologo ed epilogo.** Prima dell'elemento radice sono ammessi solo spazi, commenti `<!-- … -->` (fino al primo `-->`) e istruzioni di elaborazione `<? … ?>` (fino al primo `?>`, compresa la dichiarazione `<?xml …?>`, il cui contenuto si ignora). Dopo la radice, gli stessi. Qualsiasi `<!DOCTYPE`, `<!ENTITY` o altra dichiarazione `<!` che non sia un commento o (dentro un elemento) una sezione `<![CDATA[`, testo fuori dalla radice, una seconda radice o la fine dei byte prima della radice rendono il corpo **non valido**. Le DTD e le entità esterne non si leggono mai: è la difesa contro XXE e l'espansione delle entità ([hardening.md](hardening.md) §3).
3. **Nomi.** Un nome è una sequenza non vuota di caratteri che inizia con una lettera ASCII, `_` o un carattere non ASCII e prosegue con lettere, cifre, `.`, `-`, `:`, `_` o caratteri non ASCII. Un nome con `:` DEVE avere esattamente un `:` non iniziale né finale (`prefisso:locale`); altrimenti il corpo è non valido.
4. **Tag.** Un tag di apertura è `<` nome, poi zero o più attributi ciascuno **preceduto** da almeno uno spazio XML (`nome`, spazi opzionali, `=`, spazi opzionali, valore tra `"` o `'` senza `<`), poi spazi opzionali e `>` oppure `/>`. Due attributi con lo stesso nome qualificato rendono il corpo non valido. Un tag di chiusura è `</` nome, spazi opzionali, `>`, con lo stesso nome qualificato dell'apertura. Un tag di apertura **non vuoto** (che non termina con `/>`) quando sono già aperti 256 elementi rende il corpo non valido: un elemento vuoto `<x/>` può quindi stare a profondità 257 (vettori 2325, 2327, 2358).
5. **Riferimenti.** Nel testo e nei valori degli attributi si risolvono solo `&lt;` `&gt;` `&amp;` `&apos;` `&quot;` e i riferimenti numerici `&#N;` / `&#xH;` (cifre decimali, o esadecimali maiuscole o minuscole) il cui punto di codice è un carattere XML (`#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`). Qualsiasi altro `&` (entità sconosciuta, `&` isolato, riferimento senza `;`, punto di codice fuori dall'insieme) rende il corpo non valido. Nei valori degli attributi ogni tab e LF **letterale** (dopo il punto 1) diventa uno spazio; i riferimenti numerici restano quello che indicano. Le sezioni `<![CDATA[ … ]]>` (fino al primo `]]>`) danno il loro contenuto alla lettera; un `]]>` nel testo normale è ammesso (vettore 2328). Commenti e istruzioni dentro gli elementi si ignorano.
6. **Spazi dei nomi.** Gli attributi `xmlns` e `xmlns:p` dichiarano gli spazi dei nomi per l'elemento e i suoi discendenti (`xmlns:` con prefisso vuoto o con `:` nel prefisso è non valido; `xmlns:p=""` è ammesso e lega `p` a «nessuno spazio»). Lo spazio di un elemento è quello del suo prefisso, o quello di default (`xmlns`) senza prefisso; il prefisso `xml` vale `http://www.w3.org/XML/1998/namespace` senza dichiarazione; un prefisso non dichiarato (anche su un attributo) rende il corpo non valido. `xmlns=""` toglie lo spazio di default. Le dichiarazioni **non** compaiono nell'albero.
7. **Albero.** Ogni elemento dà un valore:
   - senza attributi (escluse le dichiarazioni) e senza elementi figli: la **stringa** del suo testo (concatenazione del testo e delle sezioni CDATA, anche vuota);
   - altrimenti un **oggetto** con, nell'ordine: gli attributi come membri `@` + nome locale (il prefisso si toglie; con due attributi dello stesso nome locale vale l'ultimo, nella sua posizione, come §9.3 punto 1); poi i figli, raggruppati per nome locale nell'ordine della prima comparsa: un nome che compare una volta dà il valore del figlio, uno che compare più volte un **array** dei valori nell'ordine del documento; infine, se il testo diretto dell'elemento contiene un carattere diverso da spazio, tab, LF e CR, il membro `#text` con quel testo (non tagliato).

   Il corpo è l'oggetto `{ <nome locale della radice>: <valore della radice> }`. Tutte le foglie sono stringhe: `keep`, `code`, `hmac` e `bucket(time)` lavorano sulla stringa, `bucket(num)` non si applica (diventa `drop`), come per i form (§8.3). Il prefisso e lo spazio dei nomi non cambiano la chiave: figli con lo stesso nome locale in spazi diversi formano lo stesso gruppo.
8. **Chiavi.** Le regole di §9.3 valgono sull'albero con una sola differenza: `#text` è sempre letterale e una chiave `@` + nome è letterale se e solo se il nome rispetta la regola dei nomi; le chiavi degli elementi seguono la regola dei nomi come le chiavi JSON (`<ORD-2026000184>` esce sotto `{*}`). Nei corpi JSON `@type` e `#text` restano chiavi dinamiche come prima. La profondità (`max_depth`, §9.2) si conta sull'albero: l'oggetto del corpo ha profondità 1. I `tt-path` delle regole usano `.@nome` e `.#text` (§5.0); un elemento ripetuto è un array, quindi lo raggiunge `[*]` (`$.Envelope.Body.GetOrderResponse.GetOrderResult.line[*].@code`). Le chiavi di `disc` seguono la stessa forma (`req.body.order.@id`, `req.body.order.mixed.#text`).
9. **`xmlns`.** Si visitano gli elementi in ordine di documento fino alla profondità XML `max_depth` (la radice ha profondità 1). Per ogni elemento il cui spazio dei nomi è diverso da quello del genitore (per la radice: diverso da «nessuno») si aggiunge, se non c'è già, la voce `percorso → ns:<pattern>`. Il percorso è `$` seguito, per ogni elemento dalla radice a quello, da `.` + nome locale (o `.*` se il nome non è letterale) e da `[*]` se l'elemento appartiene a un gruppo ripetuto. Il pattern di uno spazio:
   - nessuno spazio (assente o `xmlns=""`) → `ns:{none}`;
   - un URI con più di 512 byte, con un byte fuori da `0x21–0x7E`, o con `@`, `{` o `}` → `ns:{*}`;
   - altrimenti `ns:` + l'URI con ogni sequenza massimale di `[A-Za-z0-9_-]` che ha più di 64 byte, sei cifre consecutive o dodici esadecimali consecutivi (`[0-9A-Fa-f]{12}`) sostituita da `{*}`; gli altri caratteri restano. Esempi: `http://schemas.xmlsoap.org/soap/envelope/` resta uguale; `http://a.example/customers/3912345678/x` → `ns:http://a.example/customers/{*}/x`; `mailto:mario.rossi@example.com` → `ns:{*}`.

   Al massimo 64 voci: oltre, si tengono le prime 64 e si aggiunge `{trunc}` con `trunc:keys:<classe>` sul numero di voci. La mappa vuota si omette. Il mock usa queste voci per rispondere con gli stessi spazi dei nomi.
10. **`fmt`.** `soap11` se la radice ha nome locale `Envelope` ed è nello spazio `http://schemas.xmlsoap.org/soap/envelope/`; `soap12` con `http://www.w3.org/2003/05/soap-envelope`; `xml` in ogni altro caso, compreso il corpo non valido.
11. **`soap_action`.** Solo per la richiesta, con `bodies.xml` attivo e un `ct` di richiesta XML (§9.1), anche senza corpo. Il valore grezzo è quello normalizzato dell'header `soapaction` (SOAP 1.1, §8.0); senza header, il parametro `action` del `content-type` (SOAP 1.2). I parametri del `content-type` si leggono così: il valore normalizzato si divide sul byte `;`, il primo pezzo si scarta, gli altri si tagliano di spazi e tab e si dividono sul primo `=` (un pezzo senza `=` si ignora); il nome si taglia e si confronta in minuscolo ASCII; il valore si taglia e, se inizia con `"`, deve finire con `"` (lunghezza ≥ 2, altrimenti il pezzo si ignora) e perde le due virgolette, senza altri escape; vale il primo parametro con quel nome; un valore non UTF-8 non ha parametri. Dal valore grezzo (header non UTF-8 → `{*}`): si tolgono spazi e tab ai bordi e una coppia di `"` esterne; se resta vuoto, `soap_action` è assente; altrimenti si prende la parte dopo l'**ultimo** `/`, `#` o `:` e, se rispetta la regola dei nomi (§9.3 punto 3), esce così com'è, altrimenti `{*}`. Esempi: `"http://ws.example/orders/v2/GetOrder"` → `GetOrder`; `urn:x#Renew` → `Renew`; `""` → assente; `http://x.example/` → `{*}`. L'header `soapaction` esce comunque anche in `headers` secondo la sua regola (default `drop`). `soap_action` è un nome come una chiave JSON (struttura): discrimina le operazioni SOAP che condividono path e metodo.
12. **Errori.** Qualsiasi violazione dei punti 1–6 dà `body = "trunc:invalid-xml"` (con `fmt: "xml"`), senza voci di scoperta né `xmlns`. Un errore in qualsiasi punto del documento invalida tutto, come per il JSON (§9.2).

Limite noto: l'ordine tra figli di nome diverso non sopravvive (l'oggetto è ordinato per chiave, §10.1) e un elemento che compare una volta non è un array: chi scrive regole per una lista SOAP di lunghezza variabile scrive sia `.x` sia `.x[*]`.

### 22.3 multipart/form-data

1. **Confine.** Il parametro `boundary` del `content-type` (letto come al §22.2 punto 11) DEVE corrispondere a `^[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]$` (RFC 2046 §5.1.1). Sia `D` = `--` + confine.
2. **Delimitatori.** Il primo delimitatore è `D` all'inizio del corpo, oppure la prima occorrenza di `CR LF D` (il preambolo prima si ignora). Dopo ogni delimitatore: se seguono `--` è la chiusura (il resto, l'epilogo, si ignora); altrimenti, saltati spazi e tab, DEVONO seguire `CR LF`, poi la parte fino alla prossima occorrenza di `CR LF D`. Una parte senza delimitatore successivo rende il corpo non valido.
3. **Intestazioni della parte.** Se la parte inizia con `CR LF` non ha intestazioni; altrimenti finiscono al primo `CR LF CR LF` (assente → non valido). Ogni riga è `nome:valore`, con il nome non vuoto di caratteri token di RFC 9110 (lettere, cifre e ``!#$%&'*+.^_`|~-``); una riga senza `:` o con un nome fuori da quei caratteri (anche una continuazione) rende il corpo non valido. I nomi si confrontano in minuscolo ASCII (come ogni conversione di questa sezione), vale la prima occorrenza, il valore si taglia di spazi e tab.
4. **`content-disposition`.** DEVE esserci, in UTF-8 valido, con tipo `form-data` (la parte prima del primo `;`, tagliata, senza distinzione di maiuscole) e il parametro `name`. I parametri: dopo il tipo si saltano spazi, tab e `;`; il nome va fino a `=` o `;` (tagliato, in minuscolo); il valore, dopo `=` e gli spazi, è una stringa tra virgolette (con `\x` → `x`; senza virgoletta di chiusura → non valido; dopo la chiusura solo spazi e tab fino a `;` o alla fine, altrimenti non valido) oppure il testo fino a `;` tagliato; un parametro senza `=` vale la stringa vuota; vale la prima occorrenza. Senza questi requisiti il corpo è non valido.
5. **Parti.** Una parte con il parametro `filename` o `filename*` è una **parte file**; le altre sono **campi**. Il nome della parte (il valore di `name`, senza decodifica percentuale) segue la regola dei nomi (§9.3) come i nomi dei form: fuori regola esce `{*}`.
   - Un **campo** si tratta come un valore di form (§9.1): i suoi byte, se UTF-8 validi, sono una stringa con l'azione di `$.nome` o `$.*`; altrimenti `drop:bytes`. Nessuna decodifica dei byte.
   - Una **parte file** esce sempre come `drop:file:<tipo>:<classe documento>`, qualunque regola ci sia, e non aggiunge voci di scoperta: il contenuto non si legge oltre il riconoscimento del tipo. Il tipo è quello dei byte iniziali (§22.4 punto 3, sui byte della parte); se non è riconosciuto, quello del `content-type` della parte (parte prima di `;`, tagliata, in minuscolo): `text/plain` → `text`, `text/csv` → `csv`, `application/json` → `json`, `application/xml` e `text/xml` → `xml`; altrimenti `bin`. La classe è sulla lunghezza dei byte della parte.
6. **Uscita.** Come un form: `nome → [token]` nell'ordine di comparsa, con il limite dei nomi e `max_array` per nome (§8.2), `{trunc}` come array. Un corpo con la sola chiusura è `{}`. Una violazione dei punti 1–4 dà `body = "trunc:invalid-multipart"`.

### 22.4 Documenti base64

Con `bodies.docs`, la forma di una stringa valida (§6.2) che non è riconosciuta da un formato di §6.3 si calcola prima così:

1. Se la stringa inizia con `data:`, la parte fino alla prima `,` DEVE essere composta da byte `0x21–0x7E` e terminare con `;base64`; il resto dopo la `,` è il contenuto. Altrimenti il contenuto è l'intera stringa.
2. Il contenuto DEVE avere almeno 16 caratteri, solo caratteri dell'alfabeto base64 (`A–Z a–z 0–9 + /`) o base64url (`- _`, anche mescolati) seguiti da al più due `=`; con `=` la lunghezza totale è multipla di 4; la lunghezza senza `=` modulo 4 non è 1. Nessuno spazio. I bit di riempimento finali si ignorano.
3. Si decodifica (`-` vale `+`, `_` vale `/`) e si guarda il **tipo** dai primi byte, in quest'ordine: `%PDF-` → `pdf`; `89 50 4E 47 0D 0A 1A 0A` → `png`; `FF D8 FF` → `jpeg`; `GIF87a` o `GIF89a` → `gif`; `RIFF` con `WEBP` ai byte 8–11 → `webp`; `D0 CF 11 E0 A1 B1 1A E1` → `ole` (vecchi documenti Office); `PK 03 04` → `docx` se i byte contengono `word/document.xml`, altrimenti `xlsx` se contengono `xl/workbook.xml`, altrimenti `pptx` se contengono `ppt/presentation.xml`, altrimenti `zip`.
4. Con un tipo, la forma è `drop:doc:<tipo>:<classe documento>`; senza, si continua con §6.2 (classe di lunghezza).

Le **classi documento** sono sulla lunghezza dei byte decodificati: fino a 1024 `l1k`, fino a 16384 `l16k`, fino a 131072 `l128k`, fino a 1048576 `l1m`, fino a 8388608 `l8m`, oltre `lmax`.

La regola vale per ogni forma di stringa (corpi, query, header, cookie, segmenti di path), quindi anche quando un `keep` o un `code` degradano a forma e con un `drop` esplicito; non cambia l'HMAC né la scoperta (il valore resta quello della stringa). Il mock genera un documento **valido** dello stesso tipo e della stessa classe ([mock.md](mock.md)).

### 22.5 Corpi grandi

Con `bodies.max_large_body_bytes` = `L` > 0, il punto 4 di §9.0 diventa:

- il tetto della decodifica è `max(limits.max_body_bytes, L) + 1` byte;
- un corpo la cui lunghezza (decodificata) supera `limits.max_body_bytes` si analizza in **modalità corpo grande** se è al più `L` **e** il suo trattamento (§9.1) è JSON, form, XML o multipart; altrimenti `body = "trunc:size"`, `size = "lmax"`, come prima;
- in modalità corpo grande vale tutto il resto della specifica, con un'unica differenza: un array (anche di elementi XML ripetuti) che non ha array tra i suoi antenati tiene i primi `bodies.large_array` elementi, uno che ha almeno un array tra gli antenati i primi `bodies.large_nested_array`; il marcatore `trunc:n:<classe>` porta sempre la classe del numero totale. Le mappe di nomi (form, multipart) tengono `max_array` valori per nome come sempre.

La sorgente DEVE quindi conservare `max(limits.max_body_bytes, L) + 1` byte del corpo (§9.0) e contare il resto. Un corpo entro `max_body_bytes` non cambia: usa `max_array`. Il limite dell'evento (§10.3) resta: un corpo grande che produce più di 512 KiB diventa `trunc:size` come prima. Così i contratti degli endpoint di lista con oggetti ricchi si deducono anche oltre `max_body_bytes`, senza far crescere l'evento oltre i limiti.

### 22.6 Compatibilità e vettori

Una sorgente precedente alla v1.19 non conosce `bodies` né la forma `alnum`: rifiuta il corpo (`policy_rejected`, schema) e continua con la policy precedente. `tt-core` scrive `bodies` solo se `fleet.sanitizer.bodies` è attivo e `code(alnum)` nella versione Osserva solo se `fleet.observe.codes` e `fleet.observe.code_digits` lo sono: si spengono finché le sorgenti non sono aggiornate. `tt-core` accetta gli eventi di sorgenti di entrambe le versioni ([event.md](event.md) §5). I vettori nuovi sono nella sezione 2200 di [`conformance/README.md`](../../conformance/README.md): 2200–2213 `code(alnum)`, 2220–2233 documenti, 2240–2267 multipart, 2300–2362 XML e SOAP (2327 e 2328: i casi limite ammessi; compresi XXE, espansione di entità, annidamento, riferimenti e nomi non validi), 2400–2412 corpi grandi, 2450–2453 rifiuti di `bodies` e dei `tt-path` nuovi.
