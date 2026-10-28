# Specifiche v1.21 di traffic-twin

Queste specifiche congelano i **contratti tra i componenti**. Chi sviluppa un componente (SDK, core, keyguard, miner, mock, exporter, UI) parte da qui e non inventa formati propri. Chi implementa a partire da una versione precedente legge il [changelog](#changelog) qui sotto.

## Indice

| Documento | Formato | Schema / API | Chi lo produce → chi lo consuma |
|---|---|---|---|
| [sanitizer.md](sanitizer.md) | `tt.sanitizer/v1` (rev. 1.1, pattern degli host v1.5, corpi della v1.19) | vettori in [`conformance/`](../../conformance/format.md) | Normativo per tutte le sorgenti |
| [policy.md](policy.md) | `tt.policy/v1`, `tt.policy.body/v1`, `tt.policy.compiled/v1` | [`policy.v1`](../../schemas/policy.v1.schema.json), [`policy-compiled.v1`](../../schemas/policy-compiled.v1.schema.json) | UI/persona → `tt-core` → keyguard (firma) → sorgenti |
| [event.md](event.md) | `tt.http.exchange/v1` su OTLP/HTTP JSON | [`event.v1`](../../schemas/event.v1.schema.json) | Sorgenti → intake |
| [rules.md](rules.md) | `tt.rules/v1` | [`rules.v1`](../../schemas/rules.v1.schema.json) | Miner → UI → generatore, mock |
| [pack.md](pack.md) | `tt.pack/v1`, `tt.pack.sig/v1`, `tt.faults/v1`, `tt.scenarios/v1`, `tt.gate-report/v1`, `tt.world/v1` | [`pack-manifest.v1`](../../schemas/pack-manifest.v1.schema.json) | Gate + keyguard → `tt-mock`, exporter |
| [mock.md](mock.md) | comportamento di `tt mock` | [`control-api.v1.openapi.yaml`](../../api/control-api.v1.openapi.yaml) | Pacchetto → `tt-mock` → test; exporter come riferimento |
| [hardening.md](hardening.md) | controlli dell'intake oltre lo schema; sottoinsieme di sicurezza delle sorgenti (normativo dalla v1.3) | — | Intake (parte 1) e tutte le sorgenti (parte 2) |
| [keyguard.md](keyguard.md) | `tt.keyguard/v1` | [`keyguard-api.v1.openapi.yaml`](../../api/keyguard-api.v1.openapi.yaml) | `tt-core` → keyguard |
| API Fleet (sorgenti) | — | [`fleet-api.v1.openapi.yaml`](../../api/fleet-api.v1.openapi.yaml) | Sorgenti → `tt-core` |
| API di amministrazione | — | [`admin-api.v1.openapi.yaml`](../../api/admin-api.v1.openapi.yaml) | UI → `tt-core` |
| API di controllo del mock | — | [`control-api.v1.openapi.yaml`](../../api/control-api.v1.openapi.yaml) | Test → `tt-mock` |
| [Threat model](../THREAT_MODEL.md) | — | — | Tutti |

## Convenzioni

- Prosa in italiano; identificatori, campi, codice e commenti in inglese.
- **DEVE**, **NON DEVE**, **DOVREBBE**, **PUÒ** = MUST, MUST NOT, SHOULD, MAY (RFC 2119).
- Gli schemi sono JSON Schema **draft 2020-12** e usano solo espressioni regolari **senza lookaround**, così funzionano anche con validatori basati su RE2 (Go). Le espressioni si valutano sull'intera stringa (§0.1 del sanitizer).
- Tutti gli esempi usano dati **inventati** (e-commerce, corriere, host `*.example`). I token negli esempi in prosa sono finti: i byte veri sono nei vettori di conformità.

## Versioni

Ogni formato ha un identificatore `tt.<nome>/v<MAJOR>` nel campo `format` (o `schema` per gli eventi).

- **Patch** (chiarimenti, esempi): nessun cambiamento di comportamento; nessun cambio di identificatore.
- **Minor** (campi opzionali nuovi, nuovi valori di enum che un lettore v1 può ignorare): l'identificatore resta `v1`; il cambiamento si annota nel changelog. Un lettore v1 DEVE ignorare i campi sconosciuti **solo** dove lo schema lo consente.
- **Major** (qualsiasi cambiamento che altera l'output del sanitizer, la semantica di un campo o rimuove qualcosa): nuovo identificatore `v2`. `tt-core` DEVE accettare v1 e v2 per almeno una release minore.

Eccezione: la **revisione 1.1** cambia l'output del sanitizer pur mantenendo l'identificatore `v1`, perché nessuna sorgente v1.0 è mai stata rilasciata. Da qui in poi qualsiasi cambiamento di output, anche di un solo byte, è un cambiamento major. Seconda e ultima eccezione: la **v1.5** (pattern degli host) cambia il `service` degli eventi outbound non dichiarati per decisione di prodotto, con la compatibilità descritta nel [changelog](#v150--scoperta-automatica-degli-host-admin-api-170-ottobre-2026) (modalità stretta byte per byte, corpi di default leggibili dalle sorgenti precedenti, intake che accetta entrambe le forme).

Gli schemi in `schemas/` usano `additionalProperties: false` quasi ovunque: è voluto, perché un campo inatteso in un evento è un possibile canale di fuga. Per aggiungere un campo serve una nuova versione minor dello schema, distribuita a `tt-core` prima che alle sorgenti.

## Changelog

### v1.21.0 — il mock risponde alle operazioni SOAP e XML (mock 1.13, rules 1.10.1, ottobre 2026)

Identificatori invariati (`v1`); l'uscita del sanitizer non cambia. Generico: nessun nome, path o spazio dei nomi di un'applicazione è scritto nel prodotto.

- **Operazioni SOAP e XML nel mock (mock.md §10).** Un `POST` XML all'endpoint di operazioni logiche `<op>#<nome>` ([event.md](event.md) §6.1) sceglie l'operazione da `SOAPAction`, dal parametro `action` del `Content-Type` (SOAP 1.2) o dal primo elemento del `Body` (SOAP 1.1 e 1.2; l'elemento radice senza busta); un'operazione HTTP con un corpo XML nel contratto (*plain old XML*) risponde in XML allo stesso modo. La richiesta si legge con l'analizzatore chiuso delle sorgenti (sanitizer §22.2, hardening §3: niente DTD né entità, annidamento ≤ 256) e si presenta a validazione, regole e letture come albero (`@nome`, `#text`, elementi ripetuti), adattata allo schema. La risposta si costruisce come per il JSON (entità, regole, sessioni, formati degli id, date relative, valori calcolati) e si scrive in XML con la busta SOAP e gli spazi dei nomi di `x-tt-xml`, attributi, testo ed elementi ripetuti.
- **Fault (mock.md §10.4).** Guasti osservati o forzati come SOAP Fault (1.1 `faultcode`/`faultstring`/`detail`, 1.2 `Code`/`Reason`/`Detail`) con lo status del guasto; il corpo XML osservato per lo status se c'è (codici resi validi); un corpo d'errore scritto da una persona (§4.1) servito così com'è se è XML, come testo del fault se è una stringa, come `detail` se è un oggetto. Un errore deciso dal mock e mai osservato segue il binding HTTP di SOAP (`500` per 1.1, `400` per un fault del mittente in 1.2). Operazione mai osservata: fault `operation not observed: <nome>` con `X-TT-Unmatched: no-operation`; corpo non XML o fuori dal sottoinsieme: fault del mittente `invalid-request`, mai un'eco del corpo.
- **`tt-path` nelle regole (rules 1.10.1).** Il pacchetto, il miner (editor delle regole) e lo schema [`rules.v1`](../../schemas/rules.v1.schema.json) accettano i passi `.@nome` e `.#text` del sanitizer §5.0 (v1.19), così `created_by.state`, `read_by.by`, `key` e i legami delle regole raggiungono gli attributi e il testo dei corpi XML.
- **Console.** Le operazioni SOAP si leggono come «SOAP GetOrder» con l'endpoint (come le operazioni GraphQL); la pagina Mock dice che il mock risponde anche a SOAP e XML.

### v1.20.0 — il mock di un'applicazione vera da capo a fondo: documenti, date relative, valori calcolati, corpi d'errore, S3, pagine di terzi (mock 1.12, pack 1.8, rules 1.10, admin-api 1.23.0, control-api 1.5.0, ottobre 2026)

Identificatori invariati (`v1`); l'uscita del sanitizer non cambia (le estensioni del sanitizer sono della v1.19.0). Principio di progetto: lo strumento resta **generico**: nessun nome, path, formato o fornitore di un'applicazione è scritto nel prodotto, tutto è configurazione.

- **Documenti sintetici validi (mock.md §2.9, pack.md §4.1).** Una risposta con un tipo di documento (`application/pdf`, immagini, ZIP, Office Open XML) o un campo JSON marcato come documento in base64 (`x-tt-value.format: doc` con `doc_type`/`doc_class` dalla forma `drop:doc:<tipo>:<classe>`, oppure `contentEncoding`/`contentMediaType`) riceve un file **valido** di quel tipo e di quella classe di dimensione, generato senza dipendenze (PDF con testo, PNG/JPEG/GIF segnaposto, ZIP, DOCX, XLSX; limiti noti PPTX, OLE, WebP), con il solo testo sintetico (cliente del mondo, id, data dell'orologio) e `Content-Type`/`Content-Length`/`Content-Disposition` coerenti. L'inferenza dei contratti scrive `doc_type`, `doc_class`, le parole chiave di contenuto e un esempio valido; la grammatica dei token accetta `drop:doc:`/`drop:file:`. Gate: `pii-detectors` controlla il testo dei documenti con i clienti del mondo (`file: "documents"`).
- **Date relative (pack.md §4.4, mock.md §2.10).** `x-tt-value.date_offset = {min, max}`: l'inferenza la ricava, lato core, dalle fasce `bucket(time)` e dall'istante degli eventi (90% centrale, ogni estremo con almeno `k_min` soggetti, arrotondato verso l'esterno; nessun valore nuovo dalle sorgenti); una persona la sceglie per nome di campo nella console (admin-api `GET /api/v1/date-offsets`, `PUT|DELETE /api/v1/date-offsets/{field}`, audit `dateoffset.set`/`dateoffset.delete`), sopra quella appresa. Mondo e mock generano la data come orologio + scarto; le entità preesistenti (`seed`) contano lo scarto da `t0`, non dall'inizio della finestra, così un rinnovo «tra 30 giorni» è ancora davanti quando il mock parte. Gate: `provenance` accetta solo scarti validi. Corretto anche il mondo, che scriveva un numero nei campi `bucket(time)` senza scarto.
- **Valori calcolati (rules.md §3.15).** I valori di `create`/`set` degli effetti causali possono essere `{"$derive": {fn, args, …}}`: `copy`, `sum`, `count`, `add`, `sub`, `mul`, `div`, `min`, `max`, `round`, `date` (orologio + scarto), `template` (un formato degli id, pack.md §4.3); argomenti `${var}`, `${field:percorso}` (anche `[*]`), `${effect:id}`, `${now}`, annidati fino a 4 livelli. Valgono anche negli effetti con `target_key` e `target_all` (rules 1.9); la copia semplice dalla richiesta resta `${var}` e i conteggi letti restano aggregati (§2.12). Stesso codice in caricatore del pacchetto, miner (controlli contro i contratti: `bad_derived`, `derived_type`, `unknown_field`), mondo e mock. Esportatori: perdita `derived-value` (il campo si omette). Schema `rules.v1`: `$defs/derivedValue`, `$defs/effectValues`.
- **Corpi d'errore (mock.md §4.1, rules.md §3.6).** `respond.body` negli effetti, `example` e `body` nelle regole di guasto dell'API di controllo e dei preset (`scenarios.json`, schema `pack-manifest.v1`): un corpo scritto da una persona vince sull'esempio del contratto. Gate: rilevatori di dati personali su ogni corpo; provenienza non richiesta.
- **API compatibile S3 (mock.md §8).** `--s3`, `--s3-host`, `--s3-buckets`, limiti per oggetto e per sessione: path style (`/__s3/<bucket>/<chiave>` o host dedicato) e virtual host; Put/Get (con `Range`)/Head/Delete/Copy, ListObjectsV2 e v1, DeleteObjects, multipart; corpi `aws-chunked` degli SDK; **qualsiasi firma SigV4 accettata senza controllo** (solo test); oggetti in memoria per sessione; registro con `service: "s3"` senza i dati.
- **Pagine di terzi (mock.md §9, control-api 1.5.0, admin-api 1.23.0).** Pagine configurabili (`--pages`, `PUT /__tt/pages`, console «Pagine di terzi» per gruppo con `GET|PUT /api/v1/mocks/pages` e la risposta al rapporto) servite a `/__pages/<id>` con CSP stretta e pulsanti; il clic esegue la richiamata server a server (metodo, URL con host fisso, header, corpo con segnaposti, firma HMAC facoltativa; la cifratura non è supportata) e riporta il browser all'URL di ritorno (host da segnaposto solo se in `return_hosts`). Collegamenti nelle risposte dei contratti (`links[]`), con l'**oggetto collegato** (`entity` + `ref_path`, o l'oggetto statico della creazione) i cui campi cambia il pulsante scelto (`buttons[].set`, per esempio `status: "{value.code}"`) e l'URL di ritorno letto dalla richiesta di creazione (`return_from`, segnaposto `{link.return}`, host sempre in `return_hosts`); completamento automatico per preset o sessione, completamento dai test senza browser (`POST /__tt/sessions/{s}/pages/{id}/complete`, `PUT …/auto`); comandi della console ammessi anche per questi percorsi.
- **Console.** Contratti → servizio → «Date relative»; Mock → «Pagine di terzi» (con i campi dell'oggetto collegato per pulsante e l'URL di ritorno dalla richiesta nei collegamenti); editor di regole con «Valore calcolato» guidato e anteprima, e «Corpo d'errore» negli effetti `respond` (it/en).

### v1.19.0 — codici con cifre, corpi XML/SOAP, multipart, documenti base64 e corpi grandi (sanitizer 5.6 e 22, policy 1.5.1 e 2, event 2, 5 e 6.1, pack 4, hardening I12 e 3, admin-api 1.22.0, ottobre 2026)

Identificatori invariati (`v1`): campi facoltativi nuovi nel corpo compilato (`bodies`, `shape` di `code`) e negli eventi (`fmt`, `xmlns`, `soap_action`, nuovi marcatori e forme), cambiamento minor. **Nessun byte di uscita cambia** per le policy senza `bodies` e senza `code(alnum)`: tutti i vettori precedenti restano identici. Generico: nessun nome di un'applicazione, gli stessi interruttori per tutte.

- **sanitizer.md §5.6, policy.md §1.5.1.** Forma `alnum` di `code` (`{"action":"code","shape":"alnum"}`, autore `code(alnum)`): escono solo valori `^[A-Za-z0-9_.-]{1,16}$`, altrimenti la forma. `tt-core` e keyguard accettano `code` (entrambe le forme) su ogni campo che non sia un cookie, un header di credenziali, un parametro OAuth `code`/`state`, un nome con una parola esclusa o che finisce con una parola personale (`policy.CodeRuleSafe`): una persona può marcarlo come codice dalla console senza approvazioni. La versione Osserva propone `code(alnum)` sui nomi di codice con valori a cifre (`fleet.observe.code_digits`).
- **Guardia di cardinalità (event.md §5.2).** Un campo in chiaro (`keep`, `code`, `code(alnum)`) con più di 50 valori distinti va in quarantena da solo (riscrittura dei valori salvati e futuri) con l'allarme `value_cardinality`; la versione Osserva non gli propone più `code`.
- **sanitizer.md §22.2, hardening.md §3.** Corpi XML e SOAP (`bodies.xml`): sottoinsieme XML 1.0 + Namespaces chiuso, uguale in tutte le sorgenti, senza DTD né entità (XXE ed espansione di entità impossibili), annidamento ≤ 256; albero con attributi `@nome`, testo misto `#text`, elementi ripetuti come array; `tt-path` con `.@nome` e `.#text`; `xmlns` (pattern degli spazi dei nomi), `fmt` (`xml`, `soap11`, `soap12`), `soap_action` (nome dell'operazione); errori → `trunc:invalid-xml`.
- **sanitizer.md §22.3.** `multipart/form-data` (`bodies.multipart`): parti di testo come campi di form, parti file come `drop:file:<tipo>:<classe>`; errori → `trunc:invalid-multipart`.
- **sanitizer.md §22.4.** Documenti base64 (`bodies.docs`): una stringa base64 (o data URI) di un PDF, PNG, JPEG, GIF, WebP, OLE, ZIP, DOCX, XLSX o PPTX esce come `drop:doc:<tipo>:<classe documento>` in ogni posto in cui esce una forma.
- **sanitizer.md §22.5.** Corpi grandi (`bodies.max_large_body_bytes`, default di `tt-core` 8 MiB): un corpo JSON, form, XML o multipart oltre `max_body_bytes` si analizza ancora, con gli array troncati a `large_array` (50) e `large_nested_array` (5) e il marcatore `trunc:n:<classe>` del totale; le sorgenti tengono in memoria il limite grande + 1 byte.
- **event.md §2, §5.1, §6.1; hardening.md I12.** L'intake accetta i campi nuovi solo sotto gli interruttori della policy firmata che li producono, con `ct` coerente; un'operazione SOAP è salvata come operazione logica `<op>#<nome>` (da `soap_action` o dall'unico elemento del `Body`), come le operazioni GraphQL.
- **pack.md §4.** Contratti: `x-tt-xml` sul tipo di contenuto (`fmt` e spazi dei nomi per percorso di elemento), attributi XML con `xml.attribute`; i corpi multipart sono form; un array troncato non dà `minItems`. Il gate ammette in `x-tt-xml` solo `fmt` e pattern `ns:` validi.
- **policy.md §2, configurazione.** `tt-core` scrive `bodies` in ogni corpo compilato con `fleet.sanitizer` (default: tutto acceso); `fleet.sanitizer.bodies: false` e `fleet.observe.code_digits: false` finché ci sono sorgenti precedenti alla v1.19 (che rifiutano la policy e continuano con la precedente).
- **API di amministrazione 1.22.0.** `QuarantineItem.alert` con `value_cardinality`; azioni dei campi `code(alnum)`. Console: «code (con cifre)» nella scelta dell'azione e l'etichetta «troppi valori» in quarantena.
- **Sorgenti.** Implementato in tutte: Go (core, SDK Go, egress, OBI), node, python, java, dotnet, php.
- **Vettori.** `conformance/`: sezione 2200 (2200–2453, categorie `code-alnum`, `docs`, `multipart`, `xml`, `large-body`, `refusal`), controllo F di `leakcheck.py` (nomi, `fmt`, `soap_action` e pattern `xmlns` senza contenuti).

### v1.18.1 — `json_path` in tutti gli SDK, vettori di conformità (patch, ottobre 2026)

Nessun cambiamento di formato né di uscita per le policy che non usano `json_path`: identificatori invariati (`v1`), tutti i vettori precedenti identici.

- **sanitizer.md §11 (4 bis) e §21, policy.md §7.1.** `identity.subject.json_path` è implementato negli SDK node, python, java, dotnet e php, identico alle sorgenti Go: percorso puntato di 1–8 membri `[A-Za-z0-9_-]{1,64}`, solo `from: header`, esclude `jwt_claim`; valore grezzo al più 8192 byte, tolti spazi e tab ai bordi, nessun prefisso `bearer`; JSON in chiaro oppure base64 (alfabeto standard o URL, non mescolati, con o senza padding); un oggetto alla radice; membro finale stringa non vuota o numero entro i limiti (forma canonica); ogni altro caso nessun soggetto. Il soggetto esce solo come token HMAC, mai il valore.
- **Profondità.** Il valore si analizza per intero come in §9.2, senza limite di profondità: le sorgenti Go avevano un limite di 64 livelli nell'analisi del `json_path` (non nel resto), tolto per allinearle al testo; cambia solo il risultato per un header patologico con più di 64 livelli di annidamento fuori dal percorso.
- **Vettori.** `conformance/`: sezione 2100 (2100–2190, categorie `subject-sampling` e `refusal`): percorso annidato e di un membro, otto membri, nomi con `-` e `_`, base64 standard e URL con e senza padding, alfabeti mescolati, spazi e tab ai bordi, numeri in forma canonica e fuori limite, duplicati (vince l'ultimo), escape, intermedi e finali non validi (array, oggetto, booleano, `null`, stringa vuota, mancante), radice non oggetto, dati in coda, BOM, UTF-8 non valido, lunghezze 8192/8193, annidamento profondo, header ripetuto o assente, rifiuto del corpo (con `jwt_claim`, da cookie, percorso di nove membri, vuoto, caratteri non ammessi, membro di 65 caratteri). Il generatore di riferimento (`conformance/ref/`) li produce da solo.
- **Console.** Tolto l'avviso che `json_path` valeva solo per le sorgenti Go.

### v1.18.0 — causa → effetto, ondata 4: esiti condizionati, attributi del cliente, aggregati, liste, precondizioni, scritture su tutti gli oggetti, candidati sotto soglia, famiglie di domini, soggetto da un header JSON (rules 1.9, mock 1.11, admin-api 1.21.0, ottobre 2026)

Identificatori invariati (`v1`): campi facoltativi nuovi nelle regole, nella forma autore della policy e nel corpo compilato (`identity.subject.json_path`); nessun byte di uscita del sanitizer cambia per le policy che non usano `json_path`, i vettori restano identici. Generico: tutto si impara dal traffico mascherato (token HMAC, codici in chiaro, fasce, forme, conteggi con anonimato k) e dalla configurazione della console. Capacità C0, C6, C8, C12, C14, C15, C17, C18 ([rules.md](rules.md), appendice A) e i due vuoti lasciati dall'ondata 3 (chiavi di più campi, scritture su più oggetti dell'utente).

- **rules.md §3.12, C6.** `cause.when.match` e `outcomes[].when`: condizioni su un valore della richiesta (corpo, query, header, path) o su un attributo del cliente, per valori (`in`, confronto canonico) o intervalli (`min`/`max`). Rami ammessi, `p` congiunte e rinormalizzate, ramo vuoto se nessuno è ammesso. Il miner le propone per le regole di creazione con più rami quando il chi quadrato dice che gli esiti dipendono dal valore (`p < 0,01` con Bonferroni, almeno `k_min` soggetti per valore); gli importi mascherati restano manuali.
- **rules.md §2.11, C14.** `attributes`: attributi del cliente (valori e quote, almeno `k_min` soggetti per valore) portati da più risposte; il generatore li dà a ogni cliente (`profile`), il mock li tiene uguali per sessione.
- **rules.md §2.12, C8.** `aggregates`: un numero di una risposta calcolato alla lettura come conteggio degli oggetti del cliente in uno stato, somma di un campo o contatore mosso dalle scritture; il miner li impara confrontando il numero con le liste lette dallo stesso utente.
- **rules.md §2.3, §2.13, C12.** `list.filters`; il miner impara `limit`, `default_limit`, `page`/`offset`, `order_by`/`order` e i filtri; `lists`: paginazione delle liste che nessuna entità legge, così una lista statica con una pagina piena non pagina all'infinito.
- **rules.md §3.13, C17.** `respond.until`: precondizione attiva dall'inizio della sessione finché la causa non si vede; il miner la impara da un `4xx` che smette dopo la prima scrittura riuscita di un'altra operazione. Firma `…|until|<servizio>|<operazione>|<status>`.
- **rules.md §3.14 e §3.8.** `target_all`: un effetto su tutti gli oggetti del cliente che soddisfano `where` («segna tutte lette»), imparato da una scrittura che non cita oggetti (firma `…|update_all`); `target_key` imparato anche per chiavi di più campi.
- **rules.md §5.2, C0, C18.** Candidati sotto soglia (`candidates` di `GET /api/v1/rules/status`: struttura, fasce di utenti, scheletro `draft`, `missing_entities`) da una seconda ricerca con k = 2 (`miner.candidate_max_events`); gruppi di test con k ridotto (`PUT /api/v1/fleet/groups/{group}/test-k`, solo amministratore, audit `fleet.group_test_k`, pacchetti di un gruppo di test con l'avviso `test_k`). Nella console «Candidati sotto soglia» con **Crea bozza** e i modelli dell'editor («una scrittura cambia un campo», «scade dopo», «al massimo n», «finché non»).
- **policy.md §1.7, C15.** `hmac.families` (solo forma autore): domini uniti compilati in un solo dominio, il corpo non cambia forma; observe-safe. Candidati dalla struttura (`families` di `GET /api/v1/rules/status`), `PUT`/`DELETE /api/v1/fleet/groups/{group}/families`, audit `policy.families_set`/`policy.families_removed`.
- **policy.md §7.1, sanitizer.md §11 e §21, C14.** `identity.subject.json_path`: il soggetto da un membro di un header JSON (anche base64); observe-safe come `jwt_claim`. Nella v1.18.0 solo le sorgenti Go lo implementavano (gli altri SDK rifiutavano il corpo e restavano sulla policy precedente); dalla v1.18.1 lo implementano tutte le sorgenti. Il mock legge l'identità anche da un header JSON (mock.md §2.6).
- **mock.md §2.8 (1.11).** Condizioni, attributi per sessione, aggregati, filtri e liste statiche, precondizioni, `target_all`; ordine dei guasti: forzato > registrate > precondizioni > contatori > osservati. Esportatori: `conditional-outcome`, `customer-attribute`, `aggregate`, `list-paging`, `list-filter`, `update-effect`, `response-effect`. Gate: i valori degli attributi e delle condizioni sono letterali delle regole; `subjects` di attributi e aggregati sotto `k_min` falliscono.
- **Schemi.** `rules.v1` (`match`, `when`, `until`, `target_all`, `filters`, `attributes`, `aggregates`, `lists`), `policy.v1` (`hmac.families`, `json_path`), `policy-compiled.v1` (`json_path`); admin-api 1.21.0.

### v1.17.0 — causa → effetto, ondata 3: record per chiave, valori che tornano, contatori e unicità, oggetti che compaiono più tardi, cicli (rules 1.8, mock 1.10, ottobre 2026)

Identificatori invariati (`v1`): campi facoltativi nuovi nelle regole, nessun byte di uscita del sanitizer cambia. Generico: tutto si impara dal traffico mascherato (token HMAC, codici in chiaro, forme, tempi, conteggi con anonimato k). Capacità C7, C9, C10 ([rules.md](rules.md), appendice A) e il bersaglio per chiave lasciato a mano dall'ondata 2.

- **rules.md §3.1, §3.8.** `effects[].target_key`: un effetto `set` (o `remove`) sul **record di un'entità per chiave** del cliente della causa, con un valore (`"${variabile}"` o letterale) per ogni campo della chiave, `{}` per il record unico del cliente; con `set` il record si crea se manca. Il miner impara gli aggiornamenti dei record per chiave fatti da scritture diverse da `upserted_by` come quelli degli oggetti con id (stesse soglie e controlli); le chiavi di più campi restano manuali.
- **rules.md §3.8, C10.** Valori che tornano: un letterale impostato da un aggiornamento che l'oggetto perde da solo (nessuna scrittura in mezzo) diventa un secondo effetto `<entità>-<campo>-reverted` con `where` sul valore impostato e `after` figurativo dal tempo mediano di ritorno (≥ `k_min` soggetti, `min_share` e Wilson ≥ `min_birth_share` dei cambi seguiti abbastanza a lungo).
- **rules.md §3.9, C7.** `respond.limit { n, window, key }`: contatore per chiave. Ogni chiamata della causa conta per la sua chiave (un token della richiesta o il cliente); una chiamata con almeno `n` chiamate contate nella finestra risponde lo status osservato con l'esempio del contratto (unicità `n: 1` senza finestra, tentativi falliti, limiti di frequenza). Il miner sceglie chiave, chiamate contate, finestra (tutta, `1m`, `15m`, `1h`, `1d`, figurativa) e `n` dall'ordinale per chiave delle chiamate in errore: richiamo e precisione ≥ `min_share`, Wilson ≥ `min_birth_share`, ≥ `k_min` soggetti; un errore spiegato da una scrittura di un'altra operazione (una rimozione) non conta. Firma `…|limit|<status>`.
- **rules.md §3.10, C9.** Oggetti che compaiono più tardi, fuori dalla traccia: un'entità mai coniata da una scrittura i cui oggetti citano un oggetto creato nella finestra e compaiono dopo la sua creazione diventa un effetto `create` della regola di quella creazione, con ritardo figurativo e i valori costanti alla prima osservazione; niente `seed`, diagnostica `later`. «A nascosto quando esiste B» (id provvisorio → definitivo) è una `remove` di A dopo la creazione di B.
- **rules.md §3.11, C10.** Cicli di vita con ritorni: un ritorno spontaneo `b → a` a uno stato precedente (≥ `k_min` soggetti, senza scritture in mezzo in `min_share` dei casi) è un effetto della creazione con `where` su `b`, e gli oggetti tornati hanno l'esito `<a>-again`. Le regole già minate senza ritorni restano invariate.
- **mock.md §2.7 (1.10).** `target_key` sul record del cliente della causa (creato da un `set` se manca); i contatori decidono la risposta prima dei guasti osservati, dopo i guasti forzati e le risposte registrate; `reset` li azzera. Il generatore ignora `target_key` e i contatori; gli esportatori li dichiarano persi (`keyed-effect`, `response-effect`).
- **Console.** Nella catena di una regola: «sul record per chiave di …», «una seconda chiamata con … risponde 409», «con almeno n chiamate contate negli ultimi … risponde …»; l'editor di regole conserva i legami usati da `target_key` e `limit.key`.
- **Schema `rules.v1`.** `effects[].target_key`, `respond.limit`; il gate tratta i valori di `target_key` come i valori di `set`.

### v1.16.0 — causa → effetto, ondata 2: scritture e letture che cambiano oggetti esistenti, selettori GraphQL (rules 1.7, mock 1.9, ottobre 2026)

Identificatori invariati (`v1`): campi e forme di valore facoltativi nuovi nelle regole, nessun byte di uscita del sanitizer cambia. Generico: tutto si impara dal traffico mascherato (token HMAC, valori `keep`/`code`, fasce `num:`, forme, conteggi con anonimato k). Capacità C2, C11, C16 ([rules.md](rules.md), appendice A).

- **rules.md §3.8, C2.** Regole di **aggiornamento**: una scrittura (o un'operazione classificata come scrittura) che cita nella richiesta l'id di un oggetto di un'entità con id (creata o preesistente) e dopo la quale l'oggetto, riletto da qualsiasi operazione o servizio, ha un campo cambiato. Il valore nuovo è un letterale costante, la copia di un codice in chiaro della richiesta (`"${variabile}"` legata a quel membro), la copia di un **id** della richiesta (l'uguaglianza dei token prova quella dei valori) o, per un booleano, l'opposto di prima (`"${not:campo}"`, §3.2). Soglie: `k_min` soggetti, `min_share` delle chiamate che potevano mostrare il cambio, limite inferiore di Wilson ≥ `min_birth_share` (la confidenza); un letterale o un interruttore deve essere raro senza la chiamata. Un cambio visto solo dopo una lettura che mostrava ancora il valore vecchio è ritardato: `after` figurativo dall'ordine di grandezza. Firma `…|update`, bozza `mined`.
- **rules.md §3.8, C11.** Una lettura è una causa con le stesse regole (la notifica aperta risulta letta), solo con abbastanza osservazioni dell'oggetto senza quella lettura da confrontare.
- **rules.md §3.1, §3.8.** `effects[].where`: guardia letterale di un `set` (si applica solo se l'entità ha ancora quei valori). Le transizioni dello stato spiegate da una scrittura non sono più esiti spontanei della creazione: la regola della creazione le toglie e mette `where` sui passi spontanei rimasti. Lo stato del ciclo di vita può essere un booleano o una fascia numerica (`set` con un numero dentro la fascia) quando non c'è un codice che cambia. Le regole già minate senza transizioni attribuite restano invariate.
- **rules.md §2, C16.** Una variabile GraphQL seleziona anche per campo o proprietario; una lista può essere annidata (`$.data.contracts.items[*]`) con il conteggio nello stesso involucro (`$.data.contracts.count`).
- **mock.md §2.7 (1.9).** Le variabili della richiesta copiano il valore che il test manda; `${not:campo}` inverte il booleano corrente; `where` si controlla quando l'effetto scatta (anche nel generatore). Gli esportatori dichiarano persi gli effetti di una scrittura su oggetti esistenti (`update-effect`).
- **Console.** Nella catena di una regola: «prende il valore che la chiamata manda in …», «si inverte a ogni chiamata», «solo se … ha ancora …».
- **Schema `rules.v1`.** `effects[].where`, `${not:campo}` documentato nei valori di `set`.

### v1.15.0 — causa → effetto, ondata 1: oggetti preesistenti per cliente, stato per chiave, rimozione, letture dal comportamento (rules 1.6, mock 1.8, admin-api 1.20.0, ottobre 2026)

Identificatori invariati (`v1`): campi facoltativi nuovi nelle regole, nessun byte di uscita del sanitizer cambia. Generico: tutto si impara dal traffico mascherato (token HMAC, valori `keep`/`code`, forme, conteggi con anonimato k) e dalla configurazione della console, mai da nomi di un'applicazione. Capacità C1, C3, C4, C5 ([rules.md](rules.md), appendice A).

- **rules.md §2.8, C1.** Entità senza `created_by` con `seed`: un dominio mai emesso da una scrittura, restituito da letture riservate al proprietario, diventa un'entità con `read_by`, stato, relazioni e la distribuzione in fasce del numero di oggetti per cliente (fasce adiacenti unite finché ognuna ha almeno `k_min` soggetti) più le quote dei valori in chiaro. Il generatore crea quegli oggetti per ogni cliente sintetico (formati degli id, relazioni verso oggetti del cliente, generatore proprio: i mondi senza `seed` non cambiano); il mock li serve come le altre righe del mondo e sono bersagli delle regole.
- **rules.md §2.9, C3.** Entità per chiave (`key`, `upserted_by`, `read_by.key`): record senza id proprio, del cliente e/o di una tupla di selettori della richiesta, imparati da coppie scrittura → lettura dello stesso soggetto con valori coerenti e variabili (≥ `k_min` soggetti). Il mock crea o aggiorna il record della chiave e lo restituisce; senza record risponde come il contratto.
- **rules.md §3.7, C4.** Effetto `remove` (con `target` o `target_id`) e `read_by.removed_status`: imparato da una scrittura che cita l'id di un'entità dopo la quale lo stesso soggetto non la vede più in lista o riceve `404`/`410` per id (≥ `k_min` soggetti, `min_share`). Mock: liste e conteggi la tolgono, la lettura per id risponde `removed_status` o «non trovato»; anche la modalità statica elenca gli oggetti creati in una collezione e dimentica quelli tolti da un `DELETE` (mock.md §2.5). Gli esportatori lo dichiarano perso.
- **rules.md §2.10, C5.** Una POST (o mutation GraphQL) che restituisce identificativi già esistenti, non ne conia, risponde uguale a richieste uguali e non cambia ciò che restituisce è una **lettura**; `read_by.by` e le chiavi possono essere membri del corpo della richiesta (`$.filters.x`, `$.variables.x`), per id, campo o proprietario. Diagnostica `reads` della corsa.
- **admin-api 1.20.0, console.** `GET|PUT /api/v1/rules/op-kinds`: «Questa operazione è una lettura» per gruppo e operazione (lettura, scrittura, di nuovo il traffico), solo `rule-reviewer`, audit `rule.op_kind_set`; vince sul traffico dalla corsa successiva. Nel dettaglio di un'operazione del contratto la console dice come il miner la tratta e perché.
- **Schema `rules.v1`.** `seed`, `key`, `upserted_by`, `read_by.key`, `read_by.removed_status`, `effects[].remove`, selettori dal corpo con `field`/`owner`. Le regole già minate restano valide e invariate.

### v1.14.0 — servizi GraphQL: documenti senza valori, operazioni logiche, schema e mock (sanitizer 5.7, policy 1.6, event 6, mock 7, pack 4, ottobre 2026)

Identificatori dei formati invariati (`v1`): nuovo valore di enum del corpo compilato (`graphql`), nuovo prefisso di token (`gql:`), nuove estensioni di contratto. Generico: nessun nome o path di un'applicazione, l'endpoint si riconosce dal contenuto. Caso tipico: un gateway che fa schema stitching (prima l'introspezione, poi operazioni con nome e variabili).

- **sanitizer.md §5.7, §9.1, §20.** Azione `graphql`. Sulla richiesta un documento eseguibile GraphQL esce come `gql:` e la sua **forma**: analisi lessicale e grammatica chiuse, nomi in chiaro (con la regola delle chiavi: sei cifre, sedici esadecimali o oltre 64 byte → `*`), ogni valore scritto nel documento un placeholder tipato (`?s ?i ?f ?b ?n ?e`), al più 64 parentesi aperte e 32 768 byte; qualsiasi errore → la forma della stringa. Sulla risposta escono i nomi di un risultato di introspezione solo con il **cancello** aperto (ogni documento della richiesta con regola `graphql` seleziona alla radice solo `__schema`/`__type`/`__typename`, senza alias); con il cancello aperto gli array del corpo della risposta arrivano a 4096. Un corpo `application/graphql` con regola `graphql` su `$` è una foglia stringa. Nessun byte cambia per le policy senza `graphql`. Riferimento Go (`internal/graphql`, `internal/sanitizer`), riferimento Python (`gqlshape.py`), vettori 2000–2033, controllo E di `leakcheck.py` (nessun letterale nei `gql:`), SDK Node, Python, Java, .NET, PHP (corpus differenziale di 20 009 documenti identico in tutte le implementazioni).
- **policy.md §1.1, §1.6, §2, §7.1, §7.4.** `graphql` solo sul documento della richiesta (`$.query`, `$`, parametro `query`) e sotto `$.data.__schema`/`$.data.__type` senza `.*`; mai globale, `errors`, header, cookie, path. Non apre valori. La versione Osserva lo mette da sola sugli endpoint che riconosce dalla struttura (corpo JSON con `query` e `variables`/`operationName`, `application/graphql`, GET con `query`; risposta con `data`/`errors`), con i percorsi dell'introspezione standard (`GraphQLIntrospectionPaths`). `fleet.observe.graphql` (default `true`) lo spegne finché ci sono sorgenti precedenti alla v1.14 (rifiuterebbero il corpo).
- **event.md §5.1, §6.** L'intake accetta `gql:` solo sotto una regola `graphql`: nella richiesta una forma senza letterali (`graphql.ValidShape`), nella risposta un nome sicuro con il cancello ricostruito dalla richiesta. Un evento GraphQL si salva sotto l'**operazione logica** `POST /graphql#GetOrder` (anonima: `#~` e l'hash della forma); quarantene, controlli e proposte usano l'op HTTP. Una sorgente non può mandare un'operazione logica. Schema `event.v1`: token `gql:` fino a 32 772 caratteri.
- **Contratti, pack.md §4.** Un'operazione per operazione GraphQL, con `x-tt-graphql` (endpoint, metodo, tipo, nome, forma, variabili, campi radice) e path OpenAPI `/graphql#GetOrder`, `summary` «QUERY GetOrder»; `x-tt-graphql-schemas` con l'ultimo risultato di introspezione catturato per endpoint (solo nomi, senza soglia k: è lo schema). `x-tt-value.kind = graphql` sul membro `query`. Il gate accetta nelle estensioni GraphQL solo nomi, forme, tipi, endpoint e date.
- **Miner, rules.md §2.3.** Le operazioni GraphQL si analizzano come REST: una query è una lettura, una mutation una scrittura; l'entità di un campo `id` prende il nome dall'oggetto che lo contiene (`$.data.order.id` → `order`); una lettura può selezionare l'entità con una variabile (`by: {from: req.body, path: "$.variables.id"}`, solo per id).
- **mock.md §7.** Il mock risponde all'endpoint GraphQL vero: legge `{query, variables, operationName}` (anche `GET` e `application/graphql`), sceglie l'operazione logica per nome o per hash della forma, la serve con sessioni (anche per identità), entità, regole, guasti e formati degli id; `data` segue la selezione (alias, `__typename`); i guasti diventano un array `errors` (con `200` se l'endpoint rispondeva così); l'introspezione risponde con lo schema catturato o con uno ricostruito dalle operazioni; un'operazione mai vista dà l'errore GraphQL `operation not observed`.
- **Console.** Pagina del contratto: le operazioni GraphQL si leggono come «QUERY GetOrder» con documento, variabili e campi; scheda **GraphQL** con lo schema catturato in SDL (scaricabile) e le operazioni osservate; guida in linea e glossario.
- **THREAT_MODEL M24** e rischio residuo accettato (nomi scelti per portare dati, valori oltre `max_array`).

### v1.13.0 — identità dell'utente generica: qualsiasi header non di credenziali, rilevamento dai dati (policy §7.1 e §7.4, admin-api 1.19.0, ottobre 2026)

Nessun identificatore cambia, nessun byte di uscita del sanitizer cambia. Principio di progetto: lo strumento resta **generico**, mai verticale. L'elenco chiuso di nomi di header della v1.11.2 è **rimosso**.

- **policy.md §7.1.** È observe-safe (`policy.IdentityObserveSafe`, che keyguard ricalcola) scegliere come `identity.subject` qualsiasi header della richiesta che non sia una credenziale, con o senza `jwt_claim`, e qualsiasi claim del JWT bearer in `authorization`: il soggetto esce solo come token HMAC. Restano soggetti ad approvazione i cookie, `cookie`/`set-cookie`/`proxy-authorization`/`x-api-key`, `authorization` senza claim e, senza claim, i nomi che sembrano credenziali (token, secret, password, key, session, auth, csrf, signature…). I parametri della query non sono una sorgente del soggetto (sanitizer §11 invariato). Rischio residuo nel [threat model](../THREAT_MODEL.md).
- **policy.md §7.4.** Rilevamento automatico dell'utente dai dati della scoperta (valori distinti, chiamate, forma; mai valori): punteggio da cardinalità, forma, presenza e, debole, nome; esclusi gli id di richiesta (un valore per chiamata), i tenant (pochi valori), le forme non identificative, i cookie e le credenziali. Il `sub` del JWT bearer vince quando c'è. La classifica con i motivi è in `identity_candidates`/`identity_best` dello stato Osserva e dell'assistente.
- **admin-api 1.19.0.** `PUT /api/v1/fleet/groups/{group}/identity` (`setIdentity`): una persona sceglie o sostituisce la sorgente dell'utente dalla console; observe-safe si applica subito, con audit `policy.identity_set`. `replace_identity` nella bozza dell'assistente.

### v1.12.0 — id nel formato del servizio e sessione per utente (pack 1.7, mock 1.6, admin-api 1.18.0, control-api 1.4.0, ottobre 2026)

Nessun identificatore cambia e l'uscita del sanitizer non cambia. I client che costruiscono e scompongono gli id e non possono mandare `X-TT-Session` mostravano due limiti; le soluzioni sono **generali**: nessun formato di id, nome di header o claim è scritto nel prodotto.

- **Formati degli id** ([pack.md](pack.md) §4.3). Una persona sceglie in console, per gruppo e dominio di id, un modello (`N` cifra, `A`/`a` lettera, `X` alfanumerico, letterali, `{campo}` / `{campo#k}` / `|trim0` / `|pad6` per copiare un segmento di un altro campo, `<…>` per il base64url). Il mondo, il pacchetto (in `x-tt-value.id_format`, campo nuovo e facoltativo) e il mock generano gli id in quella forma, in modo deterministico e senza ripetizioni, e i legami per segmento copiato restano validi. Le righe del mondo ammettono id del formato del dominio (schema `pack-manifest.v1`: il pattern degli id delle entità si allarga; il mock verifica il formato). Gate: `id_format` deve essere un modello valido; gli id generati di un formato dichiarato non sono dati personali per i rilevatori; `reverse-hmac` controlla anche i primi id che il mock genererà. L'apprendimento dello «scheletro» dalle sorgenti è stato valutato e scartato (cambio major del sanitizer, quasi-identificatori): le ragioni sono in pack.md §4.3. API `GET /api/v1/id-formats`, `POST /api/v1/id-formats/preview`, `PUT|DELETE /api/v1/id-formats/{domain}`; audit `idformat.set`, `idformat.delete`.
- **Sessione per utente** ([mock.md](mock.md) §2.6). Con `--identity-header` (qualsiasi header) e facoltativamente `--identity-claim` (un claim del JWT nell'header) una richiesta senza `X-TT-Session` va nella sessione del suo chiamante (`u-` + hash con chiave), con un cliente sintetico scelto dallo stesso hash o da una mappa esplicita; `X-TT-Session` vince sempre; l'identità non si conserva né si registra. Ogni risposta del piano dati porta `X-TT-Session`. Control API 1.4.0: `Session.by_identity`. In modalità console l'impostazione del gruppo (pagina Mock) arriva nella risposta al rapporto (`identity`, admin-api: `GET|PUT /api/v1/mocks/identity`, `POST /api/v1/mocks/identity/map`, `DELETE /api/v1/mocks/identity/map/{hash}`); la console conserva la chiave del gruppo e solo hash degli utenti. Audit `mock.identity_set`, `mock.identity_map_set`, `mock.identity_map_delete`.
- **Limiti noti.** Gli id dei clienti sintetici restano `CUS-SYN-NNNN`; gli exporter (WireMock, Microcks, Prism) riusano gli esempi e gli stati del mondo, già nel formato, ma gli id che generano da sé restano `<PREFISSO>-SYN-NNNN`; gli id generati oltre la finestra controllata dal gate o che copiano campi della richiesta non passano da keyguard.

### v1.11.2 — più header per l'identità automatica (policy §7.1 e §7.4, ottobre 2026)

Nessun identificatore cambia. Molte applicazioni identificano l'utente con un header applicativo (per esempio `personid`): non era una sorgente automatica, quindi serviva un'approvazione e senza utenti il miner non contava k né ricavava regole.

- **policy.md §7.1.** L'elenco chiuso degli header di identità automatica (senza `jwt_claim`) comprende anche `personid`, `person-id`, `x-person-id`, `userid`, `user-id`, `customerid`, `customer-id` (`x-customer-id` c'era già). Nomi senza distinzione di maiuscole; il valore esce sempre come token HMAC. Mai header di credenziali. `ClassifyValues` e keyguard (che la ricalcola) firmano senza approvazioni; un header fuori elenco le richiede ancora.
- **policy.md §7.4.** Con più header presenti vince il primo nell'ordine documentato, il `sub` del JWT sempre prima di tutti. L'assistente propone come candidati anche questi header.

### v1.11.1 — collaudo di usabilità 5: regole sostituite, bozze ritirabili, messaggi coerenti, editor veloce (rules 1.5, policy §5, admin-api 1.17.0, ottobre 2026)

Nessun identificatore cambia. Una tester non admin (deliveries-api, Python, codici in chiaro) ha trovato otto punti dove la console o il backend si comportavano peggio di quanto dichiarato.

- **rules.md §5.** Una regola approvata sostituita da una regola approvata più recente (`supersedes`, o stessa firma del miner) diventa `superseded` all'approvazione della nuova: resta nella storia ma esce dall'insieme attivo e dai pacchetti (prima r-0018 e r-0019 restavano attive insieme e il 5% di CANCELLED diventava 1%). Nuovo stato `superseded` (enum dello schema `rules.v1`, minor), `superseded_by` nella vista; `POST /api/v1/rules/{id}/retire` ritira una regola approvata (`rejected`, `retired`). Audit `rule.supersede`, `rule.retire`. All'avvio le console con entrambe le regole approvate si sistemano da sole.
- **policy.md §5.** `POST /api/v1/fleet/policies/{id}/versions/{n}/withdraw`: il proponente (o un admin) ritira una bozza in attesa (`rejected`, `withdrawn`); audit `policy.withdraw`. Prima una bozza che nessun altro poteva approvare restava per sempre e fermava la versione Osserva automatica.
- **Stato del miner (admin-api).** `GET /api/v1/rules/status`: `groups[]` per gruppo (eventi esaminati, `states_observed`, `state_fields`, `clear_fields`), `events`/`subjects` del gruppo selezionato (`events_total` quelli della console), `values` (`in_clear` | `dropped`) sulle diagnostiche delle regole: la console chiede un'approvazione solo per i campi ancora `drop`, mai per uno stato che esce già come codice.
- **Editor delle regole.** `GET /api/v1/rules/catalog` ristretto al traffico del gruppo (servizi, operazioni, campi, entità del gruppo: due team con un servizio dello stesso nome non vedono le operazioni dell'altro) e costruito dagli snapshot dei contratti già salvati invece di inferire tutti i contratti dagli eventi grezzi (da ~100 s a meno di un secondo con 1 M di eventi).
- **Drift.** Gli allarmi hanno `params` (nomi e cifre) accanto a `change_kind`: la console scrive la frase in italiano; nessun allarme «compatibile» per snapshot della stessa finestra o di finestre che si sovrappongono per almeno metà, né per un `required` che cambia con uno scarto di presenza minimo.
- **Pacchetti.** `PackInfo.warnings` / `warnings_total` (`few_observations`, con i conteggi per pacchetto, regola, esito e endpoint) per un pacchetto costruito con poco traffico; non lo blocca e non fa parte del pacchetto firmato. Il risultato di «Prepara e avvia» ha `warnings`.
- **Host esterni.** `GET /api/v1/hosts`: un host dichiarato dopo le prime chiamate compare una volta sola (`folded_from`), e `counts` conta anche gli host di classe IP.

### v1.11.0 — codici in chiaro senza approvazione (sanitizer 5.6, policy 1.5, ottobre 2026)

**Decisione di progetto, dopo il collaudo di usabilità 4:** senza stati in chiaro il miner non vede cicli di vita e il mock resta statico, ma ogni `keep` chiedeva due approvazioni. Gli stati e i codici escono ora senza persone, in modo strettamente limitato.

- **Azione `code`** ([sanitizer.md](sanitizer.md) §5.6): la sorgente lascia uscire il valore solo se è una stringa `^[A-Za-z_-]{2,32}$` (niente cifre, spazi o altri caratteri, nemmeno lettere Unicode simili); altrimenti esce la forma che darebbe `drop`. In uscita è `keep:<valore>`, quindi contratti, miner, mondo, campi collegati e soglia k del gate lo trattano come un `keep`. Vettori 1810–1828 e 1850–1857; tutti i 6 SDK e il sanitizer Go.
- **Dove** ([policy.md](policy.md) §1.5): solo su campi del corpo e della query con nome da stato o codice (lista chiusa: `status`, `state`, `type`, `reason`, `code`, `error_code`, `outcome`…; mai `name`, `city`, `email`, `description`…), mai sui cookie né sugli header di credenziali. Altrove la validazione la rifiuta.
- **Classificazione:** `code` su un campo ammesso non apre valori: keyguard la firma senza approvazioni (`approval_mode: observe`); passare da `code` a `keep` sullo stesso campo apre valori.
- **Fase Osserva:** la versione automatica propone `code` sui campi stringa corti, visti almeno 20 volte e con al massimo 20 valori distinti; mai su un campo scelto da una persona. `fleet.observe.codes: false` spegne le proposte.
- **Compatibilità:** una sorgente precedente alla v1.11 rifiuta un corpo con `code` (`policy_rejected`) e resta sulla policy precedente: aggiornare prima le sorgenti, oppure `fleet.observe.codes: false` finché non lo sono.
- **Rischio accettato** ([THREAT_MODEL.md](../THREAT_MODEL.md)): un valore personale con la forma di un codice in un campo da stato (un soprannome in `type`) esce senza persone; mitigato dalla soglia k e dai rilevatori del gate.

### v1.10.1 — collaudo di usabilità 4: automazione che continua, servizi sostituiti, mock statico (policy 1.6.1, mock 1.5, sanitizer §3.5, admin-api 1.16.0, ottobre 2026)

Nessun identificatore cambia. Un tester non admin (orders-api, Node) ha trovato quattro punti dove la console si comportava peggio di quanto dichiarato.

- **policy.md §7.4 (1.6.1).** La fase Osserva non si ferma più per sempre alla prima modifica firmata da una persona: `tt-core` continua a mettere `hmac` sugli identificativi e l'identità automatica per i campi e i servizi **visti per la prima volta**, sopra la versione attiva, senza mai scavalcare una scelta (un campo con una regola resta com'è; uno che una persona ha tolto non torna `hmac`), e non mentre c'è una bozza in attesa. Interruttore per gruppo `PUT /api/v1/fleet/groups/{group}/observe` (`setObserveAuto`, audit `fleet.group_observe_auto`); `ObserveStatus.auto`. «Simula nel mock» (`twinHost`) mette già `hmac` sugli identificativi dell'host nella stessa bozza.
- **sanitizer.md §3.5, admin-api 1.16.0.** Dichiarato un host (`ip:private:9301` come `catalog-api`) le chiamate vecchie restano come storico sotto `host:<pattern>`, ma `listServices` e `listContracts` le segnano con `replaced_by`, l'assistente le fonde nel servizio dichiarato e il pacchetto costruito senza elenco di servizi le lascia fuori (niente `ext-1`/`ext-2` doppioni nel mock).
- **mock.md 1.5 (§2.5).** Mock senza regole: ogni `POST` di creazione genera un id nuovo (per sessione), i `GET` successivi lo ritrovano; un id sconosciuto risponde lo status «non trovato» osservato (404) se il contratto lo dichiara, altrimenti `200`; ogni risposta statica porta `X-TT-Static: true`.
- **policy.md §4, SDK (tutti).** Un cambio di policy normale non produce più `policy_below_min_issued_seq`, `policy_rejected`, `policy_network` nel debug: l'heartbeat annuncia insieme `min_issued_seq` e `policy_current`, la sorgente ferma la cattura (fail-closed come prima), scarica subito la nuova policy e registra solo un messaggio `info`; l'errore resta se la nuova policy non arriva o non è accettata, o se `policy_current` non è più recente (replay). Una sola richiesta di policy alla volta (Node, .NET) e le risposte di prima del cambio sono ignorate. Nessun cambiamento di formato né dei vettori.

### v1.10.0 — entità di più team e mondi mai vuoti in silenzio (admin-api 1.14.0, ottobre 2026)

In un deployment di prova due team in gruppi diversi creavano ciascuno un `order` (shop-api del gruppo `demo`, orders-api di un tester). Il miner nominava le entità per dominio HMAC su tutti gli eventi: i due ordini erano diventati **una** entità creata da orders-api, la regola approvata r-0008 di shop-api chiedeva orders-api, il mondo del gruppo `demo` usciva senza entità e senza regole e il pacchetto aveva `rules: []`, senza nessun avviso.

- **rules.md §2.7.** Un'entità è l'oggetto che un servizio crea in un dominio dentro un gruppo. Il miner analizza il traffico di ogni gruppo separatamente (entità, riferimenti, domini uniti, regole) e non propone regole che mescolano gruppi. Il primo creatore tiene il nome semplice, gli altri un nome qualificato (`order-orders-api`) con un `id_prefix` proprio; i nomi restano tra le esecuzioni (tabella `miner_entity_names`) e su una console esistente si ricavano dalle regole approvate, così r-0008 torna all'`order` di shop-api alla prossima ricerca.
- **rules.md §6.1, admin-api.** `POST /api/v1/worlds` (e «Prepara il mock») risponde `422 no_usable_rules` con `details` quando nessuna regola approvata del gruppo si può usare; con alcune regole lasciate fuori il mondo si genera e `WorldInfo.excluded_rules` le elenca. `skipped_rules` di un mondo di un gruppo elenca le regole inutilizzabili del gruppo stesso. Un Job fallito porta i `details` dell'errore.
- Generatore e mock collegano un id all'entità del proprio servizio quando due entità hanno lo stesso dominio.

### v1.9.0 — lavori pesanti in coda e memoria limitata (admin-api 1.13.0, ottobre 2026)

Su un core di prova da 4 GiB un secondo `POST /api/v1/rules/mine` mentre il primo girava ha fatto uccidere tt-core dal kernel (OOM). Mining, archetipi, mondi, pacchetti, export, snapshot dei contratti e `prepareMock` ora girano pochi alla volta (uno sotto 16 GiB), in ordine di arrivo: chi aspetta risponde con il Job `queued`. Un `POST /api/v1/rules/mine` mentre un mining è in coda o in corso si unisce a quel Job invece di avviarne un altro. Nuovo `GET /api/v1/jobs` (lavori in coda e in corso). Il risultato di un Job è limitato (diagnostica del mining: 200 voci per tipo con i totali; oltre 16 MiB `result_too_large`).

### v1.8.2 — red team round 4 (admin-api 1.12.2, ottobre 2026)

Nessun identificatore cambia. Correzioni di sicurezza, ciascuna con un test di regressione (`test/redteam/r4/`, test accanto al codice).

- **policy.md §7.1–§7.2 (RT4-OBS-1, RT4-OBS-2).** Quando la policy lascia uscire valori (`keep` o `bucket`), dichiarare o togliere un servizio accanto a un altro che può prendere lo stesso traffico, spostarne uno (`match`), dichiarare o togliere un'operazione accanto a un'altra con lo stesso metodo e numero di segmenti, trasformare un `drop` di contenitore in `hmac` o aggiungere una regola che raggiunge un discendente di un contenitore con `drop` **aprono valori** (codici `service_with_values`, `operation_with_values`, `container_with_values`; `match_with_values` vale per ogni servizio). Prima `ClassifyValues` li considerava osservazione e keyguard li firmava senza persone, anche se portavano traffico su regole `keep` già approvate. Senza valori la fase Osserva non cambia.
- **policy.md §1.4 (RT4-YAML).** Il documento YAML della policy non può usare ancore, alias, chiavi di fusione né tag espliciti.

### v1.8.1 — snapshot dei contratti come operazione lunga (admin-api 1.12.1, ottobre 2026)

Su un core di prova lo snapshot di un servizio con molto traffico richiedeva 91 s, oltre `admin.http.write_timeout` (30 s): la connessione veniva chiusa e chi lo chiedeva vedeva un errore. `POST /api/v1/contracts/{service}/snapshots` risponde ancora `201` con lo snapshot quando finisce entro l'attesa del server, altrimenti `202` con il Job `contract.snapshot` da seguire su `GET /api/v1/jobs/{job_id}` (il `result` è lo `SnapshotInfo`). La console lo segue da sola.

### v1.8.0 — il mock come servizio (pack 1.6, mock 1.4, admin-api 1.12.0, ottobre 2026)

Nessun identificatore cambia. Decisione di progetto: «collego il servizio, torno dopo un giorno, premo un pulsante e ho un mock che sostituisce i miei endpoint». I pacchetti restano il formato, ma l'utente non li maneggia più.

- **pack.md 1.6.** Campo facoltativo `group` nel manifest (coperto dalla firma), scritto da `tt-core` per i pacchetti di un solo gruppo. Lo schema lo ammette; i lettori precedenti rifiutano un manifest con `group` (chiavi sconosciute rifiutate dalla 1.4), come per i campi della 1.5.
- **mock.md 1.4, §6.** Modalità console di `tt mock` (`--console`, `--group`, token del mock): pacchetto scaricato dalla console e verificato come un file, rifiuto dei pacchetti di un altro gruppo, sostituzione senza riavvio, rapporto con il solo riassunto delle chiamate, comandi dell'API di controllo inviati dalla console (mai il registro). La modalità file non cambia.
- **admin-api 1.12.0.** `/api/v1/mocks` (mock collegati, token del mock, `prepareMock` «Prepara e avvia il mock», mock gestiti in Kubernetes, ultime chiamate, comandi) e `/api/v1/mock-agent/*` per i mock (sicurezza `mockToken`, non una sessione).
- **Configurazione di tt-core.** Sezione `mock` (`console_url`, `console_ca_file`, `image`, `report_interval`, `kubernetes.*`); chart `tt-core` con `mockManager` (Role nel solo namespace dei mock), chart `tt-mock` con `console.*` e `route.*`.

### v1.7.0 — campi collegati e regole scritte a mano (pack 1.5, rules 1.4, admin-api 1.11.0, ottobre 2026)

Campi opzionali nuovi, identificatori invariati (`tt.pack/v1`, `tt.rules/v1`). Un lettore precedente rifiuta un pacchetto che li usa (gli schemi sono chiusi): `tt-core`, `tt-mock`, generatore ed esportatori vanno aggiornati insieme.

- **Campi collegati** ([pack.md](pack.md) §4.2). Estensione `x-tt-dependencies` sugli schemi oggetto: per coppie di proprietà `keep`/`bucket` a bassa cardinalità, le combinazioni di valori viste nello stesso oggetto per almeno `k_min` soggetti distinti, con una classe di grandezza (`at_least`) e mai conteggi esatti. Mondo, mock ed esempi producono solo combinazioni elencate (campionamento condizionato); il gate le controlla (provenienza, dati personali, `k-thresholds`).
- **Effetti sulle risposte** ([rules.md](rules.md) §3.6). `effects[].respond: { service, op, status, p?, times?, example? }`: «la prossima chiamata risponde Y», «errori con frequenza p». Onorati dal mock per sessione; ignorati dal generatore; dichiarati persi dagli esportatori.
- **Origine e regole scritte a mano** ([rules.md](rules.md) §5.1). `origin: mined | manual`; editor di regole (`GET /api/v1/rules/catalog`, `POST /api/v1/rules/check`, `POST /api/v1/rules`, `PUT /api/v1/rules/{id}`), validazione contro contratti ed entità, stessa revisione. La modifica della definizione di una bozza del miner sopravvive alle ricerche successive.

### v1.6.0 — fase Osserva: collegare una sorgente senza policy né approvazioni (admin-api 1.10.0, keyguard-api 1.5.0, ottobre 2026)

**Decisione di progetto:** collegare una sorgente deve essere plug & play. Fino alla v1.5 il wizard faceva approvare una policy prima di vedere qualsiasi cosa. Dalla v1.6 c'è una fase **Osserva** senza policy da scrivere e senza approvazioni (struttura + identificativi mascherati), e le approvazioni servono solo per le modifiche che **aprono valori** ([policy.md](policy.md) §7).

**Versioni.** Nessun formato cambia: `tt.policy/v1`, `tt.policy.body/v1`, `tt.policy.compiled/v1`, `tt.sanitizer/v1` restano uguali byte per byte, nessun vettore cambia, le sorgenti non cambiano ([sanitizer.md](sanitizer.md) §18). Cambiano le regole di approvazione (policy.md §5–§7), keyguard (keyguard.md §3.2) e le API di amministrazione.

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| OB-1 | Classificazione «apre valori»: `policy.ClassifyValues(prima, dopo)` → `opens_values` e `value_reasons` (codici `keep`, `bucket`, `identity`, `literals`, `hosts_discovery`, `propagate_to`, `volume_with_values`, `rule_removed_with_values`, `match_with_values`, `service_with_values`, `operation_with_values`, `container_with_values`, `group_with_values`, `credential_header`, `keyguard_verdict`); identità observe-safe da qualsiasi header non di credenziali o claim JWT (`policy.IdentityObserveSafe`, v1.12) | policy.md §7.1–§7.2; `internal/policy/observe.go`, `internal/policy/identity.go` | core, keyguard (fatto) |
| OB-2 | keyguard firma **senza approvazioni** una modifica che, per il suo confronto con i corpi firmati (ultimo corpo del `policy_id` e policy corrente di ogni gruppo), non apre valori: `approval_mode: observe`, `opens_values` nella risposta, `observe_auto` nello stato; `TT_KEYGUARD_OBSERVE_AUTO=false` torna alla v1.5 | keyguard.md §3.2; `keyguard-api.v1` 1.5.0 | keyguard (fatto) |
| OB-3 | `tt-core`: `approvals_required: 0` per le modifiche che non aprono valori, applicate subito (bozza firmata e attivata nella stessa richiesta, ritentata se keyguard non risponde); il rollback chiede sempre le approvazioni di apertura; le modifiche che aprono valori come prima (default 2, admin da solo con motivazione) | policy.md §5, §7.3; `internal/fleet` | core (fatto) |
| OB-4 | Policy di partenza attiva subito; `hmac_kid` (primo kid di keyguard) ed `epoch` (mese corrente) facoltativi; campionamento di default 0,1 | policy.md §6; `createStarterPolicy` | core (fatto), UI |
| OB-5 | Versione Osserva automatica (`origin: observe-auto`, proposta da `system`): `hmac` sugli identificativi e identità rilevata dai dati (v1.12, `internal/fleet/identity_detect.go`) dopo `fleet.observe.min_events` chiamate o `fleet.observe.after`; si ferma quando una persona firma un'altra modifica; al rinnovo toglie le finestre scadute | policy.md §7.4; config `fleet.observe.{enabled, after, min_events, interval}` | core (fatto) |
| OB-6 | admin-api 1.10.0: `POST /api/v1/fleet/policies/classify` (`classifyPolicy`), `GET /api/v1/fleet/groups/{group}/observe` (`getObserveStatus`), `PolicyVersion.opens_values`/`value_reasons`, `approvals_required` da 0, `approval_mode: observe`, `origin: observe-auto`, dry run di `policyAssistantDraft` classificato | `api/admin-api.v1.openapi.yaml` | core (fatto), UI |
| OB-7 | UI: wizard in tre passi (servizi → comando → «In ascolto»), policy in «Avanzate»; «Rivedi in blocco» in Sorgenti → Policy; messaggio «Questa modifica non apre dati: si applica subito» / «Apre valori in chiaro: serve un'approvazione» | `ui/src/pages/Onboarding.svelte`, `Sources.svelte` | UI |

Rischio residuo accettato (policy.md §7.3): un `tt-core` compromesso può far firmare senza persone policy con più `hmac` e con la scoperta accesa (7 giorni alla volta), mai valori in chiaro né fasce.

### admin-api 1.9.0, control-api: operazioni lunghe e risposte limitate (ottobre 2026)

Nessun formato cambia (identificatori invariati). Due cambiamenti di comportamento delle API, dall'audit di prestazioni ([PERFORMANCE.md](../PERFORMANCE.md)):

- **admin-api 1.9.0.** `buildArchetypes`, `generateWorld`, `buildPack`, `runExport`, `exportEvents` e `mineRules` sono attese al più circa 20 secondi (due terzi di `admin.http.write_timeout` se più corto). Entro quel tempo la risposta è quella di prima (`Job` con `status: done`); oltre, la risposta è `202` con `status: running` e il risultato si legge con `GET /api/v1/jobs/{job_id}` (`done` con `result`, oppure `failed` con `error`). Prima, con milioni di eventi, la connessione veniva chiusa allo scadere di `write_timeout` mentre il lavoro continuava. La UI segue il job.
- **control-api (mock).** `POST /__tt/sessions/{id}/clock/advance` elenca al più i primi 1000 effetti applicati; quando sono di più aggiunge `applied_total` e `applied_truncated: true` (lo stato della sessione li contiene tutti).

### v1.5.0 — scoperta automatica degli host (admin-api 1.7.0, ottobre 2026)

**Decisione di progetto:** «se il mio servizio chiama qualcosa che non ricordo devo poterlo vedere e intercettare». Fino alla v1.4 ogni host esterno non dichiarato usciva come `host:unlisted` (decisione D-S3): il servizio chiamato era invisibile. Dalla v1.5 il default è `hosts.discovery: auto`: l'host esce come **pattern** costruito in modo che non contenga valori ([sanitizer.md](sanitizer.md) §3.5), l'intake lo ricontrolla e ne sorveglia la cardinalità ([event.md](event.md) §5.2, §5.4), e `tt-core` mostra tutti gli host raggruppati per dominio registrabile con la possibilità di gemellarli. La vecchia uscita resta disponibile come **modalità stretta** `hosts.discovery: off`.

**Versioni.** Gli identificatori restano `v1` (`tt.sanitizer/v1`, `tt.policy.body/v1`, `tt.http.exchange/v1`). È un cambiamento dell'uscita del sanitizer: come la revisione 1.1 è un'eccezione esplicita alla regola «major» di [Versioni](#versioni), decisa per il prodotto e resa compatibile così: (1) il corpo compilato scrive `hosts` **solo** per `off`, quindi le sorgenti precedenti alla v1.5 accettano le policy di default e continuano a emettere `host:unlisted`, che l'intake accetta sempre; (2) una policy con `hosts.discovery: off` fa uscire, byte per byte, quello che usciva prima (vettori 1900–1908); (3) l'intake accetta sia `host:unlisted` sia i pattern. Una sorgente non aggiornata non è conforme alla v1.5 (fallisce i vettori riscritti) ma non apre dati.

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| HP-1 | Scelta del servizio outbound: `base` → `segments.hosts_allow` (esatto) → **pattern** se `hosts.discovery` è `auto` (o assente) o la scoperta è attiva → `host:unlisted` (solo `off`) | sanitizer.md §3.1 | sorgenti |
| HP-2 | Pattern dell'host: minuscolo, porta di default tolta, un punto finale tolto, etichetta vuota → `host:invalid`; ogni etichetta letterale solo se `^[a-z][a-z0-9-]{0,62}$`, senza 6 cifre consecutive, senza 12 esadecimali consecutivi, senza formati di §6.3, altrimenti `{*}`; i `{*}` consecutivi restano uno per uno; punycode con le stesse regole | sanitizer.md §3.5 | sorgenti |
| HP-3 | Letterali IP: IPv4 (formato `ipv4` di §6.3) e IPv6 tra parentesi (parser della RFC 4291 §2.2 definito nella spec, niente zone) escono solo come `ip:private` / `ip:public` secondo una tabella chiusa; prima i letterali IPv6 erano `host:invalid` | sanitizer.md §3.1 punto 5, §3.6 | sorgenti |
| HP-4 | Modalità scoperta: gli host non escono più in chiaro ma come pattern, anche con `off` | sanitizer.md §15 | sorgenti |
| HP-5 | Policy: blocco autore `hosts: { discovery: auto \| off }`; nel corpo compilato `{"hosts":{"discovery":"off"}}` solo per `off`; altri valori o campi → policy rifiutata. `auto` → `off` chiude, `off` → `auto` apre (tt-core `hosts.discovery_auto`, keyguard `hosts.discovery`) | policy.md §1, §1.3.1, §2, §5; schemi `policy.v1`, `policy-compiled.v1` | core, keyguard (fatti), sorgenti |
| HP-6 | Evento: `service` accetta `host:<pattern>` (`{*}`, `ip:private`, `ip:public`, porta), al più 518 byte; stessa grammatica per i nomi di servizio di `rules.v1` e `pack-manifest.v1` (contratti e regole su host scoperti) | event.md §1; schemi `event.v1`, `rules.v1`, `pack-manifest.v1`; `internal/event`, `internal/pack`, `internal/miner` | core (fatto), sorgenti (solo se validano gli eventi in uscita) |
| HP-7 | Intake: controllo I11 (le etichette letterali rispettano la regola, `host_not_allowed` altrimenti); I6 accetta i pattern con `auto`; due sketch: domini registrabili per sorgente (tipo `host`, prima «host per sorgente») ed etichette per dominio registrabile e posizione (tipo nuovo `host-label`, `k` = 50); oltre soglia la posizione (o l'etichetta registrabile) diventa `{*}` negli eventi salvati e futuri, allarme `host_cardinality`; prima un host in quarantena diventava `host:unlisted`. Una sorgente precedente alla v1.5 in modalità scoperta che manda un host con etichette non sicure (le mandava in chiaro) ora è rifiutata con `host_not_allowed` | event.md §5.1, §5.2, §5.4; hardening.md I6, I11 | core (fatto) |
| HP-8 | Dominio registrabile: ultime due etichette, ultime tre per un elenco chiuso di suffissi a due etichette (`co.uk`, `com.au`, …); solo zona B | event.md §5.4; `internal/hostpat` | core (fatto) |
| HP-9 | API di amministrazione 1.6.0: `GET /api/v1/hosts` (`listHosts`, ruoli operator e admin: domini → pattern con chiamate, servizi chiamanti, prima/ultima volta, errori, tasso d'errore, latenza p50, servizi dichiarati, `unlisted` e `invalid` a parte, modo `hosts.discovery` per policy); `POST /api/v1/hosts/{pattern}/twin` (`twinHost`, operator e admin: bozza di policy con un servizio esterno `match.base`, origine `host-twin`, approvazioni normali, override dell'admin con `reason` su `approvePolicy`; per pattern con `{*}` o IP la persona dà la `base` esatta, che deve corrispondere al pattern); `QuarantineItem.kind` con `host-label` e `alert: host_cardinality`; `PolicyVersion.origin` con `host-twin` | `api/admin-api.v1.openapi.yaml`; `internal/core/hosts.go`, `internal/fleet/hosttwin.go` | core (fatto), UI |
| HP-10 | Vettori: 0007, 1134, 1137, 1142, 1340, 1342, 1343 riscritti per `auto` (1140 cambia solo la descrizione); copie in modalità stretta 1900–1908; casi nuovi 1909–1981 (regole a–c, porte, IPv4/IPv6, punycode, maiuscole, punto finale, 253/254 byte, molte etichette) e rifiuti del campo `hosts` 1990–1992; categoria nuova `hosts`; `leakcheck.py` controlla anche le etichette degli host (proprietà D) | `conformance/` | conformance (fatto), sorgenti |
| HP-11 | Threat model: M19 e rischio residuo «Host» (un nome di persona come sottodominio statico passa la regola della sorgente finché la cardinalità dell'intake non lo collassa; mitigazioni e modalità stretta); G1 con le etichette sicure degli host | THREAT_MODEL §5, §6, §7 | tutti |

**Implementato in questa versione:** riferimento Python (`conformance/ref`), Go (`internal/hostpat`, `internal/sanitizer`, quindi SDK Go, `tt-egress` e adattatore OBI), `internal/policy`, `internal/intake`, `internal/fleet`, `internal/keyguard`, `internal/core`. **Da fare:** SDK Node, Python, Java, .NET, PHP (elenco sotto) e UI.

#### Cosa devono cambiare gli SDK (Node, Python, Java, .NET, PHP)

Ogni punto è verificato dai vettori indicati; il riferimento leggibile è `conformance/ref/sanitizer.py` (`normalize_url_base`, `parse_ipv6`, `host_label_safe`, `ipv4_private`, `ipv6_private`, `host_pattern`, `Sanitizer.select_service`), quello Go è `internal/hostpat`.

1. **Validazione della policy.** Accettare nel corpo compilato il campo facoltativo di primo livello `hosts`: oggetto con il solo campo obbligatorio `discovery` di valore `"auto"` o `"off"`. Un altro valore, un campo in più o `discovery` mancante → `policy_rejected` (vettori 1990, 1991, 1992). Aggiornare la copia dello schema `policy-compiled.v1` se l'SDK ne incorpora una. Senza `hosts` il modo è `auto`.
2. **`url_base` con IPv6** (§3.1 punto 5). Se l'autorità inizia con `[`: cercare `]` (assente → `host:invalid`), dopo `]` solo la fine o `:porta` (con le regole di porta di sempre: 1–5 cifre, 1–65535, zeri iniziali tolti, porta di default tolta). Il testo tra parentesi, in minuscolo, si analizza con un parser **proprio** che segue la spec: gruppi 1–4 esadecimali, al più un `::` che vale almeno un gruppo (≤ 7 gruppi scritti con `::`, esattamente 8 senza), coda IPv4 nel formato `ipv4` di §6.3 (senza zeri iniziali) solo come ultimo elemento, niente `%` (zone). Non usare `inet_pton`, `ipaddress`, `InetAddress`, `IPAddress.TryParse` o `filter_var`: accettano forme diverse tra versioni. Un letterale IPv6 non confronta mai con `base` né con `hosts_allow` (vettori 1142, 1906, 1949–1961).
3. **Ordine della scelta** (§3.1): `base` più lunga → host esatto in `segments.hosts_allow` → se `hosts.discovery` è `auto`/assente **o** la scoperta è attiva: `host:` + pattern (o `host:invalid` se il pattern non esiste) → altrimenti `host:unlisted` (1908, 1922, 1923, 1948).
4. **Pattern** (§3.5), nell'ordine: IPv6 → classe; togliere **un** punto finale; se il resto corrisponde al formato `ipv4` di §6.3 → classe; dividere su `.`, un'etichetta vuota → `host:invalid`; ogni etichetta letterale solo se passa `^[a-z][a-z0-9-]{0,62}$` (regex ASCII sull'intera stringa, §0.1), non contiene `[0-9]{6}` e non contiene `[0-9a-f]{12}` (la regola d sui formati di §6.3 è implicata, si può saltare); altrimenti `{*}`; non fondere i `{*}` consecutivi; poi `:porta` se non di default (1909–1981).
5. **Classi IP** (§3.6): tabella chiusa della spec, IPv6 con IPv4 incorporato (`::ffff:0:0/96`, `64:ff9b::/96`) prima delle altre righe IPv6. Non usare `is_private`/`isSiteLocalAddress`/`IsPrivate` delle librerie (1840–1861).
6. **Modalità scoperta** (§15): non emettere più l'host in chiaro; emettere il pattern anche con `hosts.discovery: off` (1140, 1907, 1924).
7. **Test generativi e G1 dell'SDK**: con policy vuota il `service` outbound può contenere etichette che passano la regola (sono struttura, come i nomi); aggiungere il controllo che ogni etichetta letterale passi la regola e un caso in modalità stretta che dia `host:unlisted`. Le stringhe di `service` arrivano a 518 byte.
8. **Runner dei vettori**: categoria nuova `hosts`; 74 vettori nuovi (1900–1992) e 7 con uscita cambiata. Nessun campo d'ingresso nuovo.
9. **Integrazioni HTTP** che costruiscono `url_base`: passare l'host così come lo vede il client, con le parentesi per IPv6 (`[2001:db8::1]:8080`) e senza togliere un punto finale né convertire IDN (un host Unicode resta non valido; una forma `xn--` resta `xn--`).
10. **README** dell'SDK: documentare `hosts.discovery` e la modalità stretta. Il dominio registrabile (event.md §5.4) è solo zona B: le sorgenti **non** lo implementano.

#### Cosa deve fare la UI

1. Pagina **Host** (o sezione di «Servizi scoperti») da `GET /api/v1/hosts`: domini registrabili ordinati per chiamate, per ciascuno i pattern con chiamate, chiamanti, prima/ultima volta, `error_rate` e `client_errors`, `latency_p50_ms`, `declared` (già un servizio della policy), `quarantined`; voci a parte per `unlisted` (chiamate in modalità stretta: suggerire `auto`) e `invalid`. `{*}` si mostra come segnaposto, mai come «valore nascosto da rivelare».
2. Pulsante **Gemella** → `POST /api/v1/hosts/{pattern}/twin` (pattern percent-encoded): per `exact: false` chiedere la base esatta e il nome del servizio; mostrare che nasce una **bozza** da approvare (apertura) e portare alla pagina della bozza; errori `base_required`, `base_mismatch`, `already_declared`, `service_exists`, `policy_required`.
3. Coda di quarantena: tipo `host-label` («etichette sotto *dominio*, posizione *n*») e `alert: host_cardinality` per `host` e `host-label`.
4. Editor/diff della policy: `hosts.discovery` (`auto`/`off`), con `off` → `auto` come apertura; `PolicyVersion.origin` può valere `host-twin`.

### L'admin è il superutente (admin-api 1.6.0, policy.md §5 v1.6, ottobre 2026)

Decisione di progetto: «l'admin deve vedere tutto e non deve essere limitato». Le regole di separazione dei compiti aggiunte dal red team round 2 per l'admin diventano tracciabilità.

| # | Cambiamento | Chi agisce |
|---|---|---|
| S-1 | `admin` implica ogni ruolo: passa ogni `x-tt-roles` di `tt-core` (un solo punto: `auth.Principal.HasAny`, usato da `Require` e dalle guardie) e vede ogni pagina e azione della UI | core, UI |
| S-2 | Tolti per l'admin `409 sod_conflict` (qualsiasi combinazione di ruoli, anche da OIDC) e `409 self_grant`; un non admin non assegna mai ruoli (`403`). Resta `409 self_lockout` sul proprio `admin` | core, UI |
| S-3 | Override tracciati: `authz.admin_override` per ogni richiesta dell'admin, ammessa solo per implicazione, che cambia qualcosa o scarica un file; `admin_override: "true"` nelle voci di download/export dei pacchetti, export/download degli eventi, regole | core |
| S-4 | Quarantena: l'admin chiude o scioglie da solo (`quarantine.admin_override`, allarme per lo scioglimento); export degli eventi da parte dell'admin con allarme (`admin_override: true`), download degli export altrui con allarme `events.admin_download` | core |
| S-5 | Approvazione di policy e rilascio di pacchetti dell'admin invariati (motivazione, `approval_mode: admin`, `policy.admin_approval` / `pack.admin_approval`); un admin che ha anche `policy-approver` arriva a keyguard solo come `admin`. Keyguard invariato: `TT_KEYGUARD_ADMIN_OVERRIDE=false` è l'unico limite, scelta dell'installatore | core, keyguard (doc) |
| S-6 | Threat model M17 e §7: rischio residuo accettato, l'admin può agire da solo ma mai in modo invisibile | doc |

### Approvazioni legate alla modifica (admin-api 1.5.0, keyguard-api 1.4.0, red team round 3, ottobre 2026)

Correzione di RT3-KG-1…4 e RT3-OIDC-1/2: con OIDC le approvazioni non si fidano più di ciò che dichiara `tt-core`.

| # | Cambiamento | Chi agisce |
|---|---|---|
| A-1 | keyguard legge i ruoli dell'approvatore dal claim `TT_KEYGUARD_OIDC_ROLES_CLAIM` (obbligatorio con OIDC) del token verificato, tramite `TT_KEYGUARD_OIDC_ROLE_MAPPING`; `admin`/`policy-approver`/`publisher` assenti dal token: `403 role_unverified`. `TT_KEYGUARD_OIDC_AUDIENCE` è l'audience **dedicata alle approvazioni** (client diverso da quello del login) | keyguard, IdP |
| A-2 | Ogni token è legato alla modifica: `nonce = base64url(SHA-256("tt.approve/v1" 0x00 scopo 0x00 campi…))` (policy: `policy_id`, `version`, SHA-256 del corpo senza `issued_seq`/`created_at`/`not_after`; pacchetto: `pack_id`, SHA-256 del manifest; quarantena: id dell'elemento), più `auth_time` ≤ 10 minuti ([keyguard.md](keyguard.md) §3.2 punto 4) | keyguard, core |
| A-3 | Riuso: impronte su `iss`/`sub`/`jti` (o `iat`+`nonce`) e sulla firma decodificata, per **tutti** i token presentati (anche in modalità admin) e per i pacchetti; segmenti base64url solo canonici | keyguard |
| A-4 | `tt-core`: step-up `GET /api/v1/auth/oidc/stepup` e callback, `auth.oidc.approval_client_id`; il token resta in memoria ≤ 10 minuti e non si scrive mai; verifica `iss`/`aud`/`sub`/`nonce`; account locali senza token (`oidc_required`, `id_token_not_allowed`); `403 stepup_required`; `token_fresh` sulle approvazioni e rinnovo (`policy.approval_renewed`); `id_token` facoltativo anche su `publish` e `resolve` | core, UI |
| A-5 | Stato di keyguard: oggetto `oidc` (`issuer`, `audience`, `roles_claim`). Senza OIDC nulla cambia: `approvals_unverified: true`, garanzia ridotta mostrata nella UI | keyguard, core, UI |

### admin-api 1.4.0 (ottobre 2026)

Rifinitura dell'API di amministrazione emersa dall'integrazione della UI: la UI non deve più dedurre dai testi né fare chiamate per snapshot. Gli identificatori restano `v1`. Unico cambio di forma: `GET /api/v1/archetypes` risponde con un oggetto `{k_min, built, archetypes, …}` invece di un array.

| # | Cambiamento | Chi agisce |
|---|---|---|
| B-1 | Avvisi di drift: `kind` (`contract.drift` / `rule.stale`) nel corpo, `?kind=all` per averli in una chiamata, stato `resolved` (`resolved_by`), `PATCH /drift/{id}` `{state}` (ruolo operator, verificato in audit come `drift.ack` / `drift.resolve`, `409 invalid_transition` se si torna indietro). Webhook: `enabled`, `PATCH /webhooks/{id}` (admin, audit `webhook.enable` / `webhook.disable`) | core, UI |
| B-2 | `SnapshotInfo.breaking` / `non_breaking` (rispetto allo snapshot precedente dello stesso servizio); lacune con `id` stabile, `scope` (`op` / `field`) e `threshold`; `GET /archetypes` con `k_min` | core, UI |
| B-3 | `GET /audit/export?last=N` e `?before_seq=S` (lettura dalla coda, a ritroso); regole con `proposed_at`; `PATCH /rules/{id}` accetta `after` come durata singola o `{min, max}` (min ≤ max, rules.md §3.3); `POST /rules/mine` scrive `rule.mine_request` | core, UI |
| B-4 | `GET /settings` (admin, operator) e `PATCH /settings`: solo nome dell'installazione ed etichetta dell'ambiente sono modificabili (admin, audit `settings.update`); k minimi, retention, sessioni e SSO sono in sola lettura dalla configurazione; `GET /version` riporta anche `installation_name` e `environment` | core, UI |
| B-5 | Scelta «twin sì/no» per servizio salvata dal server: `Service.twin`, `PUT /services/{service}/twin` (operator, audit `service.twin`); è il default di `POST /packs` quando la richiesta non elenca i servizi | core, UI |
| B-6 | Token di iscrizione di tipo `k8s-inject` (sempre `group`): iscrive l'SDK di qualunque linguaggio per l'injector Kubernetes; gli snippet usano il Secret con `url` e `token` e le annotazioni che l'injector legge davvero | core, UI |

### v1.3.0 (ottobre 2026)

Sincronizzazione dei documenti normativi con ciò che è stato **costruito** (fleet, keyguard, contratti e drift, miner, mondi, gate e pacchetti, mock, intake, egress). Dove spec e codice divergevano ha vinto il codice, salvo una proprietà di sicurezza: in quel caso la spec non è stata cambiata e la divergenza è un difetto dell'implementazione (elencato sotto). Gli identificatori restano `v1`. Eccezione: la parte 2 di [hardening.md](hardening.md) è **nuova e normativa** dalla v1.3 e richiede lavoro alle sorgenti.

Legenda di "chi agisce": **core** (`tt-core`: fleet, API di amministrazione, gate, `internal/policy`), **keyguard**, **sorgenti** (SDK Node/Python/Java/.NET/PHP/Go, `tt-egress`, OBI), **mock**, **UI**, **conformance**.

#### Nuovo: hardening ([hardening.md](hardening.md))

| # | Cambiamento | Chi agisce |
|---|---|---|
| H-1 | Parte 1: i dieci controlli dell'intake oltre `event.md` §5.1 (mappe vuote, nomi letterali, header a un solo valore, nome di servizio assegnato, finestra della policy, `disc`/host/parole attive, busta OTLP, forma del corpo, rotte coerenti con la policy, tetto dei monitor) sono documentati. Già in vigore: un sanitizer conforme non li incontra | core (già fatto), sorgenti (conformità) |
| H-2 | Parte 2, **normativa v1.3**: le sorgenti rifiutano le policy firmate con `keep`/`hmac` su `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, con `keep`/`hmac` su `.*` nelle regole globali, o con scoperta/parole automatiche che scadono oltre 7 giorni da `created_at` (difesa in profondità contro un bug di validazione a monte). `tt-core` vieta anche `hmac` su quei header | **Implementato**: sorgenti Go (`internal/policy`, `internal/sourceclient`) e SDK Node, Python, Java, .NET, PHP (§2.5). core: implementato in `internal/policy`. keyguard: da verificare (§2.3). conformance: vettori 0122, 0123, 0703, 0704, 0802, 0803, 0809, 0901, 0902, 0903, 0952, 0953, 1209, 1213 riscritti; 1701–1783 nuovi |

#### Policy e keyguard (`policy.md`, `keyguard.md`, `keyguard-api.v1` 1.3.0)

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| K1 | **L'autore non approva la propria modifica, nemmeno di chiusura** (regola di `tt-core`, più severa del testo 1.2 «almeno una diversa dal proponente»); keyguard resta più largo (con 1 approvazione richiesta accetta anche il proponente; l'admin è l'unica eccezione) e fa da rete di sicurezza | policy.md §5, keyguard.md §3.2 | core (già fatto), keyguard (nessun cambio) |
| K2 | Classificazione chiusura/apertura **più severa**: confronto con l'ultimo corpo firmato dello stesso `policy_id` **e** con la policy corrente di ogni gruppo; prima policy o gruppo senza policy apre; `version` deve crescere | keyguard.md §3.2 | keyguard (già fatto) |
| K3 | ID token OIDC monouso; approvazioni al più 8; modi di approvazione `standard`/`single`/`admin` nella risposta; `classification` nella risposta, che `tt-core` usa al posto della propria | keyguard.md §3.2, keyguard-api | keyguard, core (già fatti) |
| K4 | Audit di keyguard nel **proprio database SQLite** (tabella a catena di hash con trigger), non in un file JSONL; `GET /audit` con `hash` e tetto di 1000 voci | keyguard.md §4 | keyguard (già fatto) |
| K5 | `status` espone `opening_approvals`, `admin_override`, `policy_kid`, `pack_kid`, `revoked_kids`, `last_issued_seq`, filtri; `GET /health`; `public-keys` con chiavi ritirate ed `endorsed_by`/`endorsement` facoltativi per la rotazione | keyguard.md §6–§7, keyguard-api | keyguard, core |
| K6 | `pack/sign` accetta l'header `X-TT-Approval` (publisher, oppure admin con motivazione): `approval_mode` nella risposta, allarme `pack.admin_approval`, firma identica alla costruzione; archivio al massimo 256 MiB; frequenza limitata | keyguard.md §3.4 | keyguard, core (già fatti) |
| K7 | Il rinnovo (`policy/renew`) non riporta in vita una policy scaduta o superata | keyguard.md §3.3 | keyguard (già fatto) |
| K8 | Elenco completo degli allarmi (`match.positive`, `pack.positive`, `rate.limited`, `budget.exceeded`, `policy.approval_refused`, `sign.refused`, `policy.admin_approval`, `pack.admin_approval`) | keyguard.md §5 | keyguard (già fatto) |

#### API di amministrazione (`admin-api.v1` 1.3.0)

| # | Cambiamento | Chi agisce |
|---|---|---|
| A-1 | Endpoint montati e non ancora documentati: `POST /api/v1/fleet/groups/{group}/starter-policy`, `GET /api/v1/fleet/signing-keys`, `POST /api/v1/fleet/signing-keys/{kid}/revoke`, `GET /api/v1/fleet/approval-settings`, `POST /api/v1/contracts/{service}/snapshots`, `GET /api/v1/webhooks/{id}/deliveries`, `GET /api/v1/worlds/{id}/customers/{customer}` | core, UI |
| A-2 | Campi aggiunti dal fleet: `approve.reason` (approvazione dell'admin) e ruolo `admin` su `approve`, `PolicyVersion.origin`/`approval_mode`/`note`/`approvals[].admin_override`/`reason`/`note`, `Group.policy_draft`, `OnboardingStatus.sources`, `SourceStatus.sanitizer_errors`/`last_errors`, nuovi codici di `Problem` | core, UI |
| A-3 | Campi aggiunti altrove: `SnapshotInfo.created_at`/`hash`, `Drift.where`/`change_kind`/`ack_by`, `drift?kind=`/`limit`, `contracts?format=yaml&pack_safe=`, `WorldInfo.t0`/`locale`/`entities`/`history`/`pending`/`sha256`, `PackInfo.residual_risk`/`approval_mode`, `publish` con `reason` e ruolo `admin`, `Webhook.secret` generato e mostrato una volta | core, UI |
| A-4 | `AuditEntry` allineato al registro reale (`ts`, `actor` e `target` come oggetti, `outcome` `success`/`failure`/`denied`, `reason`, `request_id`, `details`, `hash`) | core, UI |
| A-5 | Elenco dei codici d'errore e degli stati per operazione; descrizione degli errori comuni | core, UI |
| A-6 | **Lavori sincroni**: `archetypes/build`, `worlds`, `packs` rispondono `202` con il `Job` già `done`; `/api/v1/jobs/{id}` non esiste per questi (resta per esportazioni, purge ed export di eventi). I client leggono `status` prima di interrogare | core, UI |
| A-7 | Operazioni previste ma **non ancora montate** marcate `x-tt-status: planned`: utenti, esportazioni, preset di scenario, quarantena, retention e purge, export di eventi, `jobs`, `version`, proxy di keyguard | core |

#### Fleet API (`fleet-api.v1` 1.3.0)

| # | Cambiamento | Chi agisce |
|---|---|---|
| F-1 | `POST /fleet/v1/enroll` limitato in frequenza (per indirizzo, IPv6 per /64, e per token): `429 rate_limited` con `Retry-After`; default e chiavi di configurazione `fleet.enroll_rate_limit.{ip,token}` | core (già fatto), sorgenti (DOVREBBERO rispettare `Retry-After`) |
| F-3 | Red team round 3: un gruppo con `policy_id` `null` non riceve più policy (`404 no_policy`) e il suo heartbeat porta `min_issued_seq` oltre ogni policy firmata, così le sorgenti smettono di catturare; bozza di chiusura senza il gruppo se la policy ne ha altri; una policy senza gruppi collegati non è rinnovata ([policy.md](policy.md) §4.1) | core (fleet), sorgenti (già conformi) |
| F-2 | Codici d'errore completi di enroll, policy, heartbeat e renew (`token_unknown`/`expired`/`revoked`/`exhausted`, `kind_mismatch`, `no_signing_keys`, `source_mismatch`, `invalid_heartbeat`…) | core, sorgenti |

#### Regole, pacchetto, mock

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| R-1 | Liste senza limite effettivo: una sola pagina; `page` ≥ 2, offset oltre la fine e `limit` 0 danno pagina vuota; `max_limit` non si applica senza limite | rules.md §2.3 | mock (già fatto), exporter |
| R-2 | Nomi dei rami: identificatori liberi; convenzione del miner (`happy`, `never`, `stuck-<stato>`, `<stato>`). Decisione: né spec né miner cambiano; il lato che confronta per nome (valutazione del miner, e2e della demo, fixture della UI con `never-shipped`) deve confrontare per effetti o mappare i nomi | rules.md §3.1 | conformance/e2e, UI, demo |
| P-1 | Costruzione, firma e rilascio del pacchetto: sincroni, stati `gate-failed`/`signed`/`published`, doppia firma identica, scarico solo dei rilasciati, rischio residuo informativo | pack.md §8 | core |
| M-1 | `JournalEntry.reason` può valere `payload_too_large` (`control-api.v1` 1.3.0) | control-api, mock.md §3 | mock (già fatto), test |

#### Difetti o lavori dell'implementazione emersi (la spec non li ha cambiati)

| # | Cosa | Perché non è la spec a cambiare |
|---|---|---|
| D-1 | Le sorgenti non applicano ancora H1–H3 (parte 2 di hardening) e `internal/policy` vieta `keep` ma non `hmac` sui header sensibili | Decisione di progetto: normativo dalla v1.3 |
| D-2 | keyguard non emette `endorsed_by`/`endorsement` in `public-keys` e azzera i semi delle chiavi ritirate: una rotazione della chiave di firma delle policy non può essere annunciata alle sorgenti già iscritte via heartbeat (`add_signing_keys`), che rifiuterebbero le policy con il `kid` nuovo | La specifica (policy.md §3) prevede la rotazione con endorsement; manca la parte di keyguard |
| D-3 | Operazioni dell'API di amministrazione non ancora montate (A-7) e `GET /api/v1/jobs/{id}` assente, mentre i `202` portano un `job_id` | Sono parte del contratto; il codice è incompleto |

### v1.2.1 (ottobre 2026)

- Approvazioni delle policy che aprono dati: numero configurabile in keyguard (`TT_KEYGUARD_OPENING_APPROVALS`, default 2) e approvazione singola sempre consentita a un `admin` con motivazione obbligatoria e allarme (`TT_KEYGUARD_ADMIN_OVERRIDE`, default attivo). Vedi [policy.md §5](policy.md) e [keyguard.md §3.2](keyguard.md). Devono agire: keyguard, fleet, UI.

### v1.2.0 (ottobre 2026)

Revisione di regole, pacchetto e API di controllo per modellare fedelmente la demo e-commerce/corriere ([GROUND_TRUTH](../../demo/GROUND_TRUTH.md)): chiude i buchi trovati implementando il mock. Gli identificatori restano `v1`: nessun produttore di regole o mondi (miner, generatore) è ancora stato rilasciato, e chi legge (mock, exporter) va aggiornato prima che un produttore emetta i campi nuovi. I file v1.1 restano validi senza modifiche.

Legenda di "chi agisce": **mock** (`internal/mock`, `internal/pack`), **exporter** (`internal/export`), **miner** (`internal/miner`), **world** (`internal/world`, generatore), **core** (`tt-core`: gate, API di amministrazione, `internal/pack` lato scrittura), **keyguard**, **UI**.

#### Regole (`rules.md`, schema `rules.v1`)

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| R1 | Relazioni tra entità: `entities[].relations[]` (`field`, `entity`, `many`); integrità referenziale nel mondo; il mock non inventa mai un campo di relazione | rules.md §2.2, mock.md §2 | miner, world, mock, UI |
| R2 | Effetto che aggiorna un'entità esistente legata da `bind`: `target_id: "${var}"` (alternativo a `target`); `target` vale anche per un'entità **aggiornata** dall'effetto citato | rules.md §3.1 | miner, world, mock, UI |
| R3 | Riferimento `"${effect:<id>}"` all'id creato/aggiornato da un effetto della stessa esecuzione (solo antenati nella catena `after_effect`); i riferimenti valgono solo come stringa intera | rules.md §3.2 | miner, world, mock, UI |
| R4 | Effetti **immediati** (istante = causa) applicati prima della risposta; ordine normativo creazione → prima stesura → `bind` → coda → effetti immediati → corpo finale. Così `POST /orders` risponde con lo `shipmentId` della spedizione creata dalla regola | rules.md §3.5, §6 | mock, world, exporter |
| R5 | `read_by[].service`: un'operazione di un altro servizio espone l'entità (`GET /orders/{id}/shipment` dello shop) | rules.md §2 | miner, mock, exporter, UI |
| R6 | `read_by[].hidden_when`: entità invisibili per un'operazione (spedizione `PENDING`) | rules.md §2.4 | miner, mock, exporter, UI |
| R7 | Collezioni per cliente: `by.owner: true` (`GET /customers/{id}/orders`), `by` facoltativo per le liste del cliente della sessione, `read_by[].list` (`count`, `total`, `limit`, `offset`/`page`/`cursor`, `next_cursor`, `order_by`, limiti), algoritmo di selezione, ordinamento e pagina; `x-tt-entity` senza `read_by` deprecato | rules.md §2.3, pack.md §4 | miner, mock, exporter, UI; inferenza dei contratti (`x-tt-entity` resta solo informativo) |
| R8 | Proprietario delle entità (cliente della sessione all'istante della causa; `customer_id` nel mondo) e campi derivati `customerId`/`createdAt`/`updatedAt` resi normativi | rules.md §2.6, mock.md §2 | mock, world |
| R9 | Visibilità per cliente configurabile per operazione: `scope` (`any` default, `owner`), `foreign` (`not_found` default, `forbidden`), `foreign_example`, `not_found_example`; senza cliente nella sessione nessun filtro | rules.md §2.5 | miner, mock, exporter, UI |
| R10 | Chiavi di legame del miner in `evidence.keys[]` (`domain`, `from`, `to`, `matches`); come il miner ne ricava `bind`, `create`, `target_id`, relazioni ed effetti immediati | rules.md §3.4 | miner, core (soglia k), UI |
| R11 | Ritardi a intervallo: `after: { min, max }`, estrazione uniforme in secondi interi con il seed, una per effetto a intervallo dopo l'estrazione del ramo; esempi allineati a GROUND_TRUTH R3 (`2m..10m`, `1h..6h`, `6h..36h`, `30m..4h`) | rules.md §3.3 | miner, world, mock, exporter (metadati), UI |
| R12 | Semantica del generatore: simula solo le operazioni chiamate dai clienti; regole con causa chiamata da un altro servizio (r-0008) valgono solo nel mock | rules.md §6.1 | world |
| R13 | Esempio completo della demo (r-0007 con `shipment-requested` `PENDING` immediato e `order-linked`, r-0008 lato corriere, r-0012) | rules.md §2–§4, §7 | — |

#### Pacchetto (`pack.md`, schema `pack-manifest.v1`)

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| P1 | Righe `pending` in `world.jsonl` (`due_offset_s` relativo al `t0` della sessione, `seq`, `rule_id`, `outcome`, `effect_id`, `entity`, `id` assegnato in anticipo per i `create`, `customer_id`, `vars`, `effect_ids`), ultime nel file, ordinate per (`due_offset_s`, `seq`); messe in coda a ogni creazione e `reset` di sessione; contatori degli id dopo gli id pendenti | pack.md §5 | world, mock, exporter (catene esatte), UI |
| P2 | `outcome` nelle righe `history` delle regole causali; `seq` crescente per entità | pack.md §5 | world, exporter (niente più ricostruzione dell'esito più probabile), mock |
| P3 | Controlli di integrità del mondo all'avvio del mock (relazioni, clienti, righe `pending`) | pack.md §5 | mock, world |
| P4 | Schema di `scenarios.json` (`tt.scenarios/v1`, `$defs/scenarios`, `$defs/sessionFaults`): `id`, `name`, `description`, `customer` o `archetype`, `seed`, `faults`, `outcomes`; verificato all'avvio | pack.md §6.1 | core (scrittura), mock, UI |
| P5 | `not_after` facoltativo nel manifest (coperto dalla firma); verificatori rifiutano con `pack_expired` a orologio ≥ `not_after`; `--max-pack-age` resta politica locale, vale il limite più stretto; keyguard non firma se `not_after` ≤ `created_at` | pack.md §2.1, keyguard.md §3.4 | core, keyguard, mock e `tt export` (`internal/pack`), UI |
| P7 | Red team round 3: `manifest.json` canonico (codifica esatta, niente chiavi duplicate o con altre maiuscole o sconosciute); firma verificata **prima** di leggere altro che manifest e firma, poi solo i file elencati con dimensioni esatte; `created_at` non oltre +5 min; default `valid_days` 30 giorni; senza `not_after` limite di età 90 giorni; `TT_GATE_REVOKED_KIDS`; file `TT_GATE_PUBKEYS` non scrivibile da gruppo/altri | pack.md §1, §2.1, §2.2, §3, keyguard.md §3.4 | keyguard, `internal/pack`, mock, `tt export`, packwriter |
| P6 | Soglia `k_min` anche su `evidence.keys[].matches` | pack.md §7 | core (gate) |

#### Mock e API (`mock.md` nuovo, `control-api.v1` 1.2.0, `admin-api.v1` 1.2.0)

| # | Cambiamento | Dove | Chi agisce |
|---|---|---|---|
| A1 | Nuovo documento normativo del mock: verifica del pacchetto, costruzione delle risposte, involucro di errore, guasti di rete, codici dell'API di controllo, preset, `reset` | mock.md | mock, exporter |
| A2 | `GET /__tt/health` sempre pubblico anche con token, risponde solo `{"status":"ok"}` (niente `pack_id`), `Cache-Control: no-store`; prosa e `security: []` ora coerenti | mock.md §5.1, control API | mock |
| A3 | `pointer` (JSON Pointer) nell'involucro di errore e nel registro: per `invalid-request` nel documento virtuale `/path`, `/query`, `/headers`, `/cookies`, `/body`; per l'API di controllo nel corpo della chiamata | mock.md §3, §5.2 | mock (in gran parte già fatto) |
| A4 | Codici di stato resi normativi: `409 session_exists`, `404 customer_not_found`, `429 too_many_sessions`, `400` per `DELETE` della `default`, `400 clock_backwards` / `advance_too_large` / `too_many_steps`, `400 bad_request` per campi JSON sconosciuti (corpi con `additionalProperties: false`), `401` con `WWW-Authenticate` | mock.md §5.3, control API | mock (già conforme) |
| A5 | Approssimazioni dei guasti di rete: `refused`/`dns` = RST immediato senza latenza, `reset` = RST dopo la latenza, `tls` = record TLS di allarme e chiusura, `other` = chiusura senza risposta dopo la latenza, `timeout` invariato; corrispondenze WireMock | mock.md §4 | mock, exporter |
| A6 | Preset: `GET /__tt/scenarios`, `scenario` in `POST /__tt/sessions`, `{ "preset" }` in `POST /__tt/sessions/{s}/scenario` (azzera e diventa la base di `reset`); `Session.scenario`, `PackSummary.not_after` e `scenarios`, `pending_effects[].outcome` e `source` | mock.md §5.4, control API | mock, UI |
| A7 | API di amministrazione: `valid_days` in `buildPack` (→ `not_after`), `seed` in `ScenarioPreset` | admin API | core, UI |

#### Cambiamenti che rompono qualcosa

| # | Cosa | Chi si rompe | Cosa fare |
|---|---|---|---|
| X1 | `effects[].after` può essere un oggetto `{min, max}` | lettori stretti delle regole (`internal/pack`, exporter, UI) | Accettare stringa o intervallo |
| X2 | Nuovi campi facoltativi in regole (`relations`, `read_by.service/hidden_when/scope/foreign/foreign_example/not_found_example/list`, `by.owner`, `target_id`, `evidence.keys`), manifest (`not_after`) e righe `history` (`outcome`) | `internal/pack` decodifica con `DisallowUnknownFields` e oggi rifiuta i pacchetti 1.2 | Aggiornare i tipi prima che miner e generatore emettano i campi |
| X3 | Nuovo tipo di riga `pending` in `world.jsonl` | `internal/pack` (tipo di riga sconosciuto), exporter | Leggere e applicare le righe |
| X4 | `read_by[].by` non più obbligatorio (liste del cliente della sessione) | lettori che lo davano per presente | Gestire l'assenza |
| X5 | `health` pubblico anche con token e senza `pack_id` | mock (oggi richiede il token e restituisce `pack_id`); client che leggevano `pack_id` da `health` | Leggere `pack_id` da `GET /__tt/pack` |
| X6 | Effetti con istante uguale alla causa applicati **prima** della risposta (prima non specificato) | mock, test che si aspettavano lo stato precedente nella risposta | Applicare l'ordine di rules.md §6 |
| X7 | Guasti di rete: `refused`/`dns` ora RST immediato (prima chiusura normale), `tls` ora scrive un allarme TLS, `other` attende la latenza; WireMock: `other` → `EMPTY_RESPONSE` (prima `MALFORMED_RESPONSE_CHUNK`), `refused`/`dns` → `CONNECTION_RESET_BY_PEER` e `tls` → `RANDOM_DATA_THEN_CLOSE` (prima persi) | mock, exporter WireMock, test che contavano sul vecchio comportamento | Allineare a mock.md §4 |
| X8 | `tt mock` e `tt export` rifiutano i pacchetti con `not_after` scaduto | chi usa pacchetti vecchi (solo se `not_after` è impostato) | Ricostruire il pacchetto o non impostare `valid_days` |
| X11 | I pacchetti senza `not_after` più vecchi di 90 giorni (`--max-pack-age`), con `created_at` oltre 5 minuti nel futuro, con manifest non canonico o con chiavi sconosciute/maiuscole diverse sono rifiutati; il file `TT_GATE_PUBKEYS` scrivibile da gruppo/altri è rifiutato | fixture vecchie, costruttori di pacchetti non `tt-core` | Ricostruire con `not_after`, scrivere il manifest canonico, `chmod go-w` il file delle chiavi; nei test `--max-pack-age=-1s` |
| X9 | Il mock rifiuta mondi con riferimenti rotti (relazioni, `customer_id`, righe `pending`) | generatori che producono mondi incoerenti | Rispettare l'integrità di pack.md §5 |
| X10 | Operazioni con `x-tt-entity` senza `read_by`: nei pacchetti 1.2 vanno descritte con `read_by` (il comportamento 1.1 resta ammesso solo per pacchetti ≤ 1.1) | miner, inferenza dei contratti | Emettere `read_by` con `by.owner` o senza `by` |

### v1.1.1 (ottobre 2026)

Chiarimenti normativi delle 12 ambiguità rimaste aperte dopo la v1.1: vedi [sanitizer.md §17](sanitizer.md).

### v1.1.0 (ottobre 2026)

Revisione dopo la revisione indipendente delle specifiche (codici **B**, **M**, **S** e "gap" del revisore), le decisioni di progetto (**D-…**) e le ambiguità trovate scrivendo i vettori di conformità (**A-…**, vedi [`conformance/AMBIGUITIES.md`](../../conformance/AMBIGUITIES.md)). Ogni voce indica cosa risolve.

#### Custodia delle chiavi (keyguard)

| Cambiamento | Dove | Risolve |
|---|---|---|
| Nuovo processo `tt keyguard`: unico custode in zona B delle chiavi HMAC e delle chiavi di firma di policy e pacchetti; `tt-core` non ha chiavi | [keyguard.md](keyguard.md), `api/keyguard-api.v1.openapi.yaml`, THREAT_MODEL B2/M3/M7, ARCHITECTURE §1/§2/§9/§13 | D-B2, B2 |
| Prova al contrario come `match` sì/no, con limiti, filtro di Bloom dei token reali alimentato dall'intake, allarme a ogni positivo; domini, epoch e `kid` enumerati dalle policy del pacchetto, numeri in forma canonica | keyguard.md §2–§3.1 | D-B2, B2 |
| Firma delle policy in keyguard, che ricalcola la classificazione chiusura/apertura e verifica approvazioni distinte (ID token OIDC se configurato); rinnovo automatico di `not_after` | keyguard.md §3.2–§3.3, policy.md §5 | D-B2, S5, minor "signer isolation" |
| Firma dei pacchetti in keyguard, che ripete la prova al contrario su tutti i file | keyguard.md §3.4, pack.md §3 | D-B2 |

#### Sanitizer (`docs/spec/sanitizer.md`)

| Cambiamento | Sezione | Risolve |
|---|---|---|
| Espressioni regolari valutate sull'intera stringa, solo ASCII, nessuna modalità | §0.1 | B4, A-REGEX-ANCHOR |
| UTF-8 stretto RFC 3629 | §0.2, §9.2 | M4 |
| Classi di lunghezza ridotte a cinque: `l8` (0–8), `l32`, `l128`, `l1024`, `lmax` | §0.3, §6.2, event schema | D-S1, S1 |
| Ingressi nuovi: `trace_id`, `inherited`, `*_body_consumed`, `*_body_decoded`; `*_body_total` può valere `unknown`; `service_name` è quello assegnato all'iscrizione | §1 | A-TRACE-INPUT, B1, M8, S8, minor "service_name" |
| Ordine dei controlli: policy, poi chiave, poi campionamento; corpi di policy con domini riservati rifiutati anche dalla sorgente | §1, policy.md §4 | A-REFUSAL-ORDER, A-POLICY-BODY |
| Oggetto di uscita: contiene `sampled_by`, omette le mappe vuote, `resp` assente con `net_error` anche se c'erano header | §1, §2, §16 | A-OUTPUT-FIELDS, A-NET-ERROR |
| `url_base`: credenziali o path → `host:invalid`; schema e host in minuscolo; porta 1–65535, default tolta; niente IDNA; host `^[a-z0-9.-]{1,253}$` | §3.1 | M2, A-HOST-VALID, A-HOST-USERINFO |
| Confronto con `match.base` per origine normalizzata e per **segmenti** decodificati (`%2F` non è mai `/`) | §3.1 | M2, A-BASE-SEGMENTS, A-BASE-COMPARE |
| Host esterni non elencati → `host:unlisted`; in chiaro solo con `segments.hosts_allow` o durante la scoperta | §3.1 | D-S3, S3 |
| `req.path` è sempre il path completo; i template outbound sono relativi alla base | §3.2 | M2, A-BASE-REMAINDER (lettura opposta a quella dei vettori v1.0) |
| Metodo `OTHER` e path troncati non corrispondono mai a un template | §3.3 | A-PATH-TRUNC-TEMPLATE, "Other rule details" |
| `framework_route`: tabella di normalizzazione per 13 framework, prefissi di montaggio obbligatori, corrispondenza **strutturale** (nomi dei parametri ignorati, contano quelli della policy), letterali della policy in uscita, fallback al punto 2 | §3.3, §3.4 | M1, A-FRAMEWORK-MATCH, A-FRAMEWORK-FALLBACK, A-FRAMEWORK-LITERAL |
| `keep` su parametri di path solo per valori `^[A-Za-z0-9._~-]{1,64}$`; voci di `segments.allow` con la stessa grammatica | §4.2, policy schema | M3, A-PATH-TOKEN-CHARSET |
| Parole automatiche (`auto_words`) a tempo: scadenza obbligatoria entro 7 giorni | §4.3, policy.md §1.4 | S2, A-NAME-PII |
| ABNF di `tt-path` corretta | §5.0 | "Other rule details" |
| Gruppi di precedenza 1, 2a, 2b, 3, 4 | §5.0 | B7, A-ERRORS-GROUP |
| Spareggio senza il criterio "più passi in totale", che non decideva mai | §5.0 | A-SPECIFICITY-STEPS |
| `drop` esplicito su un contenitore ignorato se una regola di gruppo uguale o più forte raggiunge un discendente | §5.0 | B7, A-CONTAINER-GROUP (lettura opposta a quella dei vettori v1.0) |
| Regole per nome confrontate con il nome originale anche se collassato; valori di parti senza `=` sempre `drop`; nei form solo `$.nome` e `$.*` | §5.0, §8.3, §9.1 | M5, A-FORM, "Other rule details" |
| Limiti dei lessemi numerici (64 byte, \|esponente\| ≤ 9999) per `keep`, `hmac`, `bucket` | §5.3–§5.5, §10.2 | M7 |
| `bucket(num)`: confini convertiti in double come i valori, `-0 = 0` dichiarato, confini stampati dal lessema compilato | §5.5 | M7, A-BUCKET-DOUBLE |
| `bucket(time)`: anni 0001–9999, offset fino a 23:59, niente secondo 60 | §5.5 | minor "bucket(time)", A-TIME-OFFSET, A-TIME-YEAR |
| `trunc:size` senza classe; `size` sempre presente (salvo codifica non supportata), `l8` per il corpo vuoto, `lmax` per lunghezza ignota | §6.4, §9.0 | B1, minor "trunc:size", A-SIZE-EMPTY, A-SIZE-UNKNOWN, A-PREFIX |
| Chiave HMAC: più righe `kid:base64url`, `\r` e righe vuote ignorati, alfabeto stretto, chiave malformata = `key_missing`; `hmac.accept_kids` per la rotazione | §7.1, policy.md | gap "key handling", A-KEY-ERROR-CODE |
| Riferimento al vettore `conformance/vectors/0002-hmac-equal-values.json` | §7.3 | A-VECTOR-PATH |
| Normalizzazione degli header: niente pseudo-header, OWS tolti, valori con lo stesso nome uniti (`", "`, `cookie` con `"; "`, `set-cookie` separati) | §8.0 | B3 |
| Regola dei nomi estesa: collassano anche i nomi con sei o più cifre consecutive; vale per chiavi JSON, query, cookie e header | §8.0, §9.3 | A-NAME-PII, decisione di progetto "header names" |
| `cookie` nella risposta e `set-cookie` nella richiesta scartati | §8.1 | A-COOKIE-DIRECTION |
| Limite dei nomi: 64 nomi distinti **in uscita** per header, cookie e query, `{trunc}` come array `["trunc:keys:<classe>"]`; valori per nome limitati a `max_array` | §8.1–§8.3 | B6, A-HDR-LIMIT, A-QUERY-LIMIT, A-TRUNC-VALUE |
| `content-type` e `content-encoding` dal valore unito; OWS = spazio e tab | §8.1 | B3, A-CT-OWS |
| `set-cookie`: parti senza `=` ignorate, OWS tolti | §8.2 | A-SETCOOKIE-NOEQ, A-SETCOOKIE-TRIM |
| Query: parte senza `=` → nome `{*}`; ordine di comparsa anche sotto `{*}` | §8.3 | S2, A-COLLAPSE-ORDER, ambiguità "Query without =" |
| Codifica del corpo (`identity`, `gzip`, `deflate` a un livello, tetto di decompressione), corpi non consumati, streaming con conteggio fino alla fine | §9.0 | B1, M13 del threat model |
| JSON: BOM rifiutato, validazione completa anche oltre la profondità massima | §9.2 | M4, A-JSON-BOM, A-DEPTH-VALIDATE |
| Chiavi JSON: duplicati (vince l'ultima), selezione dei primi `max_keys` per posizione, collasso dopo la selezione; chiave con surrogato isolato → `{*}` | §9.3 | B6, M4, A-MAXKEYS-WHICH |
| Valori sotto `{*}` nei corpi JSON ordinati per la loro forma canonica; `{trunc}` nei corpi come stringa | §9.3 | minor "collapsed order", A-COLLAPSE-ORDER, A-TRUNC-VALUE |
| Limite di 512 KiB per evento, con riduzioni deterministiche | §10.3 | M6 |
| Soggetto: algoritmo esatto (header unito o primo cookie, prefisso `bearer`, JWS a tre parti, base64url con o senza padding, claim letterale di primo livello, numeri canonici) | §11 | M8, A-JWT-B64, A-SUBJECT-FIRST, A-SUBJECT-EMPTY |
| Campionamento con epoch; baggage solo con `trust_baggage` su servizi `internal`; lettura del baggage definita; outbound eredita (`sampled_by: inherited`); propagazione solo verso `propagate_to`, mai verso basi esterne; `tt-egress` toglie `tt.s` | §12 | D-M8, M8, A-BAGGAGE-FIRST |
| Policy vuota: rischio residuo dichiarato per forme e nomi | §13 | S1, S2 |
| Modalità scoperta: percorso dentro l'HMAC, scadenza massima 7 giorni, chiavi `disc` definite (`req.path.<i>` da 0 sul path completo, nomi in uscita come `{*}`), valori di booleani e `null`, niente voci per valori non validi, overflow oltre 4096 omesso, intake solo con HyperLogLog | §15, event.md §5.3 | S4, A-DISC-VALUE, A-DISC-INVALID, A-DISC-PATH-POS, A-DISC-NAMED |
| Formato normativo dei vettori = `conformance/format.md`; elenco dei campi da aggiungere per la 1.1 | §16 | B5, A-VECTOR-PATH |
| Errore interno del sanitizer: nessun evento, contatore `sanitizer_errors` | introduzione | gap "errors inside the sanitizer" |

#### Policy (`docs/spec/policy.md`, schemi `policy.v1`, `policy-compiled.v1`)

| Cambiamento | Risolve |
|---|---|
| `sampling` obbligatorio, con `trust_baggage` e `propagate_to`; conversione decimale esatta in punti base | D-M8, minor "sampling default" |
| `segments.auto_words_expires_at`, `segments.hosts_allow`, `match.internal`, `hmac.accept_kids` | S2, D-S3, D-M8, gap "key handling" |
| Grammatiche dei nomi allineate tra forma autore e compilata; parametri di path solo nelle operazioni | M9 |
| Nuove validazioni: duplicati tra scorciatoia `$` e `body`, `.*` con `keep`/`hmac`/`bucket` nelle regole globali, confini come double, scadenze di scoperta e parole automatiche ≤ 7 giorni | S4, S5, M7, minor "duplicates" |
| Corpo compilato con `issued_seq`, `not_after`, `targets.groups`; esempio "stessi byte" precisato | S6, minor "same bytes" |
| Firma su `"tt.policy.body/v1" \|\| 0x00 \|\| corpo`, fatta da keyguard; revoca delle chiavi di firma | S6, D-B2 |
| Accettazione in sorgente: firma, schema, gruppo, scadenza, `issued_seq` crescente e ≥ `min_issued_seq`; heartbeat prima della prima cattura; interruttore persistente | S6, S7 |
| Approvazioni: 1 solo per modifiche di sola chiusura (elenco chiuso), 2 persone diverse per tutto il resto, compresa la policy di onboarding | S5 |

#### Eventi (`docs/spec/event.md`, schema `event.v1`)

| Cambiamento | Risolve |
|---|---|
| `sampled_by: inherited`; `service` con `host:unlisted`; `size` facoltativo; nuova grammatica di `req.path`; classi nuove; mappe con soli array | D-M8, D-S3, D-S1, M3, A-TRUNC-VALUE |
| Nome di servizio inbound = nome assegnato all'iscrizione | S8, minor "service_name" |
| Richieste OTLP fino a 4 MiB, evento fino a 512 KiB | M6 |
| Intake: forma canonica obbligatoria, controllo certificato ↔ `source.id` e servizi ammessi, controllo di tipo di ogni valore contro la regola effettiva | minor "covert channel", S8, S9 |
| Quarantena definita: riscrittura dei valori salvati e futuri, allarme, chiusura con 1 approvazione, scioglimento con 2; vale per `keep`, nomi, segmenti e host | M1 del threat model, S2, S9 |

#### Regole, pacchetti, API

| Cambiamento | Dove | Risolve |
|---|---|---|
| Entità con `id_field`, `id_prefix`, `created_by.state` e `created_by.defaults`; `fieldValues` come percorsi puntati; effetti collegati nello stesso ramo | rules.md, `rules.v1` | gap "rules → mock/generator" |
| `world.sqlite` sostituito da `world.jsonl` canonico; tutti i JSON del pacchetto canonici; gzip con `mtime = 0` | pack.md §1, §5 | D-world, minor "world.sqlite" |
| `x-tt-value` per i valori sintetici; niente `format: tt-token`; enum filtrati per k; controllo `k-thresholds` precisato | pack.md §4, §7 | gap "contracts" |
| Firma del pacchetto su `"tt.pack/v1" \|\| 0x00 \|\| manifest`, fatta da keyguard; `TT_GATE_PUBKEYS` con più chiavi | pack.md §3 | D-B2, minor "TT_GATE_PUBKEY" |
| Fleet API ridotta agli endpoint delle sorgenti; token monouso o di gruppo; impronta della CA definita; nomi di servizio legati al gruppo; chiavi generate mai salvate; `min_issued_seq`, `policy_current`, `revoke_signing_keys` | `fleet-api.v1` | S6, S7, S8, gap "Fleet API" |
| Nuova API di amministrazione, tutta sotto `/api/v1/`, con tutte le funzioni della UI (fleet, policy con rifiuto e ripristino, contratti, drift, buchi, regole, archetipi, mondi, pacchetti, export, preset di scenari, quarantena, webhook, conservazione, audit, export di eventi) | `admin-api.v1` | D-admin, gap "Fleet API", M17 |
| Autenticazione allineata al server già implementato (`internal/server/README.md`): sessione lato server con cookie `__Host-tt_session` HttpOnly/Secure/SameSite=Strict e header `X-CSRF-Token` sui metodi non sicuri, niente bearer per le persone; endpoint `/api/v1/auth/{config,login,logout,me,oidc/start,oidc/callback}`, `/api/v1/setup`, `/api/v1/audit/{export,verify}`; ruoli piatti (`admin` gestisce solo utenti e configurazione, non è un superutente) | `admin-api.v1` | allineamento al core |
| Due listener: admin/UI (default 7070) e intake (default 4318, sempre TLS) che serve sia OTLP sia gli endpoint Fleet delle sorgenti; `enroll` senza certificato client, il resto con certificato verificato | `fleet-api.v1`, event.md §4.1 | allineamento al core |
| API di controllo del mock: token obbligatorio quando configurato, rifiuto di ascoltare fuori dal loopback senza token | `control-api.v1` | minor "control API security" |

### v1.0.0 (ottobre 2026)

Prima versione, fase 0.
