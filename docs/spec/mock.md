# Mock con stato v1

> Revisione 1.13 (operazioni SOAP e XML §10, spec v1.21) · Revisione 1.12 (documenti sintetici §2.9, date relative §2.10, valori calcolati, corpi d'errore §4.1, API compatibile S3 §8, pagine di terzi con richiamata §9, spec v1.20) · Revisione 1.11 (condizioni sulla richiesta e sul cliente, attributi del cliente per sessione, aggregati, filtri delle liste e paginazione delle liste statiche, precondizioni `respond.until`, `target_all`, identità da un header JSON: §2.6, §2.8, spec v1.18) · Revisione 1.10 (effetti sui record per chiave `target_key`, contatori per chiave `respond.limit`: §2.7, spec v1.17) · Revisione 1.9 (effetti su oggetti esistenti: valori copiati dalla richiesta, `${not:campo}`, guardie `where`; selettori GraphQL per campo e proprietario in liste annidate: §2.7, spec v1.16) · Revisione 1.8 (record per chiave, rimozione, selettori dal corpo, liste in modalità statica: §2.7, spec v1.15) · Revisione 1.7 (endpoint GraphQL, §7, spec v1.14) · API: [`api/control-api.v1.openapi.yaml`](../../api/control-api.v1.openapi.yaml) · Formati letti: [pack.md](pack.md), [rules.md](rules.md)

Questo documento fissa il comportamento di `tt mock` che non dipende dall'implementazione: verifica del pacchetto, costruzione delle risposte, errori, guasti di rete e API di controllo. La semantica di entità e regole è in [rules.md](rules.md) §2 e §6. Gli exporter ([ARCHITECTURE](../ARCHITECTURE.md) §12) riproducono questo comportamento dove lo strumento di destinazione lo permette e dichiarano il resto come perdita.

---

## 1. Caricamento del pacchetto

Prima di servire qualsiasi cosa, il mock verifica nell'ordine:

1. firma Ed25519 di `manifest.sig.json` con una chiave di `TT_GATE_PUBKEYS` non elencata in `TT_GATE_REVOKED_KIDS` ([pack.md](pack.md) §2.2, §3); prima di questo punto si leggono solo `manifest.json` e `manifest.sig.json`, con tetti di dimensione;
2. forma canonica e schema del manifest, `created_at` non nel futuro (oltre 5 minuti) e, se presente, `not_after` ([pack.md](pack.md) §2.1): orologio ≥ `not_after` → rifiuto `pack_expired`;
3. età: `--max-pack-age` (default 90 giorni per i pacchetti **senza** `not_after`; se impostato si applica a tutti, un valore negativo spegne il controllo);
4. SHA-256 e dimensione di ogni file, nessun file non elencato, nessun link simbolico;
5. contratti, regole (solo `approved`, controlli incrociati di [rules.md](rules.md)), `world.jsonl` (ordine delle righe e integrità, [pack.md](pack.md) §5), `faults.json`, `scenarios.json` ([pack.md](pack.md) §6.1), `gate-report.json` con esito `pass`;
6. che ogni operazione citata da regole, `read_by`, guasti e preset esista nei contratti.

Un errore a qualsiasi punto ferma l'avvio con un codice di uscita diverso da 0. Il mock non serve mai un pacchetto parzialmente verificato.

## 2. Costruzione delle risposte

Il corpo di una risposta di successo si costruisce dallo **schema del contratto** per quello status, così:

1. **Entità**: se l'operazione espone un'entità (`read_by`, oppure `created_by.op` per la risposta di creazione), ogni proprietà dello schema prende il valore dallo stato dell'entità con lo stesso nome. Le proprietà **facoltative** escono solo se sono nello stato. Le proprietà obbligatorie assenti dallo stato vengono, in quest'ordine, dall'esempio del contratto, da `x-tt-value`, da `enum`/`default`, dal tipo. I campi dello stato che il contratto non dichiara non escono.
2. **Campi di relazione** ([rules.md](rules.md) §2.2): non si inventano mai; se mancano dallo stato e sono obbligatori escono `null` se lo schema lo ammette, altrimenti si omettono.
3. **Campi derivati**, se lo stato non li contiene e lo schema li dichiara: `customerId` / `customer_id` = proprietario dell'entità ([rules.md](rules.md) §2.6; nell'involucro di una lista con `by.owner`, il proprietario selezionato); `createdAt` / `created_at` = istante virtuale di creazione; `updatedAt` / `updated_at` = istante virtuale dell'ultima modifica applicata. Gli istanti sono in UTC con precisione al secondo (`2026-10-19T00:05:00Z`).
4. **Senza entità**: l'esempio del contratto (`example` / `examples`) oppure la generazione dallo schema. `format: date-time` generato vale l'orologio virtuale; gli id con `x-tt-value.kind = id` sono sintetici (`<PREFISSO>-SYN-NNNN`, oppure nel formato degli id del dominio, [pack.md](pack.md) §4.3) e stabili per richiesta.
5. **Status di successo**: il 2xx con `x-tt-frequency` più alta (a parità il più basso).
6. **Liste**: [rules.md](rules.md) §2.3.
7. **Campi collegati** ([pack.md](pack.md) §4.2, 1.5): in ogni oggetto costruito i campi di una `x-tt-dependencies` formano una combinazione elencata. I valori dello stato dell'entità restano come sono; quelli generati (esempio, `x-tt-value`, `enum`) si scelgono tra le combinazioni compatibili con loro, in modo deterministico per richiesta; un campo facoltativo generato si omette se nessuna è compatibile.

### 2.5 Modalità statica (v1.5)

Un'operazione che nessuna entità del pacchetto crea o legge (pacchetto senza regole, o un servizio che le regole non toccano) risponde dal contratto (punto 4). Fino alla v1.4 ogni chiamata rispondeva la stessa cosa: un `POST` dava sempre lo stesso id e `GET .../{id}` rispondeva `200` per qualsiasi id, anche inventato. Dalla v1.5 la **sessione** ricorda quello che ha creato:

- **Creazione.** Un `POST` su una collezione (template che non finisce con un parametro, per esempio `POST /v1/shipments`) con una risposta 2xx che ha un campo id (`id`, altrimenti `<risorsa>Id` / `<risorsa>_id`, altrimenti l'unica proprietà con `x-tt-value.kind = id`; sempre una stringa) riceve a ogni chiamata un **id nuovo**: il prefisso del dominio dell'id quando il pacchetto lo conosce, altrimenti il prefisso che il miner darebbe all'entità della collezione (`shipments` → `SHP-SYN-`), e un contatore per sessione e collezione (`SHP-SYN-0001`, `SHP-SYN-0002`...). La risposta riporta i campi scalari del corpo della richiesta che lo schema della risposta dichiara con lo stesso nome e lo stesso tipo, senza `enum`, `const`, `format`, `pattern` o limiti (un valore fuori da quei vincoli romperebbe il contratto); il resto viene dall'esempio o dallo schema come prima.
- **Accesso a un elemento.** `GET`, `PUT`, `PATCH` o `DELETE` su un elemento della stessa collezione (`/v1/shipments/{id}`) rispondono con l'oggetto creato nella sessione (le proprietà che la risposta dichiara; `PUT`/`PATCH` aggiornano gli scalari come sopra, `DELETE` lo dimentica). Per un id che la sessione non ha creato il mock risponde lo **status di «non trovato» osservato** (`404`, con il suo esempio o schema) se il contratto lo dichiara e la collezione ha un'operazione di creazione; altrimenti `200` dal contratto, con l'id del path nel campo id.
- Una collezione **solo in lettura** (nessuna operazione di creazione: un catalogo che il servizio sotto test legge soltanto) risponde `200` per ogni id, come prima: il mock non può conoscerne gli id.
- Con un formato degli id per il dominio del campo id ([pack.md](pack.md) §4.3), l'id nuovo segue il formato (il contatore per sessione e collezione è il suo numero); i campi copiati vengono dal corpo della richiesta.
- Ogni risposta costruita così ha l'header **`X-TT-Static: true`**: il test sa che la risposta non viene da regole.
- Gli oggetti stanno nella sessione (al massimo 10 000), un'altra sessione non li vede, `reset` li dimentica. Il registro e il rapporto non cambiano.
- **Lista (v1.8).** Un `GET` sulla collezione (`GET /v1/shipments`) di una sessione che vi ha creato almeno un oggetto risponde con quegli oggetti, per id, nell'unica proprietà array dello schema della risposta (solo le proprietà che gli elementi dichiarano); `count` e `total`, se lo schema li dichiara, valgono il loro numero. Un oggetto dimenticato da un `DELETE` non c'è più, e un secondo `DELETE` dello stesso id risponde «non trovato» come sopra. Senza oggetti creati la risposta resta quella del contratto.

### 2.6 Sessione per utente (v1.6)

Un'applicazione vera non manda `X-TT-Session`: senza altro, tutti i tester finiscono nella sessione `default` e vedono lo stesso cliente sintetico. Con una **identità** configurata il mock sceglie la sessione dal chiamante:

- **Configurazione.** `--identity-header <nome>` (o `TT_MOCK_IDENTITY_HEADER`): qualsiasi header; con `--identity-claim <claim>` (`TT_MOCK_IDENTITY_CLAIM`) l'header porta un JWT (con o senza `Bearer `) e l'identità è quel claim (nomi puntati per claim annidati). Dalla v1.11 il claim (percorso puntato) vale anche per un header il cui valore è un **oggetto JSON**, in chiaro o codificato in base64/base64url (`x-user-context: {"user": {"id": "…"}}` con `--identity-claim user.id`); dati in coda dopo l'oggetto lo rifiutano. La firma del JWT **non** si verifica: il mock non autentica. Nessun nome di header o claim è previsto dal prodotto. In modalità console l'impostazione arriva dalla console (pagina Mock, «Sessione per utente») nella risposta al rapporto (§6.3) e sostituisce quella locale senza riavvio.
- **Sessione.** Una richiesta **senza** `X-TT-Session` con l'identità va nella sessione `u-` + le prime 16 cifre esadecimali di `HMAC-SHA256(chiave, "tt.mock.identity/v1" ‖ 0x00 ‖ identità)`. La sessione si crea al primo uso con il seed del pacchetto e un **cliente sintetico** scelto dallo stesso hash tra i clienti del mondo (ordinati per id), oppure quello della mappa esplicita. `X-TT-Session`, se presente, vince sempre; una richiesta senza identità (o con un JWT senza il claim) va nella `default`. Ogni risposta del piano dati ha l'header `X-TT-Session` con la sessione che l'ha servita. Oltre `--max-sessions` una identità nuova riceve `429 too_many_sessions`; le sessioni inattive escono come le altre (`--session-idle-ttl`).
- **Stabilità.** La chiave (`TT_MOCK_IDENTITY_KEY`, almeno 32 byte; in modalità console quella del gruppo, conservata dalla console) rende la scelta uguale tra un riavvio e l'altro con lo stesso pacchetto. Senza chiave il mock ne genera una a ogni avvio e lo scrive nel log.
- **Mappa esplicita.** `--identity-map <file>` (`TT_MOCK_IDENTITY_MAP`): oggetto JSON `{"<utente di test>": "CUS-SYN-0007"}`; una chiave `"h:<32 esadecimali>"` è già l'hash (così la console non conserva mai l'utente in chiaro). Un cliente che il pacchetto non ha si ignora (scelta dall'hash) con un avviso.
- **Riservatezza.** L'identità non si conserva, non finisce nel log, nel registro (l'header dell'identità non si registra nemmeno se è tra quelli registrati di solito), nel rapporto alla console né nella vista della sessione, che ha solo l'id `u-…` e `by_identity: true`.

Una regola approvata può cambiare lo status di una risposta successiva con un effetto `respond` ([rules.md](rules.md) §3.6): la decisione si prende prima della costruzione del corpo, come un guasto (§4), e il corpo è quello scritto nell'effetto, altrimenti l'esempio del contratto per quello status (§4.1).

La risposta della causa di una regola si costruisce **dopo** gli effetti immediati ([rules.md](rules.md) §6, punti 2–5).

### 2.7 Record per chiave, rimozione e selettori dal corpo (v1.8, regole 1.6)

- **Record per chiave** ([rules.md](rules.md) §2.9): una scrittura di `upserted_by` crea o aggiorna il record del cliente della sessione con la chiave della richiesta e la risposta si costruisce da lui; una lettura con `key` lo restituisce, oppure, se non c'è, risponde come il contratto.
- **Rimozione** ([rules.md](rules.md) §3.7): l'entità esce dalla sessione; liste e conteggi la tolgono, la lettura per id risponde `removed_status` o «non trovato».
- **Selettori dal corpo** ([rules.md](rules.md) §2.10): `by` e `key` con `from: req.body` si leggono dal corpo JSON della richiesta (per GraphQL dal corpo ricostruito, `$.variables…`); un valore non scalare o assente non seleziona nulla.
- **Entità preesistenti** ([rules.md](rules.md) §2.8): sono righe `entity` del mondo; non serve nulla di nuovo.
- **Effetti su oggetti esistenti** (v1.9, [rules.md](rules.md) §3.8): un `set` con una variabile legata alla richiesta scrive il valore che il test ha mandato (un id, un codice, un booleano, un numero); `"${not:campo}"` scrive l'opposto del booleano corrente del bersaglio (un campo che non è booleano resta com'è); un effetto con `where` si applica solo se, all'istante in cui scatta, i campi del bersaglio sono uguali a quei valori, altrimenti non compare in `applied` (un ordine annullato dal test non viene confermato dopo dal passo spontaneo).
- **GraphQL** (v1.9): una variabile seleziona anche per campo o per proprietario, e una lista può essere annidata (`$.data.orders.items[*]`, conteggio in `$.data.orders.count`).
- **Effetti sui record per chiave** (v1.10, [rules.md](rules.md) §3.8): un effetto con `target_key` cambia il record dell'entità per chiave del cliente della **causa** (se la chiave ha il proprietario) i cui campi della chiave valgono i valori di `target_key` (variabili della richiesta o letterali; `{}` è il record unico del cliente). Un `set` crea il record quando manca, come una scrittura di `upserted_by` (con `where` no: senza record la guardia non vale); un `remove` lo toglie. Una lettura con `key` vede subito il record così cambiato.
- **Contatori per chiave** (v1.10, [rules.md](rules.md) §3.9): un effetto `respond` con `limit` non registra una risposta: ogni volta che si applica **conta una chiamata** per la sua chiave (il valore di `limit.key` nella richiesta della causa, altrimenti il cliente della sessione all'istante della causa). Prima di servire una chiamata di `respond.service`/`op` il mock calcola la chiave di **quella** chiamata e conta le chiamate contate con la stessa chiave negli ultimi `limit.window` sull'orologio virtuale (tutta la sessione se manca); se sono almeno `limit.n` la chiamata risponde `respond.status` con l'esempio `respond.example` (altrimenti il primo di quello status), con probabilità `p`, senza creare nulla né far scattare regole il cui `when` non ha quello status. Precedenza: un guasto forzato dal test (modalità `custom`) vince, poi gli effetti `respond` già registrati, poi il contatore, poi i guasti osservati. Una seconda creazione con la stessa email risponde `409`; la quarta chiamata in un minuto `429`, e dopo il minuto si passa di nuovo. `reset` azzera i conteggi; ogni sessione ha i suoi.

### 2.8 Regole 1.9 (v1.11)

- **Condizioni** ([rules.md](rules.md) §3.12): `cause.when.match` si controlla dopo i legami; se non vale la regola non scatta e non si estrae nulla. Il ramo si estrae tra quelli ammessi da `outcomes[].when` (l'estrazione si consuma sempre); senza rami ammessi la regola scatta con un ramo vuoto (`triggered` con esito `""`, nessun effetto in coda). Le regole senza `when` estraggono come prima.
- **Attributi del cliente** ([rules.md](rules.md) §2.11): il valore della sessione è `profile[name]` del cliente della sessione, altrimenti un'estrazione dalle quote con un generatore proprio della sessione e dell'attributo, fatta una volta e uguale dopo il `reset`. Si scrive nei membri `fields` delle risposte `2xx`, convertito al tipo dello schema; non si scrive se l'entità da cui si costruisce il corpo ha già quel membro, né se l'oggetto che lo contiene manca; senza schema solo se il membro c'è già.
- **Aggregati** ([rules.md](rules.md) §2.12): sui corpi `2xx`, dove l'oggetto che li contiene esiste. `count`/`sum` sulle entità non rimosse della sessione del cliente della sessione (tutte se non ce n'è uno) con `where`; `delta` = numero già nel corpo (0 se non è un numero) + `by` × chiamate riuscite dell'operazione nella sessione, compresa quella in corso.
- **Ordine nel corpo**: paginazione delle liste statiche, attributi, aggregati; alla prima stesura e a ogni ricostruzione dopo gli effetti immediati.
- **Filtri delle liste** ([rules.md](rules.md) §2.3): dopo visibilità e `scope`, prima dell'ordinamento; confronto nella forma canonica; un parametro assente non filtra.
- **Liste statiche** ([rules.md](rules.md) §2.13): solo se nessuna `read_by` legge l'operazione. Una pagina oltre la fine, o un cursore non creato dal mock, è una pagina vuota (`count` 0, `total` = elementi dell'esempio); `limit` tronca; gli altri parametri non validi lasciano il corpo com'è. Così un client che pagina fino a una pagina vuota si ferma anche quando l'esempio del contratto ha una pagina piena.
- **Precondizioni** ([rules.md](rules.md) §3.13): attive dall'inizio della sessione e dopo il `reset`; vale la prima non ancora tolta in ordine di regola; si tolgono quando l'effetto si applica (nel registro `respond: "<service> <op>"`). Precedenza: guasto forzato (`custom`) > risposte registrate > precondizioni > contatori > guasti osservati.
- **`target_all`** ([rules.md](rules.md) §3.14): tutte le entità del tipo del cliente della causa (senza proprietario: quelle senza proprietario) con `where`; `set` accetta `${variabile}` e `${not:campo}`, oppure `remove`; ogni entità cambiata compare in `applied`.
- **API di controllo.** La vista della sessione non mostra ancora le precondizioni tolte né i valori degli attributi della sessione.

### 2.9 Documenti sintetici (v1.12)

Un'applicazione vera scarica PDF, immagini e archivi, o li riceve in base64 dentro il JSON, e spesso li apre: un documento finto (la stringa `synthetic`) la rompe. Il mock genera un **file valido** del tipo dichiarato, senza dipendenze esterne:

- **Quando.** (1) Una risposta il cui contratto non ha un corpo JSON ma un tipo di documento: `application/pdf`, `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `application/zip`, i tipi Office Open XML (`…wordprocessingml.document`, `…spreadsheetml.sheet`, `…presentationml.presentation`), `application/msword`, oppure qualsiasi tipo il cui schema abbia `x-tt-value.doc_type`. (2) Un campo stringa di un corpo JSON marcato come documento: `x-tt-value` con `format: "doc"` e `doc_type` (dalla forma `drop:doc:<tipo>:<classe>` del [sanitizer](sanitizer.md) §20.4, [pack.md](pack.md) §4.1), oppure le parole chiave di JSON Schema `contentEncoding: "base64"` con un `contentMediaType` di documento. Il campo esce in base64 standard; un esempio del contratto non sostituisce mai un documento (l'esempio ha un segnaposto).
- **Contenuto.** Solo testo **sintetico** di un modello fisso del prodotto: «Synthetic document - traffic-twin», il nome del cliente sintetico della sessione (profilo del mondo), i riferimenti (id del cliente, parametri del path della richiesta, cioè gli id che il test ha chiesto) e la data dell'orologio virtuale; solo ASCII. PDF 1.4 di una pagina con il testo in Helvetica e tabella dei riferimenti corretta; PNG, JPEG, GIF con un'immagine segnaposto e il testo in un commento; WebP 1×1; ZIP con un file di testo; DOCX e XLSX con il testo nei paragrafi o nelle celle. Limiti noti: PPTX è riconoscibile (contiene `ppt/presentation.xml`) ma PowerPoint non lo apre; `ole` (vecchi formati Office) ha solo l'intestazione del formato; WebP non raggiunge la classe di dimensione.
- **Dimensione.** Con una classe (`x-tt-value.doc_class`, `l1k` … `lmax`) il documento cade nella classe: poco sopra il suo limite inferiore, al più 2 MiB (una classe `l8m`/`lmax` dà 2 MiB al massimo). DOCX e XLSX non scendono sotto circa 1 KiB.
- **Header.** `Content-Type` è il tipo dichiarato dal contratto, `Content-Length` la lunghezza del file, `Content-Disposition` `attachment` (o il tipo dichiarato dall'esempio dell'header nel contratto) con `filename="document-AAAAMMGG.<estensione del tipo>"`.
- **Registro.** Il corpo di una risposta documento è descritto (`synthetic pdf document, 1234 bytes`), mai copiato.
- **Gate.** Se un contratto dichiara un documento, il controllo `pii-detectors` ([pack.md](pack.md) §7) genera il testo dei documenti per i primi 50 clienti del mondo e verifica che ogni valore inserito sia sintetico e che i rilevatori di dati personali non trovino nulla (`file: "documents"`, `pointer: "/<riga del mondo>"`, mai il valore).

### 2.10 Date relative (v1.12)

Una data che nel traffico vero è «tra 30 e 365 giorni» (un rinnovo, una scadenza, una finestra di recesso di 15 giorni) generata come data fissa diventa presto passata e cambia il comportamento dell'applicazione. Un campo con `x-tt-value.date_offset` ([pack.md](pack.md) §4.4) si genera come **orologio virtuale della sessione + uno scarto** nell'intervallo `[min, max]` (giorni interi se gli estremi sono in giorni, altrimenti ore), scelto in modo deterministico per richiesta e campo; esce come data (`2026-11-27`) se lo schema ha `format: date` (o `x-tt-value.format: date`), altrimenti come istante RFC 3339. Avanzando l'orologio le date si spostano con lui. I valori dello stato di un'entità restano quelli dello stato (nel mondo sono stati generati rispetto all'istante della loro creazione, §6.1 di [rules.md](rules.md)).

## 3. Errori generati dal mock

Quando il contratto non offre una risposta adatta, il mock usa l'involucro:

```json
{ "code": "invalid-request", "message": "body: /items/0/qty must be >= 1", "pointer": "/body/items/0/qty" }
```

| Situazione (piano dati) | Status | `code` = `reason` nel registro |
|---|---|---|
| `X-TT-Session` malformato | 400 | `bad_session_id` (non registrata) |
| Sessione sconosciuta | 404 | `session_not_found` (non registrata; mai ricaduta sulla `default`) |
| Corpo oltre `--max-body` | 413 | `payload_too_large` |
| Nessun servizio per `Host` o `/__svc/` | 404 | `no-service` |
| Nessuna operazione per metodo e path | 404, oppure 405 con `Allow` se il path esiste con altri metodi | `no-operation` |
| Richiesta non valida e il contratto non dichiara `400` né `422` | 400 | `invalid-request` |
| Lettura singola senza risultato, o risposta `foreign`, senza lo status nel contratto | 404 / 403 | `not_found` / `forbidden` |
| Status scelto (guasto) senza esempio né schema nel contratto | quello scelto | `http_<status>` |

Una richiesta non valida per cui il contratto dichiara `400` o `422` riceve quella risposta (il primo esempio); il registro conserva comunque `reason: invalid-request` e il `pointer`.

**`pointer`** (obbligatorio per `invalid-request`, nell'involucro e nel registro): JSON Pointer (RFC 6901) in un documento virtuale con quattro rami, `/path/<nome>`, `/query/<nome>`, `/headers/<nome in minuscolo>`, `/cookies/<nome>`, e `/body` seguito dal puntatore dentro il corpo (`/body/items/0/qty`). Per una proprietà obbligatoria mancante indica dove dovrebbe stare (`/body/email`); per un corpo che non è JSON valido vale `/body`. Il puntatore contiene solo nomi, mai valori. Se ci sono più violazioni si riporta la prima nell'ordine: path, query, header, cookie, corpo (nel corpo, in ordine di documento).

## 4. Guasti di rete nei mock HTTP

Un mock HTTP ha già accettato la connessione e letto la richiesta quando decide il guasto: alcuni errori delle sorgenti (connessione rifiutata, DNS, TLS) si possono solo **approssimare**. Le approssimazioni sono queste, per tutte le implementazioni:

| `net_error` | Cosa fa `tt mock` | Latenza iniettata | Cosa vede il client | WireMock (`tt export`) |
|---|---|---|---|---|
| `timeout` | Nessuna risposta; tiene aperta la connessione per `--net-timeout` (default 30 s), poi la chiude | No (l'attesa la sostituisce) | Timeout di lettura | `fixedDelayMilliseconds: 30000` + `EMPTY_RESPONSE` |
| `reset` | Chiude con RST (`SO_LINGER` 0) senza byte di risposta | Sì, prima della chiusura | Connessione azzerata | `CONNECTION_RESET_BY_PEER` |
| `refused` | Come `reset`, ma subito | No | Connessione azzerata (al posto di "connessione rifiutata") | `CONNECTION_RESET_BY_PEER` |
| `dns` | Come `refused` | No | Connessione azzerata (al posto di "host sconosciuto") | `CONNECTION_RESET_BY_PEER` |
| `tls` | Scrive un record TLS di allarme fatale `handshake_failure` (7 byte: `15 03 03 00 02 02 28`) e chiude | No | Risposta non HTTP, errore di protocollo | `RANDOM_DATA_THEN_CLOSE` |
| `other` | Chiude normalmente (FIN) senza byte di risposta | Sì, prima della chiusura | Risposta vuota / EOF inatteso | `EMPTY_RESPONSE` |

Su HTTP/2 tutti i tipi tranne `timeout` diventano `RST_STREAM` con `INTERNAL_ERROR` sullo stream della richiesta. Il registro riporta `status: null` e `fault: { "net_error": "<tipo>" }`. Microcks e Prism non hanno guasti di rete: la perdita si dichiara nell'`export-report.json`.


### 4.1 Corpi d'errore (v1.12)

Le applicazioni leggono il codice o il testo degli errori («ordine non trovato», `E-LOCKED`). Il corpo di una risposta d'errore decisa da un guasto o da un effetto `respond` è, nell'ordine:

1. il corpo **scritto da una persona**: `body` della regola di guasto (`FaultRule` dell'API di controllo, regole di un preset in `scenarios.json`) o dell'effetto `respond` ([rules.md](rules.md) §3.6); un oggetto, un array o una stringa JSON di al più 16 KiB, servito così com'è;
2. l'esempio del contratto nominato da `example` (regola di guasto, `faults.json`, effetto `respond`);
3. il primo esempio del contratto per quello status, poi lo schema, poi l'involucro di §3.

`example` e `body` valgono solo con uno `status`; un `example` di una regola di guasto deve esistere nel contratto per quello status (altrimenti `400 bad_request` con `pointer` `/rules/<i>/example`). Il gate passa i rilevatori di dati personali su ogni corpo scritto a mano (`pii-detectors`); la provenienza non lo richiede generato.

## 5. API di controllo

### 5.1 Autenticazione e `health`

- Con `TT_CONTROL_TOKEN` impostato, ogni chiamata sotto `/__tt/` richiede `Authorization: Bearer <token>`, **tranne** `GET /__tt/health`. Senza token il mock rifiuta di partire se ascolta fuori dal loopback; sul loopback accetta chiamate senza token.
- `GET /__tt/health` è sempre pubblico, così lo possono chiamare le sonde di vita (Kubernetes) senza segreti. Risponde `200 {"status":"ok"}` con `Cache-Control: no-store` e **nient'altro**: né `pack_id`, né versione, né sessioni. Rivela solo che il mock è avviato, cosa che la porta aperta dice già. Il pacchetto caricato si legge da `GET /__tt/pack`, protetto.
- Il token si confronta in tempo costante; una richiesta senza token valido riceve `401 unauthorized` con `WWW-Authenticate: Bearer`.

### 5.2 Corpi delle richieste

Corpi JSON stretti: un campo sconosciuto, un tipo sbagliato o un valore fuori schema danno `400 bad_request` (si preferisce un errore a un refuso ignorato). Il `pointer`, quando il campo è individuabile, è un JSON Pointer **nel corpo della chiamata di controllo** (`/faults/rules/0/p`, `/sedd` per un campo sconosciuto). JSON non valido o dati dopo il documento: `400 bad_request` senza `pointer`.

### 5.3 Codici di stato

| Situazione | Status | `code` |
|---|---|---|
| Token mancante o errato | 401 | `unauthorized` |
| Percorso di controllo sconosciuto | 404 | `not_found` |
| Metodo non ammesso (con `Allow`) | 405 | `method_not_allowed` |
| Corpo troppo grande | 413 | `payload_too_large` |
| Corpo non valido (§5.2), parametro di query non valido | 400 | `bad_request` |
| Id di sessione malformato | 400 | `bad_session_id` |
| Sessione sconosciuta | 404 | `session_not_found` |
| `POST /sessions` con un `id` già usato | 409 | `session_exists` |
| Cliente o archetipo sconosciuto (sessione, cliente, preset) | 404 | `customer_not_found` |
| Oltre `--max-sessions` | 429 | `too_many_sessions` |
| `DELETE /sessions/default` (la `default` si azzera con `reset`) | 400 | `bad_request` |
| `clock/advance` con `to` nel passato | 400 | `clock_backwards` |
| `clock/advance` oltre `--max-advance` | 400 | `advance_too_large` |
| `clock/advance` con troppi passi in una chiamata (l'orologio si ferma all'ultimo passo applicato, indicato nel messaggio) | 400 | `too_many_steps` |
| Regola sconosciuta o non causale | 404 | `rule_not_found` |
| Esito sconosciuto per la regola | 404 | `outcome_not_found` |
| Preset sconosciuto | 404 | `preset_not_found` |
| Pagina di terzi sconosciuta (§9) | 404 | `page_not_found` |
| Visita sconosciuta di una pagina (§9) | 404 | `visit_not_found` |
| Visita già completata (§9) | 409 | `visit_completed` |

### 5.4 Preset di scenario

- `POST /__tt/sessions` con `scenario: <id>`: il preset dà i valori di `seed`, cliente (`customer` o `archetype`) e `faults` che la richiesta non specifica (i campi della richiesta vincono) e mette in coda i suoi esiti forzati. La configurazione risultante è la **base** che `reset` ripristina.
- `POST /__tt/sessions/{s}/scenario` con `{ "preset": "<id>" }`: azzera la sessione come `reset` e poi applica il preset: `seed` (se presente, altrimenti resta), cliente (se presente, altrimenti resta), `faults` (se presenti, altrimenti quelli di creazione), esiti forzati (sostituiscono quelli in coda). Il risultato diventa la nuova base di `reset`.
- `POST /__tt/sessions/{s}/scenario` con `{ "rule", "outcome", "times" }`: aggiunge esiti forzati in coda, come nella 1.1, senza azzerare nulla.

### 5.5 `reset`

Ripristina la base della sessione: mondo a `t0` (comprese le righe `pending` rimesse in coda), orologio a `t0`, generatori dallo stesso seed, guasti ed esiti forzati della base; svuota il registro; conserva id della sessione, seed e cliente della base.

## 6. Modalità console (v1.4)

`tt mock --console <url> --group <gruppo>` (o `TT_MOCK_CONSOLE`, `TT_MOCK_GROUP`, `TT_MOCK_TOKEN`, `TT_MOCK_PUBLIC_URL`, `TT_MOCK_CONSOLE_CA`) prende i pacchetti dalla console invece che da un file. La modalità file (`tt mock pacchetto.ttpack`) resta invariata. Le API sono in [`admin-api.v1.openapi.yaml`](../../api/admin-api.v1.openapi.yaml) 1.12.0 (`/api/v1/mock-agent/*`, sicurezza `mockToken`).

### 6.1 Token del mock

- Il token (`ttm_<24 esadecimali>.<43 base64url>`) lo crea la console (pagina Mock) per **un** gruppo; la console conserva solo lo SHA-256 del segreto, il token scade (default 180 giorni, al massimo 365) e si revoca. Creazione e revoca sono nell'audit (`mock.token_create`, `mock.token_revoke`).
- Il token vale **solo** per `GET /api/v1/mock-agent/pack` e `POST /api/v1/mock-agent/report`: non è una sessione della console e ogni altra rotta risponde `401`.
- Il token non va nella riga di comando: `TT_MOCK_TOKEN` (il flag `--token` esiste ma finisce nell'elenco dei processi).
- Il mock non segue mai i redirect della console (il token finirebbe su un'altra origine o in chiaro su `http`): un redirect è un errore. Il certificato della console si verifica sempre (radici di sistema più `TT_MOCK_CONSOLE_CA`).
- La console limita i token rifiutati per client e `token_id` (20, poi 20 al minuto: `429 rate_limited` con `Retry-After`, senza controllare il segreto) e le istanze per token (50, `429 too_many_mocks`).

### 6.2 Pacchetti

1. Il mock scarica l'ultimo pacchetto **pubblicato** del gruppo del token (`X-TT-Pack-Id`, `ETag`) e lo verifica **esattamente** come un file (§1), con le chiavi di `TT_GATE_PUBKEYS`: la console non è fidata per firmare. Il download è nell'audit (`pack.download`, attore `tt-mock/<token_id>`).
2. Il mock DEVE rifiutare un pacchetto il cui `manifest.group` ([pack.md](pack.md) §2) è assente o diverso da `--group`, e un pacchetto il cui `pack_id` non è quello annunciato in `X-TT-Pack-Id` (un download senza l'header si rifiuta). Un pacchetto rifiutato non sostituisce quello in uso; l'errore va nel rapporto (`pack_error`) e lo stesso pacchetto non si riscarica finché non ne arriva un altro.
3. Un pacchetto nuovo si carica e si verifica a parte, poi sostituisce il precedente **senza riavvio**: le sessioni ripartono dal pacchetto nuovo. Prima del primo pacchetto il mock risponde solo a `GET /__tt/health`; il resto è `503 no_pack`.

### 6.3 Rapporto e comandi

- Il mock invia `POST /api/v1/mock-agent/report`: istanza, versione, gruppo, stato (`waiting`, `serving`), pacchetto in uso ed eventuale `pack_error`, URL pubblico, per ogni servizio l'URL di base (`<public-url>/__svc/<servizio o alias>`), le sessioni (id, scenario, orologio, chiamate, modalità dei guasti) e il **riassunto** delle chiamate dall'ultimo rapporto: metodo, percorso **senza query** (al più 256 caratteri), status, sessione, scenario, guasto, latenza. Mai header, corpi, query string: il registro completo resta nel mock (§5, `journal`).
- La console tiene la risposta (attesa lunga, al più `mock.report_interval`, default 3 s) finché non arriva un comando, un pacchetto nuovo, una revoca o un cambio della «Sessione per utente», poi risponde con l'ultimo `pack_id` pubblicato, al più 10 comandi e, se il gruppo ce l'ha, l'impostazione `identity` (§2.6: header, claim, chiave del gruppo in base64url, mappa con i soli hash) e le pagine di terzi `pages` (§9, v1.8: con le chiavi HMAC, che sostituiscono il file `--pages`). Il mock riparte subito con un altro rapporto.
- Un **comando** è una chiamata dell'API di controllo (§5) che il mock esegue su sé stesso, con il proprio token di controllo, e il cui risultato (status e corpo, al più 64 KiB) torna nel rapporto successivo. Sono ammessi solo `GET`, `POST`, `PUT`, `DELETE` su `/__tt/pack`, `/__tt/scenarios`, `/__tt/customers`, `/__tt/pages`, `/__tt/sessions`, `/__tt/sessions/{id}` e `…/reset`, `customer`, `clock`, `clock/advance`, `faults`, `scenario`, `entities`, `pages/{pagina}/complete`, `pages/{pagina}/auto` (v1.8); **mai il registro** (corpi delle chiamate dei test). Il controllo è sia nella console sia nel mock.
- La console pulisce il rapporto prima di mostrarlo: testi limitati in lunghezza e senza caratteri di controllo o bidirezionali, URL solo `http(s)` assoluti senza credenziali, query o frammento (altrimenti vuoti), percorsi delle chiamate senza query, risultati dei comandi oltre 64 KiB sostituiti da `too_large`. Un rapporto di un'istanza il cui token è stato revocato è sempre `401`.
- Un rapporto per un gruppo diverso da quello del token: `403 wrong_group`. Un token sconosciuto, scaduto o revocato: `401`, e il mock **si ferma** con un errore (codice di uscita 1).
- Senza `TT_CONTROL_TOKEN` il mock in modalità console ne genera uno casuale: l'API di controllo la comanda solo la console. Con `TT_CONTROL_TOKEN` i test la usano anche direttamente (§5.1).

### 6.4 Mock gestiti dalla console

Con `mock.kubernetes.enabled` tt-core crea in un namespace (Role limitato a `secrets`, `services`, `apps/deployments`, `route.openshift.io/routes` di quel namespace) per ogni gruppo un `Secret` (token del mock, token di controllo, CA della console), un `Service`, una `Route` se il cluster ha le route di OpenShift e un `Deployment` che esegue `tt mock --console`, con server-side apply e senza montare token nel pod del mock. «Riavvia» emette un token nuovo e revoca il precedente; «Ferma» cancella gli oggetti e revoca il token (`mock.start`, `mock.restart`, `mock.stop` nell'audit).

## 7. Endpoint GraphQL (v1.14)

Un servizio del pacchetto con operazioni `x-tt-graphql` ([pack.md](pack.md) §4) ha uno o più **endpoint GraphQL** (il path prima di `#`, per esempio `/graphql`). Il mock risponde a `POST` e `GET` su quel path, con qualsiasi applicazione: nessun nome o path è fissato. Le altre richieste del servizio seguono §2 come sempre.

### 7.1 Scelta dell'operazione

1. **Lettura della richiesta** (GraphQL over HTTP): un corpo JSON `{query, variables, operationName}` (un array, cioè un lotto, non è supportato), un corpo `application/graphql`, oppure i parametri `query`, `variables` (JSON) e `operationName` di un `GET`. Un corpo non leggibile, una richiesta senza `query`, un documento che non è un documento eseguibile o un `operationName` che non c'è: `400` con `{"data": null, "errors": [{"message", "extensions": {"code"}}]}` (`BAD_REQUEST`, `GRAPHQL_PARSE_FAILED`), registrata come `invalid-request`.
2. **Operazione eseguita**: quella di `operationName`, oppure l'unica del documento.
3. **Introspezione**: se l'operazione seleziona alla radice solo `__schema`, `__type` e `__typename`, il mock la esegue sullo schema dell'endpoint (§7.2) e risponde `200` con `{"data": …}`; niente guasti né regole.
4. **Operazione logica**: `METODO /path#Nome` con il nome dell'operazione, oppure, se è anonima, `~` e l'hash della forma del documento calcolata come la sorgente ([sanitizer](sanitizer.md) §5.7.1, [event.md](event.md) §6). Se manca con il metodo della richiesta si prova l'altro (`GET`/`POST`): una query osservata in `POST` risponde anche in `GET`.
5. **Operazione mai osservata**: `200` con `{"data": null, "errors": [{"message": "operation not observed: QUERY Other", "extensions": {"code": "OPERATION_NOT_OBSERVED"}}]}`, `X-TT-Unmatched: no-operation`, registrata come non corrispondente.

Da qui la chiamata segue il percorso di ogni operazione (§2, [rules.md](rules.md) §6): sessione (anche per identità, §2.6), validazione, guasti, entità, regole, formati degli id. La richiesta si presenta a validazione, regole e letture nella forma JSON `{query, variables, operationName}`, qualunque sia il trasporto; `operationName` vale il nome dell'operazione eseguita (i campi del protocollo non sono affari del contratto). Le **letture** possono selezionare l'entità con una variabile, `by: {from: req.body, path: "$.variables.<nome>"}` ([rules.md](rules.md) §2.3). Il generatore dei valori sintetici parte dall'operazione logica e dalle variabili: due letture con due id diverse danno risposte diverse.

### 7.2 Introspezione

Lo schema dell'endpoint è il risultato catturato (`x-tt-graphql-schemas`): solo nomi e tipi. Se il pacchetto non ne ha, il mock ne **ricostruisce** uno dalle operazioni osservate: tipi `Query`, `Mutation`, `Subscription` con i campi radice dei documenti; argomenti con il tipo della variabile che li alimenta (o il tipo del placeholder: `?i` → `Int`, `?f` → `Float`, `?b` → `Boolean`, altrimenti `String`); tipi di ritorno dagli schemi delle risposte osservate (oggetti con il nome del campo al singolare, liste, `ID` per i campi con `x-tt-value.kind = id`); tipi di input dalle variabili osservate; scalari predefiniti e le direttive `include`, `skip`, `deprecated`.

L'esecuzione segue la selezione della richiesta (alias, frammenti, `__typename`; `__type(name:)` con un letterale o una variabile). Un campo che lo schema catturato non ha vale `false` per `isDeprecated`, `isRepeatable`, `isOneOf`, `[]` per `args`, `locations` e per le `interfaces` di un oggetto, altrimenti `null`; un riferimento di tipo che si ferma al nome si completa con il tipo dello schema.

### 7.3 Risposta

- **Dati**: `data` segue la selezione della richiesta: solo le chiavi chieste (alias compresi; se l'alias non è quello osservato si usa il nome del campo), `null` per un campo che il contratto non conosce, `__typename` dal tipo dello schema (o dal nome del campo, in PascalCase al singolare).
- **Guasti** (§4, `faults.json`, preset, API di controllo): un guasto di rete resta un guasto di rete. Uno status d'errore che il contratto dell'operazione ha osservato con un corpo `errors` si serve così com'è; altrimenti il corpo è `{"data": null, "errors": [{"message": "<testo dello status>", "extensions": {"code": "HTTP_<TESTO>", "status": n}}]}`, con lo status del guasto, oppure `200` se l'endpoint è stato osservato rispondere errori GraphQL con `200`.
- Il registro delle chiamate ha l'operazione logica in `op`.

## 8. API compatibile S3 (v1.12)

Molte applicazioni caricano documenti su un archivio di oggetti compatibile S3. Con `--s3` (o `--s3-host`, `--s3-buckets`; `TT_MOCK_S3=true`, `TT_MOCK_S3_HOSTS`, `TT_MOCK_S3_BUCKETS`) il mock serve un sottoinsieme minimo dell'API S3, uguale per ogni applicazione:

- **Indirizzi.** Stile path sul prefisso `/__s3/<bucket>/<chiave>` dell'indirizzo del mock (l'endpoint dell'SDK è `http://<mock>/__s3` con «path style»), stile path su un host di `--s3-host` (`http://s3.mock.test/<bucket>/<chiave>`) e stile virtual host (`http://<bucket>.s3.mock.test/<chiave>`). Il nome dell'host vince sul routing dei servizi per `Host`.
- **Operazioni.** `ListBuckets` (`GET /`), `CreateBucket`, `HeadBucket`, `DeleteBucket` (vuoto), `GetBucketLocation`, `ListObjectsV2` (`list-type=2`: `prefix`, `delimiter`, `max-keys` fino a 1000, `continuation-token`, `start-after`) e `ListObjects` v1 (`marker`), `PutObject` (con `Content-Type` e `x-amz-meta-*`), `CopyObject` (`x-amz-copy-source`), `GetObject` (con un `Range` singolo), `HeadObject`, `DeleteObject`, `DeleteObjects` (`POST ?delete`), multipart (`CreateMultipartUpload`, `UploadPart`, `ListParts`, `CompleteMultipartUpload` con ETag `md5(md5 delle parti)-N`, `AbortMultipartUpload`). Le altre rispondono `501 NotImplemented`. Errori nel formato XML di S3 (`NoSuchKey`, `NoSuchBucket`, `EntityTooLarge`, …) con `x-amz-request-id`.
- **Firma.** Qualsiasi firma SigV4 (header `Authorization` o URL prefirmato) è **accettata senza controllo**: il mock non autentica, è uno strumento di test. Il corpo `aws-chunked` degli SDK (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, con i trailer dei checksum) si decodifica e si confronta con `x-amz-decoded-content-length`; le firme dei blocchi e i checksum non si verificano.
- **Bucket.** Con `--s3-buckets` esistono in ogni sessione solo quei bucket (`CreateBucket` di un altro: `403 AccessDenied`); senza, un bucket nasce alla prima scrittura.
- **Sessione e limiti.** Gli oggetti stanno in memoria nella sessione scelta come il piano dati (`X-TT-Session`, identità §2.6, `default`); un'altra sessione non li vede e `reset` li dimentica. `--s3-max-object` (default 16 MiB) limita un oggetto, `--s3-max-bytes` (default 256 MiB) gli oggetti di una sessione (`403 QuotaExceeded`).
- **Registro.** Ogni chiamata è nel registro con `service: "s3"`, `op` = nome dell'operazione S3; i dati degli oggetti non si registrano (`object data, N bytes`). Gli header di credenziali non si registrano mai (§5).

## 9. Pagine di terzi (v1.12)

Alcuni flussi passano dal browser per una terza parte: l'applicazione manda l'utente alla pagina di un gateway di pagamento o di firma, la terza parte richiama l'applicazione (server a server) e riporta il browser all'applicazione. Il mock simula la terza parte con **pagine configurabili**, uguali per ogni applicazione: nessun nome, URL o formato è previsto dal prodotto.

### 9.1 Configurazione

Un file JSON (`--pages`, `TT_MOCK_PAGES`) o, in modalità console, la pagina Mock della console («Pagine di terzi», per gruppo, admin-api `GET|PUT /api/v1/mocks/pages`), che arriva nella risposta al rapporto (§6.3) e sostituisce il file; a caldo anche `PUT /__tt/pages`. Forma: `{"pages": [Page]}`, al più 32 pagine.

| Campo | Significato |
|---|---|
| `id`, `title`, `description` | Nome (`^[a-z0-9][a-z0-9-]{0,62}$`), titolo e testo della pagina |
| `ref` | Modello del **riferimento** della visita (id del pagamento o della firma); default il parametro `ref` della query, altrimenti `REF-SYN-NNNN` per sessione |
| `show` | Parametri della query mostrati sulla pagina (importo, ordine) |
| `return_url`, `return_hosts` | Modello dell'URL a cui torna il browser. Se l'host viene da un segnaposto (`{query.returnUrl}`), `return_hosts` elenca gli host ammessi (altrimenti la configurazione è rifiutata: niente redirect aperti). Vuoto: la pagina mostra l'esito e resta |
| `buttons[]` | Da 1 a 6: `action` (nome), `label`, `values` (segnaposti `{value.<nome>}` della scelta, per esempio `code: AUTHORISED`), `no_callback` (un «annulla» senza richiamata), `set` (campi dell'**oggetto collegato** scritti con quella scelta: percorsi puntati, al più 32, valori scalari; le stringhe accettano i segnaposti, per esempio `status: "{value.code}"`) |
| `callback` | Richiamata server a server: `method` (`GET`…`DELETE`), `url` (schema e host **fissi**, segnaposti solo in path e query), `headers`, `body` (al più 16 KiB) con `body_type` `json` (i valori si inseriscono come contenuto di stringhe JSON), `form` (codificati per URL) o `text` |
| `callback.hmac` | Firma facoltativa del corpo: `header`, `key` (chiave di test, 8–256 caratteri), `algorithm` `sha256` (default) / `sha1` / `sha512`, `encoding` `hex` (default) / `base64`, `prefix` (`sha256=`). La **cifratura** della richiamata non è supportata (limite noto) |
| `links[]` | Operazioni dei contratti la cui risposta porta l'URL della pagina: `service`, `op`, `path` (tt-path nel corpo, `$.redirectUrl`), `ref_path` (dove la risposta ha il riferimento, `$.paymentId`), `base_url` (indirizzo del mock per il browser, default `http://<Host della richiesta>`), `return_from` (dove la **richiesta** dell'operazione porta l'URL di ritorno dell'applicazione: `{from: req.body, path: "$.returnUrl"}`, `{from: req.query \| req.headers, name}`; è il segnaposto `{link.return}`), `entity` (l'entità delle regole il cui oggetto, con l'id in `ref_path`, è l'oggetto collegato; senza: l'oggetto creato in modalità statica §2.5 dalla stessa operazione, se c'è) |
| `auto` | Completa la visita subito, senza mostrare la pagina: per preset di scenario (id) o `*` |

**Segnaposti** dei modelli: `{ref}`, `{action}`, `{session}`, `{uuid}` (per visita), `{now}` / `{now.date}` / `{now.unix}` (orologio virtuale), `{query.<nome>}` (parametri della pagina), `{value.<nome>}`, `{customer.id}`, `{customer.name}` (cliente sintetico della sessione), `{link.return}` (l'URL di ritorno letto da `return_from`; vuoto senza collegamento). Un segnaposto sconosciuto rifiuta la configurazione. Negli URL i valori si codificano per la query, tranne quando il modello è un solo segnaposto (l'URL intero); negli header si tolgono gli a capo.

### 9.2 Nel browser

- `GET /__pages/<id>?<parametri>` apre una **visita** nella sessione (`tt_session` della query, altrimenti come il piano dati) e risponde una pagina HTML semplice: titolo, riferimento, valori di `show`, un pulsante per scelta. **CSP stretta**: `default-src 'none'`, nessuno script, nessuna risorsa esterna, il solo stile della pagina per hash, `form-action` limitato alla pagina e all'origine dell'URL di ritorno, `frame-ancestors 'none'`; `no-store`, `no-referrer`, `nosniff`.
- Il clic (`POST /__pages/<id>/<visita>`, `action=<scelta>`) esegue la richiamata (timeout 10 s, nessun redirect seguito, risposta letta fino a 4 KiB) e poi risponde `303` verso l'URL di ritorno. Una visita si completa una volta sola: un secondo clic mostra l'esito.
- Un'operazione di `links` che risponde con successo porta nel campo `path` l'URL `…/__pages/<id>?ref=<riferimento>&tt_session=<sessione>`, con `&tt_link=<id>` quando la risposta lascia un **collegamento**: l'URL di ritorno della richiesta (`return_from`) e/o l'oggetto creato (`entity` + `ref_path`, o l'oggetto statico). La visita lo ritrova da `tt_link` o dal riferimento; la sessione ne tiene al più 2000 (oltre, si dimenticano tutti), `reset` li toglie.
- **Esito sull'oggetto collegato.** La scelta con `set` cambia i campi dell'oggetto collegato nella sessione (un pagamento `AUTHORISED`, una firma `SIGNED`): le letture successive dell'applicazione lo vedono così. Nessun effetto delle regole scatta per questo cambio; un oggetto rimosso o mai creato si ignora.
- **URL di ritorno dalla richiesta.** Con `return_url: "{link.return}"` il browser torna all'URL che l'applicazione ha mandato nella richiesta di creazione (il suo `returnUrl`); il suo host deve stare in `return_hosts`, come ogni host da segnaposto.
- Registro: `service: "pages"`, `op` `view <id>`, `callback <id>` (con il corpo inviato e la risposta), `complete <id>` (con `changed`).

### 9.3 Dai test, senza browser

- `POST /__tt/sessions/{s}/pages/{id}/complete` `{ "action", "query"?: {…}, "visit"? }`: completa una visita (nuova, con quei parametri, oppure una aperta dal browser) ed esegue la richiamata; risponde `{visit, page, ref, action, return_url, callback: {method, url, status | error, body}, changed?, error?}` (`changed`: l'oggetto collegato cambiato, `"<entità> <id>"` o `"static <id>"`). Con `query.ref` uguale al riferimento di una risposta collegata la visita usa quel collegamento.
- `PUT /__tt/sessions/{s}/pages/{id}/auto` `{ "action" }` (`DELETE` per togliere): da quel momento le visite della sessione si completano subito con quella scelta (redirect senza pagina). `reset` toglie le visite e le scelte automatiche.
- `GET /__tt/pages` mostra la configurazione con le chiavi HMAC vuote; `PUT /__tt/pages` la sostituisce (una chiave lasciata vuota mantiene quella della stessa pagina).

## 10. Operazioni SOAP e XML (v1.13)

Un servizio SOAP espone molte operazioni sullo stesso path (`POST /ws/orders.asmx`); il pacchetto le ha come **operazioni logiche** `POST /ws/orders.asmx#GetOrder` ([event.md](event.md) §6.1), con i corpi nella forma ad albero del [sanitizer](sanitizer.md) §22.2 (attributi `@nome`, testo misto `#text`, elementi ripetuti come array) e la busta in `x-tt-xml` ([pack.md](pack.md) §4: `format` e spazi dei nomi per percorso di elemento). Il mock risponde all'endpoint vero, per qualsiasi applicazione: nessun nome, path o spazio dei nomi è fissato dal prodotto. Lo stesso vale per un'operazione HTTP qualsiasi il cui corpo nel contratto è XML (*plain old XML*, senza busta).

### 10.1 Lettura della richiesta e scelta dell'operazione

1. **Endpoint.** Un `POST` sul path di un'operazione logica con un corpo XML (`x-tt-xml`, o un tipo XML con uno schema) è una chiamata SOAP. Le altre richieste seguono §2.
2. **Analisi sicura.** Il corpo si legge con **lo stesso analizzatore chiuso delle sorgenti** (sanitizer §22.2 punti 1–7, [hardening.md](hardening.md) §3): niente DTD (`<!DOCTYPE`, `<!ENTITY`: XXE ed espansione di entità impossibili), solo le cinque entità predefinite e i riferimenti numerici, al più 256 elementi aperti, un errore in qualsiasi punto rifiuta tutto il corpo; la dimensione è limitata da `--max-body`. A differenza della sorgente i valori restano in chiaro: la richiesta è del test. Un tipo di contenuto non XML o un corpo fuori dal sottoinsieme: fault del mittente (§10.4) con `invalid-request` e `pointer` `/body`; il corpo non si ripete mai nella risposta.
3. **Operazione.** Nell'ordine: il nome di `SOAPAction` (SOAP 1.1) o del parametro `action` del `Content-Type` (SOAP 1.2), calcolato come `soap_action` (sanitizer §22.2 punto 11: l'ultimo pezzo dopo `/`, `#` o `:`), se il contratto ha l'operazione; altrimenti il **primo elemento del `Body`** della busta (SOAP 1.1 e 1.2) o l'elemento radice (XML senza busta). Il metodo è quello della richiesta, altrimenti `POST`.
4. **Operazione mai osservata**: fault del mittente con `operation not observed: <nome>`, `X-TT-Unmatched: no-operation`, registrata come non corrispondente. Senza alcun nome (né azione né elemento) e con un'operazione HTTP osservata sul path, risponde quella (§2).

Da qui la chiamata segue il percorso di ogni operazione (§2, [rules.md](rules.md) §6): sessione (anche per identità), validazione, guasti, entità, regole, formati degli id, date relative, valori calcolati. La richiesta si presenta a validazione, regole e letture come **albero** (`$.Envelope.Body.GetOrder.orderId`, `$.Envelope.Body.GetOrder.@id`, `….#text`): `created_by.state`, `read_by.by` e `key` con `from: req.body` e le variabili delle regole si legano agli elementi e agli attributi della richiesta. Prima della validazione l'albero si adatta allo schema: un elemento singolo dove lo schema ha un array diventa un array di uno, un testo dove lo schema ha un numero o un booleano si converte, un elemento vuoto dove lo schema ha un oggetto è un oggetto vuoto, `xsi:nil="true"` è `null`. L'header `SOAPAction` non si valida (è servito a scegliere l'operazione). Il generatore dei valori sintetici parte dall'operazione logica e dall'albero della richiesta: due letture di due id diversi danno risposte diverse.

### 10.2 Entità

Un'entità creata da un'operazione XML prende lo stato dall'elemento indicato da `created_by.state`; nella risposta di creazione lo stato riempie l'elemento che contiene l'id (`created_by.id.path` senza l'ultimo passo, per esempio `$.Envelope.Body.CreateOrderResponse.CreateOrderResult`). Una lettura lo mette in `read_by.at` come sempre. Elementi ripetuti e attributi dello stato (`line[*].@sku`) tornano come elementi ripetuti e attributi.

### 10.3 Risposta

La risposta si costruisce come JSON (§2) e si scrive come XML:

- **Busta.** Con `format` `soap11`/`soap12` il corpo sta in `Envelope`/`Body` nello spazio della busta (`http://schemas.xmlsoap.org/soap/envelope/` con prefisso `soap`, `http://www.w3.org/2003/05/soap-envelope` con prefisso `env`); un corpo senza busta (un esempio scritto a mano, un corpo d'errore) si avvolge. Senza busta l'unico membro del corpo è l'elemento radice (più membri: `<response>`).
- **Spazi dei nomi.** Ogni elemento sta nello spazio del suo percorso in `x-tt-xml.namespaces` (senza `[*]`), altrimenti in quello del genitore; un cambio di spazio diverso dalla busta si scrive come spazio di default (`<GetOrderResponse xmlns="http://ws.example/orders">`, come fanno i servizi .NET e Java), `ns:{none}` come `xmlns=""`. I prefissi originali non si conoscono (la sorgente li toglie): conta l'URI. Un pattern con parti collassate dalla sorgente (`{*}`) ha `synthetic` al loro posto; `ns:{*}` diventa `urn:tt:synthetic`.
- **Contenuto.** I membri `@nome` sono attributi (senza prefisso; `lang` di `Text` in un fault SOAP 1.2 è `xml:lang`), `#text` è il testo, un array sono elementi ripetuti, un numero o un booleano il suo testo, `null` un elemento con `xsi:nil="true"`. I nomi non validi per XML (chiavi dinamiche `{*}`) si omettono; i caratteri che XML non ammette si tolgono. L'ordine tra figli di nome diverso non è osservato (sanitizer §22.2): i figli escono per nome, tranne l'ordine imposto da SOAP (`Header` prima di `Body`; `faultcode`, `faultstring`, `faultactor`, `detail`; `Code`, `Reason`, `Node`, `Role`, `Detail`; `Value` prima di `Subcode`).
- **Header.** `Content-Type` è il tipo del contratto con `charset=utf-8` (SOAP 1.2: `application/soap+xml`). Il registro conserva la risposta come testo.

### 10.4 Guasti e fault

- **Status.** Un guasto osservato o forzato (§4, `faults.json`, preset, API di controllo, effetti `respond`) mantiene il suo status (di solito `500`). Un errore che decide il mock e che il contratto non ha osservato (una lettura senza risultato, `404`/`403`) segue il binding HTTP di SOAP: `500` per SOAP 1.1, `400` (mittente) per SOAP 1.2, così il client vede un fault e non un errore di trasporto. I fault del protocollo (§10.1) hanno `500` (SOAP 1.1), `400` (SOAP 1.2), `404` per un'operazione sconosciuta e `400` per il resto senza busta.
- **Corpo**, nell'ordine: (1) il corpo **scritto da una persona** (§4.1): una stringa che inizia con `<` si serve così com'è; un'altra stringa è il testo del fault; un oggetto con `Envelope` o `Fault` si scrive come XML (avvolto nella busta), un altro oggetto è il `detail` di un fault con il suo `message` come testo; (2) il corpo XML osservato per quello status (esempio o schema), con i codici del fault resi validi (un `faultcode` senza prefisso diventa `soap:Client`/`soap:Server`, un `Code/Value` SOAP 1.2 fuori dai codici standard `env:Sender`/`env:Receiver`; il prefisso di un codice osservato, per esempio `s:Client`, si lega allo spazio della busta); (3) un **fault generato**: SOAP 1.1 `faultcode` (`soap:Client` per uno status < 500, altrimenti `soap:Server`), `faultstring`, `detail` con `code` (e `pointer`); SOAP 1.2 `Code/Value` (`env:Sender` / `env:Receiver`), `Reason/Text xml:lang="en"`, `Detail`; senza busta `<error>` con `code`, `message`, `pointer`.
- Una richiesta non valida per il contratto riceve la risposta `400`/`422` del contratto se è XML, altrimenti un fault del mittente con il messaggio e il `pointer` (§3).
- I guasti di rete restano guasti di rete.

Limiti noti: gli header SOAP (`Header`) della risposta escono solo se il contratto li ha osservati; WS-Security, WS-Addressing e MTOM/XOP non sono simulati; nessun WSDL è servito; la scelta dell'operazione logica per `SOAPAction` o per elemento del `Body` e la scrittura in XML sono solo di `tt mock`: gli exporter (WireMock, Microcks, Prism) non le riproducono.
