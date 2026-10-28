# Pacchetto twin v1.2

> Formato: `tt.pack/v1` · Revisione 1.8 (documenti e date relative nei contratti §4.1 e §4.4, corpi d'errore nei preset §6.1) · Schema: [`schemas/pack-manifest.v1.schema.json`](../../schemas/pack-manifest.v1.schema.json) (contiene anche `faults`, `scenarios`, `gate-report`, la firma e le righe di `world.jsonl`)

Il pacchetto twin è l'**unico** artefatto che passa dalla zona B alla zona C. Contiene solo dati sintetici, è firmato da [`tt keyguard`](keyguard.md) dopo i controlli del gate, e `tt-mock` rifiuta qualsiasi pacchetto senza firma valida.

---

## 1. Struttura

```
twin-pack/
  manifest.json                     # descrive tutto il resto, con gli hash
  manifest.sig.json                 # firma Ed25519 di manifest.json, fatta da keyguard
  contracts/
    shop-api.openapi.json           # OpenAPI 3.1 + x-tt-*
    shipping-ext.openapi.json
  rules.json                        # tt.rules/v1, solo regole approved
  world.jsonl                       # clienti ed entità sintetici, JSON canonico per riga
  faults.json                       # frequenze di errori e latenze per operazione
  scenarios.json                    # facoltativo: preset di scenari per il mock (§6.1)
  gate-report.json                  # esito dei controlli del gate
```

Tutti i file JSON del pacchetto sono in **JSON canonico tt** (§10 del [sanitizer](sanitizer.md)), con un `\n` finale. Così lo stesso contenuto produce sempre gli stessi byte.

**`manifest.json` è canonico, sul serio (v1.4, red team round 3).** Chi firma e chi verifica lo rifiutano se i byte non sono **esattamente** la codifica canonica di ciò che contengono (nessuno spazio, chiavi duplicate rifiutate, numeri e stringhe in forma canonica, `\n` finale) o se una chiave dell'oggetto non è scritta come un campo del manifest (maiuscole comprese: `PACK_ID` non vale `pack_id`; le chiavi sconosciute si rifiutano). Così due lettori diversi non possono leggere due manifest diversi dagli stessi byte firmati. Keyguard e il caricatore usano lo stesso controllo (`pack.CheckManifestCanonical`).

Distribuzione: la cartella, oppure un archivio `.ttpack` = tar POSIX (ustar) compresso gzip, con i file in ordine di percorso per byte, `mtime = 0`, proprietario `0:0`, permessi `0644`, intestazione gzip con `mtime = 0` e senza nome di file. Due pacchetti con lo stesso contenuto producono lo stesso archivio.

## 2. `manifest.json`

```json
{
  "format": "tt.pack/v1",
  "pack_id": "pk-20261019-0001",
  "created_at": "2026-10-19T03:20:00Z",
  "not_after": "2027-01-17T03:20:00Z",
  "tt_version": "0.1.0",
  "seed": 42,
  "k_min": 20,
  "source": {
    "window": { "from": "2026-10-05T00:00:00Z", "to": "2026-10-19T00:00:00Z" },
    "policies": [ { "id": "p-shop", "version": 7 } ]
  },
  "services": [
    { "name": "shop-api", "contract": "contracts/shop-api.openapi.json" },
    { "name": "shipping-ext", "contract": "contracts/shipping-ext.openapi.json", "upstream_alias": "carrier" }
  ],
  "rules": { "path": "rules.json", "approved": ["r-0007"] },
  "world": { "path": "world.jsonl", "customers": 200 },
  "faults": "faults.json",
  "gate_report": "gate-report.json",
  "scenarios": "scenarios.json",
  "files": [
    { "path": "contracts/shipping-ext.openapi.json", "sha256": "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592", "bytes": 18234 }
  ]
}
```

- `files` elenca **tutti** i file del pacchetto tranne `manifest.json` e `manifest.sig.json`, con SHA-256 esadecimale minuscolo. `tt-mock` DEVE verificarli tutti all'avvio e rifiutare file non elencati.
- `upstream_alias`: nome con cui il servizio esterno compare al posto dell'host reale, se il gate ha l'opzione di anonimizzazione degli host attiva (minaccia M16).
- `scenarios`: facoltativo, percorso di `scenarios.json` (preset definiti nella UI, §6.1).
- `not_after`: facoltativo, fine della validità del pacchetto (§2.1).
- `group` (v1.6): facoltativo, il gruppo (team) per cui il pacchetto è stato costruito (`^[a-z0-9][a-z0-9._-]{0,62}$`); assente per i pacchetti di tutti i gruppi e per quelli con servizi di più gruppi. È coperto dalla firma: un mock in modalità console ([mock.md](mock.md) §6) rifiuta un pacchetto senza `group` o di un altro gruppo. Un lettore precedente alla 1.6 rifiuta un manifest con `group` (chiave sconosciuta): usa `tt` della stessa versione della console.

### 2.1 Validità nel tempo (`not_after`)

`not_after` (date-time UTC, facoltativo) è coperto dalla firma, quindi non si può allungare senza rifirmare. Regole:

- se presente, DEVE essere successivo a `created_at`: `tt-core` non costruisce e keyguard non firma un manifest che non lo rispetta;
- `created_at` NON DEVE essere più di **5 minuti nel futuro** rispetto all'orologio di chi firma (keyguard rifiuta con `invalid_pack`) e di chi verifica (errore `invalid manifest`): una data futura aggirerebbe `--max-pack-age`;
- chi verifica un pacchetto (`tt-mock`, `tt export`, qualsiasi lettore che usa `internal/pack`) DEVE rifiutarlo, con l'errore `pack_expired`, quando il proprio orologio è **uguale o successivo** a `not_after`. Il controllo si fa al caricamento; un mock già avviato continua a servire il pacchetto caricato fino al riavvio, ma DEVE scrivere un avviso nel log quando l'orologio supera `not_after`;
- **senza `not_after`** (pacchetti di altri costruttori, o di versioni precedenti) chi verifica DEVE rifiutare il pacchetto con `pack_expired` quando `created_at` è più vecchio di `--max-pack-age`, che vale **90 giorni** se non è impostato (v1.4). Un pacchetto con `not_after` è governato da `not_after` e non da questo limite.

L'età massima (`tt mock --max-pack-age`, confronto tra l'orologio e `created_at`) è una politica del verificatore: se impostata (> 0) si applica **anche** ai pacchetti con `not_after` e vale il limite più stretto; un valore negativo spegne il controllo (solo per fixture di test). Non fa parte del formato firmato.

Tutti i pacchetti costruiti da `tt-core` hanno `not_after`: l'API di amministrazione lo fissa alla costruzione (`valid_days`, **default 30 giorni**, `gate.valid_days` in configurazione). Un pacchetto firmato da una chiave poi trapelata non resta quindi valido per sempre.

### 2.2 Chiavi revocate del gate

`TT_GATE_PUBKEYS` può contenere più chiavi (rotazione). Quando una chiave viene ritirata o trapela, chi verifica la elenca in `TT_GATE_REVOKED_KIDS` (`kid` separati da virgola o spazio; `pack.Options.RevokedKIDs`): un pacchetto firmato da un `kid` revocato è rifiutato con `pack is signed by a revoked key`, anche se il `kid` è ancora in `TT_GATE_PUBKEYS`. Keyguard smette di annunciare le chiavi revocate ([keyguard.md](keyguard.md) §6) ma non può cambiare la configurazione dei mock già distribuiti: la revoca lato verificatore è un passo esplicito della procedura di rotazione. Se `TT_GATE_PUBKEYS` è un file, il file NON DEVE essere scrivibile da gruppo o altri (si rifiuta con il suggerimento `chmod go-w`): chi lo scrive decide di chi fidarsi.

## 3. `manifest.sig.json`

```json
{ "format": "tt.pack.sig/v1", "alg": "Ed25519", "kid": "gate-2026-1", "manifest_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "sig": "Xz9kjHlb5S5NV-EPR09AZ3mQmxEJnC3cEK_trqAeaEE2Ap6cu_NyfgQ0EXFomIeJMBeil44y9bMT7p12MiKvBg" }
```

- La firma copre i byte `"tt.pack/v1" || 0x00 || byte esatti di manifest.json`.
- La fa **keyguard** ([keyguard.md](keyguard.md) §3.4), che rifà da sé il controllo `reverse-hmac` su tutti i file prima di firmare.
- `tt-mock` accetta una lista di chiavi pubbliche (`TT_GATE_PUBKEYS`: voci `kid:base64url` separate da virgola, oppure un file con una voce per riga), così una rotazione non richiede di fermare i test. Una firma con `kid` sconosciuto o revocato (§2.2) si rifiuta.
- **Ordine di lettura (v1.4).** Chi legge un pacchetto NON DEVE decomprimere o leggere in memoria altro che `manifest.json` (al massimo 4 MiB) e `manifest.sig.json` (al massimo 16 KiB) prima di avere verificato la firma. Poi legge **solo** i file elencati, ciascuno in un buffer della dimensione dichiarata in `files[].bytes` (un file più lungo o più corto, o un'intestazione di archivio con altra dimensione, è rifiutato), con tetti di 256 MiB per file e 1 GiB in tutto, anche sulla dimensione decompressa dell'archivio. Un archivio gzip di pochi KiB che si espande a centinaia di MiB non fa quindi allocare memoria prima della verifica.

## 4. Contratti

OpenAPI 3.1, una per servizio, in JSON canonico. Le estensioni `x-tt-*` ammesse:

| Estensione | Dove | Contenuto |
|---|---|---|
| `x-tt-observed` | operazione | `{ "calls": int, "first_seen": date, "last_seen": date }` (conteggi) |
| `x-tt-latency-ms` | operazione | `{ "p50": int, "p95": int, "p99": int }` |
| `x-tt-frequency` | risposta | Quota di risposte con quello status, 0–1 |
| `x-tt-presence` | proprietà di schema | Quota di oggetti in cui il campo è presente, 0–1 |
| `x-tt-when` | proprietà di schema opzionale | `{ "<proprietà sorella>": ["VALORE", …] }`: il campo esiste solo quando la proprietà sorella (un enum) ha uno di quei valori (es. `cancelReason` solo con `status: CANCELLED`). Si ricava dal traffico quando il campo compare quasi solo per quei valori; i valori nominati sono solo valori già pubblicati (visti da almeno `k_min` soggetti). Mock, esportatori, generatore del mondo ed esempi lo rispettano: un oggetto non mescola mai campi di stati diversi |
| `x-tt-entity` | operazione | Nome dell'entità esposta (da `tt.rules/v1`). Solo informativo dalla 1.2: come l'operazione espone l'entità lo dice `read_by` ([rules.md](rules.md) §2.3) |
| `x-tt-value` | schema di un valore scalare | Come generare valori sintetici (§4.1) |
| `x-tt-dependencies` | schema di un oggetto (1.5) | Campi collegati: le combinazioni di valori di due proprietà dello stesso oggetto viste insieme per almeno `k_min` soggetti (§4.2) |
| `x-tt-graphql` | operazione (v1.14) | Un'operazione logica GraphQL ([event.md](event.md) §6), con path `/<endpoint>#<nome>`: `{ "endpoint": "/graphql", "method": "POST", "in": "json" \| "query" \| "body", "type": "query" \| "mutation" \| "subscription", "name": "GetOrder", "anonymous": bool, "introspection": bool, "document": "<forma>", "variables": [{"name", "type", "has_default"}], "fields": ["order"] }`. `document` è la forma più frequente ([sanitizer](sanitizer.md) §5.7.1), senza valori. Il mock risponde all'endpoint vero scegliendo l'operazione per nome (o per hash della forma, se anonima), [mock.md](mock.md) §7 |
| `x-tt-graphql-schemas` | documento (v1.14) | `[{ "endpoint": "POST /graphql", "captured_at": date, "data": { "__schema": … } }]`: l'ultimo risultato di introspezione catturato per l'endpoint, solo nomi e tipi (descrizioni, valori di default e motivi di deprecazione `null`, `isDeprecated` falso). Non è soggetto a `k_min` (è lo schema, non dati); il gate vi ammette solo nomi GraphQL sicuri, forme, tipi, endpoint e date |
| `x-tt-xml` | tipo di contenuto di un corpo (v1.19) | `{ "format": "xml" \| "soap11" \| "soap12", "namespaces": { "$.Envelope": "ns:http://schemas.xmlsoap.org/soap/envelope/", … } }`: la busta di un corpo XML o SOAP ([sanitizer](sanitizer.md) §22.2), il `fmt` più frequente e, per percorso di elemento, il pattern di spazio dei nomi più frequente (`ns:{none}`, `ns:{*}` o l'URI con le sequenze che sembrano valori già sostituite da `{*}` alla sorgente). Gli elementi sono le proprietà dello schema, gli attributi le proprietà `@nome` (con `xml: { "name", "attribute": true }` di OpenAPI), il testo misto `#text`. Il gate vi ammette solo valori di `fmt` e pattern `ns:` validi. Un'operazione SOAP ha il path `/<endpoint>#<nome>` ([event.md](event.md) §6.1) |

I campi presenti nel 100% delle osservazioni finiscono in `required`. Gli esempi (`examples`) sono **sintetici**: forma, codici e campi opzionali fedeli, valori generati.

### 4.1 `x-tt-value`

Descrive cosa si sa di un valore, **senza** valori reali, per permettere al generatore e al mock di produrne di sintetici:

| Campo | Contenuto |
|---|---|
| `kind` | `id` (il campo aveva regola `hmac`: si genera un id sintetico), `enum` (regola `keep` con pochi valori), `bucket` (regola `bucket`), `shape` (solo forma), `graphql` (v1.14: il documento GraphQL di una richiesta, regola `graphql`; il mock non lo genera, lo riceve) |
| `domain` | Per `id`: dominio HMAC (`order`, `shipment`), che lega i campi tra loro |
| `len_class` | Classe di lunghezza osservata più frequente (`l8`, `l32`, …) |
| `format` | Formato riconosciuto (`email`, `uuid`, `datetime`, …), se presente |
| `enum` | Per `enum`: i valori `keep` osservati con **almeno k_min soggetti distinti**; gli altri si omettono |
| `enum_partial` | `true` se qualche valore è stato omesso per la soglia k |
| `bounds` | Per `bucket(num)`: i confini `[b0, …, bn]` |
| `bucket_p` | Per `bucket(num)`: le quote osservate per fascia, `n + 2` numeri (`<b0`, ogni `[bi, bi+1)`, `>=bn`); fasce con meno di `k_min` soggetti valgono 0 |
| `unit` | Per `bucket(time)`: l'unità |
| `id_format` | Per `id` (1.7): il formato degli id del dominio scelto da una persona (§4.3); assente: `<PREFISSO>-SYN-NNNN` |
| `doc_type`, `doc_class` | Per `shape` con `format: "doc"` (1.8): un documento in base64 (forma `drop:doc:<tipo>:<classe>` o `drop:file:…` del [sanitizer](sanitizer.md) §20.3–20.4): il tipo più frequente (`pdf`, `png`, `jpeg`, `gif`, `webp`, `ole`, `docx`, `xlsx`, `pptx`, `zip`; per le parti file anche `text`, `csv`, `json`, `xml`, `bin`) e la classe di dimensione (`l1k` … `lmax`). Lo schema ha anche `contentEncoding: "base64"` e `contentMediaType` per i tipi di documento; l'esempio è un documento sintetico valido. Il mock genera documenti validi ([mock.md](mock.md) §2.7) |
| `date_offset` | Per un campo data (1.8): `{min, max}`, gli scarti dall'istante dello scambio (§4.4) |

Esempio:

```json
{ "type": "string", "x-tt-value": { "domain": "shipment", "kind": "id", "len_class": "l32" } }
```

Non esiste un `format` speciale per i token: nei contratti pubblicati gli identificatori sono stringhe normali con `x-tt-value.kind = "id"`.

### 4.2 `x-tt-dependencies` (campi collegati, 1.5)

In un negozio la macrocategoria e la categoria non sono indipendenti: «Grandi elettrodomestici» va con «Forni» e «Frigoriferi», mai con «Smartphone». Un contratto che descrive i campi uno per uno lascerebbe al mondo e al mock combinazioni impossibili. L'estensione, sullo schema di un **oggetto** (il corpo, un oggetto annidato, l'elemento di una lista), elenca per ogni coppia di proprietà sorelle le combinazioni osservate:

```json
{
  "type": "object",
  "properties": { "macroCategory": { "type": "string", "enum": ["Grandi elettrodomestici", "Telefonia"] },
                  "category": { "type": "string", "enum": ["Forni", "Frigoriferi", "Smartphone"] },
                  "price": { "type": "number", "x-tt-value": { "kind": "bucket", "bounds": [0, 50, 250] } } },
  "x-tt-dependencies": [
    { "fields": ["category", "macroCategory"],
      "combinations": [
        { "values": ["Forni", "Grandi elettrodomestici"], "at_least": 100 },
        { "values": ["Frigoriferi", "Grandi elettrodomestici"], "at_least": 20 },
        { "values": ["Smartphone", "Telefonia"], "at_least": 1000 } ],
      "partial": true },
    { "fields": ["category", "price"],
      "combinations": [ { "values": ["Forni", { "min": 250 }], "at_least": 20 },
                        { "values": ["Smartphone", { "min": 50, "max": 250 }], "at_least": 100 } ] }
  ]
}
```

| Campo | Contenuto |
|---|---|
| `fields` | Due proprietà dello stesso oggetto (in v1 solo coppie), in ordine di nome |
| `combinations[].values` | Un valore per campo, nello stesso ordine: un valore `keep` pubblicato (stringa, numero) oppure una fascia di `bucket(num)` come `{ "min", "max" }` (`[min, max)`, un estremo aperto si omette) |
| `combinations[].at_least` | Classe di grandezza delle osservazioni, **mai un conteggio esatto**: la potenza di dieci non superiore al numero di oggetti visti con quella combinazione, e mai sotto `k_min` |
| `partial` | `true` se qualche combinazione osservata è stata omessa (sotto `k_min` soggetti, o con un valore non pubblicato) |

**Inferenza.** Partecipano solo le proprietà con valori `keep` a bassa cardinalità (le stesse che diventano `enum`) e le fasce `bucket(num)`; mai i token `hmac`, le forme `drop`, i tempi, né un campo con più di `MaxEnumValues` valori. Una combinazione si pubblica solo se vista per almeno `k_min` **soggetti distinti** nello stesso oggetto (come un valore di enum, con il soggetto dell'evento in ingresso per le chiamate in uscita). Una coppia si pubblica solo se dice qualcosa: se ogni coppia di valori pubblicati è stata vista, i campi risultano indipendenti e l'estensione si omette. Il conteggio si fa nello stesso passaggio in streaming dell'inferenza, con memoria limitata per nodo di schema: al più 6 proprietà seguite (15 coppie), al più 128 combinazioni per coppia (oltre, la coppia si considera ad alta cardinalità e si scarta subito, liberando la memoria), e per combinazione un contatore e al più `k_min` impronte da 8 byte dei soggetti; nel caso peggiore circa 0,3 MB per nodo, di solito pochi KB. Le combinazioni pubblicate (con i soggetti, limitati a `k_min`) restano nella fotografia del contratto.

**Uso.** Il generatore del mondo, il mock e gli esempi del contratto producono **solo** combinazioni elencate (campionamento condizionato): i valori che devono restare (quelli dello stato di un'entità, copiati da una richiesta o scritti da una regola) sono fissi, gli altri si scelgono tra le combinazioni compatibili con loro; un campo opzionale si omette quando nessuna combinazione è compatibile. Una dipendenza con un campo assente non vincola nulla. Due valori fissati dal servizio sotto test che non sono mai stati visti insieme si rispettano (il mock fa eco alla richiesta), e così i valori scritti da una regola approvata. Gli esportatori riusano gli esempi del contratto e gli stati del mondo, che le rispettano già; non applicano l'estensione ai valori che generano da sé (limite noto), e l'export Microcks toglie le estensioni `x-tt-*`.

**Gate.** Ogni campo di `fields` deve essere una proprietà del contratto e ogni valore stringa un valore `keep` dichiarato (provenienza); i rilevatori di dati personali guardano ogni stringa; il controllo `k-thresholds` (§7) verifica che ogni combinazione riguardi almeno `k_min` soggetti distinti e che nessun `at_least` sia sotto `k_min`. Il costruttore del pacchetto toglie le combinazioni con un valore sotto soglia (la dipendenza diventa `partial`) e le dipendenze rimaste vuote.

### 4.3 Formati degli id (1.7)

I client veri costruiscono e scompongono gli identificatori: un id composto `NN-NNNNNN-NNNN-NNNNNN` diviso sul trattino per ricavare un pezzo che è l'id di un altro oggetto, un id `XYZ.000123` collegato a un altro oggetto dalla parte dopo l'ultimo punto senza zeri iniziali, id numerici con zeri iniziali, id in base64url. Con gli id `<PREFISSO>-SYN-NNNN` questi client si rompono in silenzio. Un **formato degli id** è un modello scelto da una persona nella console (Contratti → servizio → «Formato degli id») per un **dominio di id** (il dominio HMAC, quindi tutti i campi del gruppo che portano id di quel dominio, in tutti i servizi). Il prodotto non conosce nessun formato di nessuna applicazione: i formati sono modelli generali.

**Grammatica** (tutta la stringa, al più 64 caratteri):

| Pezzo | Significato |
|---|---|
| `N` | una cifra casuale |
| `A` / `a` | una lettera maiuscola / minuscola casuale |
| `X` | una lettera maiuscola o una cifra casuale |
| `0`–`9` `-` `.` `_` `:` `/` `+` `=` `#` `@` | sé stessi (letterali) |
| `'testo'` | un letterale tra apici (anche lettere): `'XYZ'.NNNNNN` |
| `{campo}` | il valore di un altro campo dello stesso oggetto (percorso puntato) |
| `{campo#k}` | il suo k-esimo segmento (diviso su `-` `.` `_` `:` `/` e spazio; `k` negativo conta dalla fine) |
| `\|trim0`, `\|pad6` | dopo il campo: senza zeri iniziali; completato a sinistra con zeri fino a 6 caratteri (`{campo#-1\|trim0}`) |
| `<…>` | la codifica base64url (senza padding) di quello che contiene: `<'Item':NNNNNN>` |

Un formato deve dare almeno 1000 id diversi (le parti casuali). I codici di errore (`bad_char`, `too_small`, …) con la posizione sono quelli dell'API di amministrazione (`IdFormatError`).

**Generazione.** L'id numero `n` (da 1) di un dominio si calcola dal formato, dal dominio e da `n`: la parte casuale è una **permutazione** di `n` (mai due id uguali finché lo spazio non è esaurito), le parti copiate vengono dal campo nominato dell'oggetto (se manca, cifre deterministiche della larghezza di `pad`, altrimenti 6). Lo stesso `(formato, dominio, n)` dà sempre lo stesso id: il generatore del mondo e il mock lo calcolano allo stesso modo. Il generatore numera le entità di ogni tipo da 1; il mock riparte dopo gli id del mondo e salta quelli già presi; gli id di un dominio senza entità (`x-tt-value` senza `read_by`) e la modalità statica ([mock.md](mock.md) §2.5) usano lo stesso formato. Gli id copiati mantengono i legami: se il formato della spedizione copia il segmento 2 dell'`orderId`, un client che scompone l'id della spedizione ritrova l'ordine.

**Dove sta.** La console conserva i formati per gruppo e dominio; quando prepara gli ingressi di un mondo li scrive in `x-tt-value.id_format` di ogni campo `kind: id` di quel dominio e sostituisce gli id di esempio che l'inferenza aveva scritto per il dominio (`ORD-SYN-0042`) con l'id numero 42 del formato. Il pacchetto li porta così nei contratti: nessun file nuovo. Un mondo generato prima di un cambio di formato diventa non più valido (va generato di nuovo). Gli id delle righe `entity`, `history`, `pending` (e i valori di `effect_ids`) sono `<PREFISSO>-SYN-NNNN` oppure, se il dominio dell'entità ha un formato, un id di quel formato: il mock rifiuta il pacchetto altrimenti. Gli id dei clienti restano `CUS-SYN-NNNN`.

**Gate** (§7). `provenance`: un `id_format` deve essere un modello valido. `pii-detectors`: una stringa **generata** (provenienza del generatore) che ha la forma di un formato dichiarato non è un dato personale (16 cifre a gruppi sembrerebbero una carta). `reverse-hmac`: oltre a ogni stringa del pacchetto, keyguard controlla i primi id che il mock genererà con ogni formato (righe del mondo + 1000, al più 50 000 per formato, senza campi copiati); un id uguale a un valore vero fa fallire il gate con `file: "id-formats"`, `pointer: "/<dominio>"` e il formato va cambiato. Gli id oltre quella finestra e quelli che copiano campi della richiesta non sono controllati (limite noto: lo spazio casuale li rende improbabili).

**Perché non dalla sorgente (opzione scartata).** Si è valutato di far imparare alle sorgenti lo «scheletro» di un identificatore (classi di caratteri e separatori, per esempio `9-9-9-9` con lunghezze 2-6-4-6) come nuovo dettaglio di forma. Non si fa, per tre motivi: (1) cambierebbe l'uscita del sanitizer, cioè un cambiamento **major** (README, Versioni) da portare in tutti i sei SDK e nei vettori; (2) lo scheletro non è sempre innocuo: su un campo `hmac` che non è un vero identificatore (un nome, un indirizzo) le lunghezze dei segmenti sono quasi-identificatori (`5 5` per «Mario Rossi»), e anche su un id vero lunghezze variabili rivelano grandezze (un contatore a 7 cifre contro uno a 9); (3) dovrebbe essere comunque facoltativo per campo, e allora la scelta di una persona serve lo stesso. Il formato scelto in console non legge niente dal traffico e copre gli stessi casi.


### 4.4 Date relative (1.8)

Un campo data di un contratto PUÒ avere `x-tt-value.date_offset = { "min": "+30d", "max": "+365d" }`: l'intervallo degli **scarti** tra la data del campo e l'istante dello scambio. Il mondo genera il campo come istante del valore + uno scarto dell'intervallo, il mock come orologio virtuale della sessione + uno scarto ([mock.md](mock.md) §2.8). Gli scarti hanno la forma `^[+-]?[0-9]{1,6}(h|d)$` (al più 36600 giorni), `min ≤ max`.

- **Dal traffico (lato core).** Per un campo `bucket(time)` l'inferenza dei contratti conta, per ogni scarto tra l'inizio della fascia (`time:2026-11-27` → 27 novembre) e il giorno dell'evento, gli eventi e fino a `k_min` soggetti distinti (impronte da 8 byte); le fasce mese e anno valgono 30 e 365 giorni, quella ora si conta in ore; oltre un anno gli scarti si raggruppano per settimana, oltre dieci anni per 30 giorni, al più 1024 scarti per campo. L'intervallo pubblicato copre il 90% centrale degli eventi e **ogni estremo è sostenuto da almeno `k_min` soggetti distinti** (unione delle impronte dalla coda verso l'interno); gli estremi si arrotondano verso l'esterno (1 giorno fino a 31, 7 fino a 366, 30 oltre; ore fino a 48, poi giorni). Con meno evidenza non si pubblica nulla e la data resta «oggi». Nessun valore nuovo esce dalle sorgenti: si usano le fasce che il sanitizer produce già e l'istante dell'evento.
- **Da una persona.** Nella console (Contratti → servizio → «Date relative») una persona sceglie l'intervallo per **nome di campo** nel gruppo (admin-api `GET /api/v1/date-offsets`, `PUT|DELETE /api/v1/date-offsets/{field}`, audit `dateoffset.set`, `dateoffset.delete`); quando prepara gli ingressi di un mondo la console lo scrive in `x-tt-value.date_offset` di ogni proprietà data con quel nome (formato `date`/`date-time`, `bucket(time)`, forme `date`/`datetime`), sopra quello appreso. Un mondo generato prima del cambio non lo vede: va generato di nuovo.
- **Gate.** `provenance`: un valore di `date_offset` deve essere uno scarto valido (è struttura, non un dato).

## 5. `world.jsonl`

Un file di testo con **un oggetto JSON canonico per riga**, separatore `\n`, `\n` finale, nessuna riga vuota. È byte-deterministico: lo stesso seed e gli stessi ingressi producono gli stessi byte. `tt-mock` lo carica in memoria (o in un SQLite temporaneo) all'avvio.

Tipi di riga, in quest'ordine:

1. **una** riga `meta`:

   ```json
   {"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}
   ```

2. righe `customer`, ordinate per `id` (byte):

   ```json
   {"archetype":"arch-03","id":"CUS-SYN-0007","profile":{"email":"giulia.neri@example.com","name":"Giulia Neri"},"type":"customer"}
   ```

   `archetype` è `null` se il cliente è stato generato senza profili.

3. righe `entity`, ordinate per (`entity`, `id`):

   ```json
   {"customer_id":"CUS-SYN-0007","entity":"order","id":"ORD-SYN-0042","state":{"createdAt":"2026-10-18T09:00:00Z","currency":"EUR","id":"ORD-SYN-0042","shipmentId":"SHP-SYN-0091","status":"CONFIRMED","total":19.9},"type":"entity"}
   ```

   `state` è lo stato a `t0`, conforme allo schema del contratto. `customer_id` è il **proprietario** dell'entità ([rules.md](rules.md) §2.6), `null` se non ne ha. Gli oggetti preesistenti di un'entità con `seed` ([rules.md](rules.md) §2.8, 1.6) sono righe come le altre, con il loro proprietario e una riga `history` all'inizio della finestra; un'entità rimossa da un effetto `remove` prima di `t0` non ha la riga `entity` (resta la sua storia).

4. righe `history`, ordinate per (`entity`, `id`, `at`, `seq`):

   ```json
   {"at":"2026-10-18T09:06:00Z","effect_id":"shipment-created","entity":"shipment","id":"SHP-SYN-0091","outcome":"happy","rule_id":"r-0007","seq":2,"state":{"orderId":"ORD-SYN-0042","shipmentId":"SHP-SYN-0091","status":"CREATED"},"type":"history"}
   ```

   `at` < `t0`; `seq` cresce per ogni (`entity`, `id`) e ordina gli eventi con lo stesso istante. Una riga applicata da una regola causale porta `rule_id`, `effect_id` e (dalla 1.2) `outcome`, il ramo scelto; una riga di una regola batch porta solo `rule_id`; una riga senza `rule_id` è la creazione da `created_by`.

5. righe `pending` (dalla 1.2), ordinate per (`due_offset_s`, `seq`):

   ```json
   {"customer_id":"CUS-SYN-0007","due_offset_s":18600,"effect_id":"shipment-delivered","entity":"shipment","id":"SHP-SYN-0091","outcome":"happy","rule_id":"r-0007","seq":3,"type":"pending"}
   ```

   Un effetto di una regola scattata prima di `t0` ma con istante **dopo** `t0` (la spedizione `IN_TRANSIT` che sarà `DELIVERED`). Campi:

   | Campo | Contenuto |
   |---|---|
   | `due_offset_s` | Secondi dopo il `t0` **della sessione** a cui l'effetto si applica (≥ 1). È relativo, così una sessione creata con un `t0` diverso sposta anche gli effetti pendenti |
   | `seq` | Unico tra le righe `pending`, da 1, crescente nell'ordine del file; a parità di `due_offset_s` ordina l'applicazione |
   | `rule_id`, `outcome`, `effect_id` | Regola, ramo già estratto ed effetto (l'effetto deve far parte del ramo) |
   | `entity`, `id` | Entità modificata. Per un effetto `create` l'id è **assegnato in anticipo** dal generatore e l'entità non ha ancora una riga `entity` |
   | `customer_id` | Proprietario dell'entità (per un `create`, quello che avrà) |
   | `vars` | Facoltativo: valori delle variabili di `bind` citate dai valori dell'effetto, **solo** quelle citate |
   | `effect_ids` | Facoltativo: id delle entità create o aggiornate dagli effetti della stessa esecuzione citati con `${effect:…}`, **solo** quelli citati |

   Ogni effetto del ramo con istante dopo `t0` ha la sua riga: anche quelli che seguono un altro effetto pendente (i ritardi sono già estratti). `vars` ed `effect_ids` si omettono se vuoti.

Il mock mette in coda le righe `pending` alla creazione e all'azzeramento di ogni sessione, con istante = `t0` della sessione + `due_offset_s`, prima di qualsiasi effetto della sessione a parità di istante ([rules.md](rules.md) §6). I contatori degli id sintetici ripartono dopo gli id del mondo, **compresi** quelli assegnati in anticipo dalle righe `pending`.

Integrità del mondo, verificata dal mock all'avvio (pacchetto rifiutato se manca):

- ogni campo di relazione ([rules.md](rules.md) §2.2) presente e non `null` nello stato di una riga `entity` cita una riga `entity` del tipo giusto o l'`id` di una riga `pending` che la crea;
- ogni `customer_id` non `null` cita una riga `customer`;
- ogni riga `pending` cita una regola approvata, un suo ramo e un effetto di quel ramo; per un effetto `set` l'entità esiste come riga `entity` o è creata da una riga `pending` con `due_offset_s` minore, o uguale e `seq` minore.

Gli id sintetici usano il prefisso `<TIPO>-SYN-` per renderli riconoscibili a colpo d'occhio, tranne quelli di un dominio con un formato degli id (§4.3), che hanno la forma scelta. I nomi e i contatti finti usano domini riservati (`example.com`, `example.org`, `example.net`, `*.example`, RFC 2606) e telefoni `+39 555…`: il controllo `pii-detectors` del gate accetta **solo** questi domini e prefissi per email, URL e telefoni, e segnala qualsiasi altro.

## 6. `faults.json`

```json
{
  "format": "tt.faults/v1",
  "ops": [
    {
      "service": "shipping-ext",
      "op": "GET /v1/shipments",
      "statuses": [ { "status": 503, "p": 0.012, "example": "upstream-unavailable" } ],
      "net_errors": [ { "kind": "timeout", "p": 0.002 } ],
      "latency_ms": { "p50": 92, "p95": 310, "p99": 870, "lognormal": { "median": 92, "sigma": 0.74 } }
    }
  ]
}
```

`example` rimanda a un esempio nominato nel contratto. Le `p` sono quote osservate; il resto delle risposte segue il comportamento normale del contratto e delle regole. Come il mock HTTP riproduce i tipi di `net_errors` è in [mock.md](mock.md) §4.

### 6.1 `scenarios.json`

Facoltativo (`tt.scenarios/v1`, `$defs/scenarios` dello schema). Ogni **preset** descrive un punto di partenza di un test e corrisponde a un `ScenarioPreset` dell'API di amministrazione:

```json
{
  "format": "tt.scenarios/v1",
  "scenarios": [
    {
      "id": "shipment-cancelled",
      "name": "Spedizione annullata",
      "description": "La spedizione viene annullata dopo la creazione.",
      "customer": "CUS-SYN-0007",
      "seed": 42,
      "outcomes": [ { "rule": "r-0007", "outcome": "cancelled", "times": 1 } ]
    },
    {
      "id": "tracking-down",
      "name": "Tracciamento non disponibile",
      "archetype": "arch-03",
      "faults": { "mode": "custom", "rules": [ { "service": "shipping-ext", "op": "GET /v1/shipments", "status": 503, "p": 1, "times": 1 } ] }
    }
  ]
}
```

| Campo | Contenuto |
|---|---|
| `id` | Identificatore unico nel file (`^[a-z0-9][a-z0-9-]{0,62}$`); i preset sono ordinati per `id` |
| `name`, `description` | Testi per le persone |
| `customer` **oppure** `archetype` | Cliente da scegliere: per id, oppure il primo cliente dell'archetipo per id. Mai entrambi |
| `seed` | Facoltativo: seed della sessione |
| `faults` | Facoltativo: stessa forma dell'oggetto `Faults` dell'API di controllo (`$defs/sessionFaults`) |
| `outcomes` | Facoltativo: esiti forzati, come `POST /__tt/sessions/{s}/scenario` |

Dalla 1.8 una regola di `faults` con uno `status` PUÒ avere `example` (un esempio nominato del contratto per quello status) e `body` (un corpo d'errore scritto da una persona: oggetto, array o stringa JSON, al più 16 KiB), come la `FaultRule` dell'API di controllo ([mock.md](mock.md) §4.1). Il gate passa i rilevatori di dati personali su `body`; la provenienza non lo richiede generato.

Il mock verifica all'avvio che ogni preset citi clienti, archetipi, regole approvate causali, rami, servizi e operazioni esistenti, e rifiuta il pacchetto altrimenti. Come si applica un preset è nell'API di controllo (`POST /__tt/sessions` con `scenario`, `POST /__tt/sessions/{s}/scenario` con `preset`).

## 7. `gate-report.json`

```json
{
  "format": "tt.gate-report/v1",
  "pack_id": "pk-20261019-0001",
  "verdict": "pass",
  "k_min": 20,
  "checks": [
    { "id": "provenance",   "status": "pass", "findings": [], "by": "tt-core" },
    { "id": "reverse-hmac", "status": "pass", "findings": [], "strings_checked": 48211, "by": "keyguard" },
    { "id": "pii-detectors","status": "pass", "findings": [], "by": "tt-core" },
    { "id": "k-thresholds", "status": "pass", "findings": [], "by": "tt-core" }
  ]
}
```

Un `finding` indica `file`, `pointer` (JSON Pointer, o numero di riga + JSON Pointer per `world.jsonl`) e `reason`, **mai** il valore trovato. Con un `fail`, il verdetto è `fail` e keyguard non firma.

Dalla 1.4 il report ha un quinto controllo, **`rules-approved`**, di sola segnalazione: ha `status: "warn"` (mai `fail`: il verdetto resta `pass` e keyguard firma) quando il pacchetto non contiene alcuna regola approvata. Un gemello senza regole risponde a ogni richiesta ma non fa evolvere lo stato nel tempo (un ordine resta com'è stato creato). `status` ammette quindi `pass`, `warn` e `fail`; `tt-mock` e keyguard accettano `warn` solo per questo controllo. La UI lo mostra prima del rilascio.

Il controllo `k-thresholds` verifica che ogni archetipo abbia almeno `k_min` soggetti reali, che ogni valore di `x-tt-value.enum`, ogni combinazione di `x-tt-dependencies` (1.5, §4.2) e ogni esito di regola pubblicato riguardi almeno `k_min` soggetti distinti, e che nessun conteggio pubblicato (`x-tt-observed`, `evidence.counts`, `evidence.keys[].matches`, `x-tt-dependencies[].combinations[].at_least`) sia minore di `k_min` salvo lo zero. Le regole scritte a mano (`origin: manual`, [rules.md](rules.md) §5.1) hanno conteggi zero: non sono state osservate.

**Revisione di sicurezza r4.** `at_least` DEVE essere una classe, non un conteggio: `k_min` oppure una potenza di dieci non minore di `k_min`, scritta come intero; il costruttore del pacchetto la riscrive con il `k_min` del pacchetto (`contract.k_min` può essere diverso da `gate.k_min`) e toglie le combinazioni con una classe sotto soglia. Un valore `keep` osservato per meno di `k_min` soggetti distinti non generato dal mondo è rifiutato anche in `world.jsonl` e nei valori delle regole (`create`, `set`, `defaults`, `where`, `hidden_when`).

## 8. Costruzione, firma e rilascio (v1.3)

Il percorso da una versione del mondo a un pacchetto scaricabile, come lo implementa `tt-core` (`POST /api/v1/packs`, `…/publish`, `…/download` dell'API di amministrazione):

1. **Costruzione e gate, in modo sincrono.** `POST /api/v1/packs` assembla i file (§1) dal mondo indicato, esegue il gate (§7) e, se passa, chiede a [keyguard](keyguard.md) §3.4 di rifare `reverse-hmac` e di firmare, poi ricarica il pacchetto firmato con le stesse verifiche di `tt-mock` (firma, hash, contenuto, integrità del mondo, `not_after`) prima di dichiararlo buono. La risposta `202` porta già il lavoro **finito** (`Job` con `status: "done"` e `result` = il pacchetto): non c'è un lavoro in corso da interrogare, e `GET /api/v1/jobs/{id}` non serve per i pacchetti. Un errore di costruzione (mondo sconosciuto o obsoleto, servizio mancante, preset non valido, nessuna policy firmata) è una risposta di errore, non un lavoro `failed`.
2. **Stati.** `gate-failed`: il gate o keyguard hanno rifiutato; il pacchetto resta in archivio con manifest e `gate-report.json` (per la UI, con i `findings` senza valori), ma non ha archivio né firma e non si può rilasciare né scaricare. `signed`: firmato da keyguard alla costruzione, non ancora disponibile ai test. `published`: rilasciato. (`building` è riservato e non si usa: la costruzione è sincrona.)
3. **Rilascio.** `POST …/publish` richiede il ruolo `publisher`, oppure `admin` con una motivazione ([policy.md](policy.md) §5). `tt-core` chiede a keyguard di firmare **di nuovo** lo stesso archivio con l'approvazione del richiedente (header `X-TT-Approval`); la firma DEVE essere identica alla prima (Ed25519 è deterministico), il pacchetto si riverifica (se nel frattempo `not_after` è passato il rilascio è rifiutato con `pack_expired`) e passa a `published`. Rilasciare un pacchetto già rilasciato non fa nulla. Il modo di approvazione (`standard`, `admin`) resta nel record del pacchetto.
4. **Scarico.** Solo i pacchetti `published` si scaricano (`.ttpack` con `manifest.sig.json`), e ogni scarico è registrato nell'audit.
5. **Gruppo.** Un pacchetto appartiene a un gruppo: quello del mondo da cui nasce (un mondo generato con `group` usa solo i contratti inferiti dal traffico delle sorgenti di quel gruppo, i suoi archetipi e le regole i cui servizi sono tutti del gruppo). `POST /api/v1/packs` accetta `services` (elenco di inclusione), `exclude_services`, `group` (deve essere quello del mondo) e `multi_group`. Con un mondo di tutti i gruppi, una selezione di servizi prodotti da più di un gruppo (compreso lo stesso `host:...` chiamato da due gruppi, il cui contratto mescola le loro chiamate) è rifiutata con `mixed_groups` (422, `details` con servizio e gruppi), a meno che un amministratore chieda `multi_group: true` (`multi_group_forbidden`, 403, per gli altri). Il manifest elenca solo le policy dei gruppi del pacchetto. `PackInfo` riporta `group`, `groups` e `services`; `GET /api/v1/packs?group=` elenca i pacchetti dei gruppi scelti.
6. **Rischio residuo.** Insieme al gate, `tt-core` calcola in zona B misure di rischio di re-identificazione degli archetipi (`residual_risk`: dimensione minima del gruppo, soggetti soppressi, tasso di unicità, tasso di individuazione, quota di corrispondenze esatte, omogeneità massima). Sono **solo informative**, non entrano nel pacchetto e non fanno fallire il gate; compaiono nella risposta di `GET /api/v1/packs/{id}`.
