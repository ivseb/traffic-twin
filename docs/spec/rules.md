# Regole v1

> Formato: `tt.rules/v1` · Revisione 1.10.1 (passi `.@nome` e `.#text` dei `tt-path` accettati nei riferimenti ai corpi XML, §2, v1.21.0) · Revisione 1.10 (valori calcolati `$derive` §3.15 e corpo d'errore degli effetti `respond` §3.6, v1.20.0) · Revisione 1.9 (condizioni sulla richiesta e sul cliente `cause.when.match` e `outcomes[].when`, attributi del cliente, aggregati, filtri e paginazione delle liste e liste che nessuna entità legge, precondizioni `respond.until`, effetti su tutti gli oggetti del cliente `target_all`, chiavi di più campi, candidati sotto soglia e gruppi di test: §2.3, §2.11–§2.13, §3.8, §3.12–§3.14, §5.2) · Revisione 1.8 (effetti sui record per chiave `target_key`, valori che tornano da soli, contatori e unicità per chiave `respond.limit`, oggetti che compaiono più tardi fuori dalla traccia, cicli di vita con ritorni: §3.8–§3.11) · Revisione 1.7 (effetti delle scritture che non creano e delle letture, valori copiati dalla richiesta, `${not:campo}`, guardie `where`, stato booleano o numerico, selettori GraphQL per campo e proprietario, liste annidate: §3.8, §3.1, §3.2, §2) · Revisione 1.6 (entità preesistenti per cliente, stato per chiave senza id, rimozione, letture riconosciute dal comportamento: §2.8–§2.10, §3.7) · Revisione 1.5 (stato `superseded` e ritiro delle regole approvate, v1.11.1, §5) · Schema: [`schemas/rules.v1.schema.json`](../../schemas/rules.v1.schema.json) · File: `tt-rules.yaml` (o JSON equivalente)

Le regole descrivono il **comportamento nel tempo** dei servizi in termini di causa → effetto. Le produce il miner come bozze, oppure le scrive una persona con l'editor di regole (v1.4, §5.1); le approva una persona, le usano il generatore di mondi e il mock.

**Decisione D1**: i ritardi sono **figurativi**. Il miner non stima distribuzioni di ritardo: registra l'**ordine** degli effetti e un **ordine di grandezza** indicativo. Il campo `after` è un valore proposto e modificabile, non una misura: un valore singolo o un intervallo (§3.3).

Gli esempi di questo documento modellano la demo e-commerce/corriere e sono coerenti con [`demo/GROUND_TRUTH.md`](../../demo/GROUND_TRUTH.md) (R1–R4). L'esempio completo è in §7.

---

## 1. Struttura del file

```yaml
format: tt.rules/v1
generated_at: "2026-10-19T03:00:00Z"
window: { from: "2026-10-05T00:00:00Z", to: "2026-10-19T00:00:00Z" }
entities: [ ... ]   # §2
rules: [ ... ]      # §3 e §4
```

## 2. Entità

Un'**entità** è un oggetto di business che ha un'identità stabile e compare in più operazioni (un ordine, una spedizione). Il mock tiene lo stato **per entità**.

```yaml
entities:
  - name: order
    service: shop-api
    id_domain: order                    # dominio HMAC del suo identificatore negli eventi
    id_field: id                        # campo dell'entità che contiene l'id
    id_prefix: "ORD-SYN-"               # id sintetici: prefisso + numero a 4 cifre (o più)
    created_by:
      op: "POST /orders"
      id: { from: resp.body, path: "$.id" }
      state: { from: req.body, path: "$" }       # lo stato iniziale copia la richiesta…
      defaults: { status: "CONFIRMED", currency: "EUR" }   # …più questi valori
    relations:                                    # §2.2
      - { field: shipmentId, entity: shipment }
    read_by:
      - op: "GET /orders/{id}"
        by: { from: req.path, name: id }
        at: { from: resp.body, path: "$" }
        scope: owner                              # §2.5: ordini altrui → 404
        foreign: not_found
        not_found_example: order-not-found
      - op: "GET /customers/{id}/orders"          # §2.3: lista del cliente
        by: { from: req.path, name: id, owner: true }
        at: { from: resp.body, path: "$.items[*]" }
        scope: owner
        foreign: forbidden                        # lista di un altro cliente → 403
        list: { count: "$.count", order_by: createdAt, order: asc }

  - name: shipment
    service: shipping-ext
    id_domain: shipment
    id_field: shipmentId
    id_prefix: "SHP-SYN-"
    created_by:
      op: "POST /v1/shipments"
      id: { from: resp.body, path: "$.shipmentId" }
      state: { from: req.body, path: "$" }
      defaults: { status: "PENDING" }
    relations:
      - { field: orderId, entity: order }
    read_by:
      - op: "GET /v1/shipments"
        by: { from: req.query, name: orderId, field: orderId }
        at: { from: resp.body, path: "$.items[*]" }
        hidden_when: { status: "PENDING" }        # §2.4: PENDING non è visibile
      - op: "GET /orders/{id}/shipment"           # esposta da un altro servizio
        service: shop-api
        by: { from: req.path, name: id, field: orderId }
        at: { from: resp.body, path: "$" }
        hidden_when: { status: "PENDING" }
        scope: owner
        foreign: not_found
        foreign_example: order-not-found
        not_found_example: shipment-not-found
```

| Campo | Significato |
|---|---|
| `id_field` | Nome del campo di primo livello dell'entità che contiene il suo id |
| `id_prefix` | Prefisso degli id sintetici (`^[A-Z]{2,5}-SYN-$`). Il mock e il generatore assegnano `prefisso + numero progressivo`, con almeno 4 cifre (`SHP-SYN-0091`), contatore per entità e per sessione. Se il dominio `id_domain` ha un formato degli id ([pack.md](pack.md) §4.3), gli id seguono quel formato e il prefisso non si usa |
| `created_by.op` | Operazione che crea l'entità (sempre del `service` dell'entità) |
| `created_by.id` | Dove si trova il suo id nell'evento (serve al miner) |
| `created_by.state` | Facoltativo: parte della **richiesta** da cui il mock copia lo stato iniziale quando serve l'operazione di creazione |
| `created_by.defaults` | Facoltativo: valori iniziali aggiunti dopo la copia (valori `keep`, riferimenti o sintetici, come §3.2) |
| `relations` | Facoltativo: campi che contengono l'id di un'altra entità (§2.2) |
| `read_by[].op` | Operazione che la espone |
| `read_by[].service` | Facoltativo: servizio dell'operazione, se diverso da quello dell'entità (lo shop che espone la spedizione del corriere) |
| `read_by[].by` | Come la richiesta seleziona l'entità: per id (`from: req.path`, `req.query`, …), per un'operazione GraphQL ([event.md](event.md) §6, v1.14) anche una variabile (`from: req.body`, `path: "$.variables.id"`; per id e, dalla 1.7, per campo o proprietario), per un campo (`field`, nome di primo livello dell'entità confrontato col valore del parametro) o per proprietario (`owner: true`, §2.3). Dalla 1.6 anche un membro del **corpo della richiesta** fuori dagli array (`from: req.body`, `path: "$.filters.contractId"`), per id, campo o proprietario (§2.10). Assente: tutte le entità del cliente della sessione (solo liste), oppure il record di un'entità per chiave (§2.9) |
| `read_by[].at` | Dove si trova l'entità nella risposta (`$` = tutto il corpo, `$.items[*]` = elementi di un array, cioè una **lista**; anche annidata, `$.data.contracts.items[*]`, con `list.count` nello stesso involucro, `$.data.contracts.count`, 1.7) |
| `read_by[].hidden_when` | Facoltativo: entità nascoste da questa operazione (§2.4) |
| `read_by[].scope`, `foreign`, `foreign_example`, `not_found_example` | Visibilità per cliente (§2.5) |
| `read_by[].list` | Facoltativo, solo per le liste: conteggi, paginazione e ordinamento (§2.3) |
| `read_by[].key` | (1.6) Solo per le entità per chiave: dove la richiesta porta i valori dei campi della chiave (§2.9) |
| `read_by[].removed_status` | (1.6) Facoltativo: status di una lettura singola per id di un'entità rimossa nella sessione (§3.7); assente: come un'entità che non esiste |
| `seed` | (1.6) Facoltativo: quanti oggetti ha ogni cliente prima di qualsiasi sessione (§2.8) |
| `key`, `upserted_by` | (1.6) Facoltativi: entità senza id proprio, identificata dal proprietario e/o da campi, riscritta da scritture con la stessa chiave (§2.9). Escludono `created_by` |

Un **riferimento** a un punto dell'evento ha sempre la forma `{ from, path }` per i corpi (`req.body`, `resp.body`, con un `tt-path` del [sanitizer](sanitizer.md) §5.0, compresi `.@nome` e `.#text` per gli attributi e il testo dei corpi XML, v1.21.0) o `{ from, name }` per gli altri (`req.path`, `req.query`, `req.headers`, `req.cookies`, `resp.headers`, `resp.cookies`).

### 2.1 Campi nei valori (`fieldValues`)

Nelle mappe `create`, `set`, `where`, `defaults` e `hidden_when`, una chiave è un **percorso puntato** dentro l'entità: `status` è il campo di primo livello, `delivery.eta` è il campo `eta` dentro l'oggetto `delivery`. I nomi dei campi con un punto non si possono indirizzare. Grammatica: `^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`. Se un oggetto intermedio manca, il mock lo crea.

### 2.2 Relazioni tra entità (`relations`)

Una relazione dichiara che il campo `field` di un'entità contiene l'`id_field` di un'entità di tipo `entity` (una chiave esterna). Con `many: true` il campo è un array di id.

```yaml
relations:
  - { field: shipmentId, entity: shipment }   # order.shipmentId → shipment
```

- **Miner**: propone una relazione quando una **chiave di legame** (§3.4) collega il campo `field` delle operazioni che espongono l'entità con l'id di `entity` (stesso dominio HMAC, `x-tt-value.domain` uguale nei contratti) per almeno `k_min` soggetti distinti.
- **Generatore**: nel `world.jsonl` ogni valore di un campo di relazione (se presente e non `null`) DEVE essere l'id di una riga `entity` del tipo indicato, già esistente o creata da una riga `pending` (integrità referenziale).
- **Mock**: verifica l'integrità del mondo all'avvio e rifiuta il pacchetto se un riferimento è rotto. Durante una sessione **non** controlla i valori che arrivano dalle richieste (il servizio sotto test può citare entità che il mock non conosce). Il mock **non inventa mai** un valore per un campo di relazione: se lo stato non lo contiene, il campo esce solo se il contratto lo marca obbligatorio, con il valore `null` se lo schema lo ammette, altrimenti si omette.
- **Valori**: il campo si riempie come qualsiasi altro, con `create`/`set` e i riferimenti di §3.2 (tipicamente `"${ordine}"` o `"${effect:shipment-requested}"`).

### 2.3 Liste e collezioni per cliente

Una `read_by` è una **lista** quando `at.path` termina con `[*]`. Le entità della lista si scelgono così, in quest'ordine:

1. **Selezione**: con `by` per id o per campo, le entità il cui id o campo è uguale al valore del parametro; con `by.owner: true`, le entità il cui **proprietario** (§2.6) è il valore del parametro (`GET /customers/{id}/orders`); senza `by`, le entità del cliente della sessione (`GET /me/orders`).
2. **Visibilità**: si tolgono le entità nascoste (§2.4) e, con `scope: owner`, quelle di un altro cliente (§2.5).
3. **Ordinamento**: per `list.order_by` (percorso puntato; i valori mancanti vanno in fondo; stringhe per byte, numeri per valore) nella direzione `list.order` (default `asc`), poi per id crescente (byte). Senza `order_by`: per id crescente.
4. **Pagina**: si applicano `list.limit` e uno solo tra `list.offset`, `list.page` (da 1) e `list.cursor`. Il limite vale il parametro se presente, altrimenti `default_limit`; un valore oltre `max_limit` si riduce a `max_limit`. Un parametro non intero o negativo è una richiesta non valida (`pointer` `/query/<nome>`, [mock.md](mock.md) §3; `page` accetta solo valori ≥ 1). Casi senza limite (v1.3):
   - **senza limite effettivo** (né parametro né `default_limit`) la pagina contiene tutte le entità dall'`offset` in poi, e `list.next_cursor` è `null` (o assente, §5): la lista è un'unica pagina. Perciò `page` = 1 dà tutto, mentre `page` ≥ 2 dà una **pagina vuota** (`count` 0, `total` invariato); `max_limit` non si applica, perché non c'è un limite da ridurre;
   - un `offset` o un cursore oltre l'ultima entità dà una pagina vuota, mai un errore;
   - `limit` = 0 è un limite valido e dà una pagina vuota, con `total` corretto.
5. **Corpo**: gli elementi vanno in `at`, ognuno costruito dallo schema degli elementi del contratto ([mock.md](mock.md) §2); `list.count` riceve il numero di elementi della pagina, `list.total` quello di tutte le entità dopo il punto 2; con `list.cursor`, `list.next_cursor` riceve il cursore della pagina successiva, oppure `null` (o niente, se lo schema non ammette `null`) all'ultima pagina.

**Filtri (1.9).** `list.filters` (al più 8) tiene, tra il punto 2 e il punto 3, le entità il cui campo `field` (percorso puntato) è uguale al valore del parametro `param` (`{ from: req.query, name }`), confrontati nella forma canonica di §3.12; un parametro assente non filtra. `GET /tickets?status=OPEN` restituisce solo i ticket `OPEN`.

```yaml
        list: { count: "$.count", limit: { from: req.query, name: size }, page: { from: req.query, name: page }, default_limit: 20,
                order_by: createdAt, order: desc, filters: [ { param: { from: req.query, name: status }, field: status } ] }
```

**Miner (1.9, C12).** I parametri di una lista si imparano dai valori in chiaro della query confrontati con la lunghezza dell'array della risposta, sempre con almeno `k_min` soggetti:

- `limit`: un parametro intero con lunghezza ≤ valore nel 99 % delle chiamate e pagine piene (lunghezza = valore) per almeno `k_min` soggetti; `default_limit`: la lunghezza massima `m` (2–1000) delle chiamate senza il parametro, se `m` è anche un valore visto del parametro, raggiunto da almeno `k_min` soggetti;
- `page` o `offset`: un altro parametro intero con minimo 1 (pagina) o 0 (scostamento), quando le pagine successive di un soggetto non ripetono gli oggetti della sua prima pagina (token disgiunti) in almeno `min_share` delle coppie;
- `order_by`/`order`: un campo tempo (fascia `time:`) degli elementi monotono, in una direzione, in almeno `min_share` delle liste con almeno due valori diversi;
- `filters`: un codice in chiaro della query uguale allo stesso campo di **tutti** gli elementi in almeno `min_share` delle liste confrontabili, con almeno due valori.

I cursori non si imparano. Le stesse cose valgono per le liste che nessuna entità legge (§2.13).

I **cursori** sono stringhe opache create dal mock: `c` seguito dall'offset decimale della pagina successiva (`c20`). Un cursore che il mock non ha creato è una richiesta non valida. Gli altri campi dell'involucro (per esempio `customerId` della lista dello shop) seguono le regole dei campi derivati ([mock.md](mock.md) §2), con il proprietario selezionato da `by.owner` al posto del cliente della sessione.

Le operazioni con l'estensione di contratto `x-tt-entity` e **senza** `read_by` sono deprecate: un pacchetto v1.2 DEVE descrivere ogni lista con `read_by`. Per i pacchetti ≤ 1.1 il mock PUÒ continuare a servire queste operazioni come lista delle entità del cliente della sessione (comportamento 1.1).

### 2.4 Entità nascoste (`hidden_when`)

`hidden_when` è una mappa di valori letterali (niente riferimenti `${…}`). Un'entità i cui campi sono **tutti** uguali a quei valori non esiste per quell'operazione: una lista la omette, una lettura di un oggetto singolo risponde come se mancasse (§2.5). Serve, per esempio, per la spedizione `PENDING` che il corriere non mostra finché non diventa `CREATED` (GROUND_TRUTH R3).

**Condivisione tra letture (1.4).** La visibilità è una proprietà dello stato dell'entità e del modo in cui la si seleziona: una lettura che localizza l'entità attraverso lo stesso campo (`by.field`) di un'altra lettura con `hidden_when` ne eredita il valore, se non lo ha. Così `GET /orders/{id}/shipment` dello shop, che passa per il corriere, risponde `404` finché la spedizione è `PENDING` come `GET /v1/shipments?orderId=…`, anche quando i suoi `404` osservati sono troppo pochi per mostrarlo da soli. Il miner lo fa se lo stato non è mai esposto dalla lettura stessa; il mock e gli esportatori lo fanno anche per i pacchetti già prodotti. Le letture per id (`by` senza `field`) e per proprietario non ereditano.

### 2.5 Visibilità per cliente (`scope`, `foreign`)

| `scope` | Comportamento |
|---|---|
| `any` (default) | Nessun filtro per cliente: adatto alle API tra servizi (il corriere chiamato dallo shop con la sua chiave) |
| `owner` | Sono visibili solo le entità del cliente della sessione e quelle **senza** proprietario. Se la sessione non ha un cliente scelto, il filtro non si applica (il mock non autentica) |

Con `scope: owner`, quando la selezione indica una risorsa di un altro cliente il mock risponde secondo `foreign`:

| `foreign` | Quando | Risposta |
|---|---|---|
| `not_found` (default) | lettura singola di un'entità altrui; lista con `by.owner` di un altro cliente | Lo stesso `404` di un'entità che non esiste: **non si rivela che esiste**, come raccomandato per le API con oggetti per utente (OWASP API1, BOLA) e come fa lo shop della demo su `GET /orders/{id}` |
| `forbidden` | come sopra | `403`, come lo shop della demo su `GET /customers/{id}/orders` di un altro cliente |

Nelle liste selezionate per id o per campo le entità altrui si **tolgono in silenzio** (punto 2 di §2.3), senza `403`/`404`.

Il corpo della risposta è l'esempio del contratto per quello status: quello chiamato `foreign_example` (per la risposta `foreign`) o `not_found_example` (per una lettura singola che non trova nulla, compresa un'entità nascosta), altrimenti il primo esempio di quello status. Se il contratto non dichiara quello status, il mock usa l'involucro di errore di [mock.md](mock.md) §3 con codice `not_found` o `forbidden`.

Il miner sceglie `scope: owner` quando, per un'operazione, ogni risposta di successo a un soggetto espone solo entità di quel soggetto, e `foreign` dallo status (`404` o `403`) osservato sulle richieste che citano entità di altri soggetti; altrimenti lascia il default. La persona che approva può cambiarli.

Lo `scope` riguarda **solo** le letture (`read_by`). La creazione e le regole non sono filtrate: un'entità creata in una sessione appartiene al cliente della sessione (§2.6).

### 2.6 Proprietario di un'entità

Ogni entità ha al più un **proprietario**, un cliente sintetico:

- entità del mondo: il campo `customer_id` della riga `entity` (o della riga `pending` che la crea);
- entità create da `created_by` o da un effetto `create` durante una sessione: il cliente della sessione **all'istante della causa**, `null` se la sessione non ne ha uno. Un effetto ritardato conserva il proprietario della sua causa anche se nel frattempo la sessione ha cambiato cliente.

Il proprietario non è un campo dello stato: esce nelle risposte solo come campo derivato ([mock.md](mock.md) §2).

### 2.7 Identità di un'entità tra più team (v1.10)

Una console serve più team (gruppi), ciascuno con i suoi servizi. Un'entità è **l'oggetto che un servizio crea in un dominio HMAC dentro un gruppo**, non il dominio da solo: se lo shop-api del gruppo `demo` e l'orders-api di un altro gruppo creano entrambi un `order`, sono due entità.

- Il miner analizza il traffico di ogni gruppo **separatamente** (il gruppo di un evento è il gruppo della sua sorgente): entità, riferimenti («id già esistente»), identificatori inoltrati da un servizio esterno (domini uniti) e regole nascono solo dagli eventi di un gruppo. Il miner NON DEVE proporre una regola che usa servizi di due gruppi.
- **Nomi.** Il primo creatore di un dominio tiene il nome semplice (`order`); un creatore successivo prende un nome qualificato: `<dominio>-<servizio>` (`order-orders-api`), poi `<dominio>-<servizio>-<gruppo>` se lo stesso servizio esiste in due gruppi, poi un numero. Il nome rispetta il pattern dei nomi di entità (al più 40 caratteri, così gli id degli effetti che ne derivano restano identificatori validi) e ha un `id_prefix` proprio (`ORD-SYN-`, poi le iniziali del servizio: `ORDO-SYN-`).
- **Stabilità.** I nomi dati restano tra un'esecuzione e l'altra, qualunque team abbia più traffico: una regola approvata che scrive `order` continua a scrivere l'`order` dello stesso team. Su una console che ha minato prima di questa versione i nomi si ricavano, alla prima esecuzione, dalle regole già salvate: prima i creatori delle regole `approved`, poi `stale`, `rejected` e `draft`, dalla più vecchia, poi le entità dell'ultima esecuzione; ogni nome semplice va al primo che lo rivendica.
- La firma di una regola causale resta `causal|<servizio>|<operazione>|<dominio>` (una regola già approvata conserva il suo id); quella di una regola batch usa il nome dell'entità. Solo quando lo stesso servizio crea lo stesso dominio in due gruppi la firma del secondo usa il nome qualificato.
- Nel generatore e nel mock un campo con `x-tt-value.domain` si collega all'entità **dello stesso servizio** con quel dominio, altrimenti alla prima entità del dominio.

### 2.8 Entità preesistenti per cliente (`seed`, 1.6)

Nelle applicazioni vere quasi tutto ciò che un utente tocca **esiste già**: contratti, indirizzi, consensi, notifiche. Il traffico li legge, non li crea. Un'entità può quindi non avere `created_by` e avere un `seed`:

```yaml
  - name: contract
    service: app-api
    id_domain: contract
    id_field: id
    id_prefix: "CNT-SYN-"
    seed:
      per_customer: [ { n: "0", share: 0.2 }, { n: "1", share: 0.2 }, { n: "2", share: 0.2 }, { n: "3-5", share: 0.4 } ]
      values: { status: { ACTIVE: 0.8, SUSPENDED: 0.2 } }
      subjects: 60
    read_by:
      - { op: "GET /contracts", at: { from: resp.body, path: "$.items[*]" }, scope: owner, list: { count: "$.count" } }
      - { op: "GET /contracts/{id}", by: { from: req.path, name: id }, at: { from: resp.body, path: "$" }, scope: owner }
```

| Campo | Significato |
|---|---|
| `per_customer` | Fasce di numero di oggetti per cliente e loro quote (somma 1). Una fascia è `"0"`, `"3"`, `"2-5"` (estremi compresi) o `"11+"` |
| `values` | Facoltativo: quote dei valori in chiaro di alcuni campi (al più 16 campi, 64 valori; somma 1 per campo) |
| `subjects` | Conteggio esatto dei soggetti che la distribuzione descrive |

- **Miner.** Un dominio HMAC diventa un'entità con `seed` quando **nessuna scrittura** ne emette mai un token; le letture riuscite lo restituiscono come id proprio di record (`id`, altrimenti l'unico identificativo del record); in almeno il 99% delle osservazioni l'oggetto è del soggetto che legge, per almeno `k_min` soggetti; e non è l'identificativo dell'utente stesso (un token per soggetto, usato per leggere altri oggetti, come `/customers/{id}/orders`). `read_by`, campo di stato, relazioni e ciclo di vita si trovano come per un'entità creata. Il numero di oggetti per soggetto è quello degli oggetti distinti che ha letto; chi ha letto una lista vuota ne ha 0. Le fasce di partenza sono `0`, `1`, `2`, `3-5`, `6-10`, `11-20`, `21+`; le fasce adiacenti si **uniscono** finché ognuna ha almeno `k_min` soggetti (anonimato k: nessuna fascia descrive meno di k persone; un resto sotto k va nell'ultima). `values` contiene i campi stringa con 2–8 valori presenti nel 90% degli oggetti, col campo di stato per primo, e per ogni campo solo i valori visti per almeno `k_min` proprietari.
- **Generatore** (§6.1). Prima della simulazione ogni cliente sintetico riceve, per ogni entità con `seed` (le destinazioni delle relazioni prima), un numero di oggetti estratto dalle fasce (uniforme dentro la fascia; `"11+"` fino al doppio del minimo; al più 50). Lo stato viene dallo schema delle letture dell'entità (la prima lettura singola, altrimenti gli elementi della prima lista), i valori di `values` con le loro quote, i campi di relazione solo verso oggetti del cliente (§2.2: mai inventati), l'id dal prefisso o dal formato degli id del dominio ([pack.md](pack.md) §4.3); proprietario il cliente, creazione all'inizio della finestra (una riga `history`). Gli oggetti preesistenti usano un generatore proprio: un mondo senza `seed` resta identico byte per byte.
- **Mock.** Sono righe `entity` del mondo come le altre: le liste per proprietario e le letture per id li servono in modo coerente per sessione e cliente, e sono bersagli validi delle regole (`target_id`).

### 2.9 Stato per chiave senza id (`key`, `upserted_by`, 1.6)

Un profilo, un carrello, i consensi di un utente, la presa visione di un documento: record **senza un id proprio**, letti per utente (`GET /me/profile`) o per una tupla di selettori della richiesta (`GET /consents/{documentId}`) e riscritti da scritture con la stessa chiave.

```yaml
  - name: consent
    service: app-api
    id_domain: consent
    id_field: id
    id_prefix: "CNS-SYN-"
    key: { owner: true, fields: [documentId] }
    upserted_by:
      - op: "POST /consents"
        key: { documentId: { from: req.body, path: "$.documentId" } }
        state: { from: req.body, path: "$" }
    read_by:
      - op: "GET /consents/{documentId}"
        key: { documentId: { from: req.path, name: documentId } }
        at: { from: resp.body, path: "$" }
```

| Campo | Significato |
|---|---|
| `key.owner` | Il record è del cliente della sessione: ogni cliente ha i suoi |
| `key.fields` | Campi di primo livello del record che, con il proprietario, lo identificano (al più 8). Senza campi c'è un record per cliente (un singleton) |
| `upserted_by[]` | Scritture che creano il record della chiave o ne sostituiscono i membri: `op`, `service` (se diverso), `key` (campo → parametro della richiesta o membro del corpo, **tutti** i campi della chiave), `state` (la parte della richiesta copiata nello stato) |
| `read_by[].key` | Dove la lettura porta i valori della chiave; una lista può darne solo una parte |

`id_domain`, `id_field` e `id_prefix` restano obbligatori ma non sono dati del record: il mock e il generatore danno al record un id interno (`id_prefix` + contatore) che non scrivono nello stato. `key` esclude `created_by`.

- **Miner.** Una lettura candidata ha valori in chiaro nel suo «nodo di stato» (la radice del corpo, o l'unico oggetto annidato: `$.data.profile`) e non è il record di un'entità con id; una scrittura candidata non crea nulla e manda valori in chiaro. Una scrittura W e una lettura successiva R dello **stesso soggetto** formano una coppia: con la chiave del proprietario ogni R si accoppia con l'ultima W del soggetto, con una chiave di selettori (un token della richiesta di R uguale a un token della richiesta di W) solo con l'ultima W che ha mandato lo stesso token. La coppia è coerente quando i membri con lo stesso nome che W ha mandato e R restituisce (almeno uno) sono tutti uguali. Una chiave è accettata per (W, R) quando le coppie coerenti vengono da almeno `k_min` soggetti, sono almeno `min_share` delle coppie e mostrano almeno due valori diversi (una costante non prova nulla); la chiave di selettori vince su quella del solo proprietario e i suoi selettori diventano i campi della chiave. Il nome dell'entità viene dall'oggetto che contiene lo stato o dall'ultimo segmento letterale del path (`consent`), senza collisioni con domini ed entità.
- **Mock.** Una scrittura di `upserted_by` riuscita crea il record del cliente della sessione e della chiave, o ne sostituisce i membri mandati (i campi della chiave restano la chiave); la risposta si costruisce dal record. Una lettura con `key` restituisce il record; se non c'è, risponde **come il contratto** (lo stato di default del servizio: un profilo mai salvato esiste comunque). Ogni sessione ha i suoi record, `reset` li toglie.
- **Generatore.** Non crea record per chiave: il mock risponde come il servizio finché il test non scrive.

### 2.10 Letture riconosciute dal comportamento (1.6)

Un'operazione legge o scrive per **quello che fa**, non per il metodo: una `POST /search`, una mutation GraphQL usata come ricerca, un backend che incapsula ogni chiamata in una POST. Una POST (o una mutation) è una **lettura** quando, sulle sue chiamate riuscite viste per almeno `k_min` soggetti:

- restituisce oggetti che esistono già: la maggior parte delle chiamate restituisce identificativi e al più `1 − min_share` di essi nasce lì (una creazione ne conia uno nuovo a ogni chiamata, anche quando a coniarlo è una chiamata annidata);
- risponde in modo stabile: le richieste uguali (soggetto, token e valori in chiaro della richiesta) restituiscono gli stessi identificativi in almeno `min_share` dei casi ripetuti;
- non cambia quello che restituisce: i valori in chiaro di un oggetto restituito sono uguali a quelli dell'ultima risposta precedente che lo mostrava (di qualsiasi operazione) in almeno `min_share` dei casi confrontabili (un annullamento che restituisce l'ordine con lo stato nuovo è una scrittura).

`PUT`, `PATCH` e `DELETE` non diventano mai letture dal traffico. Una persona può decidere al suo posto, per gruppo e operazione, dalla console («Questa operazione è una lettura»: lettura, scrittura, o di nuovo il traffico; `GET|PUT /api/v1/rules/op-kinds`, audit `rule.op_kind_set`); la scelta vale dall'analisi successiva e vince sul traffico in entrambe le direzioni. Una lettura non crea mai entità e può essere `read_by`; i suoi selettori possono essere membri del corpo (`by`, `key`), che il mock legge dal corpo della richiesta.

### 2.11 Attributi del cliente (`attributes`, 1.9)

Il segmento, il piano, la lingua, il canale preferito: valori che **descrivono il cliente**, uguali in tutte le risposte che lo riguardano (`GET /me`, `GET /offers` con `customer.segment`). Fino alla 1.8 il mock li prendeva dall'esempio o dallo schema, diversi da una risposta all'altra della stessa sessione. Un attributo li lega:

```yaml
attributes:
  - name: segment
    values: { GOLD: 0.3, STANDARD: 0.7 }
    subjects: 120
    fields:
      - { service: app-api, op: "GET /me", at: { from: resp.body, path: "$.segment" } }
      - { service: app-api, op: "GET /offers", at: { from: resp.body, path: "$.customer.segment" } }
```

| Campo | Significato |
|---|---|
| `name` | Nome dell'attributo (`^[a-z][a-z0-9_]{0,31}$`), citato dalle condizioni `customer` (§3.12) |
| `values` | 2–64 valori in chiaro (codici; anche `true`/`false` e numeri scritti come stringhe) con le loro quote (somma 1) |
| `subjects` | Conteggio esatto dei soggetti che la distribuzione descrive (soglia `k_min` del gate) |
| `fields` | 1–32 membri di risposte, fuori dagli array, che portano l'attributo |

- **Generatore.** Ogni cliente sintetico riceve `profile[name]`, estratto dalle quote con un generatore proprio: un mondo senza `attributes` resta identico byte per byte, e con gli attributi cambiano solo le righe dei clienti.
- **Mock.** Il valore della sessione è `profile[name]` del cliente della sessione; senza (nessun cliente, o un mondo che non ce l'ha) si estrae **una volta** per sessione dalle quote con un generatore proprio della sessione e dell'attributo, e resta quello fino al `reset` (lo stesso valore dopo il `reset`). Nelle risposte di successo delle operazioni di `fields` il membro `at` prende quel valore, convertito al tipo dello schema (booleano, intero, numero, stringa), se l'oggetto che lo contiene esiste; lo stato dell'entità vince (un profilo salvato dal test resta quello). Vale anche per le risposte statiche.
- **Miner (C14).** Un membro in chiaro (stringa o booleano; mai token, tempi, fasce, numeri) del nodo di stato delle risposte riuscite è un attributo quando almeno `k_min` soggetti lo leggono almeno due volte, almeno `min_share` di loro vedono sempre lo stesso valore, e almeno due valori sono di almeno `k_min` soggetti ciascuno; i valori sotto `k_min` si tolgono e le quote si ricalcolano. Un membro letto una sola volta per soggetto si unisce a uno così quando, per almeno `k_min` soggetti in comune, dice lo stesso valore. Non sono attributi gli identificativi né il campo di stato di un'entità con ciclo di vita. Il nome è quello del membro in minuscolo con `_` (`customerSegment` → `customer_segment`).
- **Esportatori.** Persi nel report (`customer-attribute`).

### 2.12 Aggregati (`aggregates`, 1.9)

Il numero di notifiche non lette, il totale del carrello, il contatore dei messaggi: un numero di una risposta che **si calcola dalla collezione** del cliente al momento della lettura.

```yaml
aggregates:
  - { service: app-api, op: "GET /me/summary", at: { from: resp.body, path: "$.unread" },
      count: { entity: notification, where: { read: false } }, subjects: 80 }
  - { service: app-api, op: "GET /cart", at: { from: resp.body, path: "$.total" },
      sum: { entity: cart_item, field: price }, subjects: 45 }
  - { service: app-api, op: "GET /me", at: { from: resp.body, path: "$.messages" },
      delta: [ { op: "POST /messages", by: 1 }, { op: "DELETE /messages/{id}", by: -1 } ], subjects: 30 }
```

| Campo | Significato |
|---|---|
| `service`, `op`, `at` | La lettura e il suo membro numerico, fuori dagli array |
| `count` | Numero delle entità di `entity` del cliente i cui campi valgono `where` (valori letterali, facoltativo) |
| `sum` | Somma del campo numerico `field` (percorso puntato) delle stesse entità; i valori non numerici non contano |
| `delta` | 1–8 operazioni: il numero di base più `by` (intero da −1000 a 1000, non 0) per ogni chiamata riuscita di `op` (del `service` indicato o di quello dell'aggregato) nella sessione |
| `subjects` | Conteggio esatto dei soggetti che l'hanno confermato (soglia `k_min` del gate) |

- **Mock.** Solo sulle risposte di successo, dopo la paginazione statica (§2.13) e gli attributi (§2.11): `count` e `sum` contano le entità della sessione non rimosse del cliente della sessione (tutte, se la sessione non ha un cliente) che soddisfano `where`; `delta` parte dal numero che la risposta avrebbe (0 se non è un numero) e aggiunge `by` per ogni chiamata riuscita, compresa quella in corso se è una delle operazioni. Il membro si scrive solo se l'oggetto che lo contiene esiste; un valore intero esce come intero JSON.
- **Generatore.** Non ci sono risposte: si ignorano.
- **Miner (C8).** Per ogni membro numerico (in chiaro o in fascia `num:`, fuori dagli array; non il conteggio della lista stessa) di una lettura riuscita il miner prova: il **numero** di elementi dell'ultima lista dell'entità letta dallo stesso soggetto (al più 200 eventi prima, senza una sua scrittura riuscita in mezzo), anche solo quelli in uno stato (`where`); la **somma** di un campo numerico in chiaro di quegli elementi; il **passo** tra due letture consecutive della stessa operazione dello stesso soggetto, diviso per le chiamate dell'unica scrittura fatta in mezzo (le coppie senza scritture devono restare uguali). Una fascia corrisponde se contiene il valore. Un aggregato si propone con almeno `min_share` dei confronti, almeno `k_min` soggetti e almeno due valori diversi (uno zero costante non prova nulla).
- **Esportatori.** Persi nel report (`aggregate`).

### 2.13 Liste che nessuna entità legge (`lists`, 1.9)

Un catalogo, un elenco di filiali: liste che il mock serve dal contratto (modalità statica, [mock.md](mock.md) §2.5) perché nessuna entità le legge. Con un esempio che ha una pagina piena, un client che pagina fino a una pagina vuota chiederebbe pagine per sempre. `lists` dichiara la paginazione:

```yaml
lists:
  - { service: catalog-api, op: "GET /branches", at: { from: resp.body, path: "$.items[*]" },
      list: { count: "$.count", page: { from: req.query, name: page }, limit: { from: req.query, name: size } } }
```

- **Mock.** Solo quando nessuna `read_by` legge l'operazione. Gli elementi dell'esempio sono l'unica pagina: `page`, `offset`, `limit`, `default_limit` e `max_limit` valgono come in §2.3, i cursori del mock (`c<n>`) pure; una pagina oltre la fine, o un cursore che il mock non ha creato (la fine della lista), dà una pagina vuota con `count` 0 e `total` uguale al numero degli elementi dell'esempio; altri parametri non validi lasciano il corpo com'è. `next_cursor` vale `c<fine>` finché restano elementi, altrimenti `null` (o niente se lo schema non lo ammette).
- **Miner.** Come §2.3, per gli array di primo livello delle letture che nessuna entità copre, viste da almeno `k_min` soggetti, quando ha imparato qualcosa.
- **Esportatori.** Persi nel report (`list-paging`); i filtri delle liste di entità come `list-filter`.

## 3. Regole causa → effetto (`kind: causal`)

```yaml
rules:
  - id: r-0007
    kind: causal
    status: approved                    # draft | approved | rejected | stale | superseded
    title: "Un ordine creato genera una spedizione presso il corriere"

    cause:
      service: shop-api
      op: "POST /orders"
      when: { status: [201] }
      bind:
        order: { from: resp.body, path: "$.id" }

    effects:
      - id: shipment-requested          # immediato: esiste già nella risposta (§3.5)
        entity: shipment
        create: { orderId: "${order}", status: "PENDING" }
        after: 0s
      - id: order-linked                # l'ordine riceve l'id della spedizione
        entity: order
        target_id: "${order}"
        set: { shipmentId: "${effect:shipment-requested}" }
        after_effect: shipment-requested
        after: 0s
      - id: shipment-created
        entity: shipment
        target: shipment-requested
        set: { status: "CREATED" }
        after_effect: shipment-requested
        after: { min: 2m, max: 10m }
      - id: shipment-in-transit
        entity: shipment
        target: shipment-requested
        set: { status: "IN_TRANSIT" }
        after_effect: shipment-created
        after: { min: 1h, max: 6h }
      - id: shipment-delivered
        entity: shipment
        target: shipment-requested
        set: { status: "DELIVERED" }
        after_effect: shipment-in-transit
        after: { min: 6h, max: 36h }
      - id: shipment-cancelled
        entity: shipment
        target: shipment-requested
        set: { status: "CANCELLED" }
        after_effect: shipment-created
        after: { min: 30m, max: 4h }

    outcomes:
      - { name: happy,         p: 0.93, effects: [shipment-requested, order-linked, shipment-created, shipment-in-transit, shipment-delivered] }
      - { name: cancelled,     p: 0.04, effects: [shipment-requested, order-linked, shipment-created, shipment-cancelled] }
      - { name: never-shipped, p: 0.03, effects: [shipment-requested, order-linked] }

    evidence:
      counts:                           # conteggi esatti nella finestra
        causes: 4120
        distinct_subjects: 1310
        outcomes: { happy: 3832, cancelled: 165, never-shipped: 123 }
        key_matches: 3997               # cause il cui id è stato ritrovato nell'effetto
      keys:                             # chiavi di legame usate (§3.4)
        - domain: order
          from: { service: shop-api, op: "POST /orders", at: { from: resp.body, path: "$.id" } }
          to: { service: shipping-ext, op: "POST /v1/shipments", at: { from: req.body, path: "$.orderId" } }
          matches: 4120
        - domain: shipment
          from: { service: shipping-ext, op: "POST /v1/shipments", at: { from: resp.body, path: "$.shipmentId" } }
          to: { service: shop-api, op: "POST /orders", at: { from: resp.body, path: "$.shipmentId" } }
          matches: 4120
      hints:                            # stime, solo per proporre valori
        magnitude: { shipment-requested: seconds, shipment-created: minutes, shipment-in-transit: hours, shipment-delivered: days, shipment-cancelled: hours }

    review:
      by: []
      at: null
      note: ""
```

`never-shipped` contiene comunque la spedizione `PENDING` e il legame con l'ordine: nella demo la spedizione esiste sempre (lo shop risponde con `shipmentId`), ma resta invisibile per sempre (`hidden_when`, §2.4).

**Nomi dei rami (v1.3).** `outcomes[].name` è un identificatore libero (`ident` dello schema): il formato non prescrive un vocabolario e il mock, il generatore, i preset di scenario e l'esportatore li trattano come etichette opache, citate per nome (`scenarios.json`, `POST /__tt/sessions/{s}/scenario`). Il miner non conosce il dominio (non sa che cosa sia «spedita»), quindi nomina i rami che trova con una **convenzione fissa**: `happy` il primo ramo che arriva a uno stato terminale; `never` il ramo in cui l'entità non lascia mai lo stato iniziale; `stuck-<stato>` un ramo fermo in uno stato non terminale; `<stato>` ogni altro stato terminale (lo stato è lo `status` osservato, in minuscolo). Nell'esempio sopra `never-shipped` è il nome che una persona darebbe al ramo che il miner chiama `never`; la demo ([GROUND_TRUTH](../../demo/GROUND_TRUTH.md), `truth.json`) e le fixture della UI usano i nomi «umani». Decisione v1.3: la specifica **non cambia** e il **miner non cambia**; deve cambiare il lato che confronta per nome. I confronti tra regole estratte e verità di riferimento (valutazione del miner, e2e della demo) e i preset che citano un ramo DEVONO riconoscere i rami per **effetti** o mappare esplicitamente `never` ↔ `never-shipped` (`never_shipped` in `truth.json`), non assumere il nome. Dalla v1.4 l'editor di regole cambia anche i rami di una bozza (probabilità ed effetti di ogni ramo, §5.1); il nome di un ramo esistente resta quello del miner.

### 3.1 Campi

| Campo | Significato |
|---|---|
| `cause.when.status` | Status della risposta che fanno scattare la regola |
| `cause.bind` | Variabili legate dalla causa, usabili negli effetti come `"${nome}"` |
| `effects[].create` | Crea un'entità con questi campi |
| `effects[].target` + `set` | Aggiorna l'entità creata **o aggiornata** dall'effetto indicato (della stessa regola) |
| `effects[].target_id` + `set` | Aggiorna l'entità esistente il cui id è la variabile indicata (`"${order}"`), del tipo `entity`. Se l'entità non esiste nella sessione, l'effetto non si applica e non compare in `applied` |
| `effects[].respond` | (v1.4) Cambia le risposte di una chiamata successiva invece di un'entità (§3.6). Esclude `entity`, `create`, `target`, `target_id` e `set` |
| `effects[].remove` | (1.6) `true`: rimuove l'entità di `target` o `target_id` (dalla 1.8 anche `target_key`, §3.7). Esclude `create`, `set` e `respond` |
| `effects[].target_key` + `set` | (1.8) Cambia il **record di un'entità per chiave** (§2.9): quello del cliente della causa (se la chiave ha il proprietario) i cui campi della chiave valgono questi valori, uno per **ogni** campo di `key.fields` (`"${variabile}"` o un letterale; `{}` per il record unico del cliente). Con `set` il record si crea se manca; con `remove` si toglie. Esclude `create`, `target` e `target_id` (§3.8) |
| `effects[].respond.limit` | (1.8) Contatore per chiave: `{ n, window, key }` (§3.9). Esclude `times` |
| `cause.when.match` | (1.9) Condizioni sulla richiesta e sul cliente (§3.12): devono valere tutte, altrimenti la regola non scatta |
| `outcomes[].when` | (1.9) Condizioni di un ramo (§3.12): il ramo è ammesso solo quando valgono tutte |
| `effects[].respond.until` | (1.9) `true`: precondizione (§3.13), la risposta vale dall'inizio della sessione **finché** l'effetto non si applica. Esclude `times`, `limit` e `p` |
| `effects[].target_all` | (1.9) `true`: tutte le entità di `entity` del cliente della causa che soddisfano `where` ricevono `set` (o si rimuovono, `remove`) (§3.14). Esclude `create`, `target`, `target_id` e `target_key`; non può essere `target` né `${effect:…}` di un altro effetto |
| `effects[].where` | (1.7) Facoltativo, solo con `target`/`target_id` + `set`: valori letterali (come `hidden_when`). L'effetto si applica solo se i campi dell'entità sono **tutti** uguali a quei valori; altrimenti non si applica e non compare in `applied`. Il miner lo mette sui passi spontanei di un ciclo di vita quando una scrittura può portare l'entità altrove (§3.8) |
| `effects[].after` | Ritardo **figurativo**: una durata `^[0-9]{1,6}(s\|m\|h\|d)$` oppure un intervallo `{ min, max }` (§3.3) |
| `effects[].after_effect` | Il ritardo parte da quell'effetto invece che dalla causa |
| `outcomes` | Rami alternativi. Le `p` sommano a 1 (tolleranza 0,001). Ogni effetto citato deve esistere; un ramo può non avere effetti. Se un ramo contiene un effetto con `after_effect: X`, `target: X` o un valore `${effect:X}`, **anche X** deve far parte dello stesso ramo. |
| `evidence.counts` | **Conteggi** esatti, calcolati sul magazzino |
| `evidence.keys` | Chiavi di legame trovate dal miner (§3.4); `matches` è un conteggio esatto |
| `evidence.hints` | **Stime**: la UI le mostra in modo diverso dai conteggi |

### 3.2 Valori negli effetti

I valori di `create` e `set` possono essere:

- un riferimento `"${variabile}"` a una variabile di `cause.bind`;
- un riferimento `"${effect:<id effetto>}"`: l'id dell'entità creata o aggiornata da quell'effetto **nella stessa esecuzione** della regola. L'effetto citato DEVE essere un antenato nella catena `after_effect` dell'effetto che lo cita e comparire prima di lui in `effects`, così è sempre già applicato;
- un valore osservato con azione `keep` nella policy (tipicamente un enum come `CREATED`);
- un valore sintetico scritto da una persona;
- (1.7) `"${not:<campo>}"`, solo in `set`: l'opposto del booleano `<campo>` (percorso puntato, §2.1) dell'entità bersaglio quando l'effetto si applica (un interruttore). Se il campo non è un booleano l'effetto non cambia quel campo.

Una variabile legata a un punto della **richiesta** (`from: req.body`, `req.path`, `req.query`, …) vale nel mock il valore che il test manda davvero: un `set` con `"${piano}"` copia il valore della richiesta (§3.8). Un numero copiato resta un numero, un booleano un booleano.

Un riferimento vale solo se è l'**intera** stringa (`"${order}"`, non `"id-${order}"`); per comporre o calcolare si usa un valore calcolato (§3.15). Il gate di pubblicazione verifica che nessun valore derivi da un dato reale non `keep`.

### 3.3 Ritardi a intervallo

`after: { min: 2m, max: 10m }` (con `min ≤ max`, controllato da `tt-core` e da chi legge il pacchetto) significa: il ritardo è un numero **intero di secondi** estratto in modo uniforme in `[min, max]`, estremi compresi.

- Il **mock** estrae all'istante della causa, con il generatore della sessione, subito dopo l'estrazione del ramo: un'estrazione per ogni effetto del ramo con un intervallo, nell'ordine di `effects`. Gli effetti con un valore singolo non consumano estrazioni.
- Il **generatore di mondi** fa lo stesso con il proprio generatore inizializzato dal seed del mondo; stesso seed, stessi ingressi → stessi ritardi.
- `0s` e `{ min: 0s, max: 0s }` sono ammessi e rendono l'effetto **immediato** se lo è anche tutta la sua catena `after_effect` (§3.5).
- Il miner propone un intervallo dall'ordine di grandezza (`hints.magnitude`) e non pubblica mai i ritardi misurati; la persona che approva può scrivere un valore singolo o un intervallo.

### 3.4 Chiavi di legame (miner)

Una **chiave di legame** è una coppia di punti di eventi (servizio, operazione, riferimento) in cui compare lo stesso token HMAC dello stesso dominio. Il miner le usa per collegare una causa ai suoi effetti (ARCHITECTURE §7.2) e per proporre le relazioni (§2.2), e le riporta in `evidence.keys`:

| Campo | Significato |
|---|---|
| `domain` | Dominio HMAC del token (`order`, `shipment`) |
| `from`, `to` | `{ service, op, at }`, con `at` riferimento come in §2 (per gli elementi di una lista: `$.items[*].orderId`) |
| `matches` | Numero esatto di cause il cui token è stato ritrovato in entrambi i punti |

`matches` è un conteggio pubblicato: vale la soglia `k_min` del gate ([pack.md](pack.md) §7). I campi a bassa cardinalità (`status`, `currency`, …) non sono mai chiavi.

Dalle chiavi il miner ricava:

- `bind` della causa: il punto `from` della chiave che parte dalla risposta della causa;
- `create` con un campo uguale a `"${variabile}"`: l'effetto espone il token della causa in quel campo (`orderId`);
- un effetto `target_id` + `set` con `"${effect:…}"`: la risposta della causa o un'entità esistente espone il token dell'entità creata (lo `shipmentId` nella risposta di `POST /orders`), e quindi la relazione `order.shipmentId → shipment`;
- un effetto con `after: 0s`: il token creato compare **già nella risposta della causa** (effetto sincrono, GROUND_TRUTH R2).

### 3.5 Effetti immediati e risposta della causa

Un effetto è **immediato** quando il suo istante di applicazione coincide con l'istante della causa (ritardo estratto 0 e catena `after_effect` tutta a 0). Gli effetti immediati si applicano **prima** di inviare la risposta della causa, così la risposta può già esporre ciò che creano (lo `shipmentId` nella risposta di `POST /orders`). L'ordine preciso è in §6.

### 3.6 Effetti sulle risposte (`respond`, v1.4)

Alcuni comportamenti non sono un cambio di stato di un'entità ma di **come risponde** una chiamata: «dopo l'annullamento di un ordine, la prossima lettura della fattura risponde 410», «dopo un pagamento rifiutato, il corriere fallisce una volta su cinque». Un effetto `respond` lo dice:

```yaml
effects:
  - id: invoice-gone
    respond: { service: billing, op: "GET /invoices/{id}", status: 410, times: 1, example: invoice-gone }
    after: 0s
  - id: carrier-flaky
    respond: { service: shipping-ext, op: "GET /v1/shipments", status: 503, p: 0.2 }
    after_effect: invoice-gone
    after: 1h
```

| Campo | Significato |
|---|---|
| `service`, `op` | La chiamata le cui risposte cambiano: un'operazione del contratto di un servizio del pacchetto (anche diverso da quello della causa) |
| `status` | Lo status della risposta. Il corpo è l'esempio `example` del contratto per quello status, altrimenti il primo; senza esempi lo genera dallo schema, senza schema è l'involucro d'errore di [mock.md](mock.md) §3 |
| `body` | Facoltativo (1.10): il corpo d'errore scritto da una persona (oggetto, array o stringa JSON, al più 16 KiB), che vince su `example`: un'applicazione che legge codici o testi d'errore li riceve realistici. Il gate passa i rilevatori di dati personali su ogni stringa ([mock.md](mock.md) §4.1) |
| `p` | Facoltativo, in `(0, 1]` (default 1): probabilità per ogni chiamata |
| `times` | Facoltativo (default 0 = nessun limite): per quante chiamate vale. `times: 1` è «la prossima chiamata» |

Semantica nel mock: quando l'effetto si applica (dopo il suo ritardo, come gli altri), la **sessione** registra la risposta. Da quel momento ogni chiamata a `service`/`op` della sessione la usa con probabilità `p`, finché non ha risposto `times` volte; con più effetti sulla stessa operazione vale il più vecchio la cui estrazione riesce. Le estrazioni usano un generatore della sessione proprio (stream `responses`), così non spostano né i guasti né gli esiti. Un guasto forzato dal test (modalità `custom` di [mock.md](mock.md) §4) vince sull'effetto; l'effetto vince sui guasti osservati (`observed`), di cui si consuma comunque l'estrazione. La risposta così decisa non fa scattare regole il cui `when` non contiene quello status. Nel registro la chiamata ha `fault: { status, rule }`; tra gli effetti applicati compare con `respond: "<service> <op>"` ed `entity`/`id` vuoti. `reset` toglie le risposte registrate.

Un effetto `respond` non è un'entità: non può essere `target` né `${effect:…}` di un altro effetto, può essere `after_effect`. Il **generatore di mondi** lo ignora (non cambia lo stato del mondo) e gli **esportatori** lo dichiarano perso nel report (gli stub rispondono come osservato).

### 3.7 Rimozione (`remove`, 1.6)

```yaml
  - id: r-0031
    kind: causal
    cause:
      service: app-api
      op: "DELETE /contracts/{id}"
      when: { status: [204] }
      bind: { contract: { from: req.path, name: id } }
    effects:
      - { id: contract-removed, entity: contract, target_id: "${contract}", remove: true, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [contract-removed] }
```

- **Mock.** Quando l'effetto si applica l'entità esce dalla sessione: le liste e i loro conteggi non la contano più, una lettura singola che la seleziona per id risponde `read_by.removed_status` se c'è (per esempio `410`), altrimenti come un'entità che non esiste (`404`, §2.5). Gli effetti successivi su di lei non si applicano. `reset` la riporta. Una regola di un'altra sessione non la vede.
- **Generatore.** L'entità esce dal mondo (resta la sua storia); un effetto oltre `t0` diventa una riga `pending` come gli altri.
- **Miner.** Una scrittura che non crea nulla e cita nella richiesta l'id di un'entità (un `DELETE`, ma anche `POST …/remove`) la **rimuove** quando, dopo, l'oggetto è sparito per chi ha scritto: la prima lista dell'entità dello stesso soggetto non lo restituisce più, oppure la prima lettura per id risponde `404` o `410`. La regola nasce quando la rimozione è confermata per almeno `k_min` soggetti e in almeno `min_share` delle scritture seguite da una lettura che poteva dirlo; una scrittura che cita l'id e lascia l'oggetto al suo posto non è mai una rimozione. Lo status delle letture per id dopo la rimozione, se non è `404` e vale per almeno `k_min` casi e `min_share`, va in `removed_status`. Firma: `causal|<servizio>|<operazione>|<dominio>|remove`.
- **Esportatori.** Gli stub non hanno una rimozione per sessione: l'effetto si dichiara perso nel report (`remove-effect`).

### 3.8 Effetti delle scritture che non creano (1.7)

Quasi tutte le scritture di un'applicazione vera **cambiano** un oggetto che esiste già: un contratto sospeso, un piano cambiato, un indirizzo predefinito scelto, un preferito acceso e spento, una notifica letta. La regola ha come causa la scrittura e come effetto un `set` sull'oggetto citato dalla richiesta:

```yaml
  - id: r-0040
    kind: causal
    cause:
      service: app-api
      op: "PATCH /contracts/{id}"
      when: { status: [200] }
      bind:
        contract: { from: req.path, name: id }
        plan: { from: req.body, path: "$.plan" }             # un codice in chiaro della richiesta
        addressid: { from: req.body, path: "$.addressId" }   # un id della richiesta (token)
    effects:
      - { id: contract-updated, entity: contract, target_id: "${contract}", set: { plan: "${plan}", addressId: "${addressid}" }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [contract-updated] }
  - id: r-0041
    kind: causal
    cause: { service: app-api, op: "POST /contracts/{id}/favorite", when: { status: [200] }, bind: { contract: { from: req.path, name: id } } }
    effects:
      - { id: contract-updated, entity: contract, target_id: "${contract}", set: { favorite: "${not:favorite}" }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [contract-updated] }
```

- **Miner (C2).** Una chiamata riuscita è una causa quando la sua richiesta cita l'id di un oggetto di un'entità con id (creata o preesistente, §2.8): un parametro di path o di query, un membro del corpo fuori dagli array, una variabile GraphQL. Mai la creazione dell'entità stessa. Per ogni chiamata il miner confronta l'**ultima osservazione** dell'oggetto prima della chiamata con la **prima dopo** (fuori dalla sua traccia, prima della chiamata successiva della stessa operazione o di un'altra scrittura che cita l'oggetto, entro l'orizzonte di decisione), con qualsiasi operazione o servizio. Un campo dell'oggetto (un codice, un booleano, un numero o la sua fascia `num:`, un id) entra nell'effetto quando la chiamata spiega il suo valore nuovo, giudicato sulle chiamate dopo le quali poteva cambiare (prima aveva un altro valore), in quest'ordine:
  1. il valore di un membro in chiaro della richiesta (o un numero della richiesta che cade nella fascia osservata): `set` con `"${variabile}"` legata a quel membro; servono almeno due valori diversi, oppure lo stesso nome del campo;
  2. un id della richiesta: l'uguaglianza dei **token** prova l'uguaglianza dei valori senza vederli; `set` con la variabile legata a quel punto della richiesta (nel mock il valore vero del test);
  3. per un booleano, l'opposto del valore di prima, in entrambe le direzioni: `"${not:<campo>}"`;
  4. sempre lo stesso valore: un letterale (un codice, un booleano, un numero; per una fascia il suo estremo inferiore, `num:50-100` → `50`; mai un id).

  Il cambio deve essere visto per almeno `k_min` soggetti, in almeno `min_share` delle chiamate che potevano mostrarlo e con il limite inferiore di Wilson (95 %) di quella quota almeno `min_birth_share`; la confidenza della regola è il più basso di quei limiti. Un letterale o un interruttore deve anche essere **raro senza la chiamata**: tra le osservazioni consecutive degli oggetti senza una chiamata in mezzo (né nell'orizzonte prima), lunghe almeno quanto le finestre delle chiamate, lo stesso cambio deve essere al più la metà più frequente; così un ciclo di vita che avanza da solo non diventa l'effetto di una scrittura. Un valore copiato non ne ha bisogno (l'uguaglianza con la richiesta è la prova). Una **lettura** (C11: una `GET` dopo la quale la notifica risulta letta) è una causa con le stesse regole, ma solo con almeno `k_min` di quei confronti: un oggetto letto a ogni passo e che cambia da solo non ha la lettura come causa.
- **Ritardo.** Quando, per almeno `k_min` soggetti e almeno `1 − min_share` dei cambi, una lettura dopo la chiamata mostra ancora il valore vecchio e una successiva quello nuovo (cache, consistenza eventuale), i campi vanno in un secondo effetto (`<entità>-updated-later`) con un `after` **figurativo** dal suo ordine di grandezza (decisione D1, §3.3); gli altri in `<entità>-updated` con `after: 0s`.
- **Transizioni attribuite.** Se il campo è lo stato dell'entità (§5 del ciclo di vita, anche un booleano o una fascia numerica dalla 1.7) e almeno `min_share` delle transizioni osservate verso quel valore seguono la chiamata, la transizione è della scrittura e **non** è più un esito spontaneo della creazione: la regola della creazione la toglie (con i rami che la attraversano) e mette `where` sui passi spontanei rimasti (ognuno parte solo dallo stato che lascia), così un passo successivo non annulla lo stato impostato dalla scrittura.
- **Firma** `causal|<servizio>|<operazione>|<dominio>|update`; un ramo `always`; `origin` assente (`mined`), stato `draft`: si rivede e si approva come le altre.
- **Mock.** Come ogni `target_id` + `set` (§6): le variabili della richiesta valgono quello che il test manda, `${not:…}` inverte il booleano corrente, `where` si controlla all'istante di applicazione.
- **Generatore.** Simula solo le cause che creano (§6.1): queste regole valgono nel mock; `where` e `${not:…}` valgono anche nel generatore.
- **Esportatori.** Gli stub non hanno stato per sessione: gli effetti di una scrittura su oggetti esistenti si dichiarano persi nel report (`update-effect`), quelli sui record per chiave anche (`keyed-effect`).
- **Record per chiave (1.8).** Un record di un'entità per chiave (§2.9) cambiato da una scrittura che **non** è una sua `upserted_by` (la sottoscrizione alla newsletter che accende un flag del profilo, la firma di un documento che segna il consenso) è il bersaglio di un effetto `target_key`:

  ```yaml
  cause: { service: app-api, op: "POST /documents/{documentId}/sign", when: { status: [200] }, bind: { documentid: { from: req.path, name: documentId } } }
  effects:
    - { id: consent-updated, entity: consent, target_key: { documentId: "${documentid}" }, set: { signed: true }, after: 0s }
  ```

  Il miner osserva il record nelle risposte della sua lettura (il nodo di stato, per soggetto e, con un campo di chiave, per token del selettore della lettura); le cause sono le chiamate riuscite dello stesso soggetto che portano nella richiesta il token della chiave (qualsiasi punto; per il record unico dell'utente, ogni sua chiamata), mai le `upserted_by` né la lettura stessa. I cambi si giudicano come per gli oggetti con id (stesse soglie, ritardo, controllo «raro senza la chiamata»), e il campo della chiave si lega al punto della richiesta che lo porta. Dalla 1.9 anche le **chiavi di più campi**: il record è identificato dal soggetto e dalla tupla dei token dei selettori della lettura, una chiamata è una causa solo se la sua richiesta porta **tutti** i token della tupla (path, query o membro del corpo fuori dagli array), e ogni campo della chiave si lega al punto della richiesta che lo porta più spesso; una chiamata a cui manca un campo non è una causa. Firma `causal|<servizio>|<operazione>|<entità>|update`.
- **Valori che tornano (1.8, C10).** Un letterale impostato dalla chiamata (`SUSPENDED`, un blocco, `true`) che l'oggetto perde da solo dopo un po' — nessuna scrittura lo cita in mezzo, fino alla chiamata successiva della stessa operazione — diventa un secondo effetto: `set` al valore a cui torna (lo stesso per almeno `min_share` dei ritorni), con `where` sul valore impostato, `after_effect` l'aggiornamento e un `after` **figurativo** dall'ordine di grandezza del tempo mediano di ritorno (`<entità>-<campo>-reverted`). Servono ritorni visti per almeno `k_min` soggetti, in almeno `min_share` (limite di Wilson ≥ `min_birth_share`) dei cambi seguiti abbastanza a lungo per dirlo (visti ancora impostati almeno quel tempo mediano dopo la chiamata, oppure tornati). Scadenze, finestre di validità, sospensioni temporanee.
- **Limiti.** Fino alla 1.8 restavano a mano le scritture che cambiano più oggetti dell'utente («segna tutte lette») e i contatori (+1): dalla 1.9 sono `target_all` (§3.14) e gli aggregati (§2.12). I calcoli (totali con sconti, IVA, scadenze) si scrivono a mano come valori calcolati (§3.15, 1.10); resta fuori la logica su valori mascherati.

### 3.9 Contatori e unicità per chiave (`respond.limit`, 1.8)

Una seconda creazione con la stessa email risponde `409`; dopo tre login falliti dello stesso utente il successivo risponde `423`; più di tre preventivi al minuto rispondono `429`. È un solo comportamento: una risposta d'errore spiegata dalle chiamate **precedenti con la stessa chiave**. Lo dice un effetto `respond` con `limit`:

```yaml
  - id: r-0050
    kind: causal
    cause: { service: app-api, op: "POST /accounts", when: { status: [201] }, bind: { email: { from: req.body, path: "$.email" } } }
    effects:
      - { id: limit-409, respond: { service: app-api, op: "POST /accounts", status: 409, limit: { n: 1, key: "${email}" } }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [limit-409] }
  - id: r-0051
    kind: causal
    cause: { service: app-api, op: "POST /login", when: { status: [401] }, bind: { username: { from: req.body, path: "$.username" } } }
    effects:
      - { id: limit-423, respond: { service: app-api, op: "POST /login", status: 423, limit: { n: 3, window: 15m, key: "${username}" } }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [limit-423] }
```

| Campo | Significato |
|---|---|
| `limit.n` | Da quante chiamate contate in poi la chiamata risponde `status` (1–100000) |
| `limit.window` | Facoltativo: la finestra (una durata, figurativa come i ritardi); assente: tutta la sessione (unicità) |
| `limit.key` | Facoltativo: `"${variabile}"` legata alla **richiesta** della causa; con la chiave `service`/`op` del `respond` sono quelli della causa (la chiave si legge dalle chiamate contate e da quelle a cui si risponde). Assente: per cliente |

Le chiamate contate sono quelle della causa che fanno scattare la regola (`when`): le creazioni riuscite per l'unicità, i login falliti per i tentativi, le chiamate riuscite per un limite di frequenza. `p` vale come sempre; `times` è escluso.

- **Mock** ([mock.md](mock.md) §2.7): ogni applicazione dell'effetto conta una chiamata per la sua chiave; una chiamata di `service`/`op` la cui chiave ha almeno `n` chiamate contate negli ultimi `window` risponde `status` con l'esempio. Un guasto forzato e gli effetti `respond` registrati vincono sul contatore, il contatore vince sui guasti osservati.
- **Generatore.** Come ogni `respond`: non cambia il mondo, si ignora.
- **Miner (C7).** Per ogni operazione e ogni status `4xx` visto per almeno `k_min` soggetti prova: una chiave (un token della richiesta presente in almeno `min_share` delle chiamate, oppure il soggetto); che cosa si conta (le chiamate riuscite, oppure quelle fallite con un altro `4xx`); una finestra tra tutta la finestra, `1m`, `15m`, `1h` e `1d`. Per ogni chiamata calcola il suo **ordinale**: le chiamate contate con la sua chiave nella finestra prima di lei. Il limite `n` è l'ordinale da cui le chiamate rispondono quello status. Il candidato migliore (richiamo + precisione) si propone quando le chiamate con quello status a un ordinale ≥ `n` sono almeno `min_share` di tutte (richiamo), le chiamate a quegli ordinali hanno quello status in almeno `min_share` dei casi con limite di Wilson ≥ `min_birth_share` (precisione), vengono da almeno `k_min` soggetti e almeno `k_min` chiamate sotto `n` passano (un contatore, non un'operazione che fallisce sempre). A parità vince tutta la finestra, poi la più corta. Una chiamata preceduta, dopo la chiamata precedente con la stessa chiave, da una scrittura di un'**altra** operazione che cita un suo id non conta (un `404` dopo un `DELETE` è una rimozione, §3.7, non un contatore); uno status che arriva a caso (il 5 % delle chiamate) non ha mai la precisione. L'esempio resta quello del contratto per lo status (il miner non nomina gli esempi). Firma `causal|<servizio>|<operazione>|limit|<status>`.
- **Esportatori.** Come ogni `respond`: perso nel report (`response-effect`).

### 3.10 Oggetti che compaiono più tardi, fuori dalla traccia (1.8)

Un ticket aperto per una richiesta, un documento emesso per una richiesta, l'ordine definitivo che sostituisce quello provvisorio: oggetti che nessuna scrittura catturata conia, che compaiono in una lettura **dopo** la creazione di un altro oggetto e ne citano l'id. La creazione è la loro causa, anche se nascono fuori dalla sua traccia (le creazioni annidate di §3.4 vedono solo le chiamate fatte servendo la causa):

```yaml
    cause: { service: app-api, op: "POST /requests", when: { status: [201] }, bind: { request: { from: resp.body, path: "$.id" } } }
    effects:
      - { id: ticket-created, entity: ticket, create: { requestId: "${request}", status: "NEW" }, after: { min: 1m, max: 59m } }
      - { id: request-replaced, entity: request, target_id: "${request}", remove: true, after_effect: ticket-created, after: 0s }
```

Nessun campo nuovo: l'entità B (qui `ticket`) non ha né `created_by` né `seed` (i suoi oggetti vengono dalle creazioni di A, nel mondo come nel mock); «A nascosto quando esiste B» (l'id provvisorio sostituito dal definitivo) è una rimozione legata all'effetto che crea B.

- **Miner (C9).** Un'entità candidata a `seed` (§2.8) è invece creata dalla regola di A quando: almeno `min_share` dei suoi oggetti citano in un campo (una sua relazione) un oggetto di un'entità con `created_by`; gli oggetti che citano un A creato nella finestra, dopo la sua creazione e fuori dalla sua traccia, vengono da almeno `k_min` soggetti; e almeno `min_birth_share` delle creazioni di A il cui utente poteva vederlo (una lista di B letta dallo stesso utente abbastanza tardi: almeno il primo quartile dei tempi di comparsa) l'hanno avuto. Il `create` porta il campo legato alla causa e i valori costanti di B alla prima osservazione (uno stato iniziale). Il ritardo è figurativo: quando, per almeno `k_min` soggetti e `1 − min_share` degli oggetti, una lista di B letta dopo la creazione non lo mostrava ancora, dall'ordine di grandezza del tempo mediano di comparsa; altrimenti `0s`. La rimozione di A si aggiunge quando, comparso B, A sparisce per l'utente (la lista di A non lo restituisce più, o la lettura per id risponde `404`/`410`, come in §3.7) per almeno `k_min` soggetti e `min_share` delle coppie che potevano dirlo, e A era visibile prima per almeno `k_min` soggetti. Il ciclo di vita di B, se ha passi spontanei, segue nella stessa regola come per una creazione annidata. Diagnostica dell'entità con codice `later`. Un B che cita solo l'utente resta un `seed`.

### 3.11 Cicli di vita con ritorni (1.8)

L'ordine degli stati di §5 del ciclo di vita è una precedenza: uno stato rivisto dopo uno successivo (`ACTIVE → BLOCKED → ACTIVE`, un link che torna valido, una finestra di riprova che si chiude) non ne è un arco. Il miner conta a parte, sulle storie degli oggetti, questi **ritorni** `b → a` (con `a` prima di `b`): quanti oggetti, quanti soggetti, quanti senza una scrittura che cita l'oggetto in mezzo, quanto è durato `b`.

- Un ritorno fatto **da solo** (senza scritture in mezzo per almeno `min_share` degli oggetti, per almeno `k_min` soggetti) diventa un effetto della regola della creazione: `set` di nuovo ad `a`, con `where` su `b`, `after_effect` il passo verso `b` e un `after` figurativo dal tempo mediano in `b` (`<entità>-<a>-again`). Gli oggetti la cui ultima transizione è quel ritorno formano un esito proprio, `<a>-again` (convenzione dei nomi di §3: un oggetto tornato non è un oggetto che «non si è mai mosso»).
- Un ritorno fatto **da una scrittura** è la regola di aggiornamento di quella scrittura (§3.8); uno che arriva da solo dopo un aggiornamento è il suo «valore che torna» (§3.8).
- Le regole già minate senza ritorni restano invariate.

### 3.12 Esiti ed effetti condizionati (`cause.when.match`, `outcomes[].when`, 1.9)

Il bonifico istantaneo che fallisce più spesso dall'app che dal web, la richiesta di un cliente `GOLD` approvata subito, il pagamento sopra una soglia che passa dalla verifica manuale: lo stesso evento ha esiti diversi secondo **un valore della richiesta o del chiamante**.

```yaml
    cause:
      service: app-api
      op: "POST /transfers"
      when:
        status: [201]
        match: [ { at: { from: req.body, path: "$.type" }, in: [INSTANT, STANDARD] } ]
      bind: { transfer: { from: resp.body, path: "$.id" } }
    outcomes:
      - { name: happy-app, p: 0.25, effects: [transfer-done], when: [ { at: { from: req.headers, name: x-channel }, in: [APP] } ] }
      - { name: failed-app, p: 0.15, effects: [transfer-failed], when: [ { at: { from: req.headers, name: x-channel }, in: [APP] } ] }
      - { name: happy, p: 0.55, effects: [transfer-done] }
      - { name: failed, p: 0.05, effects: [transfer-failed] }
```

Una **condizione** è un oggetto:

| Campo | Significato |
|---|---|
| `at` | Un valore della richiesta: un membro del corpo fuori dagli array (`from: req.body`, `path`), un parametro della query, un header (nome in minuscolo) o un parametro del path (`name`) |
| `customer` | In alternativa ad `at`: un attributo del cliente (§2.11) |
| `in` | 1–64 valori scalari: la condizione vale se il valore è uno di questi |
| `min`, `max` | In alternativa a `in`: un numero in `[min, max)` (almeno uno dei due) |

I valori si confrontano nella **forma canonica**: un numero (anche una stringa che è un numero: `"100"` e `100` sono uguali) nella forma decimale più corta, `true`/`false`, le altre stringhe come sono. Un valore assente non soddisfa mai una condizione.

- `cause.when.match` (1–8 condizioni): devono valere **tutte**, altrimenti la regola non scatta (come uno status che non corrisponde) e non si estrae nulla.
- `outcomes[].when` (1–8 condizioni): sono **ammessi** i rami il cui `when` vale; se nessuno dei rami con `when` vale, quelli senza `when`. Il ramo si estrae tra gli ammessi con le loro `p` rinormalizzate; l'estrazione si consuma comunque. Senza rami ammessi la regola scatta con un ramo vuoto (nel registro esito `""`, nessun effetto). Lo scenario che forza un ramo per nome vince sulle condizioni. Le `p` sono probabilità **congiunte** (ramo e gruppo di valori) e sommano a 1 su tutti i rami.
- **Mock.** Le condizioni sulla richiesta si leggono dalla richiesta del test, quelle sul cliente dal valore dell'attributo della sessione (§2.11). Le regole senza condizioni estraggono esattamente come prima.
- **Generatore.** Non ha richieste: le condizioni sulla richiesta non si valutano (si considerano vere in `cause.when.match`); quelle sul cliente si valutano sugli attributi del cliente sintetico. Il ramo si estrae con le `p` dei rami le cui condizioni sul cliente valgono, compresi quelli senza `when`: con le probabilità congiunte la distribuzione complessiva degli esiti resta quella osservata. Un mondo con solo condizioni sulla richiesta è identico byte per byte a uno senza.
- **Miner (C6).** Solo per le regole di creazione con più rami. Le sorgenti candidate sono i valori in chiaro della richiesta della causa (membri del corpo, query, header, fasce `num:`) e gli attributi del cliente della causa. Per ogni sorgente: i valori di almeno `k_min` soggetti restano, gli altri formano un gruppo «resto»; sorgenti con più di 64 valori non si provano. Il test del chi quadrato di Pearson sull'indipendenza tra valore ed esito (gradi di libertà `(righe − 1)(colonne − 1)`; se un conteggio atteso è sotto 5 il valore meno frequente passa nel resto) deve dare `p < 0,01` divisa per il numero di sorgenti provate (Bonferroni); vince la più significativa (a pari merito la richiesta sul cliente, il corpo sull'header). Per ogni valore tenuto ogni esito di almeno `k_min` soggetti diventa il ramo `<nome del miner>-<valore>` con `when`; una fascia diventa `min`/`max` (`100-500`, `from-250`, `below-0`); il resto tiene i rami senza `when` (sempre con `k_min` soggetti). Le `p` sono le quote congiunte. Una regola le cui distribuzioni non differiscono resta identica byte per byte; un valore mascherato (token, forma) non dà mai una condizione. La struttura confrontata con le bozze precedenti contiene `when`: una condizione cambiata è una bozza nuova.
- **Esportatori.** Perse nel report (`conditional-outcome`): gli stub rispondono come osservato.

### 3.13 Precondizioni (`respond.until`, 1.9)

«Il checkout risponde 409 finché il carrello è vuoto», «il riepilogo risponde 404 finché il profilo non è completato»: una risposta di errore che vale **dall'inizio** e smette dopo una certa chiamata.

```yaml
    cause: { service: app-api, op: "POST /cart/items", when: { status: [201] } }
    effects:
      - { id: until-409, respond: { service: app-api, op: "POST /checkout", status: 409, until: true }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [until-409] }
```

- **Mock.** Dall'inizio della sessione (e dopo ogni `reset`) le chiamate di `service`/`op` rispondono `status` con l'esempio del contratto, finché l'effetto non si applica (la causa è stata vista nella sessione, più il ritardo); da lì rispondono normalmente. Ordine: guasto forzato (`custom`) > risposte registrate (§3.6) > precondizioni (la prima non ancora tolta, in ordine di regola) > contatori (§3.9) > guasti osservati. La risposta così decisa passa per le regole con quello status come ogni guasto; tra gli effetti applicati la rimozione compare con `respond: "<service> <op>"`.
- **Generatore.** Si ignora (come ogni `respond`). **Esportatori:** perso nel report (`response-effect`).
- **Miner (C17).** Per ogni operazione X e status `4xx` S visto per almeno `k_min` soggetti, contro ogni scrittura Y (diversa da X) riuscita per almeno `k_min` soggetti: per soggetto, le chiamate di X **prima** della sua prima Y riuscita (tutte, se Y non compare) e quelle **dopo**. Precisione: le S prima su tutte le chiamate prima ≥ `min_share`, limite di Wilson ≥ `min_birth_share`; richiamo: le S prima su tutte le S ≥ `min_share`; dopo: le risposte `2xx` dopo ≥ `min_share`; almeno `k_min` soggetti con una S prima e un successo dopo. Vince la Y con la somma più alta; una coppia X, S già spiegata da un contatore (§3.9) non si propone. Firma `causal|<servizio Y>|<operazione Y>|until|<servizio X>|<operazione X>|<status>`.

### 3.14 Tutti gli oggetti del cliente (`target_all`, 1.9)

«Segna tutte come lette», «archivia tutti i messaggi», «disattiva tutte le carte»: una scrittura che non cita un oggetto ma cambia **tutti** quelli del cliente.

```yaml
    cause: { service: app-api, op: "POST /notifications/read-all", when: { status: [204] } }
    effects:
      - { id: notification-read-all, entity: notification, target_all: true, where: { read: false }, set: { read: true }, after: 0s }
    outcomes:
      - { name: always, p: 1, effects: [notification-read-all] }
```

- **Mock.** Quando l'effetto si applica, ogni entità di `entity` il cui proprietario è il cliente della causa (nessun proprietario: quelle senza proprietario) e i cui campi valgono `where` riceve `set` (con `${variabile}` e `${not:campo}`) o si rimuove (`remove: true`); ognuna compare in `applied`.
- **Generatore.** Come nel mock sulle entità del mondo; un effetto oltre `t0` diventa una riga `pending` per ogni entità del cliente al momento della causa (gli oggetti che il cliente crea dopo non sono coperti).
- **Miner.** Solo entità con id. Gli oggetti di un soggetto sono quelli visti solo in risposte a lui. Le cause sono le scritture riuscite (non la creazione dell'entità) la cui richiesta non porta token dell'entità. Prima e dopo come in §3.8 (fino alla chiamata successiva della stessa operazione, a una scrittura che cita l'oggetto o all'orizzonte); il valore nuovo è un codice o un booleano (mai un numero o un id). Una chiamata è coerente quando almeno `min_share` degli oggetti giudicati (quelli che prima non avevano il valore) l'hanno preso. Serve: chiamate coerenti di almeno `k_min` soggetti, almeno `k_min` chiamate coerenti in cui due o più oggetti cambiano, quota delle coerenti ≥ `min_share` con Wilson ≥ `min_birth_share`, cambio raro senza la chiamata. `where` con il valore di prima quando è lo stesso per almeno `min_share` degli oggetti; ritardo figurativo come in §3.8. Un effetto per campo, `<entità>-<campo>-all`. Firma `causal|<servizio>|<operazione>|<dominio>|update_all`.
- **Esportatori.** Perso nel report (`update-effect`).

### 3.15 Valori calcolati (`$derive`, 1.10)

Il miner non vede i calcoli (totali, limiti residui, scadenze, numeri di documento). Una persona li scrive con l'editor di regole: un valore di `create` o `set` di un effetto causale (anche con `target_key` e `target_all`) PUÒ essere un oggetto con la sola chiave `$derive`, calcolato quando l'effetto si applica.

Rispetto a quello che il miner già impara: una copia semplice di un valore della richiesta resta `"${variabile}"` (§3.2, §3.8); un conteggio o una somma **letti** sulle entità del cliente al momento della risposta sono un aggregato (§2.12). `$derive` serve per i valori **scritti** nello stato quando l'effetto si applica (un totale con l'IVA, un residuo, una scadenza, un numero di pratica), che dopo non cambiano da soli.

```yaml
set:
  total:    { $derive: { fn: round, args: [ { $derive: { fn: mul, args: [ { $derive: { fn: sum, args: ["${field:items[*].price}"] } }, 1.22 ] } } ] } }
  residual: { $derive: { fn: sub, args: ["${field:limit}", "${amount}"] } }
  dueDate:  { $derive: { fn: date, offset: "+30d", format: date } }
  number:   { $derive: { fn: template, template: "'PR'-{orderId#-1|trim0}-NNNN" } }
```

| `fn` | Argomenti | Risultato |
|---|---|---|
| `copy` | 1 (anche un testo) | il valore (più valori: un array) |
| `sum` | 1–8, anche liste (`[*]`) | la somma dei numeri |
| `count` | 1 | quanti valori (o la lunghezza dell'array) |
| `add`, `mul`, `min`, `max` | 2–8 | somma, prodotto, minimo, massimo |
| `sub`, `div` | 2 | differenza, quoziente (divisione per zero: il campo si omette) |
| `round` | 1, `digits` 0–6 (default 2) | arrotondamento |
| `date` | 0–1 (data di partenza, default l'orologio), `offset` (`+30d`, `-12h`, `90m`, `45s`, default `+0d`), `format` `date` / `date-time` (default) | orologio virtuale (o data di partenza) + scarto |
| `template` | nessuno, `template` = un formato degli id ([pack.md](pack.md) §4.3) | il valore numero *n* del modello (contatore per regola, effetto e campo); `{campo}` legge i campi dell'entità |

Gli **argomenti** sono numeri, riferimenti o valori calcolati annidati (al più 4 livelli): `${variabile}` (di `cause.bind`), `${field:percorso}` (un campo dell'entità, con `[*]` per ogni elemento di un array: `${field:items[*].price}`), `${effect:id}` (stesse regole di §3.2), `${now}` (l'orologio). I valori si calcolano dopo i valori letterali dello stesso effetto, in ordine di chiave, e ognuno vede quelli calcolati prima: in `create` l'entità nuova, in `set` lo stato dell'entità aggiornata. Un riferimento senza valore o un calcolo impossibile lascia il campo com'era (come un `${var}` non risolto). I numeri escono interi quando lo sono, altrimenti con al più 9 decimali.

- **Controlli.** `tt-core`, il caricatore del pacchetto e il miner verificano la forma (funzione, numero di argomenti, scarto, modello), che le variabili siano legate dalla causa e gli effetti citati antenati; contro i contratti (§5.1) che i campi letti esistano nell'entità (`unknown_field`) e che il tipo del risultato vada bene per il campo scritto (`derived_type`: un numero in un campo stringa, un testo in un campo numerico); una forma sbagliata è `bad_derived`.
- **Esportatori.** Gli stub non calcolano: il campo si omette e il report lo dichiara perso (`derived-value`).
- **Mondo e mock.** Il generatore e il mock calcolano allo stesso modo (stesso codice); le stringhe generate da `date` e `template` sono sintetiche per il gate; i modelli del mondo usano un ambito diverso da quelli del mock, così non si ripetono. Le regole batch e `where`, `defaults`, `hidden_when` restano scalari.

## 4. Regole batch (`kind: batch`)

Cambi spontanei, non preceduti da una scrittura di un utente.

```yaml
  - id: r-0012
    kind: batch
    status: approved
    title: "Consolidamento notturno delle consegne"
    schedule: "0 2 * * *"               # cron a 5 campi, UTC
    entity: shipment
    where: { status: "IN_TRANSIT" }
    set: { status: "DELIVERED" }
    fraction: 0.6                       # quota delle entità che soddisfano where
    evidence:
      counts: { runs: 14, entities_changed: 9800 }
      hints: { schedule_confidence: high }
```

## 5. Ciclo di vita

| Da | A | Chi |
|---|---|---|
| — | `draft` | Miner |
| `draft` | `approved` / `rejected` | Revisore |
| `approved` | `stale` | Miner (confidenza in calo) o drift del contratto |
| `stale` | `approved` / `rejected` | Revisore |
| `approved` / `stale` | `superseded` | Alla **approvazione** di una regola che la sostituisce (v1.11.1) |
| `approved` / `stale` | `rejected` | Revisore («ritira», `retired`, v1.11.1) |

Solo le regole `approved` entrano nel pacchetto twin. Il miner **non** modifica mai una regola `approved` o `rejected`: propone una nuova bozza con un nuovo `id` e un campo `supersedes`.

**Regola sostituita (`superseded`, v1.11.1, test di usabilità 5).** Quando si approva una regola che ne sostituisce un'altra, la vecchia lascia l'insieme attivo nella stessa operazione: diventa `superseded` e non entra più in nessun pacchetto né mondo. Una regola `A` è sostituita dalla regola approvata `B` se `B.supersedes = A`, oppure se hanno la stessa firma del miner e `B` è più recente (le regole scritte a mano hanno ciascuna la propria firma e si sostituiscono solo per `supersedes`). Nel test 5 r-0018 (approvata) e r-0019 (che la sostituiva, approvata) restavano attive insieme: due serie di effetti per la stessa causa, un 5% di CANCELLED diventato 1% e uno scenario forzato su CANCELLED che finiva DELIVERED. La vecchia regola conserva corpo, evidenze e revisione (storia); `superseded_by` dice chi la sostituisce; non si riapprova né si modifica. Una console che ha entrambe le regole approvate (prima di questa versione) le sistema all'avvio. Il revisore può inoltre **ritirare** una regola approvata (`POST /api/v1/rules/{id}/retire`): diventa `rejected` (`retired`), esce dai pacchetti, il miner non la ripropone finché la sua struttura non cambia.

### 5.1 Regole scritte a mano e modifica delle bozze (v1.4)

Il miner trova ciò che il traffico mostra (causa → effetto attraverso id condivisi, cambi di stato, frequenze degli esiti, batch); non vede calcoli (totali, IVA), logica su valori mascherati o scartati, rami rari, regole su conteggi («dopo 3 resi il cliente è bloccato»). Una persona li scrive con l'editor di regole (`POST /api/v1/rules` dell'API di amministrazione):

- `origin` (facoltativo, `mined` | `manual`; assente = `mined`): chi ha scritto la regola. Una regola `manual` nasce `draft` con conteggi zero (`evidence.counts` a 0: nulla è stato osservato) e segue la stessa revisione delle altre (un amministratore può approvarla da solo, con audit). Il miner non la propone, non la aggiorna e non la rende mai `stale`.
- La definizione si controlla contro i **contratti** e le **entità**: servizio e operazione della causa e degli effetti `respond`, campi dei riferimenti di `bind` (presenti nella richiesta, nella risposta o tra i parametri), campi di `create`/`set`/`where` (presenti nelle letture dell'entità), nomi degli esempi. Un riferimento sconosciuto rifiuta la regola; uno status mai osservato è solo un avviso.
- La definizione di una bozza (anche del miner: condizioni, effetti, rami, calendario, valori) si può sostituire (`PUT /api/v1/rules/{id}`). Una bozza del miner modificata così resta `origin: mined`; le ricerche successive ne aggiornano solo i conteggi e tengono la definizione della persona. Modificare una regola `approved` o `stale` crea una nuova bozza con `supersedes`; una regola `rejected` non si modifica.
- Nel pacchetto, nel mondo e nel mock una regola `manual` vale esattamente come una regola del miner.

### 5.2 Candidati sotto soglia e gruppi di test (1.9)

Con k = 20 un ambiente di test con pochi tester non produce regole (vincolo trasversale della roadmap). Due strumenti:

- **Candidati sotto soglia (C0).** Dopo l'analisi normale il miner ripete, per ogni gruppo, la ricerca con `k_min` = 2 (o il k del gruppo di test), sullo stesso traffico e senza salvare nulla (nomi delle entità compresi). Una regola che questa ricerca trova e quella normale no, vista da meno di k soggetti, è un **candidato** nella diagnostica dell'analisi (`candidates` di `GET /api/v1/rules/status`): **solo struttura** — tipo (`create`, `update`, `keyed_update`, `update_all`, `remove`, `limit`, `precondition`, `later`, `revert`), operazione, entità, nomi dei campi, valori in chiaro di `set`/`create`/`where` (codici e booleani), status e operazione di un effetto `respond` — e il numero di soggetti **in fasce** (`1`, `2-4`, `5-9`, `10+`, sempre sotto k): nessun esempio, nessun token, nessun conteggio esatto. `draft` è lo scheletro della regola per l'editor (origine `manual`, stato `draft`, conteggi a zero, niente chiavi né stime); `missing_entities` elenca le entità che la bozza usa e che l'analisi non ha accettato (viste da meno di k soggetti): la bozza si salva solo quando esistono. Al più 200 candidati; un gruppo con più di `miner.candidate_max_events` eventi (0 = default 2 000 000; −1 spegne i candidati) non si ripete (la ricerca ripetuta costa circa quanto quella normale). Nella console: «Candidati sotto soglia», **Crea bozza** apre l'editor (§5.1) precompilato; il modello dell'editor (C18: «una scrittura cambia un campo di una lettura», «scade dopo», «al massimo n», «finché non») viene dal tipo del candidato. La regola salvata è una regola `manual` come le altre.
- **Gruppi di test (k ridotto).** Un amministratore può segnare un gruppo come **di test** con un k più basso (`PUT /api/v1/fleet/groups/{group}/test-k`, `{ "k_min": n, "reason": "…" }`, n da 2 a k − 1, motivazione obbligatoria; 0 lo toglie; audit `fleet.group_test_k` con il k e la motivazione). Il miner analizza quel gruppo con `k_min` = n (e `min_distinct` ridotto in proporzione, almeno 2) e lo dice nella diagnostica (`test_k`); i candidati usano lo stesso n. Un pacchetto di **un solo** gruppo di test si costruisce, si controlla con il gate e si firma con `k_min` = n e porta l'avviso `test_k` (k usato e k dell'installazione); un pacchetto di più gruppi o multigruppo tiene il k dell'installazione (le regole a k ridotto non passano il gate: è il risultato sicuro). La console mostra il k ridotto sul gruppo, sulle sue regole e sui pacchetti. Mai sotto 2: con un solo tester nessuna regola. Vedi [THREAT_MODEL](../THREAT_MODEL.md) §7.

## 6. Semantica nel mock

Per servire una richiesta che corrisponde a un'operazione del contratto, il mock:

0. decide la risposta: guasto iniettato ([mock.md](mock.md) §4) oppure risposta normale, con il suo status (dalla 1.9 nell'ordine guasto forzato, risposte registrate, precondizioni §3.13, contatori §3.9, guasti osservati);
1. se la risposta è di successo e l'operazione è `created_by.op` di un'entità, crea l'entità: id generato (`id_prefix` + contatore), stato iniziale da `created_by.state` e `created_by.defaults`, `id_field` impostato all'id generato, proprietario = cliente della sessione (§2.6); se è una scrittura di `upserted_by` (1.6), crea o aggiorna il record della chiave (§2.9);
2. costruisce la **prima stesura** del corpo di risposta dallo stato corrente ([mock.md](mock.md) §2);
3. per ogni regola causale (in ordine di `id`) il cui `cause` corrisponde a servizio, operazione e status che **il mock stesso** ha deciso, la regola scatta: le variabili di `bind` si leggono dalla richiesta e dalla prima stesura; (1.9) se `cause.when.match` non vale la regola non scatta e non si estrae nulla; si sceglie un ramo tra quelli ammessi da `outcomes[].when` (§3.12) (quello forzato da uno scenario della sessione, altrimenti un'estrazione pesata dalle `p` con il generatore della sessione; l'estrazione si consuma comunque); si estraggono i ritardi a intervallo (§3.3); ogni effetto del ramo va in coda con istante = istante della causa (o dell'effetto `after_effect`) + ritardo, sull'**orologio virtuale** della sessione;
4. applica subito gli effetti immediati (§3.5) messi in coda al punto 3, nell'ordine di coda;
5. se al punto 4 è cambiato qualcosa, ricostruisce il corpo dallo stato aggiornato; altrimenti invia la prima stesura. Gli id già presenti nella prima stesura non cambiano.

Poi:

6. Quando l'orologio raggiunge l'istante di un effetto in coda, l'effetto si applica all'entità. A parità di istante si applicano prima gli effetti pendenti del mondo (in ordine di `seq`, [pack.md](pack.md) §5), poi quelli messi in coda durante la sessione (nell'ordine di coda, che per una stessa esecuzione è l'ordine di `effects`), poi i batch.
7. Un effetto `set` che non cambia nulla (per esempio `DELIVERED` già impostato dal batch) non si applica e non compare in `applied`. Un effetto `target_id` su un'entità che non esiste non si applica, né uno con `where` (1.7) su un'entità i cui campi non sono più quei valori.
8. Se la risposta della causa è un guasto iniettato (es. 503), la regola **non** scatta, perché lo status non corrisponde a `when`.
9. Le regole batch scattano quando l'orologio virtuale attraversa un istante del `schedule`. La scelta delle entità (`fraction`) usa il generatore della sessione, in ordine di id: si prendono `round(fraction × n)` entità tra le `n` che soddisfano `where`.
10. Le letture (`read_by`) applicano `hidden_when` (§2.4), `scope`/`foreign` (§2.5) e, per le liste, §2.3 (filtri compresi); quelle per chiave §2.9, quelle di un'entità rimossa §3.7.
11. (1.9) Ogni corpo di successo, alla prima stesura e a ogni ricostruzione: paginazione delle liste statiche (§2.13), poi attributi del cliente (§2.11), poi aggregati (§2.12).

### 6.1 Semantica nel generatore di mondi

Il generatore costruisce il mondo **in avanti nel tempo** fino a `t0`, con le stesse regole del mock (punti 1–7 e 9) e il proprio generatore inizializzato dal seed:

- simula solo le operazioni chiamate dai clienti sintetici (il mix di endpoint degli archetipi); le regole la cui causa è un'operazione chiamata da un altro servizio (per esempio `POST /v1/shipments` del corriere, chiamata dallo shop) valgono solo nel mock, quando il servizio sotto test la chiama;
- prima della simulazione crea gli oggetti preesistenti di ogni cliente (`seed`, §2.8);
- (1.8) ignora gli effetti `target_key` (i record per chiave non sono nel mondo, §2.9) e i contatori (`respond.limit`, come ogni `respond`): la regola resta utilizzabile per gli altri effetti; gli oggetti creati più tardi da una creazione (§3.10) nascono come ogni `create`;
- (1.9) dà a ogni cliente gli attributi (§2.11), valuta le condizioni sul cliente e non quelle sulla richiesta (§3.12), applica `target_all` (§3.14), ignora precondizioni, aggregati e liste statiche (non ci sono risposte); in un pacchetto di più gruppi tiene solo i campi degli attributi, gli aggregati e le liste dei servizi del gruppo, e lascia fuori una regola che cita un attributo tolto (`attribute:<nome>`);
- ogni cambiamento applicato prima di `t0` diventa una riga `history`; lo stato a `t0` diventa la riga `entity`;
- ogni effetto di un ramo già scelto ma con istante **dopo** `t0` diventa una riga `pending` ([pack.md](pack.md) §5), con l'id assegnato in anticipo se l'effetto crea un'entità.
- un mondo di un gruppo usa le regole approvate i cui servizi sono tutti del gruppo. Se il gruppo ha regole approvate (la causa è un suo servizio) e **nessuna** si può usare (tutte chiedono un servizio di un altro gruppo, o non sono valide), la generazione si rifiuta con `422 no_usable_rules` e `details` (`rule`, `reason` `out_of_scope` con i `services` mancanti, oppure `unusable` con `detail`), invece di produrre un mondo vuoto in silenzio. Se ne resta almeno una, il mondo si genera e la risposta elenca in `excluded_rules` le regole del gruppo lasciate fuori. Le regole la cui causa è un servizio di un altro gruppo non si nominano mai.

## 7. Esempio completo della demo

Oltre a `r-0007` (§3) e `r-0012` (§4), il pacchetto della demo contiene la regola vista dal lato del corriere, che serve quando il servizio sotto test è lo shop e il mock fa da corriere: l'entità nasce da `created_by` di `POST /v1/shipments` (`PENDING`) e la regola ne fa avanzare lo stato.

```yaml
  - id: r-0008
    kind: causal
    status: approved
    title: "Una spedizione chiesta al corriere diventa visibile e poi viene consegnata"
    cause:
      service: shipping-ext
      op: "POST /v1/shipments"
      when: { status: [202] }
      bind:
        shipment: { from: resp.body, path: "$.shipmentId" }
    effects:
      - id: shipment-created
        entity: shipment
        target_id: "${shipment}"
        set: { status: "CREATED" }
        after: { min: 2m, max: 10m }
      - id: shipment-in-transit
        entity: shipment
        target: shipment-created
        set: { status: "IN_TRANSIT" }
        after_effect: shipment-created
        after: { min: 1h, max: 6h }
      - id: shipment-delivered
        entity: shipment
        target: shipment-created
        set: { status: "DELIVERED" }
        after_effect: shipment-in-transit
        after: { min: 6h, max: 36h }
      - id: shipment-cancelled
        entity: shipment
        target: shipment-created
        set: { status: "CANCELLED" }
        after_effect: shipment-created
        after: { min: 30m, max: 4h }
    outcomes:
      - { name: happy,         p: 0.93, effects: [shipment-created, shipment-in-transit, shipment-delivered] }
      - { name: cancelled,     p: 0.04, effects: [shipment-created, shipment-cancelled] }
      - { name: never-shipped, p: 0.03, effects: [] }
    evidence:
      counts:
        causes: 4120
        distinct_subjects: 1310
        outcomes: { happy: 3832, cancelled: 165, never-shipped: 123 }
        key_matches: 3997
      keys:
        - domain: shipment
          from: { service: shipping-ext, op: "POST /v1/shipments", at: { from: resp.body, path: "$.shipmentId" } }
          to: { service: shipping-ext, op: "GET /v1/shipments", at: { from: resp.body, path: "$.items[*].shipmentId" } }
          matches: 3997
```

Limite noto della v1.2: un valore scelto a caso tra più valori nello stesso ramo (il `cancelReason` 50/50 di GROUND_TRUTH R3) non si esprime; per riprodurlo si divide il ramo in due esiti con `set` diversi.

## Appendice A. Capacità causa → effetto (C0–C18)

Le note di versione ([README](README.md)) e i commenti del codice citano le capacità del miner e del mock con un codice. Sono comportamenti generici: si imparano dal traffico mascherato (token HMAC, codici in chiaro, fasce, forme, tempi, conteggi con anonimato k) e dalla configurazione della console, mai da nomi, percorsi o formati di un'applicazione.

Il caso più comune nelle applicazioni è la **modifica di oggetti che esistono già e appartengono all'utente** (profilo, contratti, consensi, notifiche, carrello), con l'effetto visibile su un'altra operazione, con un altro formato di id, su un altro sistema o dopo un ritardo.

| Id | Capacità | Cosa fa | Spec |
|---|---|---|---|
| C0 | Candidati sotto soglia come bozze guidate | strutture viste da meno di k soggetti mostrate in fasce, «crea bozza» precompilata; k ridotto facoltativo per i gruppi di test (con audit) | v1.18.0 |
| C1 | Entità preesistenti per utente («seme») | domini mai creati da una scrittura ma letti per soggetto diventano entità senza `created_by`, con la distribuzione in fasce del numero per cliente; il mondo li genera per ogni cliente sintetico | v1.15.0 |
| C2 | Effetti delle scritture che non creano | differenza tra la lettura prima e dopo una scrittura che cita il token di un'entità o il soggetto; valore nuovo costante, copiato da un codice o da un token della richiesta; ritardo osservato → `after`; stato anche booleano o numerico in fascia | v1.16.0 |
| C3 | Stato per chiave senza id | singleton per soggetto o per tupla di token/codici della richiesta (profilo, carrello, consensi, presa visione); upsert alla scrittura | v1.15.0 |
| C4 | Rimozione e appartenenza alle liste | effetto `remove` appreso da `DELETE` → assente in lista e `404` | v1.15.0 |
| C5 | `POST` di sola lettura | operazione classificata dal comportamento (nessun token nuovo, risposte stabili) o scelta in console; selettori dai campi del corpo | v1.15.0 |
| C6 | Esiti condizionati dalla richiesta e dal chiamante | `when` per esito su codici in chiaro, header in chiaro, fasce d'importo, attributi del cliente; appreso da distribuzioni diverse per valore (≥ k per valore) | v1.18.0 |
| C7 | Unicità e contatori per chiave | seconda creazione con la stessa chiave → conflitto osservato; n chiamate per chiave in una finestra → risposta osservata | v1.17.0 |
| C8 | Aggregati dalle collezioni | conteggio per stato, somma, ±1 per scrittura, calcolati alla lettura | v1.18.0 |
| C9 | Oggetti collegati che compaiono più tardi, fuori traccia | B visto solo in una lettura che cita il token di A → `create B` con ritardo; «A nascosto quando esiste B» (id provvisorio → definitivo) | v1.17.0 |
| C10 | Stati temporanei e cicli | ciclo di vita con cicli, transizioni attribuite a una scrittura o al tempo, «torna a X dopo» | v1.17.0 |
| C11 | Letture con effetto | una `GET` come causa di C2 (letto/non letto) | v1.16.0 |
| C12 | Liste: paginazione, ordinamento, filtri | `limit`/`page` dal rapporto con la lunghezza, ordinamento da fasce monotone, filtri per codice | v1.18.0 |
| C13 | Pagina di terzi legata all'esito | il bottone scelto forza esito o stato dell'entità; URL di ritorno da un campo della richiesta | — |
| C14 | Identità da un header JSON; attributi del cliente coerenti in sessione | identità da un percorso dentro un header JSON; attributi del cliente scelti una volta per sessione | v1.18.0 |
| C15 | Famiglie di domini HMAC unibili | domini dichiarati equivalenti nella policy, candidati proposti dalla struttura | v1.18.0 |
| C16 | Selettori GraphQL per campo e proprietario, liste annidate | | v1.16.0 |
| C17 | Precondizioni | `respond` con `until`: default finché non si è vista una causa | v1.18.0 |
| C18 | Modelli nell'editor | «la scrittura X cambia F della lettura Y», «scade dopo», «al massimo n», precompilati da C0, C2 e C7 | v1.18.0 |

Vincolo trasversale: con k = 20 soggetti un ambiente di test con pochi tester non produce regole automatiche; C0 rende il percorso guidato anche lì. Restano a una persona (editor di regole, valori calcolati §3.15) i calcoli con regole di prezzo, la logica su importi mascherati e le condizioni sulle regole di aggiornamento.
