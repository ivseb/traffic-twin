# Policy v1.3 (fase Osserva: spec v1.6.1)

> Formati: `tt.policy/v1` (autore, YAML) → `tt.policy.body/v1` (corpo compilato, JSON) → `tt.policy.compiled/v1` (busta firmata).
> Schemi: [`schemas/policy.v1.schema.json`](../../schemas/policy.v1.schema.json), [`schemas/policy-compiled.v1.schema.json`](../../schemas/policy-compiled.v1.schema.json). Revisione 1.3, campo `hosts` della v1.5, fase **Osserva** e classificazione «apre valori» della **v1.6** (§5, §6, §7), azione `code` della **v1.11** (§1.5, §7), famiglie di domini HMAC, soggetto da un header JSON e gruppi di test della **v1.18** (§1.7, §7.1, §7.5): vedi il changelog in [README.md](README.md).

La policy decide **cosa esce** dalla produzione. Esiste in due forme:

| Forma | Chi la scrive | Chi la legge | Formato |
|---|---|---|---|
| **Autore** | Persona, oppure assistente policy della UI | `tt-core` | YAML, comodo da scrivere e revisionare |
| **Compilata** | `tt-core`, firmata da `tt keyguard` | SDK, `tt-egress`, adattatori | JSON firmato con Ed25519, senza ambiguità |

Le sorgenti **non** leggono YAML: ricevono solo la forma compilata. Così nessun SDK deve includere un parser YAML.

---

## 1. Forma autore (`tt.policy/v1`)

```yaml
format: tt.policy/v1
policy_id: p-shop                 # ^[a-z0-9][a-z0-9-]{0,62}$
default: drop                     # unico valore ammesso: documenta il principio

hmac:
  kid: k1                         # chiave con cui le sorgenti calcolano i token
  accept_kids: []                 # altre chiavi accettate durante una rotazione
  epoch: "2026-10"                # cambia l'epoca → cambiano tutti i token
  families: {}                    # v1.18, solo forma autore: domini uniti (§1.7)

identity:
  subject: { from: header, name: authorization, jwt_claim: sub }

sampling:
  rate: 0.05                      # 0..1, al massimo 4 decimali → 500 punti base
  trust_baggage: false            # vale solo per i servizi con match.internal = true
  propagate_to: []                # host interni verso cui aggiungere tt.s al baggage

segments:
  auto_words: false               # parole minuscole nei path in chiaro, solo a tempo
  allow: [v1, v2]                 # letterali sempre ammessi nei path senza template
  hosts_allow: []                 # host esterni non in policy che escono esattamente come scritti

hosts:                            # opzionale (v1.5): host esterni senza base
  discovery: auto                 # auto (default): escono come pattern (sanitizer §3.5); off: host:unlisted

limits:                           # opzionale: valori di default se assente
  max_body_bytes: 1048576
  max_depth: 32
  max_array: 32
  max_keys: 256
  keep_max_bytes: 64

discovery:                        # opzionale, solo durante l'onboarding
  enabled: false

global:
  request:
    headers: { content-type: keep }
  response:
    headers: { content-type: keep }
  errors:
    body:
      $.error.code: keep

services:
  shop-api:
    match: { inbound: true }
    ops:
      "POST /orders":
        response:
          $.id: hmac(order)       # scorciatoia: le chiavi che iniziano con "$" sono regole del corpo
          $.status: keep
          $.total: bucket(num, [0, 50, 100, 250])
      "GET /orders/{id}":
        request:
          path: { id: hmac(order) }

  shipping-ext:
    match: { base: "https://api.carrier.example" }
    errors:
      body:
        $.error.code: keep
    ops:
      "POST /v1/shipments":
        request:
          body:
            $.orderId: hmac(order)
        response:
          $.shipmentId: hmac(shipment)
          $.status: keep
      "GET /v1/shipments":
        request:
          query: { orderId: hmac(order) }
        response:
          $.items[*].orderId: hmac(order)
          $.items[*].shipmentId: hmac(shipment)
          $.items[*].status: keep
          $.items[*].eta: bucket(time, day)
```

### 1.1 Azioni

| Scrittura | Significato |
|---|---|
| `drop` | Esce solo la forma. Su un contenitore, lo collassa (con i limiti di §5.0 del [sanitizer](sanitizer.md)). |
| `keep` | Esce il valore (stringhe fino a `keep_max_bytes`, numeri con lessema entro i limiti) |
| `code` | (v1.11) Esce il valore solo se è un **codice**: stringa di 2–32 lettere ASCII, `_` o `-`, niente cifre né spazi ([sanitizer](sanitizer.md) §5.6); altrimenti la forma. Solo sui campi ammessi da §1.5; non apre valori (§7.1) |
| `code(alnum)` | (v1.19) Come `code`, con la forma dei **codici brevi con cifre**: 1–16 caratteri tra lettere ASCII, cifre, `_`, `-` e `.` (`0000123450`, `2.1`, `R`); altrimenti la forma. Stessi campi e stessa guardia di cardinalità (§1.5.1) |
| `graphql` | (v1.14) Sul documento GraphQL della richiesta esce la sua **forma** (`gql:`: nomi, nessun valore); sui nomi di un risultato di introspezione esce il nome, solo quando la richiesta chiede soltanto lo schema ([sanitizer](sanitizer.md) §5.7); altrimenti la forma. Solo dove lo ammette §1.6; non apre valori (§7.1) |
| `hmac` | Token con dominio `id` |
| `hmac(order)` | Token con dominio `order`; il dominio rispetta `^[a-z][a-z0-9_-]{0,31}$` e non è riservato |
| `bucket(num, [0, 50, 100])` | Fascia numerica; confini strettamente crescenti come double, da 1 a 32, lessemi ≤ 64 byte |
| `bucket(time, day)` | Fascia temporale; unità `year`, `month`, `day`, `hour` |

### 1.2 Parti e grammatica dei nomi

Dentro `request`, `response` ed `errors`:

| Chiave | Contenuto | Grammatica dei nomi | Dove |
|---|---|---|---|
| `path` | `nome-parametro → azione` | `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, deve comparire come `{nome}` nel template | **Solo** nelle operazioni |
| `query` | `nome → azione` | `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$` (regola delle chiavi, §9.3 del sanitizer) | Ovunque |
| `cookies` | `nome → azione` | Come `query` | Ovunque |
| `headers` | `nome → azione` | ``^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$`` (minuscolo) | Ovunque |
| `body` | `tt-path → azione` | §5.0 del sanitizer | Ovunque |
| `$...` | Scorciatoia per `body` | | Ovunque |

Un nome che non rispetta la grammatica non potrebbe mai corrispondere a nulla in uscita, quindi lo schema lo rifiuta.

### 1.3 Servizi

`match` vale una di queste forme:

- `{ inbound: true }` oppure `{ inbound: true, internal: true }`. `internal: true` dichiara che il servizio **non** è raggiungibile da Internet: solo su questi servizi si può fidarsi del baggage (§12 del sanitizer).
- `{ base: "https://host[:porta][/segmento…]" }`. Il compilatore normalizza la base come §3.1 del sanitizer (minuscolo, porta di default tolta) e rifiuta le basi con host non valido (anche i letterali IPv6 tra parentesi).

### 1.3.1 Host esterni (`hosts`, v1.5)

`hosts.discovery` decide come escono gli host esterni che nessuna `base` dichiara e che non sono in `segments.hosts_allow` ([sanitizer](sanitizer.md) §3.1, §3.5):

| Valore | Effetto |
|---|---|
| `auto` (default, anche senza il blocco `hosts`) | L'host esce come **pattern**: etichette sicure in chiaro, le altre `{*}`, gli IP solo come `ip:private` / `ip:public`. Ogni host chiamato è visibile nel registro degli host (`GET /api/v1/hosts`) e si può gemellare con una bozza di policy (`POST /api/v1/hosts/{pattern}/twin`) |
| `off` (modalità stretta) | L'host esce come `host:unlisted`, come prima della v1.5 (decisione D-S3). Durante la modalità scoperta escono comunque i pattern |

La modalità stretta serve dove anche un solo evento con un'etichetta sicura ma personale (un sottodominio per cliente con il nome della persona) è inaccettabile, prima che l'intake la collassi ([event.md](event.md) §5.2).

### 1.4 Regole di validazione (oltre allo schema)

`tt-core` DEVE rifiutare la policy se:

- due chiavi di operazione dello stesso servizio hanno lo stesso metodo e template equivalenti (stessi letterali, parametri in posizioni uguali);
- un parametro in `path` non compare nel template dell'operazione;
- un `tt-path` non rispetta la sintassi;
- la stessa regola compare due volte nella stessa parte (per esempio come `$.id` scorciatoia **e** dentro `body`), anche con azioni uguali;
- un dominio HMAC è riservato (`subject`, `sample`, `sample-trace`, `discovery`);
- c'è un `keep` su un nome di header tra `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key` (lista minima, non configurabile);
- c'è un `keep`, `hmac` o `bucket` su un `tt-path` che contiene un passo jolly (`.*` o `[*]`) nelle regole **globali** (`global.*`);
- `sampling.rate` non è tra 0 e 1, o non è un multiplo esatto di 0,0001 (la conversione in punti base si fa in aritmetica **decimale**, non in double: `0.05` → `500`);
- i confini di un `bucket(num)` non sono strettamente crescenti **dopo** la conversione in double, o un lessema supera 64 byte;
- `discovery.enabled = true` senza `discovery.expires_at`, oppure con `expires_at` non successivo alla compilazione o oltre **7 giorni** dalla compilazione;
- `segments.auto_words = true` senza `segments.auto_words_expires_at`, o con una scadenza oltre 7 giorni;
- un host di `sampling.propagate_to` corrisponde all'host di una `base` della policy;
- `hmac.accept_kids` contiene `hmac.kid`, o ha più di 4 voci;
- **(v1.11)** c'è un `code` su un campo che non rispetta §1.5 (nome che non è di stato o di codice, cookie, parametri `code` e `state` della query, header di credenziali, `tt-path` che non finisce con un nome); c'è un `code` su un `tt-path` con un passo jolly nelle regole **globali** (come `keep`);
- **(v1.8.1, red team round 4)** il documento YAML usa ancore (`&a`), alias (`*a`), chiavi di fusione (`<<`) o tag espliciti (`!!binary`, `!!str`, `!tag`): il testo che una persona legge deve voler dire esattamente il corpo che keyguard firma (`!!binary a2VlcA==` diventerebbe `keep`). Chiavi duplicate e documenti multipli erano già rifiutati; i nomi con caratteri simili ma non ASCII (cirillico, larghezza piena, spazi di larghezza zero) non rispettano la grammatica e non si compilano.

**Dalla v1.3** (normativo, vedi [hardening.md](hardening.md) §2): `tt-core` e keyguard rifiutano anche un `keep` **o `hmac`** su un header tra `authorization`, `cookie`, `set-cookie`, `proxy-authorization` (nelle parti `request`, `response` ed `errors`, globali o di operazione; il divieto di `keep` su `x-api-key` resta come sopra). Altrimenti una sorgente, che dalla v1.3 rifiuta quelle policy, scarterebbe una policy che le persone hanno approvato. Lo stesso vale per i passi jolly (`.*` o `[*]`) nelle regole globali con `keep` o `hmac` (già coperto dal punto sopra) e per le finestre di scoperta e parole automatiche oltre 7 giorni (già coperte).

### 1.5 Campi di stato e di codice (`code`, v1.11)

**Decisione di progetto.** Gli stati e i codici escono senza approvazioni, in modo strettamente limitato: la sorgente lascia uscire solo valori con la forma di un codice ([sanitizer](sanitizer.md) §5.6) e `tt-core` e keyguard accettano `code` solo su campi il cui **nome** dice che sono uno stato o un codice. Su qualsiasi altro campo la policy è **rifiutata** dalla validazione (non classificata come «apre valori»: un `code` che si potesse approvare su `$.name` sarebbe solo un `keep` con un nome diverso).

**Nome del campo.** È l'ultimo passo del `tt-path` (che DEVE essere un passo `.name`: `$`, `.*` e `[*]` finali sono rifiutati), oppure il nome del parametro di path, della query o dell'header. Il nome si divide in **parole**: sui separatori `_`, `-`, `.` e sui cambi di maiuscola (`orderStatus` → `order status`, `HTTPStatus` → `http status`, `error2Code` → `error2 code`); le parole si confrontano in minuscolo. Il campo è di stato o di codice se:

1. l'**ultima parola** è nella lista chiusa: `status`, `state`, `type`, `kind`, `reason`, `code`, `error`, `outcome`, `result`, `stage`, `phase`, `step`, `mode`, `method`, `channel`, `level`, `severity`, `priority`, `tier`, `event`, `action`, `currency`, `unit`, `format`, `verdict`, `decision` (quindi anche `orderStatus`, `payment_state`, `cancelReason`, `error_code`, `errorCode`, `category_code`, `x-order-status`);
2. **nessuna parola** è tra le esclusioni, che indicano segreti, codici personali o postali e credenziali: `auth`, `authorization`, `oauth`, `access`, `refresh`, `verification`, `verify`, `otp`, `totp`, `mfa`, `pin`, `secret`, `security`, `reset`, `activation`, `confirmation`, `invite`, `invitation`, `referral`, `promo`, `coupon`, `voucher`, `gift`, `discount`, `postal`, `zip`, `post`, `postcode`, `password`, `passcode`, `pass`, `token`, `session`, `api`, `key`, `login`, `recovery`, `sms`, `captcha`, `nonce`, `csrf`, `xsrf`, `signature`, `sig`, `hash`, `salt`, `license`, `serial`, `tracking`, `bank`, `iban`, `swift`, `bic`, `tax`, `vat`, `fiscal`, `ssn`, `passport` (quindi **non** `zipCode`, `promo_code`, `verificationCode`, `token_type`, `session_state`);
3. non è un **cookie** (i cookie portano lo stato della sessione, non gli stati del dominio);
4. nella **query** non si chiama `code` né `state` (in qualsiasi maiuscola): sono i parametri della risposta di autorizzazione OAuth 2.0 (RFC 6749 §4.1.2) e portano segreti monouso;
5. non è un header di credenziali (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`; vedi anche [hardening.md](hardening.md) §2 H1).

Non sono campi di stato, per esempio: `name`, `city`, `user`, `email`, `address`, `description`, `note`, `comment`, `title`, `category` (testo libero), `statusText`, `statuses`, `id`, `orderId`. Per loro resta `keep` con le approvazioni di §5.

La lista è normativa e chiusa: aggiungere o togliere una parola è un cambiamento della specifica (minor), con i test di `internal/policy` (`CodeName`, `CodeRuleAllowed`). Le sorgenti **non** ricontrollano il nome (non serve: `tt-core` e keyguard rifiutano la policy, e keyguard ricalcola la classificazione da solo, §7.3); applicano sempre la forma di §5.6 del sanitizer.

Rischio residuo dichiarato: un valore personale con la forma di un codice in un campo di stato (un soprannome in `type`, un cognome in `reason`) esce in chiaro senza persone. Lo mitigano la soglia k (un valore entra in contratti, regole, mondi e pacchetti solo se l'hanno visto almeno k = 20 soggetti distinti, come ogni valore `keep`), i rilevatori di dati personali del gate e la quarantena di cardinalità dell'intake ([threat model](../THREAT_MODEL.md)).

### 1.5.1 Codici con cifre e campi scelti da una persona (v1.19)

**Decisione di progetto.** I codici delle applicazioni reali hanno spesso cifre o un solo carattere (codici di prodotto, di punto vendita, di canale, versioni, classi): senza di loro le regole e i mock non distinguono i casi. La forma `code(alnum)` li fa uscire con limiti più stretti (al più 16 byte), e una persona può scegliere `code` (di entrambe le forme) anche su campi il cui nome non è di stato o di codice. Il comportamento è generico: nessun nome di un'applicazione.

**Dove è ammesso.** `tt-core` e keyguard accettano `code` e `code(alnum)` su ogni campo che rispetta i punti 2–5 di §1.5 (nessuna parola esclusa, niente cookie, niente `code`/`state` della query, niente header di credenziali) e il cui nome **non finisce** con una parola personale: `name`, `firstname`, `lastname`, `surname`, `fullname`, `nickname`, `username`, `email`, `mail`, `phone`, `mobile`, `fax`, `address`, `street`, `city`, `birthdate`, `birthday`, `dob`, `gender`, `user`, `customer`, `client`, `person`, `owner`, `holder`, `contact` (`policy.CodeRuleSafe`). Nei corpi XML il nome di `.@attr` è `attr` e quello di `.#text` è il nome dell'elemento. Il punto 1 (l'ultima parola nella lista chiusa) resta il criterio della versione Osserva automatica (§7.4), non quello di una persona. Le sorgenti, come sempre, lasciano uscire solo valori con la forma scelta.

**Proposte automatiche.** La versione Osserva propone `code(alnum)` (con `fleet.observe.code_digits`, default attivo) sui campi di §1.5 la cui forma osservata più frequente è `drop:str:digits`, oppure `drop:str:l8`/`l32` quando l'ultima parola è `code`, `type`, `kind`, `level` o `tier` (`policy.CodeAlnumWords`); sugli altri campi di §1.5 propone `code`.

**Guardia di cardinalità.** I valori `keep:` di un campo (anche quelli di `code` e `code(alnum)`) si contano nell'intake per policy, servizio, operazione, parte e percorso ([event.md](event.md) §5.2). Oltre **50 valori distinti** il campo va **in quarantena** da solo: i valori salvati e futuri si riscrivono come forme, la coda di quarantena lo mostra con l'allarme `value_cardinality` e la spiegazione («sembra un identificativo»), e la versione Osserva **non propone più** `code` su quel campo, nemmeno dopo che la quarantena è chiusa. Lo scioglimento resta un'apertura (2 approvazioni, §5).

**Soglia k.** Come per `keep`, un valore di codice entra in contratti, regole, mondi e pacchetti solo se l'hanno visto almeno `k_min` soggetti distinti.

Rischio residuo dichiarato: un identificativo breve con meno di 50 valori in tutto (un codice cliente in un'installazione piccola) o un valore personale breve in un campo scelto da una persona esce in chiaro senza approvazioni. Lo limitano la forma (16 byte, niente spazi), la soglia k, la guardia di cardinalità e i rilevatori del gate ([threat model](../THREAT_MODEL.md), M25).

### 1.6 Documenti GraphQL (`graphql`, v1.14)

Un servizio GraphQL espone un solo endpoint e scrive l'operazione nel corpo ([sanitizer](sanitizer.md) §5.7). La regola `graphql` non apre valori, quindi la versione Osserva la mette da sola (§7.4); `tt-core` e keyguard la accettano **solo** in questi punti, e rifiutano la policy (validazione, non classificazione) in ogni altro:

| Lato | Dove |
|---|---|
| Richiesta (operazione o servizio) | il corpo `$.query` (JSON `{query, variables, operationName}`), il corpo intero `$` (`application/graphql`), il parametro di query `query` (GET) |
| Risposta (operazione o servizio) | un `tt-path` del corpo che inizia con `$.data.__schema` o `$.data.__type`, senza passi `.*` (i nomi di un risultato di introspezione: `$.data.__schema.types[*].name`, `$.data.__schema.types[*].fields[*].args[*].type.ofType.name`…) |
| Mai | regole globali, regole `errors`, header, cookie, parametri di path, altri `tt-path` |

Le regole di risposta sono la seconda linea: la sorgente lascia uscire un nome solo con il cancello di introspezione aperto (la richiesta chiede **soltanto** `__schema`/`__type`/`__typename`, senza alias). Le variabili (`$.variables.*`) sono valori come gli altri: `hmac` sugli identificativi, `code` sugli stati, `drop` per il resto.

La classificazione e la validazione sono in `internal/policy` (`checkGraphQLRules`, `GraphQLResponsePath`, `GraphQLIntrospectionPaths`). Una persona può scrivere le regole a mano per un endpoint che la versione Osserva non riconosce (un path qualsiasi: la regola vale per l'operazione in cui è scritta).

### 1.7 Famiglie di domini HMAC (`hmac.families`, v1.18)

Lo stesso identificativo si chiama spesso in due modi: `clientId` in un servizio e `customerId` in un altro, `contractRef` nella richiesta e `id` nella risposta. Con domini HMAC diversi i token sono diversi e il miner non vede che sono la stessa cosa. Una **famiglia** unisce dei domini:

```yaml
hmac:
  kid: k1
  epoch: "2026-10"
  families:
    customer: [customer, client]       # hmac(client) si compila come hmac(customer)
```

- Solo **forma autore**: il nome della famiglia segue la grammatica dei domini; 2–16 membri senza doppioni, al più 64 famiglie; un dominio sta in al più una famiglia e il nome di una famiglia non può essere membro di un'altra; i domini riservati (`subject`, `sample`, `sample-trace`, `discovery`) sono rifiutati, sia come nome sia come membro (il soggetto non si unisce mai a un campo).
- **Compilazione.** Ogni `hmac(d)` con `d` membro di una famiglia diventa `hmac(<famiglia>)` (regole globali, di servizio, di operazione e del corpo). Il corpo compilato non cambia forma: **le sorgenti non cambiano** e una policy senza famiglie compila byte per byte come prima.
- **Classificazione.** Non apre valori (§7.1): cambia solo il dominio di regole `hmac`. Effetto: i token dei campi uniti diventano uguali, quindi **collegabili tra i campi**; restano non reversibili senza la chiave e nessun valore esce. Vedi [THREAT_MODEL](../THREAT_MODEL.md) §7.
- **Console.** Il miner propone le coppie di domini che sembrano un identificativo solo dalla **struttura** — mai dai valori, i token di due domini non si confrontano: lo stesso numero di token distinti per utente, un token nuovo di un dominio visto subito dopo (60 s) un token nuovo dell'altro, gli stessi scambi ([rules.md](rules.md) §5.2, `families` di `GET /api/v1/rules/status`). `PUT /api/v1/fleet/groups/{group}/families` (`{"family": "...", "domains": [...]}`, ruoli operatore e policy-approver) sostituisce i membri di una famiglia, `DELETE /api/v1/fleet/groups/{group}/families/{family}` la toglie (`404 unknown_family`); entrambe scrivono la forma autore con la pipeline delle bozze (commenti e impaginazione conservati) e si applicano subito come le modifiche che non aprono valori. Errori: `409 domain_in_family`, `409 no_policy`, `422 invalid_family`. Audit `policy.families_set` / `policy.families_removed` (solo nomi). `GET /api/v1/fleet/groups/{group}/observe` restituisce `families`. La versione Osserva automatica conserva le famiglie.

---

## 2. Corpo compilato (`tt.policy.body/v1`)

È JSON, generato da `tt-core` con queste regole fisse. Due compilazioni della stessa policy autore con gli stessi `version`, `issued_seq`, `created_at`, `not_after` e `targets` producono **gli stessi byte**:

- serializzazione in JSON canonico tt (§10 del [sanitizer](sanitizer.md));
- `services` è un array ordinato per `name`, `ops` un array ordinato per `op`, `body` un array di `{path, action}` ordinato per `path`; le liste `allow`, `hosts_allow`, `propagate_to`, `accept_kids` sono ordinate per byte e senza duplicati;
- le azioni diventano oggetti: `{"action":"keep"}`, `{"action":"code"}` (v1.11), `{"action":"code","shape":"alnum"}` (v1.19), `{"action":"graphql"}` (v1.14), `{"action":"hmac","domain":"order"}`, `{"action":"bucket","kind":"num","bounds":[0,50,100,250]}`, `{"action":"bucket","kind":"time","unit":"day"}`, `{"action":"drop"}`; i confini si scrivono nella forma canonica §10.2;
- `match.base` è già normalizzata;
- `hosts` (v1.5) si scrive **solo** con `{"discovery":"off"}`: `auto`, il default, si rappresenta con il campo assente, così le sorgenti precedenti alla v1.5 continuano ad accettare i corpi nel modo di default. Una sorgente DEVE accettare anche `{"discovery":"auto"}` (stesso significato del campo assente) e DEVE rifiutare (`policy_rejected`) qualsiasi altro valore o campo dentro `hosts`;
- `bodies` (v1.19, [sanitizer](sanitizer.md) §22.1) si scrive **solo** se la policy autore ne ha uno o `fleet.sanitizer.bodies` è attivo (default: tutti gli interruttori accesi, `max_large_body_bytes` 8 MiB, `large_array` 50, `large_nested_array` 5): `{"xml","multipart","docs","max_large_body_bytes","large_array","large_nested_array"}`, tutti obbligatori. Una sorgente precedente alla v1.19 rifiuta un corpo con `bodies` e continua con la policy precedente (§4); si spegne con `fleet.sanitizer.bodies: false` finché le sorgenti non sono aggiornate. Gli interruttori non aprono valori (§7.1): cambiano solo la struttura che esce;
- `sampling.rate` diventa `sampling.rate_bp` (intero 0–10000);
- tutti i `limits` sono presenti, con i default espliciti;
- `version` è un intero crescente **per `policy_id`**, per le persone;
- `issued_seq` è un intero crescente **globale** per l'istanza di `tt-core` (su tutte le policy): serve alle sorgenti per ordinare le policy anche quando cambia `policy_id`;
- `created_at` è il momento della compilazione, `not_after` la scadenza (default `created_at` + 30 giorni; `tt-core` rinnova automaticamente con [keyguard](keyguard.md) §3.3);
- `targets.groups` elenca i **gruppi di sorgenti** a cui la policy è assegnata.

## 3. Busta firmata (`tt.policy.compiled/v1`)

```json
{
  "format": "tt.policy.compiled/v1",
  "policy_id": "p-shop",
  "version": 7,
  "issued_seq": 31,
  "hash": "sha256:3f7a…",
  "body_b64": "eyJmb3JtYXQiOiJ0dC5wb2xpY3kuYm9keS92MSIs…",
  "signature": { "alg": "Ed25519", "kid": "policy-2026-1", "sig": "q3Yk…" }
}
```

- `body_b64` contiene i **byte esatti** del corpo compilato in base64url senza padding. Firma e hash si calcolano su quei byte, senza ricanonicalizzare.
- `hash` = `sha256:` + esadecimale minuscolo dello SHA-256 dei byte del corpo.
- `signature.sig` = firma Ed25519, fatta da [keyguard](keyguard.md), del messaggio `"tt.policy.body/v1" || 0x00 || byte del corpo`, in base64url senza padding. Il prefisso impedisce di riusare la firma su altri formati.
- `signature.kid` identifica la chiave di firma delle policy. Le chiavi pubbliche arrivano alla sorgente all'iscrizione e la sorgente le **fissa** (pinning). Una rotazione si annuncia nella risposta all'heartbeat con una nuova chiave firmata da una già fissata (`add_signing_keys`); una revoca con `revoke_signing_keys`.
- I campi `policy_id`, `version` e `issued_seq` della busta DEVONO coincidere con quelli del corpo. La sorgente DEVE verificarlo.

### 3.1 Rotazione e revoca della chiave di firma (red team round 3)

**Sorgente.** A ogni heartbeat la sorgente:

1. applica **prima** `revoke_signing_keys` e **poi** `add_signing_keys` (RT3-KEY-3): una chiave endorsata da un `kid` revocato nella stessa risposta si rifiuta, perché chi possiede la chiave vecchia compromessa non deve ottenere una chiave nuova fidata proprio dal messaggio che la revoca;
2. per ogni voce di `add_signing_keys`, in ordine: salta in silenzio un `kid` già fissato con la stessa chiave o già revocato (`tt-core` ripete le voci a ogni heartbeat); rifiuta, segnalando un codice d'errore, un `kid` già fissato con un'altra chiave, un endorser non fissato o revocato e una firma non valida; fissa la chiave altrimenti (una chiave fissata prima nella stessa lista può endorsare le successive). Fissaggi e revoche si salvano nello stato locale e valgono anche dopo un riavvio; un `kid` revocato non torna mai fidato;
3. invia nel corpo dell'heartbeat `signing_kids`: i `kid` di cui si fida ora (fissati all'iscrizione o con `add_signing_keys`, meno i revocati), ordinati.

Lo stesso comportamento è in tutti gli SDK (Go `internal/sourceclient`, Node, Python, Java, .NET, PHP), con test dedicati.

**Codici d'errore canonici.** Una voce di `add_signing_keys` che non si fissa produce **un solo** codice nei `last_errors` dell'heartbeat (campo `code`, solo il codice: mai valori). L'insieme è lo stesso in tutti gli SDK; il dettaglio del motivo sta nel codice stesso, perché lo schema dell'heartbeat ammette solo `code` e `at`. Si applicano in quest'ordine, e il primo che vale chiude la voce:

| Ordine | Condizione | Codice |
|---|---|---|
| 1 | la voce non è un oggetto, o `kid` non rispetta `^[A-Za-z0-9._-]{1,64}$` | `signing_key_rejected` |
| 2 | il `kid` è revocato | nessuno (`tt-core` ripete le voci: non è un'anomalia) |
| 3 | `alg` diverso da `Ed25519`, `public_key` o `endorsement` non base64url stretto, `public_key` non di 32 byte, `endorsement` non di 64 byte, `endorsed_by` mancante | `signing_key_rejected` |
| 4 | il `kid` è già fissato con la stessa chiave | nessuno |
| 5 | il `kid` è già fissato con **un'altra** chiave | `signing_key_conflict` |
| 6 | `endorsed_by` non è fissato o è revocato | `signing_key_endorser_unknown` |
| 7 | la firma dell'endorsement non si verifica | `signing_key_endorsement_invalid` |

`signing_key_rejected` è quindi «voce malformata» (il `reason` è `malformed`); gli altri tre sono i motivi `conflict`, `endorser_unknown`, `endorsement_invalid`. Go: `policy.SigningKeyErrorCode` (test `TestSigningKeyErrorCodes`). Gli altri SDK provano i codici con i test di rotazione (conflitto, endorser ignoto); non esiste ancora un vettore condiviso per le altre condizioni.

**tt-core.** `POST /api/v1/fleet/signing-keys/{kid}/revoke` (ruolo `admin`) rifiuta con `409`:

- `last_signing_key`: è l'ultima chiave non revocata;
- `active_signing_key` (RT3-KEY-2): è la chiave con cui keyguard firma ora (`policy_kid` di `GET /keyguard/v1/status`, letto al momento; se keyguard non è raggiungibile vale l'ultimo valore noto, e senza alcun valore noto la revoca è `503 keyguard_unavailable`). Revocarla renderebbe inverificabile ogni firma successiva;
- `rotation_unconfirmed` (RT3-KEY-1): meno di `fleet.key_rotation.min_confirmed` (default `1`, cioè il 100%) delle sorgenti **viste** negli ultimi `fleet.key_rotation.window` (default 24 h; vista = ultimo heartbeat o iscrizione nella finestra, sorgente non revocata) ha confermato la chiave che firmerà dopo la revoca (il `policy_kid` di keyguard, o in sua assenza un'altra chiave non revocata). Una sorgente conferma con `signing_kids` nell'heartbeat; all'iscrizione vale l'elenco delle chiavi consegnate; una sorgente che non invia il campo (SDK vecchio) mantiene l'ultimo valore noto.

`GET /api/v1/fleet/signing-keys` mostra per ogni chiave `active`, `trusted_by` e `revoke` (sorgenti viste, confermate, frazione richiesta, `ok`, `blocker`); la UI lo mostra in **Impostazioni → Chiavi di firma**, con il pulsante di revoca abilitato solo quando la revoca sarebbe accettata. Ogni rifiuto è nell'audit (`fleet.signing_key_revoke`, esito `denied`, con il codice).

**Revoca d'emergenza.** Se la chiave vecchia è compromessa non si aspetta: si imposta `fleet.key_rotation.min_confirmed: 0` (e si riavvia `tt-core`). Restano i controlli `active_signing_key` e `last_signing_key`. Le sorgenti che non avevano ancora la chiave nuova smettono di catturare (fail-closed) e vanno iscritte di nuovo.

**Procedura** (il runbook passo per passo è in [deploy/README.md](../../deploy/README.md#rotazione-della-chiave-di-firma-delle-policy)):

1. si genera una chiave nuova e la si mette in **prima** riga del file di keyguard, lasciando sotto la vecchia **con il suo seed**; si riavvia keyguard, che firma con la nuova ed endorsa la nuova con la vecchia ([keyguard](keyguard.md) §1, §6);
2. `tt-core` impara la chiave e l'endorsement alla prima firma, al rinnovo o alla manutenzione periodica e li manda a tutte le sorgenti con `add_signing_keys`;
3. si aspetta che **Impostazioni → Chiavi di firma** mostri la chiave vecchia revocabile (tutte le sorgenti viste hanno confermato la nuova), poi la si revoca: le sorgenti la tolgono al heartbeat successivo (`revoke_signing_keys`);
4. si aggiunge il `kid` vecchio a `TT_KEYGUARD_REVOKED_KIDS` (o si toglie la sua riga dal file) e si riavvia keyguard.

## 4. Comportamento della sorgente (fail-closed)

Una sorgente accetta una policy **solo se** tutte queste condizioni valgono:

1. la firma è valida con una chiave fissata e **non revocata**, e il corpo è valido secondo lo schema `tt.policy.body/v1`, non usa domini HMAC riservati e, **dalla v1.3**, rispetta il sottoinsieme di sicurezza di [hardening.md](hardening.md) §2 (nessun `keep`/`hmac` su `authorization`, `cookie`, `set-cookie`, `proxy-authorization`; nessun `keep`/`hmac` su un passo jolly `.*` o `[*]` nelle regole globali; scoperta e parole automatiche con scadenza entro 7 giorni da `created_at`). Una sorgente non si fida della validazione di `tt-core` né di keyguard;
2. hash, `policy_id`, `version` e `issued_seq` sono coerenti tra busta e corpo;
3. il gruppo della sorgente (assegnato all'iscrizione) è in `targets.groups`;
4. `now < not_after`;
5. `issued_seq` è maggiore dell'ultimo accettato **e** non è minore di `min_issued_seq` ricevuto nell'ultimo heartbeat.

| Situazione | Comportamento |
|---|---|
| Avvio | La sorgente invia **un heartbeat prima di catturare qualsiasi cosa**, per ricevere lo stato dell'interruttore e `min_issued_seq` |
| Nessuna policy accettata | **Non cattura.** Heartbeat `no_policy`. |
| Policy rifiutata (firma, coerenza, gruppo, scadenza, sequenza, sottoinsieme di sicurezza v1.3) | La scarta, tiene la precedente se è ancora valida, altrimenti non cattura. Heartbeat `policy_rejected` o `expired_policy`. |
| `tt-core` irraggiungibile | Continua con l'ultima policy valida in cache **fino a** `policy_max_age` (default 24 h) e comunque non oltre `not_after`; poi smette di catturare. |
| Chiave HMAC locale assente, non valida o con `kid` non accettato | Non cattura. Heartbeat `key_missing` o `key_mismatch`. |
| Interruttore di emergenza attivo | Non cattura e scarta le code. Lo stato si **salva** nella cache insieme alla policy e resta valido anche dopo un riavvio, finché un heartbeat non dice il contrario. |
| Scoperta o parole automatiche scadute | Le ignora (§4.3 e §15 del sanitizer). |
| Cambio di policy normale (v1.6.1) | `tt-core` porta `min_issued_seq` alla nuova policy **nello stesso heartbeat** che la annuncia (`policy_current`, con `hash` diverso da quello in uso e `issued_seq` ≥ `min_issued_seq`). La sorgente ferma la cattura subito (la policy vecchia non si usa più), scarica la nuova e passa a `capturing`: **non è un errore**, si registra solo un messaggio informativo (`policy_superseded`, `policy_changed`). Gli errori `policy_below_min_issued_seq` e `policy_rejected` restano per i casi veri: la nuova policy non arriva o non è accettabile, oppure `policy_current` non la annuncia (gruppo senza policy, replay). Una risposta di policy arrivata dopo l'accettazione di una più recente (due richieste che si incrociano) si ignora, senza errore. |

"Non cattura" significa che l'app continua a funzionare normalmente e tt non produce eventi. In nessun caso un errore della policy apre più dati del previsto.

### 4.1 Togliere un gruppo dalla sua policy (v1.4, red team round 3)

Mettere `policy_id` a `null` su un gruppo (`PUT /api/v1/fleet/groups/{g}`) **ferma la cattura** delle sue sorgenti, senza aspettare approvazioni:

1. `tt-core` non serve più nessuna policy al gruppo (`GET /fleet/v1/policy` risponde `404 no_policy`) anche se i `targets.groups` firmati della versione attiva lo nominano ancora;
2. l'heartbeat di un gruppo senza policy porta `min_issued_seq` = (massimo `issued_seq` attivo) + 1: ogni sorgente scarta la policy che ha in cache (§4, punto 5) e passa a `no_policy`. Una policy emessa dopo ha `issued_seq` più alto ed è accettata normalmente;
3. se la policy ha ancora altri gruppi, `tt-core` crea una bozza di **chiusura** (origine `retarget`, 1 approvazione) senza il gruppo, riportata in `policy_draft` della risposta: quando è approvata i `targets.groups` firmati smettono di nominare il gruppo. Se non resta nessun gruppo, non c'è bozza: la versione attiva **non viene più rinnovata** (`RenewExpiringPolicies` rinnova solo versioni con almeno un gruppo ancora collegato; l'audit registra `policy.renew` negato con motivo `no_bound_group`) e scade al suo `not_after`;
4. ricollegare il gruppo alla stessa policy mentre la versione attiva lo nomina ancora (bozza di chiusura non approvata) rimette in servizio la stessa policy già approvata per quel gruppo; ricollegarlo a un'altra policy segue l'apertura normale (bozza con approvazioni). Per fermare un gruppo **senza** perdere il collegamento si usa l'interruttore di emergenza (`killed`).

La cache locale contiene la busta firmata (mai il YAML), l'ultimo `issued_seq` accettato e lo stato dell'interruttore; si riverifica a ogni avvio.

## 5. Approvazioni

**Dalla v1.6** una modifica che **non apre valori** (§7: solo forme, token HMAC, identità automatiche, finestre a tempo della scoperta) **non richiede approvazioni**: keyguard la firma da sola e si applica subito (`approval_mode: observe`). Le regole di questa sezione valgono per le modifiche che **aprono valori** (§7.2), per il ripristino di una versione precedente e per tutte le modifiche quando keyguard ha `TT_KEYGUARD_OBSERVE_AUTO=false` (allora valgono esattamente come nella v1.5).

Ogni nuova versione di una policy che apre valori richiede approvazioni di persone con ruolo `policy-approver`, registrate da `tt-core` e verificate da [keyguard](keyguard.md) §3.2 al momento della firma.

- **1 approvazione** se la modifica è solo **di chiusura** (solo con `observe_auto` spento: altrimenti una chiusura non apre valori e si applica da sola).
- **2 approvazioni di persone diverse** in **tutti gli altri casi**: in particolare per la prima policy di una sorgente che apre valori, per il ripristino di una versione precedente (anche se è una chiusura) e per lo scioglimento di una quarantena (vedi l'API di amministrazione). Con `observe_auto` spento anche la prima policy di partenza e l'attivazione della scoperta o delle parole automatiche.

**Chi conta come approvatore (v1.3).** Il controllo ha due livelli, e il secondo è più largo del primo di proposito:

1. `tt-core` (separazione dei compiti, normativo per il core): l'**autore** di una versione non conta **mai** come approvatore, nemmeno per una modifica di sola chiusura (`409 self_approval`), e nessuno approva due volte. Il quorum è fatto di persone con ruolo `policy-approver`, distinte e diverse dall'autore: quindi con 2 approvazioni richieste servono due persone diverse dall'autore, con 1 una persona diversa dall'autore. È più severo del testo v1.1/v1.2 («almeno una diversa dal proponente»), che consentiva al proponente di essere uno dei due.
2. keyguard ([keyguard.md](keyguard.md) §3.2) ripete il controllo sui dati che riceve: persone distinte (per `sub` OIDC se c'è) e, con 2 richieste, almeno una diversa dal proponente. Con 1 richiesta accetta anche il proponente stesso. È la rete di sicurezza contro un bug di `tt-core`, non la regola: l'identità del proponente è dichiarata da `tt-core`, quindi keyguard non potrebbe comunque imporre di più senza OIDC.

**Ritirare una bozza (v1.11.1, test di usabilità 5).** Una bozza in attesa può essere **ritirata dalla persona che l'ha proposta** (o da un admin) con `POST /api/v1/fleet/policies/{id}/versions/{n}/withdraw`, senza il ruolo `policy-approver`: nel test 5 un utente non admin aveva proposto una bozza che apriva valori, nessun'altra persona poteva approvarla (l'autore non conta) e la bozza bloccava la policy, e con essa la versione Osserva automatica (§7.4), senza che si potesse toglierla. La bozza diventa `rejected` (`withdrawn: true`, nota che comincia con `withdrawn`), resta nella storia, non si può più approvare (`409`); un'altra persona che non sia admin riceve `403 not_proposer`. Audit `policy.withdraw` (con `admin_override` se un admin ritira la bozza di un altro). Non cambia nulla per le versioni firmate.

**Approvazioni legate alla modifica (v1.5, red team round 3).** Con OIDC in keyguard ogni approvazione (versione di policy, rilascio di un pacchetto, scioglimento di una quarantena) richiede uno **step-up**: l'approvatore si autentica di nuovo presso l'IdP, con il client dedicato alle approvazioni, e ottiene un ID token il cui `nonce` è legato a quella sola modifica (`tt.approve/v1`, [keyguard.md](keyguard.md) §3.2 punto 4). Keyguard legge **dal token** i ruoli (`admin`, `policy-approver`, `publisher`): un `tt-core` compromesso non può più dichiarare admin un operatore né riusare il token di un login. Gli account locali non possono approvare (`403 oidc_required`) né allegare token (`403 id_token_not_allowed`). `tt-core` tiene il token in memoria al più 10 minuti: se il quorum si raggiunge quando il token di un approvatore precedente è scaduto, la bozza resta bozza (l'approvazione mostra `token_fresh: false`) e quell'approvatore approva di nuovo per rinnovarlo (`policy.approval_renewed`). Per lo scioglimento di una quarantena il token lo verifica `tt-core` (keyguard non partecipa). Senza OIDC tutto resta come prima, con `approvals_unverified: true` mostrato nella UI: garanzia ridotta, per installazioni su un solo host o di sviluppo.

L'**approvazione dell'admin** (sotto) è l'unica eccezione: vale anche per una modifica proposta dall'admin stesso.

**L'admin è il superutente (v1.6, decisione di progetto).** «L'admin deve vedere tutto e non deve essere limitato.» Il ruolo `admin` **implica tutti gli altri**: ogni controllo di ruolo di `tt-core` (rotte, pagine, azioni) passa per un admin. La separazione dei compiti resta tra le persone **non** admin; per l'admin lascia il posto alla **tracciabilità**: un admin può agire da solo, ma mai in modo invisibile. Quindi (sostituisce le regole v1.4 del red team round 2):

- **nessun blocco per l'admin**: `admin` si combina con qualsiasi ruolo (niente più `409 sod_conflict`, e i ruoli sincronizzati da OIDC si prendono come arrivano) e un admin può assegnare ruoli a sé stesso (niente più `409 self_grant`). Un utente **non** admin non assegna mai ruoli, né a sé né ad altri: la gestione degli utenti è solo dell'admin (`403 forbidden`). Togliersi il proprio `admin` resta rifiutato (`409 self_lockout`), per non restare senza amministratori;
- l'assegnazione di un ruolo **sensibile** (`admin`, `policy-approver`, `event-exporter`), alla creazione o con `PATCH`, è registrata nell'audit (`user.sensitive_role`, solo identificatori) e notificata ai webhook come `keyguard.alert` con `alert: "user.sensitive_role"`, `user`, `by`, `roles_granted`; un'assegnazione a sé stessi porta in più `self_grant` (anche in `user.update`);
- **ogni azione dell'admin che richiederebbe un altro ruolo è un override dell'admin**: se cambia qualcosa (metodo non sicuro) o scarica un file, `tt-core` registra `authz.admin_override` (modello della rotta, `roles_required`, stato della risposta) oltre alla voce dell'azione, che porta `admin_override: "true"` dove l'azione ha una propria voce (download ed export dei pacchetti, export e download degli eventi, regole). Le sole letture non si registrano una per una;
- l'approvazione di **chi ha il ruolo `admin`** è **sempre** l'approvazione dell'admin (sotto): motivazione obbligatoria (`422 reason_required` senza), `approval_mode: "admin"`, audit `policy.admin_approval`, allarme. Vale anche per un admin che ha pure `policy-approver` (a keyguard arriva solo il ruolo `admin`) e per la pubblicazione dei pacchetti (`admin` + `publisher` pubblica come admin, allarme `pack.admin_approval`). Motivazione e allarme sono tracciabilità, non un limite: keyguard li chiede per un'approvazione di una sola persona;
- lo **scioglimento o la chiusura di una quarantena** da parte di un admin hanno effetto subito, da solo: audit con `approval_mode: "admin"` e `quarantine.admin_override`, e per lo scioglimento (riapre dati) allarme `keyguard.alert` con `alert: "quarantine.admin_override"`. Un admin non conta mai come uno dei due `policy-approver`; con OIDC anche l'admin fa lo step-up;
- l'**export degli eventi** da parte di un admin è permesso, registrato e notificato (`events.export` con `admin_override: true`); l'admin scarica anche gli export degli altri (`events.download` con `admin_override` e `owner`, allarme `events.admin_download`). Download ed export dei pacchetti, approvazione e rifiuto delle regole, revoca delle chiavi di firma, retention e purge sono registrati come sopra;
- **l'unico modo di limitare un admin** è in keyguard: `TT_KEYGUARD_ADMIN_OVERRIDE=false` toglie all'admin l'approvazione da solo di policy e pacchetti (`403 admin_override_disabled`). È una scelta dell'installatore, non di `tt-core` né della UI. Con OIDC keyguard continua a esigere il ruolo `admin` nel token verificato dello step-up.

Rischio residuo accettato: un admin può creare account fantoccio e farli approvare, oppure approvare da solo. Non è nascosto: le assegnazioni di ruoli sensibili sono notificate, le approvazioni dell'admin hanno motivazione e allarme, gli override sono nell'audit a catena di hash ([THREAT_MODEL.md](../THREAT_MODEL.md) M17).

**Approvazioni non più valide (v1.4).** Ogni volta che il quorum si valuta (approvazione di una policy, scioglimento di una quarantena) `tt-core` rilegge lo stato **attuale** degli approvatori precedenti: le approvazioni di utenti disattivati, o che non hanno più il ruolo richiesto (o che ora hanno `admin`: da quel momento approvano solo come admin), non contano più e si tolgono dalla bozza (audit `policy.approval_dropped` / `quarantine.approval_dropped`). A keyguard arrivano solo le approvazioni valide con i ruoli che gli approvatori hanno **adesso**, non quelli del momento dell'approvazione. Il rilascio di un pacchetto usa i ruoli letti alla richiesta stessa.

**Numero configurabile (v1.2.1).** Il numero di approvazioni per le modifiche che aprono dati è un'impostazione di installazione, `approvals.opening_required`, che vale `2` per default e può essere portata a `1` per team piccoli. Con `1` la UI mostra un avviso permanente nella pagina delle policy e ogni firma porta `approval_mode: "single"` nell'audit. L'impostazione è letta da keyguard (`TT_KEYGUARD_OPENING_APPROVALS`, valori `1` o `2`), non da `tt-core`, così un `tt-core` compromesso non può abbassarla.

**Approvazione dell'amministratore (v1.2.1).** Un utente con ruolo `admin` può sempre approvare **da solo** qualsiasi modifica di policy, e pubblicare qualsiasi pacchetto, anche quando sono richieste 2 approvazioni. È una scelta esplicita dell'installazione per non bloccare chi lavora da solo. L'approvazione dell'admin:
- richiede una **motivazione** testuale obbligatoria (senza valori reali), registrata nell'audit;
- produce `approval_mode: "admin"` nella busta firmata (campo non firmato della risposta di keyguard) e nell'audit, con allarme webhook `policy.admin_approval`;
- è verificata da keyguard come le altre: con OIDC il ruolo `admin` DEVE essere nel claim dei ruoli dell'ID token di step-up, legato alla modifica (`403 role_unverified` altrimenti); senza OIDC keyguard si fida del ruolo dichiarato da `tt-core`;
- può essere disattivata con `TT_KEYGUARD_ADMIN_OVERRIDE=false` (default `true`): è l'unico limite all'admin in tutto traffic-twin, ed è una scelta dell'installatore;
- si dà con `POST …/approve` e il campo `reason` (ogni admin DEVE darlo: dalla v1.4 l'approvazione di un admin è sempre questa), per i pacchetti con `POST /api/v1/packs/{id}/publish` e `reason`; la motivazione resta nel record della policy, il registro di audit di `tt-core` ne conserva solo l'impronta SHA-256 e la lunghezza, quello di keyguard il testo ridotto a un identificatore sicuro. Per i pacchetti l'admin non salta nessun controllo del gate ([keyguard.md](keyguard.md) §3.4).

Una modifica è **di chiusura** se è composta solo da queste operazioni rispetto alla versione attiva:

| Operazione di chiusura |
|---|
| Cambiare l'azione di una regola in `drop` |
| `keep` → `hmac` o `keep` → `bucket` |
| Togliere confini a un `bucket(num)` (i confini nuovi sono un sottoinsieme dei vecchi) o rendere più grossolana l'unità di un `bucket(time)` |
| Togliere una regola `keep` |
| Abbassare `sampling.rate`; `trust_baggage` da `true` a `false` |
| Spegnere scoperta o parole automatiche, o anticiparne la scadenza |
| Togliere voci da `segments.allow`, `segments.hosts_allow`, `sampling.propagate_to`, `hmac.accept_kids` |
| `hosts.discovery` da `auto` (o assente) a `off` (v1.5; il contrario apre) |
| Abbassare un valore di `limits` |
| Togliere un gruppo da `targets.groups` (aggiungerlo invece apre) |

Il rinnovo di `not_after` senza altri cambiamenti non richiede approvazioni ([keyguard](keyguard.md) §3.3).

Qualsiasi altra modifica (nuove regole, nuovi servizi o operazioni, `hmac` → `keep`, `bucket` → `keep`, confini più fini, percorsi con `.*`, cambi di `identity`, `hmac.kid`, `hmac.epoch` o `match`, nuove voci nelle liste) **apre** dati e richiede 2 approvazioni. Nel dubbio, la modifica apre.

## 6. Policy di partenza dell'onboarding

L'assistente della UI crea la prima policy di una sorgente così (`POST /api/v1/fleet/groups/{group}/starter-policy`):

- `default: drop`, nessuna regola sui corpi;
- `segments.auto_words: true` per 72 ore, per far vedere i path nella pagina "Servizi scoperti";
- `discovery.enabled: true` per 72 ore, per stimare la cardinalità dei campi (gli host esterni sono visibili anche dopo, con `hosts.discovery: auto`, v1.5);
- `sampling.rate` proposto dalla UI; default **0,1** dalla v1.6 (era 0,05): con k = 20 e l'obiettivo di 2·k utenti campionati bastano circa 400 utenti nel traffico (§7.4);
- `hmac.kid` di default il primo `kid` HMAC di keyguard, `hmac.epoch` di default il mese corrente (`YYYY-MM`), dalla v1.6.

**Dalla v1.6** non apre valori (§7): keyguard la firma senza approvazioni e la risposta è la versione già **attiva**. Con `TT_KEYGUARD_OBSERVE_AUTO=false` resta una bozza che richiede **2 approvazioni**, come nella v1.5.

## 7. Fase Osserva e modifiche che aprono valori (v1.6)

**Decisione di progetto.** «Collegare una sorgente deve essere plug & play.» Fino alla v1.5 il wizard faceva approvare una policy prima di vedere qualsiasi cosa. Dalla v1.6 l'onboarding ha una fase **Osserva** senza policy da scrivere e senza approvazioni: si cattura la **struttura** (endpoint, nomi, tipi e classi di lunghezza dei campi, status, latenza; i valori si scartano) e gli **identificativi mascherati** (token HMAC). Le approvazioni servono solo quando una modifica **apre valori**.

### 7.1 Modifica che non apre valori («observe-safe»)

Una modifica, confrontata con il corpo firmato precedente, **non apre valori** se nessuna delle condizioni di §7.2 vale. In pratica può solo:

- aggiungere o cambiare regole `drop` e `hmac` (anche con un altro dominio; con valori, salvo i casi di contenitore di §7.2), togliere regole `keep` o `bucket`, passare da `keep` a `hmac`/`bucket`/`code`, rendere un `bucket` più grossolano;
- **(v1.11)** aggiungere regole `code` sui campi di stato e di codice (§1.5), o passare a `code` da `drop`/`hmac`/`keep`: escono solo codici con la forma di [sanitizer](sanitizer.md) §5.6. Una policy con `code` ma senza `keep` né `bucket` **non lascia uscire valori** ai fini dei motivi «con valori» qui sotto (campionamento, `limits`, gruppi, servizi): alzare il campionamento per arrivare a k soggetti resta senza approvazioni;
- **(v1.19)** aggiungere `code(alnum)`, o `code` su un campo scelto da una persona, dove §1.5.1 lo ammette; cambiare l'oggetto `bodies` (struttura di XML, multipart, documenti e corpi grandi, mai valori);
- **(v1.14)** aggiungere o togliere regole `graphql` dove §1.6 le ammette: escono solo la forma dei documenti (nomi, nessun valore) e, dietro il cancello di introspezione, i nomi dello schema ([sanitizer](sanitizer.md) §5.7). Una policy con `graphql` ma senza `keep` né `bucket` non lascia uscire valori ai fini dei motivi «con valori»;
- dichiarare servizi e operazioni (anche senza regole) (v1.8.1: con `keep` o `bucket`, solo se non tolgono traffico a un altro servizio o a un'altra operazione, vedi §7.2), cambiare `hmac.kid`, `hmac.epoch` e `hmac.accept_kids`;
- **(v1.12)** impostare o cambiare `identity.subject` da **qualsiasi header della richiesta che non sia una credenziale**, con o senza `jwt_claim`, oppure da **qualsiasi claim** del JWT bearer nell'header `authorization`. Il soggetto esce sempre e solo come token HMAC, mai in chiaro ([sanitizer](sanitizer.md) §11): scegliere da dove leggerlo non lascia uscire nessun valore. La regola è **generica**: nessun elenco di nomi di header di un'applicazione (fino alla v1.11.2 c'era un elenco chiuso, rimosso perché ogni applicazione chiama l'utente a modo suo). Restano fuori, e servono le approvazioni (`identity` in §7.2):
  - i **cookie** (portano segreti di sessione);
  - gli header di credenziali `cookie`, `set-cookie`, `proxy-authorization` e gli altri di `ForbiddenKeepHeaders` (`x-api-key`), anche con un claim;
  - `authorization` **senza** `jwt_claim` (il token intero);
  - un header il cui nome **sembra una credenziale**, senza `jwt_claim` né `json_path`: nomi che contengono `token`, `secret`, `passw`, `pwd`, `apikey`/`api-key`/`api_key`, `session`, `csrf`, `xsrf`, `signature`, `credential`, `auth`, `cookie`, `nonce`, o con una parola intera `key`, `sig`, `sid`, `pin`, `otp`, `pass`, `jwt`, `bearer`, `code`. Nel dubbio il nome è una credenziale. Con un `jwt_claim` (per esempio `x-id-token` con `sub`) esce solo il token del claim, quindi non apre valori.
  - **(v1.18)** `json_path`: il soggetto è un membro di un header il cui valore è un **oggetto JSON**, in chiaro o in base64/base64url (`x-user-context` con `user.id`; [sanitizer](sanitizer.md) §11). Vale come `jwt_claim`: anche con un nome che sembra una credenziale non apre valori (esce solo il token del membro); `authorization` vuole comunque un `jwt_claim`; cookie e header di credenziali mai. Solo `from: header`, esclude `jwt_claim`; percorso puntato di 1–8 membri `[A-Za-z0-9_-]{1,64}`.

  I parametri della query **non** sono una sorgente del soggetto: [sanitizer](sanitizer.md) §11 legge il soggetto solo da header o cookie, e aggiungerne una cambierebbe tutte le sorgenti. Keyguard ricalcola la classificazione con la stessa funzione (`policy.IdentityObserveSafe`). Rischio residuo: un header che porta un segreto con un nome che non lo fa capire (fuori dall'elenco qui sopra) può diventare il soggetto senza approvazioni; il segreto non esce mai, ma il suo token HMAC sì (collegabile tra chiamate, non reversibile senza la chiave della sorgente), vedi [THREAT_MODEL](../THREAT_MODEL.md);
- **(v1.18)** unire o separare domini HMAC con `hmac.families` (§1.7): cambia solo il dominio di regole `hmac`;
- accendere o allungare la scoperta e le parole automatiche, sempre **entro 7 giorni** dalla compilazione (§1.4);
- alzare il campionamento, `trust_baggage`, i `limits` o aggiungere un gruppo **se la policy non lascia uscire valori** (nessun `keep` né `bucket`): sono solo più forme e più token.

Nessuna modifica che non apre valori può rilassare il sottoinsieme di sicurezza di §1.4 e di [hardening.md](hardening.md) §2: niente `keep`/`hmac` su `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, niente passi jolly nelle regole globali con `keep`/`hmac`, finestre entro 7 giorni. Quelle policy non si compilano nemmeno.

### 7.2 Modifica che apre valori

Apre valori, e segue le approvazioni di §5, una modifica con almeno uno di questi motivi (codice nel campo `value_reasons`, con la posizione nella policy, mai un valore):

| Codice | Motivo |
|---|---|
| `keep` | una regola ora lascia uscire il valore in chiaro (nuova, o da `drop`/`hmac`/`bucket`) |
| `bucket` | una regola ora mette il valore in una fascia (nuova, da `drop`/`hmac`), o confini o unità più fini |
| `credential_header` | `hmac` o `code` su un header di credenziali (comunque rifiutato dalla validazione) |
| `code_field` | (v1.11) `code` su un campo che non è di stato o di codice (§1.5; comunque rifiutato dalla validazione) |
| `identity` | `identity.subject` da un cookie, da un header di credenziali o, senza `jwt_claim` (né `json_path`, v1.18), da `authorization` o da un nome che sembra una credenziale (§7.1) |
| `literals` | nuove voci in `segments.allow` o `segments.hosts_allow` (parole e host in chiaro scelti da persone) |
| `hosts_discovery` | `hosts.discovery` da `off` ad `auto` (qualcuno aveva scelto la modalità stretta) |
| `propagate_to` | nuovi host in `sampling.propagate_to` (cambia il traffico dell'applicazione) |
| `volume_with_values` | più campionamento, `trust_baggage`, `limits` più alti, quando la policy lascia uscire valori |
| `rule_removed_with_values` | tolta una regola `drop`, `hmac` o `code` quando la policy lascia uscire valori (una regola più larga potrebbe applicarsi) |
| `match_with_values` | cambiato `match` di un servizio quando la policy lascia uscire valori (dalla v1.8.1 qualsiasi servizio: anche uno senza valori, le cui regole `drop` coprivano un `keep` globale) |
| `service_with_values` | (v1.8.1) dichiarato o tolto un servizio, anche senza regole, quando la policy lascia uscire valori **e** un altro servizio può prendere lo stesso traffico (stessa origine, un path della `base` prefisso dell'altro): la scelta del servizio (sanitizer §3.1) sposta il traffico su regole `keep`/`bucket` già approvate o lo toglie a regole `drop`/`hmac` che le coprivano. Un servizio su un host che nessun altro servizio dichiara (la «Gemella» di un host esterno) non apre valori |
| `operation_with_values` | (v1.8.1) dichiarata o tolta un'operazione, anche senza regole, quando la policy lascia uscire valori **e** il servizio ha un'altra operazione con lo stesso metodo e lo stesso numero di segmenti: la scelta del template (sanitizer §3.3) decide le regole del gruppo 1 |
| `container_with_values` | (v1.8.1) con valori: un `drop` su un percorso che può essere un contenitore diventa `hmac` (o altro), oppure si aggiunge una regola che può raggiungere un discendente di un contenitore con `drop`, mentre una regola `keep`/`bucket` può raggiungere un discendente dello stesso contenitore. Il `drop` del contenitore smetterebbe di applicarsi (sanitizer §5.0) e la regola più debole con valori varrebbe sulle foglie. Il controllo è statico e ignora gruppi e parti: nel dubbio apre |
| `group_with_values` | aggiunto un gruppo a una policy che lascia uscire valori |
| `keyguard_verdict` | keyguard ha rifiutato di firmare senza approvazioni (il suo confronto differisce da quello di `tt-core`) |

Nel dubbio, la modifica apre valori. Il ripristino di una versione precedente (`origin: rollback`) richiede sempre le approvazioni di apertura.

### 7.3 Chi decide

- `tt-core` classifica ogni bozza (`opens_values`, `value_reasons` in `PolicyVersion`, `approvals_required: 0` per le modifiche che non aprono valori) contro la versione attiva della policy **e** contro la policy che ogni gruppo di destinazione esegue ora. `POST /api/v1/fleet/policies/classify` classifica senza salvare (la UI lo usa per dire «Questa modifica non apre dati: si applica subito» oppure «Apre valori in chiaro: serve un'approvazione»).
- keyguard **ricalcola da solo** il verdetto, con la stessa funzione (`policy.ClassifyValues`) e dai corpi che ha firmato: contro l'ultimo corpo dello stesso `policy_id` (destinazioni comprese) e contro la policy corrente di ogni gruppo di destinazione (destinazioni escluse). Firma senza approvazioni **solo** se nessun confronto apre valori e `TT_KEYGUARD_OBSERVE_AUTO` è acceso (default); `approval_mode: observe`, `opens_values: false` nella risposta, audit `keyguard.policy_sign` con `approval_mode=observe`. Altrimenti `403 insufficient_approvals` con il motivo nell'audit (`value_reason`): `tt-core` lascia la bozza in attesa con le approvazioni di apertura (`keyguard_verdict`).
- Il numero di approvazioni per le modifiche che aprono valori resta `TT_KEYGUARD_OPENING_APPROVALS` (default 2); l'approvazione dell'admin da solo con motivazione resta come in §5.

Rischio residuo accettato: un `tt-core` compromesso può firmare, senza persone, policy che mascherano con `hmac` qualsiasi campo e accendono scoperta e parole automatiche per 7 giorni alla volta. Non può far uscire valori in chiaro né fasce, salvo dalla v1.11 i codici (§1.5: solo sui campi di stato, solo con la forma di un codice); ogni firma è nell'audit di keyguard. Chi non lo accetta spegne `TT_KEYGUARD_OBSERVE_AUTO`.

### 7.4 La versione Osserva automatica

Dopo che la policy di partenza è attiva, `tt-core` osserva le forme (sketch della scoperta, [sanitizer](sanitizer.md) §15) e, appena ha visto `fleet.observe.min_events` chiamate (default 200) o passato `fleet.observe.after` (default 15 minuti) con almeno una chiamata, ricava **da solo** una nuova versione:

- `hmac` sui campi che l'assistente classifica come **identificativi** (motivi `id` e `path_id`: parametri del path, nomi come `id`, `uuid`, `*_id`, `*Id`, `*Ref`, forme `uuid`/esadecimali, campi con molti valori distinti), con lo stesso dominio sui campi che si chiamano allo stesso modo nelle diverse operazioni (`orderId` in una risposta e nella richiesta successiva: stesso token);
- `identity.subject` dalla sorgente che il **rilevamento automatico dell'utente** sceglie dai dati (sotto), se la policy non ne ha già una;
- solo sui servizi propri e sugli esterni già dichiarati (lo schema di un host esterno non si indovina), solo su campi senza regola;
- **(v1.11)** `code` sui campi di stato e di codice (§1.5) le cui forme sembrano codici: stringhe di classe `l8` o `l32` senza formato riconosciuto (niente `digits`, `uuid`, `email`, date…), così gli stati escono in chiaro e il miner trova i cicli di vita senza che nessuno tocchi la policy. Un campo che l'assistente classifica come identificativo resta `hmac`. `fleet.observe.codes: false` lo spegne (per esempio finché ci sono sorgenti precedenti alla v1.11, che rifiuterebbero il corpo, [sanitizer](sanitizer.md) §19);
- **(v1.19)** `code(alnum)` sui campi di §1.5 con valori a cifre o, per i nomi in `code`, `type`, `kind`, `level`, `tier`, anche con stringhe brevi (§1.5.1); mai su un campo che l'intake ha messo in quarantena per cardinalità. `fleet.observe.code_digits: false` lo spegne (sorgenti precedenti alla v1.19, [sanitizer](sanitizer.md) §22.6);
- **(v1.14)** `graphql` sugli **endpoint GraphQL** che riconosce dalla struttura degli eventi, su qualsiasi servizio e path, senza nomi di un'applicazione: la maggior parte delle chiamate dell'operazione ha un corpo JSON con la chiave `query` e `variables` o `operationName` (oppure il content-type `application/graphql`, oppure è un GET con il parametro `query`) e una risposta con `data` o `errors`. Mette `graphql` sul documento (`$.query`, `$` o il parametro `query`) e sui nomi di un risultato di introspezione standard (`policy.GraphQLIntrospectionPaths`: tipi, campi, argomenti, campi di input, interfacce, tipi possibili, valori di enum, direttive, riferimenti di tipo fino a 5 livelli di `ofType`). Le variabili ricevono `hmac` come ogni identificativo. Un'operazione che sembra GraphQL ma non lo è (un'API di ricerca con `{"query": "testo"}`) non perde nulla: il testo non è un documento ed esce come forma. `fleet.observe.graphql: false` lo spegne (sorgenti precedenti alla v1.14, [sanitizer](sanitizer.md) §20);
- mai `keep` né `bucket`: se la versione ricavata aprisse valori `tt-core` non la crea e lo registra (`policy.observe-auto`, esito `denied`).

La versione ha `origin: observe-auto`, proposta da `system`, firmata senza approvazioni e registrata nell'audit con l'attore di sistema (`policy.observe-auto`, `policy.activate` con `approval_mode=observe`). Il passaggio si ripete (ogni `fleet.observe.interval`, default 1 minuto) e aggiunge gli identificativi **nuovi** (campi e servizi visti per la prima volta) sopra la versione attiva.

**Dalla v1.6.1** il passaggio continua anche **dopo che una persona ha firmato un'altra modifica** (fino alla v1.6 si fermava per sempre: nel test di usabilità 4 gli id dei servizi esterni dichiarati con «Simula nel mock» restavano `drop`). Non scavalca mai una scelta di una persona:

- un campo con una regola resta com'è scritto (`drop`, `keep`, `hmac`, `bucket`, a livello di operazione o di servizio);
- un campo la cui regola una persona ha **tolto** (rimesso a `drop`) in una versione che ha firmato non torna `hmac` da solo; lo stesso per `identity.subject` tolto da una persona. `tt-core` lo ricava dalle versioni firmate, in ordine di `issued_seq`: una regola presente prima di una versione con origine diversa da `starter`, `observe-auto`, `renew`, `retarget` e assente da essa è una scelta della persona (finché una versione successiva non la riscrive);
- con una bozza in attesa di approvazione non ricava nulla (firmare un'altra versione renderebbe la bozza superata, `stale_draft`): riprende quando la bozza è decisa;
- quando la policy lascia uscire valori e l'insieme delle decisioni aprirebbe valori (per esempio `container_with_values`, §7.2), tiene i servizi le cui decisioni da sole non ne aprono; il rifiuto è registrato una volta per contenuto (`policy.observe-auto`, esito `denied`).

**Rilevamento automatico dell'utente (v1.12).** Chi è l'utente si ricava dai dati, mai da un elenco di nomi. I candidati sono gli header (e i cookie) delle richieste in ingresso dei servizi propri, più il JWT bearer di `authorization`; si usano solo gli sketch della scoperta che `tt-core` ha già: valori distinti stimati, chiamate che portano il campo, forma più frequente. Nessun valore in chiaro. Gli header di protocollo (HTTP, proxy, tracing: `user-agent`, `content-length`, `traceparent`, `x-forwarded-*`…) non sono candidati. Ogni candidato ha un punteggio da 0 a 100:

| Segnale | Peso | Come |
|---|---|---|
| cardinalità | 35 | molti valori distinti ma chiaramente meno delle chiamate (un utente ripete le chiamate): pieno fino a 0,5 valori per chiamata, poi scende fino a 0,9 |
| forma | 25 | `uuid`, `digits`, `hex` pieno; testo corto (`l32` 0,8, `l8` 0,7); formati personali `email` 0,6 e `phone` 0,5 (escono comunque solo come token); `l128` 0,4; date, URL, IP, testi lunghi 0 |
| presenza | 25 | quota delle chiamate in ingresso dei suoi servizi che lo portano (piena da 0,8) |
| nome | 15 | segnale **debole**: il nome contiene una parola che spesso indica una persona in qualche lingua (`user`, `person`, `customer`, `client`, `member`, `account`, `subject`, `utente`, `cliente`, `kunde`, `usuario`, `utilisateur`…, o le parole intere `uid`, `usr`, `sub`, `acct`) |

Non viene mai scelto da solo (ma una persona può sceglierlo), con il motivo in `excluded`: `few_values` (al più 20 valori distinti: un tenant, un canale, una versione, o ancora troppo pochi utenti), `per_call` (almeno 0,9 valori per chiamata: un id di richiesta o di traccia), `not_id_shape` (forma che non è un identificativo), `rare` (su meno del 20% delle chiamate), `credential` (non observe-safe, §7.1), `cookie`. La stabilità di un valore tra le chiamate consecutive dello stesso chiamante sarebbe un altro segnale, ma gli sketch sono per operazione e non per chiamante: non si usa.

Vince il `sub` del JWT bearer se la maggior parte delle richieste in ingresso ha `authorization` (punteggio 100); poi un header i cui valori sono JWT (forma `jwt`: il suo `sub`); altrimenti il candidato con il punteggio più alto, se almeno 60. Sotto la soglia non si sceglie nulla e la console lo dice. Il risultato, con punteggi, segnali ed esclusioni, è in `identity_candidates` e `identity_best` di `GET /api/v1/fleet/groups/{group}/observe` e dell'assistente.

**La scelta di una persona.** `PUT /api/v1/fleet/groups/{group}/identity` (`{"from": "header", "name": "...", "jwt_claim": "..."}`, oppure dalla v1.18 `"json_path": "..."`) imposta o sostituisce `identity.subject`: un header che non è una credenziale (o un claim del JWT) si applica subito, senza approvazioni; un cookie o una credenziale crea una bozza che attende le approvazioni di apertura. La scelta è registrata nell'audit (`policy.identity_set`, solo nomi) e il passaggio automatico non la sostituisce più.

Ogni gruppo ha un interruttore (`PUT /api/v1/fleet/groups/{group}/observe` con `{"auto": false}`, audit `fleet.group_observe_auto`; default acceso): spento, `tt-core` non ricava nulla da solo per le policy collegate al gruppo; le versioni già firmate restano. `fleet.observe.enabled: false` spegne la versione automatica per tutti (la policy di partenza resta senza approvazioni se keyguard lo consente).

**«Simula nel mock» (v1.6.1).** La bozza che dichiara un host esterno come servizio (`POST /api/v1/hosts/{pattern}/twin`, [sanitizer](sanitizer.md) §3.5) mette già `hmac` sugli identificativi visti nelle chiamate a quell'host (le stesse decisioni di questo paragrafo, con i template relativi al path della `base`): dichiarare un servizio e mascherare non aprono valori, quindi la versione si applica subito quando keyguard firma le modifiche observe-safe.

Quando le finestre della scoperta e delle parole automatiche sono scadute il corpo non si può più rinnovare così com'è (§1.4): al rinnovo `tt-core` crea una versione senza di esse (`origin: observe-auto`, chiusura, senza approvazioni), così la cattura non si ferma alla scadenza di `not_after`.

`GET /api/v1/fleet/groups/{group}/observe` restituisce lo stato per il wizard: fase (`no_policy`, `waiting_approval`, `listening`, `masked`, `managed`; `managed` dice solo che una persona ha firmato una modifica), l'interruttore del gruppo (`auto`), inizio della cattura, quando è prevista la versione Osserva, chiamate viste, servizi scoperti, campi mascherati (nomi e domini HMAC, mai valori), identità, candidati dell'identità con i segnali del rilevamento (v1.12) e consiglio sul campionamento.

**Campionamento e k.** Il campionamento è per utente; una regola o un valore escono solo con almeno k = 20 utenti distinti (miner, contratti, gate). Il default 0,1 della fase Osserva fa vedere 2·k = 40 utenti con circa 400 utenti nel traffico; con meno utenti si alza il tasso, e finché la policy non lascia uscire valori alzarlo **non apre valori** (si applica subito).

### 7.5 Gruppi di test con k ridotto (v1.18)

Con k = 20 un ambiente di test con pochi tester non produce regole. Un **amministratore** può segnare un gruppo come **gruppo di test** con un k più basso: `PUT /api/v1/fleet/groups/{group}/test-k` con `{"k_min": n, "reason": "..."}`, `n` da 2 a k − 1 (0 lo toglie), motivazione obbligatoria (al più 500 caratteri); gli altri ruoli ricevono `403 forbidden`. Si salva nel gruppo (non nella policy firmata: le sorgenti non cambiano), è nell'audit (`fleet.group_test_k`, con `k_min`, il k dell'installazione e la motivazione) e la console lo mostra sul gruppo, sulle sue regole e sui suoi pacchetti (`test_k_min` e `k_min` in `GET /api/v1/fleet/groups/{group}/observe`).

Effetti: il miner analizza il gruppo con quel k ([rules.md](rules.md) §5.2); un pacchetto di **un solo** gruppo di test si costruisce e si controlla con quel k e porta l'avviso `test_k`; i pacchetti di più gruppi tengono il k dell'installazione. Non va usato su un gruppo con traffico di persone vere: con k = 3 una regola può descrivere il comportamento di tre persone. Vedi [THREAT_MODEL](../THREAT_MODEL.md) §7.
