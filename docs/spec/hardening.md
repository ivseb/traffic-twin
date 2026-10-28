# Rafforzamenti v1.3

> Revisione 1.3, controlli degli host della v1.5 (I6, I11), azione `code` della v1.11 in H1 e H2, controlli dei corpi e analisi XML della v1.19 (I12, §3) · Complementa: [event.md](event.md) §5, [policy.md](policy.md) §1.4 e §4, [sanitizer.md](sanitizer.md) · Implementazione di riferimento: `internal/intake` (parte 1), `internal/policy` (parte 2)

Questo documento raccoglie i controlli che vanno **oltre** il testo degli schemi, perché chiudono canali nascosti o rendono impossibile, anche per un bug a monte, che una sorgente apra più dati del previsto. Ha due parti con valore diverso:

| Parte | Cosa | Valore |
|---|---|---|
| [1](#1-rafforzamenti-dellintake-in-vigore) | Controlli dell'intake di `tt-core` oltre `event.md` §5.1 | **In vigore** da prima della v1.3; qui documentati. Normativi per `tt-core`; per le sorgenti sono un vincolo di conformità (un sanitizer conforme non li fa mai scattare) |
| [2](#2-sottoinsieme-di-sicurezza-lato-sorgente-normativo-dalla-v13) | Sottoinsieme di sicurezza che le **sorgenti** applicano alle policy firmate | **Normativo dalla v1.3**, da implementare in tutte le sorgenti (§2.5) |

---

## 1. Rafforzamenti dell'intake (in vigore)

Tutti i controlli di [event.md](event.md) §5.1 sono implementati. I seguenti vanno oltre il testo dello schema `event.v1`: chiudono canali nascosti (presenza/assenza di un campo, un valore scritto in un nome, un evento ripetuto sotto una policy scaduta) o fanno rispettare regole che il [sanitizer](sanitizer.md) già enuncia. Tutti i vettori di tipo `event` di [`conformance/`](../../conformance/format.md) (384 alla stesura) sono accettati senza modifiche con i controlli attivi: **un sanitizer conforme non li incontra mai**. Un evento rifiutato non si corregge: si conta (per codice, senza contenuto) e compare come `events_rejected` nell'heartbeat della sorgente ([event.md](event.md) §4.4).

| # | Controllo | Perché |
|---|---|---|
| I1 | Le mappe `query`, `headers`, `cookies` e l'oggetto `resp` **vuoti** si rifiutano | Il sanitizer li omette ([sanitizer.md](sanitizer.md) §2, §10.1 regola 7): presente-contro-assente sarebbe un canale da 1 bit |
| I2 | I nomi letterali (chiavi JSON, nomi di query, di cookie e di header) rispettano la regola dei nomi di [sanitizer.md](sanitizer.md) §9.3 punto 3 (niente uuid, email, esadecimali, cifre, jwt, né sequenze di 6 o più cifre); i nomi di header sono in minuscolo | Un sanitizer conforme li ridurrebbe a `{*}`; un nome letterale così fatto indica una sorgente non conforme o un valore nascosto in un nome |
| I3 | Un header ha **un solo** valore (salvo `{*}` e `{trunc}`) | [sanitizer.md](sanitizer.md) §8.0 punto 4 unisce gli header ripetuti |
| I4 | Il `service` di un evento `inbound` è **esattamente** il nome assegnato all'iscrizione (`SourceInfo.service_name`), quando il registro lo conosce, non uno qualsiasi tra i nomi ammessi del gruppo | [event.md](event.md) §1.2: il nome si fissa all'iscrizione (S8) |
| I5 | L'istante dell'evento sta nella finestra della policy: da `created_at` − 5 minuti a `not_after` + 5 minuti | Riproposizione di eventi sotto una policy scaduta o non ancora emessa |
| I6 | `disc` e le parole automatiche si accettano solo mentre sono **attivi** all'istante dell'evento (+ 5 minuti di tolleranza di orologio); un `host:<nome>` non elencato in `segments.hosts_allow` solo se la policy ha `hosts.discovery: auto` (o il campo assente) oppure la scoperta è attiva | La sorgente li ignora dopo la scadenza ([sanitizer.md](sanitizer.md) §3.1, §4.3, §15) |
| I7 | La **busta OTLP** concorda con l'evento: attributi della risorsa, `service.name`, versione dello scope, `tt.schema`, `tt.policy.hash`, `traceId`, `spanId`, `timeUnixNano`; nessun attributo in più, nessun campo sconosciuto | Ogni altro dato accanto al corpo canonico è un canale laterale ([event.md](event.md) §4.2) |
| I8 | La **forma del corpo** segue il content type: albero JSON, mappa dei nomi per i form, solo marcatori `drop` e `trunc` negli altri casi; array, chiavi e profondità sono limitati dai `limits` della policy | [sanitizer.md](sanitizer.md) §9.1 e limiti |
| I9 | Le rotte `template` DEVONO indicare un'operazione dichiarata dalla policy e un path coerente con il suo template e con la base del servizio; le rotte `raw` possono portare solo marcatori `drop` e segmenti letterali ammessi | [event.md](event.md) §5.1 punto 6 (S9) |
| I10 | Un evento che richiederebbe un nuovo monitor di cardinalità oltre il massimo (`MaxMonitors`) si rifiuta | Fail-closed invece di memoria illimitata |
| I11 | **(v1.5)** Un `host:<pattern>` non elencato deve essere un pattern di [sanitizer.md](sanitizer.md) §3.5 con ogni etichetta letterale conforme alle regole a–c dell'etichetta sicura (niente sei cifre consecutive, niente dodici esadecimali consecutivi, `^[a-z][a-z0-9-]{0,62}$`), al più 127 etichette e un host di partenza di al più 253 byte, porta 1–65535 senza zeri iniziali, oppure `ip:private` / `ip:public` con la porta. Le etichette letterali alimentano gli sketch per dominio registrabile e posizione ([event.md](event.md) §5.2, §5.4) | La regola si verifica di nuovo in zona B: una sorgente che lascia passare un valore in un'etichetta viene rifiutata (`host_not_allowed`), non corretta |
| I12 | **(v1.19)** `fmt`, `xmlns` e `soap_action` solo sotto l'interruttore `bodies` che li produce e con un `ct` coerente; chiavi `@nome`/`#text` solo in un corpo XML, foglie solo stringa e mai `num:`; pattern `ns:` con la regola delle sequenze di [sanitizer.md](sanitizer.md) §22.2 punto 9 (niente sei cifre, dodici esadecimali o sequenze oltre 64 byte, niente `@`); `drop:doc`/`drop:file` solo con tipi e classi della lista chiusa; array oltre `max_array` solo in un corpo grande (`size` `lmax`) ed entro `large_array`/`large_nested_array`; `keep:` di `code(alnum)` con la sua forma | Una sorgente difettosa o modificata non può usare i campi nuovi come canale: ogni campo esiste solo dove la policy firmata lo prevede ([event.md](event.md) §5.1) |

I rifiuti si contano per **codice**, un insieme chiuso senza contenuto (`internal/intake/reasons.go`): `event_too_large` (oltre 512 KiB), `invalid_json`, `non_canonical`, `schema`, `source_mismatch`, `policy_unknown`, `policy_mismatch`, `policy_group`, `policy_time`, `service_not_allowed`, `host_not_allowed`, `op_unknown`, `path_shape`, `segment_not_allowed`, `subject_not_allowed`, `value_not_allowed`, `disc_not_allowed`, `body_shape`, `limits`, `otlp_shape`, `resource_mismatch`, `monitor_overflow`.

### 1.1 Note di comportamento

- **Quarantena.** Gli stati sono `open` → `closed` (una policy ha chiuso il campo: la riscrittura continua) e si esce solo con lo scioglimento (2 approvazioni, imposte dal chiamante). Riscrivere il nome di un header, di una query o di un cookie in quarantena sposta i suoi valori sotto `{*}` come array. Dalla v1.5 la quarantena di un host (tipi `host` e `host-label`, allarme `host_cardinality`) riscrive solo le etichette interessate in `{*}` (l'etichetta registrabile, o quella nella posizione in quarantena), non tutto l'host in `host:unlisted`; un risultato fuori grammatica (solo per host strani di `segments.hosts_allow`) diventa `host:unlisted`.
- **Soglie di cardinalità** con stime HyperLogLog: il cinquantunesimo valore distinto può contare come cinquantesimo; la soglia è una stima, non un conteggio ([event.md](event.md) §5.2).
- **Dimensioni.** Il listener dell'intake DEVE accettare corpi di almeno 4 MiB (`intake.http.max_body_bytes`, default di `tt-core`), perché una richiesta OTLP può arrivare a 4 MiB ([event.md](event.md) §4.4).

---

## 2. Sottoinsieme di sicurezza lato sorgente (normativo dalla v1.3)

**Decisione di progetto.** Una sorgente non si fida della validazione di `tt-core` né di keyguard ([policy.md](policy.md) §4 punto 1): ricontrolla lo schema e i domini HMAC riservati di ogni policy firmata. Dalla v1.3 ricontrolla anche un sottoinsieme *fisso* delle regole di [policy.md](policy.md) §1.4, quelle la cui violazione espone credenziali o apre dati su larga scala. È difesa in profondità contro un bug di validazione in `tt-core` o in keyguard che porti alla firma di una policy pericolosa: la firma vale a quel punto, ma le persone non l'avrebbero approvata.

### 2.1 Regole

Una sorgente DEVE **rifiutare** una policy firmata (corpo `tt.policy.body/v1`) se vale **una** di queste condizioni:

| # | Condizione | Dove si applica |
|---|---|---|
| H1 | Un'azione `keep`, `code` (v1.11) **o** `hmac` su un nome di header tra `authorization`, `cookie`, `set-cookie`, `proxy-authorization` | Regole `headers` di `request`, `response` ed `errors`, sia in `global` sia nelle operazioni e nei servizi. Il confronto è sul nome in minuscolo. (`x-api-key` resta vietata per `keep` come in §1.4 di `policy.md`, ma non rientra nel sottoinsieme della sorgente) |
| H2 | Un'azione `keep`, `code` (v1.11) **o** `hmac` su un `tt-path` che contiene **un qualsiasi passo jolly** (`.*` per i membri o `[*]` per gli elementi di array: `$[*]`, `$[*].x`, `$.a[*]`, `$.a.*`, combinazioni annidate) | Solo nelle regole **globali** (`global.*`): corpi `request`, `response`, `errors`. Nelle regole di servizio e di operazione `.*` resta ammesso. `bucket` su `.*` globale resta vietato da `tt-core` e da keyguard (§1.4) ma non è richiesto alla sorgente |
| H3 | `discovery.enabled = true` con `discovery.expires_at` oltre `created_at` + **7 giorni**; oppure `segments.auto_words = true` con `segments.auto_words_expires_at` oltre `created_at` + 7 giorni (una scadenza mancante con `auto_words` attivo resta un errore di validità del corpo, come già in §4 di `policy.md`) | Corpo compilato. Il confronto è fra istanti del corpo, non con l'orologio della sorgente |

Le condizioni non dipendono dall'orologio né dal gruppo: sono proprietà del corpo.

### 2.2 Comportamento

Una policy che viola H1–H3 si tratta **come qualsiasi altra policy rifiutata** ([policy.md](policy.md) §4): la sorgente la scarta senza aggiornare `issued_seq`, tiene la precedente se è ancora valida, altrimenti non cattura; l'heartbeat riporta `policy_rejected`; in `last_errors` il codice è `policy_unsafe` (solo il codice, mai il contenuto). Il controllo si fa a ogni caricamento della policy, **anche dalla cache locale** all'avvio.

### 2.3 Allineamento di `tt-core` e keyguard

Perché una sorgente non scarti una policy che le persone hanno approvato, `tt-core` (compilazione) e keyguard (firma, §3.2 punto 1 di [keyguard.md](keyguard.md)) DEVONO rifiutare le stesse policy:

- H1: `internal/policy` vieta `keep` su quei nomi (più `x-api-key`) e, dalla v1.3, anche `hmac` su `authorization`, `cookie`, `set-cookie`, `proxy-authorization`;
- H2: già vietato (con `bucket` in più), vedi §1.4 di `policy.md`; il controllo di `tt-core` e keyguard usa lo stesso predicato dei passi jolly (`.*` o `[*]`) e vale per `keep`, `code`, `hmac` e `bucket`; la sorgente richiede solo `keep`, `code` e `hmac`;
- `code` (v1.11): `tt-core` e keyguard lo accettano solo sui campi di stato e di codice di §1.5 di `policy.md`, quindi mai su un header di credenziali; la sorgente non ricontrolla la lista dei nomi (applica sempre la forma di [sanitizer.md](sanitizer.md) §5.6), ma rifiuta `code` dove rifiuta `keep` (H1, H2);
- H3: già vietato alla compilazione; la regola del sanitizer che spegne comunque scoperta e parole automatiche a `created_at` + 7 giorni ([sanitizer.md](sanitizer.md) §4.3, §15) **resta** come seconda barriera.

### 2.4 Rapporto con la regola del sanitizer

Il sanitizer continua ad applicare le sue regole su una policy accettata, comprese le scadenze di §4.3 e §15. Il sottoinsieme H1–H3 è *prima*: decide se la policy si accetta.

### 2.5 Chi lo implementa

Tutte le sorgenti che accettano policy firmate. Ognuna ha la propria validazione della busta, tranne le sorgenti Go, che condividono il codice.

| Sorgente | Dove | Stato |
|---|---|---|
| Go (riferimento): `internal/policy` (`ValidateSource`), usata da `internal/sanitizer`, dal decoder di buste e quindi da `internal/sourceclient` | Condiviso da `tt-egress`, dall'SDK Go e dall'adattatore OBI | Implementato (H1–H3) |
| `tt-egress` (`internal/egress`) | Eredita da `internal/sourceclient` | Implementato (eredita) |
| SDK Go (`sdk/go`, riusa `internal/sourceclient`) | Eredita | Implementato (eredita) |
| Adattatore OBI (`internal/obi`) | Eredita da `internal/sourceclient` | Implementato (eredita) |
| SDK Node (`sdk/node`) | Validazione della policy nel proprio sanitizer | Implementato |
| SDK Python (`sdk/python`) | Come sopra | Implementato |
| SDK Java (`sdk/java`) | Come sopra | Implementato |
| SDK .NET (`sdk/dotnet`) | Come sopra | Implementato |
| SDK PHP (`sdk/php`) | Come sopra | Implementato |

Una sorgente è conforme alla v1.3 solo se supera i vettori di §2.6.

### 2.6 Vettori di conformità

Ogni sorgente DEVE superare i vettori di rifiuto della v1.3 (formato di [`conformance/format.md`](../../conformance/format.md)): una policy per ciascuna delle condizioni H1 (quattro nomi × `keep` e `hmac`, in `global` e in un'operazione, in `request`, `response` ed `errors`), H2 e H3 (scadenza a `created_at` + 7 giorni + 1 secondo, per scoperta e per parole automatiche), più i casi limite accettati (scadenza esattamente a `created_at` + 7 giorni; `.*` con `keep` in un servizio o in un'operazione). La verifica attesa è «policy rifiutata, nessun evento». I vettori 1701–1783 coprono questi casi (sezione 1700 di [`conformance/README.md`](../../conformance/README.md)); dalla v1.11 i vettori 1850–1857 coprono `code` in H1 (quattro header) e H2 (passi jolly globali in `request`, `response`, `errors`) e 1828 il caso accettato (`code` su un passo jolly in un servizio). I vettori esistenti riscritti per la v1.3 sono 0122, 0123, 0703, 0704, 0802, 0803, 0809, 0901, 0902, 0903, 0952, 0953, 1209 e 1213: ciascuno prova lo stesso comportamento di prima, con la policy adeguata alle regole H1–H3.

### 2.7 Messa in vigore

La parte 2 è implementata in `internal/policy` e `internal/sourceclient` (Go) e in tutti gli SDK (§2.5). In un'installazione è in vigore quando le sorgenti in uso sono aggiornate a questa versione. `tt-core` non può verificarlo (l'iscrizione riporta solo la versione dell'SDK): fino ad allora, per le sorgenti non aggiornate, `tt-core` e keyguard (§2.3) restano l'unica barriera per H1 con `hmac`, H2 e H3.

---

## 3. Analisi dei corpi XML e multipart alla sorgente (v1.19)

Normativo per tutte le sorgenti ([sanitizer.md](sanitizer.md) §22). L'analisi avviene **dentro l'applicazione** strumentata, su dati che arrivano da client e servizi esterni non fidati: deve essere sicura per costruzione, non per configurazione.

| # | Regola | Perché |
|---|---|---|
| X1 | Nessun analizzatore XML generico: ogni sorgente implementa il sottoinsieme chiuso di §22.2 (stesso albero in tutti i linguaggi, vettori 2300–2362) | Le librerie XML risolvono entità, leggono DTD esterne o seguono `xinclude` a seconda della versione e della configurazione |
| X2 | `<!DOCTYPE`, `<!ENTITY` e ogni dichiarazione `<!` diversa da commenti e `CDATA` rendono il corpo **non valido** (`trunc:invalid-xml`): nessuna DTD, interna o esterna, si legge mai | Difesa contro XXE (lettura di file, SSRF verso la rete interna) e contro l'espansione di entità («billion laughs», vettore 2341) |
| X3 | Si risolvono solo le cinque entità predefinite e i riferimenti numerici a caratteri XML validi; qualsiasi altro `&` invalida il corpo | Nessuna espansione, nessun riferimento esterno |
| X4 | Limiti: al più 256 elementi aperti (annidamento), il corpo entro `max(limits.max_body_bytes, bodies.max_large_body_bytes)` byte decodificati, `max_depth`, `max_keys` e `max_array` sull'albero, al più 64 voci `xmlns` | Memoria e tempo lineari nella dimensione del corpo; nessuna ricorsione illimitata |
| X5 | Un errore in qualsiasi punto invalida tutto il corpo: niente analisi parziali né recupero | Un corpo costruito per confondere l'analisi non fa uscire nulla di più del marcatore |
| X6 | Multipart: confine conforme a RFC 2046, intestazioni delle parti con nomi token, `content-disposition: form-data` obbligatoria; le parti file escono solo come tipo e classe (`drop:file:<tipo>:<classe>`), il loro contenuto non si analizza oltre i byte iniziali | Un file caricato (documento d'identità, contratto firmato) non esce mai, nemmeno con una regola `keep` |
| X7 | Documenti base64: si decodificano solo per riconoscere il tipo dai byte iniziali; esce `drop:doc:<tipo>:<classe>`, mai il contenuto, qualunque regola ci sia | Il tipo e la dimensione servono al mock per generare un documento valido, il contenuto no |
| X8 | Corpi grandi: la sorgente tiene in memoria al più il limite grande + 1 byte e conta il resto; oltre il limite il corpo è `trunc:size`; gli array si troncano a `large_array`/`large_nested_array` con il marcatore della classe del totale | Struttura delle liste ricche senza far crescere memoria e evento oltre i limiti (evento ≤ 512 KiB) |

