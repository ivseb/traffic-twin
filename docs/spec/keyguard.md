# Keyguard v1 — custodia delle chiavi in zona B

> Formato: `tt.keyguard/v1` · Revisione 1.4, firma senza approvazioni delle modifiche che non aprono valori della spec v1.6 (§3.2) · API: [`api/keyguard-api.v1.openapi.yaml`](../../api/keyguard-api.v1.openapi.yaml)

**Decisione di progetto D-B2.** In zona B le chiavi esistono **solo** dentro `tt keyguard`, un processo piccolo e separato (sottocomando dello stesso binario `tt`). `tt-core`, il magazzino, la UI e gli analisti **non** possiedono mai:

- le chiavi HMAC (tutte le epoche e tutti i `kid`);
- la chiave di firma delle **policy**;
- la chiave di firma dei **pacchetti twin**.

Così chi legge il magazzino, una copia di backup o la UI vede solo token e non può fare attacchi a dizionario. Le sorgenti in zona A hanno la propria copia della chiave HMAC (§7.1 del [sanitizer](sanitizer.md)); keyguard ha la stessa chiave, per i controlli del gate.

---

## 1. Distribuzione

- Si installa **separato** da `tt-core`: un altro container, un altro pod (namespace dedicato in Kubernetes) o un altro host. Lo stesso host è ammesso solo per installazioni di prova, con un avviso nella UI.
- Ascolta **solo** su un socket Unix (stesso host, `TT_KEYGUARD_SOCKET`, permessi `0600` o `0660`) o su mTLS (`TT_KEYGUARD_LISTEN`) con un certificato client accettato: quello di `tt-core`, pinnato per impronta SPKI (`TT_KEYGUARD_CLIENT_PINS`) e, facoltativamente, verificato su una CA. Nessun altro client. L'autenticazione è quella del trasporto: l'API non ha token né header di identità.
- Ha un **proprio database SQLite** (`TT_KEYGUARD_DB`, default `data/tt-keyguard.db`), separato da quello di `tt-core`: contiene i corpi firmati, le approvazioni, i filtri, i budget e il registro di audit (§4). `tt-core` non lo apre mai.
- Non fa chiamate in uscita, salvo il webhook di allarme configurato (§5).
- Chiavi su file con permessi `0600` o in variabili d'ambiente:
  - `TT_KEYGUARD_HMAC_KEYS_FILE`: righe `kid:base64url` come §7.1 del sanitizer;
  - `TT_KEYGUARD_POLICY_SIGNING_KEY_FILE`, `TT_KEYGUARD_PACK_SIGNING_KEY_FILE`: seed Ed25519 di 32 byte in base64url, con un `kid` (`kid:base64url`). La **prima** riga non revocata è la chiave attiva; le righe successive sono chiavi ritirate, dalla più recente alla più vecchia. All'avvio il seed di ogni chiave ritirata firma l'**endorsement** della chiave immediatamente più nuova (§6), poi in memoria resta solo la parte pubblica (il seed si azzera). Il seed di una chiave ritirata va quindi tenuto nel file **fino alla revoca** del suo `kid`: senza, la chiave nuova non raggiunge le sorgenti già iscritte. Un `kid` ripetuto è un errore;
  - `TT_KEYGUARD_REVOKED_KIDS`: `kid` revocati (HMAC o di firma), che keyguard rifiuta di usare e non annuncia.
- Verifica delle approvazioni con OIDC (§3.2 punto 4), facoltativa ma raccomandata in produzione: `TT_KEYGUARD_OIDC_ISSUER`, `TT_KEYGUARD_OIDC_AUDIENCE` (l'**audience dedicata alle approvazioni**: il client id di un client "approvazioni" registrato apposta presso l'IdP, **mai** quello del login di `tt-core`), `TT_KEYGUARD_OIDC_JWKS_FILE` o `TT_KEYGUARD_OIDC_JWKS_URL`, `TT_KEYGUARD_OIDC_ROLES_CLAIM` (obbligatorio con OIDC: il claim, stringa o lista, da cui keyguard legge i ruoli) e `TT_KEYGUARD_OIDC_ROLE_MAPPING` (coppie `gruppo=ruolo` separate da virgole; senza mapping i valori del claim sono nomi di ruolo).
- Le chiavi non si esportano mai da nessuna API; non compaiono nei log.

- **Un solo `tt-core` per keyguard (v1).** Keyguard protegge dal ritorno indietro: rifiuta una policy con `version` o `issued_seq` non maggiori dell'ultima firmata (`version_not_increasing`, `issued_seq_not_increasing`). Un secondo `tt-core` sullo stesso keyguard ha contatori propri e parte da capo, quindi sarebbe rifiutato. Non è supportato in v1: ogni core ha il suo keyguard (anche per le prove di carico). L'API di amministrazione lo segnala con `409 keyguard_state_conflict` e una spiegazione, non più con `502 keyguard_refused`.

## 2. Filtro dei token reali

Il controllo "prova al contrario" (G6) ha bisogno dell'insieme dei **token reali** osservati. Keyguard lo tiene come **filtro di Bloom** per epoch, alimentato dall'intake:

- `POST /keyguard/v1/tokens` riceve lotti di token `tk1:` che l'intake ha accettato (append-only); keyguard li inserisce nel filtro dell'epoch e del `kid` indicati;
- dimensionamento: tasso di falsi positivi ≤ 10⁻⁶ alla capienza dichiarata; un falso positivo produce un `fail` spurio del gate (direzione sicura);
- i filtri più vecchi della finestra di conservazione del magazzino si eliminano.

Limite dichiarato (threat model §7): keyguard si fida dei token che `tt-core` gli invia. Protegge le chiavi da chi **legge** la zona B, non da un processo `tt-core` interamente compromesso, che potrebbe non inviare i token.

## 3. Operazioni

### 3.1 `match`: prova al contrario

Ingresso: un insieme di **stringhe candidate** e il **contesto** (`policies`: lista di `{policy_id, version}` da cui si ricavano domini, epoch e `kid`).

Per ogni stringa candidata `s` keyguard calcola i token per:

- ogni `kid` tra `hmac.kid` e `hmac.accept_kids` delle policy indicate;
- ogni `epoch` delle policy indicate;
- ogni dominio presente in una regola `hmac` delle policy indicate, più `subject`;
- ogni rappresentazione canonica di `s`: i byte della stringa; inoltre, se `s` è un lessema numerico JSON valido entro i limiti di §5.3 del sanitizer, la sua forma canonica (§10.2); i numeri JSON del pacchetto si passano già in forma canonica.

e controlla l'appartenenza al filtro. Restituisce solo un **booleano per stringa**, mai i token.

Le policy del contesto si ricavano dai corpi che **keyguard stessa ha firmato** (non da una descrizione inviata da `tt-core`): una versione mai firmata è `422 unknown_policy`, e se keyguard non possiede uno dei `kid` HMAC il controllo fallisce (`422 kid_not_held`, fail-closed) invece di rispondere «nessun positivo».

Limiti, configurabili ma con questi default (`TT_KEYGUARD_MATCH_MAX_BATCH`, `_MATCH_INTERVAL`, `_MATCH_DAILY_BUDGET`):

- al massimo 10 000 stringhe per chiamata (`400 batch_too_large`) e 1 chiamata al secondo (`429 rate_limited`, `Retry-After`);
- al massimo 5 000 000 di stringhe al giorno, conteggio **persistente** (`429 budget_exceeded`); la firma dei pacchetti consuma lo stesso budget con le stringhe distinte del pacchetto;
- ogni **risposta positiva** è un evento d'allarme: voce nel registro di audit di keyguard e webhook (§5). In uso normale i positivi sono zero; un uso come oracolo per attacchi a dizionario lascia quindi traccia a ogni colpo.

### 3.2 `policy/sign`: firma delle policy

Ingresso: i byte del corpo compilato (`tt.policy.body/v1`), l'identità del **proponente** e le **approvazioni** (`user`, `roles`, `at`; `id_token` se c'è OIDC; `reason` per l'admin).

Keyguard:

1. valida il corpo: schema, **tutte** le regole di [policy.md](policy.md) §1.4 (compresa la forma canonica: keyguard firma esattamente i byte che ha analizzato), `created_at` non nel futuro, `not_after` non scaduto e non oltre la validità massima (`TT_KEYGUARD_POLICY_MAX_VALIDITY`, default 30 giorni), `kid` HMAC posseduti e non revocati (`422 invalid_body`, `not_canonical`, `invalid_times`, `kid_not_held`, `kid_revoked`);
2. calcola **lui stesso** se la modifica apre dati, con le regole di [policy.md](policy.md) §5 e **senza fidarsi di `tt-core`**. La classificazione è più severa di quella della v1.1: il corpo nuovo si confronta (a) con l'**ultimo corpo firmato** per lo stesso `policy_id` (targets compresi: un gruppo aggiunto apre) **e** (b) per **ogni gruppo** di `targets.groups`, con la **policy corrente del gruppo** (il corpo firmato più recente che lo riguarda, se non scaduto; qui si confronta solo ciò che le sorgenti del gruppo ricevono). Basta un confronto che apre, una prima policy per quel `policy_id` o un gruppo senza policy corrente, perché la modifica **apra**. Il motivo (un codice, mai un valore) va nell'audit. `version` DEVE superare l'ultima versione firmata del `policy_id` (`422 version_not_increasing`);
3. verifica le approvazioni: al massimo 8, ciascuna ben formata e non datata nel futuro, da **persone distinte** (con OIDC, distinte per `sub`). Il numero richiesto è 1 per le chiusure e `TT_KEYGUARD_OPENING_APPROVALS` (1 o 2, default 2) per le aperture; contano le approvazioni di utenti con ruolo `policy-approver`, e con 2 richieste almeno una NON DEVE essere del proponente. Con una sola richiesta, quindi, keyguard accetta anche il proponente stesso: il divieto che l'autore approvi la propria modifica, anche di chiusura, è una regola di `tt-core` ([policy.md](policy.md) §5), non un controllo di keyguard. **Eccezione:** una singola approvazione di un utente con ruolo `admin`, con motivazione non vuota, basta sempre (anche se l'admin è il proponente), salvo `TT_KEYGUARD_ADMIN_OVERRIDE=false` (`403 admin_override_disabled`, `admin_reason_required`; [policy.md](policy.md) §5). In `tt-core` l'admin è il superutente (policy.md §5, v1.6): questa variabile è l'**unico** modo di limitarlo, ed è una scelta dell'installatore; il default lascia l'approvazione dell'admin attiva, tracciata da motivazione, `approval_mode: admin` e allarme. Con OIDC il ruolo `admin` DEVE comunque essere nel token verificato (punto 4). La risposta riporta `approval_mode`: `standard`, `single` (apertura accettata con `TT_KEYGUARD_OPENING_APPROVALS=1`) o `admin`;
4. se è configurato un emittente OIDC (`TT_KEYGUARD_OIDC_ISSUER`, `TT_KEYGUARD_OIDC_AUDIENCE`), **ogni** approvazione DEVE includere un ID token OIDC dell'approvatore ottenuto con uno **step-up** per quella modifica (v1.4, red team round 3: RT3-KG-1…4). Keyguard verifica da solo:
   - firma (JWKS dell'emittente, da file o URL, in cache), `iss`, `aud` uguale all'**audience dedicata alle approvazioni** (un ID token del login di `tt-core` ha come `aud` il client del login e non passa), `exp`;
   - `iat` e `auth_time` di al massimo 10 minuti (`auth_time` è obbligatorio: `tt-core` chiede `prompt=login` e `max_age=600`, quindi l'approvatore si autentica di nuovo al momento dell'approvazione);
   - il **legame con la modifica**: `nonce` DEVE valere `base64url(SHA-256("tt.approve/v1" || 0x00 || "policy-approve" || 0x00 || policy_id || 0x00 || version || 0x00 || body_sha256))`, dove `version` è in decimale e `body_sha256` è lo SHA-256 esadecimale del corpo canonico **senza** `issued_seq`, `created_at` e `not_after` (gli unici campi noti solo alla firma; keyguard li controlla comunque al punto 1). Keyguard lo ricalcola dal corpo che riceve: un token di login, di un'altra policy, di un'altra versione o di una bozza ricompilata con altri gruppi non vale;
   - i **ruoli**: keyguard li legge dal claim `TT_KEYGUARD_OIDC_ROLES_CLAIM` del token verificato, attraverso `TT_KEYGUARD_OIDC_ROLE_MAPPING`, e **non** da ciò che dichiara `tt-core`: un ruolo `admin`, `policy-approver` o `publisher` dichiarato ma assente dal token è `403 role_unverified`;
   - `sub` distinti, e **lo stesso token mai due volte**: per ogni token presentato in una firma riuscita (anche in modalità admin, dove conta solo l'approvazione dell'admin) keyguard conserva due impronte, una su `iss`, `sub` e `jti` (o `iat` e `nonce` se manca `jti`) e una sulla firma decodificata, e rifiuta un token se ne ha già vista una. I segmenti del token DEVONO essere base64url canonico (senza padding né bit finali diversi da zero): la stessa firma ha una sola grafia accettata.

   Senza OIDC, keyguard si fida dell'identità e dei ruoli dichiarati da `tt-core` e lo segnala nel suo stato (`approvals_unverified: true`), visibile nella UI accanto a ogni approvazione: è una **garanzia ridotta**, accettabile solo per installazioni su un solo host o di sviluppo (threat model §7). Il registro di audit riporta `approvals_unverified` e `approvals_bound`.

   **Configurazione dell'IdP.** Si registrano due client presso lo stesso emittente: quello del login di `tt-core` (`auth.oidc.client_id`, redirect `/api/v1/auth/oidc/callback`) e quello delle approvazioni (`auth.oidc.approval_client_id` = `TT_KEYGUARD_OIDC_AUDIENCE`, redirect `/api/v1/auth/oidc/stepup/callback`, code flow con PKCE). Il client delle approvazioni DEVE mettere nell'ID token il claim dei ruoli (per esempio i gruppi) e `auth_time`, e rispettare `prompt=login`/`max_age`. `tt-core` controlla che emittente e audience riportati da keyguard (§7) coincidano con il suo client delle approvazioni e che l'audience sia diversa dal client del login (`503 stepup_misconfigured` altrimenti). Lo step-up lato `tt-core` è descritto nell'API di amministrazione (`GET /api/v1/auth/oidc/stepup`);
5. verifica che `issued_seq` sia maggiore di qualsiasi `issued_seq` già firmato (`403 issued_seq_not_increasing`; il controllo e l'inserimento sono una sola transazione, quindi il contatore resta crescente anche dopo un riavvio);
6. firma i byte `"tt.policy.body/v1" || 0x00 || corpo` con Ed25519, **registra** il corpo e le approvazioni nel proprio database e solo dopo restituisce `alg`, `kid`, `sig`, `classification` (il verdetto di keyguard, che `tt-core` usa al posto del proprio) e `approval_mode`.

**Modifiche che non aprono valori (v1.6, [policy.md](policy.md) §7).** Prima del punto 3 keyguard calcola anche, da solo e con la stessa funzione di `tt-core` (`policy.ClassifyValues`), se la modifica apre valori: contro l'ultimo corpo firmato dello stesso `policy_id` e contro la policy corrente di ogni gruppo di destinazione (come al punto 2). Se nessun confronto apre valori, la lista delle approvazioni è **vuota** e `TT_KEYGUARD_OBSERVE_AUTO` è acceso (default `true`, riportato come `observe_auto` nello stato), keyguard salta i punti 3 e 4 e firma con `approval_mode: observe`. Una modifica che apre valori senza approvazioni è `403 insufficient_approvals`, con il motivo nell'audit (`value_reason`). La risposta riporta sempre `opens_values`. Con approvazioni presenti il controllo resta quello dei punti 3 e 4.

Un rifiuto è sempre una voce d'audit e un allarme (§5). Le operazioni di firma sono serializzate.

### 3.3 `policy/renew`: rinnovo della scadenza

Re-firma un corpo che differisce dall'ultimo firmato per lo stesso `policy_id` **solo** nei campi `version`, `issued_seq`, `created_at` e `not_after`. Non servono approvazioni. Serve a rinnovare `not_after` senza intervento umano.

Un rinnovo non può riportare in vita una policy: l'ultimo corpo firmato NON DEVE essere scaduto (`403 expired`: serve una nuova firma con approvazioni), `version` NON DEVE diminuire e la policy DEVE essere ancora quella **corrente** di ogni gruppo di destinazione (`403 superseded`); anche `issued_seq` DEVE crescere. Il corpo si valida come in §3.2 punto 1.

### 3.4 `pack/sign`: firma dei pacchetti

Ingresso: l'archivio `.ttpack` (senza `manifest.sig.json`, al massimo 256 MiB) e, facoltativo, l'header `X-TT-Approval`: l'approvazione di chi ha chiesto di rilasciare il pacchetto (JSON di un'approvazione come in §3.2, in base64url senza padding).

`tt-core` chiama l'operazione **due volte** per ogni pacchetto: alla costruzione, senza approvazione, per sapere se il gate passa e ottenere la firma; al rilascio, con l'approvazione del richiedente. Ed25519 è deterministico, quindi le due firme sono uguali e `tt-core` DEVE rifiutare il rilascio se differiscono. Con l'approvazione, il richiedente DEVE avere il ruolo `publisher`; in alternativa il ruolo `admin` con una motivazione non vuota ([policy.md](policy.md) §5): la risposta riporta `approval_mode` `admin`, l'audit registra la motivazione e parte l'allarme `pack.admin_approval`. L'approvazione dell'admin non salta nessun controllo: un positivo di `reverse-hmac` o un gate non superato rifiutano sempre. Senza ruolo adatto: `403 missing_role`. Se è configurato OIDC, l'approvazione porta il suo ID token come in §3.2 punto 4, legato al pacchetto: `nonce = base64url(SHA-256("tt.approve/v1" || 0x00 || "pack-publish" || 0x00 || pack_id || 0x00 || manifest_sha256))` con `manifest_sha256` lo SHA-256 esadecimale di `manifest.json`; `publisher` (o `admin`) DEVE essere nel claim dei ruoli del token, e anche questo token si usa una volta sola. La firma dei pacchetti ha un limite di frequenza (`TT_KEYGUARD_PACK_INTERVAL`, default 1 secondo, `429 rate_limited`).

Keyguard:

1. legge l'archivio **in due passaggi** (v1.4): il primo controlla le intestazioni (solo file regolari con nomi ammessi, niente duplicati né `manifest.sig.json`, limiti di dimensione, espansione totale limitata anche se le intestazioni mentono) e legge solo `manifest.json` (al massimo 4 MiB); il secondo legge **solo** i file elencati, ciascuno in un buffer della dimensione dichiarata. Un archivio che si espande oltre i limiti (gzip bomb) è rifiutato senza allocare la memoria dichiarata. Poi verifica che l'elenco `files` del manifest coincida con i file ricevuti, dimensioni comprese, e che gli hash SHA-256 corrispondano (`403 invalid_pack`, `hash_mismatch`). Il manifest DEVE essere **canonico** ([pack.md](pack.md) §1: codifica canonica esatta, nessuna chiave duplicata, chiavi scritte come i campi, nessuna chiave sconosciuta) e `created_at` NON DEVE essere più di 5 minuti nel futuro rispetto all'orologio di keyguard (`403 invalid_pack`): keyguard firma esattamente i byte che ogni lettore interpreta allo stesso modo;
2. verifica che `gate-report.json` sia valido per quel `pack_id`, abbia `verdict = "pass"` e contenga, tutti `pass`, i controlli `provenance`, `pii-detectors`, `k-thresholds` (eseguiti da `tt-core`) e `reverse-hmac` (`403 gate_report`),
   e che `not_after`, se presente nel manifest, sia successivo a `created_at` ([pack.md](pack.md) §2.1);
3. esegue **lui stesso** il controllo `reverse-hmac` (§3.1) su **tutte** le stringhe e i numeri di tutti i file del pacchetto (contratti, regole, `world.jsonl`, `faults.json`, esempi), usando le policy elencate in `manifest.source.policies`;
   Il controllo copre anche le **chiavi** degli oggetti. Un positivo è `403 reverse_hmac`, con i `findings` (file e puntatore, mai il valore); i file che non sono JSON valido non si possono controllare e il pacchetto si rifiuta.
   **Puntatori senza valori (v1.4, red team round 2).** Un segmento del puntatore che è una chiave di oggetto ed è esso stesso un positivo non si scrive mai: diventa `@k<n>`, l'`n`-esimo membro (da 0) dell'oggetto padre. Così né una chiave positiva (`2:/profile/@k0` invece di `2:/profile/<id reale>`) né un positivo sotto di essa (`2:/@k3/status`) portano il valore. Il pre-controllo di `tt-core` (`internal/gate`) segue la stessa regola per tutti i controlli del gate: ogni chiave che è oggetto di un finding (positivo, chiave che sembra PII, chiave sconosciuta o senza provenienza) è sostituita da `@k<n>` in tutti i puntatori del rapporto. Vale per i rapporti **nuovi**: i `gate-report.json` già salvati prima della v1.4 non sono riscritti (sono pacchetti rifiutati, non pubblicabili; chi li vuole eliminare li cancella con la retention dei pacchetti);
4. se tutto passa, firma i byte esatti di `manifest.json` con la chiave del gate e restituisce `manifest.sig.json` (come oggetto `signature`) insieme all'esito del suo controllo (`reverse_hmac`) e ad `approval_mode`. `tt-core` usa l'esito per il `gate-report.json` mostrato nella UI.

Il `gate-report.json` dentro il pacchetto contiene già il risultato di `reverse-hmac` calcolato da keyguard in un passaggio precedente (`match` in modalità "pre-controllo"): keyguard ripete il controllo al momento della firma e rifiuta se l'esito è diverso. Le stringhe distinte del pacchetto consumano il budget giornaliero di `match` (§3.1).

## 4. Audit

Keyguard tiene un **proprio** registro di audit append-only, nel **proprio database SQLite** (§1), non in un file JSONL: una tabella a catena di hash in cui ogni voce contiene l'hash della precedente, protetta da trigger che vietano modifiche e cancellazioni. Ogni operazione registra: istante, operazione (`keyguard.policy_sign`, `keyguard.policy_renew`, `keyguard.pack_sign`, `keyguard.match`, `keyguard.tokens`), esito, conteggi (stringhe controllate, positivi), `policy_id`/`version` o `pack_id`, `kid`, classificazione e motivo di apertura, `approval_mode`, identità degli approvatori e, per l'approvazione dell'admin, la motivazione. **Mai** stringhe candidate, token o valori. Se la scrittura dell'audit fallisce, la risposta è un errore e la firma non viene restituita: nessuna firma esce senza traccia.

`GET /keyguard/v1/audit?since_seq=N` restituisce a `tt-core` fino a 1000 voci successive a `N`, con `seq`, `at`, `op`, `outcome` (`ok`, `refused`, `alert`), `detail` (stringhe), `prev_hash` e `hash`, per la UI (ruolo `auditor`). La catena si verifica ripercorrendo gli hash (`VerifyAudit` nel pacchetto `internal/keyguard`; non c'è ancora un comando dedicato).

## 5. Allarmi

Webhook configurabile (`TT_KEYGUARD_ALERT_WEBHOOK`) per: risposte positive di `match` (`match.positive`) e di `pack/sign` (`pack.positive`), superamento dei limiti (`rate.limited`, `budget.exceeded`), approvazioni rifiutate (`policy.approval_refused`), firma rifiutata (`sign.refused`), approvazione dell'admin su una policy (`policy.admin_approval`) o su un pacchetto (`pack.admin_approval`). Il corpo dell'allarme contiene solo tipo, istante e conteggi. Gli allarmi finiscono sempre anche nel log di keyguard.

## 6. Chiavi pubbliche

`GET /keyguard/v1/public-keys` restituisce le chiavi pubbliche di firma (policy e pacchetti) con il loro `kid`: la chiave attiva e, durante una rotazione, le chiavi ritirate ancora annunciate; le chiavi revocate non compaiono. `tt-core` le distribuisce alle sorgenti all'iscrizione e a `tt-mock` tramite configurazione (`TT_GATE_PUBKEYS`, più chiavi per la rotazione). Un mock che si fida ancora di una chiave revocata la tiene in `TT_GATE_PUBKEYS`: per rifiutarne i pacchetti si elenca il `kid` in `TT_GATE_REVOKED_KIDS` ([pack.md](pack.md) §2.2); la procedura di rotazione DEVE includere questo passo.

Una chiave di firma delle policy nuova arriva alle sorgenti già iscritte con l'heartbeat (`add_signing_keys`), **endorsata** da una chiave già fissata e non revocata: `endorsement` = firma Ed25519 di `endorsed_by` su `"tt-fleet-key/v1" || 0x00 || kid || 0x00 || byte della chiave` ([policy.md](policy.md) §3, Fleet API).

**Endorsement automatico (red team round 3, RT3-KEY-1).** Keyguard calcola gli endorsement da sé: ogni chiave annunciata è endorsata dalla chiave annunciata **successiva** nel file (la più nuova dalla più vecchia), con il seed della chiave ritirata (§1). Una chiave revocata si salta: con `new`, `mid` (revocata) e `old`, `new` è endorsata da `old`. Le voci di `public-keys` portano quindi `endorsed_by` e `endorsement` per tutte le chiavi tranne la più vecchia; `tt-core` li salva e li inoltra nell'heartbeat, in ordine (chi endorsa prima della chiave endorsata), così anche una catena `k1 → k2 → k3` arriva in un solo heartbeat. Prima della correzione keyguard azzerava i seed ritirati senza firmare nulla: la chiave nuova raggiungeva solo le sorgenti iscritte dopo, e revocare la vecchia spegneva tutte le altre. Le chiavi dei pacchetti portano gli stessi campi, che `tt-mock` ignora.

La procedura completa di rotazione e revoca è in [policy.md](policy.md) §3.1.

## 7. Stato

`GET /keyguard/v1/status` restituisce: `kid` HMAC posseduti (mai le chiavi), epoch dei filtri, dimensioni dei filtri (conteggi), budget residuo, `kid` attivi di firma (`policy_kid`, `pack_kid`: `tt-core` rifiuta di revocare `policy_kid`, [policy.md](policy.md) §3.1), `kid` revocati, ultimo `issued_seq` firmato, `approvals_unverified`, con OIDC l'oggetto `oidc` (`issuer`, `audience`, `roles_claim`: niente segreti) e le impostazioni di approvazione `opening_approvals` (1 o 2) e `admin_override`. `tt-core` le legge da qui (non le configura) e le mostra: non può abbassarle. Finché non ha raggiunto keyguard, `tt-core` assume i valori più severi (2 approvazioni). `GET /keyguard/v1/health` risponde `{"status":"ok"}`.
