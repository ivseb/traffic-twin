# tt-core: server, autenticazione, audit

Fondamenta HTTP di `tt core`. Questo documento descrive le API di autenticazione usate dalla UI
(da integrare in `api/admin-api.v1.openapi.yaml`), il modo in cui gli altri pacchetti montano le
proprie rotte, la configurazione e le regole di sicurezza che il server applica.

Pacchetti: `internal/server` (composizione, middleware, listener), `internal/server/httpx`
(helper JSON condivisi), `internal/auth` (login, sessioni, CSRF, RBAC), `internal/audit`
(registro append-only a catena di hash), `internal/config` (YAML + env), `internal/store`
(SQLite e registro delle migrazioni).

## 1. Listener

| Listener | Default | TLS | Contenuto |
|---|---|---|---|
| admin/UI | `127.0.0.1:7070` | obbligatorio se l'indirizzo non è loopback | UI, API di autenticazione, audit, rotte montate con `Mount*` |
| intake | `127.0.0.1:4318` (vuoto lo disattiva) | **sempre** (mai in chiaro; di default certificato gestito da Fleet); certificato client verificato | rotte montate con `MountIntake` (OTLP `/v1/logs`, endpoint sorgente di Fleet) |

Entrambi rispondono a `GET /healthz` (vivo) senza autenticazione. Il listener admin espone anche
`GET /readyz` (pronto: database raggiungibile più i controlli registrati con
`AddReadinessCheck`; in caso di errore risponde `503` con i soli **nomi** dei controlli falliti).

Arresto ordinato su `SIGINT`/`SIGTERM`, entro `admin.shutdown_timeout` (default 10 s).

## 2. API di autenticazione

Formato degli errori: `{"code": "...", "message": "..."}` (stesso schema `Error` di Fleet).
Tutte le risposte `/api/` hanno `Cache-Control: no-store`.

| Metodo e path | Autenticazione | Limite di frequenza | Descrizione |
|---|---|---|---|
| `GET /api/v1/auth/config` | nessuna | no | `{"local": bool, "oidc": bool, "setup_required": bool}`: cosa mostrare nella pagina di login |
| `POST /api/v1/setup` | token di setup | sì | Crea il primo amministratore. Corpo `{"setup_token", "username", "password"}`. `201` + sessione (come `/me`); `401 invalid_setup_token`; `409 setup_done`; `400 invalid_input` |
| `POST /api/v1/auth/login` | nessuna | sì | Corpo `{"username", "password"}`. `200` + cookie di sessione + corpo come `/me`; `401 invalid_credentials` (identico per utente sconosciuto, password errata, utente disabilitato) |
| `POST /api/v1/auth/logout` | sessione + CSRF | no | `204`, sessione eliminata e cookie cancellato |
| `GET /api/v1/auth/me` | sessione | no | Utente, ruoli, token CSRF, scadenze (vedi sotto) |
| `GET /api/v1/auth/oidc/start?return_to=/path` | nessuna | sì | `302` verso il provider OIDC (code + PKCE S256, `state`, `nonce`). `return_to` accetta solo path locali |
| `GET /api/v1/auth/oidc/callback` | `state` legato al browser | sì | Verifica e crea la sessione, poi `302` a `return_to`; in caso di errore `302 /?auth_error=<codice>` |
| `GET /api/v1/auth/oidc/stepup?purpose=&ref=&return_to=/` | sessione (utente OIDC) | sì | Step-up di un'approvazione: `302` verso l'IdP con il client delle approvazioni, `nonce` legato alla modifica, PKCE, `prompt=login`, `max_age=600`; errori `302 return_to?stepup_error=<codice>` |
| `GET /api/v1/auth/oidc/stepup/callback` | `state` legato al browser (`__Host-tt_stepup`) | sì | Verifica l'ID token (`iss`, `aud` delle approvazioni, `nonce`, `auth_time`, `iss`/`sub` dell'approvatore) e lo tiene **solo in memoria**, al più 10 minuti, per la prossima approvazione di quell'utente per quella modifica; `302 return_to?stepup=ok` |
| `GET /api/v1/audit/export?after_seq=0&limit=100000` | ruolo `auditor` | no | JSON Lines (`application/x-ndjson`), una voce per riga |
| `GET /api/v1/audit/verify` | ruolo `auditor` | no | `{"ok", "entries", "head_seq", "head_hash"}` (+ `error` se la catena è rotta) |

Risposta di `/me` (anche di login e setup):

```json
{
  "user": {"id": "usr_…", "username": "alice", "display_name": "alice", "auth_method": "local", "roles": ["admin"]},
  "roles": ["admin"],
  "csrf_token": "…",
  "csrf_header": "X-CSRF-Token",
  "expires_at": "2026-10-19T22:00:00Z",
  "idle_expires_at": "2026-10-19T10:30:00Z",
  "session_idle_timeout_ms": 1800000
}
```

Codici `auth_error` del callback OIDC: `idp_error`, `state_mismatch`, `state_invalid`,
`idp_unavailable`, `exchange_failed`, `no_id_token`, `id_token_invalid`, `nonce_mismatch`,
`at_hash_mismatch`, `claims_invalid`, `user_disabled`, `internal`. Il testo d'errore del provider
non viene mai riflesso.

Le richieste con corpo devono avere `Content-Type: application/json`; campi sconosciuti, dati
dopo l'oggetto e corpi oltre 8 KiB sono rifiutati (`400`).

### 2.1 Sessioni

- Id opaco di 256 bit; nel database si salva solo il suo SHA-256.
- Cookie `__Host-tt_session` con TLS, `tt_session` sul listener loopback in chiaro; sempre
  `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, senza `Max-Age`.
  Nota: in chiaro su loopback alcuni browser (Safari) scartano i cookie `Secure`: in quel caso
  configurare TLS anche in locale.
- Scadenza per inattività (`auth.session.idle_timeout`, default 30 m) e assoluta
  (`auth.session.absolute_timeout`, default 12 h). Ogni login genera un id nuovo ed elimina la
  sessione eventualmente presentata (niente fixation).
- I ruoli si rileggono a ogni richiesta: revoche e modifiche valgono subito. Disabilitare un
  utente o cambiargli la password elimina le sue sessioni.

### 2.2 CSRF

Token sincronizzatore legato alla sessione, restituito da `/me`. Ogni metodo non sicuro
(`POST`, `PUT`, `PATCH`, `DELETE`) su una rotta autenticata richiede l'header `X-CSRF-Token`
uguale al token (`403 csrf` altrimenti). In più, su tutto il listener admin, le richieste non
sicure con `Origin` diverso dall'host o `Sec-Fetch-Site: cross-site|same-site` sono rifiutate
(`403 cross_origin`): questo protegge anche login e setup, che non hanno ancora una sessione.

### 2.3 Primo avvio

Se non esiste alcun utente e il login locale è attivo, `tt core` stampa su **stdout** (mai nei
log) un token di setup monouso `tts_…`, valido 24 h e sostituito a ogni riavvio finché non viene
usato. Con `POST /api/v1/setup` si crea l'utente con ruolo `admin`.

### 2.4 Ruoli (RBAC)

`admin`, `operator`, `rule-reviewer`, `policy-approver`, `publisher`, `auditor`,
`event-exporter`. I sei ruoli non admin sono **piatti**; `admin` è il **superutente** e li implica
tutti (`Principal.HasAny`): passa ogni controllo di `Require` e delle guardie dei pacchetti. Le
rotte accettano "almeno uno dei ruoli indicati" (o admin). Ogni richiesta di un admin ammessa solo
per questa implicazione che cambia qualcosa (metodo non sicuro) o scarica un file
(`Content-Disposition: attachment`) è registrata da `Require` come `authz.admin_override` (modello
della rotta, `roles_required`, stato): l'admin agisce da solo, ma mai in modo invisibile
(policy.md §5, threat model M17). `Principal.Has` resta il controllo letterale, per distinguere
l'override dal percorso del ruolo (approvazione dell'admin, `AdminOverride`).

Separazione dei compiti (tra non admin): `auth.CheckApproval(approvatore, ruolo, autoreID, approvatoriPrecedenti)`
rifiuta l'autore della modifica e chi ha già approvato; `auth.DistinctApprovals` conta gli
approvatori distinti diversi dall'autore (due per le modifiche di policy che aprono dati, M7).

Gestione utenti per l'admin API (spec v1.1): `CreateLocalUser`, `SetRoles`, `SetDisabled`,
`SetPassword`, `RevokeSessions`, `GetUser`, `ListUsers` su `*auth.Service`. Questi metodi non
scrivono audit: lo fa il chiamante, che conosce l'attore.

### 2.5 OIDC

Authorization code + PKCE (S256), `state` (salvato lato server come hash, monouso, 10 minuti, e
legato al browser da un cookie `__Host-tt_oidc` `SameSite=Lax`), `nonce`, verifica dell'ID token
(firma con JWKS in cache e ricaricato su `kid` sconosciuto, `iss`, `aud`, scadenza, `at_hash`).
La discovery è pigra: `tt core` parte anche se il provider è irraggiungibile e ritenta al massimo
ogni 10 s. Se `roles_claim` è impostato, i ruoli dell'utente OIDC sono sincronizzati a ogni
login tramite `role_mapping`; altrimenti si gestiscono localmente.

**Step-up delle approvazioni** ([keyguard.md](../../docs/spec/keyguard.md) §3.2 punto 4). Con
`auth.oidc.approval_client_id` (un secondo client presso lo stesso IdP, diverso da `client_id`, il cui
client id è `TT_KEYGUARD_OIDC_AUDIENCE` di keyguard; segreto in `approval_client_secret_file` o
`TT_CORE_AUTH_OIDC_APPROVAL_CLIENT_SECRET`, redirect `/api/v1/auth/oidc/stepup/callback`) ogni
approvazione di un utente OIDC passa per uno step-up: `nonce = base64url(SHA-256("tt.approve/v1" 0x00
scopo 0x00 campi…))` calcolato da `tt-core` sulla modifica (`internal/approvebind`). Il token torna
alla richiesta di approvazione (Fleet, pacchetti, quarantena) tramite `auth.Service.ApprovalToken` e
non viene mai scritto su disco. Gli account locali non possono allegare ID token. Audit:
`auth.oidc_stepup`.

## 3. Montare rotte da altri pacchetti

Prima di `Run`/`Serve`:

```go
srv.Mount("/fleet/v1/admin", fleetAdmin, auth.RoleOperator)          // sessione + CSRF + almeno un ruolo
srv.MountAuthenticated("/api/v1/notifications", h)                   // qualsiasi utente autenticato
srv.MountPublic("/api/v1/public-thing", h)                           // scelta esplicita, da evitare
srv.MountIntake("/v1/logs", otlp)                                    // certificato client verificato obbligatorio
srv.MountIntake("/fleet/v1/enroll", enroll, server.AllowNoClientCert())
srv.SetIntakeTLS(server.IntakeTLSHooks{ClientCAs: …, VerifyPeer: …, GetCertificate: …})
srv.AddReadinessCheck("fleet", func(ctx context.Context) error { … })
```

- `Mount` senza ruoli va in panic: per aprire una rotta serve dirlo (`MountAuthenticated`,
  `MountPublic`). Prefissi assoluti, senza `/` finale, senza pattern; prefissi sovrapposti fra loro
  o con quelli riservati (`/api/v1/auth`, `/api/v1/setup`, `/api/v1/audit`, `/healthz`,
  `/readyz`) vanno in panic.
- Il prefisso **non** viene rimosso: l'handler riceve il path completo e può usare pattern
  `http.ServeMux` come `"GET /fleet/v1/admin/sources/{id}"`.
- Nel contesto: `auth.PrincipalFrom(ctx)` (utente, ruoli), `httpx.RequestID(ctx)`;
  sull'intake `server.PeerCertificate(r)` restituisce il certificato verificato della sorgente.
- Helper JSON: `httpx.DecodeJSON` (rigoroso), `httpx.WriteJSON`, `httpx.WriteError`.
- Audit: `audit.Log.Record(ctx, audit.Event{…})`; l'attore si ottiene con
  `principal.AuditActor()`.
- I `/api/…` non montati rispondono `404` JSON; tutto il resto va alla UI.

Intake TLS: `VerifyClientCertIfGiven` a livello di handshake (un certificato presentato viene
sempre verificato), poi ogni rotta richiede un certificato verificato salvo `AllowNoClientCert`.
Il pool delle CA si legge a ogni handshake (`ClientCAs`), quindi la rotazione è immediata;
`VerifyPeer` serve per revoca e controlli sull'id sorgente; con `intake.tls.managed: true` il
certificato del server arriva da `GetCertificate`.

## 4. Middleware e regole

Ordine sul listener admin: request id e log di accesso → recupero dai panic → header di
sicurezza → controllo d'origine → limite del corpo → rotte.

- **Header**: la stessa CSP di `internal/ui`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP `same-origin`,
  `Permissions-Policy`, HSTS quando c'è TLS, `X-Request-Id`.
- **Limiti**: corpo massimo `*.http.max_body_bytes` (default 1 MiB, `413`), timeout di lettura,
  scrittura e inattività per listener, header massimi 64 KiB.
- **Panic**: risposta `500 {"code":"internal"}` senza dettagli; nel log solo tipo del valore e
  stack, mai il valore.
- **Limite di frequenza**: token bucket per IP (IPv6 per /64) su login, setup e OIDC;
  default 10/min con raffica 5; `429` con `Retry-After`. Gli header `X-Forwarded-For` sono
  ignorati (nessun proxy fidato supportato per ora).
- **Log** (`log/slog`, JSON o testo): una riga per richiesta con listener, metodo, **pattern della
  rotta** (non il path), stato, byte, durata, request id, IP. Mai path, query, header, cookie o
  corpi. Gli attributi con nomi sensibili (`password`, `token`, `secret`, `cookie`, `body`, …)
  sono comunque sostituiti da `[REDACTED]`. `TestLogsNeverContainRequestValues` fallisce se un
  valore inviato in una richiesta compare nei log o nell'audit (M14).

## 5. Audit

Tabella `audit_entries` append-only (trigger che bloccano `UPDATE` e `DELETE`), ogni voce con
l'hash SHA-256 della precedente. `Verify` rileva modifiche, cancellazioni, inserimenti e
rinumerazioni; il troncamento delle voci più recenti si rileva solo confrontando `head_hash` con
un valore conservato fuori dal database (esportarlo periodicamente).

Le voci registrano chi, cosa, su quale oggetto, quando ed esito, **mai valori**: azione
`dominio.verbo`, codici `reason` brevi, dettagli limitati a 16 chiavi con valori identificativi
(`[A-Za-z0-9_.:/@+=,-]`, max 128). Testo libero e spazi vengono rifiutati. Un login fallito
registra il nome utente solo se l'utente esiste (una password digitata nel campo utente non
finisce nell'audit).

Eventi registrati da questi pacchetti: `core.start`, `auth.setup_token_issued`, `auth.setup`,
`auth.login`, `auth.oidc_login`, `auth.oidc_stepup`, `auth.logout`, `authz.deny`, `authz.csrf`, `audit.export`,
`audit.verify`.

## 6. Configurazione

`tt core -config tt-core.yaml` (oppure `TT_CORE_CONFIG`). Esempio completo con i default:
[`internal/config/testdata/example.yaml`](../config/testdata/example.yaml) e
[`deploy/examples/`](../../deploy/examples/). La composizione di tutti i componenti è in
[`internal/core`](../core/README.md).

- `keyguard.url` è obbligatorio (tt-core non firma nulla da solo): `https://host:porta` con
  `client_cert_file`/`client_key_file` e `ca_file` o `server_pin`, oppure `unix:///percorso` (stesso host, solo
  installazioni di prova). Per provare in locale: `tt dev up`.

- Chiavi sconosciute, più documenti YAML, file scrivibile da tutti: errore.
- Override da ambiente: `TT_CORE_` + percorso in maiuscolo con `_`
  (`TT_CORE_ADMIN_ADDR`, `TT_CORE_AUTH_SESSION_IDLE_TIMEOUT=45m`, liste separate da virgole).
  Una variabile `TT_CORE_*` sconosciuta è un errore. `role_mapping` solo da file.
  `TT_CORE_ADDR` e il flag `-addr` restano come alias di `admin.addr`.
- Il segreto del client OIDC non si scrive mai nel YAML: `auth.oidc.client_secret_file` oppure
  `TT_CORE_AUTH_OIDC_CLIENT_SECRET` (per il client delle approvazioni `approval_client_secret_file` oppure
  `TT_CORE_AUTH_OIDC_APPROVAL_CLIENT_SECRET`; `approval_client_id` deve differire da `client_id`).
- Validazione: admin non loopback senza TLS, intake senza TLS, OIDC con issuer o redirect non
  HTTPS (HTTP solo su loopback, per sviluppo), redirect diverso da
  `/api/v1/auth/oidc/callback`, ruoli sconosciuti nel mapping, timeout fuori intervallo.

## 7. Database

SQLite con driver Go puro (`modernc.org/sqlite`), WAL, `busy_timeout` 5 s, chiavi esterne
attive su ogni connessione, `secure_delete`, transazioni di scrittura `IMMEDIATE`. File,
WAL/SHM e directory creati con permessi solo proprietario (0600/0700).

**Cifratura a riposo**: SQLite non la fornisce. Mettere `storage.path` su un volume cifrato
(LUKS/dm-crypt, disco cloud cifrato, PersistentVolume cifrato).

Migrazioni: ogni pacchetto registra le proprie nel suo namespace, di solito in `init()`:

```go
func init() {
	store.Register(store.Namespace{Name: "fleet", DependsOn: []string{"auth"}, Migrations: []store.Migration{
		{Version: 1, Name: "sources", SQL: `CREATE TABLE fleet_sources (…) STRICT;`},
	}})
}
```

Versioni da 1, contigue; tabelle con prefisso `<namespace>_`; mai modificare una migrazione già
applicata (il checksum SHA-256 lo rileva e `tt core` non parte); un database migrato da un
binario più nuovo viene rifiutato. Ogni migrazione gira in una transazione insieme alla sua riga
in `store_migrations`.
