# Inferenza dei contratti, fotografie, drift

Pacchetti: `internal/contract` (inferenza, OpenAPI, fotografie, diff, buchi, API) e `internal/drift`
(confronto tra fotografie, allarmi, webhook firmati). Specifiche: [ARCHITECTURE §6 e §10](../../docs/ARCHITECTURE.md),
[pack.md §4](../../docs/spec/pack.md), [admin API](../../api/admin-api.v1.openapi.yaml).

## Cosa fa

1. **Inferenza** (`Inferrer`, `InferFromStore`): un solo passaggio in streaming sugli eventi dell'intake, con memoria
   proporzionale ai campi e non agli eventi. Per ogni `(servizio, op, status)`:
   - albero dello schema con unione di tipi, `null`, presenza (`x-tt-presence`), `required` solo con presenza 100% su almeno
     `MinSamples` (20) oggetti, array con schema degli elementi, `{*}` come `additionalProperties`;
   - forme dai token: `format` (`email`, `uuid`, `date-time`, ...), classe di lunghezza, `x-tt-value` con `kind` `id`
     (dominio HMAC), `enum`, `bucket` (confini, `bucket_p`, unità), `shape`;
   - **filtro k**: un valore `keep` finisce in `enum` solo se visto per almeno `KMin` (20) soggetti distinti; per gli
     eventi in uscita (senza soggetto) si usa il soggetto dell'evento in ingresso con lo stesso `trace_id`. I valori nascosti
     mettono `enum_partial: true` e, se resta un enum parziale, il vincolo `enum` di JSON Schema non viene emesso;
   - **campi collegati** (`x-tt-dependencies`, pack.md §4.2, `joint.go`): per le coppie di proprietà `keep`/`bucket` dello
     stesso oggetto, le combinazioni viste per almeno `KMin` soggetti distinti (impronte da 8 byte, al più `KMin` per
     combinazione); al più 6 proprietà per nodo e 128 combinazioni per coppia (oltre, la coppia è ad alta cardinalità e si
     scarta), mai `hmac`, forme o tempi; si pubblicano solo le coppie non indipendenti, con classi di grandezza
     (`at_least`), mai conteggi esatti. Gli esempi le rispettano;
   - header, query, cookie e parametri di path (dal template già negli eventi: nessuna ri-templatizzazione);
   - frequenze degli status (`x-tt-frequency`, sul totale delle chiamate), latenza p50/p95/p99 (istogramma con errore
     relativo 1%), errori di rete, conteggi esatti (`x-tt-observed`) presi dai riepiloghi dello store anche quando i gruppi
     più grandi di `SampleCap` (50 000) si campionano con passo fisso;
   - lo schema della richiesta si ricava dagli scambi che non finiscono con status ≥ 400.
2. **OpenAPI 3.1** (`Contract.OpenAPI`, `JSON`, `YAML`): deterministico (chiavi ordinate, JSON canonico tt). Esempi OK e KO
   sintetici, generati **solo dalle annotazioni** (nomi per codice d'errore pubblicato; id `ORD-SYN-0042`; email
   `user@example.com`). `RenderOptions.PackSafe` toglie operazioni e risposte con meno di `k` chiamate (controllo
   `k-thresholds` del gate).
3. **Fotografie** (`Engine`): una per servizio e finestra (default 24 h, allineata al giorno UTC, `Grace` 5 minuti), in
   SQLite (namespace `contract`, modello compresso). `Engine.Run` le produce ogni giorno; `SnapshotWindow` a richiesta.
4. **Diff** (`Diff`, `Engine.DiffSnapshots`): classifica `breaking` / `non-breaking` con elenco leggibile.
   Rompe: operazione sparita, campo di risposta sparito o non più sempre presente, cambio di tipo o formato, valore di enum
   sparito, status di successo sparito, nuovo status d'errore frequente (≥ 1%), campo obbligatorio nuovo in richiesta.
   Non rompe: campo opzionale nuovo, valore di enum nuovo, variazioni di presenza e frequenza oltre soglia. Le soglie sono
   in `Config.Diff`. Il testo delle modifiche non contiene mai valori (solo nomi, tipi, conteggi); i valori d'enum stanno
   solo nel campo `values` della risposta di amministrazione.
5. **Buchi** (`Contract.Gaps`, `GapSource`): operazioni con pochi campioni, status mai visti (4xx/5xx), campi opzionali con
   poco supporto, valori nascosti dal filtro k. Il miner può aggiungere i suoi (`rule-low-support`,
   `entity-without-creator`) con `APIDeps.ExtraGaps`.
6. **Drift** (`drift.Manager`): a ogni fotografia confronta con la precedente e salva un allarme `contract.drift` per
   modifica (deduplicato finché ne esiste uno aperto uguale), con gravità, prova (`calls_after_change`) e `affected_rules`
   (via `drift.RuleLookup`). `drift.RuleStaleness` è l'interfaccia che il miner chiama quando la confidenza di una regola
   approvata cala (allarme `rule.stale`).
7. **Webhook**: corpo JSON con solo tipi, conteggi e identificatori; firma
   `X-TT-Signature: t=<unix>,v1=<hex HMAC-SHA256(segreto, "<t>." + corpo)>` (`drift.Sign`, `drift.VerifySignature`),
   coda persistente, tentativi con attesa esponenziale (1 s, 5 s, 30 s, 2 min, 10 min, +-20%; 6 tentativi), registro delle
   consegne senza corpo. Destinazioni solo se nella lista `TT_WEBHOOK_ALLOW` (`host`, `host:porta`, `*.suffisso`; lista
   vuota = nessuna), https salvo `AllowHTTP`, nessun redirect seguito.

8. **GraphQL** (`graphql.go`, v1.14): le operazioni logiche `POST /graphql#Nome` ([event.md](../../docs/spec/event.md) §6)
   sono operazioni come le altre; `Op.GraphQL` porta endpoint, tipo, nome, forma più frequente del documento, variabili e
   campi radice (`x-tt-graphql`), `Contract.GraphQL` l'ultimo risultato di introspezione catturato per endpoint
   (`x-tt-graphql-schemas`, ricostruito dai token `gql:` con `graphql.IntrospectionFromEvent`: nomi, descrizioni `null`).
   Le operazioni logiche non entrano nell'inferenza dei template.

## Collegamento in `cmd/tt` (`mountComponents`)

```go
// Dopo store.Open, auth, audit, server.New e intake.New:
hints := contract.PolicyHints(compiledPolicies...)       // domini HMAC e confini dei bucket dalle policy firmate

eng, err := contract.New(contract.Config{ /* KMin dal gate, Window 24h */ }, contract.Deps{
	DB: db, Events: in.Store(), Hints: hints, Logger: logger,
})
mgr, err := drift.New(drift.Config{
	Allow: strings.Split(os.Getenv("TT_WEBHOOK_ALLOW"), ","),
}, drift.Deps{DB: db, Audit: auditLog, Logger: logger, Rules: miner /* RuleLookup, opzionale */})
mgr.Attach(eng)                                          // allarmi a ogni fotografia

contract.Mount(srv, contract.APIDeps{Engine: eng, Audit: auditLog /*, ExtraGaps: []contract.GapSource{miner}*/})
drift.Mount(srv, mgr)                                    // /api/v1/drift e /api/v1/webhooks
miner.SetStaleness(mgr)                                  // il miner riceve drift.RuleStaleness

go eng.Run(ctx)                                          // fotografie giornaliere
go mgr.Run(ctx)                                          // consegna dei webhook
// quando arriva una nuova policy firmata: eng.SetHints(contract.PolicyHints(...))
// altri pacchetti possono notificare: mgr.Emit(ctx, "quarantine.opened", map[string]any{...})
```

Le migrazioni (`contract`, `drift`) si registrano in `init`: basta che il binario importi i pacchetti prima di `store.Open`.

### Rotte e ruoli

Ogni prefisso è montato con l'unione dei ruoli delle sue operazioni; ogni rotta ricontrolla i ruoli di `x-tt-roles`.

| Rotta | Ruoli |
|---|---|
| `GET /api/v1/services`, `/services/{s}/ops` | operator, rule-reviewer, auditor |
| `GET /api/v1/contracts`, `/contracts/{s}` (`?format=yaml`) | operator, rule-reviewer, publisher, auditor |
| `GET /api/v1/contracts/{s}/postman` (`?base_url=`, `?pack_safe=true`): collezione Postman v2.1 generata dall'OpenAPI (richieste con corpo di esempio, indirizzo in `{{baseUrl}}`, risposte registrate come esempi salvati; importabile anche in Insomnia) | operator, rule-reviewer, publisher, auditor |
| `GET /api/v1/contracts/{s}/snapshots`, `/snapshots/{id}` (`?diff_against=`) | operator, rule-reviewer, auditor |
| `GET /api/v1/gaps` | operator, rule-reviewer, auditor |
| `GET /api/v1/drift`, `POST /api/v1/drift/{id}/ack` | lettura operator, rule-reviewer, auditor; ack operator, rule-reviewer |
| `GET /api/v1/webhooks` | admin, operator, auditor |
| `POST/PUT/DELETE /api/v1/webhooks[/{id}]`, `POST .../test` | admin |

Aggiunte non presenti in `admin-api.v1` (compatibili, da riportare nell'API): `POST /api/v1/contracts/{s}/snapshots`
(operator, fotografia subito), `GET /api/v1/webhooks/{id}/deliveries` (registro delle consegne),
`GET /api/v1/drift?kind=rule.stale|all`, `?pack_safe=true` sui contratti. Il segreto di un webhook è in sola scrittura; se la
creazione non ne dà uno, il server ne genera uno e lo restituisce **una volta** nella risposta `201`.
Le chiamate che modificano scrivono il registro di audit (`contract.snapshot`, `drift.ack`, `webhook.*`).

### Test

`internal/contract/contracttest` genera traffico e-commerce/corriere (secondo GROUND_TRUTH) con il sanitizer Go e una
policy compilata vera, lo passa dall'intake e lo lascia in SQLite. I test di integrazione verificano campi, opzionalità
(`eta` ≈ 37%), status e frequenze, latenza, e il drift (cambio di tipo → allarme `breaking` → webhook con firma valida).
