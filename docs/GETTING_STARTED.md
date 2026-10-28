# traffic-twin — Primo giro in 15 minuti

> **Per chi è questa guida.** Per chi ha il **repository** e prova la demo in locale (`make build`, `tt dev up`, `demo/`) o sviluppa traffic-twin. Se invece il team piattaforma ti ha dato una console già installata e vuoi collegare il tuo servizio, leggi [USER_GUIDE.md](USER_GUIDE.md) (anche nella console: *Aiuto > Manuale utente*).

Dal niente a un **mock con stato** che gira in CI, partendo dal traffico di una demo. Ci passano tutti i componenti: `tt dev up` (tt-core + keyguard), la demo (un e-commerce inventato che chiama un corriere inventato), l'SDK Node che cattura, il miner delle regole, il gate che firma il pacchetto e `tt mock` che lo serve.

Cosa serve: Go 1.25+, Node.js 24+ (l'SDK funziona da Node 20, ma il corpo completo delle risposte di `fetch` si vede solo da Node 24: con 20/22 la demo funzionerebbe a metà), `make`, `curl`, `jq`, `openssl`. Docker è facoltativo. Tutto resta su loopback e i dati sono inventati.

Tempi indicativi: build 2 min, avvio e wizard 3 min, demo 2 min, traffico 15 min (nel frattempo la policy si fa con l'assistente del wizard e si guarda la UI), regole, mondo e pacchetto 3 min, mock 2 min.

```
 loadgen ──▶ shop (Node + SDK) ──▶ carrier        demo/ (dati inventati)
                  │ eventi sanificati, mTLS
                  ▼
              tt dev up  (tt-core + keyguard)  ──▶  contratti → regole → mondo → pacchetto firmato
                                                                              │
                                                       tt mock (CI) ◀─────────┘
```

Convenzione: ogni comando parte dalla radice del repository, salvo dove è scritto `cd`. Servono **tre terminali** (A, B, C) e un browser. Porte usate: `7070` (UI), `4318` (intake), `3000` (shop), `8080` (corriere), `8480` (mock): devono essere libere.

## 1. Compila (terminale A)

```sh
make build            # costruisce la UI e bin/tt
```

## 2. Avvia tt-core e keyguard (terminale A)

```sh
./bin/tt dev up -miner-horizon 5m
```

`-miner-horizon 5m` serve solo alla prova. Il miner delle regole non decide nulla finché il traffico catturato non copre almeno **1 ora** di tempo reale (di default); la demo comprime i giorni in secondi (orologio accelerato, punto 3.2), ma le catture hanno l'ora vera, quindi senza il flag aspetteresti un'ora. In produzione non si usa: lascia il default.

Stampa, tra le altre cose:

- l'URL della UI, `https://127.0.0.1:7070` (certificato autofirmato su loopback: accettalo nel browser);
- l'URL dell'intake, `https://localhost:4318`;
- il file della chiave HMAC delle sorgenti, `tt-dev/keys/hmac.keys`;
- la riga `keyguard`: il socket di keyguard, che serve al punto 8;
- il **token monouso** `tts_…` per creare il primo amministratore (compare solo al primo avvio; se lo perdi, cancella `tt-dev/` e riparti).

Apri la UI: porta da sola alla pagina **Primo avvio**. Incolla il token, scegli un nome utente e una password di almeno 12 caratteri e crea l'amministratore (ha tutti i ruoli). Lascia il terminale A aperto.

> Se la UI mostra l'accesso ma la sessione sparisce, stai usando HTTP: serve l'indirizzo `https://`. Safari scarta i cookie `Secure` su HTTP anche su loopback. Puoi avere più accessi insieme (fino a 5 per utente: browser diversi, `curl`); due schede dello **stesso** browser condividono però il cookie, quindi se rientri da un'altra scheda la prima dice «Sessione scaduta o aperta altrove: ricarica la pagina».

## 3. Aggiungi la sorgente: l'SDK Node nello shop

### 3.1 Il wizard: token e policy iniziale (browser)

In **Onboarding** (**Aggiungi una sorgente**):

1. **Sorgente**: SDK **Node.js**; **Nome del gruppo** `shop`; **Nomi di servizio ammessi**: lascialo vuoto (il gruppo prende il nome con cui si iscrive la prima sorgente, qui `shop-api`, e da quel momento ammette solo quello); **Campionamento della scoperta**: **100% (prova con dati inventati)**. **Genera il token e continua**.
2. **Istruzioni**: copia il **token di iscrizione** `tte_…` (monouso, scade in un'ora). Il nome del servizio nelle istruzioni è d'esempio: usa `shop-api`, come qui sotto. Sotto le istruzioni c'è la **Policy iniziale (scoperta, nessun valore esce)**: tutto `drop`, scoperta e parole automatiche per 72 ore. Va approvata come ogni modifica che attiva la scoperta: nella prova sei l'unico amministratore, quindi scrivi un **motivo** (per esempio «Prova locale con dati inventati») e premi **Approva e avvia la cattura** (un override tracciato nell'audit, che genera l'allarme `policy.admin_approval`; in produzione servono due persone).

Il wizard ricorda dove sei (anche se ricarichi la pagina o apri il glossario) finché la scheda resta aperta.

### 3.2 La demo e lo shop con l'SDK (terminale B)

Tutti i processi della demo devono condividere l'orologio simulato; qui un giorno simulato dura 30 secondi:

```sh
export TIME_SCALE=2880 CLOCK_ANCHOR=$(date +%s)

# l'SDK, compilato una volta
(cd sdk/node && npm ci --no-audit --no-fund --ignore-scripts && npm run build)

# il corriere (porta 8080) in background
(cd demo && go run ./carrier) &

# lo shop (porta 3000) con l'SDK agganciato senza toccare il suo codice
export TT_ENROLL_URL=https://localhost:4318
export TT_ENROLL_TOKEN=tte_...                       # il token del wizard
export TT_HMAC_KEY_FILE=$PWD/tt-dev/keys/hmac.keys   # la chiave HMAC locale (kid k1): i valori diventano token qui
export TT_STATE_DIR=$PWD/tt-dev/shop-state           # certificato e policy della sorgente: se cancelli tt-dev/ spariscono insieme
export TT_SERVICE_NAME=shop-api
export TT_DEBUG=1                                    # stampa lo stato dell'SDK (mai valori)
CARRIER_BASE_URL=http://localhost:8080 \
  node --import $PWD/sdk/node/dist/esm/register.js demo/shop/server.js
```

La sorgente si iscrive e, con la policy iniziale approvata, stampa `state capturing`. Se stampa `state no_policy` la policy iniziale non è ancora approvata (il wizard, al passo **Attesa dati**, lo dice e mostra di nuovo il pulsante per approvarla). Se vedi `error enroll_http_403` il nome di servizio non è ammesso dal gruppo; `error heartbeat_network` dopo aver rifatto `tt-dev/` significa che `TT_STATE_DIR` contiene il certificato di un'installazione precedente: cancellalo.

> Con Docker puoi avviare il corriere così: `(cd demo && docker compose up -d --build carrier)` (usa lo stesso `TIME_SCALE` e `CLOCK_ANCHOR`). Lo shop resta sull'host, perché l'SDK deve iscriversi all'intake su loopback.

Senza toccare lo shop si può catturare anche con il proxy di uscita `tt egress`: vedi [`internal/egress/README.md`](../internal/egress/README.md) (per una chiamata usa o l'SDK o tt-egress, mai entrambi). Il resto di questa guida segue la strada dell'SDK.

## 4. Genera traffico (terminale C)

```sh
export TIME_SCALE=2880 CLOCK_ANCHOR=<lo stesso valore del terminale B>   # echo $CLOCK_ANCHOR nel B
cd demo && SHOP_BASE_URL=http://localhost:3000 DURATION=15m go run ./loadgen
```

Duemila clienti finti ordinano e controllano le spedizioni per 15 minuti (circa 7 giorni simulati; il tempo vero, non quello simulato, è ciò che conta per l'orizzonte del miner). I primi minuti servono alla scoperta (punto 5); dopo l'approvazione della policy servono almeno 5 minuti di traffico e alcune centinaia di ordini perché contratti e regole abbiano campioni sufficienti (soglie `k_min` e `min_samples` di 20).

## 5. La policy dall'assistente (browser)

Una policy dice cosa può uscire dal processo. Quella iniziale non dichiara le operazioni e non tiene nessun valore: serve solo all'assistente, che dal traffico vede operazioni e campi (forme e conteggi, mai valori) e propone un'azione per campo. Torna al wizard:

1. **Attesa dati**: i tre controlli diventano verdi (sorgente connessa, policy ricevuta, primi eventi). **Vedi i servizi scoperti**.
2. **Servizi**: solo quelli del gruppo `shop`: `shop-api` (proprio) e l'host esterno `host:localhost:8080` (il corriere), da **gemellare** (spunta già messa).
3. **Policy**: l'assistente elenca le operazioni come template, raggruppate per servizio (`POST /orders`, `GET /orders/{id}`, `GET /orders/{id}/shipment`, `GET /customers/{id}/orders`; per il corriere `POST /v1/shipments`, `GET /v1/shipments`). Se dice «Servono ancora N chiamate per operazione», lascia girare il traffico e premi **Aggiorna**. Poi:
   - **Chi è l'utente?**: lascia la proposta `header authorization` con claim `sub` (la demo usa un Bearer JWT);
   - per `host:localhost:8080`: **Nome del servizio nella policy** `carrier`, **Schema** `http` (gli eventi non dicono lo schema: va scelto, non c'è un valore predefinito);
   - controlla le proposte: identificativi (`$.id`, `orderId`, `shipmentId`, `customerId`, il parametro `{id}`) come `hmac` con il loro spazio dei nomi (`order`, `shipment`, `customer`), stati e codici come `keep`, importi e quantità come `bucket`, date come `bucket(time, day)`; nomi, email e indirizzi restano `drop`. **Applica tutte le proposte** le rimette tutte; puoi cambiare l'azione di ogni campo, mai vedere un valore.
4. **Rivedi le modifiche**: il diff YAML scritto da tt-core sulla policy attiva. **Richiedi approvazione**, poi, da amministratore, scrivi il motivo e **Approva come amministratore**.

Entro 30 secondi lo shop (terminale B) passa alla nuova versione della policy e cattura identificativi come token, stati e fasce. Lo stesso assistente si riapre in seguito da **Sorgenti → Policy → Assistente policy di shop**, o dal primo passo del wizard (**Gruppo già collegato?**).

Mentre il traffico continua, nel browser:

- **Servizi**: `shop-api` e `carrier` (il corriere, `localhost:8080`, dichiarato dalla policy) con le loro operazioni. In **Host esterni** il corriere compare raggruppato per dominio e risulta **Gemellato** (è il servizio che il mock simula).
- **Contratti**: l'inferenza costruisce un contratto OpenAPI per `shop-api` e per il corriere (`POST /v1/shipments`, `GET /v1/shipments?orderId=`).

La risposta giusta si può confrontare con [`demo/GROUND_TRUTH.md`](../demo/GROUND_TRUTH.md) e con `curl -s localhost:8080/__truth`.

### Scorciatoia: la policy della demo già scritta

[`demo/policy.yaml`](../demo/policy.yaml) è una policy equivalente scritta a mano (`policy_id: p-shop`, il nome che il wizard dà alla policy del gruppo `shop`). Al posto del punto 5 la si può proporre dall'API e approvare con un motivo:

```sh
TT=https://127.0.0.1:7070
read -rs TT_ADMIN_PW                  # la password scelta al punto 2 (non resta nella cronologia)
JAR=$(mktemp)
CSRF=$(jq -n --arg p "$TT_ADMIN_PW" '{username:"admin",password:$p}' |
  curl -sk -c "$JAR" -H 'Content-Type: application/json' -d @- $TT/api/v1/auth/login | jq -r .csrf_token)
V=$(curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/yaml' \
  --data-binary @demo/policy.yaml $TT/api/v1/fleet/policies | jq -r .version)
curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"reason":"Prova locale con dati inventati"}' \
  $TT/api/v1/fleet/policies/p-shop/versions/$V/approve | jq -c '{version,status}'
```

(`admin` è il nome utente creato al punto 2. L'accesso con `curl` non chiude la sessione del browser.)

## 6. Regole (browser)

**Regole** → **Cerca nuove regole**. Se dice «dati insufficienti: servono almeno N minuti di traffico», aspetta e riprova. Il miner trova la causa → effetto che la demo nasconde: `POST /v1/shipments` sul corriere crea una spedizione (`r-0001`), e `POST /orders` sullo shop crea un ordine e la sua spedizione (`r-0002`). Apri ogni regola, controlla l'evidenza (conteggi, esiti, ciclo di vita PENDING → CREATED → IN_TRANSIT → DELIVERED) e **Approva**. Solo le regole approvate entrano nel pacchetto.

## 7. Mondo (browser)

**Mondi** → **Genera** (seed `42`, 100 clienti, i valori proposti): un insieme di clienti sintetici con la loro storia. La prima volta tt-core costruisce da solo gli archetipi dai clienti reali (soltanto token, in gruppi di almeno 20).

## 8. Pacchetto e rilascio (browser)

1. **Pacchetti twin** → **Nuovo pacchetto** → **Avvia il gate**. Il gate controlla provenienza, PII, k-anonimato e le chiavi; se li supera, keyguard firma. Se dice BLOCCO, il report indica file e percorso del campo, mai il valore.
2. **Rilascia ai test** (da amministratore chiede un motivo), poi **Scarica il pacchetto**: ottieni `<pack_id>.ttpack`, di solito in `~/Downloads`.

Gli stessi passi dall'API, per un job di CI che costruisce il pacchetto (l'accesso con `curl` è nelle prime righe della scorciatoia del punto 5: `$TT`, `$JAR`, `$CSRF`; vedi `api/admin-api.v1.openapi.yaml`):

```sh
W=$(curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"seed":42,"customers":100}' \
  $TT/api/v1/worlds | jq -r .result.world_id)
P=$(curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "{\"world_id\":\"$W\",\"valid_days\":30}" \
  $TT/api/v1/packs | jq -r .result.pack_id)
curl -sk -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{"reason":"Prova locale"}' \
  -X POST $TT/api/v1/packs/$P/publish | jq -c '{pack_id,status}'
curl -sk -b "$JAR" -o "$P.ttpack" $TT/api/v1/packs/$P/download
```

(Il mondo si genera dall'API solo dopo la prima generazione dalla UI, oppure dopo `POST /api/v1/archetypes/build` con `{"k_min":20}`.)

## 9. Il mock, in locale e in CI

Il mock si fida solo delle chiavi pubbliche del gate. Il modo più semplice, qui come in produzione: nella UI, **Pacchetti twin > Come usarlo nei test** mostra il comando con il valore di `TT_GATE_PUBKEYS` (pulsante Copia) e fa scaricare `gate-keys.txt`; lo stesso valore lo dà l'API a qualsiasi utente autenticato (`GET /api/v1/gate/keys`, `?format=txt` per il file). In `tt dev up` si possono leggere anche da keyguard, dal socket indicato dalla riga `keyguard` del terminale A (di solito `tt-dev/keyguard.sock`; con un percorso lungo è in una cartella temporanea, `unix:///…/keyguard.sock`):

```sh
curl -s --unix-socket tt-dev/keyguard.sock http://localhost/keyguard/v1/public-keys
# {"pack":[{"kid":"pack-dev-1","alg":"Ed25519","public_key":"…"}],"policy":[…]}
```

Poi (terminale C):

```sh
export TT_GATE_PUBKEYS='pack-dev-1:<public_key>'
export TT_CONTROL_TOKEN="$(openssl rand -hex 24)"      # sempre, anche in locale e in CI
./bin/tt mock --pack ~/Downloads/<pack_id>.ttpack --addr 127.0.0.1:8480 --latency record &

AUTH="Authorization: Bearer $TT_CONTROL_TOKEN"
curl -s localhost:8480/__tt/health                                   # pubblico: {"status":"ok"}
curl -s -H "$AUTH" localhost:8480/__tt/pack | jq .services           # ["carrier","shop-api"]
SID=$(curl -s -H "$AUTH" -X POST localhost:8480/__tt/sessions -d '{}' | jq -r .id)

# il corriere crea una spedizione nella sessione (il corpo deve rispettare il contratto)
curl -s -H "$AUTH" -H "X-TT-Session: $SID" -H 'Content-Type: application/json' -X POST \
  localhost:8480/__svc/carrier/v1/shipments -d '{"orderId":"ORD-NEW-1","service":"STANDARD","parcels":1,
  "recipient":{"fullName":"Anna Leone","email":"anna@example.org"},
  "address":{"line1":"Via Roma 1","city":"Bologna","postcode":"40121","country":"IT"}}'
# {"createdAt":"…","orderId":"ORD-NEW-1","service":"STANDARD","shipmentId":"SHP-SYN-0130","status":"PENDING"}

# l'orologio è virtuale: avanzalo e la spedizione evolve (PENDING → CREATED → IN_TRANSIT → DELIVERED)
curl -s -H "$AUTH" -X POST localhost:8480/__tt/sessions/$SID/clock/advance -d '{"by":"5m"}'
curl -s -H "$AUTH" -H "X-TT-Session: $SID" 'localhost:8480/__svc/carrier/v1/shipments?orderId=ORD-NEW-1'
```

Lo stato è per sessione: ogni test usa la sua (`X-TT-Session`), e la scrittura di un test è visibile solo a lui. Le transizioni si provano in millisecondi, spostando l'orologio dell'API di controllo (i ritardi delle regole sono figurativi: contano l'ordine e il «cosa succede»). Guasti e latenze seguono le frequenze osservate. Il nome del servizio (`carrier`) e le operazioni si leggono da `GET /__tt/pack` e dai contratti nel pacchetto.

Questo è il flusso della demo, finito. Se il mock si ferma con `pack signature is invalid`, `TT_GATE_PUBKEYS` non contiene la chiave che ha firmato il pacchetto (dopo aver cancellato `tt-dev/` le chiavi cambiano); con `no trusted keys configured` la variabile è vuota.

### In CI

Un job tipico (GitHub Actions o equivalente): scarica `tt` e il pacchetto dal registro dei pacchetti firmati (il pacchetto lo produce tt-core, punto 8; la CI non ha bisogno di tt-core), avvia il mock, lancia i test dell'app con la base URL del servizio esterno puntata al mock.

```yaml
- name: mock del corriere
  run: |
    echo "TT_CONTROL_TOKEN=$(openssl rand -hex 24)" >> "$GITHUB_ENV"
    # tt e il pacchetto: dal tuo registro interno (artefatto firmato dal gate)
    TT_GATE_PUBKEYS="${{ vars.TT_GATE_PUBKEYS }}" ./tt mock --pack twin/shop.ttpack --addr 127.0.0.1:8480 --latency record &
    curl --retry 10 --retry-connrefused -s localhost:8480/__tt/health
- name: test
  env:
    CARRIER_BASE_URL: http://127.0.0.1:8480/__svc/carrier
  run: npm test
```

Imposta sempre `TT_CONTROL_TOKEN`: senza, l'API di controllo è aperta a chiunque raggiunga la porta (consentito solo su loopback). Il token si passa ai test come segreto e non si scrive nel repository. Ogni test chiede la sua sessione (`POST /__tt/sessions`) e manda `X-TT-Session`. In Kubernetes: chart `tt-mock` ([`deploy/README.md`](../deploy/README.md)).

Il pacchetto si può anche convertire per altri strumenti: `./bin/tt export` produce mapping WireMock, esempi Microcks o un OpenAPI per Prism (il pacchetto si verifica prima con `TT_GATE_PUBKEYS`).

## 10. Ripulire

`Ctrl+C` nei terminali A, B e C (anche il corriere e il mock in background: `kill %1 %2` o `pkill -f "go run ./carrier"`, `pkill -f "tt mock"`). Per ricominciare da zero cancella `tt-dev/` (contiene anche lo stato della sorgente, `shop-state`). Il token di iscrizione e la sessione dell'amministratore non servono più.

## E dopo

- Un'installazione vera, con keyguard su un host a parte, backup e sicurezza: [OPERATIONS.md](OPERATIONS.md).
- Come funziona e perché i dati reali non escono mai: [ARCHITECTURE.md](ARCHITECTURE.md) e [THREAT_MODEL.md](THREAT_MODEL.md).
- Altri linguaggi (Python, Java, .NET, Go, PHP) e Kubernetes: [`sdk/`](../sdk/) e [`deploy/README.md`](../deploy/README.md).
