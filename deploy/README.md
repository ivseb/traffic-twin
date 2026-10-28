# Deploy su Kubernetes

Chart Helm, webhook di iniezione e immagini per portare traffic-twin su Kubernetes
(ARCHITECTURE §3.4 e §13, THREAT_MODEL M10 e M11).

```
deploy/
  helm/
    tt-core/       tt-core: intake, analisi, UI, gate (rete di produzione, StatefulSet + PVC)
    tt-keyguard/   keyguard: chiavi HMAC e di firma (namespace separato)
    tt-egress/     proxy di uscita per stack senza SDK (Deployment e snippet sidecar)
    tt-mock/       tt-mock per i cluster di CI (zona C)
    tt-injector/   webhook di mutazione: aggiunge l'SDK ai pod annotati
  images/
    sdk-node/  sdk-python/  sdk-java/  sdk-dotnet/   immagini "init" con l'SDK, base fissata per digest
  test/
    helm-check.sh  lint --strict e template di tutti i chart e delle varianti (senza cluster)
    kind-e2e.sh    prova end-to-end su un cluster kind usa e getta
  examples/        a cura dell'integrazione (non toccare da qui)
```

## Topologia

| Componente | Namespace consigliato | Note |
|---|---|---|
| `tt-core` | `traffic-twin` | rete di produzione, un solo pod (SQLite), PVC cifrato |
| `tt-keyguard` | `tt-keyguard` | **separato** da tt-core, accetta solo tt-core |
| `tt-injector` | `tt-system` | non strumenta i pod del proprio namespace |
| `tt-egress` | quello delle app che lo usano | oppure sidecar nel pod dell'app |
| `tt-mock` | namespace di test o di CI | solo dati sintetici; in modalità console chiama solo la console (pacchetti e stato), in modalità file nessuna chiamata in uscita |

I namespace predefiniti delle NetworkPolicy sono questi: se ne usi altri, cambia i selettori nei `values`.

## Installazione, nell'ordine

I chart sono nella cartella `deploy/helm/`; le immagini di default sono `ghcr.io/ivseb/traffic-twin` (il `Dockerfile`
della radice) e `ghcr.io/ivseb/traffic-twin/sdk-<lang>` (sotto). Cambia `image.repository`/`image.tag`/`image.digest`.

### 1. Certificati e chiavi (a mano, mai nei values)

Helm salva i `values` di una release in un Secret del cluster: **le chiavi non passano mai da Helm**. Si creano con
`kubectl` e i chart le referenziano per nome.

```bash
# chiavi di keyguard (file con permessi 0600, creati da tt)
tt keyguard genkey -type hmac    -kid k1  -out hmac.keys
tt keyguard genkey -type ed25519 -kid pol1 -out policy.key
tt keyguard genkey -type ed25519 -kid pak1 -out pack.key

kubectl create ns tt-keyguard
kubectl label ns tt-keyguard pod-security.kubernetes.io/enforce=baseline     # vedi "Segreti con permessi 0400"
kubectl -n tt-keyguard create secret generic tt-keyguard-keys \
  --from-file=hmac-keys=hmac.keys --from-file=policy-signing-key=policy.key --from-file=pack-signing-key=pack.key
kubectl -n tt-keyguard create secret tls tt-keyguard-tls --cert=keyguard.crt --key=keyguard.key

# identità mTLS di tt-core verso keyguard e il suo "pin" (impronta SPKI del certificato client)
tt keyguard pin tt-core-client.crt        # -> sha256:<hex>
kubectl create ns traffic-twin
kubectl -n traffic-twin create secret tls tt-core-tls --cert=core.crt --key=core.key
kubectl -n traffic-twin create secret generic tt-core-keyguard-client \
  --from-file=tls.crt=tt-core-client.crt --from-file=tls.key=tt-core-client.key --from-file=ca.crt=keyguard-ca.crt
```

Il certificato `tt-core-tls` serve il solo listener di amministrazione (UI e API): deve valere per il Service `tt-core`
(con `.ns`, `.ns.svc`, `.ns.svc.cluster.local`) e ci si fida con la CA del proprio browser/client. Con cert-manager:
`--set tls.certManager.enabled=true --set tls.certManager.issuerRef.name=...`. Il listener di **intake** (le sorgenti) usa
invece il certificato gestito da Fleet (`intake.tls.managed: true`): la CA di Fleet vive sul volume dati
(`/data/fleet-ca`) e i token di iscrizione ne portano l'impronta, quindi non servono Secret per l'intake.

### 2. keyguard, poi tt-core

```bash
helm install tt-keyguard deploy/helm/tt-keyguard -n tt-keyguard \
  --set 'clientPins[0]=sha256:<pin di tt-core>'

helm install tt-core deploy/helm/tt-core -n traffic-twin --set tls.existingSecret=tt-core-tls
# keyguard.url, keyguard.clientTLSSecret (tt-core-keyguard-client) e caFromSecret hanno già questi valori di default
```

Impostazioni di keyguard da conoscere (blocco `settings:` dei values del chart `tt-keyguard`, variabili `TT_KEYGUARD_*`):

| Variabile | Default | Effetto |
|---|---|---|
| `TT_KEYGUARD_OPENING_APPROVALS` | `2` | approvazioni distinte per una modifica di policy che apre valori |
| `TT_KEYGUARD_ADMIN_OVERRIDE` | `true` | un amministratore approva policy e rilascia pacchetti da solo, con motivazione (allarme e audit) |
| `TT_KEYGUARD_OBSERVE_AUTO` | `true` | **fase Osserva** ([policy.md](../docs/spec/policy.md) §7): keyguard firma **senza approvazioni** le modifiche che non aprono valori (policy di partenza, `hmac` sugli identificativi, identità automatica, scoperta ≤ 7 giorni), con `approval_mode: observe` nell'audit. `false`: ogni modifica torna a chiedere le approvazioni, come prima della v1.6 (rischio residuo in [THREAT_MODEL](../docs/THREAT_MODEL.md)) |

Per spegnerla: `helm upgrade tt-keyguard deploy/helm/tt-keyguard -n tt-keyguard --reuse-values --set-string settings.TT_KEYGUARD_OBSERVE_AUTO=false`.

Il `core.yaml` viene **generato dal chart** (ConfigMap) a partire da `config:` più quello che il chart ricava dagli altri
valori; ogni sezione dello schema di `internal/config` (`contract`, `miner`, `world`, `gate`, `retention`, `fleet`, ...)
si imposta sotto `config:`. In particolare:

| Chiave di `core.yaml` | Da dove |
|---|---|
| `keyguard.url`, `client_cert_file`, `client_key_file`, `ca_file`, `server_pin`, `timeout` | blocco `keyguard:` dei values (il certificato client è obbligatorio; serve almeno `caFromSecret` o `serverPin`) |
| `fleet.public_url`, `fleet.server_names` | se vuote, dal Service di intake (`https://<release>-intake.<ns>.svc.cluster.local:4318`) |
| `drift.webhook_allow` | dall'elenco `webhooks:` dei values, **lo stesso** che genera le regole di egress della NetworkPolicy |

Webhook di allarme: ogni voce di `webhooks` ha `host` (come compare nell'URL), `port` (default 443) e `cidr` (gli indirizzi
dietro quell'host, l'unica cosa che una NetworkPolicy sa confrontare). Esempio:
`--set 'webhooks[0].host=alerts.tt.internal' --set 'webhooks[0].cidr=10.20.30.40/32'` scrive `alerts.tt.internal` in
`drift.webhook_allow` e apre `10.20.30.40/32:443` in uscita; senza `cidr` tt-core accetta l'host ma la rete lo blocca
(il chart lo segnala). Senza `webhooks` non esce nulla dal cluster oltre a DNS e keyguard.

Il test `deploy/test/charts_test.go` (`go test ./deploy/test/`) rende i chart con `helm template` e fa caricare il
`core.yaml` risultante da `config.Load` (e l'ambiente di keyguard da `keyguard.ConfigFromEnv`), quindi un chart non
allineato allo schema fallisce in CI.

Al primo avvio il token monouso per creare l'amministratore esce **una volta** sulla console del pod
(`kubectl -n traffic-twin logs tt-core-0`). L'URL di iscrizione delle sorgenti (`TT_ENROLL_URL`) è
`https://tt-core-intake.traffic-twin.svc.cluster.local:4318`.

### 3. Sorgenti: injector o egress

```bash
helm install tt-injector deploy/helm/tt-injector -n tt-system --create-namespace
# per ogni namespace applicativo (Secret "opzionali": senza, il pod parte e l'SDK resta inerte):
kubectl -n shop create secret generic tt-enroll --from-literal=url=https://tt-core-intake.traffic-twin.svc.cluster.local:4318 \
                                                --from-literal=token=tte_...
kubectl -n shop create secret generic tt-hmac   --from-file=hmac-key=./hmac.key
```

```bash
helm install tt-egress deploy/helm/tt-egress -n shop \
  --set 'upstreams[0].alias=carrier' --set 'upstreams[0].url=https://api.carrier.example' \
  --set enroll.url=https://tt-core-intake.traffic-twin.svc.cluster.local:4318 \
  --set enroll.tokenSecret.name=tt-egress-token --set hmacKey.existingSecret=tt-hmac
# l'app chiama http://tt-egress.shop.svc.cluster.local:9090/carrier/...  (cambia solo la base URL)
```

Come sidecar: `--set sidecar.enabled=true` pubblica il ConfigMap `<release>-sidecar` con `snippet.yaml` (container e
volumi da aggiungere al pod; l'app chiama `http://127.0.0.1:9090/carrier`). Il proxy si iscrive da solo con ogni
replica: usa un token **di gruppo**, perché lo stato (certificato) non sopravvive al riavvio del pod.

### 4. tt-mock: il mock dei test

Il mock si usa in due modi, con lo stesso chart `deploy/helm/tt-mock` e la stessa immagine `ghcr.io/ivseb/traffic-twin`
(il binario `tt`, comando `tt mock`):

| Modo | Cosa lo alimenta | Quando |
|---|---|---|
| **console** (`console.url`) | la console: il mock scarica con un **token del mock** l'ultimo pacchetto rilasciato del suo gruppo, lo verifica come un file e passa da solo ai pacchetti nuovi; manda alla console stato, indirizzi e il riassunto delle chiamate | il caso normale: lo vedi e lo comandi dalla pagina **Mock** |
| **file** (`pack.*`) | un pacchetto fisso da PVC, ConfigMap o immagine OCI | CI che non raggiunge la console |

#### 4a. Avviato dalla console (mockManager di tt-core)

Se tt-core gira nel cluster, la console può accendere da sola il mock di un gruppo («Prepara e avvia il mock»). Si attiva
nel chart di tt-core:

```bash
helm upgrade tt-core deploy/helm/tt-core -n traffic-twin --reuse-values \
  --set mockManager.enabled=true --set mockManager.namespace=bookings-test \
  --set mockManager.apiServer.cidr="$(kubectl get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}')/32" \
  --set mockManager.apiServer.port=6443
```

| Cosa fa il chart | Perché |
|---|---|
| `Role` + `RoleBinding` **nel solo namespace dei mock**: `secrets`, `services`, `apps/deployments`, `route.openshift.io/routes`, verbi `get create patch update delete` | il minimo per creare, aggiornare e cancellare un mock; niente di cluster, niente `pods/exec`, nessun altro namespace |
| `automountServiceAccountToken: true` sul pod di tt-core (solo con `mockManager.enabled`) | tt-core parla all'API di Kubernetes con il suo service account (in-cluster, senza librerie client) |
| `mock.console_url` = `https://<release>.<ns>.svc.cluster.local:<porta admin>` (o `mockManager.consoleURL`) | l'indirizzo con cui i mock raggiungono tt-core: il certificato di amministrazione deve valere per quel nome; con una CA interna `mockManager.consoleCAFromTLSSecret=true` passa ai mock `ca.crt` del Secret TLS |
| NetworkPolicy: uscita verso `mockManager.apiServer.cidr`, ingresso sulla porta admin dai pod `tt-mock` del namespace dei mock | senza `apiServer.cidr` la regola non c'è: aggiungila in `networkPolicy.egress.extra` |

Per ogni gruppo tt-core applica (server-side apply, field manager `tt-core`) `Secret`, `Service`, `Route` (se il cluster ha
le route di OpenShift: `mockManager.route=auto|on|off`) e `Deployment` `tt-mock-<gruppo>`, con etichetta
`app.kubernetes.io/managed-by=tt-core`. Il pod del mock non monta token, gira con lo stesso `securityContext` restrittivo
degli altri chart e prende dal Secret il token del mock (`mock-token`), il token dell'API di controllo (`control-token`) e la
CA della console. Le chiavi pubbliche del gate le mette tt-core nel Deployment (le chiede a keyguard). «Ferma» cancella
gli oggetti e revoca il token; «Riavvia» emette un token nuovo e rinnova i pod.

#### 4b. Installato da te, collegato alla console

La pagina **Mock > Avvia il mock tu** crea un token del mock (mostrato una volta) e dà i comandi già compilati. In
sintesi, su OpenShift:

```bash
oc project bookings-ci
oc create secret generic tt-mock-token --from-literal=token='ttm_...'
helm install tt-mock deploy/helm/tt-mock \
  --set console.url=https://tt.example.internal --set console.group=bookings \
  --set console.tokenSecret=tt-mock-token --set gatePubKeys='gate-2026-1:Xz9k...' \
  --set route.enabled=true --set route.host=tt-mock-bookings-ci.apps.ocp.example
```

| Valore | Significato |
|---|---|
| `console.url`, `console.group` | console e gruppo; con `console.url` il chart passa alla modalità console e ignora `pack.*` |
| `console.tokenSecret` / `tokenKey` | Secret con il token del mock (`TT_MOCK_TOKEN`) |
| `console.caConfigMap` / `caKey` | ConfigMap con la CA del certificato della console, se non è pubblica |
| `console.publicURL` | l'indirizzo che la pagina Mock mostra ai test; default `https://<route.host>` o l'indirizzo del Service |
| `gatePubKeys` | chiavi pubbliche del gate: il mock **verifica sempre** la firma, anche dei pacchetti che arrivano dalla console |
| `route.*` | Route OpenShift (TLS edge) verso il mock |
| `networkPolicy.egress.console.to` | in modalità console l'uscita è solo DNS e la porta della console (default verso qualsiasi indirizzo: restringila ai pod di tt-core) |
| `controlToken.existingSecret` | facoltativo in modalità console (l'API di controllo la comanda la console); serve se i test creano sessioni da soli |

Con Docker: `docker run -e TT_MOCK_TOKEN=... -e TT_GATE_PUBKEYS=... ghcr.io/ivseb/traffic-twin:<versione> mock --console <url> --group <gruppo> --addr 0.0.0.0:8480`.

Il mock deve raggiungere la porta di amministrazione di tt-core: se tt-core ha la sua NetworkPolicy, aggiungi il namespace
del mock a `networkPolicy.ingress.admin.from` del chart di tt-core (i mock del `mockManager` sono già ammessi).

#### 4c. Da file (CI senza console)

Il pacchetto twin firmato arriva da una PVC, da un ConfigMap (pacchetti piccoli) o da un'immagine OCI copiata da un
init container (`pack.image.*`). Servono le chiavi pubbliche del gate e un token per l'API di controllo (il mock non
parte fuori dal loopback senza):

```bash
kubectl -n ci create secret generic tt-mock-control --from-literal=token="$(openssl rand -hex 24)"
helm install tt-mock deploy/helm/tt-mock -n ci \
  --set pack.image.repository=registry.interno/twin/shop --set-string pack.image.tag=2026-10-24 \
  --set gatePubKeys='gate-2026-1:Xz9k...' --set controlToken.existingSecret=tt-mock-control
```

> **Imposta sempre il token dell'API di controllo, anche in CI.** Senza `TT_CONTROL_TOKEN` il mock lascia `/__tt/` aperto a
> chiunque raggiunga la porta: è ammesso solo sul loopback, e in un cluster condiviso (altri job, altri pod nello stesso
> namespace, un sidecar) basta il `Service` per azzerare le sessioni, forzare guasti ed esiti o leggere il registro delle chiamate.
> Genera il segreto a ogni esecuzione come sopra e passalo ai test con `Authorization: Bearer <token>`. Il chart lo fa per te se
> `controlToken.existingSecret` è valorizzato; lasciarlo vuoto è una scelta da fare solo per prove locali.

## Cosa garantiscono i chart

| Garanzia | Come |
|---|---|
| Nessuna chiamata in uscita da tt-core e keyguard (M11, G9) | NetworkPolicy con `Egress` e senza regola verso Internet. tt-core: DNS, keyguard, webhook elencati in `webhooks`. keyguard: niente (nemmeno DNS) salvo `networkPolicy.egress.allowed`. tt-mock: niente in modalità file, DNS e console in modalità console. tt-injector: niente |
| keyguard raggiungibile solo da tt-core | NetworkPolicy `ingress` sui soli pod `tt-core` del suo namespace, più il pin del certificato client sull'mTLS |
| Pod non privilegiati | `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem`, `capabilities: drop ALL`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, nessun token di ServiceAccount montato (tranne tt-core con `mockManager.enabled`: Role nel solo namespace dei mock) |
| Pod Security `restricted` | provato da `kind-e2e.sh` su tutti i namespace tranne `tt-keyguard` (`baseline`) |
| Sonde | tt-core: `/healthz` e `/readyz` su HTTPS; keyguard: TCP (le sue API chiedono il certificato client); egress: `/_tt/health`; mock: `/__tt/health`; injector: `/healthz` |
| Dati su volume | tt-core e keyguard in StatefulSet a una replica con PVC (`persistence.*`, usa una StorageClass cifrata) |

### Segreti con permessi 0400 (keyguard)

keyguard **rifiuta** i file di chiavi leggibili da gruppo o altri. Un volume Secret è di proprietà di root e, con
`fsGroup`, il kubelet lo rende leggibile dal gruppo (0440: verificato su Kubernetes 1.32), quindi montarlo direttamente
non basta. Il chart usa un init container (`keys.installer`, busybox fissato per digest) che copia chiavi e certificato
in un volume `emptyDir` **in memoria**, con proprietario l'utente di keyguard e modo `0400`. L'init container gira come
root con la sola capability `CHOWN` e filesystem di sola lettura: per questo il namespace di keyguard va con Pod Security
`baseline` (non `restricted`); il container di keyguard resta pienamente non privilegiato. Con
`keys.installer.enabled=false` i Secret si montano direttamente (serve un driver che fornisca file `0400` col
proprietario giusto, per esempio il Secrets Store CSI).

### Limiti noti

- Una sola replica per tt-core e keyguard (SQLite): l'aggiornamento riavvia il pod, con una breve interruzione
  dell'intake (le sorgenti riprovano e scartano code piene, mai richieste).
- Senza persistenza (`persistence.enabled=false`) si perdono a ogni riavvio il database **e la CA di Fleet**: tutte le
  sorgenti devono iscriversi di nuovo.
- Un token di iscrizione vale per un solo tipo di SDK (`sdk-node`, `sdk-python`, ...): per le app di linguaggi diversi nello
  stesso namespace servono più token, uno per Secret (`traffic-twin.io/enroll-secret` sceglie quale).

## Spazio su disco di tt-core (SQLite)

SQLite non restringe mai il file da solo: dopo una `purge` (o la retention automatica) le pagine cancellate restano nel file e vengono riusate dalle scritture successive (in un deployment di prova il file è rimasto a 4,7 GB dopo aver cancellato milioni di eventi).

- **Database nuovi**: sono creati con `auto_vacuum=INCREMENTAL`. Dopo ogni purge tt-core restituisce le pagine libere al file system a gruppi di circa 8 MB, ciascuno in una transazione breve, e tronca il WAL: l'intake e la UI continuano a funzionare. La risposta del job `store.purge` riporta `reclaimed_bytes`.
- **Database esistenti** (creati prima di questa modifica) hanno `auto_vacuum=NONE`, e SQLite lo cambia solo riscrivendo il file con `VACUUM`: serve spazio libero pari a circa la dimensione del database e **nessuno può scrivere** per tutta la durata. Per questo non lo fa mai da solo: tt-core lo segnala nel log (`space not reclaimed`) e nel job di purge (`reclaim_note`). Si converte **una volta**, in una finestra di manutenzione, con tt-core fermo:

```bash
systemctl stop tt-core
tt compact -confirm-core-stopped -config /etc/tt/core.yaml     # oppure: -db /var/lib/tt/tt-core.db
systemctl start tt-core
```

  Il comando rifiuta di partire senza `-confirm-core-stopped`; su un database già incrementale restituisce soltanto lo spazio libero.

## Rotazione della chiave di firma delle policy

Runbook per sostituire la chiave con cui keyguard firma le policy senza fermare le sorgenti già iscritte. Le regole
sono in [policy.md §3.1](../docs/spec/policy.md) e [keyguard.md §6](../docs/spec/keyguard.md). Esempio: la chiave
attuale è `pol1`, la nuova sarà `pol2`.

1. **Controlla lo stato di partenza.** In **Impostazioni → Chiavi di firma** `pol1` è «In uso per firmare» e la
   colonna «Sorgenti che la conoscono» conta le sorgenti viste nelle ultime 24 ore. Le sorgenti con SDK precedenti a
   questa versione non inviano `signing_kids`: aggiornale prima, o la revoca del punto 5 resterà bloccata.
2. **Genera la chiave nuova e mettila in prima riga**, lasciando sotto la vecchia **con il suo seed** (serve a
   keyguard per endorsare la nuova; non togliere la riga vecchia fino al punto 6):

   ```bash
   tt keyguard genkey -type ed25519 -kid pol2 -out pol2.key
   cat pol2.key policy.key > policy.next && mv policy.next policy.key && chmod 600 policy.key   # pol2 sopra, pol1 sotto
   kubectl -n tt-keyguard create secret generic tt-keyguard-keys --dry-run=client -o yaml \
     --from-file=hmac-keys=hmac.keys --from-file=policy-signing-key=policy.key --from-file=pack-signing-key=pack.key \
     | kubectl apply -f -
   kubectl -n tt-keyguard rollout restart statefulset/tt-keyguard
   ```

   Al riavvio keyguard firma con `pol2` e annuncia `pol2` endorsata da `pol1` (`GET /keyguard/v1/public-keys`:
   `endorsed_by: pol1`).
3. **Aspetta che tt-core la distribuisca.** Alla manutenzione periodica (ogni 10 minuti; anche alla prima firma) tt-core
   impara `pol2`, la manda a tutte le sorgenti nell'heartbeat (`add_signing_keys`) e **ri-firma con `pol2`** le policy
   attive firmate da `pol1` (come un rinnovo, senza approvazioni). Una policy con finestra di scoperta o parole
   automatiche scadute non si può ri-firmare: serve una nuova versione approvata, come per la scadenza.
4. **Verifica.** In **Impostazioni → Chiavi di firma** `pol2` è «In uso per firmare», `endorsed_by` è `pol1`, e sulla
   riga di `pol1` la colonna «Revoca» passa da «In attesa: N di M sorgenti…» al pulsante **Revoca la chiave**. Le stesse
   informazioni sono in `GET /api/v1/fleet/signing-keys` (campo `revoke`: `seen_sources`, `confirmed_sources`,
   `sources_on_old_key`, `ok`, `blocker`). Una sorgente conta come confermata quando il suo heartbeat elenca `pol2` in
   `signing_kids` e non esegue più una policy firmata da `pol1`. Le sorgenti spente da più di 24 ore
   (`fleet.key_rotation.window`) non contano: se ripartono dopo la revoca non catturano e vanno iscritte di nuovo.
5. **Revoca `pol1`** dal pulsante (ruolo `admin`) o con `POST /api/v1/fleet/signing-keys/pol1/revoke`. tt-core
   rifiuta con `409`: `active_signing_key` se keyguard firma ancora con `pol1` (punto 2 non applicato),
   `rotation_unconfirmed` se manca qualche conferma (il messaggio dice quante), `last_signing_key` se è l'unica chiave.
   Le sorgenti tolgono `pol1` al heartbeat successivo (`revoke_signing_keys`) e continuano a catturare con `pol2`.
6. **Chiudi in keyguard:** aggiungi `pol1` a `TT_KEYGUARD_REVOKED_KIDS` (`--set settings.TT_KEYGUARD_REVOKED_KIDS=pol1`)
   oppure togli la sua riga dal file, aggiorna il Secret e riavvia keyguard. Cancella le copie del seed di `pol1`.

**Chiave compromessa (revoca d'emergenza).** Non aspettare le conferme: esegui i punti 2 e 3, poi imposta
`fleet.key_rotation.min_confirmed: 0` sotto `config:` di tt-core (`helm upgrade ... --set config.fleet.key_rotation.min_confirmed=0`),
revoca `pol1` (punto 5) e chiudi in keyguard (punto 6); infine riporta `min_confirmed` a `1`. Restano attivi i controlli
`active_signing_key` e `last_signing_key`. Le sorgenti che non avevano ancora `pol2` smettono di catturare (fail-closed)
e vanno iscritte di nuovo con un token nuovo. Le policy firmate con `pol1` restano rifiutate per sempre.

## Iniezione dell'SDK (`tt injector`)

Il webhook di mutazione (`tt injector`, Go standard library, TLS) aggiunge l'SDK ai pod con l'annotazione
`traffic-twin.io/inject`. Va messa nel **template del pod** (`spec.template.metadata.annotations`), non nel Deployment:

```yaml
spec:
  template:
    metadata:
      annotations:
        traffic-twin.io/inject: node          # node | python | java | dotnet | go | php
        # facoltative:
        # traffic-twin.io/container-names: "app,worker"    (default: il primo container)
        # traffic-twin.io/service-name: shop-api            (default: vedi sotto)
        # traffic-twin.io/enroll-secret: tt-enroll          (Secret con url e token)
        # traffic-twin.io/hmac-secret: tt-hmac              (Secret con hmac-key)
```

### Cosa aggiunge al pod

1. Un init container `tt-sdk-init` (immagine `sdk-<lang>`, uid 65532, rootfs di sola lettura, nessuna capability) che
   copia l'SDK in un `emptyDir` condiviso, montato in sola lettura nei container strumentati su `/tt/sdk`.
2. Il wiring del linguaggio:

| Linguaggio | Cosa viene impostato | Note |
|---|---|---|
| `node` | `NODE_OPTIONS += --import /tt/sdk/node/dist/esm/register.js` | Node ≥ 20. Funziona anche per app CommonJS |
| `python` | `PYTHONPATH = /tt/sdk/python/bootstrap:/tt/sdk/python/site[:esistente]` | Python legge `sitecustomize` all'avvio; quello dell'app viene eseguito prima (concatenato) |
| `java` | `JAVA_TOOL_OPTIONS += -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar` (**in coda**: un `-javaagent` già presente, dell'OTel Operator o di un APM, non si sostituisce né si sposta); con un `-javaagent` altrui in `JAVA_TOOL_OPTIONS` (o `traffic-twin.io/java-otel-extension: "true"`) aggiunge anche `-Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar`; con `traffic-twin.io/java-classpath: "true"` (modo libreria) aggiunge `CLASSPATH=/tt/sdk/java/lib/*` **e non** l'agent | vedi "Java e .NET" sotto |
| `dotnet` | `DOTNET_STARTUP_HOOKS += /tt/sdk/dotnet/TrafficTwin.StartupHook.dll` (separatore `:`) e `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES += TrafficTwin.Sdk.AspNetCore` (separatore `;`), in coda | .NET 8+, Linux; vedi "Java e .NET" sotto |
| `go`, `php` | solo l'ambiente `TT_*` e i volumi (nessun init container) | Go è linkato nel binario; PHP chiede composer e `tt-shipper` |

3. L'ambiente, per ogni container strumentato (mai su variabili già presenti):
   - `TT_ENROLL_URL` e `TT_ENROLL_TOKEN` da `secretKeyRef` (chiavi `url` e `token`, `optional: true`);
   - `TT_SERVICE_NAME` dal nome del servizio: annotazione `traffic-twin.io/service-name`, poi label
     `app.kubernetes.io/name`, poi `app`, poi il workload proprietario (senza l'hash del ReplicaSet), poi il nome del
     container. Non viene impostato se esiste `OTEL_SERVICE_NAME` (l'SDK lo usa come ripiego);
   - `TT_HMAC_KEY_FILE=/var/run/secrets/traffic-twin/hmac-key` da un volume Secret `optional` (modo di default `0444`:
     l'app può girare con qualsiasi uid; con `hmacMode: "0440"` e un `fsGroup` del pod si stringe);
   - `TT_STATE_DIR=/tt/state/agent` su un `emptyDir` (anche con rootfs di sola lettura).

   I Secret sono tutti **opzionali**: se mancano, il pod parte lo stesso e l'SDK resta inerte (fail-closed).

### Convivenza con OpenTelemetry

- Non tocca mai una variabile `OTEL_*` esistente e non ne aggiunge, tranne l'estensione Java sopra, aggiunta solo se
  `OTEL_JAVAAGENT_EXTENSIONS` e `otel.javaagent.extensions` non sono già impostate (altrimenti avvisa e lascia stare).
- `NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS` e `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES` si **estendono** (in coda, o in testa per `PYTHONPATH`), non si
  sostituiscono: l'iniezione dell'OpenTelemetry Operator e la nostra stanno insieme in qualunque ordine. Se la variabile
  viene da `valueFrom` (ConfigMap/Secret) non si può estendere in sicurezza: il webhook non la tocca e lo dice in un
  avviso di ammissione (`kubectl apply` lo mostra) per aggiungere la voce a mano.
- Il webhook è registrato con `reinvocationPolicy: IfNeeded` ed è **idempotente**: ogni elemento (volume, init
  container, variabile) si aggiunge solo se manca, quindi una seconda chiamata dopo l'Operator non cambia nulla o
  completa soltanto ciò che mancava (per esempio l'estensione Java quando l'Operator ha appena messo `-javaagent`).

### Non blocca mai un deploy

- `failurePolicy: Ignore` e `timeoutSeconds: 3`: se l'injector non c'è, i pod nascono **senza SDK** (da riavviare dopo
  il ripristino). Non cambiarlo in `Fail`.
- Su Kubernetes ≥ 1.28 il webhook viene chiamato solo per i pod con l'annotazione (`matchConditions`); sono esclusi
  `kube-system`, `kube-public`, `kube-node-lease` e il namespace dell'injector.
- Un linguaggio sconosciuto o senza immagine configurata **non** fa fallire il pod: il pod passa invariato, `kubectl`
  mostra l'avviso `traffic-twin: refused: unknown language ...` e il pod riceve l'annotazione
  `traffic-twin.io/inject-status`. Con `denyUnknown: true` il pod viene invece rifiutato (scelta esplicita).
- I log dell'injector contengono solo namespace, nome del pod, linguaggio ed esito: mai variabili, comandi o immagini.

### Java e .NET: iniezione a zero codice

- **Java**: l'agent `-javaagent` (`traffic-twin-agent.jar`, un solo jar senza dipendenze) installa il filtro servlet in Tomcat e
  Jetty (anche incorporati, Spring Boot incluso) e la cattura di `java.net.http`, `RestTemplate`/`RestClient` e OkHttp, senza
  toccare l'applicazione. Convive con l'agent OpenTelemetry 2.x in **entrambi gli ordini** dei flag: il webhook accoda il nostro
  in fondo a `JAVA_TOOL_OPTIONS`, e se l'Operator aggiunge il suo dopo di noi (reinvocazione) il nostro non si duplica né si sposta.
  Contenitori non coperti (Undertow, WildFly, WebLogic, Liberty, WebFlux/Netty) e le altre limitazioni: `sdk/java/README.md`
  ("Iniezione senza codice"). `traffic-twin.io/java-classpath: "true"` resta il modo libreria (nessun agent, `CLASSPATH`).
- **.NET**: `DOTNET_STARTUP_HOOKS` carica `TrafficTwin.StartupHook.dll` prima del `Main` (avvia l'agente e rende trovabili gli assembly
  `TrafficTwin.*` senza che l'app li referenzi) e `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES` registra middleware in ingresso e handler di
  `IHttpClientFactory`. Gli `HttpClient` creati a mano escono come metadati (senza corpi). Dettagli e limiti: `sdk/dotnet/README.md`.
  Se l'immagine dell'app ha già `DOTNET_STARTUP_HOOKS` (per esempio OpenTelemetry Automatic Instrumentation) il nostro hook si accoda.
- **Condizione comune**: senza `TT_ENROLL_URL` (Secret `tt-enroll` assente) l'agent Java e l'hook .NET non installano nulla.

## Immagini SDK

Si costruiscono dalla radice del repository (il contesto è la radice; ogni cartella ha il suo `Dockerfile.dockerignore`):

```bash
docker build -f deploy/images/sdk-node/Dockerfile   -t ghcr.io/ivseb/traffic-twin/sdk-node:0.1.0 .
docker build -f deploy/images/sdk-python/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-python:0.1.0 .
docker build -f deploy/images/sdk-java/Dockerfile   -t ghcr.io/ivseb/traffic-twin/sdk-java:0.1.0 .
docker build -f deploy/images/sdk-dotnet/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-dotnet:0.1.0 .
```

Sono minime (busybox musl, circa 3 MiB, utente 65532, solo `cp`), con le immagini di base fissate per digest
(`busybox:1.37.0-musl`, `node:24-alpine` come il `Dockerfile` della radice, `eclipse-temurin:17-jdk`, `mcr.microsoft.com/dotnet/sdk:8.0`); aggiorna tag e
digest insieme. L'SDK non ha dipendenze a runtime, quindi l'immagine contiene solo i suoi file. Pubblica le immagini nel
registro interno e imposta `sdkImages.*` del chart `tt-injector`. Per `Go` e `PHP` non c'è un'immagine.

## Test

```bash
go test ./internal/injector/ ./cmd/tt/        # webhook: fixture AdmissionReview in internal/injector/testdata/
go test ./deploy/test/                        # i chart rendono un core.yaml / un ambiente keyguard validi (serve helm o docker)
deploy/test/helm-check.sh                     # lint --strict + template (usa alpine/helm via Docker se manca helm)
deploy/test/kind-e2e.sh                       # end-to-end su kind (vedi sotto)
```

`kind-e2e.sh` crea un cluster kind con un kubeconfig suo (il tuo `~/.kube/config` e il contesto corrente non vengono
toccati), costruisce le immagini, installa i cinque chart con certificati e chiavi di prova e verifica, tra l'altro:
tt-core **vero** con keyguard (creazione dell'amministratore col token di setup, gruppo, token di iscrizione, policy
iniziale firmata da keyguard), iscrizione dei pod Node e Python strumentati dall'injector (mTLS, CA di Fleet fissata dal
token) e **accettazione degli eventi sanificati** da parte di tt-core, iniezione Node e Python (l'agente parte davvero nel
processo dell'app), convivenza con le variabili OTEL, linguaggio
sconosciuto, pod senza annotazione invariati, pod creati con l'injector spento (`Ignore`), keyguard con le chiavi `0400`,
Pod Security `restricted`, isolamento di keyguard con le NetworkPolicy, mock con un pacchetto firmato. `TT_E2E_JAVA=1`
aggiunge Java. Variabili: `KIND`, `TT_E2E_CLUSTER`, `TT_E2E_REUSE`, `TT_E2E_KEEP`, `TT_E2E_SKIP_BUILD` (elenco in testa
allo script). Richiede docker, kind, kubectl, helm e go. Con Docker recente (image store containerd) `kind load docker-image`
fallisce: lo script usa `docker save --platform` + `kind load image-archive`.

Nel CI e in locale si lancia con `deploy/test/kind-e2e.sh` così com'è; l'ultima esecuzione locale (con
`TT_E2E_JAVA=1`) ha passato 63 verifiche su Kubernetes 1.32.2 (kind 0.27).
