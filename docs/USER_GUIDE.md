# traffic-twin: manuale utente (console già installata)

> **Per chi è questo manuale.** Per lo sviluppatore che riceve traffic-twin **già installato** dal team piattaforma (una console, un indirizzo dell'intake, un account) e vuole un mock con stato dei servizi esterni che il proprio servizio chiama. Non serve il repository.
> Chi invece prova la demo o sviluppa il prodotto dal repository (`make build`, `tt dev up`, `demo/`) legga [GETTING_STARTED.md](GETTING_STARTED.md). Chi installa e gestisce la piattaforma legga [OPERATIONS.md](OPERATIONS.md).

Lo stesso manuale è nella console: menu **Aiuto > Manuale utente**.

Esempio usato in tutto il manuale (dati inventati): un servizio di prenotazioni, `bookings-api` (`POST /bookings`, `GET /bookings/{id}`, `GET /users/{id}/bookings`, `POST /bookings/{id}/cancel`), che chiama un'API di pagamenti (`payments-ext`: a volte 402 "declined", a volte 503, e più tardi la charge risulta rimborsata) e un'API meteo (`weather-ext`). Funziona uguale in **Python** (FastAPI, Flask, Django), **Node.js**, **Java**, **.NET**, **Go** e **PHP**: i comandi di ogni linguaggio sono nella sezione 3.4.

## In breve: il percorso in 4 passi

Il menu della console è il percorso, nell'ordine in cui lo fai. La pagina **Panoramica** (la prima, quella che si apre all'ingresso) dice a che punto sei e qual è la prossima cosa da fare.

| Passo | Cosa fai | Dove nella console | Nel manuale |
|---|---|---|---|
| **1 Collega** | colleghi il tuo servizio con un token e metti la chiave HMAC; la fase **Osserva** parte da sola, senza policy da scrivere né approvazioni | Collega un servizio, Sorgenti | sezioni 3, 4, 5 |
| **2 Osserva** | lasci girare il servizio **almeno 24 ore** e vedi quali servizi e host esterni chiama | Servizi, Host esterni | sezione 6 |
| **3 Rivedi** | guardi i contratti OpenAPI (anche per Postman e Insomnia), le regole sui dati, i buchi e gli allarmi | Contratti, Regole, Buchi, Allarmi | sezioni 7, 8 |
| **4 Usa il mock** | prepari e avvii con un clic un mock che risponde al posto dei servizi reali nei tuoi test | Mock | sezione 10 (9 e 11 per i dettagli) |

Le funzioni per andare a fondo (policy in dettaglio, archetipi, mondi, pacchetti twin, quarantena, esportazione eventi, audit, utenti, impostazioni, glossario) sono nel gruppo **Avanzate** del menu, chiuso di partenza: sezione 14.

In pratica, in ordine:

1. **Collega** (3.1): scegli il linguaggio, scrivi il nome del servizio e genera il token. Nessuna policy da scrivere, nessuna approvazione. Metti la chiave HMAC che ti dà il team piattaforma (sezione 4) e avvia il servizio con l'SDK (3.4).
2. **In ascolto** (3.5): il wizard mostra gli eventi che arrivano, i servizi e gli host scoperti e, dopo pochi minuti, «Policy Osserva attivata alle HH:MM» con l'elenco degli identificativi mascherati. È tutto automatico.
3. Genera un po' di traffico e controlla in **Sorgenti** e **Servizi** che arrivi (3.6).
4. **Stati e codici escono da soli**: sui campi che si chiamano come uno stato o un codice (`status`, `state`, `type`, `reason`, `error_code`…) la versione Osserva lascia uscire in chiaro i valori come `DELIVERED`, `in_transit`, `card_declined` (solo lettere, `_` e `-`, fino a 32 caratteri), senza approvazioni: è così che il miner trova i cicli di vita e il mock cambia stato nel tempo (5).
5. **Solo se servono altri valori in chiaro** (categorie o motivi con spazi come «in transito», fasce di importi, città) apri la policy (sezione 5: «Avanzate» del wizard o **Sorgenti > Policy > Rivedi in blocco**). Quelle modifiche richiedono un'approvazione; mascherare altri campi o ridurre la cattura si applica subito. Chiedi l'approvazione subito: senza categorie in chiaro non avrai **campi collegati** (macrocategoria → categoria) e il mock genererà valori di categoria inventati.
6. **Osserva**: torna dopo 24 ore. I **contratti** compaiono in minuti (7), le **regole** servono ore e utenti sufficienti (8.1).
7. **Rivedi**: contratti, regole, buchi, allarmi (7, 8, 8.4).
8. **Usa il mock**: **Mock > Prepara e avvia il mock** (10.1). Un clic prepara i dati sintetici, li fa controllare e firmare, li rilascia e accende il mock (o lo lanci tu, 10.3); poi copi dalla pagina gli indirizzi che sostituiscono quelli veri.
9. Nei test: una sessione per test, orologio virtuale, guasti a comando (pagina Mock, oppure 10.4 e 10.9).
10. Se qualcosa non torna: sezione 12.

## 1. Cos'è e cosa ottieni

traffic-twin guarda le chiamate HTTP del tuo servizio in produzione (in ingresso e verso le API esterne) **senza far uscire valori reali**: dentro il tuo processo un SDK sanifica tutto secondo una policy approvata (all'inizio tutto è `drop`: esce solo la "forma" dei dati). Dal traffico ricava:

- **contratti** (OpenAPI) di ogni servizio, con status, frequenze e latenze;
- **regole causa → effetto** (per esempio "creo una prenotazione → compare una charge presso i pagamenti");
- un **mondo sintetico** di clienti inventati.

Tutto finisce in un **pacchetto twin** firmato, che `tt mock` serve come mock con stato nei tuoi test (o che esporti verso WireMock, Microcks e Prism).

## 2. Cosa ti serve

| Cosa | Dove si prende |
|---|---|
| Console | Indirizzo, account e certificato della CA aziendale te li dà il team piattaforma. Nel browser installa la CA (o accetta il certificato); con curl: `curl --cacert company-ca.crt https://<console>/`. |
| Intake (dove l'SDK invia gli eventi) | Lo scrive la console nel wizard di Onboarding. Il token di iscrizione contiene l'impronta della CA: l'SDK **non** ha bisogno del file della CA. |
| Python | **≥ 3.9**, nessuna dipendenza. Funziona con FastAPI/Starlette, Flask, Django e qualunque app WSGI o ASGI, con `requests` e `httpx` in uscita. Dal registro interno (`pip install traffic-twin`) se c'è; altrimenti dal file del kit: `pip install ./traffic_twin-x.y.z-py3-none-any.whl`. |
| Node.js | **≥ 20**. Il corpo completo delle risposte di `fetch` si vede **da Node ≥ 24** (su 20 e 22 l'evento ha solo la forma senza corpo). `node:http`, Express e Fastify funzionano da 20. Dal registro npm interno (`npm install @traffic-twin/sdk`) o dal file del kit: `npm install ./traffic-twin-sdk-x.y.z.tgz`. |
| Java, .NET, Go, PHP | Java ≥ 17 (`traffic-twin-agent.jar`), .NET ≥ 8, Go ≥ 1.25, PHP ≥ 8.1. Comandi nella sezione 3.4; i file (jar, pacchetti) li dà il team piattaforma. |
| CLI `tt` | Il binario del kit (`tt version` per la versione). Serve per `tt mock`. |
| Chiave HMAC | Un file dell'installazione distribuito dal team piattaforma (sezione 4). **Non** si genera in locale. |
| Chiavi pubbliche del gate | Per il mock: già inserite nei comandi della pagina **Mock**; per il mock da file in **Pacchetti twin > Come usarlo nei test** (sezione 10.8). |

> **Passo 1 di 4 · Collega** (sezioni 3, 4 e 5): menu *Collega un servizio* e *Sorgenti*.

## 3. Collegare il proprio servizio

### 3.1 Onboarding (console > Onboarding)

1. Scegli il linguaggio del tuo servizio (**Python**, Node.js, Java, .NET, Go, PHP). La console ti mostra i comandi giusti per quel linguaggio, già con URL dell'intake, token e `TT_HMAC_KEY_FILE`.
2. **Nomi di servizio ammessi**: il nome con cui l'app si presenta (es. `bookings-api`). **Gruppo**: l'insieme delle sorgenti che condividono la stessa policy, di solito un'applicazione (es. `bookings`). Il campo Gruppo parte **vuoto**: il suggerimento (grigio) deriva dal nome del servizio e lo prendi con **Usa «bookings»**. Scegli un nome tuo: se esiste già un gruppo con quel nome (di un altro team) la console lo segnala, perché entrarci significa usare la sua policy.
3. **Genera il token e continua**: ottieni un token `tte_...` (monouso, scade in 1 ora; per più istanze usa un token di gruppo) e gli snippet con URL dell'intake, token e `TT_HMAC_KEY_FILE` già inseriti. Se il gruppo non ha una policy, la console crea e **attiva subito** la policy di partenza `p-<gruppo> v1` (fase **Osserva**): cattura solo la struttura, quindi non serve nessuna approvazione.
   **Il segreto del token si vede una sola volta**: il server ne conserva solo l'impronta e non può restituirlo. La console mostra «Token creato alle HH:MM, scade alle HH:MM»; ricaricando la pagina nella stessa scheda il token resta lì, in un'altra scheda o browser compare l'avviso «Hai già generato un token» (senza il segreto) con **Rigenera il token**. Se non l'hai copiato, rigeneralo: il precedente scade comunque alla sua ora.
4. Il passo **In ascolto** (3.5) segue la tua sorgente dal vivo. Le scelte sui campi (sezione 5) sono facoltative e stanno sotto **Avanzate: modifica la policy**.

### 3.2 Installare l'SDK

Dal registro interno, se il team piattaforma l'ha pubblicato; altrimenti dal file del kit (finché il pacchetto non è pubblicato):

```sh
cd myapp
# Python (3.9+)
pip install ./traffic_twin-x.y.z-py3-none-any.whl          # oppure: pip install traffic-twin
# Node.js (20+)
npm install ./traffic-twin-sdk-x.y.z.tgz                   # oppure: npm install @traffic-twin/sdk
# Go
go get github.com/ivseb/traffic-twin/sdk/go
# PHP (8.1+)
composer require traffic-twin/sdk
# Java: scarica traffic-twin-agent.jar dal registro degli artefatti
# .NET: dotnet add package TrafficTwin.Sdk.AspNetCore  (o l'hook senza codice, sezione 3.4)
```

### 3.3 La chiave HMAC

Mettila dove punta `TT_HMAC_KEY_FILE` (es. `/etc/traffic-twin/hmac.key`, permessi 0640). Cos'è, da dove viene e perché non va generata in locale: sezione 4.

### 3.4 Avviare il servizio con l'SDK

Le variabili sono le stesse per tutti i linguaggi (il wizard le scrive già compilate):

```sh
export TT_ENROLL_URL=https://<intake>:4318           # dal wizard
export TT_ENROLL_TOKEN='tte_...'                     # dal wizard (segreto: non committarlo)
export TT_SERVICE_NAME=bookings-api                  # uno dei nomi ammessi del gruppo
export TT_HMAC_KEY_FILE=/etc/traffic-twin/hmac.key   # dal team piattaforma
export TT_STATE_DIR=$PWD/.tt-state                   # certificato e policy locali (default ~/.traffic-twin)
export TT_DEBUG=1                                    # facoltativo: stampa solo codici di stato, mai valori
```

Poi avvia il servizio **con il comando del tuo linguaggio**, senza toccare il codice:

**Python (FastAPI, Flask, Django).** `python -m traffic_twin run -- <il tuo comando>` avvia il programma con l'SDK già attivo. Cattura da solo **le chiamate in ingresso** (la tua API, quella che compare tra i servizi) e **quelle in uscita** (`requests`, `httpx`, `urllib`):

```sh
python -m traffic_twin run -- uvicorn app:app --port 8000             # FastAPI / Starlette / qualunque app ASGI
python -m traffic_twin run -- gunicorn app:app                        # Flask / WSGI (anche -k uvicorn.workers.UvicornWorker)
python -m traffic_twin run -- flask --app app run                     # Flask
python -m traffic_twin run -- python manage.py runserver              # Django
```

- Flask, FastAPI/Starlette, Django e le app caricate da uvicorn o gunicorn si avvolgono da sole. Con `--factory` l'app che la factory crea è avvolta se è FastAPI/Starlette o Flask; una factory che restituisce una funzione ASGI nuda non si avvolge da sola: dentro la factory usa `traffic_twin.install(app)`.
- Le chiamate in uscita di `requests` e `httpx` si catturano appena le importi; `TT_OUTBOUND=off` spegne la parte in uscita, `TT_OUTBOUND=httpx` (o `requests,httpx,urllib,http.client`) sceglie quali.
- **Se non si riesce ad avvolgere nessuna app** (un server o un framework che non conosciamo) l'SDK lo dice **una volta sola**, dopo 20 secondi, su stderr: `inbound not captured: ... add traffic_twin.install(app)`, e la console mostra sulla sorgente il problema **Ingresso non catturato**. Rimedio, una riga dove crei l'app:

```python
import traffic_twin
app = traffic_twin.install(app)                    # Flask, FastAPI/Starlette, qualunque app WSGI/ASGI
application = traffic_twin.install(get_wsgi_application())      # Django (anche get_asgi_application())
```

- Su Python 3.9 serve anche `TT_ENROLL_CA_FILE` (il file PEM della CA aziendale): l'impronta del token si verifica su quel file.

**Node.js.**

```sh
node --import @traffic-twin/sdk/register server.js
```

**Java (17+).**

```sh
java -javaagent:traffic-twin-agent.jar -jar app.jar
```

**.NET (8+), senza codice.** L'hook si pubblica una volta da `sdk/dotnet` (o lo prendi dal registro degli artefatti):

```sh
dotnet publish src/TrafficTwin.StartupHook -c Release -o /opt/traffic-twin
DOTNET_STARTUP_HOOKS=/opt/traffic-twin/TrafficTwin.StartupHook.dll \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore \
  dotnet app.dll
```

Oppure nel codice, con il pacchetto NuGet: `builder.Services.AddTrafficTwin(); ... app.UseTrafficTwin();`.

**Go (1.25+).** Nel codice:

```go
tt.Start(context.Background())                          // legge TT_ENROLL_URL, TT_ENROLL_TOKEN, TT_HMAC_KEY_FILE
http.ListenAndServe(":8080", tt.Handler(mux))
client := &http.Client{Transport: tt.Transport(http.DefaultTransport)}
```

**PHP (8.1+).**

```sh
php -d auto_prepend_file=vendor/traffic-twin/sdk/register.php -S 0.0.0.0:8080
```

Il token serve solo alla prima iscrizione: ai riavvii basta `TT_STATE_DIR`. Per altre istanze serve un token nuovo o un token di gruppo.

Se manca la chiave l'SDK lo dice sempre, anche senza `TT_DEBUG`, con una riga `[traffic-twin] key_missing: ...` che spiega la causa; l'applicazione funziona come prima ma non viene catturato nulla. In console la sorgente mostra **Chiave HMAC mancante**.

### 3.5 In ascolto: la fase Osserva

Non c'è niente da approvare per cominciare. La policy di partenza `p-<gruppo> v1` è già attiva quando avvii il servizio: l'SDK la riceve al primo contatto e passa a `state capturing`. Cosa cattura:

- **solo la struttura**: endpoint, nomi dei campi, tipo e classe di lunghezza, status, latenza; i valori si scartano tutti;
- per 72 ore la **scoperta** (quanti valori distinti ha ogni campo, senza vederli) e le parole nei percorsi, che servono alla console per riconoscere gli identificativi;
- il campionamento di default è il **10%** degli utenti: con k = 20 (una regola o un valore escono solo se almeno 20 utenti distinti li hanno prodotti, e la console ne vuole il doppio) bastano circa 400 utenti nel traffico. Se il tuo servizio ne ha meno, alza il campionamento nella scheda del wizard: finché la policy non lascia uscire valori in chiaro, alzarlo **non apre dati** e si applica subito.

Il passo **In ascolto** del wizard mostra, aggiornati da soli: gli eventi che arrivano, i servizi e gli host esterni scoperti, e poi **«Policy Osserva attivata alle HH:MM»**. Dopo circa 200 chiamate (o al più tardi 15 minuti dopo l'avvio, con l'impostazione di default) la console crea **da sola** una nuova versione della policy che:

- trasforma in **sigle (`hmac`)** gli identificativi che riconosce: parametri dei percorsi (`/bookings/{id}`), campi come `id`, `uuid`, `bookingId`, `user_id`, `chargeRef`, valori con forma di UUID; campi con lo stesso nome nelle diverse chiamate prendono la stessa sigla, così una prenotazione creata e poi letta si riconosce come la stessa;
- riconosce **chi è l'utente** dai dati e lo usa sempre come sigla (sezione «Identità dell'utente» qui sotto): il `sub` del JWT nell'header `authorization` se c'è, altrimenti l'header che si comporta come un id utente, qualunque sia il suo nome;
- lascia uscire in chiaro gli **stati e i codici** (`code`, «codice in chiaro»): sui campi che si chiamano `status`, `state`, `type`, `kind`, `reason`, `code`, `error_code`, `outcome`, `result`, `stage`, `phase`, `step`, `mode`, `method`, `channel`, `level`, `severity` e simili (anche `orderStatus`, `payment_state`, `cancelReason`) e le cui forme sembrano codici, il valore esce solo se è fatto di lettere, `_` e `-` (da 2 a 32, niente cifre né spazi): `DELIVERED`, `in_transit`, `card_declined` escono, «in transito» o `E404` escono solo come forma. Mai su nomi come `name`, `email`, `city`, `note`, `title`, `category`, né sui codici segreti (`promoCode`, `verificationCode`, `zipCode`, i parametri `code`/`state` di OAuth);
- **(v1.19) codici con cifre** (`code(alnum)`, «code (con cifre)»): sui campi di codice i cui valori sono cifre o codici brevi (`itemCode`, `storeCode`, `channelType`, `version`…) esce in chiaro solo un valore di 1–16 caratteri tra lettere, cifre, `_`, `-` e `.` (`0000123450`, `2.1`, `R`); il resto esce come forma. Se un campo così mostra **più di 50 valori diversi** è un identificativo: va da solo in quarantena con l'allarme «troppi valori» e la console non lo propone più come codice;
- non lascia mai uscire altri valori in chiaro né una fascia (`keep`, `bucket`).

Il wizard elenca i campi mascherati in parole semplici («`bookingId` nella risposta di `POST /bookings` → sigla `booking`»). La versione è firmata da keyguard come tutte le altre, compare in **Sorgenti > Policy** con origine «Osserva (automatica)» e nell'audit con attore *sistema*. Anche dopo che una persona ha firmato un'altra modifica (per esempio **Simula nel mock**), la console continua a mascherare da sola gli identificativi che vede per la prima volta (campi e servizi nuovi), ma non tocca mai un campo su cui una persona ha scelto: un campo con una regola resta com'è, uno che una persona ha rimesso a `drop` resta `drop`. Non lo fa mentre c'è una bozza in attesa di approvazione. Per spegnere l'automatismo di un gruppo: `PUT /api/v1/fleet/groups/<gruppo>/observe` con `{"auto": false}`. **Simula nel mock** mette già `hmac` sugli identificativi dell'host nella stessa versione.

#### Identità dell'utente

Per contare gli utenti distinti (k), campionare per utente e ricavare regole, la console deve sapere quale parte della richiesta dice **chi è l'utente** (`identity.subject`). Il valore non esce mai in chiaro: la sorgente lo trasforma in una sigla HMAC.

**Come la console lo riconosce da sola.** Non usa un elenco di nomi: guarda i dati della scoperta (quanti valori distinti ha ogni header, su quante chiamate compare, che forma hanno), mai i valori. Un buon candidato:

- ha **molti valori distinti ma meno delle chiamate**: lo stesso utente fa più chiamate. Un header con un valore nuovo a ogni chiamata è un id di richiesta o di traccia e viene scartato; uno con pochi valori (un tenant, un canale, una versione) anche;
- ha la **forma di un identificativo** (UUID, numeri, esadecimale; un testo corto va bene, un'e-mail o un telefono valgono meno ma escono comunque solo come sigla; date, URL e testi lunghi no);
- compare sulla **maggior parte delle chiamate**;
- ha, come indizio debole, un **nome** che in qualche lingua indica una persona (user, customer, member, account, utente, cliente…). Il nome da solo non basta: decidono i dati.

Se la maggior parte delle richieste porta un JWT bearer vince il suo `sub`. Altrimenti vince il candidato con il punteggio più alto, se è abbastanza convincente; se nessuno lo è la console non sceglie e te lo dice. I cookie e gli header che sembrano credenziali (token, secret, session, key, auth…) non vengono mai scelti da soli.

**Cambiarlo dalla console.** Nel passo **In ascolto** del wizard e in **Sorgenti > Policy** la scheda **Identità dell'utente** mostra la scelta attuale, il candidato rilevato con i motivi («molti valori, si ripete per utente», «forma da identificativo», «su quasi tutte le chiamate»…) e gli altri candidati, compresi quelli scartati con il perché. Puoi sceglierne un altro o scrivere un nome (un header, un claim del JWT, un cookie):

- **qualsiasi header che non sia una credenziale**, con o senza claim JWT, e **qualsiasi claim** del JWT bearer in `authorization` si applicano **subito**, senza approvazioni: escono solo come sigla. La scelta è nell'audit (`policy.identity_set`);
- un **cookie**, `authorization` senza claim o un header il cui nome sembra una credenziale (senza claim) **aprono valori**: nasce una bozza da approvare;
- i parametri della query non possono indicare l'utente (le sorgenti leggono l'utente solo da header e cookie).

Una volta scelta da una persona, la console non sostituisce più l'identità da sola.

Se la tua installazione ha spento la firma automatica (`TT_KEYGUARD_OBSERVE_AUTO=false`, scelta del team piattaforma), la policy di partenza resta una bozza da approvare come nelle versioni precedenti: **Sorgenti > Policy**, apri la bozza `p-<gruppo> v1` e premi **Approva** in fondo al pannello (un amministratore approva da solo con una motivazione). Una sorgente in attesa compare come **In attesa di policy** (stato neutro, non un errore) e non cattura nulla.

### 3.6 Verificare che arrivino eventi

- **Sorgenti**: il tuo servizio è **In salute**, "Ultimo contatto" pochi secondi fa. Il campionamento mostrato è quello della policy, oppure quello ridotto su quella sorgente (vale sempre il più basso).
- **Servizi**: compaiono il tuo servizio (Proprio) e gli host esterni che chiama. Se vedi **solo gli esterni** e il tuo servizio manca, la cattura in ingresso non è attiva: guarda il problema **Ingresso non catturato** sulla sorgente (sezione 3.4).
- Genera un po' di traffico (test, carico, uso normale).

## 4. La chiave HMAC

L'SDK trasforma gli identificativi (id di prenotazione, di charge, dell'utente) in sigle stabili e non reversibili (`hmac`) con una chiave segreta. Regole:

- c'è **una sola chiave per tutta l'installazione**, generata e distribuita dal team piattaforma; è un file con una riga `<kid>:<base64url>` (es. `k1:...`);
- il **kid** deve essere quello di `hmac.kid` della policy del gruppo (di solito `k1`);
- il file deve contenere **la stessa chiave di keyguard**: il gate rifà i calcoli con le chiavi di keyguard ("prova al contrario") per essere sicuro che in un pacchetto non finisca un valore reale. Con una chiave diversa il gate non può proteggere i tuoi dati.

Non generare una chiave per conto tuo. Se il kid non coincide con quelli di keyguard, la console mostra sulla sorgente **"chiave HMAC sconosciuta a keyguard"**; se coincide ma la chiave è un'altra, i dati non sono verificabili.

Per il team piattaforma (dettagli nella console, **Aiuto > Chiavi HMAC**):

```sh
# una volta per installazione, sull'host di keyguard
tt keyguard genkey -type hmac -kid k1 -out /etc/traffic-twin/hmac.keys
# keyguard legge lo stesso file: TT_KEYGUARD_HMAC_KEYS_FILE=/etc/traffic-twin/hmac.keys

# macchine delle sorgenti
sudo install -m 0640 -o root -g <gruppo-app> hmac.keys /etc/traffic-twin/hmac.key

# Kubernetes: un Secret per namespace dell'applicazione (il webhook di iniezione lo monta)
kubectl -n <namespace> create secret generic tt-hmac --from-file=hmac-key=/etc/traffic-twin/hmac.keys
# annotazione del pod template: traffic-twin.io/hmac-secret: tt-hmac
```

Rotazione: si aggiunge la chiave nuova allo stesso file (una riga per kid, la vecchia resta), si redistribuisce il file e poi si porta `hmac.kid` delle policy al kid nuovo (con quello vecchio in `accept_kids`).

## 5. Capire e approvare la policy

La policy è la lista di **cosa può uscire** dal tuo processo, campo per campo. Cinque azioni:

| Azione | Cosa esce | Quando |
|---|---|---|
| `drop` | solo la forma (tipo del campo, presenza, classe di lunghezza) | default; email, header, timestamp, testo libero |
| `keep` | il valore così com'è (max 64 byte) | campi con **pochi valori possibili** che non sono codici: categorie e motivi con spazi, città |
| `code` («codice in chiaro») | il valore solo se è un codice (lettere, `_`, `-`, 2–32 caratteri), altrimenti la forma | **stati e codici** (`status`, `state`, `type`, `reason`, `error_code`…): si applica senza approvazioni e la versione Osserva lo propone da sola |
| `code(alnum)` («code (con cifre)», v1.19) | il valore solo se è un codice breve con cifre (lettere, cifre, `_`, `-`, `.`, 1–16 caratteri), altrimenti la forma | **codici di prodotto, punto vendita, canale, versioni, classi** (`0000123450`, `2.1`, `R`). Puoi sceglierlo anche su un campo che non si chiama come un codice, purché non sia una credenziale, un segreto o un dato personale (`name`, `email`, `phone`, `address`, `city`, `user`…): non servono approvazioni, ma oltre 50 valori diversi il campo va in quarantena da solo |
| `hmac` | una sigla stabile e non reversibile: lo stesso id dà sempre la stessa sigla | **identificativi** che servono per collegare causa ed effetto (id di prenotazione, charge, rimborso, utente, id nei percorsi) |
| `bucket` | la fascia del numero, con bordi scelti da te | importi, temperature (scegli bordi adatti all'unità: per centesimi, es. `0, 5000, 10000, 50000`) |

Non escono mai: gli header di credenziali (`authorization` è "never kept") e i valori dei campi `drop`. L'assistente mostra solo forme e conteggi distinti, mai valori.

Esempio di scelte per `bookings-api` e le sue API esterne:

| Campo (esempi) | Azione |
|---|---|
| `$.id`, `$.booking.id`, `$.chargeId`, `$.refundId`, `$.userId`, id nei percorsi | `hmac` |
| `$.status`, `$.currency`, `$.error.code` (valori come `CONFIRMED`, `EUR`, `card_declined`) | `code` |
| `$.refunded`, `$.forecast[*].sky`, `query.city`, un motivo con testo libero | `keep` |
| `$.amount`, `$.price_cents`, `$.forecast[*].temp_c` | `bucket` |
| `$.email`, `createdAt`, gli header tranne `content-type` | `drop` |

**Quali modifiche richiedono un'approvazione.** Solo quelle che **aprono valori**. La console lo dice prima dell'invio, con il motivo:

- **«Questa modifica non apre dati: si applica subito»**: aggiungere `hmac`, `drop` o `code` sui campi di stato e di codice, togliere `keep` o `bucket`, dichiarare servizi e operazioni, scegliere come utente un claim del JWT o un header che non sia una credenziale (qualunque nome), alzare il campionamento quando nessun valore esce in chiaro. keyguard la firma subito, senza persone (l'audit lo registra).
- **«Apre valori in chiaro: serve un'approvazione»**: un `keep` (per esempio una categoria con spazi, che `code` lascerebbe come forma), un `bucket` (o confini più fini), un'identità da un cookie, da `authorization` senza claim o da un header che sembra una credenziale, parole o host in `segments.allow`/`hosts_allow`, il ritorno da `hosts.discovery: off` ad `auto`, più campionamento o un gruppo in più su una policy che lascia già uscire valori, il ripristino di una versione precedente. Servono le approvazioni configurate (default 2 persone; un amministratore può approvare da solo con una motivazione).

Come si fa: **Sorgenti > Policy > Rivedi in blocco** mostra i campi raggruppati per tipo (identificativi, stati e codici, numeri, date, dati personali) con una sola azione per gruppo e dice subito se la modifica si applica o va approvata. Dentro ogni gruppo ogni campo ha la sua casella: l'azione scelta vale per i campi spuntati, e su ogni riga vedi cosa fa la policy ora, la proposta dell'assistente e cosa diventa. Un campo che è già «codice in chiaro» (`code`) non diventa mai `keep` da qui, e il conto «aprono valori» include solo i campi che davvero lasciano uscire valori. Prima di inviare, il pannello dice quante approvazioni servono e chi può darle (le persone con il ruolo Approvatore di policy, tu escluso); se sono meno di quelle richieste, lo dice, e ricorda che un amministratore può approvare da solo con una motivazione. Per il dettaglio campo per campo c'è anche il wizard, sotto **Avanzate: modifica la policy**: l'assistente propone un'azione per ogni campo osservato; scegli, rivedi le modifiche e invia. Ogni invio crea una nuova **versione della policy** (v1, v2, …).

**Ordine consigliato per le modifiche che aprono valori: una sola bozza, una sola approvazione.** Ogni versione che apre valori costa una motivazione e almeno due clic di approvazione, e il campionamento cambia il numero di utenti che l'assistente vede: se prima scegli i campi e poi l'utente o il campionamento, i numeri si spostano e ricominci. Fai così, **tutto nella stessa pagina del passo Policy, in un solo invio**:

1. **Utente** (`identity.subject`): scegli il candidato che l'assistente ha riconosciuto (per un JWT è il `sub`; vedi «Identità dell'utente» nella sezione 3.5). Il conteggio degli utenti distinti cambia proprio in base a questa scelta.
2. **Campionamento**: guarda la scheda e accetta il tasso proposto, che è già calcolato **sul criterio che hai appena scelto**.
3. **Host esterni da simulare nel mock** (sezione 6): in questo passo (Servizi scoperti) o da **Host esterni > Simula nel mock**. Se c'è già una bozza in attesa si sommano a quella.
4. **Campi**: `hmac` per gli identificativi, `keep` per gli enum, `bucket` per gli importi (tabella sopra).
5. **Richiedi approvazione**, una sola volta.

Finché non invii, nel passo Policy compare «**Le modifiche si accumulano nella bozza v5 finché non la invii**» (con il numero della tua bozza, se ne esiste già una). **Ritirare una bozza**: finché è in attesa, chi l'ha proposta (o un amministratore) la toglie con **Ritira bozza** (in Sorgenti > Policy, nel pannello della bozza e nella Panoramica). Non diventa mai attiva, le approvazioni già date vanno perse, la policy attiva non cambia; resta nell'audit e l'automatismo Osserva riprende. Se il server non offre ancora il ritiro, la console lo dice e si può sostituire la bozza con una nuova proposta. Se hai già inviato e ti accorgi che manca qualcosa, nel passo Rivedi premi **Modifica la bozza**, correggi e **Aggiorna la bozza**: nasce una versione nuova che sostituisce quella in attesa, con tutto dentro (non si perde nessuna approvazione, finché la bozza non ne ha). Se la bozza ha già ricevuto approvazioni, modificarla le annullerebbe: approvala o rifiutala da Sorgenti > Policy e, se serve altro, proponi una nuova modifica.

**Chi è l'utente.** Per i contratti con valori, le regole e il mondo serve sapere a quale utente appartiene una chiamata (`identity.subject`), per esempio il `sub` del JWT nell'header `authorization`. Senza un utente riconosciuto i valori `keep` non superano la soglia k (k_min = 20 utenti distinti) e restano nascosti.

**Campionamento e k-anonimato.** Il campionamento della policy è **per utente**: con `sampling.rate` 0,05 passa il traffico del 5% degli utenti. Un valore o una regola escono solo se almeno **k = 20 utenti distinti** li hanno prodotti. Con pochi utenti e un tasso basso se ne vedono meno di k e il miner non può proporre nessuna regola: per esempio 200 clienti al 5% sono circa 10 utenti campionati. La console lo dice con le cifre:

- nel passo **In ascolto** e nel passo **Policy** del wizard, la scheda **Campionamento** mostra gli utenti distinti campionati, k e il tasso che servirebbe (calcolato sul traffico visto finora, con un margine di due volte k). Se la policy non lascia uscire valori in chiaro, alzarlo non apre dati e si applica subito; se ne lascia uscire, è una modifica che apre valori e va approvata;
- in **Regole** il miner dice "Pochi utenti distinti campionati: N < k=20; aumenta il campionamento della policy o attendi più traffico", con il link all'assistente (sezione 8.1).
- **Prima di aver scelto chi è l'utente** (`identity.subject`) la scheda non conta nessuno e dice «Identità utente non configurata: impossibile contare gli utenti»: i token di autorizzazione non sono utenti (lo stesso membro con un token nuovo a ogni accesso conterebbe più volte) e il campionamento diventa per utente solo dopo l'approvazione. Ordine consigliato: utente, poi campionamento, nella stessa bozza. La scheda chiede il **doppio di k** (40 con k = 20), perché ogni esito di una regola abbia almeno k utenti: «34, ne servono almeno 40» non è un errore di conto.

La riduzione che si imposta su una singola sorgente (Sorgenti) può solo **abbassare** il tasso; per alzarlo serve una nuova versione della policy, cioè questa scheda.

> **Passo 2 di 4 · Osserva** (sezione 6): menu *Servizi* e *Host esterni*. Lascia girare il servizio almeno 24 ore e torna: più traffico, contratti e regole più completi.

## 6. Host esterni e servizi da simulare nel mock

"Simulare nel mock" un host = dirgli un nome e dire a traffic-twin che è un servizio esterno che il mock deve simulare al posto di quello vero.

1. **Host esterni**: tutto ciò che i servizi chiamano, raggruppato per dominio (i contatori in alto contano anche gli host chiamati per indirizzo IP; un host dichiarato compare una volta sola, «dichiarato come …», con le chiamate viste prima della dichiarazione sommate). Se chiami per IP (es. `127.0.0.1:9101` in locale o in CI) l'indirizzo non esce mai: vedi `ip:private:9101`.
2. **Simula nel mock** sull'host: scrivi l'URL di base esatto (stessa classe di indirizzo e stessa porta, es. `http://127.0.0.1:9101`) e un nome (`payments-ext`), poi **Controlla cosa cambia**: il dialogo ti dice cosa dice il server prima di confermare. Di solito aggiungere un servizio **non apre valori** e si applica subito («Applicata alle HH:MM»); se apre valori nasce una bozza e il dialogo dice quante approvazioni servono e chi può darle. Con un nome DNS vero (es. `api.payments.example`) non serve scrivere l'URL. Dopo, controlla gli identificativi del nuovo servizio con **Rivedi in blocco > Identificativi**: restano nascosti finché non diventano sigle (hmac).
   Se la policy ha già una bozza di simulazione o dell'assistente in attesa, **la nuova richiesta si aggiunge a quella bozza** (diventa una nuova versione che contiene anche l'host precedente; la versione vecchia risulta "sostituita"): non nascono bozze sorelle che si cancellano a vicenda. Simula due host di seguito e approva solo l'ultima bozza. Lo stesso vale se poi passi dall'assistente (utente, campionamento, campi): tutto finisce nell'ultima bozza, da approvare una volta.
3. Da quel momento le chiamate nuove compaiono sotto `payments-ext`; quelle di prima restano sotto `host:ip:private:9101`, che la console mostra come **"ora dichiarato come payments-ext"** (una sola voce, non un duplicato).

In **Servizi** l'interruttore **Simula nel mock** decide chi risponde: **acceso** ("Il mock risponde"), il mock risponde al posto di quel servizio e il servizio entra nel prossimo pacchetto twin; **spento** ("Resta il servizio reale"), la tua app continua a chiamare quello vero. Spegnerlo non cancella nulla: i contratti restano visibili. Un `host:...` non ancora dichiarato è "Da simulare nel mock", con il link a Host esterni.

### 6.1 Il filtro Gruppo

La console è condivisa tra più team, e ogni team ha il suo **gruppo** (es. `bookings`): le sue sorgenti, la sua policy `p-<gruppo>`, i suoi servizi, contratti, regole, mondi e pacchetti. Il selettore **Gruppo** nella barra in alto serve a vedere solo i tuoi.

- **Cosa filtra**: tutto. Servizi, Host esterni, Sorgenti → Policy, Contratti (anche il menu "Per servizio" e i viewer OpenAPI), Archetipi, Mondi, Pacchetti (compreso il rischio residuo), Regole (anche il riquadro "Ultima analisi"), Buchi, Allarmi e Quarantena. Il filtro è applicato dal server: una pagina filtrata non riceve proprio i dati degli altri gruppi.
- **Un servizio è (gruppo, servizio)**: il gruppo di una chiamata è quello della sorgente che l'ha catturata. Se due team chiamano lo stesso indirizzo (per esempio due API finte su `127.0.0.1:9301`, che diventano entrambe `host:ip:private:9301`) sono **due servizi diversi**, con chiamate, contratti e pacchetti separati. Il nome che un team dà a quell'host nella sua policy (es. `pizza-payments`) vale solo per lui: "ora dichiarato come" compare solo per gli host dichiarati dalla policy del tuo gruppo.
- **Cosa vedi di default**: un amministratore vede **tutti** i gruppi, con una colonna Gruppo in Servizi, Host, Contratti e Policy (lo stesso host chiamato da due team è su due righe); gli altri "I miei gruppi" (quelli per cui hanno creato un token o proposto una policy; per un amministratore la voce si chiama "Gruppi con mie azioni"). Scegli il tuo gruppo la prima volta e lascialo: la scelta resta nel browser.
- **Più gruppi**: puoi selezionarne più d'uno (per esempio `bookings` e `bookings-twin`); "Tutti" li mostra tutti.
- **Approvare**: con il filtro attivo la pagina Policy mostra solo le policy del gruppo; con "Tutti" le bozze di altri gruppi dicono "Di un altro gruppo" e non hanno il pulsante Approva. Controlla comunque che la bozza sia della tua policy (`p-<tuo gruppo>`).
- **Assistente policy**: mostra solo gli host chiamati dalle sorgenti del gruppo; un vecchio `host:...` che descrive un servizio ormai dichiarato è riunito in quel servizio ("Comprende anche: ..."), e "Dichiara nella policy" è spuntato solo per gli host chiamati di recente e non ancora dichiarati (quelli fermi da tempo, per esempio una porta vecchia, sono segnati "nessuna chiamata recente"). Gli header di trasporto (`host`, `user-agent`, `accept`...) e gli istanti delle chiamate (`createdAt`, `updatedAt`) restano drop; bucket del giorno solo per le date di business (scadenze, inizio, fine).
- **Mondi e pacchetti**: un mondo si genera per un gruppo: contratti ricavati dal solo traffico del gruppo, archetipi del gruppo, regole i cui servizi sono tutti del gruppo. Nel dialogo del pacchetto scegli quali servizi includere o escludere; un pacchetto che mescola servizi di più gruppi (o un host chiamato da più gruppi in un mondo di tutti i gruppi) è rifiutato (`mixed_groups`) a meno che un amministratore scelga esplicitamente "più gruppi" (sezione 9).
- **Dati di prima**: all'avvio, i contratti, i mondi e i pacchetti salvati prima di questa versione sono attribuiti al gruppo che ha prodotto i loro servizi; un contratto di un servizio usato da più gruppi resta "di tutti i gruppi" finché la fotografia successiva non ne crea uno per gruppo. Gli archetipi si ricostruiscono da soli per gruppo alla prima generazione di un mondo (la pagina Archetipi, in Avanzate, li mostra).


> **Passo 3 di 4 · Rivedi** (sezioni 7 e 8): menu *Contratti*, *Regole*, *Buchi* e *Allarmi*.

## 7. Contratti

- **Contratti**: "Vista globale" (operazioni a sinistra) e "Per servizio" (riepilogo, operazioni, fotografie, scheda OpenAPI). Per ogni operazione: schema con la presenza di ogni campo, status e latenze, esempi sintetici; "Fotografie" confronta due date e dice se un cambiamento è **incompatibile** (può far smettere di funzionare un client, per esempio un campo che cambia tipo) o **compatibile** (un'aggiunta che non lo tocca, per esempio un campo opzionale nuovo).
- Il contratto si ricava dal traffico **senza dichiarare le operazioni nella policy**: i segmenti dei percorsi che cambiano a ogni chiamata (id, uuid, numeri) diventano parametri, per esempio `GET /bookings/{id}` e `GET /users/{id}/bookings`.
- **Quando compare**: la fotografia del contratto si fa una volta per finestra (24 ore, a fine giornata UTC più 5 minuti). Prima della prima fotografia la pagina del servizio mostra il contratto "dal vivo" e la scheda **Quando compare il contratto**: chiamate viste, operazioni, quante hanno già almeno 20 chiamate (il minimo per uno schema affidabile) e quando è la prossima fotografia.
- **Aggiorna contratto ora** (operatore) fa subito una fotografia del traffico delle ultime 24 ore, senza aspettare fine giornata.
- Un'operazione con meno di 20 chiamate è marcata "poche osservazioni"; nei pacchetti entrano solo operazioni e risposte viste almeno k volte.
- Lo stesso documento si scarica dalla scheda OpenAPI (JSON o YAML), e si apre in Swagger UI, Redoc e Scalar.
- **Postman e Insomnia**: nella pagina del servizio, **Scarica collezione Postman** dà un file con una richiesta per ogni operazione, già con il corpo di esempio. L'indirizzo è nella variabile `{{baseUrl}}`: impostala sull'indirizzo del tuo mock (per esempio `http://localhost:8480`) e puoi provare le chiamate a mano. Anche Insomnia importa la collezione, e sia Postman sia Insomnia importano direttamente il documento OpenAPI scaricato qui sopra.
- **Campi collegati**: sotto lo schema di una risposta (o della richiesta) compaiono i valori che vanno insieme nello stesso oggetto, per esempio «Grandi elettrodomestici → Forni, Frigoriferi». Si ricavano dai campi `keep` e `bucket` a pochi valori, mai dagli id `hmac`; ogni combinazione è vista per almeno k utenti diversi (le altre non si mostrano). Il mondo sintetico, il mock e gli esempi producono solo queste combinazioni; nel documento OpenAPI sono l'estensione `x-tt-dependencies`.

- **Servizi SOAP/XML, upload e documenti** (v1.19): un corpo XML o SOAP diventa un albero come il JSON (attributi `@nome`, elementi ripetuti come liste) e un servizio SOAP con molte operazioni sullo stesso indirizzo si divide per operazione (`POST /ws/orders.asmx#GetOrder`, dal `SOAPAction` o dall'elemento del `Body`); il contratto conserva la busta e gli spazi dei nomi (`x-tt-xml`), che servono al mock per rispondere con la stessa busta (v1.21, sezione 10.12). Gli upload `multipart/form-data` diventano campi come un form, e i file escono solo come tipo e dimensione (`drop:file:pdf:l128k`); i PDF e le immagini in base64 dentro il JSON escono come `drop:doc:<tipo>:<dimensione>`, mai il contenuto. Le risposte oltre 1 MiB (liste ricche) si leggono fino a 8 MiB: la struttura resta, le liste si accorciano ai primi 50 elementi (5 per le liste annidate) con il conteggio in classi. Tutto è acceso di default (`fleet.sanitizer` in `tt-core`); con sorgenti precedenti alla v1.19 spegnilo finché non sono aggiornate.
- **Servizi GraphQL** (v1.14): un servizio GraphQL ha un solo indirizzo (per esempio `POST /graphql`), ma nel contratto ogni operazione che i client chiamano è un'operazione a sé, letta come **QUERY GetOrder** o **MUTATION CreateOrder**, con il documento osservato, le variabili e la risposta. La sorgente non manda mai il testo della query: ne manda la forma, con i nomi e senza valori (ogni valore scritto nella query diventa `?s`, `?i`, `?e`…). Non serve dichiarare nulla: la fase Osserva riconosce l'endpoint dal contenuto, su qualsiasi percorso, e mette da sola le regole `graphql`. La scheda **GraphQL** del servizio mostra lo schema catturato dall'introspezione (solo nomi e tipi, scaricabile come `.graphql`) e le operazioni osservate. Il mock risponde all'indirizzo vero: introspezione per i gateway (schema stitching), operazioni per nome, errori GraphQL; un'operazione mai vista risponde `operation not observed`. La collezione Postman manda le richieste GraphQL all'indirizzo vero.

### 7.1 Formato degli id

Di default gli id sintetici sono del tipo `ORD-SYN-0042`: riconoscibili, ma non hanno la forma degli id veri. Se la tua applicazione **costruisce o scompone** gli id (divide `12-345678-0001-654321` sul trattino per ricavare un altro codice, prende la parte dopo l'ultimo punto di `XYZ.000123` senza gli zeri, si aspetta solo cifre, decodifica un base64url) con quegli id si rompe senza errori evidenti. Nella pagina del servizio, scheda **Formato degli id**, ogni dominio di id (gli `hmac` con lo stesso dominio, per esempio tutti i campi `orderId`) può avere un **modello**:

| Scrivi | Ottieni |
|---|---|
| `N`, `A`, `a`, `X` | una cifra, una lettera maiuscola, minuscola, una lettera o cifra a caso |
| cifre e `- . _ : / + = # @` | sé stessi; `'XYZ'` tra apici per le lettere fisse |
| `{campo}`, `{campo#2}`, `{campo#-1}` | il valore di un altro campo dello stesso oggetto, il suo 2° segmento, l'ultimo (segmenti divisi da `- . _ : /`) |
| `<…>` | il base64url di quello che c'è dentro |

Dopo il campo copiato, `|trim0` toglie gli zeri iniziali e `|pad6` completa a 6 cifre con zeri: `{campo#-1|trim0}`.

Esempi: `NN-NNNNNN-NNNN-NNNNNN`, `'XYZ'.NNNNNN`, `0000NNNNNN`, `NN-{parentId|pad6}-NNNN-NNNNNN` (il secondo segmento è l'id dell'oggetto collegato, così un client che lo estrae lo ritrova), `<'Item':NNNNNN>`. La scheda mostra subito tre id di prova e quanti id diversi il modello può dare (servono almeno 1000).

- Il formato vale per **tutti i campi del dominio nel gruppo**, in tutti i servizi, nel mondo sintetico, nel pacchetto e nel mock. Lo stesso oggetto ha lo stesso id ovunque, e due oggetti non hanno mai lo stesso id.
- Le parti casuali sono generate: **nessun valore vero** entra nel modello. Il gate controlla comunque, con keyguard, che nessun id generato (anche i primi che il mock genererà) sia uguale a un id vero; se capita, il pacchetto non passa e il messaggio dice di cambiare il formato.
- Dopo un cambio i mondi già generati del gruppo non valgono più: **generane uno nuovo** e prepara un pacchetto nuovo (o usa «Prepara e avvia» sulla pagina Mock).
- Gli id dei clienti sintetici restano `CUS-SYN-0001`.

## 8. Regole causa → effetto

- **Regole > Cerca nuove regole** lancia il miner; compaiono come **Bozza**. Ogni regola ha catena, esiti e prove; solo quelle che **approvi** entrano nel pacchetto. Stati: Bozza, Approvata, Da riconfermare (dopo un cambio di contratto), Rifiutata.
- **Quanto dura**: da pochi secondi a un paio di minuti con molto traffico (un'ora di carico continuo: circa 70 secondi). La pagina segue la ricerca da sola («Ricerca in corso da N s», «in coda dietro un altro lavoro»), anche se il server per un momento non risponde: non serve ripremere.
- **Il risultato**: alla fine compare un riquadro con le regole proposte e aggiornate, gli eventi esaminati e, **operazione per operazione, perché** (in italiano, con il link all'assistente quando serve cambiare la policy): "POST /loans su library-loans-api: regola proposta", "solo 12 utenti distinti, ne servono almeno 20", "nessuna chiamata è abbastanza vecchia da conoscerne l'esito: riprova tra poco", "crea reservation e non si osserva altro: basta il contratto". Sotto il titolo della pagina c'è sempre **«Ultima analisi alle HH:MM»**: anche senza premere il pulsante, il riquadro mostra l'esito dell'ultima analisi (pure quella programmata) per i servizi del filtro Gruppo. I testi tecnici del miner restano in «Dettagli tecnici».
- Il miner collega causa ed effetto tramite gli **identificativi in `hmac`** (sezione 5): senza id aperti non trova regole per il tuo servizio.
- I **ritardi sono figurativi**: conta l'ordine degli eventi ("dopo la charge compare il rimborso"), non il tempo reale; nel mock l'orologio è virtuale e si sposta a comando.

### 8.1 Regole: quando compaiono e cosa fare se non compaiono

Le regole sono la parte più lenta: **non compaiono subito** e il miner non propone nulla finché non ha visto abbastanza. Cinque condizioni, tutte necessarie:

| Condizione | Quanto | Come la controlli / cosa fare |
|---|---|---|
| **Orizzonte di traffico** | il traffico catturato deve coprire almeno **1 ora** di tempo reale (di default). Un esito (consegnata, rimbalzata…) si decide quando la causa è abbastanza vecchia: il miner lo impara dal traffico (il doppio del tempo in cui il 99% degli oggetti arriva allo stato finale, almeno 1 minuto), quindi una notifica che diventa `delivered` in pochi secondi è decisa dopo un minuto, non dopo un'ora | in Regole compare «servono almeno N ore di traffico» con le ore già viste. Lascia girare il carico (anche in un test di carico: conta il tempo vero, non il numero di chiamate). Per una prova veloce l'amministratore può abbassare `miner.min_horizon`; mai sul traffico vero |
| **Utenti distinti campionati ≥ k** | almeno **k = 20** utenti diversi devono aver prodotto il comportamento | «Pochi utenti distinti campionati: N < k=20»: alza il campionamento dall'assistente (sezione 5) o aspetta più utenti. Con 200 utenti al 5% sono circa 10: non bastano |
| **Utente configurato** | la policy deve dire chi è l'utente (`identity.subject`) | passo Policy del wizard, scheda Utente. Senza, il campionamento non è per utente e i conti non tornano |
| **Identificativi in `hmac`** | gli id che collegano causa ed effetto (id prenotazione, charge, …) devono essere `hmac`, non `drop` | assistente policy, azione dei campi `$.id`, `$.chargeId`, id nei percorsi |
| **Almeno k creazioni dell'oggetto** | per riconoscere un oggetto che nasce (una `POST` che crea una charge) servono almeno k creazioni viste: «solo N creazioni catturate, ne servono almeno 20» | genera più operazioni di creazione (per esempio 300 prestiti e non 17), con utenti diversi |

Cosa il miner riconosce, con un esempio (prestiti di una biblioteca): `POST /loans` crea il prestito, chiama il catalogo (`POST /v1/reservations` crea la prenotazione) e le notifiche (`POST /v1/messages` crea un messaggio `queued`); letture successive (`GET /v1/messages/{id}`, anche fatte dal tuo servizio) mostrano il messaggio `delivered` o `bounced`. La regola proposta è «POST /loans crea loan, reservation e message; il messaggio poi è consegnato (circa 90%) o rimbalza (circa 10%)». Tre dettagli:

- gli oggetti che **esistono già** prima della chiamata (il membro, il cliente, l'utente che la fa) sono **riferimenti**, non oggetti creati: non bloccano nessuna regola e non generano avvisi;
- se il tuo servizio restituisce con un nome suo (`notificationId`) l'id creato da un'API esterna (`$.id` di `POST /v1/messages`), il miner li collega anche se la policy li ha messi in spazi di nomi `hmac` diversi (`notification` e `message`): lo riconosce dalla struttura delle chiamate, mai dai valori;
- per vedere gli esiti servono **letture nel tempo** (anche una prima di quello finale): il miner non indovina stati che non ha mai visto.

**Dove leggere lo stato del miner**: pagina **Regole**. In alto c'è un badge (ore insufficienti, pochi utenti, avvisi), la riga «Ultima analisi alle HH:MM» e, dopo **Cerca nuove regole**, il riquadro **Risultato dell'ultima ricerca**: regole nuove e aggiornate, eventi esaminati e il perché di ogni operazione dei servizi del tuo gruppo; in «Motivi del miner» resta il testo tecnico. Gli stessi numeri sono nell'API (`GET /api/v1/rules/status`: `state`, `observed_hours`, `min_hours`, `subjects`, `k_min`, `events`, e per candidato `rule_diagnostics[].code` con `service`, `op`, `causes`, `decided`, `subjects`, `horizon_s`). Gli stati sono: `never_run` (non ha mai girato), `no_data` (nessun evento nella finestra), `insufficient_data` (meno ore dell'orizzonte), `few_subjects` (meno di k utenti), `ok`.

**Cosa fare se non compare nessuna regola**, in quest'ordine:

1. Premi **Cerca nuove regole** e leggi il riquadro del risultato: dice quale condizione manca.
2. «servono almeno N ore»: aspetta, il miner non si accelera.
3. «Pochi utenti distinti»: sezione 5 (campionamento) e controlla che l'utente sia configurato.
4. Il traffico c'è ma nessuna catena supera le soglie: controlla gli `hmac` (4ª condizione) e che gli oggetti si creino abbastanza volte (5ª).
5. Se dopo tutto questo non esce niente, il tuo caso potrebbe non avere una catena "scrittura → oggetto che cambia stato": il mock funziona lo stesso, ma **senza regole è statico** (nessuno stato che cambia con l'orologio). Puoi scrivere la regola a mano (sezione 8.3) o forzare risposte e guasti con i guasti personalizzati (sezione 10.9).

Il gate segnala "no approved rules" come avviso, non come errore: un pacchetto senza regole si può rilasciare.

### 8.2 Cosa il miner trova da solo e cosa no

Il miner lavora su token e forme, mai sui valori veri: vede solo ciò che il traffico mascherato mostra. Detto onestamente:

| Trova da solo | Non trova (usa l'editor) |
|---|---|
| **Causa → effetto tramite id condivisi**: lo stesso token `hmac` in due chiamate (l'ordine creato che compare nella spedizione del corriere) | **Calcoli**: totali, IVA, sconti, arrotondamenti. Vede che `total` cade in una fascia, non come si ottiene. Dalla v1.20 li scrivi come «Valore calcolato» nell'editor (§10.11) |
| **Cambi di stato** di un oggetto letto più volte (`PENDING` → `CREATED` → `DELIVERED`) e il loro ordine | **Logica su valori mascherati o scartati**: se un campo è `drop` o `hmac`, il miner non sa che «email aziendale» porta a un altro percorso |
| **Frequenze degli esiti**: consegnata nel 93% dei casi, annullata nel 4%, mai spedita nel 3% | **Rami rari**: un esito visto da meno di k utenti non diventa mai un ramo (protezione k-anonimità) |
| **Batch**: tanti cambi senza una scrittura dell'utente, concentrati alla stessa ora (consegne notturne) | **Regole aggregate su altri oggetti**: «dopo 3 resi il cliente è bloccato», «il quinto ordine del mese è gratis». I contatori sulla **stessa** operazione invece li trova (v1.17, sotto) |
| **Campi collegati** nei contratti (macrocategoria → categoria), con k utenti per combinazione | Comportamenti che dipendono da **tempo reale** o da sistemi che il traffico non mostra |
| **Oggetti che esistono già** (v1.15): contratti, indirizzi, consensi che nessuna scrittura crea ma che ogni utente legge come suoi. Il mondo sintetico ne dà a ogni cliente un numero preso da fasce viste per almeno k utenti | |
| **Stato senza id** (v1.15): profilo, carrello, consensi per documento, letti per utente o per un parametro e riscritti da una scrittura con la stessa chiave. Il mock tiene un record per chiave e sessione | |
| **Rimozioni** (v1.15): dopo un `DELETE` (o una scrittura che cita l'id) l'oggetto sparisce dalle liste e la lettura per id risponde 404 o 410 | |
| **Letture fatte con POST** (v1.15): una ricerca in POST che restituisce solo oggetti esistenti, sempre gli stessi a richiesta uguale, è una lettura. Se il miner sbaglia, nel dettaglio dell'operazione del contratto c'è «Questa operazione è una lettura» | |
| **Scritture che cambiano un oggetto esistente** (v1.16): la `PATCH` di un contratto, la sospensione, il cambio di indirizzo, il preferito acceso e spento. Il miner confronta l'oggetto letto prima e dopo la chiamata (anche con un'altra operazione o un altro servizio) e capisce se il valore nuovo è sempre lo stesso (`SUSPENDED`), quello che la chiamata manda (il piano scelto, l'id dell'indirizzo: due token uguali sono lo stesso valore, senza vederlo) o l'opposto di prima (un interruttore). Nel mock il valore copiato è quello che manda il tuo test. Se il cambio si vede solo dopo qualche lettura (una cache) la regola ha un ritardo figurativo. Nella catena della regola la console scrive «prende il valore che la chiamata manda in …» o «si inverte a ogni chiamata» | **Contatori e scritture su più oggetti**: «segna tutte come lette», «+1 a ogni chiamata». Le chiavi di stato fatte di più campi |
| **Letture che cambiano qualcosa** (v1.16): aprire una notifica la segna come letta. Una lettura diventa una causa solo se ci sono abbastanza oggetti osservati senza quella lettura per confrontare: un oggetto letto a ogni passo che cambia da solo (una spedizione che avanza) non diventa mai l'effetto della lettura | |
| **Stati che cambia l'utente** (v1.16): se l'annullamento di un ordine arriva sempre dopo `POST /orders/{id}/cancel`, non è più un esito «spontaneo» della creazione: la creazione propone solo i passi che avvengono da soli, ognuno con la condizione «solo se l'ordine è ancora nello stato di partenza», così nel mock un ordine annullato dal test non viene confermato dopo. Lo stato può essere anche un sì/no (`paid`) o una fascia di numeri | |
| **GraphQL** (v1.16): una query che filtra per un campo (`productId`) o per l'utente (`ownerId`) in una variabile, con la lista dentro un involucro (`data.contracts.items`, con il conteggio accanto) | |
| **Stati senza id cambiati da un'altra scrittura** (v1.17): l'iscrizione alla newsletter che accende un flag del profilo, la firma di un documento che segna il consenso di quel documento. Nella catena la console scrive «sul record per chiave di … : se manca lo crea» | |
| **Valori che tornano da soli** (v1.17): un contratto sospeso che dopo qualche ora torna attivo, un blocco temporaneo, un link valido per un po'. La regola dell'aggiornamento ha un secondo passo «torna a … dopo un ritardo figurativo», solo se nel frattempo nessuno l'ha cambiato | |
| **Unicità, tentativi, limiti di frequenza** (v1.17): una seconda creazione con la stessa email risponde 409, dopo 3 login falliti dello stesso utente il successivo risponde 423, più di 3 chiamate al minuto rispondono 429. Il miner conta, per ogni chiamata, le chiamate precedenti con la stessa chiave (un id della richiesta o l'utente) in una finestra figurativa (1 minuto, 15 minuti, 1 ora, 1 giorno o tutta la sessione); nel mock la risposta usa l'esempio del contratto per quello status | |
| **Oggetti che compaiono più tardi** (v1.17): il ticket aperto per una richiesta, che nessuna chiamata catturata crea ma che dopo un po' compare nella lista dell'utente e cita la richiesta. Diventa un effetto della creazione della richiesta, con un ritardo figurativo; se la richiesta sparisce quando compare il ticket (un id provvisorio sostituito da quello definitivo) la regola lo dice | |
| **Cicli** (v1.17): una carta bloccata che torna attiva da sola. Il ritorno è un passo della regola della creazione e gli oggetti tornati hanno un esito loro (`active-again`), invece di contare come «mai cambiati» | |
| **Esiti che dipendono da un valore** (v1.18): il bonifico che fallisce più spesso dall'app che dal web, la richiesta approvata subito per un cliente `GOLD`, il pagamento sopra una fascia d'importo che passa da una verifica. Il miner confronta gli esiti per valore (un codice in chiaro della richiesta, un header in chiaro, una fascia, un attributo del cliente) e propone rami con la condizione solo se la differenza è statisticamente netta e ogni valore ha almeno k utenti. Nella catena: «se il canale è APP …» | **Logica su importi mascherati**: un importo che esce come token o come forma non dà mai una condizione; con una fascia (`bucket`) sì |
| **Attributi del cliente** (v1.18): segmento, piano, lingua che compaiono in più risposte e sono sempre gli stessi per lo stesso utente. Il mondo li dà a ogni cliente sintetico e il mock li tiene uguali in tutte le risposte della sessione | |
| **Numeri che si contano** (v1.18): «3 notifiche non lette», il totale del carrello, il contatore che sale a ogni messaggio. Il mock li calcola dagli oggetti della sessione quando rispondi | **Calcoli con regole di prezzo**: sconti, IVA, arrotondamenti |
| **Liste** (v1.18): la dimensione della pagina, il numero di pagina, l'ordine (i più recenti prima) e i filtri per codice (`?status=OPEN`). Nel mock una lista statica non dà più pagine piene all'infinito | I cursori opachi del servizio (il mock usa i suoi) |
| **Precondizioni** (v1.18): «il checkout risponde 409 finché non hai aggiunto qualcosa al carrello». Nel mock vale dall'inizio della sessione finché il test non fa la chiamata che la toglie | |
| **Scritture su tutti gli oggetti dell'utente** (v1.18): «segna tutte come lette». E le chiavi di più campi (il consenso per documento **e** versione) | |

Per tutto quello che sta nella colonna di destra c'è l'editor di regole: la regola scritta a mano segue la stessa revisione e finisce nel pacchetto come le altre.

**Pochi tester (v1.18).** Con k = 20 un ambiente di test con 5 tester non produce regole. Due aiuti:

- **Candidati sotto soglia** (pagina *Regole*): le strutture che il miner vede, ma da meno di k utenti. Solo struttura (operazione, oggetto, campi, stati in chiaro, status) e il numero di utenti in fasce (`2-4`, `5-9`…). **Crea bozza** apre l'editor già compilato con il modello giusto («una scrittura cambia un campo», «scade dopo», «al massimo n», «finché non»); la salvi e la approvi come una regola scritta a mano. Se il candidato usa un oggetto che il miner non riconosce ancora, la console lo dice e suggerisce il gruppo di test.
- **Gruppo di test con k ridotto** (*Sorgenti › Policy › Domini e gruppo di test*, solo amministratore, con motivazione): il miner analizza quel gruppo con un k più basso (mai sotto 2) e i suoi pacchetti lo dicono con un avviso. Solo per traffico di tester: con k = 3 una regola può descrivere tre persone.

**Domini da unire (v1.18).** Nello stesso pannello la console propone le coppie di campi mascherati che sembrano lo stesso identificativo con due nomi (`clientId` e `customerId`): **Unisci** li fa uscire con lo stesso token, così il miner li collega; nessun valore esce e la modifica si applica subito; **Separa** la annulla.

### 8.3 Scrivere una regola a mano

**Regole > Nuova regola** apre l'editor guidato: «**Quando** *operazione di un servizio, con status* **allora** *effetti*», con i menu presi dai contratti e dalle entità riconosciute (servizi, operazioni, campi, stati osservati). Gli effetti possibili:

- **lo stato di un'entità diventa X** dopo un ritardo figurativo (l'ordine indicato dall'id nel percorso diventa `CANCELLED` dopo 1h);
- **nasce una nuova entità** con certi campi;
- **la prossima chiamata risponde Y** (`GET /invoices/{id}` risponde 410 una volta, con un esempio del contratto);
- **una chiamata fallisce con frequenza p** (il corriere risponde 503 una volta su cinque, da quel momento).

Sotto, «**In parole semplici**» riscrive la regola come la leggerà chi la rivede; **Verifica sui contratti** controlla che operazioni e campi esistano (un'operazione o un campo sconosciuti rifiutano la regola, uno status mai visto dà solo un avviso); **Salva come bozza** la registra con origine «scritta a mano». Poi si rivede e si approva come una regola del miner (un amministratore può farlo da solo, resta nell'audit). **Modifica condizioni ed effetti** sulla pagina di una regola cambia anche le bozze del miner: le ricerche successive aggiornano solo i conteggi e tengono la tua versione; su una regola approvata nasce una nuova bozza che la sostituisce quando la approvi. **Ritirare una regola approvata**: sulla pagina di una regola approvata **Ritira regola** (ruolo Revisore regole, o amministratore) la toglie dai pacchetti: dal prossimo «Prepara e avvia il mock» il mock non ne applica più gli effetti; resta nell'elenco come «Ritirata» e il miner non la ripropone uguale. Quando approvi una regola che ne sostituisce un'altra, la vecchia esce dai pacchetti da sola e compare come «Ritirata» («sostituita da …»). Con un server meno recente restano approvate tutte e due: la pagina della vecchia lo dice (gli effetti si sommano) e propone di ritirarla. Se il server non offre ancora il ritiro, la console lo dice. L'editor delle regole si apre subito sull'elenco di contratti ed entità già letto (la pagina Regole lo legge in anticipo); se il server è lento mostra i secondi di attesa e dopo qualche secondo offre «Comincia con quello che c'è» (servizi, operazioni e status dei contratti; le entità compaiono da sole).

**Prova nel mock**: approva la regola, premi **Mock > Prepara e avvia il mock** (10.1); in una sessione chiama l'operazione della causa, fai avanzare l'orologio del ritardo (`POST /__tt/sessions/{s}/clock/advance`) e guarda il registro: per ogni risposta decisa da una regola compare `fault: { status, rule }`.

> **Passo 4 di 4 · Usa il mock** (sezione 10; 9 e 11 per i dettagli): menu *Mock*, «Prepara e avvia il mock»; mondi e pacchetti twin sono in *Avanzate*.

### 8.4 Allarmi, quarantena e buchi: cosa fa ogni azione

- **Allarmi** (menu *Allarmi*). Un allarme **incompatibile** dice che un client esistente può smettere di funzionare (esempio: il campo `eta` passa da testo a numero); uno **compatibile** è un'aggiunta che non lo tocca (esempio: compare un campo opzionale nuovo). **Prendi in carico**: dici che l'hai visto e ci stai lavorando; resta nell'elenco e non cambia né il contratto né il mock. **Risolvi**: lo chiudi, esce da «Da gestire» e resta nello storico; se il cambiamento si ripresenta nasce un nuovo allarme.
- **Quarantena** (*Avanzate > Quarantena*). Un campo con l'etichetta **troppi valori** (v1.19) era in chiaro come `keep` o come codice e ha mostrato più di 50 valori diversi: sembra un identificativo, i suoi valori ora escono come forme e la versione Osserva non lo propone più come codice; se è davvero un codice (per esempio un catalogo grande) lo scioglimento va approvato da due persone. Un elemento è qui perché in un punto che finora sembrava fisso (un campo conservato, un nome, un pezzo di percorso, una parte del nome di un host) il sistema ha visto troppi valori diversi: di solito è un **parametro**, per esempio un identificativo. Finché è qui i valori sono riscritti come `{*}`. Per ogni elemento: **È un parametro: raggruppa i valori** lo lascia nascosto per sempre (basta un approvatore); **È un nome fisso: tienilo** fa tornare i valori visibili e riparte il conteggio, quindi apre dati e servono due approvatori diversi (un amministratore decide da solo, con audit e un allarme).
- **Buchi** (menu *Buchi*). Non c'è nulla da chiudere: un buco dice dove il mock ha poche informazioni e sparisce da solo quando arriva più traffico. Accanto a ogni riga trovi «Cosa fare».

## 9. Mondo sintetico e pacchetto twin (Avanzate)

> Di solito non serve: **Mock > Prepara e avvia il mock** (10.1) fa tutti questi passi da solo. Questa sezione spiega cosa succede sotto, e serve per scaricare un pacchetto (CI senza console, export).

1. **Mondi > Genera**: seed (es. `42`) e numero di clienti (es. `50`). Il mondo applica le regole **approvate**. **Con il filtro Gruppo attivo il mondo usa solo i servizi e le regole di quel gruppo** (la pagina lo scrive sotto il pulsante): le regole di un altro team non entrano mai, e non trascinano nel tuo pacchetto servizi che non sono tuoi. Senza filtro (amministratore su "Tutti i gruppi") il mondo usa le regole approvate di tutti. Se mancano i profili di comportamento (archetipi) la pagina li costruisce da sola e mostra i passi che avanzano; non c'è nulla da fare prima. La generazione richiede 10-40 secondi e il mondo compare nell'elenco. Selezionandolo, l'**esploratore** sotto l'elenco ti fa sfogliare i clienti inventati (ricerca per id, nome o archetipo, pagine da 20) e, per ciascuno, i suoi ordini e le sue spedizioni con gli stati attraversati nel tempo.
2. **Pacchetti twin > Nuovo pacchetto**: la console propone il mondo **più recente**. Con il filtro Gruppo attivo, il pacchetto contiene di default solo i servizi di quel gruppo (casella "Solo i servizi del filtro gruppo"). **Avvia il gate**: il dialogo mostra l'avanzamento (di solito 10-30 secondi) e i 5 controlli (provenienza, prova al contrario, dati personali, soglie k, regole approvate). Al termine si chiude e apre il pacchetto. Il pacchetto del gruppo contiene solo i servizi e le regole del gruppo.
3. **Se una regola usa un servizio che non è nel pacchetto**, il gate non firma e il messaggio dice quale servizio e quali regole, con l'azione: "La regola r-0007 usa il servizio shipping-ext, che non è nel pacchetto. Includi il servizio shipping-ext (togli il filtro gruppo), oppure escludi la regola r-0007: genera di nuovo il mondo solo con i servizi del tuo gruppo". Di solito il mondo è stato generato senza filtro gruppo e contiene regole di un altro team: **Mondi > Genera** con il filtro del tuo gruppo, poi ricrea il pacchetto.
4. Se il mondo non corrisponde più a regole o contratti di oggi, il dialogo lo dice ("il mondo non corrisponde più") con il pulsante **Rigenera il mondo**.
5. Apri il pacchetto ("Firmato, da rilasciare") > **Rilascia ai test** (un publisher, oppure un amministratore con motivazione).
6. **Scarica il pacchetto** → `pk-AAAAMMGG-NNNN.ttpack` (un tar.gz con `contracts/*.openapi.json`, `rules.json`, `world.jsonl`, `faults.json`, `scenarios.json`, `manifest.json`, `manifest.sig.json`).

## 10. Usa il mock

Il mock è un server finto che risponde come i servizi veri, con dati inventati e con stato: crea gli oggetti, li fa cambiare nel tempo come hai visto in produzione, a volte sbaglia come sbagliavano i servizi veri. Nei test lo usi **al posto degli indirizzi veri**. Non vede mai dati di produzione: riceve solo dati sintetici controllati e firmati.

Ci sono tre modi di averlo, dal più semplice:

| Modo | Quando | Dove |
|---|---|---|
| **Dalla console, nel cluster** | la console gira in Kubernetes/OpenShift e il team piattaforma ha attivato i mock nel cluster | 10.1, esempio OpenShift in 10.2 |
| **Lanciato da te, collegato alla console** | la console non avvia container, oppure ti serve il mock vicino ai test (CI, un altro namespace, il tuo PC) | 10.3 |
| **Da file, senza console** | una CI che non raggiunge la console | 10.8 |

Nei primi due casi il mock **si aggiorna da solo**: quando prepari di nuovo i dati, passa ai nuovi entro pochi secondi, senza riavvii.

### 10.1 Il modo semplice: la pagina Mock

1. Apri **Mock** nel menu e scegli il **gruppo** (il tuo team): di solito è già scelto dal filtro Gruppo.
2. Premi **Prepara e avvia il mock**. La pagina mostra i passi, in chiaro:
   - **Profili dei clienti**: tipi di cliente ricavati dal traffico (mai copiati; se i clienti sono troppo pochi si usano clienti inventati);
   - **Dati sintetici**: clienti e oggetti inventati che si comportano come in produzione;
   - **Controlli e firma**: il gate controlla che non ci sia nessun dato reale e keyguard firma;
   - **Rilascio ai test**: serve il ruolo **Pubblicatore**; un amministratore lo fa da solo scrivendo una motivazione. Se non hai il ruolo, la preparazione si ferma qui e lo chiedi a chi ce l'ha;
   - **Avvio del mock**: se la console può, lo accende nel cluster; altrimenti i mock già collegati passano ai dati nuovi.
3. In **I tuoi mock** trovi lo stato (pronto, dati non aggiornati, non risponde) e, per ogni servizio, la riga da copiare: «sostituisci `https://api.payments.example` con `https://tt-mock-bookings…/__svc/payments-ext`». Metti quell'indirizzo nella configurazione dei test al posto di quello vero (per esempio `PAYMENTS_BASE_URL`).
4. Lancia i test e guarda **Ultime chiamate**: metodo, percorso, esito, scenario e guasto di ogni chiamata, in tempo reale. Una chiamata con esito 404 `no-operation` vuol dire che il test chiama qualcosa che il servizio vero non ha mai ricevuto.
5. In **Sessione e scenari** prepari la situazione da provare senza scrivere codice: crea una sessione per il test, applica uno scenario (per esempio «Pagamenti non disponibili»), spegni i guasti per un test ripetibile, fai avanzare l'**orologio virtuale** di 15 minuti per vedere il rimborso arrivare. Il test sceglie la sessione con l'header `X-TT-Session` (senza header usa la sessione `default`).
6. Quando i dati cambiano (nuovi servizi, nuove regole) premi di nuovo **Prepara e avvia il mock**.

I pacchetti twin restano in **Avanzate > Pacchetti twin**: ti servono solo per scaricare un pacchetto in una CI senza console (10.8) o per gli export (11).

### 10.2 Mock nel cluster: esempio OpenShift

Il team piattaforma attiva i mock nel cluster installando tt-core con `mockManager.enabled=true` (vedi [deploy/README.md](../deploy/README.md)): la console ottiene un permesso **solo** nel namespace dei mock (per esempio `bookings-test`) e solo su Secret, Service, Deployment e Route.

Da quel momento, per il team `bookings`:

1. **Mock > Prepara e avvia il mock**, gruppo `bookings`. Alla fine la pagina dice «Fatto. Il mock risponde a https://tt-mock-bookings-bookings-test.apps.ocp.example».
2. Nel namespace compaiono (li vedi, non li devi toccare):

   ```sh
   oc -n bookings-test get deploy,svc,route,secret -l app.kubernetes.io/managed-by=tt-core
   # deployment/tt-mock-bookings  service/tt-mock-bookings  route/tt-mock-bookings  secret/tt-mock-bookings
   ```

3. I test che girano **nel cluster** usano l'indirizzo interno `http://tt-mock-bookings.bookings-test.svc.cluster.local:8480/__svc/<servizio>`; quelli **fuori** usano la Route `https://…apps.ocp.example/__svc/<servizio>`. Tutti e due sono nella pagina Mock, con il pulsante Copia.
4. **Riavvia** riparte da capo (sessioni vuote); **Ferma** cancella gli oggetti dal namespace e revoca il token del mock.
5. Se i test creano da soli le sessioni con l'API di controllo (10.4), il token di controllo è nel Secret:
   `oc -n bookings-test get secret tt-mock-bookings -o jsonpath='{.data.control-token}' | base64 -d`.

Se la preparazione si ferma su «Avvio del mock» con «Il cluster ha rifiutato», al service account di tt-core manca il Role nel namespace: è una correzione del team piattaforma.

### 10.3 Il mock lanciato da te (container o Helm)

Quando la console non avvia container, o ti serve il mock dove girano i test:

1. **Mock > Avvia il mock tu > Crea un token per <gruppo>**. Il token (`ttm_…`) si vede **una volta sola**: copialo subito. Può solo scaricare i dati di quel gruppo e mandare lo stato del mock alla console: non apre nient'altro della console. Scade dopo 180 giorni e lo revochi dalla stessa pagina.
2. Scegli la scheda con il comando, già compilato con token, gruppo, indirizzo della console e chiavi pubbliche del gate:

   **Docker** (sul tuo PC o in un job CI):

   ```sh
   docker run --rm -p 8480:8480 \
     -v "$PWD/console-ca.pem:/etc/tt/console-ca.pem:ro" \
     -e TT_MOCK_TOKEN='ttm_…' \
     -e TT_GATE_PUBKEYS='gate-2026-1:Xz9k…' \
     ghcr.io/ivseb/traffic-twin:<versione della console> mock --console https://tt.example.internal --group bookings \
     --console-ca /etc/tt/console-ca.pem \
     --addr 0.0.0.0:8480 --public-url http://localhost:8480
   ```

   **tt (kit)**, senza container: il binario `tt` del kit, **della stessa versione della console** (la scheda la scrive; controlla con `tt version`):

   ```sh
   export TT_MOCK_TOKEN='ttm_…'
   export TT_GATE_PUBKEYS='gate-2026-1:Xz9k…'
   tt mock --console https://tt.example.internal --group bookings \
     --console-ca ./console-ca.pem \
     --addr 127.0.0.1:8480
   ```

   `console-ca.pem` è la CA del certificato della console (quella aziendale: chiedila al team piattaforma); con un certificato di una CA pubblica togli `--console-ca`. Il mock scarica il pacchetto rilasciato del gruppo, risponde su `http://127.0.0.1:8480/__svc/<servizio>` e passa da solo ai dati nuovi a ogni rilascio. `tt mock -h` elenca tutte le opzioni.

   Il comando **Docker** contiene già il montaggio della CA (`-v "$PWD/console-ca.pem:/etc/tt/console-ca.pem:ro"` e `--console-ca /etc/tt/console-ca.pem`) e usa l'immagine della stessa versione della console.

   Il token ha due nomi: `ttm_…` è il **segreto** (va in `TT_MOCK_TOKEN`, si vede una volta sola), `mtk-…` è solo il suo **identificativo**, quello che vedi nell'elenco dei token e usi per revocarlo.

   **Helm** (Kubernetes) e **OpenShift**: il file `values-mock.yaml` e i comandi, per esempio su OpenShift

   ```sh
   oc project bookings-ci
   oc create secret generic tt-mock-token --from-literal=token='ttm_…'
   helm install tt-mock deploy/helm/tt-mock -f values-mock.yaml --set route.enabled=true
   oc get route tt-mock -o jsonpath='{.spec.host}'
   ```

   con `values-mock.yaml`:

   ```yaml
   console:
     url: https://tt.example.internal
     group: bookings
     tokenSecret: tt-mock-token
   gatePubKeys: "gate-2026-1:Xz9k…"
   route:
     enabled: true
     host: tt-mock-bookings-ci.apps.ocp.example   # così la pagina Mock mostra l'indirizzo giusto
   ```

3. Entro pochi secondi il mock compare in **I tuoi mock** come «installato da te», con gli indirizzi da usare. Da lì funziona come in 10.1: chiamate in tempo reale, sessioni, scenari, orologio, aggiornamento automatico a ogni rilascio.

Il mock verifica ogni pacchetto con le chiavi pubbliche del gate (`TT_GATE_PUBKEYS`) esattamente come un file: un pacchetto non firmato, firmato da un'altra chiave o **di un altro gruppo** viene rifiutato, e la pagina Mock lo dice («Il mock ha rifiutato i dati nuovi…») mentre il mock continua con i dati di prima. Se la console usa un certificato di una CA interna, passa al mock la CA (`--console-ca`, nel chart `console.caConfigMap`). Se i test usano l'API di controllo (10.4) direttamente, dai al mock anche un `TT_CONTROL_TOKEN` (nel chart `controlToken.existingSecret`); senza, l'API di controllo la comanda solo la console.

### 10.4 L'API di controllo del mock, l'essenziale

Tutto sotto `/__tt/`, con `Authorization: Bearer $TT_CONTROL_TOKEN` (solo `GET /__tt/health` è pubblico; su loopback senza token le chiamate sono accettate). Il corpo è JSON; le richieste con campi sconosciuti sono rifiutate (`400 bad_request`). L'elenco completo è in `api/control-api.v1.openapi.yaml`.

| Cosa | Chiamata |
|---|---|
| Pacchetto, clienti, preset | `GET /__tt/pack` (servizi e operazioni), `GET /__tt/customers`, `GET /__tt/scenarios` (preset del pacchetto) |
| **Sessioni** | `POST /__tt/sessions` con `{"id":"test-1","seed":42,"customer":"CUS-SYN-0007","faults":{"mode":"off"},"scenario":"<preset>"}` (tutto facoltativo) → `201` con `id`, `now`; `POST /__tt/sessions/{id}/reset`; `DELETE /__tt/sessions/{id}` (la sessione `default` si può solo azzerare) |
| Chi sei | `POST /__tt/sessions/{id}/customer` con `{"customer":"CUS-SYN-0007"}` o `{"archetype":"arch-03"}`: le entità create da ora in poi sono di quel cliente |
| **Orologio** | `GET /__tt/sessions/{id}/clock`; `POST /__tt/sessions/{id}/clock/advance` con `{"by":"15m"}` (durata `Ns`, `Nm`, `Nh`, `Nd`) oppure `{"to":"2026-10-25T09:00:00Z"}`. Applica in ordine tutti gli effetti scaduti e risponde `{"now": ..., "applied": [...]}`. L'orologio non torna indietro |
| **Scenari** | `POST /__tt/sessions/{id}/scenario` con `{"rule":"r-0003","outcome":"declined","times":1}` forza l'esito delle prossime N volte che la regola scatta; con `{"preset":"payment-declined"}` azzera la sessione e applica il preset. Gli id delle regole e i nomi degli esiti sono quelli del tuo pacchetto: li vedi in `GET /__tt/pack` e `GET /__tt/scenarios` |
| **Guasti** | `PUT /__tt/sessions/{id}/faults` con `{"mode":"custom","rules":[{"service":"payments-ext","op":"POST /v1/charges","status":503,"p":1.0,"times":1}]}` (oppure `"net_error":"timeout"`, `"latency_ms":800`); `"mode":"observed"` usa le frequenze del pacchetto, `"mode":"off"` non inietta niente |
| **Giornale** | `GET /__tt/sessions/{id}/journal` (una riga JSON per chiamata ricevuta; `?since=<seq>` per leggere solo le nuove, `?format=har` per un HAR); `GET .../journal/unmatched` le chiamate che non corrispondono al contratto, con l'operazione più vicina e il motivo. `GET .../entities?entity=charge` lo stato delle entità, per capire un test che fallisce |

Il servizio sotto test chiama `http://127.0.0.1:8480/__svc/<servizio>/...`; la sessione si sceglie con l'header `X-TT-Session` (senza header vale la sessione `default`). Se il tuo servizio non sa inoltrare l'header, usa la sessione `default` e azzerala prima di ogni test (`POST /__tt/sessions/default/reset`).

### 10.5 Un test completo in Python (pytest)

`conftest.py` avvia `tt mock` una volta e dà a ogni test una sessione sua; i test provano il pagamento riuscito, il 402, il 503 una volta sola e il rimborso dopo 15 minuti (virtuali). Status, campi, id delle regole e nomi degli esiti sono quelli dell'esempio (`payments-ext`): nel tuo caso sono quelli del tuo pacchetto (`GET /__tt/pack`).

```python
# conftest.py
import os, subprocess, time, uuid
import pytest, requests

MOCK = "http://127.0.0.1:8480"
TOKEN = os.environ.setdefault("TT_CONTROL_TOKEN", uuid.uuid4().hex)
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture(scope="session")
def mock_server():
    # TT_GATE_PUBKEYS=./gate-keys.txt (dalla console: Pacchetti twin > Come usarlo nei test)
    p = subprocess.Popen(["tt", "mock", "--pack", "twin.ttpack", "--addr", "127.0.0.1:8480", "--latency", "off"])
    for _ in range(100):
        try:
            if requests.get(MOCK + "/__tt/health", timeout=0.2).ok:
                break
        except requests.ConnectionError:
            time.sleep(0.1)
    else:
        p.kill()
        raise RuntimeError("tt mock non parte")
    yield
    p.terminate()


class Mock:
    def __init__(self):
        self.id = "t-" + uuid.uuid4().hex[:8]

    def _ctl(self, method, path, **kw):
        r = requests.request(method, f"{MOCK}/__tt/sessions/{self.id}{path}", headers=AUTH, timeout=5, **kw)
        r.raise_for_status()
        return r

    def start(self):
        requests.post(MOCK + "/__tt/sessions", headers=AUTH, json={"id": self.id, "faults": {"mode": "off"}}, timeout=5).raise_for_status()

    def url(self, service):                     # la base URL da dare al servizio sotto test
        return f"{MOCK}/__svc/{service}"

    @property
    def headers(self):                          # da mandare a ogni chiamata del test
        return {"X-TT-Session": self.id}

    def advance(self, by):
        return self._ctl("POST", "/clock/advance", json={"by": by}).json()

    def force(self, rule, outcome, times=1):
        self._ctl("POST", "/scenario", json={"rule": rule, "outcome": outcome, "times": times})

    def fail(self, service, op, status, times=1):
        self._ctl("PUT", "/faults", json={"mode": "custom", "rules": [{"service": service, "op": op, "status": status, "p": 1.0, "times": times}]})

    def journal(self):
        return [__import__("json").loads(l) for l in self._ctl("GET", "/journal").text.splitlines() if l]

    def stop(self):
        requests.delete(f"{MOCK}/__tt/sessions/{self.id}", headers=AUTH, timeout=5)


@pytest.fixture
def mock(mock_server):
    m = Mock()
    m.start()
    yield m
    m.stop()
```

```python
# test_payments.py — il codice sotto test è il tuo client dei pagamenti (qui un esempio minimo)
import requests


class PaymentsClient:
    def __init__(self, base_url, headers=None):
        self.base, self.headers = base_url, headers or {}

    def charge(self, amount, currency="eur"):
        return requests.post(self.base + "/v1/charges", json={"amount": amount, "currency": currency}, headers=self.headers, timeout=5)

    def get(self, charge_id):
        return requests.get(f"{self.base}/v1/charges/{charge_id}", headers=self.headers, timeout=5)


def test_charge_ok(mock):
    pay = PaymentsClient(mock.url("payments-ext"), mock.headers)
    r = pay.charge(12000)
    assert r.status_code == 201
    assert r.json()["status"] == "succeeded"


def test_declined(mock):
    mock.force("r-0003", "declined")                 # id regola ed esito: vedi GET /__tt/pack
    assert PaymentsClient(mock.url("payments-ext"), mock.headers).charge(12000).status_code == 402


def test_provider_down_once_then_ok(mock):
    mock.fail("payments-ext", "POST /v1/charges", 503, times=1)
    pay = PaymentsClient(mock.url("payments-ext"), mock.headers)
    assert pay.charge(500).status_code == 503        # la prima volta il servizio non risponde
    assert pay.charge(500).status_code == 201        # poi torna normale (times=1)


def test_refund_shows_up_after_15_minutes(mock):
    pay = PaymentsClient(mock.url("payments-ext"), mock.headers)
    charge_id = pay.charge(12000).json()["id"]
    assert pay.get(charge_id).json()["refunded"] is False
    mock.advance("15m")                              # tempo virtuale: il test non aspetta
    assert pay.get(charge_id).json()["refunded"] is True
    assert any(e["path"].endswith("/v1/charges") for e in mock.journal())
```

Esegui con `TT_GATE_PUBKEYS=./gate-keys.txt pytest`. Il servizio vero lo avvii come al solito con `PAYMENTS_BASE_URL=http://127.0.0.1:8480/__svc/payments-ext` e, se sa inoltrare l'header, `X-TT-Session` per test.

### 10.6 Lo stesso test in Node.js (`node:test`, Node ≥ 20)

```js
// payments.test.mjs
import { test, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const MOCK = 'http://127.0.0.1:8480';
const TOKEN = process.env.TT_CONTROL_TOKEN ?? randomBytes(12).toString('hex');
const AUTH = { Authorization: `Bearer ${TOKEN}` };
let server, id;

before(async () => {
  // TT_GATE_PUBKEYS=./gate-keys.txt (dalla console: Pacchetti twin > Come usarlo nei test)
  server = spawn('tt', ['mock', '--pack', 'twin.ttpack', '--addr', '127.0.0.1:8480', '--latency', 'off'], { env: { ...process.env, TT_CONTROL_TOKEN: TOKEN }, stdio: 'inherit' });
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${MOCK}/__tt/health`)).ok) return; } catch { /* non ancora */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('tt mock non parte');
});
after(() => server.kill());

const ctl = (method, path, body) =>
  fetch(`${MOCK}/__tt/sessions/${id}${path}`, { method, headers: { ...AUTH, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
beforeEach(async () => {
  id = 't-' + randomBytes(4).toString('hex');
  await fetch(`${MOCK}/__tt/sessions`, { method: 'POST', headers: { ...AUTH, 'Content-Type': 'application/json' }, body: JSON.stringify({ id, faults: { mode: 'off' } }) });
});
afterEach(() => fetch(`${MOCK}/__tt/sessions/${id}`, { method: 'DELETE', headers: AUTH }));

// il tuo client dei pagamenti: base URL e header di sessione si passano da fuori
const pay = { base: () => `${MOCK}/__svc/payments-ext`, headers: () => ({ 'X-TT-Session': id, 'Content-Type': 'application/json' }) };
const charge = (amount) => fetch(`${pay.base()}/v1/charges`, { method: 'POST', headers: pay.headers(), body: JSON.stringify({ amount, currency: 'eur' }) });

test('pagamento riuscito', async () => {
  const r = await charge(12000);
  assert.equal(r.status, 201);
});

test('carta rifiutata (402)', async () => {
  await ctl('POST', '/scenario', { rule: 'r-0003', outcome: 'declined' }); // id regola ed esito: GET /__tt/pack
  assert.equal((await charge(12000)).status, 402);
});

test('il fornitore non risponde una volta (503), poi torna', async () => {
  await ctl('PUT', '/faults', { mode: 'custom', rules: [{ service: 'payments-ext', op: 'POST /v1/charges', status: 503, p: 1, times: 1 }] });
  assert.equal((await charge(500)).status, 503);
  assert.equal((await charge(500)).status, 201);
});

test('il rimborso compare dopo 15 minuti virtuali', async () => {
  const { id: chargeId } = await (await charge(12000)).json();
  const get = async () => (await fetch(`${pay.base()}/v1/charges/${chargeId}`, { headers: pay.headers() })).json();
  assert.equal((await get()).refunded, false);
  const adv = await (await ctl('POST', '/clock/advance', { by: '15m' })).json();
  assert.ok(adv.applied.length > 0);
  assert.equal((await get()).refunded, true);
});
```

Esegui con `TT_GATE_PUBKEYS=./gate-keys.txt node --test`.

### 10.7 Se il mock rifiuta il pacchetto

Il messaggio dice dove trovare le chiavi:

| Messaggio | Causa |
|---|---|
| `no trusted keys configured (TT_GATE_PUBKEYS is empty)` | manca `TT_GATE_PUBKEYS`: copialo da Pacchetti twin > Come usarlo nei test |
| `pack signature is invalid` / `signed by an unknown key` | chiave sbagliata (spesso quella delle policy) o non aggiornata dopo una rotazione: scarica di nuovo gate-keys.txt |
| `key file ... is writable by group or others` | `chmod 644 gate-keys.txt` |
| `pack ... belongs to group X, not Y: refused` (pagina Mock: «Il mock ha rifiutato i dati nuovi») | il mock è avviato con `--group` di un altro team, oppure i dati sono stati preparati per tutti i gruppi: prepara il mock dal tuo gruppo |
| `the console refused the mock token` (il mock si ferma) | token revocato, scaduto o copiato male: creane uno nuovo nella pagina Mock |
| il mock non compare nella pagina Mock | il mock non raggiunge la console: indirizzo (`--console`), rete o certificato (`--console-ca`); il log del mock dice quale |

### 10.8 In CI senza console: il mock da file

Il mock legge un pacchetto scaricato (Avanzate > Pacchetti twin) invece di chiederlo alla console. `tt mock` verifica la firma del pacchetto con le **chiavi pubbliche del gate** (non con la chiave delle policy). Le trovi in **Pacchetti twin > Come usarlo nei test**: c'è il comando pronto con il valore di `TT_GATE_PUBKEYS` (pulsante Copia) e il file **gate-keys.txt** da scaricare. Sono chiavi pubbliche: non sono segreti.

```sh
export TT_GATE_PUBKEYS=./gate-keys.txt        # o il valore 'pack-1:...' copiato dalla console
export TT_CONTROL_TOKEN="$(openssl rand -hex 24)"
tt mock --pack pk-20261024-0012.ttpack --addr 127.0.0.1:8480 --latency record &
AUTH="Authorization: Bearer $TT_CONTROL_TOKEN"
curl -s localhost:8480/__tt/health                                  # pubblico
curl -s -H "$AUTH" localhost:8480/__tt/pack | head                  # servizi e operazioni del pacchetto
SID=$(curl -s -H "$AUTH" -X POST localhost:8480/__tt/sessions -d '{}' | jq -r .id)
curl -s -H "X-TT-Session: $SID" -X POST localhost:8480/__svc/payments-ext/v1/charges -d '{"amount":12000,"currency":"eur"}'
```

- **Stato per sessione**: ogni test usa la sua (`X-TT-Session`); quello che scrive un test non si vede negli altri.
- **Orologio virtuale**: si sposta con l'API di controllo (sotto), così "charge creata → rimborsata" si prova in millisecondi. Guasti e latenze seguono le frequenze osservate (`--faults observed|off`, `--latency real|record|off`): con `observed` ogni operazione risponde con gli errori 5xx, 408, 429 e i rifiuti del servizio esterno (402, 409 come «libro non disponibile», 423-425) alla frequenza vista nel traffico, se ce ne sono almeno k = 20, con il corpo d'esempio del contratto, e la sequenza dipende dal seed della sessione; 400/401/403/404/422 no, li decidono richiesta e stato. Per guasti decisi da te vedi 10.9. Preset di guasti ed esiti forzati: pagina **Mock**, scheda «Scenari salvati».
- **Le stesse parole in console, nell'aiuto di `tt mock -h` e nell'API**: scenari (*scenarios*), guasti (*faults*), orologio (*clock*), sessioni (*sessions*); il pacchetto si chiama "Pacchetti twin" (*Twin packs*) e le chiavi del gate sono in "Come usarlo nei test" (*Use it in tests*). `tt mock -h` stampa un esempio completo.
- **Punta il servizio al mock** con le sue variabili di base URL, per esempio `PAYMENTS_BASE_URL=http://127.0.0.1:8480/__svc/payments-ext WEATHER_BASE_URL=http://127.0.0.1:8480/__svc/weather-ext node server.js`.

In una pipeline:

1. Salva `gate-keys.txt` nel repository dei test (è pubblico) o in una variabile della pipeline; dopo una rotazione delle chiavi del gate scaricalo di nuovo.
2. Scarica il pacchetto rilasciato (dalla console, o con l'API `GET /api/v1/packs/{id}/download` e un account di servizio con ruolo publisher) e mettilo tra gli artefatti della pipeline.
3. Nel job:

```sh
export TT_GATE_PUBKEYS=./gate-keys.txt
export TT_CONTROL_TOKEN="$(openssl rand -hex 24)"
tt mock --pack ./twin.ttpack --addr 127.0.0.1:8480 &
until curl -sf localhost:8480/__tt/health >/dev/null; do sleep 0.2; done
PAYMENTS_BASE_URL=http://127.0.0.1:8480/__svc/payments-ext npm test
```

### 10.9 Guasti: le opzioni, con un esempio

I guasti si decidono **per sessione**, con `PUT /__tt/sessions/{id}/faults` (o `"faults"` nel corpo di `POST /__tt/sessions`). Tre modalità (`mode`):

| `mode` | Cosa fa |
|---|---|
| `observed` | usa le frequenze del pacchetto (`faults.json`: status, errori di rete e latenze visti nel traffico). È il default di `--faults` |
| `off` | non inietta niente |
| `custom` | applica le tue regole (`rules`, fino a 256) in ordine: decide la prima regola con `status` o `net_error` che scatta; i ritardi (`latency_ms`) delle regole scattate si sommano |

Ogni regola `custom` ha questi campi (almeno uno tra `status`, `net_error`, `latency_ms`):

| Campo | Significato |
|---|---|
| `service` | nome del servizio come in `GET /__tt/pack` (es. `library-catalog`), oppure `*` per tutti |
| `op` | operazione esattamente come nel contratto (`POST /v1/loans/{id}/renew`), oppure `*` |
| `p` | probabilità da 0 a 1 (`1.0` = sempre, `0.05` = una volta su venti); la sequenza è deterministica con il seed della sessione |
| `status` | status HTTP da restituire (100-599), per esempio `409` o `503` |
| `net_error` | al posto dello status: `timeout`, `reset`, `refused`, `dns`, `tls`, `other` (si escludono a vicenda con `status`) |
| `latency_ms` | ritardo aggiunto in millisecondi (0-60000); si può usare da solo o insieme a `status` |
| `times` | quante volte al massimo scatta (≥ 1): `1` = "una volta sola, poi torna normale" |

Le opzioni del processo sono `--faults observed|off` (modalità delle sessioni nuove), `--latency real|record|off` (`real` aspetta davvero, `record` scrive solo il ritardo nel giornale: test veloci, `off` niente) e `--net-timeout` (quanto resta appesa una connessione in `timeout`). Una regola `custom` non si imposta da riga di comando: sempre per sessione.

Esempio (servizio `library-catalog` con `GET /books/{id}`): il libro risulta non disponibile (409) la prima volta, poi il catalogo risponde 503 una volta su cinque con 800 ms di ritardo, e le notifiche vanno in timeout per tutte le chiamate:

```sh
curl -s -H "$AUTH" -X PUT localhost:8480/__tt/sessions/t1/faults -d '{
  "mode": "custom",
  "rules": [
    {"service": "library-catalog", "op": "GET /books/{id}", "status": 409, "p": 1.0, "times": 1},
    {"service": "library-catalog", "op": "GET /books/{id}", "status": 503, "p": 0.2, "latency_ms": 800},
    {"service": "library-notifications", "op": "*", "net_error": "timeout", "p": 1.0}
  ]
}'
curl -s -H "$AUTH" localhost:8480/__tt/sessions/t1/faults        # leggi com'è impostato
curl -s -H "$AUTH" -X PUT localhost:8480/__tt/sessions/t1/faults -d '{"mode":"off"}'   # torna alla normalità
```

Se un nome di servizio o un'operazione non esistono nel pacchetto la risposta è `400` con il puntatore al campo (`/rules/0/op`): copia i nomi da `GET /__tt/pack`. Nel giornale (`GET .../journal`) ogni chiamata dice quale guasto è scattato.

### 10.10 Una sessione per utente (senza `X-TT-Session`)

L'applicazione vera non manda `X-TT-Session`: senza altro tutti i tester finiscono nella sessione `default` e vedono lo **stesso** cliente sintetico e lo stesso stato. Con la **sessione per utente** il mock legge l'identità di chi chiama da un header a tua scelta e dà a ogni utente di test la sua sessione e il suo cliente sintetico, sempre gli stessi.

- **Dalla console**: pagina Mock, scheda del gruppo, **Sessione per utente**. Scrivi il nome dell'header che porta l'utente (quello che usa la tua applicazione, per esempio `x-user-id`); se l'header porta un JWT (per esempio `authorization`), scrivi anche il **claim** che identifica l'utente (per esempio `sub`; la firma non si verifica: il mock non autentica). L'impostazione arriva in pochi secondi a tutti i mock del gruppo collegati alla console, senza riavvio.
- **Con `tt mock --pack`**: `--identity-header <header>` e, per un JWT, `--identity-claim <claim>`; la chiave in `TT_MOCK_IDENTITY_KEY` (almeno 32 caratteri, per esempio `openssl rand -hex 32`) tiene la scelta uguale tra un riavvio e l'altro.
- **Utenti con un cliente preciso**: nella console aggiungi «utente di test → cliente» (per esempio `CUS-SYN-0007`, gli id sono nella pagina del mondo); con `tt mock` usa `--identity-map utenti.json` con `{"tester1": "CUS-SYN-0007"}`.
- Ogni risposta del mock ha l'header `X-TT-Session` con la sessione usata (`u-` seguito da 16 cifre esadecimali): con quell'id puoi usare l'API di controllo (orologio, guasti, reset) per quell'utente. Se una richiesta manda `X-TT-Session`, vince quella.
- **Riservatezza**: il valore dell'utente non si conserva e non si mostra da nessuna parte (giornale, log, console): solo un hash con chiave. La console conserva degli utenti mappati solo l'hash, e mostra un'impronta.

### 10.11 Documenti, date, calcoli, errori, S3 e pagine di terzi (v1.20)

Per far girare contro il mock un'applicazione vera, da capo a fondo:

- **Documenti.** Se il contratto dice che una risposta è un PDF, un'immagine o un archivio (o che un campo JSON contiene un documento in base64), il mock restituisce un file **valido** di quel tipo, con un testo sintetico (cliente del mondo, id, data). Niente da configurare.
- **Date relative.** Contratti → servizio → «Date relative»: per ogni campo data vedi lo scarto appreso dal traffico (per esempio «tra 30 e 365 giorni») e puoi sceglierne uno tu. Il mock calcola la data dall'orologio della sessione: un rinnovo resta «tra un anno» qualunque giorno giri il test. Vale dal prossimo «Prepara il mock».
- **Valori calcolati.** Regole → editor: un valore di un effetto può essere «calcolato» (somma degli importi, residuo = limite − importo, scadenza = oggi + 30 giorni, numero di documento con un formato degli id), con anteprima su un esempio.
- **Corpi d'errore.** Un effetto «risponde con» e un guasto possono avere un corpo d'errore scritto da te (codice e messaggio come quelli veri); il gate controlla che non contenga dati personali.
- **S3.** `tt mock … --s3 --s3-buckets documenti` serve un'API compatibile S3 su `http://<mock>/__s3` (o su un host dedicato con `--s3-host`, anche in stile «virtual host» `documenti.s3.mock.test`): l'SDK dell'applicazione carica e scarica oggetti nella sessione (anche in più parti), li elenca e li cancella. Gli oggetti stanno in memoria, per sessione e con limiti di dimensione; nel registro compaiono le chiamate senza i dati. **La firma SigV4 non si controlla**: qualsiasi chiave va bene, è un mock di test e non va mai esposto come archivio vero.
- **Pagine di terzi.** Mock → «Pagine di terzi»: una pagina finta di pagamento o di firma con i suoi pulsanti (Approva, Rifiuta, Annulla), l'URL di ritorno all'applicazione e la richiamata server a server (con firma HMAC se serve). Nei test senza browser: `POST /__tt/sessions/{id}/pages/{pagina}/complete` con `{"action": "approve"}`.
  - **L'esito resta nell'oggetto.** Nei «Collegamenti» indica l'operazione che crea il pagamento (o la firma), il campo con il suo id e, se è un'entità delle regole, il suo nome; su ogni pulsante scrivi i campi da cambiare (`status={value.code}`). Dopo il clic le letture dell'applicazione vedono il pagamento `AUTHORISED` o `REFUSED`.
  - **URL di ritorno scelto dall'applicazione.** Se la richiesta di creazione manda il suo `returnUrl`, indica dove (per esempio `req.body` `$.returnUrl`) e scrivi `{link.return}` come URL di ritorno; il suo host va tra gli host ammessi (niente redirect aperti).

I dettagli sono nelle specifiche: [mock.md](spec/mock.md) §2.9, §2.10, §4.1, §8, §9, [rules.md](spec/rules.md) §3.15, [pack.md](spec/pack.md) §4.4.

### 10.12 Servizi SOAP e XML (v1.21)

Se l'applicazione chiama un servizio SOAP (un `.asmx`, un servizio WCF o JAX-WS) o un endpoint che parla XML, il mock risponde in XML, senza configurare nulla:

- **Stesso indirizzo, molte operazioni.** Mandi la busta SOAP all'indirizzo di sempre (`…/__svc/<servizio>/ws/orders.asmx`); il mock sceglie l'operazione dall'header `SOAPAction`, dal parametro `action` del `Content-Type` (SOAP 1.2) oppure dal primo elemento del `Body`. Nel registro la chiamata ha l'operazione logica (`POST /ws/orders.asmx#GetOrder`).
- **Risposta con la stessa busta.** SOAP 1.1 o 1.2 come quella osservata, con gli spazi dei nomi osservati (`<GetOrderResponse xmlns="http://…">`), gli attributi, gli elementi ripetuti e i valori sintetici: entità, regole, sessioni, formati degli id e date relative funzionano come per il JSON. Un ordine creato con `CreateOrder` si rilegge con `GetOrder` e ha le righe che hai mandato.
- **Regole sugli elementi.** Nelle regole (e nell'editor) i percorsi dei corpi XML sono gli stessi dei contratti: `$.Envelope.Body.GetOrder.orderId`, un attributo con `.@nome`, il testo con `.#text`.
- **Fault.** Un guasto (osservato, di uno scenario o forzato dalla pagina Mock / dall'API di controllo) esce come SOAP Fault con lo status del guasto (di solito 500): il fault osservato, oppure `soap:Client`/`soap:Server` (`env:Sender`/`env:Receiver` in SOAP 1.2) con il testo dello status. Un corpo d'errore scritto da te può essere XML (servito così com'è), un testo (diventa il `faultstring`) o un oggetto (diventa il `detail`). Un'operazione mai vista risponde con un fault `operation not observed: <nome>`.
- **Sicurezza.** Il mock legge l'XML con lo stesso analizzatore chiuso delle sorgenti: niente DTD né entità (nessun XXE, nessuna «billion laughs»), al più 256 livelli. Un corpo così risponde con un fault del mittente, senza ripeterne il contenuto.
- **Limiti.** L'ordine tra elementi di nome diverso non si osserva: escono in ordine di nome (tranne l'ordine che SOAP impone). Il mock non serve un WSDL e non simula WS-Security, WS-Addressing né MTOM; gli export verso WireMock, Microcks e Prism non scelgono l'operazione SOAP.

I dettagli sono in [mock.md](spec/mock.md) §10.

### 10.13 Preparare l'applicazione: indirizzi che non si possono cambiare e cache

**Servizi il cui indirizzo non si può configurare.** Alcune applicazioni costruiscono da sole
l'indirizzo di un servizio interno (per esempio `http://<servizio>.<namespace>.svc.cluster.local:8080`) e
non offrono una variabile per cambiarlo. Il mock instrada anche per **header `Host`**: una richiesta
che arriva con `Host: <servizio>.<namespace>.svc.cluster.local` va al servizio simulato con quel nome
di host, senza `/__svc/` nel percorso (se nessun servizio corrisponde: 404 con
`X-TT-Unmatched: no-service`). Nel namespace di test basta quindi far risolvere quel nome verso il
mock, senza toccare il codice:

- in Kubernetes/OpenShift, un `Service` con lo stesso nome nel namespace di test che seleziona i pod
  del mock (o di tipo `ExternalName` verso il Service del mock), sulla stessa porta;
- fuori da Kubernetes, una voce in `/etc/hosts` (o nel DNS di test) verso l'indirizzo del mock.

Lo schema resta quello dell'applicazione: `tt mock` serve HTTP in chiaro, quindi se l'applicazione
chiama in `https` metti davanti al mock una terminazione TLS (una Route edge in OpenShift, un Ingress
o un proxy come nginx); un'applicazione che verifica il certificato deve fidarsi della CA che lo firma.

**Cache dell'applicazione.** Il mock è sempre coerente: dopo una scrittura la lettura successiva vede
già il nuovo stato. Se l'applicazione sotto test tiene in cache le risposte dei servizi (cache HTTP,
DataLoader, Redis, cache del client Apollo), può mostrare dati vecchi dopo una scrittura e far
sembrare che il mock non abbia applicato una regola. In test:

- disattiva le cache delle risposte esterne dell'applicazione (di solito c'è una variabile apposta),
  oppure accorcia i TTL sotto il secondo;
- se una cache non si può spegnere, avanza l'orologio del mock **e** aspetta la scadenza della cache
  prima di rileggere, oppure leggi con un header che la salta, se l'applicazione lo prevede;
- uno store interno dell'applicazione che non è HTTP (Redis, un database) **non** passa dal mock: in
  test usane uno vuoto o dedicato, perché lo stato che vi salva l'applicazione non si azzera con le
  sessioni del mock.

Lo stesso vale per il traffico reale osservato: le letture servite dalla cache dell'applicazione
non arrivano ai servizi, quindi non diventano eventi; il miner ne tiene conto (gli effetti visti in
ritardo diventano un `after` figurativo).

## 11. Export verso WireMock / Microcks / Prism

Sulla pagina del pacchetto, **Esporta per WireMock** (o Microcks, Prism) apre un dialogo "Cosa produce / Cosa passa": file e mapping generati, cosa viene convertito e cosa no (per esempio lo stato tra chiamate, che solo `tt mock` conserva). **Scarica lo zip** con `wiremock/<servizio>/mappings/<servizio>.json` ed `export-report.json`. L'export non richiede le chiavi del gate.

## 12. Problemi comuni

| Sintomo | Causa / cosa fare |
|---|---|
| `npm install @traffic-twin/sdk` fallisce | il pacchetto non è nel tuo registro: `npm install ./traffic-twin-sdk-x.y.z.tgz` dal kit |
| L'SDK scrive `key_missing: ...` | manca `TT_HMAC_KEY_FILE` o il file non si legge o è malformato: chiedi il file al team piattaforma (sezione 4) |
| La sorgente è "In attesa di policy" | il gruppo non ha ancora una policy approvata: approva la bozza in Sorgenti > Policy |
| Sulla sorgente "chiave HMAC sconosciuta a keyguard" | la chiave non è quella dell'installazione (spesso generata in locale): sostituiscila con il file del team piattaforma |
| `error heartbeat_network` nel log dell'SDK | intake momentaneamente non raggiungibile; l'SDK riprova da solo e l'app funziona comunque |
| Con `TT_DEBUG=1`: `info policy_superseded` seguito da `info policy_changed` | è attiva una nuova versione della policy: l'SDK la scarica subito (la cattura si ferma per un istante, stato `starting`) e riparte da solo. Non serve fare nulla |
| `error policy_network` nel log dell'SDK | `tt-core` non era raggiungibile per un momento (per esempio durante un suo aggiornamento): l'SDK continua con la policy che ha e riprova |
| `error policy_below_min_issued_seq` | la policy dell'SDK è superata e quella nuova non si è potuta scaricare o accettare, oppure il gruppo non ha più una policy: guarda lo stato della sorgente in console |
| Il mock senza regole risponde a ogni id | in modalità statica (nessuna regola per quel servizio) il mock ricorda solo gli oggetti creati nella sessione: un id mai creato risponde `404` se il contratto l'ha visto e la collezione si può creare, altrimenti `200` dal contratto. Le risposte statiche hanno l'header `X-TT-Static: true` ([mock.md](spec/mock.md) §2.5) |
| I vecchi `host:ip:private:...` compaiono ancora accanto al servizio dichiarato | sono le chiamate di prima della dichiarazione, tenute come storico: le liste li segnano «sostituito da ...» e il pacchetto non li include (niente più `ext-1` nel mock) |
| Python: vedo gli host esterni ma non il mio servizio (problema **Ingresso non catturato**) | nessuna app web è stata avvolta: avvia con `python -m traffic_twin run -- uvicorn app:app` (o gunicorn, flask, manage.py runserver) oppure aggiungi `app = traffic_twin.install(app)` (sezione 3.4) |
| `python -m traffic_twin.run: No module named` | il comando giusto è `python -m traffic_twin run -- <comando>` (con lo spazio) |
| `pip install traffic-twin` non trova il pacchetto | non è nel registro: `pip install ./traffic_twin-x.y.z-py3-none-any.whl` dal kit |
| Il contratto non ha ancora operazioni | servono le prime chiamate; la scheda "Quando compare il contratto" dice quante ne mancano. **Aggiorna contratto ora** per non aspettare la fotografia giornaliera |
| Nessuna regola, e il miner dice «nessun ciclo di vita osservato» (`no_effect`) | se gli stati escono già come `code` (la console lo dice: «Gli stati e i codici escono già in chiaro …») non serve nessuna approvazione: l'oggetto in quelle chiamate non cambia stato (un pagamento che resta `AUTHORIZED`), oppure serve più traffico. Se lo status non esce in chiaro, controlla in **Rivedi in blocco > Stati e codici**: di norma basta `code` (senza approvazione); un `keep` serve solo per campi che non hanno il nome di uno stato e va approvato da un'altra persona |
| L'SDK con `TT_DEBUG=1` scrive `policy_below_min_issued_seq`, `policy_rejected`, `policy_network` | non è un guasto: a ogni nuova versione di policy l'SDK scarta quella vecchia (`policy_below_min_issued_seq`, `policy_rejected` = «questa versione è superata»), scarica la nuova e torna a `capturing`; `policy_network` è un tentativo di scaricarla fallito (per esempio durante un aggiornamento della console), ripetuto da solo. Il servizio non si ferma mai. Preoccupati solo se resta in `policy_rejected` per minuti: guarda la sorgente in Sorgenti |
| Nessuna regola per il mio servizio | sezione 8.1: orizzonte di almeno 1 ora di traffico, almeno k = 20 utenti distinti campionati, utente configurato (`identity.subject`), id in `hmac`, almeno k creazioni dell'oggetto. "Cerca nuove regole" e lo stato in Regole dicono quale manca |
| Ho perso il token di iscrizione | il segreto si vede una sola volta e il server non può rivederlo: nel wizard **Rigenera il token** (3.1) |
| Ho 5 versioni di policy in un'ora | raccogli utente, campionamento, host simulati e campi in una sola bozza (sezione 5); se ne esiste una in attesa, si somma a quella |
| Non posso approvare la mia bozza | chi propone non può approvare una modifica che apre dati: sotto la bozza leggi **Chi può approvare** e copia il link (3.5) |
| Il gate dice che una regola usa un servizio non presente nel pacchetto | genera il mondo con il filtro Gruppo del tuo team (le regole di un altro team non entrano) oppure includi il servizio: sezione 9 |
| Il dialogo del gate dice che il mondo non corrisponde più | regole o contratti sono cambiati dopo il mondo: **Rigenera il mondo** e ricrea il pacchetto |
| `tt mock: ... no trusted keys configured` o `pack signature is invalid` | sezione 10.7: chiavi del gate da Pacchetti twin > Come usarlo nei test |
| Vedo servizi e regole di altri team | usa il filtro **Gruppo** in alto |

## 13. Glossario minimo

- **Sorgente**: l'SDK (o `tt egress`, l'adattatore OBI) che sta vicino al tuo processo e sanifica prima di inviare.
- **Gruppo**: insieme di sorgenti che condividono la stessa policy (di solito un'applicazione).
- **Policy**: lista firmata di cosa può uscire; parte chiusa (`drop`). **Versione di policy**: ogni modifica è un numero nuovo (v1, v2, …), prima bozza poi attiva. **Bozza**: proposta in attesa di approvazione; una bozza nuova di simulazione o assistente si somma a quella in attesa.
- **drop / keep / hmac / bucket**: sezione 5. **kid / epoca**: identificano la chiave HMAC in uso.
- **Fase Osserva**: i primi giorni dopo il collegamento; esce solo la struttura e gli identificativi diventano sigle, senza approvazioni (sezione 3.5). **Policy Osserva**: la versione che la console crea da sola per mascherare gli identificativi. **Apre valori**: una modifica che lascia uscire valori in chiaro o in fasce; solo queste richiedono un'approvazione (sezione 5).
- **Simulare nel mock**: dare un nome a un host esterno perché sia simulato dal mock (sezione 6); l'interruttore di un servizio dice se risponde il mock o il servizio vero. **Buco**: ciò che il mock non conosce ancora bene (poche osservazioni, regole con poco supporto): pagina Buchi.
- **Pubblica questo mondo** (pagina Mondi): non pubblica niente, apre Pacchetti twin con quel mondo già scelto; esce dalla produzione solo il pacchetto rilasciato dopo il gate.
- **Contratto**: cosa fa un'API, ricavato dal traffico (OpenAPI con frequenze). **Fotografia**: contratto congelato a una data.
- **Regola**: relazione causa → effetto osservata nel tempo; **ritardo figurativo**: conta l'ordine, non il tempo vero.
- **Mondo**: clienti sintetici con la loro storia (stesso seed = stesso mondo).
- **Pacchetto twin** (`.ttpack`): l'unico file che passa dalla produzione ai test, firmato dal gate. **Gate**: i 5 controlli prima della firma.
- **k-anonimato / k_min (20)**: un valore esce solo se visto per almeno k utenti distinti.
- **Sessione (mock)**: stato isolato di un test (`X-TT-Session`).

## 14. Avanzate: cosa c'è nel gruppo del menu

Il gruppo **Avanzate** del menu è chiuso di partenza (si apre da solo quando entri in una sua pagina). Non serve per usare il mock: serve quando vuoi capire o governare cosa succede sotto.

- **Policy** (Sorgenti > Policy): le versioni della policy, le bozze e le approvazioni (sezione 5).
- **Archetipi**: i profili di comportamento da cui nascono i clienti sintetici. Si costruiscono da soli alla prima generazione di un mondo; qui li vedi, con la soglia k.
- **Mondi**: generi i clienti sintetici e li esplori uno per uno (sezione 9).
- **Pacchetti twin**: assembli, controlli (gate), firmi e rilasci ciò che esce dalla produzione; esporti per WireMock, Microcks e Prism (sezioni 9 e 11).
- **Scenari mock**: ora sono nella pagina **Mock**, scheda «Scenari salvati» (guasti ed esiti forzati che entrano nei dati alla prossima preparazione; sezione 10.1 e 10.9).
- **Quarantena**: sezione 8.4.
- **Esporta eventi**: un file con gli eventi osservati in un intervallo, per analisi fuori dalla console. Scegli il servizio dall'elenco (o tutti), l'intervallo (ci sono i tasti rapidi 24 ore, 7 e 30 giorni) e il formato (OCEL 2.0 o JSON Lines). Sono dati personali pseudonimi: restano nella zona B e ogni esportazione è nell'audit.
- **Audit, Utenti e ruoli, Impostazioni**: il registro delle azioni, chi può fare cosa, le impostazioni dell'installazione.
- **Glossario, Manuale utente, Chiavi HMAC**: l'aiuto.
