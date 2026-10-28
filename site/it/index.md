---
layout: home
title: traffic-twin
titleTemplate: Mock con stato ricavati dal traffico di produzione

hero:
  name: traffic-twin
  text: Mock con stato ricavati dal traffico di produzione
  tagline: traffic-twin osserva il traffico HTTP della tua applicazione in produzione, ne ricava contratti e regole causa → effetto e costruisce un mock con stato per i tuoi test, popolato da clienti sintetici coerenti. I valori veri non escono mai dal processo dell'applicazione.
  image:
    src: /logo.svg
    alt: ''
  actions:
    - theme: brand
      text: Primo giro in 15 minuti
      link: /it/docs/getting-started
    - theme: alt
      text: Architettura
      link: /it/docs/architecture
    - theme: alt
      text: GitHub
      link: https://github.com/ivseb/traffic-twin

features:
  - title: Sanificato dentro il processo
    details: Un SDK o il proxy tt-egress applica una policy firmata e chiusa per default prima che qualcosa esca dall'app. Di ogni campo resta solo la forma, salvo che la policy dica keep, hmac, bucket o code.
  - title: Contratti dal traffico vero
    details: Contratti OpenAPI 3.1 con estensioni x-tt-* per ogni operazione, ricavati solo da forme e conteggi, con status, tassi d'errore e latenze. Il drift dei contratti manda allarmi via webhook.
  - title: Regole causa → effetto
    details: Il miner trova le chiavi di legame, gli effetti che seguono una chiamata e gli esiti alternativi (un ordine crea una spedizione che attraversa i suoi stati). Ogni regola la rivede e la approva una persona.
  - title: Mondi sintetici k-anonimi
    details: Gli utenti diventano archetipi di almeno k persone (k = 20 per default). I clienti sintetici, con dati inventati e id nuovi, vivono in avanti nel tempo secondo le regole approvate. Stesso seed, stesso mondo.
  - title: Un mock con stato per i test
    details: tt mock serve un pacchetto twin firmato con sessioni per test, orologio virtuale, guasti alle frequenze osservate e un'API di controllo. I pacchetti si esportano anche verso WireMock, Microcks e Prism.
  - title: Una console che si spiega
    details: Onboarding guidato con i comandi già pronti, un assistente che propone un'azione per campo partendo da forme e conteggi, e il manuale utente dentro la console.
---

<div class="tt-home">

<p class="tt-status"><strong>Stato: primi rilasci pubblici, v0.1.1.</strong> La pipeline gira tutta da un capo all'altro, ma formati, API e opzioni degli SDK possono ancora cambiare. Prima di usarlo su traffico vero leggi la <a href="./docs/operations#9-checklist-di-sicurezza-per-la-produzione">checklist di sicurezza per la produzione</a>.</p>

## Come funziona

<p class="tt-lead">I dati diventano sempre meno sensibili man mano che si allontanano dall'applicazione, e ogni passaggio di zona ha un controllo. I valori veri esistono solo dentro l'applicazione, per il tempo di una chiamata.</p>

<PipelineDiagram lang="it" />

1. **Osserva.** Un SDK nativo (Go, Node.js, Python, Java, .NET, PHP) si aggancia al gestore delle richieste in ingresso e al client HTTP in uscita, prima della cifratura TLS. Per gli stack senza SDK c'è `tt egress`, un reverse proxy di uscita con lo stesso sanitizer.
2. **Sanifica.** La policy firmata decide cosa può uscire: per default solo la forma (`"drop:str:email"`), altrimenti un token HMAC stabile, una fascia o un valore dichiarato a bassa cardinalità. Gli eventi viaggiano come OTLP/HTTP JSON su mTLS verso l'intake, che scarta tutto ciò che la policy non ammette.
3. **Ricava.** tt-core costruisce i contratti OpenAPI e cerca le regole causa → effetto partendo da token e forme, mai dai valori.
4. **Sintetizza.** Gli archetipi di almeno *k* utenti e le regole approvate generano un mondo sintetico deterministico.
5. **Mock.** Il gate di pubblicazione controlla gli artefatti, keyguard firma il pacchetto twin e `tt mock` lo serve nei test in locale e in CI.

## Modello di sicurezza

<p class="tt-lead">traffic-twin promette proprietà verificabili e dichiara apertamente cosa non garantisce. Qui il riassunto; i dettagli sono nel <a href="./docs/threat-model">threat model</a> e nell'<a href="./docs/architecture">architettura</a>.</p>

<div class="tt-grid">
  <div class="tt-card">
    <h3>Tre zone di fiducia</h3>
    <p>La zona A è l'app (valori veri), la zona B è tt-core (forme e token HMAC, nessuna chiave), la zona C è sviluppo e CI (solo dati sintetici).</p>
  </div>
  <div class="tt-card">
    <h3>Chiuso per default</h3>
    <p>Con una policy vuota non esce nessun valore da nessuna parte dello scambio, solo forme grossolane e nomi della struttura. Gli stessi vettori di conformità valgono byte per byte per ogni SDK.</p>
  </div>
  <div class="tt-card">
    <h3>Keyguard custodisce le chiavi</h3>
    <p>Un processo separato è l'unico custode delle chiavi HMAC e di firma in zona B. Ricontrolla le approvazioni prima di firmare una policy: per aprire dati servono due persone diverse, oppure un amministratore con un motivo registrato e un allarme (chi installa può vietarlo).</p>
  </div>
  <div class="tt-card">
    <h3>Gate di pubblicazione</h3>
    <p>Provenienza di ogni stringa, prova al contrario HMAC che trova le copie esatte di valori veri, rilevatori di dati personali e soglie k. Keyguard firma il pacchetto; il mock rifiuta i pacchetti non firmati.</p>
  </div>
  <div class="tt-card">
    <h3>k-anonimato</h3>
    <p>Archetipi, valori enum pubblicati, esiti e conteggi devono riguardare ciascuno almeno <em>k</em> utenti distinti, altrimenti si sopprimono o si fondono.</p>
  </div>
  <div class="tt-card">
    <h3>Sorgenti fail-closed</h3>
    <p>Senza una policy firmata valida, la chiave HMAC e un primo heartbeat la sorgente non cattura nulla e l'app continua a funzionare. Sotto pressione scarta eventi, mai richieste.</p>
  </div>
</div>

## Overhead misurato

<p class="tt-lead">Misure di <a href="./docs/performance#36-deployment-multi-host-di-prova">docs/PERFORMANCE.md §3.6</a> su un deployment multi-host di prova (hardware condiviso, misure rumorose). Descrivono quella prova, non sono una garanzia per la tua installazione.</p>

| Cosa si è misurato | Risultato |
|---|---|
| Latenza aggiunta da `tt egress` (p50 / p99) | circa +0,9 ms / +3 ms, nel rumore |
| SDK Node, campionamento 5%, richiesta da 70 µs (caso peggiore) | +1,6% req/s rispetto all'SDK spento, indistinguibile nel rumore |
| SDK Node, costo di uno scambio *campionato* | circa 130–250 µs |
| Intake di tt-core in un container da 4 vCPU | circa 4.000 eventi/s sostenuti senza perdite |

## Avvio rapido

Cosa serve: Go 1.25+, Node.js 24+ per la demo (l'SDK Node da solo funziona da Node 20), make, curl, jq, openssl.

```sh
git clone https://github.com/ivseb/traffic-twin.git && cd traffic-twin
make build
./bin/tt dev up            # keyguard (socket Unix) + tt-core, chiavi generate in ./tt-dev
```

`tt dev up` stampa l'URL della UI (`https://127.0.0.1:7070`, certificato autofirmato su loopback), l'URL dell'intake per le sorgenti (`https://localhost:4318`), il file della chiave HMAC che serve alle sorgenti e un token monouso per creare il primo amministratore. Poi: crea un gruppo di sorgenti nel wizard di onboarding, avvia una sorgente (un SDK o `tt egress`), approva una policy e segui contratti → regole → mondo → pacchetto firmato. Il pacchetto si esegue con `tt mock --pack pack.ttpack`.

Vuoi prima vedere tutto il prodotto in pochi secondi?

```sh
go test ./internal/core -run TestProductEndToEnd -v
```

Avvia keyguard e tt-core, iscrive una sorgente, manda su mTLS una settimana simulata dello shop della demo, cerca le regole, costruisce e pubblica un pacchetto, lo esegue nel mock e lo esporta. Il [primo giro in 15 minuti](./docs/getting-started) accompagna passo per passo.

## SDK

<p class="tt-lead">SDK di cattura nativi, senza dipendenze a runtime oltre alla libreria standard. I pacchetti arrivano sui registri dal workflow di rilascio: la disponibilità è indicata nelle <a href="https://github.com/ivseb/traffic-twin/releases">note di rilascio</a>.</p>

| Linguaggio | Pacchetto | Runtime minimo |
|---|---|---|
| Go | `github.com/ivseb/traffic-twin/sdk/go` | Go 1.25 |
| Node.js | `@traffic-twin/sdk` (npm) | Node 20 (corpi completi di `fetch` da 24) |
| Python | `traffic-twin` (PyPI) | Python 3.9 |
| Java | `io.github.ivseb.traffictwin:sdk`, `sdk-servlet-javax`, `sdk-otel-extension`, `sdk-agent` (Maven Central) | Java 17 |
| .NET | `TrafficTwin.Sdk`, `TrafficTwin.Sdk.AspNetCore` (NuGet) | .NET 8 |
| PHP | `traffic-twin/sdk` (dai sorgenti in `sdk/php`; Packagist in arrivo) | PHP 8.1 con ext-sodium |

Nessun SDK per il tuo stack? `tt egress` cattura le chiamate in uscita come reverse proxy: si cambia la base URL del servizio esterno, senza toccare il codice. Requisiti di ogni SDK nella [guida operativa](./docs/operations#41-sdk).

## Open source

traffic-twin si installa in casa ed è rilasciato con licenza Apache-2.0. tt-core e keyguard non fanno chiamate in uscita, salvo i webhook in lista ammessa, e non c'è telemetria verso i manutentori. Questo sito non carica tracker, strumenti di analisi o risorse di terzi.

<div class="tt-links">
  <a href="https://github.com/ivseb/traffic-twin">Repository GitHub</a>
  <a href="https://github.com/ivseb/traffic-twin/releases">Release</a>
  <a href="./docs/security">Segnalare una vulnerabilità</a>
  <a href="./docs/contributing">Contribuire</a>
  <a href="https://github.com/ivseb/traffic-twin/blob/main/LICENSE">Licenza</a>
</div>

</div>
