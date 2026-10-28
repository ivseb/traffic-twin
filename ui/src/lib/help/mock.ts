import type { FieldHelp, GlossaryEntry, PageGuide } from './types';

// Guide, field help and glossary of the Mock page (mock as a service). Merged into the help packs by index.svelte.ts.

export const mockPagesIt: Record<string, PageGuide> = {
  mock: {
    title: 'Mock',
    purpose: 'Il posto da cui usi il mock nei test: lo prepari con un clic dal traffico osservato, prendi gli indirizzi che sostituiscono gli endpoint veri, guardi le chiamate dei test in tempo reale e comandi scenari, guasti e orologio.',
    steps: [
      'Scegli il gruppo (il tuo team) e premi **Prepara e avvia il mock**: la console costruisce i dati sintetici, li fa controllare e firmare, li rilascia ai test e avvia il mock (nel cluster, se la console può farlo).',
      'Se la console non avvia container, in **Avvia il mock tu** crei un token e copi il comando Docker, Helm o OpenShift: il mock compare in «I tuoi mock» entro pochi secondi.',
      'In «Indirizzi da usare nei test» copia l’indirizzo del mock di ogni servizio e mettilo nella configurazione dei test al posto dell’indirizzo vero.',
      'Lancia i test e guarda **Ultime chiamate**: metodo, percorso, esito, scenario e guasto di ogni chiamata.',
      'In **Sessione e scenari** applica uno scenario, spegni i guasti o fai avanzare l’orologio di una sessione.',
      'Quando i dati cambiano premi di nuovo **Prepara e avvia il mock**: i mock collegati passano da soli ai dati nuovi.',
    ],
    concepts: [
      { term: 'Mock collegato', text: 'Un mock in [[console-mode|modalità console]]: scarica dalla console gli ultimi dati rilasciati del suo gruppo, li verifica come un file firmato e manda alla console stato e chiamate.' },
      { term: 'Token del mock', text: 'La chiave con cui il mock parla alla console. Vale per un solo gruppo e apre solo i suoi dati. Vedi [[mock-token]].' },
      { term: 'Mock nel cluster', text: 'Con la console in Kubernetes/OpenShift il mock si avvia da qui, nel namespace dei mock. Vedi [[managed-mock]].' },
      { term: 'Sessione', text: 'Una copia isolata del mock per un test, scelta con l’header X-TT-Session. Vedi [[mock-session]].' },
    ],
    effects: [
      'Il mock non vede mai dati di produzione: riceve solo dati sintetici controllati dal [[gate]] e firmati da [[keyguard]], e alla console manda solo il riassunto delle chiamate (niente header né corpi).',
      'Ogni preparazione costruisce un nuovo [[twin-pack|pacchetto twin]]; lo trovi in Avanzate > Pacchetti twin, per esempio per scaricarlo in una CI senza console.',
      'Quando il mock passa ai dati nuovi le sue sessioni ripartono da capo.',
      'Revocare un token ferma i mock che lo usano.',
    ],
    firstVisit: 'Qui ottieni il mock che sostituisce i tuoi endpoint veri nei test: un clic per prepararlo, poi copi gli indirizzi.',
  },
};

export const mockPagesEn: Record<string, PageGuide> = {
  mock: {
    title: 'Mock',
    purpose: 'Where you use the mock in the tests: prepare it with one click from the observed traffic, take the addresses that replace the real endpoints, watch the calls of the tests live and drive scenarios, faults and clock.',
    steps: [
      'Pick the group (your team) and press **Prepare and start the mock**: the console builds the synthetic data, has them checked and signed, releases them to the tests and starts the mock (in the cluster, when the console can).',
      'If the console does not start containers, in **Start the mock yourself** create a token and copy the Docker, Helm or OpenShift command: the mock shows in "Your mocks" within seconds.',
      'In "Addresses to use in the tests" copy the mock address of each service and put it in the configuration of the tests instead of the real address.',
      'Run the tests and watch **Last calls**: method, path, outcome, scenario and fault of every call.',
      'In **Session and scenarios** apply a scenario, turn the faults off or advance the clock of a session.',
      'When the data change press **Prepare and start the mock** again: the connected mocks switch to the new data by themselves.',
    ],
    concepts: [
      { term: 'Connected mock', text: 'A mock in [[console-mode|console mode]]: it downloads from the console the latest released data of its group, verifies them like a signed file and sends the console its status and calls.' },
      { term: 'Mock token', text: 'The key the mock uses to talk to the console. It is valid for one group and opens only its data. See [[mock-token]].' },
      { term: 'Mock in the cluster', text: 'With the console in Kubernetes/OpenShift the mock starts from here, in the mock namespace. See [[managed-mock]].' },
      { term: 'Session', text: 'An isolated copy of the mock for one test, chosen with the X-TT-Session header. See [[mock-session]].' },
    ],
    effects: [
      'The mock never sees production data: it receives only synthetic data checked by the [[gate]] and signed by [[keyguard]], and sends the console only the summary of the calls (no headers, no bodies).',
      'Every preparation builds a new [[twin-pack|twin pack]]; you find it in Advanced > Twin packs, for example to download it in a CI without the console.',
      'When the mock switches to new data its sessions start again.',
      'Revoking a token stops the mocks using it.',
    ],
    firstVisit: 'Here you get the mock that replaces your real endpoints in the tests: one click to prepare it, then copy the addresses.',
  },
};

export const mockFieldsIt: Record<string, FieldHelp> = {
  'mock.group': { title: 'Gruppo (team)', meaning: 'Il gruppo i cui servizi il mock simula: i dati vengono solo dal suo traffico.', effect: 'Ogni gruppo ha il suo mock e i suoi token; un mock rifiuta i dati di un altro gruppo.', default: 'Il gruppo scelto nel filtro Gruppo/Team, o il primo dei tuoi.' },
  'mock.reason': { title: 'Motivazione', meaning: 'Perché rilasci i dati ai test da amministratore, senza un Pubblicatore.', effect: 'Resta nell’audit e keyguard firma il rilascio come approvazione dell’amministratore (con allarme).', when: 'Solo se sei amministratore.' },
  'mock.pack': { title: 'Dati in uso', meaning: 'Il pacchetto twin che il mock sta servendo: dati sintetici controllati e firmati.', effect: 'Se non è l’ultimo rilasciato, il mock lo sostituisce entro pochi secondi; se lo rifiuta, lo dice qui sotto.', term: 'twin-pack' },
  'mock.url': { title: 'Indirizzo del mock', meaning: 'L’indirizzo da mettere nei test al posto di quello vero del servizio: risponde come il servizio, con dati inventati.', effect: 'Le chiamate a questo indirizzo compaiono in Ultime chiamate; le chiamate senza header X-TT-Session usano la sessione default.', term: 'mock' },
  'mock.token': { title: 'Token del mock', meaning: 'La chiave che il mock usa per scaricare i dati del gruppo e mandare il suo stato alla console.', effect: 'Si vede una volta sola; la console ne conserva solo l’impronta. Non apre nient’altro della console. Scade dopo 180 giorni.', term: 'mock-token' },
  'mock.session': { title: 'Sessione', meaning: 'La copia isolata del mock su cui agiscono scenari, guasti e orologio.', effect: 'I test la scelgono con l’header X-TT-Session; azzerarla riporta dati, orologio e guasti all’inizio.', term: 'mock-session' },
  'mock.scenario': { title: 'Scenario', meaning: 'Una situazione pronta da provare (guasti, esiti forzati, cliente), presa dai dati in uso.', effect: 'Applicarlo azzera la sessione e la fa ripartire con lo scenario.', term: 'scenario' },
  'mock.faults': { title: 'Guasti', meaning: 'Errori, guasti di rete e latenze iniettati nelle risposte.', effect: '«Come in produzione» li inietta alle frequenze osservate; «Nessun guasto» rende i test ripetibili.', default: 'Come in produzione.' },
  'mock.clock': { title: 'Orologio virtuale', meaning: 'Il tempo della sessione, che avanza solo a comando.', effect: 'Avanzando, gli effetti in coda si eseguono (la spedizione passa in consegna). Non torna mai indietro.', term: 'virtual-clock' },
};

export const mockFieldsEn: Record<string, FieldHelp> = {
  'mock.group': { title: 'Group (team)', meaning: 'The group whose services the mock simulates: the data come only from its traffic.', effect: 'Each group has its own mock and tokens; a mock refuses the data of another group.', default: 'The group chosen in the Group/Team filter, or the first of yours.' },
  'mock.reason': { title: 'Reason', meaning: 'Why you release the data to the tests as an administrator, without a Publisher.', effect: 'It is kept in the audit log and keyguard signs the release as an administrator approval (with an alert).', when: 'Only if you are an administrator.' },
  'mock.pack': { title: 'Data in use', meaning: 'The twin pack the mock is serving: synthetic data, checked and signed.', effect: 'When it is not the latest released, the mock replaces it within seconds; when it refuses it, it says so below.', term: 'twin-pack' },
  'mock.url': { title: 'Mock address', meaning: 'The address to put in the tests instead of the real one of the service: it answers like the service, with invented data.', effect: 'The calls to this address show in Last calls; calls without the X-TT-Session header use the default session.', term: 'mock' },
  'mock.token': { title: 'Mock token', meaning: 'The key the mock uses to download the data of the group and send its status to the console.', effect: 'Shown once; the console keeps only its fingerprint. It opens nothing else of the console. It expires after 180 days.', term: 'mock-token' },
  'mock.session': { title: 'Session', meaning: 'The isolated copy of the mock scenarios, faults and clock act on.', effect: 'The tests choose it with the X-TT-Session header; resetting it brings data, clock and faults back to the start.', term: 'mock-session' },
  'mock.scenario': { title: 'Scenario', meaning: 'A ready situation to try (faults, forced outcomes, customer), from the data in use.', effect: 'Applying it resets the session and starts it again with the scenario.', term: 'scenario' },
  'mock.faults': { title: 'Faults', meaning: 'Errors, network failures and latency injected into the answers.', effect: '"As in production" injects them at the observed frequencies; "No faults" makes the tests repeatable.', default: 'As in production.' },
  'mock.clock': { title: 'Virtual clock', meaning: 'The time of the session, which moves only on command.', effect: 'Moving it runs the queued effects (the shipment goes in transit). It never goes back.', term: 'virtual-clock' },
};

export const mockGlossaryIt: Record<string, GlossaryEntry> = {
  'console-mode': { term: 'Modalità console', short: 'Il mock che prende i dati dalla console invece che da un file.', long: 'Avviato con `tt mock --console <url> --group <gruppo>` e un token del mock, scarica l’ultimo pacchetto rilasciato del gruppo, lo verifica con le chiavi pubbliche del gate come un file, passa da solo al pacchetto nuovo e manda alla console stato, indirizzi e il riassunto delle chiamate. La modalità file (`tt mock pacchetto.ttpack`) resta per la CI senza console.', see: ['mock', 'mock-token', 'twin-pack'] },
  'mock-token': { term: 'Token del mock', short: 'La chiave di un mock collegato alla console, per un solo gruppo.', long: 'Inizia con `ttm_`. Permette solo di scaricare l’ultimo pacchetto rilasciato del suo gruppo e di mandare lo stato del mock: non è un accesso alla console. La console ne conserva l’impronta (SHA-256), scade e si revoca dalla pagina Mock.', see: ['console-mode'] },
  'managed-mock': { term: 'Mock nel cluster', short: 'Il mock che la console avvia da sola in Kubernetes/OpenShift.', long: 'Se la console gira in un cluster con `mock.kubernetes` attivo, crea nel namespace dei mock un Deployment, un Service, un Secret e (su OpenShift) una Route con un permesso limitato a quel namespace. Si ferma e si riavvia dalla pagina Mock.', see: ['console-mode', 'mock'] },
};

export const mockGlossaryEn: Record<string, GlossaryEntry> = {
  'console-mode': { term: 'Console mode', short: 'The mock that takes its data from the console instead of a file.', long: 'Started with `tt mock --console <url> --group <group>` and a mock token, it downloads the latest released pack of the group, verifies it with the public keys of the gate like a file, switches to a newer pack by itself and sends the console its status, addresses and the summary of the calls. File mode (`tt mock pack.ttpack`) stays for CI without the console.', see: ['mock', 'mock-token', 'twin-pack'] },
  'mock-token': { term: 'Mock token', short: 'The key of a mock connected to the console, for one group.', long: 'It starts with `ttm_`. It only downloads the latest released pack of its group and sends the status of the mock: it is no access to the console. The console keeps its fingerprint (SHA-256); it expires and is revoked from the Mock page.', see: ['console-mode'] },
  'managed-mock': { term: 'Mock in the cluster', short: 'The mock the console starts by itself in Kubernetes/OpenShift.', long: 'When the console runs in a cluster with `mock.kubernetes` on, it creates in the mock namespace a Deployment, a Service, a Secret and (on OpenShift) a Route, with a permission limited to that namespace. It is stopped and restarted from the Mock page.', see: ['console-mode', 'mock'] },
};
