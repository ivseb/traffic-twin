import type { FieldHelp, PageGuide } from './types';

// Guides written for the 4-step journey (Collega, Osserva, Rivedi, Usa il mock): the home page, the Mock page
// placeholder and the pages whose actions got a plain-language consequence (quarantine, alerts, gaps) or changed
// (worlds with the explorer and automatic archetypes, the event export). They replace the guides of the same id.

export const journeyPagesIt: Record<string, PageGuide> = {
  home: {
    title: 'Panoramica',
    purpose: 'Il percorso in quattro passi: **1 Collega** il servizio, **2 Osserva** cosa chiama, **3 Rivedi** contratti, regole e cambiamenti, **4 Usa il mock** al posto dei servizi reali. Qui vedi a che punto sei e cosa fare dopo.',
    steps: [
      'Leggi il riquadro «Prossimo passo»: dice una cosa sola da fare e perché.',
      'Premi il pulsante per andare alla pagina giusta; ogni passo ha il suo pulsante anche nelle schede sotto.',
      'Torna qui dopo qualche ora o il giorno dopo: il quadro si aggiorna da solo con quello che è arrivato.',
    ],
    concepts: [
      { term: 'Collega', text: 'Unisci un servizio con un token. Non serve scrivere nulla a mano: la guida ti dà il comando.' },
      { term: 'Osserva', text: 'Lascia girare il servizio almeno 24 ore: più traffico significa contratti più completi.' },
      { term: 'Rivedi', text: 'Controlla i contratti OpenAPI (anche per Postman e Insomnia), le regole sui dati, i buchi e gli allarmi.' },
      { term: 'Usa il mock', text: 'Un mock risponde al posto dei tuoi servizi reali nei test. Vedi [[mock]].' },
      { term: 'Avanzate', text: 'Policy, archetipi, mondi, pacchetti twin, quarantena, esportazione, audit, utenti e impostazioni: nel menu, in un gruppo chiuso. Servono solo quando vuoi andare a fondo.' },
    ],
    effects: ['Questa pagina non cambia nulla: legge soltanto conteggi.', 'Se il tuo ruolo non può leggere un elenco, quel conteggio manca e il passo resta valutato sul resto.'],
    firstVisit: 'Qui vedi a che punto sei del percorso e cosa fare dopo.',
  },
  mock: {
    title: 'Usa il mock',
    purpose: 'Il mock risponde al posto dei servizi reali che la tua app chiama, usando i contratti e le regole che hai rivisto.',
    steps: ['Scegli quali servizi simulare in **Osserva > Servizi** (interruttore «Simula nel mock»).', 'Prepara e rilascia un pacchetto in **Avanzate > Pacchetti twin**.', 'Avvia il mock nei tuoi test (`tt mock`) e punta la tua app all’indirizzo del mock.'],
    concepts: [{ term: 'Simula nel mock', text: 'Acceso: il mock risponde per quel servizio. Spento: la tua app continua a chiamare quello vero.' }],
    effects: ['Finché non rilasci un pacchetto il mock non ha nulla da servire e la tua app non cambia.'],
    firstVisit: 'Qui avvii il mock che sostituisce i servizi reali nei tuoi test.',
  },
  quarantine: {
    title: 'Quarantena',
    purpose: 'Qui compaiono i punti dove il sistema ha visto **troppi valori diversi** in un posto che considerava fisso: un campo conservato, un nome, un pezzo di percorso, una parte del nome di un host. Di solito è un **parametro** (un identificativo, un id cliente), che potrebbe essere un dato personale. Finché è qui i valori sono riscritti come {*} e non si vedono.',
    steps: [
      'Per ogni elemento leggi «Perché è qui» e il numero di valori diversi stimati (mai i valori).',
      'Se è un parametro che cambia sempre, premi **È un parametro: raggruppa i valori**: restano nascosti per sempre, basta un approvatore.',
      'Se è davvero un nome fisso con tanti valori ammessi, premi **È un nome fisso: tienilo**: i valori tornano visibili. Apre dati, quindi servono due approvatori diversi (un amministratore decide da solo, con audit).',
    ],
    concepts: [
      { term: 'Raggruppa i valori', text: 'È l’azione sicura: da ora quel punto resta scritto come {*}. Non apre nulla e non si annulla da sola.' },
      { term: 'Tienilo', text: 'I valori tornano visibili e il conteggio riparte da zero; se tornano a essere troppi, l’elemento ricompare qui.' },
      { term: 'Host', text: 'Se una parte del nome di un host ha troppi valori diversi (un id cliente come sottodominio) l’intake la raccoglie in {*}: lo vedi come «Etichette sotto dominio, posizione n». Vedi [[host-wildcard]].' },
      { term: 'Due persone', text: 'Tenere i valori visibili apre dati: vale la regola delle due persone. Vedi [[two-person]].' },
    ],
    effects: [
      '«Raggruppa i valori» non apre nulla ed è sempre sicuro.',
      '«Tienilo» fa tornare i valori in chiaro dopo la seconda approvazione e resta nell’audit; un amministratore che lo fa da solo genera anche un allarme.',
    ],
    firstVisit: 'Qui decidi, per ogni punto con troppi valori diversi, se è un parametro da raggruppare o un nome fisso da tenere.',
  },
  gaps: {
    title: 'Buchi',
    purpose: 'Dove il mock è debole: operazioni con pochi campioni, status d’errore mai visti, regole con poco supporto. È la lista di ciò che conviene osservare ancora. Non c’è nulla da chiudere: un buco sparisce da solo quando arriva più traffico.',
    steps: ['Filtra per tipo di buco.', 'Leggi «Cosa fare» accanto a ogni riga.', 'Apri l’operazione o la regola indicata per capire il contesto, poi aspetta più traffico e controlla di nuovo.'],
    concepts: [
      { term: 'Pochi campioni', text: 'Troppe poche chiamate per fidarsi di schema e frequenze.' },
      { term: 'Status mai visto', text: 'Per esempio un 404 mai osservato: il mock non saprà rispondere “non trovato”.' },
    ],
    effects: ['Un buco non blocca nulla, ma il mock sarà meno realistico in quel punto.', 'Per colmarlo puoi anche usare uno [[scenario]] che forza quel caso nei test.'],
    firstVisit: 'Questa è la lista di ciò che il mock non conosce ancora bene, con cosa fare per ognuno.',
  },
  worlds: {
    title: 'Mondi',
    purpose: 'Un mondo è un insieme di **clienti sintetici** con la loro storia (ordini, spedizioni…), generata applicando le regole approvate. Serve al mock per rispondere con dati coerenti. Qui li generi e li **esplori**.',
    steps: [
      'Scegli un **seed** (un numero) e quanti clienti creare, poi premi Genera. Se mancano i profili di comportamento (archetipi) li costruisce da solo, e vedi i passi avanzare.',
      'Seleziona un mondo: sotto compare l’esploratore con l’elenco dei clienti. Cerca per id, nome o archetipo e scorri le pagine.',
      'Scegli un cliente: vedi i suoi ordini e le sue spedizioni e, per ognuno, gli stati attraversati nel tempo.',
      'Quando sei soddisfatto usa **Rilascia ai test** per metterlo in un pacchetto.',
    ],
    concepts: [
      { term: 'Seed', text: 'Il numero da cui parte la generazione casuale. Stesso seed, stesso mondo: i test sono ripetibili.' },
      { term: 'Cliente sintetico', text: 'Un cliente inventato (CUS-SYN-0007) basato su un archetipo. Nome ed e-mail sono inventati: nessuna persona reale dietro. Vedi [[world]].' },
      { term: 'Archetipi', text: 'I profili di comportamento da cui nascono i clienti. Si costruiscono da soli alla prima generazione; la pagina Archetipi (in Avanzate) li mostra.' },
    ],
    effects: ['Generare un mondo non lo rende disponibile ai test: serve passare dal gate e rilasciarlo in un pacchetto.', 'Più clienti = pacchetto più grande, ma test più vari.'],
    firstVisit: 'Qui crei i clienti inventati che popoleranno il mock e li sfogli uno per uno.',
  },
  events: {
    title: 'Esporta eventi',
    purpose: 'Esporta gli eventi sanificati di un intervallo per analizzarli nella zona B (per esempio con strumenti di process mining). Sono dati personali pseudonimi: è una funzione avanzata, non serve per usare il mock.',
    steps: ['Scegli l’intervallo (o uno dei tasti rapidi) e, se vuoi, un solo servizio dall’elenco.', 'Scegli il formato: OCEL 2.0 o JSON Lines.', 'Prepara l’esportazione e scarica il file: lo scarichi solo tu.'],
    concepts: [{ term: 'Zona B', text: 'Dove vive tt-core: i dati pseudonimi non devono uscirne. Vedi [[zone-b]].' }],
    effects: ['Ogni esportazione resta nell’audit e viene annunciata ai webhook degli amministratori (solo formato e dimensione).'],
    firstVisit: 'Esportazione a livello di evento: usala solo dentro la zona B.',
  },
};

export const journeyPagesEn: Record<string, PageGuide> = {
  home: {
    title: 'Overview',
    purpose: 'The journey in four steps: **1 Connect** the service, **2 Observe** what it calls, **3 Review** contracts, rules and changes, **4 Use the mock** instead of the real services. Here you see where you are and what to do next.',
    steps: [
      'Read the “Next step” box: it says one thing to do and why.',
      'Press the button to go to the right page; every step also has its own button in the cards below.',
      'Come back after a few hours or the next day: the picture updates by itself with what arrived.',
    ],
    concepts: [
      { term: 'Connect', text: 'Join a service with a token. Nothing to write by hand: the guide gives you the command.' },
      { term: 'Observe', text: 'Let the service run for at least 24 hours: more traffic means more complete contracts.' },
      { term: 'Review', text: 'Check the OpenAPI contracts (also for Postman and Insomnia), the data rules, the gaps and the alerts.' },
      { term: 'Use the mock', text: 'A mock answers instead of your real services in the tests. See [[mock]].' },
      { term: 'Advanced', text: 'Policy, archetypes, worlds, twin packs, quarantine, export, audit, users and settings: in the menu, in a closed group. You only need them when you want to go deeper.' },
    ],
    effects: ['This page changes nothing: it only reads counts.', 'If your role cannot read a list, that count is missing and the step is judged on the rest.'],
    firstVisit: 'Here you see where you are in the journey and what to do next.',
  },
  mock: {
    title: 'Use the mock',
    purpose: 'The mock answers instead of the real services your app calls, using the contracts and rules you reviewed.',
    steps: ['Choose which services to simulate in **Observe > Services** (the “Simulate in the mock” switch).', 'Build and release a pack in **Advanced > Twin packs**.', 'Start the mock in your tests (`tt mock`) and point your app at the mock’s address.'],
    concepts: [{ term: 'Simulate in the mock', text: 'On: the mock answers for that service. Off: your app keeps calling the real one.' }],
    effects: ['Until you release a pack the mock has nothing to serve and your app does not change.'],
    firstVisit: 'Here you start the mock that replaces the real services in your tests.',
  },
  quarantine: {
    title: 'Quarantine',
    purpose: 'Here appear the places where the system saw **too many different values** in a spot it considered fixed: a kept field, a name, a path segment, a part of a host name. Usually it is a **parameter** (an identifier, a customer id) that could be personal data. While it is here the values are rewritten as {*} and cannot be seen.',
    steps: [
      'For each item read “Why it is here” and the estimated number of different values (never the values).',
      'If it is a parameter that always changes, press **It is a parameter: group the values**: they stay hidden for good, one approver is enough.',
      'If it really is a fixed name with many allowed values, press **It is a fixed name: keep it**: the values become visible again. That opens data, so two different approvers are needed (an administrator decides alone, with audit).',
    ],
    concepts: [
      { term: 'Group the values', text: 'The safe action: from now on that spot stays written as {*}. It opens nothing and does not undo itself.' },
      { term: 'Keep it', text: 'The values become visible and the count restarts from zero; if they become too many again, the item shows up here again.' },
      { term: 'Host', text: 'If a part of a host name has too many different values (a customer id as a subdomain) the intake gathers it into {*}: you see it as “Labels under domain, position n”. See [[host-wildcard]].' },
      { term: 'Two people', text: 'Keeping the values visible opens data: the two-person rule applies. See [[two-person]].' },
    ],
    effects: [
      '“Group the values” opens nothing and is always safe.',
      '“Keep it” brings the values back in the clear after the second approval and stays in the audit; an administrator doing it alone also raises an alert.',
    ],
    firstVisit: 'Here you decide, for each spot with too many different values, whether it is a parameter to group or a fixed name to keep.',
  },
  gaps: {
    title: 'Gaps',
    purpose: 'Where the mock is weak: operations with few samples, error statuses never seen, rules with little support. It is the list of what is worth observing more. There is nothing to close: a gap goes away by itself when more traffic arrives.',
    steps: ['Filter by kind of gap.', 'Read “What to do” next to each row.', 'Open the operation or rule indicated to understand the context, then wait for more traffic and check again.'],
    concepts: [
      { term: 'Few samples', text: 'Too few calls to trust schema and frequencies.' },
      { term: 'Status never seen', text: 'For example a 404 never observed: the mock will not know how to answer “not found”.' },
    ],
    effects: ['A gap blocks nothing, but the mock will be less realistic at that point.', 'To fill it you can also use a [[scenario]] that forces that case in the tests.'],
    firstVisit: 'This is the list of what the mock does not know well yet, with what to do about each.',
  },
  worlds: {
    title: 'Worlds',
    purpose: 'A world is a set of **synthetic customers** with their history (orders, shipments…), generated by applying the approved rules. The mock uses it to answer with consistent data. Here you generate and **explore** them.',
    steps: [
      'Choose a **seed** (a number) and how many customers to create, then press Generate. If the behaviour profiles (archetypes) are missing it builds them by itself, and you see the steps advance.',
      'Select a world: the explorer appears below with the list of customers. Search by id, name or archetype and page through.',
      'Pick a customer: you see its orders and shipments and, for each, the states it went through over time.',
      'When you are happy use **Release to tests** to put it in a pack.',
    ],
    concepts: [
      { term: 'Seed', text: 'The number the random generation starts from. Same seed, same world: tests are repeatable.' },
      { term: 'Synthetic customer', text: 'An invented customer (CUS-SYN-0007) based on an archetype. Name and e-mail are invented: no real person behind. See [[world]].' },
      { term: 'Archetypes', text: 'The behaviour profiles customers are drawn from. They are built by themselves at the first generation; the Archetypes page (in Advanced) shows them.' },
    ],
    effects: ['Generating a world does not make it available to tests: it has to go through the gate and be released in a pack.', 'More customers = bigger pack, but more varied tests.'],
    firstVisit: 'Here you create the invented customers that will populate the mock and browse them one by one.',
  },
  events: {
    title: 'Export events',
    purpose: 'Export the sanitized events of a range to analyse them in zone B (for example with process-mining tools). They are pseudonymous personal data: an advanced function, not needed to use the mock.',
    steps: ['Choose the range (or one of the quick buttons) and, if you want, a single service from the list.', 'Choose the format: OCEL 2.0 or JSON Lines.', 'Prepare the export and download the file: only you can download it.'],
    concepts: [{ term: 'Zone B', text: 'Where tt-core lives: pseudonymous data must not leave it. See [[zone-b]].' }],
    effects: ['Every export stays in the audit and is announced to the administrators’ webhooks (only format and size).'],
    firstVisit: 'Event-level export: use it only inside zone B.',
  },
};

export const journeyFieldsIt: Record<string, FieldHelp> = {
  'ct.postman': {
    title: 'Collezione Postman',
    meaning: 'Un file con una richiesta per ogni operazione del contratto, già con il corpo di esempio, e l’indirizzo base nella variabile `baseUrl`.',
    effect: 'Importalo in Postman o in Insomnia e imposta `baseUrl` sull’indirizzo del tuo mock: puoi provare il mock a mano senza scrivere nulla.',
    when: 'Quando vuoi provare il mock o il servizio da un client grafico. Postman e Insomnia importano anche direttamente il documento OpenAPI.',
    example: '`{{baseUrl}}/orders/:id` diventa `http://localhost:8480/__svc/shop-api/orders/1` con `baseUrl = http://localhost:8480/__svc/shop-api` (l’indirizzo del mock del servizio: la pagina Mock lo mette già nella collezione).',
  },
  'svc.twin': {
    title: 'Simula nel mock',
    meaning: 'Acceso: il mock risponde per questo servizio. Spento: la tua app continua a chiamare quello vero.',
    effect: 'Vale dal prossimo pacchetto: i test possono chiamare il mock senza la rete reale. Non cancella nulla: i contratti restano visibili.',
    term: 'twin-pack',
  },
};

export const journeyFieldsEn: Record<string, FieldHelp> = {
  'ct.postman': {
    title: 'Postman collection',
    meaning: 'A file with one request per operation of the contract, already with the example body, and the base address in the `baseUrl` variable.',
    effect: 'Import it in Postman or Insomnia and set `baseUrl` to the address of your mock: you can try the mock by hand without writing anything.',
    when: 'When you want to try the mock or the service from a graphical client. Postman and Insomnia also import the OpenAPI document directly.',
    example: '`{{baseUrl}}/orders/:id` becomes `http://localhost:8480/__svc/shop-api/orders/1` with `baseUrl = http://localhost:8480/__svc/shop-api` (the mock address of the service: the Mock page puts it in the collection).',
  },
  'svc.twin': {
    title: 'Simulate in the mock',
    meaning: 'On: the mock answers for this service. Off: your app keeps calling the real one.',
    effect: 'It applies from the next pack: tests can call the mock without the real network. It deletes nothing: the contracts stay visible.',
    term: 'twin-pack',
  },
};
