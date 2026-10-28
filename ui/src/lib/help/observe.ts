import type { FieldHelp, GlossaryEntry, PageGuide } from './types';

// Help of the observe phase (spec v1.6, docs/spec/policy.md §7): connecting a source needs no policy and no approval;
// only changes that open values wait for people. These texts come last and replace the entries of the same id.

export const observePagesIt: Record<string, PageGuide> = {
  onboarding: {
    title: 'Collega un servizio',
    purpose: 'Colleghi un’app in tre passi, senza scrivere una policy e senza approvazioni: all’inizio esce solo la **struttura** delle chiamate e gli identificativi diventano sigle da soli. Vedi [[observe-phase]].',
    steps: [
      '**Collega**: scegli come arriva il traffico (un SDK nel linguaggio dell’app, il proxy di uscita, OBI, l’annotazione Kubernetes o un file HAR) e scrivi il nome del servizio.',
      '**Avvia**: copia il comando già compilato con il tuo [[enrollment-token|token di iscrizione]] ed eseguilo dove gira l’app. La chiave HMAC resta sulla macchina.',
      '**In ascolto**: guarda arrivare gli eventi, i servizi e gli host scoperti. Dopo poche centinaia di chiamate compare «Policy Osserva attivata alle HH:MM» con l’elenco degli identificativi mascherati.',
      'Solo se ti servono valori in chiaro (stati, codici) o fasce di importi apri **Avanzate: modifica la policy**: quelle modifiche richiedono un’approvazione.',
    ],
    concepts: [
      { term: 'Fase Osserva', text: 'I primi giorni: escono endpoint, nomi e tipi dei campi, status e latenza, mai i valori. Vedi [[observe-phase]].' },
      { term: 'Policy Osserva', text: 'La versione che la console crea da sola: gli identificativi (id, uuid, *_id, parametri dei percorsi) escono come sigle [[hmac]], l’utente come sigla del `sub` del JWT o dell’header che i dati indicano come utente.' },
      { term: 'Apre valori', text: 'Solo le modifiche che lasciano uscire valori in chiaro o in fasce chiedono un’approvazione. Vedi [[opens-values]].' },
    ],
    effects: [
      'Generare il token non cambia nulla in produzione: diventa efficace solo quando lo usi su una sorgente.',
      'La policy di partenza e la policy Osserva sono firmate da keyguard senza persone perché non aprono valori; ogni firma è nell’audit con attore «sistema».',
      'Le scelte in Avanzate che lasciano uscire valori (keep, bucket) restano bozze finché le approvazioni non bastano: fino ad allora la sorgente usa la versione precedente.',
    ],
    firstVisit: 'Colleghi un servizio in tre passi: nessuna policy da scrivere, nessuna approvazione per cominciare.',
  },
};

export const observePagesEn: Record<string, PageGuide> = {
  onboarding: {
    title: 'Connect a service',
    purpose: 'You connect an app in three steps, without writing a policy and without approvals: at first only the **structure** of the calls leaves, and identifiers become tokens by themselves. See [[observe-phase]].',
    steps: [
      '**Connect**: choose how the traffic arrives (an SDK in the app’s language, the egress proxy, OBI, the Kubernetes annotation or a HAR file) and type the service name.',
      '**Start**: copy the command already filled in with your [[enrollment-token|enrollment token]] and run it where the app runs. The HMAC key stays on the machine.',
      '**Listening**: watch the events, the services and the hosts arrive. After a few hundred calls “Observe policy activated at HH:MM” shows, with the list of the masked identifiers.',
      'Only if you need values in clear (states, codes) or amounts in bands, open **Advanced: edit the policy**: those changes need an approval.',
    ],
    concepts: [
      { term: 'Observe phase', text: 'The first days: endpoints, field names and types, status and latency leave, never the values. See [[observe-phase]].' },
      { term: 'Observe policy', text: 'The version the console makes by itself: identifiers (id, uuid, *_id, path parameters) leave as [[hmac]] tokens, the user as a token of the JWT `sub` or of the header the data point to as the user.' },
      { term: 'Opens values', text: 'Only changes that let values out in clear or in bands ask for an approval. See [[opens-values]].' },
    ],
    effects: [
      'Creating the token changes nothing in production: it takes effect only when a source uses it.',
      'The starter policy and the observe policy are signed by keyguard without people because they open no values; every signature is in the audit with the “system” actor.',
      'Choices in Advanced that let values out (keep, bucket) stay drafts until enough approvals: until then the source keeps the previous version.',
    ],
    firstVisit: 'Connect a service in three steps: no policy to write, no approval to start.',
  },
};

export const observeFieldsIt: Record<string, FieldHelp> = {
  'obs.sampling': {
    title: 'Campionamento',
    meaning: 'La quota degli utenti di cui la sorgente cattura il traffico (sampling.rate). Il campionamento è per utente: si vede tutto il percorso di un cliente campionato.',
    effect: 'Un valore o una regola escono solo se almeno k = 20 utenti distinti li hanno prodotti, e la console ne vuole il doppio: al 10% servono circa 400 utenti nel traffico. Finché la policy non lascia uscire valori, alzarlo non apre dati e si applica subito.',
    default: '10%.',
    when: '100% per una prova con dati inventati o per un servizio con pochi utenti; 5% per un servizio con moltissimi utenti.',
    term: 'k-anonymity',
  },
  'obs.identity': {
    title: 'Identità dell’utente',
    meaning: 'La parte della richiesta da cui la sorgente legge chi è l’utente (identity.subject): un header di qualsiasi nome, il claim di un JWT (di solito sub) o un cookie. La console la riconosce dai dati, non dai nomi: un buon candidato ha molti valori distinti ma meno delle chiamate (lo stesso utente ripete le chiamate), la forma di un identificativo e compare su quasi tutte le chiamate; il nome è solo un indizio debole. Scarta gli id di richiesta (un valore nuovo a ogni chiamata), i tenant (pochi valori), i cookie e le credenziali.',
    effect: 'Il valore non esce mai: esce una sigla [[hmac]] stabile per utente, che serve al campionamento per utente e a contare gli utenti distinti (k). Un header che non è una credenziale, o un claim del JWT, si applica subito senza approvazioni (resta nell’audit); un cookie o un header che sembra una credenziale (token, secret, session, key…) senza claim crea una bozza da approvare. Scelta da una persona, la console non la cambia più da sola.',
    default: 'Il sub del JWT bearer se c’è, altrimenti il candidato rilevato con il punteggio più alto (almeno 60/100); nessuno se non c’è un candidato convincente.',
    when: 'Cambiala se il rilevato non è l’utente (per esempio un id di dispositivo) o se nessun candidato è stato scelto. I parametri della query non possono indicare l’utente.',
    term: 'sampling',
  },
  'obs.masked': {
    title: 'Identificativi mascherati',
    meaning: 'I campi che la policy attiva trasforma in sigle (hmac): parametri dei percorsi, id, uuid, campi *_id e simili.',
    effect: 'Escono come sigle stabili: lo stesso id dà la stesso sigla anche in chiamate diverse, così la console collega una risorsa creata e poi letta, senza mai vedere il valore.',
    default: 'Scelti dalla console nella fase Osserva.',
    term: 'observe-phase',
  },
  'obs.auto': {
    title: 'Mascheramento automatico',
    meaning: 'Se è acceso, la console aggiunge da sola alla policy del gruppo il mascheramento (hmac) degli identificativi che vede per la prima volta e l’identità automatica dell’utente. Non tocca mai un campo su cui una persona ha già deciso.',
    effect: 'Acceso: i servizi e i campi nuovi vengono mascherati senza che nessuno debba ricordarselo; ogni versione è firmata da keyguard e registrata nell’audit. Spento: la console non deriva più nulla da sola; le versioni già firmate restano, i campi nuovi restano scartati finché una persona non li sceglie in «Rivedi in blocco».',
    default: 'Acceso.',
    when: 'Spegnilo solo se il team vuole decidere a mano ogni campo della policy.',
    term: 'observe-phase',
  },
  'obs.classify': {
    title: 'Si applica subito o serve un’approvazione',
    meaning: 'La console confronta la modifica con la policy attiva: se lascia uscire valori in chiaro o in fasce «apre valori».',
    effect: '«Non apre dati»: keyguard firma subito, senza persone (l’audit lo registra). «Apre valori»: nasce una bozza che richiede le approvazioni configurate (default 2; un amministratore può approvare da solo con una motivazione).',
    term: 'opens-values',
  },
  'obs.bulk': {
    title: 'Rivedi in blocco',
    meaning: 'I campi osservati raggruppati per tipo (identificativi, stati e codici, numeri, date, dati personali, altri), con una sola azione per gruppo.',
    effect: 'Le azioni diventano una sola versione della policy: se nessuna apre valori si applica subito, altrimenti è una bozza da approvare. I dati personali restano sempre drop.',
    term: 'opens-values',
  },
  'obs.group': {
    title: 'Gruppo',
    meaning: 'Il gruppo di sorgenti (di solito un’applicazione) di cui rivedi la policy.',
    effect: 'Vedi solo i campi del traffico di quel gruppo, mai quelli di altri team.',
  },
  'policy.action': {
    title: 'Azione sul campo',
    meaning: '**drop**: esce solo la forma. **keep**: esce il valore (solo enum). **hmac**: esce una sigla stabile. **bucket**: esce la fascia di un numero.',
    effect: 'drop e hmac non aprono dati e si applicano subito. keep e bucket aprono valori: servono le approvazioni, e solo dopo quei campi escono dalla sorgente.',
    default: 'drop.',
    term: 'opens-values',
  },
  'wiz.sampling': {
    title: 'Campionamento',
    meaning: 'La quota degli utenti di cui la policy cattura il traffico (sampling.rate).',
    effect: 'Più è alta, prima si vedono abbastanza utenti distinti (k = 20, la console ne vuole 40). Finché nessun valore esce in chiaro, alzarlo non apre dati e si applica subito.',
    default: '10%; 100% per una prova con dati inventati.',
    term: 'sampling',
  },
};

export const observeFieldsEn: Record<string, FieldHelp> = {
  'obs.sampling': {
    title: 'Sampling',
    meaning: 'The share of the users whose traffic the source captures (sampling.rate). Sampling is per user: the whole journey of a sampled customer is seen.',
    effect: 'A value or a rule leaves only when at least k = 20 distinct users produced it, and the console wants twice that: at 10% about 400 users in the traffic are needed. While the policy lets no value out, raising it opens no data and applies at once.',
    default: '10%.',
    when: '100% for a trial with invented data or a service with few users; 5% for a service with very many users.',
    term: 'k-anonymity',
  },
  'obs.identity': {
    title: 'User identity',
    meaning: 'The part of the request the source reads the user from (identity.subject): a header of any name, a JWT claim (usually sub) or a cookie. The console recognises it from the data, not from names: a good candidate has many distinct values but fewer than calls (the same user repeats calls), the shape of an identifier and shows on almost every call; the name is only a weak hint. It leaves out request ids (a new value on every call), tenants (few values), cookies and credentials.',
    effect: 'The value never leaves: a stable [[hmac]] token per user does, used for per-user sampling and to count distinct users (k). A header that is not a credential, or a JWT claim, applies at once without approvals (it stays in the audit); a cookie, or a header that looks like a credential (token, secret, session, key...) without a claim, creates a draft to approve. Once a person chose it, the console never changes it by itself.',
    default: 'The bearer JWT sub when there is one, else the detected candidate with the highest score (at least 60/100); none when no candidate is convincing.',
    when: 'Change it when the detected one is not the user (a device id, for instance) or when none was chosen. Query parameters cannot carry the user.',
    term: 'sampling',
  },
  'obs.masked': {
    title: 'Masked identifiers',
    meaning: 'The fields the active policy turns into tokens (hmac): path parameters, id, uuid, *_id fields and the like.',
    effect: 'They leave as stable tokens: the same id gives the same token in different calls too, so the console links a resource created and then read, without ever seeing the value.',
    default: 'Chosen by the console in the observe phase.',
    term: 'observe-phase',
  },
  'obs.auto': {
    title: 'Automatic masking',
    meaning: 'When on, the console adds to the group’s policy by itself the masking (hmac) of identifiers it sees for the first time and the automatic user identity. It never touches a field a person already decided on.',
    effect: 'On: new services and fields get masked without anyone having to remember; every version is signed by keyguard and recorded in the audit. Off: the console derives nothing by itself; versions already signed stay, new fields stay dropped until a person picks them in “Bulk review”.',
    default: 'On.',
    when: 'Turn it off only if the team wants to decide every field of the policy by hand.',
    term: 'observe-phase',
  },
  'obs.classify': {
    title: 'Applies at once or needs an approval',
    meaning: 'The console compares the change with the active policy: if it lets values out in clear or in bands it “opens values”.',
    effect: '“Opens no data”: keyguard signs at once, without people (the audit records it). “Opens values”: a draft is made that needs the configured approvals (default 2; an administrator can approve alone with a reason).',
    term: 'opens-values',
  },
  'obs.bulk': {
    title: 'Bulk review',
    meaning: 'The observed fields grouped by kind (identifiers, states and codes, numbers, dates, personal data, others), with one action per group.',
    effect: 'The actions become a single policy version: if none opens values it applies at once, otherwise it is a draft to approve. Personal data always stays drop.',
    term: 'opens-values',
  },
  'obs.group': {
    title: 'Group',
    meaning: 'The group of sources (usually one application) whose policy you review.',
    effect: 'You see only the fields of that group’s traffic, never those of other teams.',
  },
  'policy.action': {
    title: 'Action on the field',
    meaning: '**drop**: only the shape leaves. **keep**: the value leaves (enums only). **hmac**: a stable token leaves. **bucket**: the band of a number leaves.',
    effect: 'drop and hmac open no data and apply at once. keep and bucket open values: approvals are needed, and only then those fields leave the source.',
    default: 'drop.',
    term: 'opens-values',
  },
  'wiz.sampling': {
    title: 'Sampling',
    meaning: 'The share of the users whose traffic the policy captures (sampling.rate).',
    effect: 'The higher it is, the sooner enough distinct users are seen (k = 20, the console wants 40). While no value leaves in clear, raising it opens no data and applies at once.',
    default: '10%; 100% for a trial with invented data.',
    term: 'sampling',
  },
};

export const observeGlossaryIt: Record<string, GlossaryEntry> = {
  'observe-phase': {
    term: 'Fase Osserva',
    short: 'Il collegamento senza policy né approvazioni: esce la struttura, gli identificativi come sigle.',
    long: 'Appena colleghi un servizio la policy di partenza è già attiva: endpoint, nomi e tipi dei campi, status e latenza, mai i valori. Dopo poche centinaia di chiamate (o 15 minuti) la console crea da sola la **policy Osserva**: gli identificativi escono come sigle hmac e l’utente come sigla del `sub` del JWT o dell’header che i dati indicano come utente (qualunque nome: molti valori che si ripetono per utente). keyguard la firma senza persone perché non apre valori; l’audit la registra con attore «sistema». Quando una persona firma un’altra modifica, la console smette di aggiungere da sola.',
    example: '«orderId» nella risposta di POST /orders → sigla «order».',
    see: ['opens-values', 'hmac', 'discovery'],
  },
  'opens-values': {
    term: 'Apre valori',
    short: 'Una modifica che lascia uscire valori in chiaro o in fasce: solo queste chiedono approvazioni.',
    long: 'Aprono valori: un `keep`, un `bucket` (o fasce più fini), un utente letto da un cookie o da un altro claim, parole o host in chiaro scelti a mano, il ritorno dalla modalità stretta degli host, più traffico o un gruppo in più su una policy che lascia già uscire valori, il ripristino di una versione precedente. Tutto il resto (drop, hmac, dichiarare servizi, ridurre la cattura) non apre dati e si applica subito. keyguard ricalcola il verdetto da solo prima di firmare.',
    see: ['two-person', 'observe-phase', 'keep', 'bucket'],
  },
  discovery: {
    term: 'Modalità di scoperta',
    short: 'Finestra temporanea in cui si contano i valori distinti dei campi, senza vederli.',
    long: 'Serve nella fase Osserva per riconoscere gli identificativi e proporre la policy: la sorgente manda token corti da cui l’intake stima la cardinalità. Dura al più 7 giorni (72 ore per default) e non apre valori.',
    see: ['policy', 'observe-phase'],
  },
  'auto-words': {
    term: 'Parole automatiche (auto_words)',
    short: 'I segmenti di percorso in minuscolo restano in chiaro, per qualche giorno.',
    long: 'Nei percorsi come /orders/{id}/items le parole “orders” e “items” non sono dati personali e restano leggibili; gli identificativi vengono resi anonimi. Fanno parte della fase Osserva, durano al più 7 giorni e non chiedono approvazioni.',
    example: '/customers/mario@x.it/orders → /customers/{drop:str:email}/orders.',
  },
  'two-person': {
    term: 'Regola delle due persone',
    short: 'Le modifiche che aprono valori vogliono più approvazioni.',
    long: 'Per default servono 2 approvazioni di persone diverse, di cui almeno una non è chi ha proposto. Il numero (1 o 2) è deciso in keyguard. Le modifiche che non aprono valori (drop, hmac, ridurre la cattura) si applicano subito, senza approvazioni. Un amministratore può sempre approvare da solo, con una motivazione.',
    see: ['keyguard', 'admin-override', 'opens-values'],
  },
};

export const observeGlossaryEn: Record<string, GlossaryEntry> = {
  'observe-phase': {
    term: 'Observe phase',
    short: 'Connecting without policy or approvals: the structure leaves, identifiers as tokens.',
    long: 'As soon as you connect a service the starter policy is already active: endpoints, field names and types, status and latency, never the values. After a few hundred calls (or 15 minutes) the console makes the **observe policy** by itself: identifiers leave as hmac tokens and the user as a token of the JWT `sub` or of the header the data point to as the user (any name: many values repeated per user). keyguard signs it without people because it opens no values; the audit records it with the “system” actor. Once a person signs another change, the console stops adding by itself.',
    example: '“orderId” in the response of POST /orders → token “order”.',
    see: ['opens-values', 'hmac', 'discovery'],
  },
  'opens-values': {
    term: 'Opens values',
    short: 'A change that lets values out in clear or in bands: only these ask for approvals.',
    long: 'These open values: a `keep`, a `bucket` (or finer bands), a user read from a cookie or another claim, words or hosts in clear chosen by hand, leaving the strict hosts mode, more traffic or one more group on a policy that already lets values out, restoring an earlier version. Everything else (drop, hmac, declaring services, capturing less) opens no data and applies at once. keyguard recomputes the verdict by itself before signing.',
    see: ['two-person', 'observe-phase', 'keep', 'bucket'],
  },
  discovery: {
    term: 'Discovery mode',
    short: 'A timed window in which the distinct values of the fields are counted, without seeing them.',
    long: 'It is used in the observe phase to recognise identifiers and propose the policy: the source sends short tokens from which the intake estimates the cardinality. It lasts at most 7 days (72 hours by default) and opens no values.',
    see: ['policy', 'observe-phase'],
  },
  'auto-words': {
    term: 'Automatic words (auto_words)',
    short: 'Lowercase path segments stay in clear, for a few days.',
    long: 'In paths like /orders/{id}/items the words “orders” and “items” are not personal data and stay readable; identifiers are anonymized. They are part of the observe phase, last at most 7 days and need no approval.',
    example: '/customers/mario@x.it/orders → /customers/{drop:str:email}/orders.',
  },
  'two-person': {
    term: 'Two-person rule',
    short: 'Changes that open values need more approvals.',
    long: 'By default 2 approvals from different people are needed, at least one not the proposer. The number (1 or 2) is decided in keyguard. Changes that open no values (drop, hmac, capturing less) apply at once, without approvals. An administrator can always approve alone, with a reason.',
    see: ['keyguard', 'admin-override', 'opens-values'],
  },
};
