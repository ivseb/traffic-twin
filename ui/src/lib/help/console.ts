import type { FieldHelp, PageGuide } from './types';

// Guides of the pages for the users of an installed console (user guide, HMAC keys) and the fields they use.
// Merged into the help packs by index.svelte.ts.

export const consolePagesIt: Record<string, PageGuide> = {
  manual: {
    title: 'Manuale utente',
    purpose: 'Il manuale per chi usa traffic-twin già installato dal team piattaforma: dal collegamento del servizio al mock nei test.',
    steps: ['Scegli una sezione nell’indice a sinistra.', 'I comandi si copiano dai blocchi di codice; i valori (token, URL, chiavi pubbliche) li trovi nelle pagine della console indicate.'],
    concepts: [{ term: 'Console installata', text: 'Questo manuale non presuppone il repository: per la demo e lo sviluppo del prodotto c’è GETTING_STARTED.md.' }],
    effects: ['Leggere il manuale non cambia nulla.'],
    firstVisit: 'Il manuale passo per passo per collegare il tuo servizio e usare il mock.',
  },
  'hmac-keys': {
    title: 'Chiavi HMAC',
    purpose: 'Da dove viene la chiave HMAC delle sorgenti, come la distribuisce il team piattaforma e cosa succede se manca o non coincide con quella di keyguard.',
    steps: [
      'Sviluppatore: chiedi al team piattaforma il file della chiave e mettilo dove punta **TT_HMAC_KEY_FILE**.',
      'Team piattaforma: genera la chiave una volta con **tt keyguard genkey**, dalla a keyguard e distribuisci lo stesso file a tutte le sorgenti.',
      'Controlla in Sorgenti che nessuna sorgente mostri “Chiave HMAC mancante” o “chiave HMAC sconosciuta a keyguard”.',
    ],
    concepts: [
      { term: 'kid', text: 'Il nome della chiave (es. k1): deve essere quello di **hmac.kid** della policy.' },
      { term: 'Prova al contrario', text: 'Il gate ricalcola i token con le chiavi di keyguard: con una chiave diversa non può accorgersi di un valore reale.' },
    ],
    effects: ['Senza la chiave la sorgente non cattura nulla (l’applicazione non cambia).', 'Una chiave inventata in locale rende i dati non verificabili dal gate.'],
    firstVisit: 'La chiave HMAC è una sola per l’installazione e la distribuisce il team piattaforma.',
  },
};

export const consolePagesEn: Record<string, PageGuide> = {
  manual: {
    title: 'User guide',
    purpose: 'The guide for people who use traffic-twin as installed by the platform team: from connecting the service to the mock in the tests.',
    steps: ['Pick a section in the index on the left.', 'Copy the commands from the code blocks; the values (token, URLs, public keys) are on the console pages named there.'],
    concepts: [{ term: 'Installed console', text: 'This guide does not assume the repository: the demo and the development of the product are in GETTING_STARTED.md.' }],
    effects: ['Reading the guide changes nothing.'],
    firstVisit: 'The step-by-step guide to connect your service and use the mock.',
  },
  'hmac-keys': {
    title: 'HMAC keys',
    purpose: 'Where the HMAC key of the sources comes from, how the platform team distributes it and what happens when it is missing or differs from keyguard’s.',
    steps: [
      'Developer: ask the platform team for the key file and put it where **TT_HMAC_KEY_FILE** points.',
      'Platform team: generate the key once with **tt keyguard genkey**, give it to keyguard and distribute the same file to every source.',
      'Check on Sources that no source shows “HMAC key missing” or “HMAC key unknown to keyguard”.',
    ],
    concepts: [
      { term: 'kid', text: 'The name of the key (e.g. k1): it must be the policy’s **hmac.kid**.' },
      { term: 'Reverse proof', text: 'The gate recomputes the tokens with keyguard’s keys: with a different key it cannot notice a real value.' },
    ],
    effects: ['Without the key the source captures nothing (the application does not change).', 'A key made up locally makes the data impossible for the gate to verify.'],
    firstVisit: 'There is one HMAC key per installation and the platform team distributes it.',
  },
};

export const consoleFieldsIt: Record<string, FieldHelp> = {
  'status.waiting': { title: 'In attesa di policy', meaning: 'La sorgente è iscritta ma il suo gruppo non ha ancora una policy approvata: non cattura nulla, e non è un errore.', effect: 'Approva la bozza del gruppo in Sorgenti > Policy: in pochi secondi passa a “In salute”.' },
};
export const consoleFieldsEn: Record<string, FieldHelp> = {
  'status.waiting': { title: 'Waiting for a policy', meaning: 'The source is enrolled but its group has no approved policy yet: it captures nothing, and this is not a fault.', effect: 'Approve the group’s draft in Sources > Policy: within seconds it becomes “Healthy”.' },
};
