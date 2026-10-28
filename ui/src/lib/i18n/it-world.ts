// Testi dei mondi senza regole usabili (laboratorio: due team con un «order» ciascuno). Tenuti a parte
// per non toccare i dizionari grandi.
export const itWorld = {
  'err.no_usable_rules': 'Nessuna regola approvata di questo gruppo si può usare: il mondo sarebbe vuoto (nessun oggetto, nessuna regola) e il mock non simulerebbe niente di quello che hai approvato.',
  'err.no_usable_rules.out_of_scope': 'La regola {rule} usa {services}, che non è un servizio di questo gruppo.',
  'err.no_usable_rules.unusable': 'La regola {rule} non si può usare: {detail}.',
  'err.no_usable_rules.fix': 'Di solito succede quando un altro team ha un oggetto con lo stesso nome: in Regole fai «Cerca nuove regole» e approva le regole che il miner propone di nuovo per il gruppo.',
  'world.excluded': 'Il mondo {id} è stato generato senza {n, plural, one {# regola del gruppo} other {# regole del gruppo}}: {rules}. Servono servizi che non sono di questo gruppo: {services}.',
  'world.failedTitle': 'Il mondo non è stato generato',
  'mk.step.code.no_usable_rules': 'nessuna regola approvata del gruppo si può usare ({rules}; servizi mancanti: {services})',
  'mk.step.code.rules_excluded': '{customers} clienti inventati, {entities} oggetti; lasciate fuori le regole {rules} (usano {services})',
  'mk.err.no_usable_rules': 'Il mondo del gruppo sarebbe vuoto: nessuna delle sue regole approvate si può usare (il dettaglio è nel passo del mondo). In Regole fai «Cerca nuove regole», approva le regole proposte per il gruppo e riprova.',
} as const;

export type WorldKey = keyof typeof itWorld;
