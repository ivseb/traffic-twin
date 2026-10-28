// Testi delle capacità generiche dell'ondata 1 (regole v1.6): «questa operazione è una lettura» nel dettaglio di
// un'operazione del contratto. Tenuti a parte come it-ux.ts.
export const itWave1 = {
  'w1.kind.title': 'Lettura o scrittura',
  'w1.kind.subtitle':
    'Per trovare gli oggetti e le loro regole traffic-twin deve sapere quali operazioni leggono e quali scrivono. Lo capisce dal comportamento, non dal metodo: una POST che restituisce solo oggetti già esistenti, sempre gli stessi a parità di richiesta, senza cambiarli, è una lettura.',
  'w1.kind.isRead': 'Questa operazione è una lettura',
  'w1.kind.choice.auto': 'Decide il traffico',
  'w1.kind.choice.read': 'È una lettura',
  'w1.kind.choice.write': 'È una scrittura',
  'w1.kind.now.read': 'Oggi è trattata come una lettura.',
  'w1.kind.now.write': 'Oggi è trattata come una scrittura.',
  'w1.kind.why.method': 'Lo dice il metodo ({method}).',
  'w1.kind.why.auto': 'Lo dice il comportamento: nell’ultima analisi restituiva solo oggetti già esistenti, sempre gli stessi a parità di richiesta.',
  'w1.kind.why.person': 'L’ha deciso {by} il {date}.',
  'w1.kind.next': 'La scelta vale dalla prossima analisi del traffico e resta nel registro di controllo.',
  'w1.kind.saved': 'Scelta salvata: vale dalla prossima analisi del traffico.',
  'w1.kind.readonly': 'Solo chi rivede le regole può cambiarla.',
  'w1.rules.removes': 'rimuove {entity}: sparisce dalle liste, la lettura per id risponde come per un oggetto rimosso',
  'w2.rules.copy': '{field} prende il valore che la chiamata manda in {ref}',
  'w2.rules.toggle': '{field} si inverte (vero ↔ falso) a ogni chiamata',
  'w2.rules.where': 'solo se {entity} ha ancora {cond}: una scrittura che l’ha già portato altrove vince',
} as const;

export type Wave1Key = keyof typeof itWave1;
