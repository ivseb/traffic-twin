// Testi delle capacità generiche dell'ondata 3 (regole v1.8): effetti sui record per chiave, contatori per chiave
// (unicità, tentativi, limiti di frequenza) nella catena di una regola. Tenuti a parte come it-wave1.ts.
export const itWave3 = {
  'w3.rules.targetKey': 'sul record per chiave di {entity}{fields}: se manca lo crea',
  'w3.rules.targetKey.fields': ' con {fields}',
  'w3.rules.limit.unique': 'una seconda chiamata con {key} risponde {status}: unicità vista nel traffico',
  'w3.rules.limit.count':
    'ogni chiamata della causa conta per {key}; con almeno {n} chiamate contate {window} la chiamata risponde {status}',
  'w3.rules.limit.window': 'negli ultimi {window}',
  'w3.rules.limit.session': 'nella sessione',
  'w3.rules.limit.keyUser': 'lo stesso cliente',
  'w3.rules.limit.keyRef': 'lo stesso valore di {ref}',
} as const;

export type Wave3Key = keyof typeof itWave3;
