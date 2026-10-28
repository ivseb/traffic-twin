import type { Wave3Key } from './it-wave3';

// English texts of the wave 3 generic capabilities (rules v1.8, see it-wave3.ts).
export const enWave3: Record<Wave3Key, string> = {
  'w3.rules.targetKey': 'on the keyed record of {entity}{fields}: created when missing',
  'w3.rules.targetKey.fields': ' with {fields}',
  'w3.rules.limit.unique': 'a second call with {key} answers {status}: uniqueness seen in the traffic',
  'w3.rules.limit.count': 'every call of the cause counts for {key}; with at least {n} counted calls {window} the call answers {status}',
  'w3.rules.limit.window': 'in the last {window}',
  'w3.rules.limit.session': 'in the session',
  'w3.rules.limit.keyUser': 'the same customer',
  'w3.rules.limit.keyRef': 'the same value of {ref}',
};
