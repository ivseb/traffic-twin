// Sanitizer worker thread: receives wire exchanges, returns ready-made OTLP logRecords.
// It runs exactly the code the main thread would run inline (export/pipeline.ts), so the
// events are byte-identical. It holds the HMAC key like the main thread does and has no
// network, file or Fleet access of its own: it only reads messages and posts results.

import { parentPort } from 'node:worker_threads';
import { sanitizeToRecord } from '../export/pipeline.js';
import { nodeToPlain, parseJson } from '../sanitizer/json.js';
import { Policy } from '../sanitizer/policy.js';
import { Sanitizer } from '../sanitizer/sanitizer.js';
import type { FromWorker, ToWorker } from './protocol.js';

const MAX_GENS = 16;
const sans = new Map<number, Sanitizer>();
const port = parentPort;

if (port) {
  const send = (m: FromWorker) => port.postMessage(m);
  port.on('message', (m: ToWorker) => {
    try {
      if (m.t === 'policy') {
        const p = new Policy(nodeToPlain(parseJson(m.body), true) as { [k: string]: never });
        p.hash = m.hash;
        sans.set(m.gen, new Sanitizer(p, { kid: m.kid, key: Buffer.from(m.key) }, { rateOverrideBp: m.rateOverrideBp }));
        while (sans.size > MAX_GENS) sans.delete(sans.keys().next().value as number);
      } else if (m.t === 'run') {
        const recs: string[] = [];
        const errs: string[] = [];
        const now = Date.now();
        for (const j of m.jobs) {
          const san = sans.get(j.gen);
          const r = san ? sanitizeToRecord(san, j.wire, j.decision, j.meta, m.sourceId, now) : { err: 'sanitizer_error' as const };
          if (r === null) continue;
          if ('record' in r) recs.push(r.record);
          else errs.push(r.err);
        }
        send({ t: 'out', epoch: m.epoch, recs, errs });
      } else if (m.t === 'sync') {
        send({ t: 'synced', seq: m.seq });
      }
    } catch {
      // A malformed message must not kill the worker; the jobs it carried are lost.
      if (m.t === 'run') send({ t: 'out', epoch: m.epoch, recs: [], errs: m.jobs.map(() => 'sanitizer_error') });
    }
  });
  send({ t: 'ready' });
}
