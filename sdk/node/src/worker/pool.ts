// Main-thread side of the sanitizer worker pool: a small number of worker threads that turn
// wire exchanges into OTLP records off the request path. Bounded and drop-on-pressure by
// construction (the agent charges every posted job to its pending limits and drops when
// they are exceeded); fail-open for the app: a dead worker just means "sanitize inline".

import { Worker } from 'node:worker_threads';
import { join } from 'node:path';
import type { Sanitizer } from '../sanitizer/sanitizer.js';
import { debug } from '../log.js';
import { workerDir } from './dir.js';
import type { FromWorker, Job, ToWorker } from './protocol.js';

interface Batch { n: number; bytes: number }

interface W {
  worker: Worker;
  ready: boolean;
  dead: boolean;
  gens: Set<number>;
  batches: Batch[];
  syncs: Map<number, () => void>;
}

export interface PoolOptions {
  size: number;
  /** A batch came back: `stale` when it was posted before a discard(); recs/errs are then empty. */
  onOut: (b: Batch & { recs: string[]; errs: string[]; stale: boolean }) => void;
  /** A worker died with `lost` batches in flight. */
  onLost: (lost: Batch) => void;
}

export class SanitizerPool {
  private workers: W[] = [];
  private epoch = 0;
  private seq = 0;
  private nextGen = 1;
  private readonly gens = new WeakMap<Sanitizer, number>();
  private closed = false;

  constructor(private readonly o: PoolOptions) {}

  /** True when at least one worker is up. */
  get usable(): boolean {
    return !this.closed && this.workers.some((w) => w.ready && !w.dead);
  }

  /** Starts the first worker (idempotent). Never throws. */
  warm(): void {
    if (this.closed || this.workers.length > 0) return;
    this.spawn();
  }

  /** The policy of this sanitizer can be shipped to a worker. */
  canHandle(san: Sanitizer): boolean {
    if (!san.policy.bodyBytes) return false;
    const g = this.gens.get(san);
    return g === undefined || g > this.nextGen - 12;
  }

  private spawn(): W | null {
    try {
      const worker = new Worker(join(workerDir(), 'sanitizer-worker.js'), {
        // The parent's --import/--require preloads must not run again in the worker.
        execArgv: [],
        env: { TT_DISABLED: '1' },
        workerData: { ttSanitizer: true },
        resourceLimits: { maxOldGenerationSizeMb: 192 },
      });
      const w: W = { worker, ready: false, dead: false, gens: new Set(), batches: [], syncs: new Map() };
      worker.unref();
      worker.on('message', (m: FromWorker) => this.onMessage(w, m));
      const die = () => {
        if (w.dead) return;
        w.dead = true;
        w.ready = false;
        let n = 0;
        let bytes = 0;
        for (const b of w.batches) {
          n += b.n;
          bytes += b.bytes;
        }
        w.batches = [];
        for (const r of w.syncs.values()) r();
        w.syncs.clear();
        if (n > 0) this.o.onLost({ n, bytes });
        debug('sanitizer_worker', 'down');
      };
      worker.on('error', die);
      worker.on('exit', die);
      this.workers.push(w);
      return w;
    } catch {
      return null;
    }
  }

  private onMessage(w: W, m: FromWorker): void {
    if (m.t === 'ready') {
      w.ready = true;
    } else if (m.t === 'out') {
      const b = w.batches.shift();
      if (!b) return;
      const stale = m.epoch !== this.epoch;
      this.o.onOut({ ...b, recs: stale ? [] : m.recs, errs: stale ? [] : m.errs, stale });
    } else if (m.t === 'synced') {
      const f = w.syncs.get(m.seq);
      if (f) {
        w.syncs.delete(m.seq);
        f();
      }
    }
  }

  private pick(): W | null {
    let best: W | null = null;
    for (const w of this.workers) {
      if (!w.ready || w.dead) continue;
      if (!best || w.batches.length < best.batches.length) best = w;
    }
    // Grow (up to the configured size) only when the least busy worker already has a backlog.
    if ((!best || best.batches.length >= 2) && this.workers.filter((w) => !w.dead).length < this.o.size) this.spawn();
    return best;
  }

  /** Posts a batch of jobs. False (nothing posted) when no worker is ready. */
  post(items: Array<{ san: Sanitizer; job: Job }>, bytes: number, sourceId: string): boolean {
    const w = this.pick();
    if (!w) return false;
    try {
      const jobs: Job[] = [];
      for (const { san, job } of items) {
        let g = this.gens.get(san);
        if (g === undefined) {
          g = this.nextGen++;
          this.gens.set(san, g);
        }
        job.gen = g;
        jobs.push(job);
        if (!w.gens.has(g)) {
          const p = san.policy;
          const msg: ToWorker = {
            t: 'policy',
            gen: g,
            body: Uint8Array.from(p.bodyBytes!),
            hash: p.hash,
            kid: san.key.kid,
            key: Uint8Array.from(san.key.key),
            rateOverrideBp: san.options.rateOverrideBp ?? null,
          };
          w.worker.postMessage(msg);
          w.gens.add(g);
        }
      }
      w.worker.postMessage({ t: 'run', epoch: this.epoch, sourceId, jobs } satisfies ToWorker);
      w.batches.push({ n: jobs.length, bytes });
      return true;
    } catch {
      return false;
    }
  }

  /** Results of everything posted so far are ignored when they arrive (kill switch, revocation). */
  discard(): void {
    this.epoch++;
  }

  /** Resolves when every batch posted before this call has come back. */
  sync(): Promise<void> {
    const ps: Array<Promise<void>> = [];
    for (const w of this.workers) {
      if (w.dead || !w.ready || w.batches.length === 0) continue;
      const seq = ++this.seq;
      ps.push(new Promise<void>((r) => {
        w.syncs.set(seq, r);
        w.worker.postMessage({ t: 'sync', seq } satisfies ToWorker);
      }));
    }
    return Promise.all(ps).then(() => undefined);
  }

  terminate(): void {
    this.closed = true;
    for (const w of this.workers) {
      w.dead = true;
      for (const r of w.syncs.values()) r();
      void w.worker.terminate().catch(() => undefined);
    }
    this.workers = [];
  }
}
