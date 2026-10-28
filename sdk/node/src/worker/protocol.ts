// Messages between the main thread and a sanitizer worker (structured-clone friendly).

import type { WireExchange } from '../capture/wire.js';
import type { JobMeta } from '../export/pipeline.js';
import type { Decision } from '../sanitizer/sanitizer.js';

export interface Job {
  gen: number;
  decision: Decision;
  meta: JobMeta;
  wire: WireExchange;
}

export type ToWorker =
  | { t: 'policy'; gen: number; body: Uint8Array; hash: string; kid: string; key: Uint8Array; rateOverrideBp: number | null }
  | { t: 'run'; epoch: number; sourceId: string; jobs: Job[] }
  | { t: 'sync'; seq: number };

export type FromWorker =
  | { t: 'ready' }
  | { t: 'out'; epoch: number; recs: string[]; errs: string[] }
  | { t: 'synced'; seq: number };
