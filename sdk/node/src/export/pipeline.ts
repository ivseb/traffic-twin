// The off-path half of one exchange: wire form -> sanitizer -> canonical event -> OTLP
// logRecord. Used both inline (main thread) and by the sanitizer worker threads, so the
// output is the same bytes either way.

import { wireToExchange, type WireExchange } from '../capture/wire.js';
import type { Decision, NetError, Sanitizer } from '../sanitizer/sanitizer.js';
import { buildEvent, makeRecord, serializedParts } from './event.js';

/** Per-exchange facts the source fills in (event.md 1). */
export interface JobMeta {
  dir: 'inbound' | 'outbound';
  tsMs: number;
  latencyMs: number;
  status?: number;
  netError?: NetError;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
}

export type JobResult =
  | { record: string }
  | { err: 'event_too_large' | 'event_invalid_or_too_large' | 'sanitizer_error' }
  | null;

/** Null when the exchange turned out not to be sampled. Never throws. */
export function sanitizeToRecord(
  san: Sanitizer, wire: WireExchange, decision: Decision, meta: JobMeta, sourceId: string, nowMs: number,
): JobResult {
  try {
    const r = san.run(wireToExchange(wire), nowMs, decision);
    if (r.outcome === 'not_sampled') return null;
    if (r.outcome === 'too_large') return { err: 'event_too_large' };
    const p = san.policy;
    const json = buildEvent(serializedParts(r.parts), {
      policyId: p.policyId,
      policyVersion: p.version,
      policyHash: p.hash,
      sourceId,
      dir: meta.dir,
      tsMs: meta.tsMs,
      latencyMs: meta.latencyMs,
      status: meta.status,
      netError: meta.netError,
      traceId: meta.traceId,
      spanId: meta.spanId,
      parentSpanId: meta.parentSpanId,
    });
    if (json === null) return { err: 'event_invalid_or_too_large' };
    return { record: makeRecord({ json, tsMs: meta.tsMs, traceId: meta.traceId, spanId: meta.spanId, policyHash: p.hash }, Date.now()) };
  } catch {
    // 0: an internal error never produces an event.
    return { err: 'sanitizer_error' };
  }
}
