// Exchange context (event.md 1.1, sanitizer.md 12, ARCHITECTURE 3.2).
//
// An AsyncLocalStorage store binds outbound calls to the inbound exchange being served:
// same trace_id, inherited sampling decision. W3C traceparent is read from the inbound
// request. If the app uses OpenTelemetry, the active span context is only READ through
// @opentelemetry/api resolved from the app; this module never registers a provider,
// propagator or context manager and never injects traceparent.

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomFillSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { join } from 'node:path';

export interface ExchangeCtx {
  sampled: boolean;
  traceId: string;
  /** true when traceId came from the request (traceparent) or from OpenTelemetry. */
  traceKnown: boolean;
  spanId: string;
}

export const als = new AsyncLocalStorage<ExchangeCtx>();

/** Context of every unsampled exchange: nothing is recorded for it or for the calls it makes, so one shared frozen object serves. */
export const UNSAMPLED: ExchangeCtx = Object.freeze({ sampled: false, traceId: '', traceKnown: false, spanId: '' });

// Ids come from a pooled CSPRNG buffer: one system call per 256 ids instead of one per id.
const pool = Buffer.alloc(4096);
let poolOff = pool.length;

function nonZeroHex(bytes: number): string {
  for (;;) {
    if (poolOff + bytes > pool.length) {
      randomFillSync(pool);
      poolOff = 0;
    }
    const h = pool.toString('hex', poolOff, poolOff + bytes);
    poolOff += bytes;
    if (!/^0+$/.test(h)) return h;
  }
}

export const newTraceId = (): string => nonZeroHex(16);
export const newSpanId = (): string => nonZeroHex(8);

const TRACEPARENT = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$/;

/** W3C trace context: returns ids from a traceparent value, or null if invalid. */
export function parseTraceparent(v: string | undefined | null): { traceId: string; spanId: string } | null {
  if (typeof v !== 'string') return null;
  const m = TRACEPARENT.exec(v.trim());
  if (!m) return null;
  if (m[1] === 'ff' || (m[1] === '00' && m[5] !== undefined)) return null;
  if (/^0+$/.test(m[2]!) || /^0+$/.test(m[3]!)) return null;
  return { traceId: m[2]!, spanId: m[3]! };
}

interface OtelApi {
  trace: { getSpanContext(ctx: unknown): { traceId: string; spanId: string } | undefined };
  context: { active(): unknown };
  isSpanContextValid?: (sc: unknown) => boolean;
}

let otel: OtelApi | null | undefined;

/**
 * Loads @opentelemetry/api from the application's dependency tree, if present. Loading the
 * API package has no side effect; the SDK only calls read-only functions on it.
 */
export function loadOtelApi(): boolean {
  if (otel !== undefined) return otel !== null;
  otel = null;
  try {
    const req = createRequire(join(process.cwd(), '__traffic_twin_resolve__.js'));
    const mod = req(req.resolve('@opentelemetry/api')) as OtelApi & { default?: OtelApi };
    const api = mod.trace ? mod : mod.default;
    if (api && api.trace && typeof api.trace.getSpanContext === 'function' && api.context) otel = api;
  } catch {
    otel = null;
  }
  return otel !== null;
}

/** Active OpenTelemetry span context, if the app has one. Never throws. */
export function otelActive(): { traceId: string; spanId: string } | null {
  if (!otel) return null;
  try {
    const sc = otel.trace.getSpanContext(otel.context.active());
    if (!sc) return null;
    if (otel.isSpanContextValid && !otel.isSpanContextValid(sc)) return null;
    if (!/^[0-9a-f]{32}$/.test(sc.traceId) || /^0+$/.test(sc.traceId)) return null;
    return { traceId: sc.traceId, spanId: /^[0-9a-f]{16}$/.test(sc.spanId) ? sc.spanId : '' };
  } catch {
    return null;
  }
}
