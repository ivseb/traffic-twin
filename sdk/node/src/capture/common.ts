// Shared pieces of the capture hooks.

import type { Decision, NetError, Sanitizer } from '../sanitizer/sanitizer.js';
import { ExchangeCtx, newTraceId, otelActive } from './context.js';
import type { WireExchange, WireHeaders } from './wire.js';

/** A finished exchange, converted to sanitizer input lazily (off the request path, possibly in a worker thread). */
export interface RawExchange {
  sanitizer: Sanitizer;
  decision: Decision;
  wire: WireExchange;
  dir: 'inbound' | 'outbound';
  tsMs: number;
  latencyMs: number;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  status?: number;
  netError?: NetError;
  /** Bytes held by this exchange (queue accounting). */
  heldBytes: number;
}

/** What the capture hooks need from the agent. Every method must be cheap and never throw. */
export interface CaptureHost {
  /** Current sanitizer when capture is allowed, else null (fast path). */
  active(): Sanitizer | null;
  serviceName(): string;
  /** Header names (lowercase) needed for the inbound sampling decision. */
  decisionHeaders(): ReadonlySet<string>;
  /** Whether tt.s may be added to the baggage of a call to this url base (sanitizer.md 12). */
  mayPropagate(urlBase: string): boolean;
  /** Whether the policy asks for tt.s on some outbound calls (else unsampled calls need no per-call work). */
  propagates(): boolean;
  submit(raw: RawExchange): void;
  noteSeen(): void;
  noteSampled(): void;
  noteOverhead(ns: number): void;
  noteError(code: string): void;
}

/** True while the SDK itself creates a request (exporter, Fleet): such requests are never captured. */
export const internal = { depth: 0 };

/** HTTP agents owned by the SDK; requests through them are never captured. */
export const internalAgents = new WeakSet<object>();

export function runInternal<T>(fn: () => T): T {
  internal.depth++;
  try {
    return fn();
  } finally {
    internal.depth--;
  }
}

const lengthsOf = new WeakMap<ReadonlySet<string>, Set<number>>();

/** node:http rawHeaders (latin1 strings) to [name, bytes] pairs. */
export function rawPairs(raw: readonly string[] | undefined, only?: ReadonlySet<string>): Array<[string, Buffer]> {
  const out: Array<[string, Buffer]> = [];
  if (!raw) return out;
  let lens: Set<number> | undefined;
  if (only) {
    lens = lengthsOf.get(only);
    if (!lens) {
      lens = new Set();
      for (const k of only) lens.add(k.length);
      lengthsOf.set(only, lens);
    }
  }
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const n = raw[i]!;
    // Most headers cannot match by length alone: skip the lowercase copy for them.
    if (only && (!lens!.has(n.length) || !only.has(n.toLowerCase()))) continue;
    out.push([n, Buffer.from(raw[i + 1]!, 'latin1')]);
  }
  return out;
}

export function rawHeader(raw: readonly string[] | undefined, lower: string): string | undefined {
  if (!raw) return undefined;
  for (let i = 0; i + 1 < raw.length; i += 2) if (raw[i]!.length === lower.length && raw[i]!.toLowerCase() === lower) return raw[i + 1];
  return undefined;
}

/** Parses the serialized header block of an OutgoingMessage (`_header`). */
export function parseHeaderBlock(block: string): Array<[string, Buffer]> {
  const out: Array<[string, Buffer]> = [];
  const lines = block.split('\r\n');
  for (let i = 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (l === '') continue;
    const c = l.indexOf(':');
    if (c <= 0) continue;
    out.push([l.slice(0, c), Buffer.from(l.slice(c + 1), 'latin1')]);
  }
  return out;
}

/** Headers of an OutgoingMessage (server response or client request) as sent on the wire. */
export function outgoingHeaders(msg: {
  _header?: unknown;
  getHeaders?: () => Record<string, unknown>;
}): Array<[string, Buffer]> {
  if (typeof msg._header === 'string' && msg._header.length > 0) return parseHeaderBlock(msg._header);
  const out: Array<[string, Buffer]> = [];
  try {
    const h = msg.getHeaders ? msg.getHeaders() : {};
    for (const k of Object.keys(h)) {
      const v = h[k];
      for (const one of Array.isArray(v) ? v : [v]) {
        if (one === undefined || one === null) continue;
        out.push([k, Buffer.from(String(one), 'latin1')]);
      }
    }
  } catch {
    // ignore
  }
  return out;
}

/** Headers of an OutgoingMessage in wire form: the serialized block when Node has built it (parsed later), else a flat list. */
export function outgoingHeadersWire(msg: {
  _header?: unknown;
  getHeaders?: () => Record<string, unknown>;
}): WireHeaders {
  if (typeof msg._header === 'string' && msg._header.length > 0) return msg._header;
  const out: string[] = [];
  try {
    const h = msg.getHeaders ? msg.getHeaders() : {};
    for (const k of Object.keys(h)) {
      const v = h[k];
      for (const one of Array.isArray(v) ? v : [v]) {
        if (one === undefined || one === null) continue;
        out.push(k, String(one));
      }
    }
  } catch {
    // ignore
  }
  return out;
}

/** Splits a request target into raw path and raw query bytes (query undefined without "?"). */
export function splitTarget(target: string): { path: Buffer; query: Buffer | undefined } {
  let t = target;
  const abs = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/.exec(t);
  if (abs) t = t.slice(abs[0].length) || '/';
  const hash = t.indexOf('#');
  if (hash >= 0) t = t.slice(0, hash);
  const q = t.indexOf('?');
  if (q < 0) return { path: Buffer.from(t, 'latin1'), query: undefined };
  return { path: Buffer.from(t.slice(0, q), 'latin1'), query: Buffer.from(t.slice(q + 1), 'latin1') };
}

/** Maps a network error to the event enum (event.md). */
export function netErrorOf(err: unknown): NetError {
  const e = err as { code?: unknown; name?: unknown; message?: unknown; cause?: unknown } | null;
  const code = typeof e?.code === 'string' ? e.code : '';
  if (!code && e?.cause) return netErrorOf(e.cause);
  if (/TIMEOUT|ETIMEDOUT|ESOCKETTIMEDOUT/.test(code)) return 'timeout';
  if (code === 'ECONNRESET' || code === 'EPIPE' || code === 'UND_ERR_SOCKET' || code === 'ECONNABORTED') return 'reset';
  if (code === 'ECONNREFUSED') return 'refused';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NONAME' || code === 'EAI_FAIL') return 'dns';
  if (/^ERR_TLS|^ERR_SSL|CERT|UNABLE_TO_VERIFY|SELF_SIGNED|DEPTH_ZERO/.test(code)) return 'tls';
  return 'other';
}

/** Trace data for an outbound call, from the inbound context or OpenTelemetry. */
export function outboundTrace(ctx: ExchangeCtx | undefined): {
  traceId: string;
  parentSpanId?: string;
  samplingTraceId?: string;
} {
  if (ctx && !ctx.sampled) return { traceId: '' }; // inherited: not sampled, no ids needed
  const o = otelActive();
  if (ctx) {
    // Adopt the OpenTelemetry trace id when the inbound request carried none, so the
    // inbound and outbound events share the app's own trace.
    if (!ctx.traceKnown && o) {
      ctx.traceId = o.traceId;
      ctx.traceKnown = true;
    }
    return { traceId: ctx.traceId, parentSpanId: ctx.spanId };
  }
  if (o) return { traceId: o.traceId, parentSpanId: o.spanId || undefined, samplingTraceId: o.traceId };
  return { traceId: newTraceId() };
}

/** Monotonic clock in nanoseconds as a double (no BigInt allocation on the request path). */
export function hrNow(): number {
  return performance.now() * 1e6;
}

/** Adds tt.s to a baggage header value without touching the other members. */
export function withTtS(existing: string | undefined, sampled: boolean): string {
  const member = 'tt.s=' + (sampled ? '1' : '0');
  if (!existing || existing.trim() === '') return member;
  return existing + ',' + member;
}
