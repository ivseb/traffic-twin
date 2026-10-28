// Outbound capture for fetch / undici through its diagnostics channels
// (`undici:request:create`, `:headers`, `:bodyChunkSent`, `:bodyChunkReceived`,
// `:trailers`, `:error`). Body chunk channels exist in recent undici releases (Node 24);
// where they are missing, bodies the SDK cannot see are reported as unknown length
// (sanitizer.md 9.0: `trunc:size`), never guessed.
//
// Response chunks are observed before fetch removes the content-encoding, so the body is
// passed as encoded bytes (`*_body_decoded = false`) and decoded by the sanitizer.

import diagnostics_channel from 'node:diagnostics_channel';
import { BodyTap } from './body.js';
import { type CaptureHost, hrNow, internal, netErrorOf, outboundTrace, withTtS } from './common.js';
import { als, newSpanId } from './context.js';
import { UNREAD_BODY_TIMEOUT_MS } from './outbound-http.js';
import type { Decision, NetError, Sanitizer } from '../sanitizer/sanitizer.js';
import type { WireExchange } from './wire.js';

const EMPTY = Buffer.alloc(0);

interface UndiciRequest {
  origin?: unknown;
  method?: unknown;
  path?: unknown;
  headers?: unknown;
  body?: unknown;
  addHeader?: (k: string, v: string) => unknown;
}

interface UState {
  san: Sanitizer;
  decision: Decision;
  urlBase: string;
  method: string;
  path: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  t0: number;
  tsMs: number;
  reqTap: BodyTap;
  reqBodyKnown: boolean;
  resTap: BodyTap;
  reqHeaders?: string[];
  status?: number;
  respHeaders?: string[];
  netError?: NetError;
  done: boolean;
  timer?: NodeJS.Timeout;
  overheadNs: number;
}

const states = new WeakMap<object, UState>();

/** undici headers (flat array of Buffer/string, or a header block string) as flat latin1 [name, value, ...] strings. */
function headerFlat(h: unknown): string[] {
  const out: string[] = [];
  if (Array.isArray(h)) {
    for (let i = 0; i + 1 < h.length; i += 2) {
      const k = h[i];
      const v = h[i + 1];
      const name = Buffer.isBuffer(k) ? k.toString('latin1') : String(k);
      if (Array.isArray(v)) for (const one of v) out.push(name, Buffer.isBuffer(one) ? one.toString('latin1') : String(one));
      else out.push(name, Buffer.isBuffer(v) ? v.toString('latin1') : String(v));
    }
  } else if (typeof h === 'string') {
    for (const line of h.split('\r\n')) {
      const c = line.indexOf(':');
      if (c > 0) out.push(line.slice(0, c), line.slice(c + 1));
    }
  }
  return out;
}

function hasHeader(h: unknown, lower: string): string | undefined {
  const f = headerFlat(h);
  for (let i = 0; i + 1 < f.length; i += 2) if (f[i]!.toLowerCase() === lower) return f[i + 1]!;
  return undefined;
}

export function installOutboundUndici(host: CaptureHost): () => void {
  const subs: Array<[string, (m: unknown) => void]> = [];
  const on = (name: string, fn: (m: { request: UndiciRequest } & Record<string, unknown>) => void) => {
    const h = (m: unknown) => {
      try {
        fn(m as { request: UndiciRequest } & Record<string, unknown>);
      } catch {
        host.noteError('capture_undici');
      }
    };
    diagnostics_channel.subscribe(name, h);
    subs.push([name, h]);
  };
  // Whether this undici publishes body chunks is learnt from the first chunk seen.
  const seen = { sent: false, received: false };

  on('undici:request:create', ({ request }) => {
    if (internal.depth > 0) return;
    const t = hrNow();
    const san = host.active();
    if (!san) return;
    host.noteSeen();
    const ctx = als.getStore();
    if (ctx !== undefined && !ctx.sampled && !host.propagates()) {
      host.noteOverhead(hrNow() - t);
      return;
    }
    const origin = String(request.origin ?? '');
    const tr = outboundTrace(ctx);
    const decision = san.decide({ dir: 'outbound', req_headers: [], trace_id: tr.samplingTraceId, inherited: ctx?.sampled });
    if (host.mayPropagate(origin) && typeof request.addHeader === 'function') {
      const prev = hasHeader(request.headers, 'baggage');
      if (prev === undefined) request.addHeader('baggage', withTtS(undefined, decision.sampled));
      else request.addHeader('baggage', 'tt.s=' + (decision.sampled ? '1' : '0'));
    }
    if (!decision.sampled) {
      host.noteOverhead(hrNow() - t);
      return;
    }
    host.noteSampled();
    const limit = san.policy.captureLimit; // max(max_body_bytes, bodies.max_large_body_bytes) + 1 (sanitizer.md 9.0, 22.5)
    const st: UState = {
      san,
      decision,
      urlBase: origin,
      method: String(request.method ?? 'GET'),
      path: String(request.path ?? '/'),
      traceId: tr.traceId,
      spanId: newSpanId(),
      parentSpanId: tr.parentSpanId,
      t0: performance.now(),
      tsMs: Date.now(),
      reqTap: new BodyTap(limit),
      reqBodyKnown: false,
      resTap: new BodyTap(limit),
      done: false,
      overheadNs: 0,
    };
    const b = request.body;
    if (b === null || b === undefined) {
      st.reqBodyKnown = true;
    } else if (typeof b === 'string' || b instanceof Uint8Array) {
      st.reqTap.add(b);
      st.reqBodyKnown = true;
    }
    // Streamed bodies are counted by bodyChunkSent, when this undici publishes it.
    states.set(request as object, st);
    st.overheadNs = hrNow() - t;
  });

  on('undici:request:bodyChunkSent', ({ request, chunk }) => {
    seen.sent = true;
    const st = states.get(request as object);
    if (!st) return;
    const b = request.body;
    if (typeof b === 'string' || b instanceof Uint8Array) return; // already taken from the request object
    st.reqTap.add(chunk);
  });

  on('undici:request:headers', ({ request, response }) => {
    const st = states.get(request as object);
    if (!st) return;
    const r = response as { statusCode?: number; headers?: unknown };
    st.status = typeof r.statusCode === 'number' ? r.statusCode : undefined;
    st.respHeaders = headerFlat(r.headers);
    st.reqHeaders = headerFlat(request.headers);
    st.timer = setTimeout(() => complete(host, request, false), UNREAD_BODY_TIMEOUT_MS);
    st.timer.unref();
  });

  on('undici:request:bodyChunkReceived', ({ request, chunk }) => {
    seen.received = true;
    const st = states.get(request as object);
    if (st) st.resTap.add(chunk);
  });

  on('undici:request:trailers', ({ request }) => {
    const st = states.get(request as object);
    if (!st) return;
    st.resTap.ended = true;
    complete(host, request, true);
  });

  on('undici:request:error', ({ request, error }) => {
    const st = states.get(request as object);
    if (!st) return;
    if (st.status === undefined) st.netError = netErrorOf(error);
    complete(host, request, false);
  });

  // Without the received-chunk channel the response body is never visible: a response is
  // complete only if chunks were seen, the channel is known to work, or it declares no body.
  const respBodyVisible = (st: UState) => {
    if (st.resTap.total > 0 || seen.received) return true;
    const rh = st.respHeaders ?? [];
    for (let i = 0; i + 1 < rh.length; i += 2) if (rh[i]!.toLowerCase() === 'content-length') return rh[i + 1]!.trim() === '0';
    return false;
  };

  function complete(h: CaptureHost, request: UndiciRequest, ended: boolean): void {
    const st = states.get(request as object);
    if (!st || st.done) return;
    const t = hrNow();
    st.done = true;
    states.delete(request as object);
    if (st.timer) clearTimeout(st.timer);
    try {
      const latencyMs = Math.max(0, Math.floor(performance.now() - st.t0));
      const netError: NetError | undefined = st.status === undefined ? st.netError ?? 'other' : undefined;
      const consumed = ended && respBodyVisible(st);
      if (!st.reqBodyKnown && (st.reqTap.total > 0 || seen.sent)) st.reqBodyKnown = true;
      const reqHeaders = st.reqHeaders ?? headerFlat(request.headers);
      const reqBody = st.reqTap.bytes();
      const resBody = consumed ? st.resTap.bytes() : EMPTY;
      const wire: WireExchange = {
        dir: 'outbound',
        url_base: st.urlBase,
        method: st.method,
        target: st.path,
        inherited: st.decision.by === 'inherited' ? st.decision.sampled : undefined,
        req_headers: reqHeaders,
        req_body: reqBody,
        req_body_total: st.reqBodyKnown ? st.reqTap.total : 'unknown',
      };
      if (netError) {
        wire.net_error = netError;
      } else {
        wire.status = st.status;
        wire.resp_headers = st.respHeaders ?? [];
        wire.resp_body = resBody;
        wire.resp_body_total = st.resTap.total;
        wire.resp_body_consumed = consumed;
      }
      h.submit({
        sanitizer: st.san,
        decision: st.decision,
        dir: 'outbound',
        tsMs: st.tsMs,
        latencyMs,
        traceId: st.traceId,
        spanId: st.spanId,
        parentSpanId: st.parentSpanId,
        status: st.status,
        netError,
        heldBytes: reqBody.length + resBody.length,
        wire,
      });
    } catch {
      h.noteError('capture_undici_complete');
    }
    h.noteOverhead(st.overheadNs + (hrNow() - t));
  }

  return () => {
    for (const [name, fn] of subs) diagnostics_channel.unsubscribe(name, fn);
  };
}
