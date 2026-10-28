// Outbound capture for node:http / node:https clients through diagnostics_channel
// (`http.client.request.start`, `http.client.response.finish`, `http.client.request.error`).

import diagnostics_channel from 'node:diagnostics_channel';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { BodyTap } from './body.js';
import {
  type CaptureHost, hrNow, internal, internalAgents, netErrorOf, outboundTrace, outgoingHeadersWire, withTtS,
} from './common.js';
import { als, newSpanId } from './context.js';
import { tapPush, tapWrites } from './inbound.js';
import type { Decision, NetError, Sanitizer } from '../sanitizer/sanitizer.js';
import type { WireExchange } from './wire.js';

const EMPTY = Buffer.alloc(0);

/** How long an unread response body is waited for before the exchange is closed as not consumed. */
export const UNREAD_BODY_TIMEOUT_MS = 60_000;

interface OutState {
  san: Sanitizer;
  decision: Decision;
  urlBase: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  t0: number;
  tsMs: number;
  reqTap: BodyTap;
  resTap: BodyTap;
  response?: IncomingMessage;
  netError?: NetError;
  done: boolean;
  /** The hook ran after the app had already written: the request body is not fully known. */
  late: boolean;
  overheadNs: number;
  timer?: NodeJS.Timeout;
}

const kState = Symbol('traffic-twin.outbound');
const kSeen = Symbol('traffic-twin.outbound.seen');
type Req = ClientRequest & { [kState]?: OutState; [kSeen]?: true; protocol?: string; _header?: unknown };

export function installOutboundHttp(host: CaptureHost): () => void {
  // `http.client.request.created` (Node >= 22.12 / 23.2) fires in the ClientRequest
  // constructor, before the app can write or end: body capture and the optional baggage
  // member work there. On older runtimes `start` fires once a socket is assigned, which may
  // be after end(): the body is then reported as unknown and nothing is injected.
  const onCreated = (message: unknown) => {
    if (internal.depth > 0) return;
    const t = hrNow();
    try {
      const request = (message as { request: Req & { agent?: object } }).request;
      if (request[kSeen]) return;
      request[kSeen] = true;
      if (request.agent && internalAgents.has(request.agent)) return;
      start(host, request, t);
    } catch {
      host.noteError('capture_outbound_start');
    }
  };
  const onStart = onCreated;
  const onResponse = (message: unknown) => {
    try {
      const { request, response } = message as { request: Req; response: IncomingMessage };
      const st = request[kState];
      if (!st || st.done) return;
      st.response = response;
      tapPush(response as unknown as { push: (c: unknown, e?: unknown) => boolean }, st.resTap);
      response.once('end', () => complete(host, request, true));
      response.once('close', () => complete(host, request, false));
      st.timer = setTimeout(() => complete(host, request, false), UNREAD_BODY_TIMEOUT_MS);
      st.timer.unref();
    } catch {
      host.noteError('capture_outbound_response');
    }
  };
  const onError = (message: unknown) => {
    try {
      const { request, error } = message as { request: Req; error: unknown };
      const st = request[kState];
      if (st && !st.response) st.netError = netErrorOf(error);
    } catch {
      // ignore
    }
  };
  diagnostics_channel.subscribe('http.client.request.created', onCreated);
  diagnostics_channel.subscribe('http.client.request.start', onStart);
  diagnostics_channel.subscribe('http.client.response.finish', onResponse);
  diagnostics_channel.subscribe('http.client.request.error', onError);
  return () => {
    diagnostics_channel.unsubscribe('http.client.request.created', onCreated);
    diagnostics_channel.unsubscribe('http.client.request.start', onStart);
    diagnostics_channel.unsubscribe('http.client.response.finish', onResponse);
    diagnostics_channel.unsubscribe('http.client.request.error', onError);
  };
}

/** Authority when the request has no Host header: the host option, bracketed if it is an IPv6 literal. */
function fallbackAuthority(request: Req): string {
  const h = String(request.host ?? '');
  return h.includes(':') && !h.startsWith('[') ? '[' + h + ']' : h;
}

function start(host: CaptureHost, request: Req, t: number): void {
  const san = host.active();
  if (!san) return;
  host.noteSeen();
  const ctx = als.getStore();
  if (ctx !== undefined && !ctx.sampled && !host.propagates()) {
    // Inherited "not sampled" and nothing to inject: no work at all for this call.
    host.noteOverhead(hrNow() - t);
    return;
  }
  const hostHeader = request.getHeader('host');
  const proto = typeof request.protocol === 'string' ? request.protocol : 'http:';
  // The host as the client sees it (spec v1.5, point 9): the Host header as is, a trailing dot and
  // an `xn--` form untouched, IPv6 with its brackets. No IDN conversion, no dot stripping.
  const urlBase = proto + '//' + (typeof hostHeader === 'string' ? hostHeader : fallbackAuthority(request));
  const tr = outboundTrace(ctx);
  const decision = san.decide({ dir: 'outbound', req_headers: [], trace_id: tr.samplingTraceId, inherited: ctx?.sampled });
  if (host.mayPropagate(urlBase) && !request.headersSent) {
    try {
      const prev = request.getHeader('baggage');
      request.setHeader('baggage', withTtS(typeof prev === 'string' ? prev : Array.isArray(prev) ? prev.join(',') : undefined, decision.sampled));
    } catch {
      // headers already flushed: leave the request untouched
    }
  }
  if (!decision.sampled) {
    host.noteOverhead(hrNow() - t);
    return;
  }
  host.noteSampled();
  const limit = san.policy.captureLimit; // max(max_body_bytes, bodies.max_large_body_bytes) + 1 (sanitizer.md 9.0, 22.5)
  const st: OutState = {
    san,
    decision,
    urlBase,
    traceId: tr.traceId,
    spanId: newSpanId(),
    parentSpanId: tr.parentSpanId,
    t0: performance.now(),
    tsMs: Date.now(),
    reqTap: new BodyTap(limit),
    resTap: new BodyTap(limit),
    done: false,
    late: typeof request._header === 'string' || request.writableEnded || request.writableLength > 0,
    overheadNs: 0,
  };
  tapWrites(request as unknown as { write: (...a: unknown[]) => boolean; end: (...a: unknown[]) => unknown }, st.reqTap);
  request[kState] = st;
  // 'close' never changes the app's error handling (unlike an 'error' listener).
  request.once('close', () => {
    if (!st.response) complete(host, request, false);
  });
  st.overheadNs = hrNow() - t;
}

function complete(host: CaptureHost, request: Req, ended: boolean): void {
  const st = request[kState];
  if (!st || st.done) return;
  const t = hrNow();
  st.done = true;
  request[kState] = undefined;
  if (st.timer) clearTimeout(st.timer);
  try {
    const latencyMs = Math.max(0, Math.floor(performance.now() - st.t0));
    const res = st.response;
    const netError: NetError | undefined = res ? undefined : st.netError ?? 'other';
    const status = res?.statusCode;
    const resConsumed = ended && st.resTap.ended;
    const reqBody = st.reqTap.bytes();
    const resBody = res && resConsumed ? st.resTap.bytes() : EMPTY;
    const wire: WireExchange = {
      dir: 'outbound',
      url_base: st.urlBase,
      method: request.method ?? 'GET',
      target: request.path ?? '/',
      inherited: st.decision.by === 'inherited' ? st.decision.sampled : undefined,
      req_headers: outgoingHeadersWire(request as unknown as { _header?: unknown; getHeaders?: () => Record<string, unknown> }),
      req_body: reqBody,
      req_body_total: st.late ? 'unknown' : st.reqTap.total,
    };
    if (netError) {
      wire.net_error = netError;
    } else {
      wire.status = status;
      wire.resp_headers = res!.rawHeaders;
      wire.resp_body = resBody;
      wire.resp_body_total = st.resTap.total;
      wire.resp_body_consumed = resConsumed;
    }
    host.submit({
      sanitizer: st.san,
      decision: st.decision,
      dir: 'outbound',
      tsMs: st.tsMs,
      latencyMs,
      traceId: st.traceId,
      spanId: st.spanId,
      parentSpanId: st.parentSpanId,
      status,
      netError,
      heldBytes: reqBody.length + resBody.length,
      wire,
    });
  } catch {
    host.noteError('capture_outbound_complete');
  }
  host.noteOverhead(st.overheadNs + (hrNow() - t));
}
