// Inbound capture for node:http / node:https servers through diagnostics_channel
// (`http.server.request.start`, `http.server.response.finish`). No global patching: the
// only wrappers are installed on the request/response objects of sampled exchanges, they
// are synchronous and they never change arguments, return values or timing.

import diagnostics_channel from 'node:diagnostics_channel';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { BodyTap } from './body.js';
import {
  type CaptureHost, hrNow, outgoingHeadersWire, rawHeader, rawPairs,
} from './common.js';
import { als, newSpanId, newTraceId, otelActive, parseTraceparent, UNSAMPLED, type ExchangeCtx } from './context.js';
import type { Decision, Sanitizer } from '../sanitizer/sanitizer.js';
import type { WireExchange } from './wire.js';

const EMPTY = Buffer.alloc(0);

interface InState {
  san: Sanitizer;
  decision: Decision;
  ctx: ExchangeCtx;
  parentSpanId?: string;
  traceForSampling?: string;
  t0: number;
  tsMs: number;
  reqTap: BodyTap;
  resTap: BodyTap;
  overheadNs: number;
}

const kState = Symbol('traffic-twin.inbound');

type Req = IncomingMessage & { [kState]?: InState; push: (chunk: unknown, enc?: unknown) => boolean; route?: { path?: unknown }; baseUrl?: unknown };
type Res = ServerResponse & { [kState]?: InState; _header?: unknown };

/** Wraps `push` of an IncomingMessage to tee body bytes (de-chunked by the parser). */
export function tapPush(stream: { push: (chunk: unknown, enc?: unknown) => boolean }, tap: BodyTap): void {
  const orig = stream.push;
  stream.push = function push(this: unknown, chunk: unknown, enc?: unknown) {
    if (chunk === null) tap.ended = true;
    else tap.add(chunk, enc);
    // eslint-disable-next-line prefer-rest-params
    return orig.apply(this, arguments as unknown as [unknown, unknown]);
  };
}

/** Wraps write/end of an OutgoingMessage to tee body bytes. */
export function tapWrites(
  msg: { write: (...a: unknown[]) => boolean; end: (...a: unknown[]) => unknown },
  tap: BodyTap,
  onEnd?: () => void,
): void {
  const ow = msg.write;
  const oe = msg.end;
  msg.write = function write(this: unknown, chunk: unknown, enc?: unknown) {
    if (typeof chunk !== 'function') tap.add(chunk, typeof enc === 'string' ? enc : undefined);
    // eslint-disable-next-line prefer-rest-params
    return ow.apply(this, arguments as unknown as unknown[]);
  };
  msg.end = function end(this: unknown, chunk?: unknown, enc?: unknown) {
    if (typeof chunk !== 'function') tap.add(chunk, typeof enc === 'string' ? enc : undefined);
    tap.ended = true;
    if (onEnd) {
      try {
        onEnd();
      } catch {
        // ignore
      }
    }
    // eslint-disable-next-line prefer-rest-params
    return oe.apply(this, arguments as unknown as unknown[]);
  };
}

export function installInbound(host: CaptureHost): () => void {
  const onStart = (message: unknown) => {
    const t = hrNow();
    const { request, response } = message as { request: Req; response: Res };
    try {
      start(host, request, response, t);
    } catch {
      host.noteError('capture_inbound_start');
    }
  };
  const onFinish = (message: unknown) => {
    const { request, response } = message as { request: Req; response: Res };
    // Unsampled exchanges (the vast majority at low rates) carry no state: nothing to do.
    if (response[kState] === undefined) return;
    const t = hrNow();
    try {
      finish(host, request, response, t);
    } catch {
      host.noteError('capture_inbound_finish');
    }
  };
  diagnostics_channel.subscribe('http.server.request.start', onStart);
  diagnostics_channel.subscribe('http.server.response.finish', onFinish);
  return () => {
    diagnostics_channel.unsubscribe('http.server.request.start', onStart);
    diagnostics_channel.unsubscribe('http.server.response.finish', onFinish);
  };
}

function start(host: CaptureHost, req: Req, res: Res, t: number): void {
  const san = host.active();
  if (!san) return;
  host.noteSeen();
  const raw = req.rawHeaders;
  const tph = rawHeader(raw, 'traceparent');
  const tp = tph === undefined ? null : parseTraceparent(tph);
  const service = host.serviceName();
  const decision = san.decideRaw(service, raw, tp?.traceId) ?? san.decide({
    dir: 'inbound',
    service_name: service,
    req_headers: rawPairs(raw, host.decisionHeaders()),
    trace_id: tp?.traceId,
  });
  if (!decision.sampled) {
    // Nothing is recorded for this exchange or for the calls it makes (their decision is
    // inherited): no tees, no wrappers, no ids; only the shared "not sampled" context.
    als.enterWith(UNSAMPLED);
    host.noteOverhead(hrNow() - t);
    return;
  }
  const ctx: ExchangeCtx = { sampled: true, traceId: tp?.traceId ?? newTraceId(), traceKnown: !!tp, spanId: newSpanId() };
  // Bind the rest of this request's async work (handlers, outbound calls) to ctx.
  als.enterWith(ctx);
  host.noteSampled();
  const limit = san.policy.captureLimit; // max(max_body_bytes, bodies.max_large_body_bytes) + 1 (sanitizer.md 9.0, 22.5)
  const st: InState = {
    san,
    decision,
    ctx,
    parentSpanId: tp?.spanId,
    t0: performance.now(),
    tsMs: Date.now(),
    reqTap: new BodyTap(limit),
    resTap: new BodyTap(limit),
    overheadNs: 0,
  };
  tapPush(req, st.reqTap);
  // res.end() runs inside the handler, where an OpenTelemetry server span (if any) is active:
  // adopt its trace id when the request carried none, so the event joins the app's trace.
  tapWrites(res as unknown as { write: (...a: unknown[]) => boolean; end: (...a: unknown[]) => unknown }, st.resTap, () => {
    if (st.ctx.traceKnown) return;
    const o = otelActive();
    if (o) {
      st.ctx.traceId = o.traceId;
      st.ctx.traceKnown = true;
    }
  });
  res[kState] = st;
  st.overheadNs = hrNow() - t;
}

function finish(host: CaptureHost, req: Req, res: Res, t: number): void {
  const st = res[kState];
  if (!st) return;
  res[kState] = undefined;
  const latencyMs = Math.max(0, Math.floor(performance.now() - st.t0));
  // 9.0: a body the app did not read to the end is "not consumed"; an empty body is complete.
  const reqConsumed = req.readableEnded || (req.complete && st.reqTap.total === 0);
  const status = res.statusCode;
  const method = req.method ?? '';
  const noBody = method === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200);
  const target = req.url ?? '/';
  const respHeaders = outgoingHeadersWire(res as unknown as { _header?: unknown; getHeaders?: () => Record<string, unknown> });
  // Express: only routes defined directly on the app carry their complete template.
  let route: string | undefined;
  if (req.route && typeof req.route.path === 'string' && (req.baseUrl === '' || req.baseUrl === undefined)) route = req.route.path;
  const reqBody = reqConsumed ? st.reqTap.bytes() : EMPTY;
  const resBody = noBody ? EMPTY : st.resTap.bytes();
  const resTotal = noBody ? 0 : st.resTap.total;
  const resEnded = noBody || st.resTap.ended;
  const wire: WireExchange = {
    dir: 'inbound',
    service_name: host.serviceName(),
    method,
    target,
    trace_id: st.ctx.traceKnown ? st.ctx.traceId : undefined,
    req_headers: req.rawHeaders,
    req_body: reqBody,
    req_body_total: st.reqTap.total,
    req_body_consumed: reqConsumed,
    status,
    resp_headers: respHeaders,
    resp_body: resBody,
    resp_body_total: resEnded ? resTotal : 'unknown',
  };
  if (route !== undefined) {
    wire.framework = 'express';
    wire.framework_route = route;
  }
  host.submit({
    sanitizer: st.san,
    decision: st.decision,
    dir: 'inbound',
    tsMs: st.tsMs,
    latencyMs,
    traceId: st.ctx.traceId,
    spanId: st.ctx.spanId,
    parentSpanId: st.parentSpanId,
    status,
    heldBytes: reqBody.length + resBody.length,
    wire,
  });
  host.noteOverhead(st.overheadNs + (hrNow() - t));
}
