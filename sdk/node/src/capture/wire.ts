// Wire form of a captured exchange: plain strings, numbers and byte arrays only, so it can
// be posted to a sanitizer worker thread (structured clone) or converted in place.
//
// The capture hooks fill this in with the least possible work (they keep references to the
// strings Node already built); the conversion to the sanitizer's `Exchange` (header
// buffers, request-target split, header-block parsing) happens later, off the request
// path, and on the worker thread when one is used.

import type { Exchange, NetError } from '../sanitizer/sanitizer.js';
import { parseHeaderBlock, splitTarget } from './common.js';

/** Flat [name, value, name, value ...] latin1 strings, or a serialized HTTP header block. */
export type WireHeaders = string[] | string;

export interface WireExchange {
  dir: 'inbound' | 'outbound';
  service_name?: string;
  url_base?: string;
  method: string;
  /** Request target as received/sent (path and optional query). */
  target: string;
  framework?: string;
  framework_route?: string;
  trace_id?: string;
  inherited?: boolean;
  req_headers: WireHeaders;
  req_body: Uint8Array;
  req_body_total?: number | 'unknown';
  req_body_consumed?: boolean;
  status?: number;
  net_error?: NetError;
  resp_headers?: WireHeaders;
  resp_body?: Uint8Array;
  resp_body_total?: number | 'unknown';
  resp_body_consumed?: boolean;
}

function pairs(h: WireHeaders | undefined): Array<[string, Buffer]> {
  if (h === undefined) return [];
  if (typeof h === 'string') return parseHeaderBlock(h);
  const out: Array<[string, Buffer]> = [];
  for (let i = 0; i + 1 < h.length; i += 2) out.push([h[i]!, Buffer.from(h[i + 1]!, 'latin1')]);
  return out;
}

/** Zero-copy view of body bytes that arrived through a message port or the tap. */
function asBuffer(b: Uint8Array | undefined): Buffer | undefined {
  if (b === undefined) return undefined;
  return Buffer.isBuffer(b) ? b : Buffer.from(b.buffer, b.byteOffset, b.byteLength);
}

/** Wire exchange to the sanitizer's input (sanitizer.md 1). */
export function wireToExchange(w: WireExchange): Exchange {
  const { path, query } = splitTarget(w.target);
  const ex: Exchange = {
    dir: w.dir,
    method: w.method,
    raw_path: path,
    raw_query: query,
    req_headers: pairs(w.req_headers),
    req_body: asBuffer(w.req_body),
  };
  if (w.service_name !== undefined) ex.service_name = w.service_name;
  if (w.url_base !== undefined) ex.url_base = w.url_base;
  if (w.framework_route !== undefined) {
    ex.framework = w.framework ?? 'express';
    ex.framework_route = w.framework_route;
  }
  if (w.trace_id !== undefined) ex.trace_id = w.trace_id;
  if (w.inherited !== undefined) ex.inherited = w.inherited;
  if (w.req_body_total !== undefined) ex.req_body_total = w.req_body_total;
  if (w.req_body_consumed !== undefined) ex.req_body_consumed = w.req_body_consumed;
  if (w.net_error) {
    ex.net_error = w.net_error;
  } else {
    ex.status = w.status;
    ex.resp_headers = pairs(w.resp_headers);
    ex.resp_body = asBuffer(w.resp_body);
    if (w.resp_body_total !== undefined) ex.resp_body_total = w.resp_body_total;
    if (w.resp_body_consumed !== undefined) ex.resp_body_consumed = w.resp_body_consumed;
  }
  return ex;
}
