// Event assembly (event.md 1) and the OTLP/HTTP JSON logs body (event.md 4.2), written by hand.

import { CNum, writeCanonical, type OMap, type Out } from '../sanitizer/json.js';
import { MAX_EVENT_BYTES, composeCanonical, type NetError } from '../sanitizer/sanitizer.js';
import { SDK_VERSION, SOURCE_KIND } from '../version.js';

export interface EventMeta {
  policyId: string;
  policyVersion: number;
  policyHash: string;
  sourceId: string;
  dir: 'inbound' | 'outbound';
  tsMs: number;
  latencyMs: number;
  status?: number;
  netError?: NetError;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
}

const HEX32 = /^[0-9a-f]{32}$/;
const HEX16 = /^[0-9a-f]{16}$/;

/**
 * Full canonical event from the sanitizer output (a map or its serialized top-level members)
 * and the fields the source fills. Null if it exceeds 512 KiB (counted as sanitizer error).
 */
export function buildEvent(out: OMap | Map<string, string>, m: EventMeta): string | null {
  const parts = new Map<string, string>();
  const pre = isSerialized(out);
  for (const [k, v] of out) parts.set(k, pre ? (v as string) : writeCanonical(v as Out));
  const set = (k: string, v: Out) => parts.set(k, writeCanonical(v));
  set('schema', 'tt.http.exchange/v1');
  set('policy', new Map<string, Out>([['id', m.policyId], ['version', new CNum(String(m.policyVersion))], ['hash', m.policyHash]]));
  set('source', new Map<string, Out>([['kind', SOURCE_KIND], ['version', SDK_VERSION], ['id', m.sourceId]]));
  set('ts', new Date(m.tsMs).toISOString());
  set('latency_ms', new CNum(String(Math.max(0, Math.floor(m.latencyMs)))));
  set('dir', m.dir);
  if (m.netError) {
    set('net_error', m.netError);
    parts.delete('resp');
  } else if (typeof m.status === 'number' && m.status >= 100 && m.status <= 599) {
    set('status', new CNum(String(m.status)));
  } else {
    return null;
  }
  if (m.traceId && HEX32.test(m.traceId)) set('trace_id', m.traceId);
  if (m.spanId && HEX16.test(m.spanId)) set('span_id', m.spanId);
  if (m.parentSpanId && HEX16.test(m.parentSpanId)) set('parent_span_id', m.parentSpanId);
  const s = composeCanonical(parts);
  return s.length > MAX_EVENT_BYTES ? null : s;
}

const serialized = new WeakSet<object>();

/** Marks a map of already serialized members (Result.parts) for buildEvent. */
export function serializedParts(parts: Map<string, string>): Map<string, string> {
  serialized.add(parts);
  return parts;
}

function isSerialized(m: object): boolean {
  return serialized.has(m);
}

export interface QueuedEvent {
  /** Canonical event JSON. Empty when `record` already carries it (worker pipeline). */
  json: string;
  tsMs: number;
  traceId?: string;
  spanId?: string;
  policyHash: string;
  /** Ready-made OTLP logRecord (see makeRecord): the batch body is then only joined. */
  record?: string;
  /** Bytes charged to the export queue; defaults to json.length. */
  size?: number;
}

export interface Resource {
  serviceName: string;
  sourceId: string;
}

const attr = (key: string, value: string) => ({ key, value: { stringValue: value } });

const nanos = (ms: number): string => (ms > 0 ? String(Math.trunc(ms)) + '000000' : '0');

/**
 * OTLP/HTTP JSON logRecord for one event (event.md 4.2), written by hand: the canonical
 * event is escaped once, here, and the batch body is a join of ready-made records.
 */
export function makeRecord(e: QueuedEvent, observedMs: number): string {
  let r = '{"timeUnixNano":"' + nanos(e.tsMs) + '","observedTimeUnixNano":"' + nanos(observedMs)
    + '","severityNumber":9,"severityText":"INFO","eventName":"tt.http.exchange"';
  if (e.traceId && HEX32.test(e.traceId)) r += ',"traceId":"' + e.traceId + '"';
  if (e.spanId && HEX16.test(e.spanId)) r += ',"spanId":"' + e.spanId + '"';
  r += ',"attributes":[{"key":"tt.schema","value":{"stringValue":"tt.http.exchange/v1"}},{"key":"tt.policy.hash","value":{"stringValue":'
    + JSON.stringify(e.policyHash) + '}}],"body":{"stringValue":' + JSON.stringify(e.json) + '}}';
  return r;
}

/** OTLP/HTTP JSON body for a batch of events. */
export function otlpBody(events: QueuedEvent[], res: Resource, nowMs: number): string {
  let recs = '';
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (i > 0) recs += ',';
    recs += e.record ?? makeRecord(e, nowMs);
  }
  return '{"resourceLogs":[{"resource":' + JSON.stringify({
    attributes: [
      attr('service.name', res.serviceName),
      attr('tt.source.kind', SOURCE_KIND),
      attr('tt.source.version', SDK_VERSION),
      attr('tt.source.id', res.sourceId),
    ],
  }) + ',"scopeLogs":[{"scope":' + JSON.stringify({ name: 'traffic-twin', version: SDK_VERSION }) + ',"logRecords":[' + recs + ']}]}]}';
}
