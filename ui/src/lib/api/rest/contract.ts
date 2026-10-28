// OpenAPI 3.1 contract of tt-core (GET /api/v1/contracts/{service}, with the
// x-tt-* extensions of docs/spec/pack.md section 4) -> operations and schemas
// of the UI.

import type { LinkedFields, OperationDetail, OperationSummary, ResponseContract, SchemaNode, ServiceInfo, ServiceSummary, StatusStat } from '../types';
import type { WireServiceEntry } from './wire';
import { exactBaseUrl, hostPatternOfService } from '../../hosts';
import { graphqlOf } from '../../graphql';
import { soapOf } from '../../soap';

export type OpenApiDoc = Record<string, unknown>;
type Obj = Record<string, unknown>;

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);

/** Default of the contract engine (contract.Config.MinSamples). */
export const DEFAULT_MIN_SAMPLES = 20;

function typeOf(s: Obj): SchemaNode['type'] {
  const raw = s.type;
  const list = (Array.isArray(raw) ? raw : raw ? [raw] : []).filter((x): x is string => typeof x === 'string' && x !== 'null');
  const first = list[0];
  if (first === 'object' || first === 'array' || first === 'string' || first === 'integer' || first === 'number' || first === 'boolean') return first;
  if (isObj(s.properties)) return 'object';
  if (isObj(s.items)) return 'array';
  return 'string';
}

function xValue(s: Obj): Obj | undefined {
  return isObj(s['x-tt-value']) ? s['x-tt-value'] : undefined;
}

function formatOf(s: Obj): string | undefined {
  if (typeof s.format === 'string') return s.format;
  const xv = xValue(s);
  switch (xv?.kind) {
    case 'id':
      return 'tt-token';
    case 'bucket':
      return 'bucket';
    case 'shape':
      return typeof xv.format === 'string' ? xv.format : undefined;
    default:
      return undefined;
  }
}

function enumOf(s: Obj): string[] | undefined {
  const e = Array.isArray(s.enum) ? s.enum : Array.isArray(xValue(s)?.enum) ? (xValue(s)?.enum as unknown[]) : undefined;
  return e?.map((x) => String(x));
}

/** Schema -> tree node. `presence` is decided by the parent (required / x-tt-presence). */
export function schemaNode(name: string, schema: unknown, presence = 1): SchemaNode {
  const s = isObj(schema) ? schema : {};
  const type = typeOf(s);
  const node: SchemaNode = { name, type, presence, format: formatOf(s), enumValues: enumOf(s) };
  const fieldsOf = (o: Obj): SchemaNode[] => {
    const props = isObj(o.properties) ? o.properties : {};
    const required = new Set(Array.isArray(o.required) ? o.required.map(String) : []);
    return Object.entries(props).map(([k, v]) => schemaNode(k, v, required.has(k) ? 1 : num(isObj(v) ? v['x-tt-presence'] : undefined, 1)));
  };
  if (type === 'object') {
    const kids = fieldsOf(s);
    if (kids.length) node.children = kids;
  } else if (type === 'array' && isObj(s.items)) {
    const items = s.items;
    node.itemType = typeOf(items);
    if (typeOf(items) === 'object') {
      const kids = fieldsOf(items);
      if (kids.length) node.children = kids;
    } else {
      node.format = node.format ?? formatOf(items);
      node.enumValues = node.enumValues ?? enumOf(items);
    }
  }
  if (node.format === undefined) delete node.format;
  if (node.enumValues === undefined) delete node.enumValues;
  return node;
}

/** A value of a combination: the keep value, or a band {min, max} as "50–100", "< 0", "≥ 250". */
function linkedValue(v: unknown): string {
  if (isObj(v)) {
    const lo = typeof v.min === 'number' ? v.min : undefined;
    const hi = typeof v.max === 'number' ? v.max : undefined;
    if (lo !== undefined && hi !== undefined) return `${lo}–${hi}`;
    if (hi !== undefined) return `< ${hi}`;
    if (lo !== undefined) return `≥ ${lo}`;
    return '?';
  }
  return String(v);
}

/** The linked fields (x-tt-dependencies) of a body schema and of its nested objects and list items. */
export function linkedFields(schema: unknown, doc?: OpenApiDoc, at = '', depth = 0): LinkedFields[] {
  let s = isObj(schema) ? schema : {};
  if (typeof s.$ref === 'string' && doc && s.$ref.startsWith('#/')) {
    let cur: unknown = doc;
    for (const part of s.$ref.slice(2).split('/')) cur = isObj(cur) ? cur[part.replace(/~1/g, '/').replace(/~0/g, '~')] : undefined;
    s = isObj(cur) ? cur : {};
  }
  if (depth > 6) return [];
  const out: LinkedFields[] = [];
  for (const d of Array.isArray(s['x-tt-dependencies']) ? s['x-tt-dependencies'] : []) {
    if (!isObj(d) || !Array.isArray(d.fields) || !Array.isArray(d.combinations)) continue;
    const fields = d.fields.map(String);
    const combos = d.combinations
      .filter(isObj)
      .filter((c) => Array.isArray(c.values) && c.values.length === fields.length)
      .map((c) => ({ values: (c.values as unknown[]).map(linkedValue), atLeast: num(c.at_least) }));
    if (combos.length) out.push({ at, fields, combos, partial: d.partial === true });
  }
  if (isObj(s.items)) out.push(...linkedFields(s.items, doc, `${at}[]`, depth + 1));
  for (const [k, v] of Object.entries(isObj(s.properties) ? s.properties : {})) out.push(...linkedFields(v, doc, at ? `${at}.${k}` : k, depth + 1));
  return out;
}

function pickContent(content: unknown): { schema?: unknown; examples?: Obj } | undefined {
  if (!isObj(content)) return undefined;
  const key = Object.keys(content).find((k) => k.includes('json')) ?? Object.keys(content)[0];
  const item = key ? content[key] : undefined;
  return isObj(item) ? { schema: item.schema, examples: isObj(item.examples) ? item.examples : undefined } : undefined;
}

const iso = (d: unknown): string => {
  const s = typeof d === 'string' ? d : '';
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s}T00:00:00Z` : s;
};

interface RawOp {
  key: string;
  method: string;
  path: string;
  op: Obj;
}

function rawOps(doc: OpenApiDoc): RawOp[] {
  const out: RawOp[] = [];
  const paths = isObj(doc.paths) ? doc.paths : {};
  for (const [path, item] of Object.entries(paths)) {
    if (!isObj(item)) continue;
    for (const m of METHODS) {
      const op = item[m];
      if (isObj(op)) out.push({ key: `${m.toUpperCase()} ${path}`, method: m.toUpperCase(), path, op });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

export function operationSummaries(service: string, doc: OpenApiDoc, fewSamples: (op: string, calls: number) => boolean): OperationSummary[] {
  return rawOps(doc).map((r) => summary(service, r, fewSamples));
}

function summary(service: string, r: RawOp, fewSamples: (op: string, calls: number) => boolean): OperationSummary {
  const obs = isObj(r.op['x-tt-observed']) ? r.op['x-tt-observed'] : {};
  const lat = isObj(r.op['x-tt-latency-ms']) ? r.op['x-tt-latency-ms'] : {};
  const calls = num(obs.calls);
  const responses = isObj(r.op.responses) ? r.op.responses : {};
  const statuses: StatusStat[] = Object.entries(responses)
    .filter(([code]) => /^\d{3}$/.test(code))
    .map(([code, resp]) => {
      const freq = isObj(resp) ? num(resp['x-tt-frequency']) : 0;
      const pc = isObj(resp) ? pickContent(resp.content) : undefined;
      const first = pc?.examples ? Object.keys(pc.examples)[0] : undefined;
      return { status: Number(code), frequency: freq, calls: Math.round(freq * calls), example: first };
    })
    .sort((a, b) => a.status - b.status);
  return {
    service,
    op: r.key,
    method: r.method,
    pathTemplate: r.path,
    calls,
    firstSeen: iso(obs.first_seen),
    lastSeen: iso(obs.last_seen),
    latencyMs: { p50: num(lat.p50), p95: num(lat.p95), p99: num(lat.p99) },
    statuses,
    fewSamples: fewSamples(r.key, calls),
    entity: typeof r.op['x-tt-entity'] === 'string' ? r.op['x-tt-entity'] : undefined,
    ...(graphqlOf(r.op) ? { graphql: graphqlOf(r.op) } : {}),
    ...(soapOf(r.method, r.path, r.op) ? { soap: soapOf(r.method, r.path, r.op) } : {}),
  };
}

export function operationDetail(service: string, doc: OpenApiDoc, op: string, fewSamples: (op: string, calls: number) => boolean): OperationDetail | undefined {
  const r = rawOps(doc).find((x) => x.key === op);
  if (!r) return undefined;
  const base = summary(service, r, fewSamples);
  const body = isObj(r.op.requestBody) ? pickContent(r.op.requestBody.content) : undefined;
  const responses: ResponseContract[] = Object.entries(isObj(r.op.responses) ? r.op.responses : {})
    .filter(([code]) => /^\d{3}$/.test(code))
    .map(([code, resp]) => {
      const rs = isObj(resp) ? resp : {};
      const pc = pickContent(rs.content);
      const examples = Object.entries(pc?.examples ?? {}).map(([name, ex]) => ({ name, value: isObj(ex) ? ex.value : ex }));
      const linked = linkedFields(pc?.schema, doc);
      return { status: Number(code), frequency: num(rs['x-tt-frequency']), schema: schemaNode('$', pc?.schema), examples, ...(linked.length ? { linked } : {}) };
    })
    .sort((a, b) => a.status - b.status);
  const requestLinked = body ? linkedFields(body.schema, doc) : [];
  return { ...base, request: body ? schemaNode('$', body.schema) : undefined, ...(requestLinked.length ? { requestLinked } : {}), responses, latencySeries: [] };
}

/**
 * Host data of a service entry. `host:<pattern>` entries carry their pattern; a base URL is shown only when the
 * pattern names exactly one host (never `https://unlisted`, `https://{*}.x` or an IP class). A declared service
 * (kind outbound-policy) gets its host from the hosts registry (`declaredHosts`: service name -> host of its base).
 */
export function hostInfoOf(service: string, declaredHosts?: { get(service: string): string | undefined }): { hostPattern?: string; baseUrl?: string } {
  const pattern = hostPatternOfService(service) ?? declaredHosts?.get(service);
  if (!pattern) return {};
  const baseUrl = exactBaseUrl(pattern);
  return { hostPattern: pattern, ...(baseUrl ? { baseUrl } : {}) };
}

export function serviceInfoOf(e: WireServiceEntry, twin: boolean, sources: number, declaredHosts?: { get(service: string): string | undefined }): ServiceInfo {
  const external = e.kind !== 'inbound';
  return {
    name: e.service,
    ...(e.group !== undefined ? { group: e.group } : {}),
    kind: external ? 'external' : 'own',
    ...(external ? hostInfoOf(e.service, declaredHosts) : {}),
    operations: e.ops,
    calls: e.calls,
    twin,
    lastSeen: e.last_seen,
    sources,
  };
}

/** Aggregates of one service from its operations (call-weighted error rate and latency). */
export function aggregate(ops: OperationSummary[]): Pick<ServiceSummary, 'operations' | 'calls' | 'errorRate' | 'latencyMs'> {
  const calls = ops.reduce((a, o) => a + o.calls, 0);
  const err = ops.reduce((a, o) => a + o.statuses.filter((s) => s.status >= 400).reduce((b, s) => b + s.calls, 0), 0);
  const w = (k: 'p50' | 'p95') => (calls ? Math.round(ops.reduce((a, o) => a + o.latencyMs[k] * o.calls, 0) / calls) : 0);
  return { operations: ops.length, calls, errorRate: calls ? err / calls : 0, latencyMs: { p50: w('p50'), p95: w('p95') } };
}

/** Pretty JSON of the operations touched by a diff, for the side-by-side view. */
export function fragmentOf(doc: OpenApiDoc, ops: string[]): string {
  const paths = isObj(doc.paths) ? doc.paths : {};
  const keep = new Set(ops);
  const out: Record<string, Record<string, unknown>> = {};
  for (const r of rawOps(doc)) {
    if (keep.size === 0 || keep.has(r.key)) (out[r.path] ??= {})[r.method.toLowerCase()] = (paths[r.path] as Obj)[r.method.toLowerCase()];
  }
  return JSON.stringify(out, null, 2);
}
