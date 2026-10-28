// Builds an OpenAPI 3.1 document (with the x-tt-* extensions of docs/spec/pack.md §4)
// from the observed operations. Used by the mock adapter; the real API returns the
// document that tt-core builds for the pack.

import type { OperationDetail, SchemaNode, ServiceInfo } from '../types';

const KNOWN_FORMATS = new Set(['date-time', 'uri', 'tt-token', 'email']);

/**
 * The relative dates the demo "learned" from the traffic (docs/spec/pack.md 4.4): the delivery estimate of a shipment
 * is between one and five days after the call that returns it.
 */
const LEARNED_DATE_OFFSETS: Record<string, { min: string; max: string }> = { eta: { min: '+1d', max: '+5d' } };

/** The id domain of a tokenized id field (docs/spec/pack.md 4.1): shipmentId -> shipment, id -> the entity. */
function idDomainOf(name: string, entity?: string): string | undefined {
  if (name === 'id') return entity ?? 'id';
  const m = /^([a-z][A-Za-z0-9]*?)(Id|Ref)$/.exec(name);
  return m ? m[1].toLowerCase() : undefined;
}

export function schemaOf(n: SchemaNode, entity?: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (n.type === 'object' || (n.type === 'array' && n.children)) {
    const props: Record<string, unknown> = {};
    const required: string[] = [];
    for (const c of n.children ?? []) {
      const cs = schemaOf(c, entity);
      if (c.presence < 1) cs['x-tt-presence'] = c.presence;
      else required.push(c.name);
      props[c.name] = cs;
    }
    const obj: Record<string, unknown> = { type: 'object', properties: props };
    if (required.length) obj.required = required;
    return n.type === 'array' ? { type: 'array', items: obj } : obj;
  }
  out.type = n.type;
  if (n.format) {
    if (KNOWN_FORMATS.has(n.format)) out.format = n.format;
    else out['x-tt-shape'] = n.format;
    const domain = n.format === 'tt-token' ? idDomainOf(n.name, entity) : undefined;
    if (domain) out['x-tt-value'] = { kind: 'id', domain };
    const learned = n.format === 'date-time' || n.format === 'date' ? LEARNED_DATE_OFFSETS[n.name] : undefined;
    if (learned) out['x-tt-value'] = { kind: 'shape', date_offset: { ...learned } };
  }
  if (n.enumValues) out.enum = n.enumValues;
  return out;
}

export function buildOpenApi(svc: ServiceInfo, ops: OperationDetail[], alias?: string): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const o of ops) {
    const item = (paths[o.pathTemplate] ??= {});
    const params = [...o.pathTemplate.matchAll(/\{(\w+)\}/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string', format: 'tt-token' } }));
    const responses: Record<string, unknown> = {};
    for (const r of o.responses) {
      const hasBody = (r.schema.children?.length ?? 0) > 0;
      const content = hasBody
        ? {
            'application/json': {
              schema: schemaOf(r.schema, o.entity),
              ...(r.examples.length ? { examples: Object.fromEntries(r.examples.map((e) => [e.name, { value: e.value }])) } : {}),
            },
          }
        : undefined;
      responses[String(r.status)] = {
        description: r.status >= 500 ? 'Server error' : r.status >= 400 ? 'Client error' : 'Success',
        'x-tt-frequency': r.frequency,
        ...(content ? { content } : {}),
      };
    }
    item[o.method.toLowerCase()] = {
      operationId: `${o.method.toLowerCase()}_${o.pathTemplate.replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`,
      ...(params.length ? { parameters: params } : {}),
      ...(o.request ? { requestBody: { required: true, content: { 'application/json': { schema: schemaOf(o.request, o.entity) } } } } : {}),
      responses,
      'x-tt-observed': { calls: o.calls, first_seen: o.firstSeen.slice(0, 10), last_seen: o.lastSeen.slice(0, 10) },
      'x-tt-latency-ms': o.latencyMs,
      ...(o.entity ? { 'x-tt-entity': o.entity } : {}),
    };
  }
  return {
    openapi: '3.1.0',
    info: { title: svc.name, version: '2026-10-22', description: 'Observed contract (synthetic examples, no real values).' },
    servers: [{ url: alias ? `https://${alias}.example` : (svc.baseUrl ?? 'https://' + svc.name + '.example') }],
    paths,
  };
}
