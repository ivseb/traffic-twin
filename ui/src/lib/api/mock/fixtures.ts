// Invented fixtures for the mock adapter: an e-commerce (shop-api) calling an
// external carrier (shipping-ext). Hosts use *.example; every value is made up.

import type {
  Archetype,
  ContractChange,
  DriftAlert,
  Gap,
  OperationDetail,
  OperationSummary,
  PolicySuggestion,
  LinkedFields,
  Rule,
  RuleCatalog,
  RuleDefinition,
  RuleEffect,
  RuleEffectDef,
  RuleRefDef,
  HostDomain,
  HostEntry,
  HostsRegistry,
  ScenarioPreset,
  SchemaNode,
  ServiceInfo,
  SnapshotInfo,
  Source,
  User,
  Webhook,
  MinerCandidate,
  FamilyCandidate,
} from '../types';
import { mulberry32 } from '../../hash';
import { MIN_SAMPLES, LOW_SUPPORT_MIN } from '../../thresholds';

export { MIN_SAMPLES, LOW_SUPPORT_MIN };

export const iso = (ms: number) => new Date(ms).toISOString();
const ago = (now: number, seconds: number) => iso(now - seconds * 1000);

function series(seed: number, base: number, n = 30): number[] {
  const r = mulberry32(seed);
  return Array.from({ length: n }, () => Math.max(0, Math.round(base * (0.8 + r() * 0.4))));
}

// ------------------------------------------------------------------ users

export const DEMO_PASSWORD = 'demo';

export function users(now: number): User[] {
  return [
    { id: 'u-1', username: 'elena.admin', displayName: 'Elena Amministratrice', roles: ['admin'], authMethod: 'local', lastLogin: ago(now, 3600) },
    { id: 'u-2', username: 'olga.operator', displayName: 'Olga Operatrice', roles: ['operator'], authMethod: 'local', lastLogin: ago(now, 7200) },
    { id: 'u-3', username: 'rita.reviewer', displayName: 'Rita Revisora', roles: ['rule-reviewer'], authMethod: 'sso', lastLogin: ago(now, 86400) },
    { id: 'u-4', username: 'paolo.approver', displayName: 'Paolo Approvatore', roles: ['policy-approver'], authMethod: 'sso', lastLogin: ago(now, 172800) },
    { id: 'u-5', username: 'pia.publisher', displayName: 'Pia Pubblicatrice', roles: ['publisher'], authMethod: 'local', lastLogin: ago(now, 5400) },
    { id: 'u-7', username: 'anna.approver', displayName: 'Anna Approvatrice', roles: ['policy-approver'], authMethod: 'local', lastLogin: ago(now, 40000) },
    { id: 'u-6', username: 'vera.exporter', displayName: 'Vera Esportatrice', roles: ['event-exporter'], authMethod: 'sso', lastLogin: ago(now, 604800) },
    { id: 'u-8', username: 'ada.auditor', displayName: 'Ada Auditrice', roles: ['auditor'], authMethod: 'local', lastLogin: ago(now, 90000) },
  ];
}

// ------------------------------------------------------------------ sources

export function sources(now: number): Source[] {
  const base = {
    updateAvailable: false,
    killed: false,
    revoked: false,
    problems: [],
    lastErrors: [],
    samplingBp: 500,
    policyRateBp: 500,
  };
  return [
    {
      ...base,
      id: 'src-8Kf3a1',
      kind: 'sdk-node',
      version: '0.4.1',
      serviceName: 'shop-api',
      group: 'shop-api',
      instance: 'shop-api-6d9f (+2)',
      instances: 3,
      state: 'capturing',
      policy: { id: 'p-shop', version: 7 },
      lastSeen: ago(now, 12),
      eventsPerMin: 1840,
      dropRatio: 0.002,
      overheadUs: { p50: 1100, p99: 4200 },
      series: series(1, 1840),
    },
    {
      ...base,
      id: 'src-2Lm9q4',
      kind: 'egress',
      version: '0.4.0',
      updateAvailable: true,
      serviceName: 'legacy-app',
      group: 'legacy',
      instance: 'legacy-app-0',
      instances: 1,
      state: 'capturing',
      policy: { id: 'p-legacy', version: 2 },
      lastSeen: ago(now, 8),
      eventsPerMin: 310,
      dropRatio: 0,
      samplingBp: 1000,
      policyRateBp: 1000,
      series: series(2, 310),
    },
    {
      ...base,
      id: 'src-7Qa0b2',
      kind: 'sdk-python',
      version: '0.4.1',
      serviceName: 'billing-worker',
      group: 'billing',
      instance: 'billing-worker-1',
      instances: 1,
      state: 'key_mismatch',
      policy: { id: 'p-billing', version: 3 },
      lastSeen: ago(now, 45),
      eventsPerMin: 0,
      dropRatio: 0.31,
      overheadUs: { p50: 900, p99: 3100 },
      problems: [
        {
          code: 'key_mismatch',
          message: 'La chiave HMAC locale ha un kid diverso da quello della policy.',
          hint: 'Imposta TT_HMAC_KEY con la chiave del kid "k1" oppure aggiorna il kid della policy.',
        },
      ],
      lastErrors: [
        { code: 'key_mismatch', at: ago(now, 45) },
        { code: 'key_mismatch', at: ago(now, 105) },
      ],
      series: series(3, 40).map((v, i) => (i > 22 ? 0 : v)),
    },
    {
      ...base,
      id: 'src-5Zt6c8',
      kind: 'sdk-java',
      version: '0.3.9',
      updateAvailable: true,
      serviceName: 'reports-batch',
      group: 'reports',
      instance: 'reports-batch-0',
      instances: 1,
      state: 'capturing',
      policy: { id: 'p-reports', version: 1 },
      lastSeen: ago(now, 7500),
      eventsPerMin: 0,
      dropRatio: 0,
      series: series(4, 60).map((v, i) => (i > 5 ? 0 : v)),
    },
    {
      ...base,
      id: 'src-9Vd1e5',
      kind: 'sdk-dotnet',
      version: '0.4.1',
      serviceName: 'checkout-web',
      group: 'checkout',
      instance: 'checkout-web-2 (+1)',
      instances: 2,
      state: 'killed',
      killed: true,
      policy: { id: 'p-checkout', version: 4 },
      lastSeen: ago(now, 20),
      eventsPerMin: 0,
      dropRatio: 0,
      series: series(5, 220).map((v, i) => (i > 18 ? 0 : v)),
    },
    {
      ...base,
      id: 'src-1Hn4f7',
      kind: 'obi',
      version: '0.2.0',
      serviceName: 'old-gateway',
      group: 'edge',
      instance: 'edge-vm-1',
      instances: 1,
      state: 'capturing',
      revoked: true,
      policy: { id: 'p-edge', version: 1 },
      lastSeen: ago(now, 259200),
      eventsPerMin: 0,
      dropRatio: 0,
      series: series(6, 0, 30),
    },
  ];
}

// ------------------------------------------------------------------ services

export function services(now: number): ServiceInfo[] {
  return [
    { name: 'shop-api', group: 'shop-api', kind: 'own', operations: 6, calls: 184200, twin: true, lastSeen: ago(now, 12), sources: 1 },
    { name: 'legacy-app', group: 'legacy', kind: 'own', operations: 1, calls: 31900, twin: true, lastSeen: ago(now, 8), sources: 1 },
    { name: 'shipping-ext', group: 'shop-api', kind: 'external', baseUrl: 'https://api.carrier.example', hostPattern: 'api.carrier.example', operations: 3, calls: 91400, twin: true, lastSeen: ago(now, 14), sources: 2 },
    { name: 'payments-ext', group: 'shop-api', kind: 'external', baseUrl: 'https://api.pay.example', hostPattern: 'api.pay.example', operations: 2, calls: 40200, twin: true, lastSeen: ago(now, 30), sources: 1 },
    { name: 'tax-ext', group: 'shop-api', kind: 'external', baseUrl: 'https://tax.example', hostPattern: 'tax.example', operations: 1, calls: 1260, twin: false, lastSeen: ago(now, 600), sources: 1 },
    // Two teams calling the same local port: two services (group, service), never one mixed row.
    { name: 'host:ip:private:9301', group: 'shop-api', kind: 'external', hostPattern: 'ip:private:9301', operations: 2, calls: 820, twin: false, lastSeen: ago(now, 90), sources: 1 },
    { name: 'host:ip:private:9301', group: 'legacy', kind: 'external', hostPattern: 'ip:private:9301', operations: 1, calls: 140, twin: false, lastSeen: ago(now, 400), sources: 1 },
  ];
}

// ------------------------------------------------------------------ hosts (spec v1.5)

type HostSeed = Partial<HostEntry> & Pick<HostEntry, 'pattern' | 'calls'> & { firstAgo: number; lastAgo: number };

/**
 * A host pattern of the registry: calls and times are invented, errors 5xx / calls. `firstAgo` / `lastAgo` are seconds.
 * `{*}` marks a label that looked like a value (a tenant id, a hash): the server hides it and never knew it.
 */
function host(now: number, h: HostSeed): HostEntry {
  const { firstAgo, lastAgo, ...rest } = h;
  const serverErrors = rest.serverErrors ?? 0;
  return {
    service: `host:${h.pattern}`,
    group: 'shop-api',
    declared: false,
    declaredBy: [],
    exact: !h.pattern.includes('{*}') && !h.pattern.startsWith('ip:'),
    quarantined: false,
    serverErrors,
    clientErrors: 0,
    errorRate: h.calls ? serverErrors / h.calls : 0,
    latencyP50Ms: 120,
    firstSeen: ago(now, firstAgo),
    lastSeen: ago(now, lastAgo),
    callers: [{ service: 'shop-api', calls: h.calls }],
    policies: ['p-shop'],
    ...rest,
  };
}

const group = (domain: string, patterns: HostEntry[]): HostDomain => ({
  domain,
  calls: patterns.reduce((a, p) => a + p.calls, 0),
  firstSeen: patterns.map((p) => p.firstSeen).filter((x): x is string => !!x).sort()[0] ?? null,
  lastSeen: patterns.map((p) => p.lastSeen).filter((x): x is string => !!x).sort().at(-1) ?? null,
  patterns,
});

const H = 3600;
const D = 86400;

/**
 * The hosts registry of the demo: a carrier, a payment provider and a tax service that policies declare, a tracking
 * service with per-tenant sub-domains (`{*}`, collapsed by the intake), a few hosts nobody declared (two of them new)
 * and calls to private IPs. In strict mode (`strict`) the undeclared hosts disappear: their calls are `host:unlisted`.
 */
export function hostsRegistry(now: number, strict = false): HostsRegistry {
  const carrier = [
    host(now, { pattern: 'api.carrier.example', service: 'shipping-ext', declared: true, declaredBy: ['p-shop'], calls: 91400, serverErrors: 640, clientErrors: 1210, latencyP50Ms: 142, firstAgo: 60 * D, lastAgo: 14, callers: [{ service: 'shop-api', calls: 62100 }, { service: 'legacy-app', calls: 29300 }] }),
    host(now, { pattern: 'sandbox.carrier.example', calls: 380, serverErrors: 0, clientErrors: 12, latencyP50Ms: 96, firstAgo: 5 * H, lastAgo: 240, callers: [{ service: 'shop-api', calls: 380 }] }),
    host(now, { pattern: 'webhooks.carrier.example:8443', calls: 2210, serverErrors: 8, latencyP50Ms: 54, firstAgo: 12 * D, lastAgo: 95, callers: [{ service: 'legacy-app', calls: 2210 }] }),
  ];
  const pay = [
    host(now, { pattern: 'api.pay.example', service: 'payments-ext', declared: true, declaredBy: ['p-shop'], calls: 40200, serverErrors: 2815, clientErrors: 904, latencyP50Ms: 231, firstAgo: 60 * D, lastAgo: 30 }),
    host(now, { pattern: '3ds.pay.example', calls: 5120, serverErrors: 41, clientErrors: 77, latencyP50Ms: 310, firstAgo: 9 * D, lastAgo: 41 }),
  ];
  const tracking = [
    host(now, { pattern: '{*}.tracking.example', calls: 18400, serverErrors: 130, clientErrors: 66, latencyP50Ms: 88, quarantined: true, firstAgo: 21 * D, lastAgo: 22, callers: [{ service: 'shop-api', calls: 18400 }] }),
    host(now, { pattern: 'cdn.tracking.example', calls: 960, serverErrors: 0, latencyP50Ms: 21, firstAgo: 30 * D, lastAgo: 700 }),
  ];
  const tax = [host(now, { pattern: 'tax.example', service: 'tax-ext', declared: true, declaredBy: ['p-shop'], calls: 1260, serverErrors: 3, latencyP50Ms: 175, firstAgo: 60 * D, lastAgo: 600 })];
  const analytics = [host(now, { pattern: 'collect.analytics-vendor.example', calls: 720, serverErrors: 36, latencyP50Ms: 64, firstAgo: 6 * H, lastAgo: 75, callers: [{ service: 'shop-api', calls: 540 }, { service: 'legacy-app', calls: 180 }] })];
  const priv = [
    host(now, { pattern: 'ip:private', calls: 412, serverErrors: 9, latencyP50Ms: 12, firstAgo: 40 * D, lastAgo: 180, callers: [{ service: 'legacy-app', calls: 412 }] }),
    host(now, { pattern: 'ip:private:8080', calls: 63, serverErrors: 0, latencyP50Ms: 9, firstAgo: 2 * D, lastAgo: 3600, callers: [{ service: 'legacy-app', calls: 63 }] }),
    // The same local port called by two teams: one entry per group, each with its own callers and policy.
    host(now, { pattern: 'ip:private:9301', calls: 820, serverErrors: 4, latencyP50Ms: 6, firstAgo: 3 * D, lastAgo: 90, callers: [{ service: 'shop-api', calls: 820 }] }),
    host(now, { pattern: 'ip:private:9301', group: 'legacy', calls: 140, serverErrors: 0, latencyP50Ms: 7, firstAgo: 1 * D, lastAgo: 400, callers: [{ service: 'legacy-app', calls: 140 }], policies: ['p-legacy'] }),
  ];
  const pub = [host(now, { pattern: 'ip:public', calls: 9, serverErrors: 2, latencyP50Ms: 380, firstAgo: 3 * H, lastAgo: 2 * H, callers: [{ service: 'shop-api', calls: 9 }] })];
  // The egress proxy seen by an SDK in front of it: the same call is captured twice (glossary: double capture).
  const proxy = [host(now, { pattern: 'tt-egress:9090', calls: 1900, serverErrors: 0, latencyP50Ms: 3, firstAgo: 14 * D, lastAgo: 20, callers: [{ service: 'shop-api', calls: 1900 }] })];

  const groups = [group('carrier.example', carrier), group('pay.example', pay), group('tracking.example', tracking), group('tax.example', tax), group('analytics-vendor.example', analytics), group('tt-egress', proxy), group('ip:private', priv), group('ip:public', pub)];
  const empty = (pattern: string, calls: number): HostEntry => host(now, { pattern, calls, exact: false, firstAgo: 5 * D, lastAgo: 300, callers: calls ? [{ service: 'shop-api', calls }] : [] });
  let domains = groups.sort((a, b) => b.calls - a.calls);
  let unlisted = empty('unlisted', 0);
  if (strict) {
    // Strict mode: only declared hosts keep their name; everything else leaves as host:unlisted.
    const hidden = domains.flatMap((d) => d.patterns).filter((p) => !p.declared && !p.pattern.startsWith('ip:'));
    domains = domains
      .map((d) => group(d.domain, d.patterns.filter((p) => p.declared || p.pattern.startsWith('ip:'))))
      .filter((d) => d.patterns.length > 0);
    unlisted = empty('unlisted', hidden.reduce((a, p) => a + p.calls, 0));
  }
  return {
    domains,
    unlisted: { ...unlisted, service: 'host:unlisted' },
    invalid: { ...empty('invalid', 3), service: 'host:invalid', serverErrors: 0, errorRate: 0 },
    discovery: { 'p-shop': strict ? 'off' : 'auto' },
  };
}

// ------------------------------------------------------------------ schemas

const f = (name: string, type: SchemaNode['type'], presence = 1, extra: Partial<SchemaNode> = {}): SchemaNode => ({ name, type, presence, ...extra });
const obj = (name: string, presence: number, children: SchemaNode[]): SchemaNode => ({ name, type: 'object', presence, children });
const arr = (name: string, presence: number, children: SchemaNode[]): SchemaNode => ({ name, type: 'array', presence, itemType: 'object', children });
const TOK = 'tt-token';

const lat = (p50: number, p95: number, p99: number) => ({ p50, p95, p99 });
const day = (d: string) => `2026-${d}T00:00:00Z`;

interface OpSpec {
  service: string;
  op: string;
  calls: number;
  latency: { p50: number; p95: number; p99: number };
  statuses: [number, number, string?][];
  request?: SchemaNode;
  schemas: Record<number, SchemaNode>;
  examples: Record<number, { name: string; value: unknown }[]>;
  entity?: string;
  linked?: Record<number, LinkedFields[]>;
}

const SHIPMENT_ITEM = (): SchemaNode[] => [
  f('shipmentId', 'string', 1, { format: TOK }),
  f('orderId', 'string', 1, { format: TOK }),
  f('status', 'string', 1, { enumValues: ['PENDING', 'CREATED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED'] }),
  f('eta', 'string', 0.37, { format: 'date-time' }),
  f('carrierRef', 'string', 0.12, { format: TOK }),
];

const ERR = (codes: string[]): SchemaNode => obj('error', 1, [f('code', 'string', 1, { enumValues: codes }), f('message', 'string', 0.64)]);

const SPECS: OpSpec[] = [
  {
    service: 'shop-api',
    op: 'POST /orders',
    calls: 74200,
    latency: lat(184, 520, 1100),
    entity: 'order',
    statuses: [
      [201, 0.962],
      [400, 0.021, 'invalid-items'],
      [422, 0.014, 'out-of-stock'],
      [500, 0.003, 'internal-error'],
    ],
    request: obj('$', 1, [
      arr('items', 1, [f('sku', 'string', 1, { format: 'drop:str:l16' }), f('qty', 'integer', 1)]),
      f('email', 'string', 0.88, { format: 'drop:str:email' }),
      f('note', 'string', 0.21, { format: 'drop:str:l0' }),
    ]),
    schemas: {
      201: obj('$', 1, [f('id', 'string', 1, { format: TOK }), f('status', 'string', 1, { enumValues: ['CREATED'] }), f('total', 'number', 1, { format: 'bucket' })]),
      400: obj('$', 1, [ERR(['INVALID_ITEMS', 'INVALID_JSON'])]),
      422: obj('$', 1, [ERR(['OUT_OF_STOCK', 'ADDRESS_NOT_SERVED'])]),
      500: obj('$', 1, [ERR(['INTERNAL'])]),
    },
    examples: {
      201: [{ name: 'created', value: { id: 'ORD-SYN-0042', status: 'CREATED', total: 74.9 } }],
      422: [{ name: 'out-of-stock', value: { error: { code: 'OUT_OF_STOCK', message: 'Articolo non disponibile' } } }],
    },
  },
  {
    service: 'shop-api',
    op: 'GET /orders/{id}',
    calls: 61300,
    latency: lat(41, 120, 260),
    entity: 'order',
    statuses: [
      [200, 0.934],
      [404, 0.066, 'not-found'],
    ],
    schemas: {
      200: obj('$', 1, [
        f('id', 'string', 1, { format: TOK }),
        f('status', 'string', 1, { enumValues: ['CREATED', 'PAID', 'SHIPPED', 'DELIVERED', 'CANCELLED'] }),
        f('total', 'number', 1, { format: 'bucket' }),
        f('trackingUrl', 'string', 0.46, { format: 'uri' }),
      ]),
      404: obj('$', 1, [ERR(['ORDER_NOT_FOUND'])]),
    },
    examples: { 200: [{ name: 'shipped', value: { id: 'ORD-SYN-0042', status: 'SHIPPED', total: 74.9, trackingUrl: 'https://track.example/SHP-SYN-0091' } }] },
  },
  {
    service: 'shop-api',
    op: 'GET /products',
    calls: 38400,
    latency: lat(23, 70, 150),
    statuses: [[200, 1]],
    schemas: { 200: obj('$', 1, [arr('items', 1, [f('sku', 'string', 1, { format: TOK }), f('macroCategory', 'string', 1, { enumValues: ['CASA', 'TEMPO_LIBERO'] }), f('category', 'string', 1, { enumValues: ['HOME', 'TOYS', 'BOOKS', 'GARDEN'] }), f('price', 'number', 1, { format: 'bucket' })])]) },
    examples: { 200: [{ name: 'list', value: { items: [{ sku: 'SKU-SYN-0007', macroCategory: 'CASA', category: 'HOME', price: 19.9 }] } }] },
    linked: {
      200: [
        {
          at: 'items[]',
          fields: ['category', 'macroCategory'],
          combos: [
            { values: ['GARDEN', 'CASA'], atLeast: 100 },
            { values: ['HOME', 'CASA'], atLeast: 1000 },
            { values: ['BOOKS', 'TEMPO_LIBERO'], atLeast: 100 },
            { values: ['TOYS', 'TEMPO_LIBERO'], atLeast: 20 },
          ],
          partial: true,
        },
        { at: 'items[]', fields: ['category', 'price'], combos: [{ values: ['BOOKS', '0–50'], atLeast: 100 }, { values: ['HOME', '50–250'], atLeast: 100 }, { values: ['GARDEN', '≥ 250'], atLeast: 20 }, { values: ['TOYS', '0–50'], atLeast: 20 }], partial: false },
      ],
    },
  },
  {
    service: 'shop-api',
    op: 'POST /carts/{id}/items',
    calls: 9900,
    latency: lat(35, 99, 210),
    statuses: [
      [200, 0.99],
      [409, 0.01, 'conflict'],
    ],
    schemas: { 200: obj('$', 1, [f('cartId', 'string', 1, { format: TOK }), f('count', 'integer', 1)]), 409: obj('$', 1, [ERR(['CART_LOCKED'])]) },
    examples: { 200: [{ name: 'added', value: { cartId: 'CRT-SYN-0310', count: 3 } }] },
  },
  {
    service: 'shop-api',
    op: 'DELETE /orders/{id}',
    calls: 12,
    latency: lat(60, 140, 140),
    statuses: [[204, 1]],
    schemas: { 204: obj('$', 1, []) },
    examples: { 204: [{ name: 'deleted', value: {} }] },
  },
  {
    service: 'shop-api',
    op: 'POST /returns',
    calls: 31,
    latency: lat(88, 190, 190),
    statuses: [[201, 1]],
    schemas: { 201: obj('$', 1, [f('id', 'string', 1, { format: TOK }), f('status', 'string', 1, { enumValues: ['REQUESTED'] })]) },
    examples: { 201: [{ name: 'requested', value: { id: 'RET-SYN-0004', status: 'REQUESTED' } }] },
  },
  {
    service: 'legacy-app',
    op: 'GET /legacy/stock',
    calls: 31900,
    latency: lat(210, 640, 1300),
    statuses: [
      [200, 0.995],
      [500, 0.005, 'legacy-fail'],
    ],
    schemas: { 200: obj('$', 1, [arr('rows', 1, [f('sku', 'string', 1, { format: TOK }), f('qty', 'integer', 1)])]), 500: obj('$', 1, [ERR(['LEGACY_FAILURE'])]) },
    examples: { 200: [{ name: 'stock', value: { rows: [{ sku: 'SKU-SYN-0007', qty: 12 }] } }] },
  },
  {
    service: 'shipping-ext',
    op: 'GET /v1/shipments',
    calls: 58210,
    latency: lat(92, 310, 870),
    entity: 'shipment',
    statuses: [
      [200, 0.981],
      [400, 0.007, 'bad-request'],
      [503, 0.012, 'upstream-unavailable'],
    ],
    schemas: {
      200: obj('$', 1, [arr('items', 1, SHIPMENT_ITEM())]),
      400: obj('$', 1, [ERR(['BAD_REQUEST'])]),
      503: obj('$', 1, [ERR(['CARRIER_UNAVAILABLE'])]),
    },
    examples: {
      200: [
        { name: 'in-transit', value: { items: [{ shipmentId: 'SHP-SYN-0091', orderId: 'ORD-SYN-0042', status: 'IN_TRANSIT', eta: '2026-10-21T18:00:00Z' }] } },
        { name: 'created', value: { items: [{ shipmentId: 'SHP-SYN-0102', orderId: 'ORD-SYN-0050', status: 'CREATED' }] } },
      ],
      503: [{ name: 'upstream-unavailable', value: { error: { code: 'CARRIER_UNAVAILABLE' } } }],
    },
  },
  {
    service: 'shipping-ext',
    op: 'POST /v1/shipments',
    calls: 30900,
    latency: lat(140, 380, 720),
    entity: 'shipment',
    statuses: [
      [202, 0.988],
      [409, 0.012, 'duplicate'],
    ],
    request: obj('$', 1, [f('orderId', 'string', 1, { format: TOK }), f('address', 'object', 1, { format: 'drop:obj:l8' })]),
    schemas: {
      202: obj('$', 1, [f('shipmentId', 'string', 1, { format: TOK }), f('status', 'string', 1, { enumValues: ['PENDING'] })]),
      409: obj('$', 1, [ERR(['DUPLICATE_ORDER'])]),
    },
    examples: { 202: [{ name: 'accepted', value: { shipmentId: 'SHP-SYN-0091', status: 'PENDING' } }] },
  },
  {
    service: 'shipping-ext',
    op: 'GET /v1/shipments/{id}',
    calls: 2290,
    latency: lat(70, 210, 400),
    entity: 'shipment',
    statuses: [[200, 1]],
    schemas: { 200: obj('$', 1, SHIPMENT_ITEM()) },
    examples: { 200: [{ name: 'delivered', value: { shipmentId: 'SHP-SYN-0033', orderId: 'ORD-SYN-0011', status: 'DELIVERED' } }] },
  },
  {
    service: 'payments-ext',
    op: 'POST /v1/charges',
    calls: 40100,
    latency: lat(240, 720, 1900),
    statuses: [
      [201, 0.961],
      [402, 0.034, 'card-declined'],
      [504, 0.005, 'gateway-timeout'],
    ],
    schemas: {
      201: obj('$', 1, [f('chargeId', 'string', 1, { format: TOK }), f('orderId', 'string', 1, { format: TOK }), f('status', 'string', 1, { enumValues: ['AUTHORIZED', 'CAPTURED'] })]),
      402: obj('$', 1, [ERR(['CARD_DECLINED', 'INSUFFICIENT_FUNDS'])]),
      504: obj('$', 1, [ERR(['GATEWAY_TIMEOUT'])]),
    },
    examples: { 201: [{ name: 'authorized', value: { chargeId: 'CHG-SYN-0200', orderId: 'ORD-SYN-0042', status: 'AUTHORIZED' } }], 402: [{ name: 'card-declined', value: { error: { code: 'CARD_DECLINED' } } }] },
  },
  {
    service: 'payments-ext',
    op: 'POST /v1/refunds',
    calls: 44,
    latency: lat(310, 700, 700),
    statuses: [[201, 1]],
    schemas: { 201: obj('$', 1, [f('refundId', 'string', 1, { format: TOK }), f('status', 'string', 1, { enumValues: ['PENDING', 'DONE'] })]) },
    examples: { 201: [{ name: 'pending', value: { refundId: 'RFD-SYN-0012', status: 'PENDING' } }] },
  },
  {
    service: 'tax-ext',
    op: 'GET /v2/rates',
    calls: 1260,
    latency: lat(55, 130, 240),
    statuses: [[200, 1]],
    schemas: { 200: obj('$', 1, [f('country', 'string', 1, { enumValues: ['IT', 'DE', 'FR'] }), f('rate', 'number', 1, { format: 'bucket' })]) },
    examples: { 200: [{ name: 'it', value: { country: 'IT', rate: 22 } }] },
  },
];


function splitOp(op: string): { method: string; pathTemplate: string } {
  const i = op.indexOf(' ');
  return { method: op.slice(0, i), pathTemplate: op.slice(i + 1) };
}

export function operationSummaries(now: number): OperationSummary[] {
  return SPECS.map((s) => {
    const { method, pathTemplate } = splitOp(s.op);
    return {
      service: s.service,
      op: s.op,
      method,
      pathTemplate,
      calls: s.calls,
      firstSeen: day('10-05'),
      lastSeen: ago(now, 20 + (s.calls % 90)),
      latencyMs: s.latency,
      statuses: s.statuses.map(([status, frequency, example]) => ({ status, frequency, calls: Math.round(s.calls * frequency), example })),
      fewSamples: s.calls < MIN_SAMPLES,
      entity: s.entity,
    };
  });
}

export function operationDetail(now: number, service: string, op: string): OperationDetail | null {
  const s = SPECS.find((x) => x.service === service && x.op === op);
  if (!s) return null;
  const sum = operationSummaries(now).find((x) => x.service === service && x.op === op)!;
  return {
    ...sum,
    request: s.request,
    responses: s.statuses.map(([status, frequency]) => ({ status, frequency, schema: s.schemas[status], examples: s.examples[status] ?? [], ...(s.linked?.[status] ? { linked: s.linked[status] } : {}) })),
    latencySeries: series(s.calls, s.latency.p50),
  };
}

// ------------------------------------------------------------------ snapshots (shipping-ext)

export const SNAPSHOT_DATES = ['10-05', '10-12', '10-19', '10-22'];

export function snapshots(service: string): SnapshotInfo[] {
  const changes = SNAPSHOT_CHANGES.map((c) => c);
  return SNAPSHOT_DATES.map((d, i) => ({
    id: `snap-${service}-${d}`,
    date: day(d),
    calls: 12000 + i * 9000,
    breaking: changes[i].filter((c) => c.severity === 'breaking').length,
    nonBreaking: changes[i].filter((c) => c.severity === 'non-breaking').length,
  }));
}

/** Changes introduced by snapshot i with respect to snapshot i-1. */
export const SNAPSHOT_CHANGES: ContractChange[][] = [
  [],
  [{ severity: 'non-breaking', op: 'GET /v1/shipments', path: '$.items[].carrierRef', kind: 'field-added', to: 'string(tt-token), presence 12%', detail: 'Nuovo campo opzionale' }],
  [
    { severity: 'non-breaking', op: 'GET /v1/shipments', path: 'responses.400', kind: 'new-status', to: '400 (0,7%)', detail: 'Nuovo status raro' },
    { severity: 'non-breaking', op: 'GET /v1/shipments', path: '$.items[].status', kind: 'enum-changed', from: 'PENDING, CREATED, IN_TRANSIT, DELIVERED', to: '+ CANCELLED', detail: 'Nuovo valore ammesso' },
  ],
  [
    { severity: 'breaking', op: 'GET /v1/shipments', path: '$.items[].eta', kind: 'type-changed', from: 'string(date-time)', to: 'integer(epoch)', detail: "Il campo 'eta' cambia tipo" },
    { severity: 'breaking', op: 'GET /v1/shipments', path: 'responses.503', kind: 'new-status', from: 'assente', to: '503 (1,2%)', detail: 'Nuovo status di errore frequente' },
  ],
];

export function snapshotFragment(stage: number): string {
  const items: Record<string, unknown> = {
    shipmentId: 'string (tt-token)',
    orderId: 'string (tt-token)',
    status: { type: 'string', enum: stage >= 2 ? ['PENDING', 'CREATED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED'] : ['PENDING', 'CREATED', 'IN_TRANSIT', 'DELIVERED'] },
    eta: stage >= 3 ? { type: 'integer', format: 'epoch', presence: 0.37 } : { type: 'string', format: 'date-time', presence: 0.37 },
  };
  if (stage >= 1) items.carrierRef = { type: 'string', format: 'tt-token', presence: 0.12 };
  const responses: Record<string, unknown> = { '200': { items: [items] } };
  if (stage >= 2) responses['400'] = { frequency: 0.007 };
  if (stage >= 3) responses['503'] = { frequency: 0.012 };
  return JSON.stringify({ 'GET /v1/shipments': { responses } }, null, 2);
}

// ------------------------------------------------------------------ rules

type RuleBase = Omit<Rule, 'origin' | 'definition'> & { origin?: Rule['origin'] };

const refOf = (text: string): RuleRefDef => {
  const [from, rest = ''] = text.split(' ');
  return from.endsWith('body') ? { from, path: rest } : { from, name: rest };
};

/** The editable definition of a display rule (what the server would store). */
export function definitionOf(r: RuleBase): RuleDefinition {
  if (r.kind === 'batch' && r.batch) {
    return { kind: 'batch', title: r.title, schedule: r.batch.schedule, entity: r.batch.entity, where: { ...r.batch.where }, set: { ...r.batch.set }, fraction: r.batch.fraction };
  }
  const bindVar = Object.keys(r.cause?.bind ?? {})[0] ?? 'ref';
  return {
    kind: 'causal',
    title: r.title,
    cause: r.cause && { service: r.cause.service, op: r.cause.op, when: { status: [...r.cause.whenStatus] }, bind: Object.fromEntries(Object.entries(r.cause.bind).map(([k, v]) => [k, refOf(v)])) },
    effects: r.effects.map((e) => {
      const d: RuleEffectDef = { id: e.id, after: e.after, ...(e.afterEffect ? { after_effect: e.afterEffect } : {}) };
      if (e.kind === 'respond' && e.respond) return { ...d, respond: { ...e.respond } };
      d.entity = e.entity;
      if (e.kind === 'create') return { ...d, create: { ...e.values } };
      return { ...d, ...(e.target ? { target: e.target } : { target_id: '${' + bindVar + '}' }), set: { ...e.values } };
    }),
    outcomes: r.outcomes.map((o) => ({ name: o.name, p: o.p, effects: [...o.effects] })),
  };
}

export const withDefinition = (r: RuleBase): Rule => ({ ...r, origin: r.origin ?? 'mined', definition: definitionOf(r) });

/** What the demo contracts let a rule name (the rule editor's dropdowns). */
export function ruleCatalog(): RuleCatalog {
  const states = ['CONFIRMED', 'CANCELLED', 'PAID', 'ON_HOLD'];
  const shipStates = ['PENDING', 'CREATED', 'IN_TRANSIT', 'DELIVERED', 'CANCELLED'];
  return {
    services: [
      {
        name: 'shop-api',
        ops: [
          { op: 'GET /orders/{id}', statuses: [200, 404], examples: { '404': ['order-not-found'] }, params: [{ from: 'req.path', name: 'id', kind: 'id', domain: 'order' }], response: [{ from: 'resp.body', path: '$.id', kind: 'id', domain: 'order' }, { from: 'resp.body', path: '$.status', kind: 'enum', values: states }] },
          { op: 'POST /orders', statuses: [201, 400, 503], examples: { '400': ['validation-error'], '503': ['carrier-unavailable'] }, request: [{ from: 'req.body', path: '$.email', kind: 'shape' }], response: [{ from: 'resp.body', path: '$.id', kind: 'id', domain: 'order' }, { from: 'resp.body', path: '$.status', kind: 'enum', values: states }, { from: 'resp.body', path: '$.shipmentId', kind: 'id', domain: 'shipment' }] },
          { op: 'POST /orders/{id}/cancel', statuses: [200, 409], params: [{ from: 'req.path', name: 'id', kind: 'id', domain: 'order' }], response: [{ from: 'resp.body', path: '$.status', kind: 'enum', values: states }] },
          { op: 'POST /returns', statuses: [201], response: [{ from: 'resp.body', path: '$.id', kind: 'id', domain: 'return' }] },
        ],
      },
      {
        name: 'shipping-ext',
        ops: [
          { op: 'GET /v1/shipments', statuses: [200, 503], examples: { '503': ['carrier-unavailable'] }, params: [{ from: 'req.query', name: 'orderId', kind: 'id', domain: 'order' }] },
          { op: 'POST /v1/shipments', statuses: [202, 503], response: [{ from: 'resp.body', path: '$.shipmentId', kind: 'id', domain: 'shipment' }] },
        ],
      },
    ],
    entities: [
      { name: 'order', service: 'shop-api', idField: 'id', idDomain: 'order', ops: ['POST /orders', 'GET /orders/{id}'], fields: [{ from: '', name: 'status', kind: 'enum', values: states }, { from: '', name: 'note', kind: 'shape' }] },
      { name: 'shipment', service: 'shipping-ext', idField: 'shipmentId', idDomain: 'shipment', ops: ['POST /v1/shipments', 'GET /v1/shipments'], fields: [{ from: '', name: 'status', kind: 'enum', values: shipStates }, { from: '', name: 'orderId', kind: 'id', domain: 'order' }, { from: '', name: 'eta', kind: 'shape', type: 'string' }] },
    ],
  };
}

/** The derived value of the demo (rules 1.10): the delivery estimate is three days after the effect. */
export const DEMO_DERIVED_ETA = { $derive: { fn: 'date', offset: '+3d', format: 'date-time' } };

export function rules(now: number): Rule[] {
  return ruleBases(now).map(withDefinition).map((r) => {
    if (r.id !== 'r-0016') return r;
    // A value computed when the effect applies: the definition keeps the object, the display its JSON (as the REST
    // adapter maps a stored rule).
    const def = r.definition;
    def.effects![0].create = { ...def.effects![0].create, eta: structuredClone(DEMO_DERIVED_ETA) };
    return { ...r, effects: r.effects.map((e, i) => (i === 0 ? { ...e, values: { ...e.values, eta: JSON.stringify(DEMO_DERIVED_ETA) } } : e)) };
  });
}

function ruleBases(now: number): RuleBase[] {
  const shipEffects: RuleEffect[] = [
    { id: 'shipment-created', entity: 'shipment', kind: 'create' as const, values: { orderId: '${order}', status: 'CREATED' }, after: '5m', magnitude: 'minutes' as const },
    { id: 'shipment-in-transit', entity: 'shipment', kind: 'set' as const, values: { status: 'IN_TRANSIT' }, target: 'shipment-created', afterEffect: 'shipment-created', after: '4h', magnitude: 'hours' as const },
    { id: 'shipment-delivered', entity: 'shipment', kind: 'set' as const, values: { status: 'DELIVERED' }, target: 'shipment-created', afterEffect: 'shipment-in-transit', after: '2d', magnitude: 'days' as const },
    { id: 'shipment-cancelled', entity: 'shipment', kind: 'set' as const, values: { status: 'CANCELLED' }, target: 'shipment-created', afterEffect: 'shipment-created', after: '1h', magnitude: 'minutes' as const },
  ];
  return [
    {
      id: 'r-0007',
      kind: 'causal',
      status: 'draft',
      title: 'Un ordine creato genera una spedizione presso il corriere',
      cause: { service: 'shop-api', op: 'POST /orders', whenStatus: [201], bind: { order: 'resp.body $.id' } },
      effects: shipEffects,
      outcomes: [
        { name: 'happy', p: 0.93, effects: ['shipment-created', 'shipment-in-transit', 'shipment-delivered'], count: 3832 },
        { name: 'cancelled', p: 0.04, effects: ['shipment-created', 'shipment-cancelled'], count: 165 },
        { name: 'never-shipped', p: 0.03, effects: [], count: 123 },
      ],
      counts: { causes: 4120, distinctSubjects: 1310, keyMatches: 3997 },
      hints: { magnitude: { 'shipment-created': 'minutes', 'shipment-in-transit': 'hours', 'shipment-delivered': 'days', 'shipment-cancelled': 'minutes' } },
      review: { by: [], at: null, note: '' },
      proposedAt: ago(now, 7200),
    },
    {
      id: 'r-0012',
      kind: 'batch',
      status: 'draft',
      title: 'Consolidamento notturno delle consegne',
      effects: [],
      outcomes: [],
      counts: { causes: 0, distinctSubjects: 0, keyMatches: 0 },
      hints: { magnitude: {}, scheduleConfidence: 'high' },
      batch: { schedule: '0 2 * * *', entity: 'shipment', where: { status: 'IN_TRANSIT' }, set: { status: 'DELIVERED' }, fraction: 0.6, runs: 14, entitiesChanged: 9800 },
      review: { by: [], at: null, note: '' },
      proposedAt: ago(now, 7000),
    },
    {
      id: 'r-0003',
      kind: 'causal',
      status: 'approved',
      title: 'Un pagamento autorizzato conferma l’ordine',
      cause: { service: 'payments-ext', op: 'POST /v1/charges', whenStatus: [201], bind: { order: 'resp.body $.orderId' } },
      effects: [
        { id: 'order-paid', entity: 'order', kind: 'set', values: { status: 'PAID' }, after: '10s', magnitude: 'seconds' },
      ],
      outcomes: [
        { name: 'happy', p: 0.97, effects: ['order-paid'], count: 38000 },
        { name: 'no-update', p: 0.03, effects: [], count: 1180 },
      ],
      counts: { causes: 39180, distinctSubjects: 8800, keyMatches: 38950 },
      hints: { magnitude: { 'order-paid': 'seconds' } },
      review: { by: ['rita.reviewer'], at: ago(now, 864000), note: 'Coerente con il comportamento atteso.' },
      proposedAt: ago(now, 1000000),
    },
    {
      id: 'r-0005',
      kind: 'causal',
      status: 'stale',
      title: 'Un rimborso richiesto genera un accredito',
      cause: { service: 'payments-ext', op: 'POST /v1/refunds', whenStatus: [201], bind: { refund: 'resp.body $.refundId' } },
      effects: [
        { id: 'refund-done', entity: 'refund', kind: 'set', values: { status: 'DONE' }, after: '1d', magnitude: 'days' },
      ],
      outcomes: [
        { name: 'happy', p: 0.81, effects: ['refund-done'], count: 36 },
        { name: 'pending', p: 0.19, effects: [], count: 8 },
      ],
      counts: { causes: 44, distinctSubjects: 31, keyMatches: 40 },
      hints: { magnitude: { 'refund-done': 'days' } },
      review: { by: ['rita.reviewer'], at: ago(now, 1900000), note: '' },
      staleReason: 'La confidenza è scesa da 0,97 a 0,81 nell’ultima finestra.',
      proposedAt: ago(now, 2000000),
    },
    {
      id: 'r-0015',
      kind: 'causal',
      status: 'draft',
      title: 'Un reso richiesto genera un ritiro presso il cliente',
      cause: { service: 'shop-api', op: 'POST /returns', whenStatus: [201], bind: { ret: 'resp.body $.id' } },
      effects: [{ id: 'pickup-scheduled', entity: 'pickup', kind: 'create', values: { returnId: '${ret}', status: 'SCHEDULED' }, after: '1d', magnitude: 'days' }],
      outcomes: [
        { name: 'happy', p: 0.9, effects: ['pickup-scheduled'], count: 28 },
        { name: 'never-picked', p: 0.1, effects: [], count: 3 },
      ],
      counts: { causes: 31, distinctSubjects: 22, keyMatches: 28 },
      hints: { magnitude: { 'pickup-scheduled': 'days' } },
      review: { by: [], at: null, note: '' },
      proposedAt: ago(now, 3600),
    },
    {
      id: 'r-0016',
      kind: 'causal',
      status: 'draft',
      origin: 'manual',
      title: 'Una spedizione creata a mano riceve la consegna prevista tra tre giorni',
      cause: { service: 'shop-api', op: 'POST /orders', whenStatus: [201], bind: { order: 'resp.body $.id' } },
      effects: [{ id: 'shipment-planned', entity: 'shipment', kind: 'create', values: { orderId: '${order}', status: 'CREATED' }, after: '10m', magnitude: 'minutes' }],
      outcomes: [{ name: 'always', p: 1, effects: ['shipment-planned'], count: 0 }],
      counts: { causes: 0, distinctSubjects: 0, keyMatches: 0 },
      hints: { magnitude: { 'shipment-planned': 'minutes' } },
      review: { by: [], at: null, note: '' },
      proposedAt: ago(now, 1800),
    },
    {
      id: 'r-0002',
      kind: 'causal',
      status: 'rejected',
      title: 'Una lettura prodotti aggiorna il carrello (correlazione casuale)',
      cause: { service: 'shop-api', op: 'GET /products', whenStatus: [200], bind: { sku: 'resp.body $.items[*].sku' } },
      effects: [{ id: 'cart-touched', entity: 'cart', kind: 'set', values: { touched: 'true' }, after: '1m', magnitude: 'minutes' }],
      outcomes: [{ name: 'happy', p: 1, effects: ['cart-touched'], count: 900 }],
      counts: { causes: 900, distinctSubjects: 412, keyMatches: 61 },
      hints: { magnitude: { 'cart-touched': 'minutes' } },
      review: { by: ['rita.reviewer'], at: ago(now, 1500000), note: 'Legame debole: solo 61 corrispondenze su 900.' },
      proposedAt: ago(now, 1600000),
    },
  ];
}

// ------------------------------------------------------------------ archetypes

export function archetypes(): Archetype[] {
  const mk = (id: string, label: string, size: number, opm: string, hrs: string, mix: Record<string, number>, kMin: number): Archetype => ({
    id,
    label,
    size: size >= kMin ? size : null,
    belowK: size < kMin,
    features: { ordersPerMonth: opm, activeHours: hrs, outcomesMix: mix },
  });
  const k = 20;
  return [
    mk('arch-01', 'acquirente occasionale, spedizioni standard', 412, '1-2', '12-18', { happy: 0.94, cancelled: 0.04, 'never-shipped': 0.02 }, k),
    mk('arch-02', 'acquirente occasionale, molti resi', 96, '1-2', '09-12', { happy: 0.86, cancelled: 0.1, 'never-shipped': 0.04 }, k),
    mk('arch-03', 'acquirente frequente, spedizioni standard', 214, '3-5', '18-22', { happy: 0.95, cancelled: 0.03, 'never-shipped': 0.02 }, k),
    mk('arch-04', 'acquirente frequente, pagamenti rifiutati spesso', 58, '3-5', '20-24', { happy: 0.78, cancelled: 0.15, 'never-shipped': 0.07 }, k),
    mk('arch-05', 'cliente business, ordini grandi', 27, '6-10', '08-12', { happy: 0.97, cancelled: 0.02, 'never-shipped': 0.01 }, k),
    mk('arch-06', 'utilizzo notturno anomalo', 12, '1-2', '00-04', { happy: 0.7, cancelled: 0.2, 'never-shipped': 0.1 }, k),
    mk('arch-07', 'ordini internazionali', 7, '1-2', '10-16', { happy: 0.8, cancelled: 0.1, 'never-shipped': 0.1 }, k),
  ];
}

// ------------------------------------------------------------------ scenarios

export function scenarioPresets(): ScenarioPreset[] {
  return [
    {
      id: 'sc-observed',
      name: 'Frequenze osservate',
      description: 'Guasti e lentezze alle frequenze viste in produzione, riproducibili con il seed.',
      builtin: true,
      faults: [],
      forcedOutcomes: [],
      deterministic: false,
    },
    {
      id: 'sc-deterministic',
      name: 'Tutto deterministico',
      description: 'Nessun guasto casuale: ideale per test che devono dare sempre lo stesso risultato.',
      builtin: true,
      faults: [],
      forcedOutcomes: [{ rule: 'r-0007', outcome: 'happy' }],
      deterministic: true,
    },
    {
      id: 'sc-carrier-down',
      name: 'Corriere non disponibile',
      description: 'Ogni lettura delle spedizioni risponde 503 (CARRIER_UNAVAILABLE).',
      builtin: true,
      faults: [{ service: 'shipping-ext', op: 'GET /v1/shipments', status: 503, p: 1 }],
      forcedOutcomes: [],
      deterministic: true,
    },
    {
      id: 'sc-cancelled',
      name: 'Spedizione annullata',
      description: 'Forza l’esito “cancelled” della regola r-0007 e fa avanzare l’orologio di 1 ora.',
      builtin: true,
      faults: [],
      forcedOutcomes: [{ rule: 'r-0007', outcome: 'cancelled' }],
      deterministic: true,
      clockAdvance: '1h',
    },
    {
      id: 'sc-flaky-payments',
      name: 'Pagamenti instabili',
      description: 'Il 30% dei pagamenti risponde 504, il 10% viene rifiutato (402).',
      builtin: true,
      faults: [
        { service: 'payments-ext', op: 'POST /v1/charges', status: 504, p: 0.3 },
        { service: 'payments-ext', op: 'POST /v1/charges', status: 402, p: 0.1 },
      ],
      forcedOutcomes: [],
      deterministic: false,
    },
  ];
}

// ------------------------------------------------------------------ alerts, webhooks

export function alerts(now: number): DriftAlert[] {
  return [
    {
      id: 'al-1',
      type: 'contract.drift',
      severity: 'breaking',
      service: 'shipping-ext',
      op: 'GET /v1/shipments',
      change: "campo 'eta': tipo cambiato da string(date-time) a integer(epoch)",
      firstSeen: ago(now, 3600 * 7),
      callsAfterChange: 1840,
      state: 'open',
    },
    {
      id: 'al-2',
      type: 'contract.drift',
      severity: 'breaking',
      service: 'shipping-ext',
      op: 'GET /v1/shipments',
      change: 'nuovo status di errore frequente: 503 (1,2% delle risposte)',
      firstSeen: ago(now, 3600 * 7),
      callsAfterChange: 700,
      state: 'acknowledged',
    },
    {
      id: 'al-3',
      type: 'contract.drift',
      severity: 'non-breaking',
      service: 'shipping-ext',
      op: 'GET /v1/shipments',
      change: "nuovo campo opzionale 'carrierRef' (12% delle risposte)",
      firstSeen: ago(now, 86400 * 10),
      callsAfterChange: 6900,
      state: 'resolved',
    },
    {
      id: 'al-4',
      type: 'rule.stale',
      severity: 'info',
      service: 'payments-ext',
      change: 'regola r-0005: confidenza scesa da 0,97 a 0,81',
      firstSeen: ago(now, 86400),
      state: 'open',
    },
    {
      id: 'al-5',
      type: 'source.health',
      severity: 'info',
      service: 'billing-worker',
      change: 'la sorgente non invia eventi da 45 s (key_mismatch)',
      firstSeen: ago(now, 600),
      state: 'open',
    },
  ];
}

export function webhooks(now: number): Webhook[] {
  return [
    { id: 'wh-1', name: 'Chat del team', url: 'https://hooks.internal.example/tt-alerts', events: ['contract.drift', 'rule.stale'], enabled: true, lastDelivery: { at: ago(now, 3600 * 7), ok: true, httpStatus: 204 } },
    { id: 'wh-2', name: 'Email di reparto', url: 'https://mail-gw.internal.example/hooks/tt', events: ['contract.drift'], enabled: false, lastDelivery: { at: ago(now, 86400 * 4), ok: false, httpStatus: 502 } },
  ];
}

// ------------------------------------------------------------------ policy assistant

export function policySuggestions(): PolicySuggestion[] {
  const s = (
    n: number,
    service: string,
    op: string,
    part: PolicySuggestion['part'],
    path: string,
    shape: string,
    observed: number,
    distinct: number,
    action: PolicySuggestion['suggestion'],
    reason: string,
  ): PolicySuggestion => ({ id: `sg-${n}`, service, op, part, path, shape, observed, distinct, suggestion: action, current: n === 2 ? { action: 'keep' } : n === 8 ? { action: 'code' } : { action: 'drop' }, reason });
  return [
    s(1, 'shop-api', 'POST /orders', 'response', '$.id', 'stringa, 16 caratteri, alta entropia', 4120, 4120, { action: 'hmac', arg: 'order' }, 'Identificatore: tutti i valori sono distinti.'),
    s(2, 'shop-api', 'POST /orders', 'response', '$.status', 'stringa maiuscola', 4120, 5, { action: 'keep' }, 'Pochi valori distinti: sembra un enum.'),
    s(3, 'shop-api', 'POST /orders', 'response', '$.total', 'numero', 4120, 3870, { action: 'bucket', arg: '0, 50, 100, 250' }, 'Numero con molti valori: meglio generalizzarlo in fasce.'),
    s(4, 'shop-api', 'POST /orders', 'request', '$.email', 'stringa, formato email', 3620, 1290, { action: 'drop' }, 'Formato email: resta chiuso.'),
    s(5, 'shop-api', 'POST /orders', 'request', '$.note', 'stringa, lunghezza libera', 870, 801, { action: 'drop' }, 'Testo libero: resta chiuso.'),
    s(6, 'shipping-ext', 'GET /v1/shipments', 'response', '$.items[*].orderId', 'stringa, 16 caratteri, alta entropia', 58210, 3997, { action: 'hmac', arg: 'order' }, 'Stesso dominio di POST /orders: serve a collegare le chiamate.'),
    s(7, 'shipping-ext', 'GET /v1/shipments', 'response', '$.items[*].shipmentId', 'stringa, 16 caratteri, alta entropia', 58210, 3997, { action: 'hmac', arg: 'shipment' }, 'Identificatore: tutti i valori sono distinti.'),
    s(8, 'shipping-ext', 'GET /v1/shipments', 'response', '$.items[*].status', 'stringa maiuscola', 58210, 5, { action: 'keep' }, 'Pochi valori distinti: sembra un enum.'),
    s(9, 'shipping-ext', 'GET /v1/shipments', 'errors', '$.error.code', 'stringa maiuscola', 780, 3, { action: 'keep' }, 'Codice errore: enum a bassa cardinalità.'),
    s(10, 'shipping-ext', 'POST /v1/shipments', 'request', '$.address', 'oggetto, 8 chiavi', 30900, 29800, { action: 'drop' }, 'Indirizzo: resta chiuso.'),
  ];
}

export const BASE_POLICY_ACTIVE = {
  format: 'tt.policy/v1',
  policy_id: 'p-shop',
  default: 'drop',
  hmac: { kid: 'k1', epoch: '2026-10' },
  sampling: { rate: 0.05 },
  global: { errors: { body: { '$.error.code': 'keep' } } },
};

// ------------------------------------------------------------------ gaps

/**
 * Rules v1.9 (C0): structures seen by fewer than k users in the demo traffic. Structure only (operations, field names,
 * clear states), the users as a bucket; the draft is what «Crea bozza» opens in the editor.
 */
export function demoCandidates(): MinerCandidate[] {
  return [
    {
      group: 'shop-api',
      signature: 'causal|shop-api|POST /orders/{id}/cancel|order|update',
      kind: 'update',
      template: 'write_changes_field',
      service: 'shop-api',
      op: 'POST /orders/{id}/cancel',
      entity: 'order',
      fields: ['status'],
      states: ['CANCELLED'],
      subjects: '5-9',
      draft: {
        kind: 'causal',
        title: 'Un annullamento porta l’ordine a CANCELLED',
        cause: { service: 'shop-api', op: 'POST /orders/{id}/cancel', when: { status: [200] }, bind: { order: { from: 'req.path', name: 'id' } } },
        effects: [{ id: 'order-updated', entity: 'order', target_id: '${order}', set: { status: 'CANCELLED' }, after: '0s' }],
        outcomes: [{ name: 'always', p: 1, effects: ['order-updated'] }],
      },
    },
    {
      group: 'shop-api',
      signature: 'causal|shop-api|POST /orders|limit|429',
      kind: 'limit',
      template: 'at_most_n',
      service: 'shop-api',
      op: 'POST /orders',
      status: 429,
      target: 'shop-api POST /orders',
      subjects: '2-4',
      draft: {
        kind: 'causal',
        title: 'Al massimo 3 ordini al minuto per cliente',
        cause: { service: 'shop-api', op: 'POST /orders', when: { status: [201] }, bind: {} },
        effects: [{ id: 'limit-429', respond: { service: 'shop-api', op: 'POST /orders', status: 429, limit: { n: 3, window: '1m' } }, after: '0s' }],
        outcomes: [{ name: 'always', p: 1, effects: ['limit-429'] }],
      },
    },
  ];
}

/** Rules v1.9 (C15): HMAC domains of the demo that look like one identifier under two names (structure only). */
export function demoFamilies(): FamilyCandidate[] {
  return [{ domains: ['order', 'order_ref'], subjects: 64, signals: ['same_cardinality', 'write_read_follow'], score: 0.82 }];
}

export function gaps(): Gap[] {
  return [
    ...operationSummaries(Date.now())
      .filter((o) => o.fewSamples)
      .map((o, i): Gap => ({
        id: `gp-s${i}`,
        kind: 'few-samples',
        scope: 'op',
        service: o.service,
        op: o.op,
        count: o.calls,
        threshold: MIN_SAMPLES,
        detail: 'Poche osservazioni: schema e frequenze non sono affidabili.',
      })),
    { id: 'gp-n1', kind: 'status-never-seen', scope: 'op', service: 'shipping-ext', op: 'GET /v1/shipments/{id}', count: 0, threshold: 1, detail: 'Status 404 mai visto: il mock non saprà rispondere “non trovato”.' },
    { id: 'gp-n2', kind: 'status-never-seen', scope: 'op', service: 'payments-ext', op: 'POST /v1/refunds', count: 0, threshold: 1, detail: 'Nessun errore (4xx/5xx) osservato su questa operazione.' },
    { id: 'gp-n3', kind: 'status-never-seen', scope: 'op', service: 'shop-api', op: 'POST /carts/{id}/items', count: 0, threshold: 1, detail: 'Status 404 mai visto per carrelli inesistenti.' },
  ];
}

