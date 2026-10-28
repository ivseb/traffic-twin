import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { applyHostsDiscovery, hostsDiscoveryOf } from './policy-doc';
import { mapHosts } from './map';
import { err, json, noSleep, on, scripted, type Recorded } from './testkit';

const ME = {
  user: { id: 'usr_1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['operator'] },
  roles: ['operator'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-24T12:00:00Z',
  idle_expires_at: '2026-10-24T10:00:00Z',
  session_idle_timeout_ms: 1800000,
};
const loggedIn = on('GET', '/api/v1/auth/me', json(ME));

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-24T09:30:00Z'), docTtlMs: 0 });
  return { api, ...s };
}
const body = (r: Recorded) => JSON.parse(r.body ?? 'null') as Record<string, unknown>;

const P = (over: Record<string, unknown> = {}) => ({
  pattern: 'api.carrier.example',
  service: 'host:api.carrier.example',
  declared: false,
  exact: true,
  quarantined: false,
  calls: 100,
  server_errors: 5,
  client_errors: 2,
  error_rate: 0.05,
  latency_p50_ms: 120,
  first_seen: '2026-10-24T08:00:00Z',
  last_seen: '2026-10-24T09:00:00Z',
  callers: [{ service: 'shop-api', calls: 100 }],
  policies: ['p-shop'],
  ...over,
});
const REGISTRY = {
  domains: [
    { domain: 'carrier.example', calls: 100, first_seen: '2026-10-24T08:00:00Z', last_seen: '2026-10-24T09:00:00Z', patterns: [P(), P({ pattern: '{*}.tracking.example', service: 'host:{*}.tracking.example', exact: false, quarantined: true })] },
    { domain: 'ip:private', calls: 7, first_seen: null, last_seen: null, patterns: [P({ pattern: 'ip:private', service: 'host:ip:private', exact: false, first_seen: null, last_seen: null })] },
  ],
  unlisted: { ...P({ pattern: 'unlisted', service: 'host:unlisted', exact: false, calls: 0 }), callers: [], policies: [] },
  invalid: { ...P({ pattern: 'invalid', service: 'host:invalid', exact: false, calls: 3 }) },
  discovery: { 'p-shop': 'off', 'p-old': 'weird' },
};

describe('hosts registry', () => {
  it('maps GET /api/v1/hosts: domains, patterns, system entries and the discovery mode of each policy', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/hosts', json(REGISTRY)));
    const r = await api.hosts.list();
    expect(r.domains.map((d) => d.domain)).toEqual(['carrier.example', 'ip:private']);
    expect(r.domains[0].patterns[0]).toEqual({
      pattern: 'api.carrier.example',
      service: 'host:api.carrier.example',
      declared: false,
      declaredBy: [],
      exact: true,
      quarantined: false,
      calls: 100,
      serverErrors: 5,
      clientErrors: 2,
      errorRate: 0.05,
      latencyP50Ms: 120,
      firstSeen: '2026-10-24T08:00:00Z',
      lastSeen: '2026-10-24T09:00:00Z',
      callers: [{ service: 'shop-api', calls: 100 }],
      policies: ['p-shop'],
    });
    expect(r.domains[0].patterns[1]).toMatchObject({ pattern: '{*}.tracking.example', exact: false, quarantined: true });
    expect(r.domains[1].patterns[0]).toMatchObject({ firstSeen: null, lastSeen: null });
    expect(r.unlisted).toMatchObject({ pattern: 'unlisted', calls: 0, callers: [] });
    expect(r.invalid).toMatchObject({ pattern: 'invalid', calls: 3 });
    // anything but "off" reads as auto
    expect(r.discovery).toEqual({ 'p-shop': 'off', 'p-old': 'auto' });
  });
  it('an empty registry still has the two special entries', () => {
    const r = mapHosts({});
    expect(r.domains).toEqual([]);
    expect(r.unlisted).toMatchObject({ pattern: 'unlisted', service: 'host:unlisted', calls: 0, callers: [] });
    expect(r.invalid).toMatchObject({ pattern: 'invalid', calls: 0 });
  });
});

describe('twin of a host', () => {
  const DRAFT = {
    policy_id: 'p-shop',
    version: 9,
    issued_seq: null,
    status: 'draft',
    origin: 'host-twin',
    proposed_by: 'Olga',
    proposed_at: '2026-10-24T09:30:00Z',
    classification: 'opening',
    approvals_required: 2,
    approvals: [],
    targets: { groups: ['shop'] },
    diff: [],
    author_yaml: 'x: 1',
  };
  it('percent-encodes the pattern ({*} is %7B%2A%7D) and sends only what was typed', async () => {
    const { api, calls } = make(loggedIn, on('POST', /\/api\/v1\/hosts\/.*\/twin$/, json(DRAFT, 201)));
    const v = await api.hosts.twin({ pattern: '{*}.tracking.example:8443', base: ' https://acme.tracking.example:8443 ', service: ' tracking-acme ' });
    const c = calls.at(-1) as Recorded;
    expect(c.path).toBe('/api/v1/hosts/%7B%2A%7D.tracking.example%3A8443/twin');
    expect(body(c)).toEqual({ base: 'https://acme.tracking.example:8443', service: 'tracking-acme' });
    expect(v).toMatchObject({ policyId: 'p-shop', version: 9, status: 'draft', origin: 'host-twin', opensData: true, approvalsRequired: 2 });
  });
  it('an exact host sends the scheme the person chose (never guessed); the policy is sent when given', async () => {
    const { api, calls } = make(loggedIn, on('POST', /twin$/, json(DRAFT, 201)));
    await api.hosts.twin({ pattern: 'localhost:8080', scheme: 'http' });
    expect(body(calls.at(-1) as Recorded)).toEqual({ scheme: 'http' });
    await api.hosts.twin({ pattern: 'api.carrier.example' });
    expect(body(calls.at(-1) as Recorded)).toEqual({});
    await api.hosts.twin({ pattern: 'ip:private', policyId: 'p-shop', base: 'https://10.0.0.5' });
    expect((calls.at(-1) as Recorded).path).toBe('/api/v1/hosts/ip%3Aprivate/twin');
    expect(body(calls.at(-1) as Recorded)).toEqual({ policy_id: 'p-shop', base: 'https://10.0.0.5' });
  });
  it.each([
    [422, 'base_required', 'invalid'],
    [422, 'scheme_required', 'invalid'],
    [422, 'base_mismatch', 'invalid'],
    [422, 'policy_required', 'invalid'],
    [409, 'already_declared', 'conflict'],
    [409, 'service_exists', 'conflict'],
  ] as const)('keeps the server code %s %s for the dialog', async (status, code, kind) => {
    const { api } = make(loggedIn, on('POST', /twin$/, err(status, code)));
    expect(await api.hosts.twin({ pattern: 'x.example' }).catch((e: unknown) => e)).toMatchObject({ code: kind, serverCode: code });
  });
});

describe('services and the host of a service', () => {
  const SVCS = [
    { service: 'shop-api', kind: 'inbound', calls: 10, ops: 1, in_policy: true, first_seen: 'a', last_seen: 'b', twin: true },
    { service: 'shipping-ext', kind: 'outbound-policy', calls: 20, ops: 2, in_policy: true, first_seen: 'a', last_seen: 'b', twin: true },
    { service: 'host:{*}.tracking.example', kind: 'outbound-host', calls: 5, ops: 1, in_policy: false, first_seen: 'a', last_seen: 'b', twin: true },
    { service: 'host:unlisted', kind: 'outbound-host', calls: 4, ops: 1, in_policy: false, first_seen: 'a', last_seen: 'b', twin: true },
    { service: 'host:ip:private', kind: 'outbound-host', calls: 2, ops: 1, in_policy: false, first_seen: 'a', last_seen: 'b', twin: true },
  ];
  it('links a declared service to its host group and never invents a URL for {*}, unlisted or an IP class', async () => {
    const reg = { ...REGISTRY, domains: [{ domain: 'carrier.example', calls: 20, first_seen: null, last_seen: null, patterns: [P({ pattern: 'api.carrier.example', service: 'shipping-ext', declared: true, declared_by: ['p-shop'] })] }] };
    const { api } = make(loggedIn, on('GET', '/api/v1/services', json(SVCS)), on('GET', '/api/v1/hosts', json(reg)), on('GET', '/api/v1/fleet/sources', json([])));
    const list = await api.services.list();
    const by = Object.fromEntries(list.map((s) => [s.name, s]));
    // The host only: the registry does not say the scheme, and none is guessed.
    expect(by['shipping-ext']).toMatchObject({ kind: 'external', hostPattern: 'api.carrier.example', baseUrl: 'api.carrier.example' });
    expect(by['host:{*}.tracking.example']).toMatchObject({ hostPattern: '{*}.tracking.example' });
    expect(by['host:{*}.tracking.example'].baseUrl).toBeUndefined();
    expect(by['host:unlisted'].baseUrl).toBeUndefined();
    expect(by['host:ip:private'].baseUrl).toBeUndefined();
    expect(by['shop-api'].hostPattern).toBeUndefined();
    expect(JSON.stringify(list)).not.toContain('https://unlisted');
  });
  it('works for a role that cannot read the registry', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/services', json(SVCS)), on('GET', '/api/v1/hosts', err(403, 'forbidden')), on('GET', '/api/v1/fleet/sources', json([])));
    const list = await api.services.list();
    expect(list.find((s) => s.name === 'shipping-ext')?.hostPattern).toBeUndefined();
    expect(list).toHaveLength(5);
  });
  it('the discovered services of the wizard follow the same rule', async () => {
    const { api } = make(on('GET', '/api/v1/services', json(SVCS)));
    const list = await api.onboarding.discovered('tok');
    expect(list.map((s) => s.baseUrl)).toEqual([undefined, undefined, undefined, undefined, undefined]);
    expect(list[2].hostPattern).toBe('{*}.tracking.example');
  });
});

describe('quarantine of host labels', () => {
  it('keeps the host-label kind and the host_cardinality alert', async () => {
    const Q = { item_id: 'q-9', kind: 'host-label', service: 'host:*', where: 'hosts under tracking.example position 1', alert: 'host_cardinality', distinct_estimate: 1850, state: 'quarantined', since: '2026-10-24T08:00:00Z' };
    const { api } = make(loggedIn, on('GET', '/api/v1/quarantine', json([Q, { ...Q, item_id: 'q-10', kind: 'keep-value', alert: undefined }])));
    const [a, b] = await api.quarantine.list();
    expect(a).toMatchObject({ id: 'q-9', kind: 'host-label', alert: 'host_cardinality', where: 'hosts under tracking.example position 1' });
    expect('alert' in b).toBe(false);
  });
});

describe('policy hosts.discovery', () => {
  const BASE = '# starter\nformat: tt.policy/v1\npolicy_id: p-shop\ndefault: drop\n';
  it('reads the mode (absent = auto) and writes it, keeping the rest', () => {
    expect(hostsDiscoveryOf(BASE)).toBe('auto');
    expect(hostsDiscoveryOf(BASE + 'hosts:\n  discovery: off\n')).toBe('off');
    expect(hostsDiscoveryOf('not: [valid')).toBe('auto');
    const off = applyHostsDiscovery(BASE, 'off');
    expect(off).toContain('# starter');
    expect(hostsDiscoveryOf(off)).toBe('off');
    expect(off).toMatch(/hosts:\s*\n\s+discovery: off/);
  });
  it('auto removes the block; a text that already says it stays byte for byte', () => {
    const off = applyHostsDiscovery(BASE, 'off');
    const back = applyHostsDiscovery(off, 'auto');
    expect(back).not.toContain('hosts');
    expect(hostsDiscoveryOf(back)).toBe('auto');
    expect(applyHostsDiscovery(BASE, 'auto')).toBe(BASE);
    expect(applyHostsDiscovery(off, 'off')).toBe(off);
  });
  const GROUP = { name: 'shop', policy_id: 'p-shop', allowed_service_names: ['shop-api'], sampling_override_bp: null, killed: false };
  const ACTIVE = { policy_id: 'p-shop', version: 3, status: 'active', origin: 'propose', proposed_by: 'a', proposed_at: '2026-10-20T10:00:00Z', classification: 'closing', approvals_required: 1, approvals: [], targets: { groups: ['shop'] }, diff: [], author_yaml: BASE + 'hosts:\n  discovery: off\n' };
  it('the adapter reads it from the active version of the policy of the group', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/fleet/groups/shop', json(GROUP)), on('GET', '/api/v1/fleet/policies', json([ACTIVE])));
    expect(await api.policies.hostsDiscovery('shop')).toBe('off');
  });
  const EMPTY = { policy_id: 'p-shop', min_calls: 20, ready: false, need_calls: 20, message: '', has_identity: false, services: [] };
  const OFF = BASE + 'hosts:\n  discovery: off\n';
  it('the preview and the proposal carry the new mode to tt-core, which writes it', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/fleet/groups/shop', json(GROUP)),
      on('GET', '/api/v1/fleet/policies/p-shop/assist', json(EMPTY)),
      on('GET', '/api/v1/fleet/policies', json([ACTIVE])),
      on('POST', '/api/v1/fleet/policies/p-shop/assist/draft', (r) =>
        JSON.parse(r.body ?? '{}').dry_run ? json({ before: OFF, after: BASE }) : json({ ...ACTIVE, version: 4, status: 'draft', classification: 'opening', approvals_required: 2 }, 201),
      ),
    );
    const pv = await api.policies.preview({ group: 'shop', choices: [], hostsDiscovery: 'auto' });
    expect(pv.before).toContain('discovery: off');
    expect(pv.after).not.toContain('hosts');
    await api.policies.propose({ group: 'shop', choices: [], hostsDiscovery: 'auto' });
    const post = calls.filter((c) => c.method === 'POST' && c.path === '/api/v1/fleet/policies/p-shop/assist/draft').at(-1) as Recorded;
    expect(JSON.parse(post.body ?? '{}')).toEqual({ services: [], hosts_discovery: 'auto' });
  });
  it('proposing the mode that is already in force changes nothing', async () => {
    const { api } = make(
      loggedIn,
      on('GET', '/api/v1/fleet/groups/shop', json(GROUP)),
      on('GET', '/api/v1/fleet/policies/p-shop/assist', json(EMPTY)),
      on('GET', '/api/v1/fleet/policies', json([ACTIVE])),
      on('POST', '/api/v1/fleet/policies/p-shop/assist/draft', json({ before: OFF, after: OFF })),
    );
    await expect(api.policies.propose({ group: 'shop', choices: [], hostsDiscovery: 'off' })).rejects.toMatchObject({ code: 'invalid' });
  });
});
