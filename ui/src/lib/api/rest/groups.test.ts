// Group-scoped API (multi-team isolation): the identity of an observed service is (group, service). Every list call
// sends `group=a,b` when the header filter has groups and nothing for "every group"; a row's own group travels to
// its detail calls.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { groupQuery } from './map';
import { json, noSleep, on, scripted, type Recorded } from './testkit';
import type { Api, GroupSel } from '../types';

const ME = { user: { id: 'u1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['admin'] }, roles: ['admin'], csrf_token: 'c', csrf_header: 'X-CSRF-Token', expires_at: '2026-10-24T12:00:00Z', idle_expires_at: '2026-10-24T10:00:00Z', session_idle_timeout_ms: 1 };
const T = '2026-10-24T09:00:00Z';
const SVC = (service: string, group: string, extra: Record<string, unknown> = {}) => ({ service, group, kind: 'outbound-host', calls: 10, ops: 1, in_policy: false, first_seen: T, last_seen: T, twin: false, ...extra });
const DOC = { openapi: '3.1.0', info: { title: 'x', version: '1' }, paths: { '/v1/charges': { post: { 'x-tt-observed': { calls: 30 }, responses: { '201': { 'x-tt-frequency': 1 } } } } } };
const PV = { policy_id: 'p-shop', version: 3, issued_seq: null, status: 'draft', origin: 'propose', proposed_by: 'olga', proposed_at: T, classification: 'opening', approvals_required: 2, approvals: [], targets: { groups: ['shop'] }, groups: ['shop'], diff: [] };
const PACK = { pack_id: 'pk-1', status: 'signed', created_at: T, world_id: 'w-1', group: 'shop', groups: ['shop'], services: ['shop-api'], published_at: null };
const WORLD = { world_id: 'w-1', group: 'shop', seed: 1, customers: 1, archetypes_used: true, rules: [], created_at: T, t0: T, locale: 'it', entities: 1, history: 1, pending: 0, sha256: 'x' };
const job = (result: unknown) => json({ job_id: 'j1', kind: 'x', status: 'done', result });

function make() {
  const s = scripted(
    on('GET', '/api/v1/auth/me', json(ME)),
    on('GET', '/api/v1/services', json([SVC('host:ip:private:9301', 'shop'), SVC('host:ip:private:9301', 'bookings')])),
    on('PUT', /^\/api\/v1\/services\/.+\/twin$/, json({})),
    on('GET', '/api/v1/fleet/sources', json([])),
    on('GET', '/api/v1/hosts', json({ domains: [], discovery: {} })),
    on('POST', /^\/api\/v1\/hosts\/.+\/twin$/, json(PV)),
    on('GET', /^\/api\/v1\/contracts\/[^/]+\/status$/, json({ service: 's', calls: 1, operations: 1, ready_operations: 1, best_op_calls: 1, min_calls: 20, k_min: 20, inferred_operations: 0, snapshot: null, next_snapshot_at: T, window_hours: 24 })),
    on('GET', /^\/api\/v1\/contracts\/[^/]+\/snapshots$/, json([])),
    on('POST', /^\/api\/v1\/contracts\/[^/]+\/snapshots$/, json({})),
    on('GET', /^\/api\/v1\/contracts\/[^/]+\/snapshots\/s2$/, (r) => json(r.query.get('diff_against') ? { service: 's', breaking: 0, non_breaking: 0, changes: [] } : DOC)),
    on('GET', /^\/api\/v1\/contracts\/[^/]+\/snapshots\/s1$/, json(DOC)),
    on('GET', /^\/api\/v1\/contracts\/[^/]+$/, json(DOC)),
    on('GET', '/api/v1/fleet/policies', json([PV])),
    on('GET', '/api/v1/fleet/groups/shop', json({ name: 'shop', policy_id: 'p-shop', allowed_service_names: [], sampling_override_bp: null, killed: false })),
    on('GET', '/api/v1/fleet/policies/p-shop/assist', json({ policy_id: 'p-shop', min_calls: 20, ready: true, need_calls: 0, message: '', has_identity: true, services: [] })),
    on('GET', '/api/v1/archetypes', json({ group: 'shop', k_min: 20, built: true, profiles: 0, dropped_subjects: 0, archetypes: [] })),
    on('GET', '/api/v1/worlds', json([WORLD])),
    on('POST', '/api/v1/worlds', job(WORLD)),
    on('GET', '/api/v1/packs', json([PACK])),
    on('POST', '/api/v1/packs', job(PACK)),
    on('GET', '/api/v1/rules', json([{ id: 'r-1', kind: 'causal', status: 'draft', title: 'x', groups: ['shop'] }])),
    on('GET', '/api/v1/rules/status', json({ state: 'ok', min_hours: 1, observed_hours: 1, events: 0 })),
    on('GET', '/api/v1/gaps', json([])),
    on('GET', '/api/v1/drift', json([])),
    on('GET', '/api/v1/quarantine', json([])),
  );
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, docTtlMs: 0 });
  return { api, calls: s.calls };
}

const groupOf = (calls: Recorded[], method: string, path: string | RegExp): (string | null)[] =>
  calls.filter((c) => c.method === method && (typeof path === 'string' ? c.path === path : path.test(c.path))).map((c) => c.query.get('group'));
const bodyOf = (calls: Recorded[], method: string, path: string | RegExp) => {
  const c = calls.find((x) => x.method === method && (typeof path === 'string' ? x.path === path : path.test(x.path)));
  return JSON.parse(c?.body ?? 'null') as Record<string, unknown>;
};

/** Each list endpoint and the call that reads it with a selection. */
const LISTS: [string, string | RegExp, (api: Api, g: GroupSel) => Promise<unknown>][] = [
  ['services', '/api/v1/services', (api, g) => api.services.list(g)],
  ['hosts', '/api/v1/hosts', (api, g) => api.hosts.list(g)],
  ['fleet policies', '/api/v1/fleet/policies', (api, g) => api.policies.list(g)],
  ['archetypes', '/api/v1/archetypes', (api, g) => api.archetypes.get(g)],
  ['worlds', '/api/v1/worlds', (api, g) => api.worlds.list(g)],
  ['packs', '/api/v1/packs', (api, g) => api.publications.list(g)],
  ['rules', '/api/v1/rules', (api, g) => api.rules.list(g)],
  ['rules status', '/api/v1/rules/status', (api, g) => api.rules.status(g)],
  ['gaps', '/api/v1/gaps', (api, g) => api.gaps.list(g)],
  ['drift', '/api/v1/drift', (api, g) => api.alerts.list(g)],
  ['quarantine', '/api/v1/quarantine', (api, g) => api.quarantine.list(g)],
  ['contracts (every service of the groups)', '/api/v1/services', (api, g) => api.contracts.operations(undefined, g)],
];

describe('group selection of the list endpoints', () => {
  it.each(LISTS)('%s: sends group=a,b with a filter and nothing for every group', async (_name, path, call) => {
    const a = make();
    await call(a.api, ['shop', 'bookings']);
    expect(groupOf(a.calls, 'GET', path)).toEqual(['shop,bookings']);
    const b = make();
    await call(b.api, null);
    expect(groupOf(b.calls, 'GET', path)).toEqual([null]);
    const c = make();
    await call(c.api, undefined);
    expect(groupOf(c.calls, 'GET', path)).toEqual([null]);
  });

  it('groupQuery: names, duplicates and the unknown group ""', () => {
    expect(groupQuery(['a', 'b', 'a'])).toEqual({ group: 'a,b' });
    expect(groupQuery('a')).toEqual({ group: 'a' });
    expect(groupQuery('')).toEqual({});
    expect(groupQuery([])).toEqual({});
    expect(groupQuery(null)).toEqual({});
  });
});

describe('the row group travels to the detail calls', () => {
  it('contracts of one (group, service): status, snapshots, refresh, document, diff, summary', async () => {
    const { api, calls } = make();
    const svc = 'host:ip:private:9301';
    await api.contracts.status(svc, 'bookings');
    await api.contracts.snapshots(svc, 'bookings');
    await api.contracts.refreshNow(svc, 'bookings');
    await api.contracts.openapi(svc, 'bookings');
    await api.contracts.rawDocument(svc, 'yaml', 'bookings');
    await api.contracts.diff(svc, 's1', 's2', 'bookings');
    await api.contracts.service(svc, 'bookings');
    const contract = calls.filter((c) => c.path.startsWith('/api/v1/contracts/'));
    expect(contract.length).toBeGreaterThan(8);
    for (const c of contract) expect(c.query.get('group'), `${c.method} ${c.path}`).toBe('bookings');
    // The summary reads the service list, the drift and the hosts of that group only.
    for (const p of ['/api/v1/services', '/api/v1/drift', '/api/v1/hosts']) expect(groupOf(calls, 'GET', p)).toContain('bookings');
  });
  it('without a group the detail calls carry none', async () => {
    const { api, calls } = make();
    await api.contracts.status('shop-api');
    await api.contracts.openapi('shop-api');
    for (const c of calls.filter((x) => x.path.startsWith('/api/v1/contracts/'))) expect(c.query.get('group')).toBeNull();
  });
  it('the list of every contract reads each service with its own group', async () => {
    const { api, calls } = make();
    const ops = await api.contracts.operations(undefined, ['shop', 'bookings']);
    expect(groupOf(calls, 'GET', /^\/api\/v1\/contracts\/[^/]+$/).sort()).toEqual(['bookings', 'shop']);
    // Same service, same operation, two groups: both kept, each with its group.
    expect(ops.map((o) => `${o.group}/${o.service}/${o.op}`).sort()).toEqual(['bookings/host:ip:private:9301/POST /v1/charges', 'shop/host:ip:private:9301/POST /v1/charges']);
  });
  it('twin choice, host twin, assistant, world and pack carry the group', async () => {
    const { api, calls } = make();
    await api.services.setTwin('host:ip:private:9301', true, 'bookings');
    expect(bodyOf(calls, 'PUT', /\/twin$/)).toEqual({ twin: true, group: 'bookings' });
    await api.hosts.twin({ pattern: 'ip:private:9301', group: 'bookings', base: 'http://10.0.0.1:9301' });
    expect(bodyOf(calls, 'POST', /^\/api\/v1\/hosts\//)).toMatchObject({ group: 'bookings' });
    await api.onboarding.assist('shop');
    expect(groupOf(calls, 'GET', '/api/v1/fleet/policies/p-shop/assist')).toEqual(['shop']);
    await api.worlds.generate({ seed: 1, customers: 1, group: 'shop' });
    expect(bodyOf(calls, 'POST', '/api/v1/worlds')).toEqual({ seed: 1, customers: 1, group: 'shop' });
    await api.publications.run('w-1', { group: 'shop', services: ['shop-api'], excludeServices: ['host:ip:private:9301'], multiGroup: true });
    expect(bodyOf(calls, 'POST', '/api/v1/packs')).toEqual({ world_id: 'w-1', group: 'shop', services: ['shop-api'], exclude_services: ['host:ip:private:9301'], multi_group: true });
  });
  it('a world and a pack without a group send none', async () => {
    const { api, calls } = make();
    await api.worlds.generate({ seed: 1, customers: 1 });
    expect(bodyOf(calls, 'POST', '/api/v1/worlds')).toEqual({ seed: 1, customers: 1 });
    await api.publications.run('w-1');
    expect(bodyOf(calls, 'POST', '/api/v1/packs')).toEqual({ world_id: 'w-1' });
  });
});

describe('rows of several groups', () => {
  it('keeps two services with the same name and different groups', async () => {
    const { api } = make();
    const list = await api.services.list(null);
    expect(list.map((s) => `${s.group}/${s.name}`)).toEqual(['shop/host:ip:private:9301', 'bookings/host:ip:private:9301']);
  });
  it('maps the group fields of policies, packs, worlds, rules and archetypes', async () => {
    const { api } = make();
    expect((await api.policies.list(null))[0].groups).toEqual(['shop']);
    expect((await api.publications.list(null))[0]).toMatchObject({ group: 'shop', groups: ['shop'], services: ['shop-api'] });
    expect((await api.worlds.list(null))[0].group).toBe('shop');
    expect((await api.rules.list(null))[0].groups).toEqual(['shop']);
    expect((await api.archetypes.get('shop')).group).toBe('shop');
  });
  it('keeps the same host pattern of two groups as two entries, each with its own group and declaration', async () => {
    const s = scripted(
      on('GET', '/api/v1/auth/me', json(ME)),
      on('GET', '/api/v1/fleet/sources', json([])),
      on('GET', '/api/v1/services', json([SVC('host:ip:private:9301', 'bookings'), SVC('pay', 'shop', { kind: 'outbound-policy' })])),
      on(
        'GET',
        '/api/v1/hosts',
        json({
          domains: [
            {
              domain: 'ip:private',
              calls: 20,
              first_seen: T,
              last_seen: T,
              patterns: [
                { pattern: 'ip:private:9301', group: 'shop', service: 'pay', declared: true, exact: false, quarantined: false, calls: 10, server_errors: 0, client_errors: 0, error_rate: 0, latency_p50_ms: null, first_seen: T, last_seen: T },
                { pattern: 'ip:private:9301', group: 'bookings', service: 'host:ip:private:9301', declared: false, exact: false, quarantined: false, calls: 10, server_errors: 0, client_errors: 0, error_rate: 0, latency_p50_ms: null, first_seen: T, last_seen: T },
              ],
            },
          ],
        }),
      ),
    );
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null });
    const reg = await api.hosts.list(null);
    expect(reg.domains[0].patterns.map((p) => `${p.group}:${p.service}:${p.declared}`)).toEqual(['shop:pay:true', 'bookings:host:ip:private:9301:false']);
    // The "now declared as" of one team never leaks into the other team's row.
    const svcs = await api.services.list(null);
    expect(svcs.find((x) => x.group === 'bookings')?.nowDeclaredAs).toBeUndefined();
    expect(svcs.find((x) => x.name === 'pay')).toMatchObject({ group: 'shop', hostPattern: 'ip:private:9301' });
  });
});

describe('policy assistant fields of the group API', () => {
  it('maps preselect, merged_patterns and stale', async () => {
    const s = scripted(
      on('GET', '/api/v1/auth/me', json(ME)),
      on('GET', '/api/v1/fleet/groups/shop', json({ name: 'shop', policy_id: 'p-shop', allowed_service_names: [], sampling_override_bp: null, killed: false })),
      on('GET', '/api/v1/fleet/policies', json([])),
      on(
        'GET',
        '/api/v1/fleet/policies/p-shop/assist',
        json({
          policy_id: 'p-shop',
          min_calls: 20,
          ready: true,
          need_calls: 0,
          message: '',
          has_identity: true,
          services: [
            { service: 'pay', kind: 'outbound-policy', declared: true, name: 'pay', exact: true, calls: 10, ops: [], merged_patterns: ['ip:private:9301'], preselect: false },
            { service: 'host:new.example', kind: 'outbound-host', declared: false, name: '', host_pattern: 'new.example', exact: true, calls: 5, ops: [], preselect: true },
            { service: 'host:old.example', kind: 'outbound-host', declared: false, name: '', host_pattern: 'old.example', exact: true, calls: 1, ops: [], preselect: false, stale: true },
          ],
        }),
      ),
    );
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null });
    const a = await api.onboarding.assist('shop');
    expect(a.services.map((x) => ({ s: x.service, p: x.preselect, m: x.mergedPatterns, st: x.stale }))).toEqual([
      { s: 'pay', p: false, m: ['ip:private:9301'], st: undefined },
      { s: 'host:new.example', p: true, m: undefined, st: undefined },
      { s: 'host:old.example', p: false, m: undefined, st: true },
    ]);
  });
});
