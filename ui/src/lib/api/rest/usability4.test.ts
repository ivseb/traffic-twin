// Usability round 4 (orders-api, Node, not an admin): the policy assistant without repeated rows, «Cerca nuove regole»
// followed as a job, presets whose faults fire, «Simula nel mock» classified before confirming, the approvers of a
// group, the tt command of the kit, the last mock preparation after a reload. Invented data only.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { createMockServiceRest } from './mocksvc';
import { Http } from './http';
import { err, json, noSleep, on, scripted, type Recorded } from './testkit';
import { cliCommand } from '../mocksvc';

const ME = {
  user: { id: 'usr_1', username: 'marta.dev', display_name: 'Marta', auth_method: 'local', roles: ['operator'] },
  roles: ['operator'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-25T18:00:00Z',
  idle_expires_at: '2026-10-25T13:00:00Z',
  session_idle_timeout_ms: 1800000,
};
const loggedIn = on('GET', '/api/v1/auth/me', json(ME));

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-25T12:30:00Z'), docTtlMs: 0, retryDelayMs: 0 });
  return { api, ...s };
}
const body = (r: Recorded) => JSON.parse(r.body ?? '{}');

const field = (path: string, suggestion = 'hmac:id') => ({ part: 'response', path, shape: 'str', observed: 400, distinct_estimate: 380, suggestion, reason: 'identifier', reason_code: 'id' });
const op = (o: string, fields: unknown[]) => ({ op: o, declared: true, calls: 400, need_calls: 0, raw_ops: [o], fields });
const ASSIST = {
  policy_id: 'p-orders',
  min_calls: 20,
  ready: true,
  need_calls: 0,
  message: '',
  has_identity: true,
  services: [
    { service: 'orders-api', kind: 'inbound', declared: true, name: 'orders-api', calls: 900, ops: [op('POST /orders', [field('$.id'), field('$.status', 'keep')])] },
    // The old key of the host, declared since as catalog-api: the same operation and field again.
    { service: 'host:ip:private:9301', kind: 'outbound', declared: true, name: 'catalog-api', host_pattern: 'ip:private:9301', calls: 300, ops: [op('GET /v1/products/{id}', [field('$.id'), field('$.price_cents', 'bucket:0,100,1000')])] },
    { service: 'catalog-api', kind: 'outbound', declared: true, name: 'catalog-api', calls: 500, ops: [op('GET /v1/products/{id}', [field('$.id'), field('$.category', 'keep')])] },
    // The same service twice, with a field repeated.
    { service: 'catalog-api', kind: 'outbound', declared: true, name: 'catalog-api', calls: 20, ops: [op('GET /v1/products/{id}', [field('$.category', 'keep')])] },
  ],
};
// The server writes the service and the operation on every field.
for (const s of ASSIST.services) for (const o of s.ops) for (const f of o.fields as Record<string, unknown>[]) Object.assign(f, { service: s.service, op: o.op });
const assistRoutes = [
  loggedIn,
  on('GET', '/api/v1/fleet/groups/orders', json({ name: 'orders', policy_id: 'p-orders' })),
  on('GET', '/api/v1/fleet/policies/p-orders/assist', json(ASSIST)),
  on('GET', '/api/v1/fleet/policies', json([])),
];

describe('policy assistant without repeats (M2)', () => {
  it('lists every service, operation and field once, the old host key folded into the declared service', async () => {
    const { api } = make(...assistRoutes);
    const a = await api.onboarding.assist('orders');
    expect(a.services.map((s) => s.service)).toEqual(['orders-api', 'host:ip:private:9301', 'catalog-api']);
    const catalog = a.services.find((s) => s.service === 'catalog-api')!;
    expect(catalog.ops.map((o) => o.op)).toEqual(['GET /v1/products/{id}']);
    expect(catalog.ops[0].fields.map((f) => f.path)).toEqual(['$.id', '$.category']);
    // The old key keeps only what the declared block lacks (price_cents), never $.id twice.
    const old = a.services.find((s) => s.service === 'host:ip:private:9301')!;
    expect(old.ops[0].fields.map((f) => f.path)).toEqual(['$.price_cents']);
    // Suggestions: unique ids, one per row shown, and the rows by (service name, op, part, path) are unique.
    const ids = a.suggestions.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    const rows = a.suggestions.map((s) => `${a.services.find((x) => x.service === s.service)?.name}|${s.op}|${s.part}|${s.path}`);
    expect(new Set(rows).size).toBe(rows.length);
  });
});

describe('«Cerca nuove regole» followed as a job (M3)', () => {
  const done = { job_id: 'job_1', kind: 'rules.mine', status: 'done', result: { new: [], events: 4119, status: { state: 'ok', last_run_at: '2026-10-25T12:31:10Z', rule_diagnostics: [{ decision: 'not_mined', code: 'no_effect', service: 'orders-api', op: 'POST /orders', entity: 'payment', reason: 'no lifecycle observed' }] } } };

  it('a running job survives a failing poll and says where it is', async () => {
    let polls = 0;
    const { api } = make(
      loggedIn,
      on('POST', '/api/v1/rules/mine', json({ job_id: 'job_1', kind: 'rules.mine', status: 'queued' }, 202)),
      on('GET', '/api/v1/jobs/job_1', () => {
        polls++;
        if (polls === 1) return json({ job_id: 'job_1', kind: 'rules.mine', status: 'running' });
        if (polls === 2) return err(500, 'internal');
        if (polls === 3) return err(504, 'gateway_timeout');
        return json(done);
      }),
    );
    const seen: string[] = [];
    const r = await api.rules.mine((p) => seen.push(`${p.status}${p.retrying ? '!' : ''}`));
    expect(r.events).toBe(4119);
    expect(r.diagnostics.map((d) => d.code)).toEqual(['no_effect']);
    expect(seen).toContain('queued');
    expect(seen).toContain('running');
    expect(seen.some((s) => s.endsWith('!'))).toBe(true);
  });

  it('a lost answer to the request follows the job the server has', async () => {
    const { api, calls } = make(
      loggedIn,
      on('POST', '/api/v1/rules/mine', err(502, 'bad_gateway')),
      on('GET', '/api/v1/jobs', json({ jobs: [{ job_id: 'job_9', kind: 'mock.prepare', status: 'running' }, { job_id: 'job_1', kind: 'rules.mine', status: 'running' }] })),
      on('GET', '/api/v1/jobs/job_1', json(done)),
    );
    const r = await api.rules.mine();
    expect(r.events).toBe(4119);
    expect(calls.some((c) => c.path === '/api/v1/jobs/job_1')).toBe(true);
  });

  it('a failed run is an error with its code; no job at all keeps the error of the request', async () => {
    const failed = make(loggedIn, on('POST', '/api/v1/rules/mine', json({ job_id: 'job_2', kind: 'rules.mine', status: 'failed', error: 'mining_failed' }, 202)));
    await expect(failed.api.rules.mine()).rejects.toMatchObject({ code: 'server', serverCode: 'mining_failed' });
    const none = make(loggedIn, on('POST', '/api/v1/rules/mine', err(500, 'internal')), on('GET', '/api/v1/jobs', json({ jobs: [] })));
    await expect(none.api.rules.mine()).rejects.toMatchObject({ code: 'server' });
    // A refusal for the role is never retried as a job.
    const denied = make(loggedIn, on('POST', '/api/v1/rules/mine', err(403, 'forbidden')));
    await expect(denied.api.rules.mine()).rejects.toMatchObject({ code: 'forbidden' });
    expect(denied.calls.some((c) => c.path === '/api/v1/jobs')).toBe(false);
  });
});

describe('scenario presets (M4)', () => {
  it('a preset with its own faults is custom: they fire, the observed random ones do not', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/scenario-presets', (r) => json({ ...body(r) }, 201)));
    const saved = await api.scenarios.save({ id: '', name: 'pagamenti-503', description: '', builtin: false, deterministic: true, forcedOutcomes: [], faults: [{ service: 'payments-api', op: 'POST /v1/charges', status: 503, p: 1 }] });
    expect(body(calls.at(-1)!).faults).toEqual({ mode: 'custom', rules: [{ service: 'payments-api', op: 'POST /v1/charges', status: 503, p: 1 }] });
    expect(saved.deterministic).toBe(true);
    await api.scenarios.save({ id: '', name: 'ripetibile', description: '', builtin: false, deterministic: true, forcedOutcomes: [], faults: [] });
    expect(body(calls.at(-1)!).faults).toEqual({ mode: 'off' });
    await api.scenarios.save({ id: '', name: 'come-in-prod', description: '', builtin: false, deterministic: false, forcedOutcomes: [], faults: [] });
    expect(body(calls.at(-1)!).faults).toEqual({ mode: 'observed' });
  });

  it('flags a preset stored with mode off and faults (they never fire)', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/scenario-presets', json([{ preset_id: 'old', name: 'old', faults: { mode: 'off', rules: [{ service: 'payments-api', op: 'POST /v1/charges', status: 503, p: 1 }] } }])));
    expect((await api.scenarios.list())[0]).toMatchObject({ deterministic: true, faultsIgnored: true });
  });
});

describe('«Simula questo host nel mock» classified before confirming (M5)', () => {
  const host = {
    service: 'host:ip:private:9622',
    kind: 'outbound',
    declared: false,
    name: 'payments-api',
    host_pattern: 'ip:private:9622',
    calls: 200,
    ops: [op('POST /v1/charges', [field('$.id')])],
  };
  it('asks the assistant draft as a dry run and reports what the server says', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/fleet/groups/orders', json({ name: 'orders', policy_id: 'p-orders' })),
      on('GET', '/api/v1/fleet/policies/p-orders/assist', json({ ...ASSIST, services: [host] })),
      on('GET', '/api/v1/fleet/policies', json([])),
      on('POST', '/api/v1/fleet/policies/p-orders/assist/draft', json({ before: 'a', after: 'b', opens_values: false, value_reasons: [], approvals_required: 0 })),
    );
    const c = await api.hosts.twinPreview({ pattern: 'ip:private:9622', group: 'orders', base: 'http://127.0.0.1:9622', service: 'payments-api' });
    expect(c).toEqual({ opensValues: false, valueReasons: [], approvalsRequired: 0 });
    const sent = body(calls.at(-1)!);
    expect(sent.dry_run).toBe(true);
    expect(sent.services).toEqual([{ service: 'host:ip:private:9622', name: 'payments-api', base: 'http://127.0.0.1:9622', ops: [{ op: 'POST /v1/charges', rules: [] }] }]);
  });
  it('says it cannot tell for a host the assistant has not seen, or without a group', async () => {
    const { api } = make(...assistRoutes);
    expect(await api.hosts.twinPreview({ pattern: 'api.unknown.example', group: 'orders', scheme: 'https' })).toBeNull();
    expect(await api.hosts.twinPreview({ pattern: 'api.unknown.example', scheme: 'https' })).toBeNull();
  });
});

describe('approvers of a group (B1)', () => {
  it('maps names and roles, never anything else', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/fleet/groups/orders/approvers', json({ group: 'orders', approvers: [{ name: 'piero', display_name: 'Piero', roles: ['policy-approver'] }, { name: '', display_name: 'Ada', roles: ['admin', 'other'], self: true }] })),
    );
    expect(await api.policies.approvers('orders')).toEqual([
      { name: 'piero', displayName: 'Piero', roles: ['policy-approver'], self: false },
      { name: '', displayName: 'Ada', roles: ['admin'], self: true },
    ]);
    expect(calls.at(-1)!.path).toBe('/api/v1/fleet/groups/orders/approvers');
  });
});

describe('the mock run by you (m1, m4)', () => {
  it('maps the tt command of the server, and builds one for an older server with the console CA', () => {
    const setup = { consoleUrl: 'https://console.example.test:7443', group: 'orders', image: 'ghcr.io/ivseb/traffic-twin:0.1.0-lab.abc', gatePubKeys: 'k1:pub' };
    const cmd = cliCommand(setup, "ttm_x'y");
    expect(cmd).toContain('tt mock --console https://console.example.test:7443 --group orders \\');
    expect(cmd).toContain('--console-ca ./console-ca.pem');
    expect(cmd).toContain('version 0.1.0-lab.abc');
    expect(cmd).toContain(`export TT_MOCK_TOKEN='ttm_x'\\''y'`);
    expect(cliCommand({ ...setup, consoleUrl: 'http://127.0.0.1:7080' }, 't')).not.toContain('console-ca');
    expect(cliCommand({ ...setup, cli: 'from the server' }, 't')).toBe('from the server');
  });

  it('reads a preparation again by its job id (after a reload), null when the server forgot it', async () => {
    let n = 0;
    const s = scripted(
      on('GET', '/api/v1/jobs/job_p', () => {
        n++;
        return json(n === 1 ? { job_id: 'job_p', status: 'running', progress: { steps: [{ id: 'archetypes', status: 'done' }] } } : { job_id: 'job_p', status: 'done', result: { result: { pack_id: 'pk-1' }, steps: [{ id: 'archetypes', status: 'done' }, { id: 'mock', status: 'done' }] } });
      }),
      on('GET', '/api/v1/jobs/job_gone', err(404, 'not_found')),
    );
    const svc = createMockServiceRest(new Http({ fetch: s.fetch, retryDelayMs: 0 }), noSleep);
    const seen: string[] = [];
    const r = await svc.preparation('job_p', (x) => seen.push(x.status));
    expect(r).toMatchObject({ status: 'done', packId: 'pk-1' });
    expect(seen).toEqual(['running', 'done']);
    expect(await svc.preparation('job_gone')).toBeNull();
  });
});
