// Usability round 5: the calls the console assumes the server offers (withdraw a draft, retire a rule, the host counters)
// and what it does when it does not. Invented data only.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { err, json, noSleep, on, scripted, type Recorded } from './testkit';
import { ApiError } from '../types';

const ME = {
  user: { id: 'usr_1', username: 'marco.dev', display_name: 'Marco', auth_method: 'local', roles: ['operator'] },
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
const codeOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? e.code : 'other';
  }
};

const VERSION = { policy_id: 'p-deliveries', version: 12, status: 'rejected', withdrawn: true, note: 'withdrawn: cambio idea', proposed_by: 'marco.dev', groups: ['deliveries'], classification: 'opening', opens_values: true, approvals_required: 2, approvals: [], diff: [], author_yaml: 'x: 1' };
const RULE = { id: 'r-0018', kind: 'causal', status: 'rejected', retired: true, title: 'POST /v1/assignments', superseded_by: 'r-0019', cause: { service: 'couriers-ext', op: 'POST /v1/assignments', when: { status: [201] } }, effects: [], outcomes: [], evidence: { counts: {} } };

describe('withdrawing a pending draft (major 2)', () => {
  it('POSTs the withdrawal on the version and maps the answer', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/fleet/policies/p-deliveries/versions/12/withdraw', json(VERSION)));
    const v = await api.policies.withdraw('p-deliveries', 12, '  cambio idea ');
    expect(v).toMatchObject({ policyId: 'p-deliveries', version: 12, status: 'withdrawn' });
    const sent = calls.at(-1) as Recorded;
    expect(sent.method).toBe('POST');
    // admin-api 1.17.0: the body is {note} (additionalProperties: false)
    expect(body(sent)).toEqual({ note: 'cambio idea' });
  });

  it('a plain rejected version stays rejected; a server that says «withdrawn» as a status is read too', async () => {
    const a = make(loggedIn, on('POST', /\/withdraw$/, json({ ...VERSION, withdrawn: false })));
    expect((await a.api.policies.withdraw('p-deliveries', 12)).status).toBe('rejected');
    const b = make(loggedIn, on('POST', /\/withdraw$/, json({ ...VERSION, status: 'withdrawn', withdrawn: undefined })));
    expect((await b.api.policies.withdraw('p-deliveries', 12)).status).toBe('withdrawn');
  });

  it('sends no body without a reason', async () => {
    const { api, calls } = make(loggedIn, on('POST', /\/withdraw$/, json(VERSION)));
    await api.policies.withdraw('p-deliveries', 12);
    expect((calls.at(-1) as Recorded).body).toBeUndefined();
  });

  it('a server without the route is «unsupported» (405, or the generic 404), a missing version stays not_found', async () => {
    const a = make(loggedIn, on('POST', /\/withdraw$/, err(405, 'method_not_allowed')));
    expect(await codeOf(a.api.policies.withdraw('p-deliveries', 12))).toBe('unsupported');
    const b = make(loggedIn, on('POST', /\/withdraw$/, new Response('404 page not found', { status: 404 })));
    expect(await codeOf(b.api.policies.withdraw('p-deliveries', 12))).toBe('unsupported');
    const c = make(loggedIn, on('POST', /\/withdraw$/, err(404, 'not_found', 'no such endpoint')));
    expect(await codeOf(c.api.policies.withdraw('p-deliveries', 12))).toBe('unsupported');
    const d = make(loggedIn, on('POST', /\/withdraw$/, err(404, 'not_found', 'not found')));
    expect(await codeOf(d.api.policies.withdraw('p-deliveries', 99))).toBe('not_found');
    const e = make(loggedIn, on('POST', /\/withdraw$/, err(403, 'forbidden')));
    expect(await codeOf(e.api.policies.withdraw('p-deliveries', 12))).toBe('forbidden');
    const f = make(loggedIn, on('POST', /\/withdraw$/, err(409, 'not_draft', 'the version is no longer a draft')));
    expect(await codeOf(f.api.policies.withdraw('p-deliveries', 12))).toBe('conflict');
  });
});

describe('retiring an approved rule (major 1)', () => {
  it('POSTs the retirement and maps the retired rule with the one that replaced it', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/rules/r-0018/retire', json(RULE)));
    const r = await api.rules.retire('r-0018', 'sostituita da r-0019');
    expect(r).toMatchObject({ id: 'r-0018', status: 'retired', supersededBy: 'r-0019' });
    expect(body(calls.at(-1) as Recorded)).toEqual({ note: 'sostituita da r-0019' });
  });

  it('a rule the server calls superseded counts as retired, with the rule that replaced it', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/rules/r-0018', json({ ...RULE, status: 'superseded', retired: undefined })));
    expect(await api.rules.get('r-0018')).toMatchObject({ status: 'retired', supersededBy: 'r-0019' });
  });

  it('a rejected rule that was not retired stays rejected', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/rules/r-0018', json({ ...RULE, retired: undefined, superseded_by: undefined })));
    expect((await api.rules.get('r-0018')).status).toBe('rejected');
  });

  it('unsupported without the route; the other errors are the server\'s', async () => {
    const a = make(loggedIn, on('POST', '/api/v1/rules/r-0018/retire', err(404, 'not_found', 'no such endpoint')));
    expect(await codeOf(a.api.rules.retire('r-0018'))).toBe('unsupported');
    const b = make(loggedIn, on('POST', '/api/v1/rules/r-0018/retire', err(409, 'conflict', 'only an approved rule can be retired')));
    expect(await codeOf(b.api.rules.retire('r-0018'))).toBe('conflict');
  });
});

describe('host counters and folded rows (m10)', () => {
  const host = { pattern: 'ip:private:9731', group: 'deliveries', service: 'restaurants-ext', declared: true, calls: 5, folded_from: ['ip:private:9731'] };
  const reg = { domains: [{ domain: 'ip:private', calls: 5, first_seen: null, last_seen: null, patterns: [host] }], discovery: {} };

  it('maps the server counts: the IP classes are hosts apart, not named domains', async () => {
    const a = make(loggedIn, on('GET', '/api/v1/hosts', json({ ...reg, counts: { domains: 1, hosts: 3, ip_hosts: 3, declared: 3, undeclared: 0, folded: 3 } })));
    const out = await a.api.hosts.list();
    expect(out.counters).toEqual({ domains: 0, hosts: 0, ips: 3, all: 3, undeclared: 0 });
    expect(out.domains[0].patterns[0].foldedFrom).toEqual(['ip:private:9731']);
  });

  it('named and IP hosts together; an odd counter is left to the local count', async () => {
    const named = { domains: [...reg.domains, { domain: 'example.com', calls: 1, first_seen: null, last_seen: null, patterns: [{ ...host, pattern: 'api.example.com', folded_from: undefined }] }], discovery: {} };
    const a = make(loggedIn, on('GET', '/api/v1/hosts', json({ ...named, counts: { domains: 2, hosts: 4, ip_hosts: 3, undeclared: -1 } })));
    expect((await a.api.hosts.list()).counters).toEqual({ domains: 1, hosts: 1, ips: 3, all: 4 });
  });

  it('an older server without counts', async () => {
    const b = make(loggedIn, on('GET', '/api/v1/hosts', json(reg)));
    expect((await b.api.hosts.list()).counters).toBeUndefined();
  });
});

describe('miner candidates whose values are already in clear (M3)', () => {
  it('reads values and clear_fields of the rule diagnostics', async () => {
    const st = { state: 'ok', events: 10, rule_diagnostics: [
      { decision: 'not_mined', code: 'no_effect', service: 'payments-ext', op: 'POST /v1/payments', entity: 'payment', values: 'in_clear', clear_fields: ['status', 'reason'] },
      { decision: 'not_mined', code: 'no_effect', service: 'restaurants-ext', op: 'POST /orders', entity: 'order', values: 'dropped' },
      { decision: 'not_mined', code: 'few_causes', service: 'x', op: 'GET /y', entity: 'z' },
    ] };
    const { api } = make(loggedIn, on('GET', '/api/v1/rules/status', json(st)));
    const d = (await api.rules.status()).diagnostics;
    expect(d[0]).toMatchObject({ values: 'in_clear', clearFields: ['status', 'reason'] });
    expect(d[1]).toMatchObject({ values: 'dropped' });
    expect(d[1].clearFields).toBeUndefined();
    expect(d[2].values).toBeUndefined();
  });
});
