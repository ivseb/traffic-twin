// Usability round 2: sampling vs k-anonymity, "Cerca nuove regole" result, worlds scoped to a team, errors that
// name the missing service and the rules.
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../types';
import { errorMessage } from '../../stores.svelte';
import { i18n } from '../../i18n/index.svelte';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted, type Recorded } from './testkit';

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

describe('mining: the result of "Cerca nuove regole" is never a silent zero', () => {
  const STATUS = { state: 'few_subjects', min_hours: 1, observed_hours: 3, events: 800, subjects: 7, k_min: 20, rules: {}, warnings: ['few distinct sampled users: 7 < k=20; raise the policy sampling or wait for more traffic'] };
  it('the status carries the distinct users and k', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/rules/status', json(STATUS)));
    expect(await api.rules.status()).toMatchObject({ state: 'few_subjects', subjects: 7, kMin: 20 });
  });
  it('a run with nothing proposed explains why: the state, the users and the miner reasons', async () => {
    const result = {
      events: 800,
      new: [],
      updated: [],
      stale: [],
      entities: [{ name: 'order', accepted: false, reason: 'only 4 objects seen being created, at least 20 needed' }],
      rule_diagnostics: [{ decision: 'not_mined', reason: 'only 3 distinct subjects, at least 20 needed' }],
      status: STATUS,
    };
    const { api } = make(loggedIn, on('POST', '/api/v1/rules/mine', json({ job_id: 'j', kind: 'rules.mine', status: 'done', result }, 202)));
    const r = await api.rules.mine();
    expect(r).toMatchObject({ newRules: 0, events: 800, state: 'few_subjects', subjects: 7, kMin: 20 });
    expect(r.reasons).toEqual(['only 3 distinct subjects, at least 20 needed', 'order: only 4 objects seen being created, at least 20 needed']);
  });
});

describe('policy assistant: sampling', () => {
  const GROUP = { name: 'pizzeria', policy_id: 'p-pizzeria', allowed_service_names: ['pizzeria-orders'], sampling_override_bp: null, killed: false };
  const ASSIST = {
    policy_id: 'p-pizzeria',
    min_calls: 20,
    ready: true,
    need_calls: 0,
    message: '',
    has_identity: false,
    identity_candidates: [],
    sampling: { current_bp: 500, sampled_subjects: 10, source: 'subject', k_min: 20, target_subjects: 40, enough: false, population_estimate: 200, suggested_bp: 2000, message: 'few' },
    services: [],
  };
  const routes = [
    loggedIn,
    on('GET', '/api/v1/fleet/groups/pizzeria', json(GROUP)),
    on('GET', '/api/v1/fleet/policies/p-pizzeria/assist', json(ASSIST)),
    on('GET', '/api/v1/fleet/policies', json([])),
  ];
  it('maps the advice and sends the chosen rate with the draft', async () => {
    const { api, calls } = make(...routes, on('POST', '/api/v1/fleet/policies/p-pizzeria/assist/draft', json({ before: 'a: 1\n', after: 'a: 2\n' })));
    const a = await api.onboarding.assist('pizzeria');
    expect(a.sampling).toEqual({ currentBp: 500, sampledSubjects: 10, source: 'subject', kMin: 20, targetSubjects: 40, enough: false, populationEstimate: 200, suggestedBp: 2000 });
    await api.policies.preview({ group: 'pizzeria', choices: [], samplingBp: a.sampling?.suggestedBp });
    const post = calls.find((c) => c.method === 'POST' && c.path.endsWith('/assist/draft')) as Recorded;
    expect(body(post)).toMatchObject({ sampling_rate_bp: 2000, dry_run: true });
  });
});

describe('worlds are generated for the services of a team', () => {
  const WORLD = { world_id: 'w-0002', seed: 1, customers: 10, archetypes_used: true, rules: ['r-0001'], services: ['pizzeria-orders', 'pizza-payments'], created_at: '2026-10-20T00:00:00Z', t0: 'x', locale: 'it', entities: 4, history: 0, pending: 0, sha256: 'a' };
  it('sends the services and reads the scope back', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/worlds', json({ job_id: 'j', kind: 'world.generate', status: 'done', result: WORLD }, 202)));
    const w = await api.worlds.generate({ seed: 1, customers: 10, services: ['pizzeria-orders', 'pizza-payments'] });
    expect(body(calls.at(-1) as Recorded)).toEqual({ seed: 1, customers: 10, services: ['pizzeria-orders', 'pizza-payments'] });
    expect(w.services).toEqual(['pizzeria-orders', 'pizza-payments']);
  });
  it('without a filter no services are sent', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/worlds', json({ job_id: 'j', kind: 'world.generate', status: 'done', result: WORLD }, 202)));
    await api.worlds.generate({ seed: 1, customers: 10 });
    expect(body(calls.at(-1) as Recorded)).toEqual({ seed: 1, customers: 10 });
  });
});

describe('a pack whose rules use a service outside it', () => {
  const missing = {
    code: 'missing_service',
    message: 'the rules use a service that is not in the pack: ...',
    details: [{ service: 'shipping-ext', rules: ['r-0007', 'r-0008'], entities: [] }],
  };
  it('the error keeps the details and the console says which service, which rules and what to do', async () => {
    const { api } = make(loggedIn, on('POST', '/api/v1/packs', new Response(JSON.stringify(missing), { status: 422, headers: { 'Content-Type': 'application/json' } })));
    const e = await api.publications.run('w-0001', { services: ['pizzeria-orders'] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).details).toEqual(missing.details);
    for (const lang of ['it', 'en'] as const) {
      i18n.lang = lang;
      const text = errorMessage(e);
      expect(text, lang).toContain('shipping-ext');
      expect(text, lang).toContain('r-0007, r-0008');
    }
    i18n.lang = 'it';
    expect(errorMessage(e)).toMatch(/Includi il servizio shipping-ext.*escludi le regole r-0007, r-0008/);
  });
  it('a single rule and a rule outside the selected services are named too', () => {
    i18n.lang = 'it';
    expect(errorMessage(new ApiError('invalid', 'x', 422, 'missing_service', [{ service: 'payments-ext', rules: ['r-0009'] }]))).toMatch(/La regola r-0009 usa il servizio payments-ext/);
    expect(errorMessage(new ApiError('invalid', 'x', 422, 'rule_out_of_scope', [{ rule: 'r-0003', services: ['shipping-ext'] }]))).toMatch(/r-0003.*shipping-ext/);
    expect(errorMessage(new ApiError('invalid', 'x', 422, 'unknown_service', [{ service: 'pizza-payments' }]))).toMatch(/pizza-payments/);
  });
});
