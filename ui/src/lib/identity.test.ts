// «Identità dell'utente» (policy.md §7.1, §7.4): the helpers of the console control and the console flow on the REST and
// demo adapters, plus the control rendered on the server. Invented names and counts only.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'svelte/server';
import IdentityControl from '../components/IdentityControl.svelte';
import { candidateSource, identityVerdict, normalizeSource, sameSource, sourceText, splitCandidates } from './identity';
import { createRestApi } from './api/rest/adapter';
import { json, noSleep, on, scripted, type Recorded } from './api/rest/testkit';
import { createMockApi } from './api/mock/adapter';
import type { Api, IdentityCandidate, ObserveStatus } from './api/types';
import { setLang } from './i18n/index.svelte';

const cands: IdentityCandidate[] = [
  { from: 'header', name: 'x-qz-ref', calls: 2000, distinct: 140, jwt: false, shape: 'drop:str:uuid', presence: 1, perCall: 0.13, score: 85, signals: ['repeats', 'id_shape', 'most_calls'], observeSafe: true, best: true },
  { from: 'header', name: 'x-op-ref', calls: 2000, distinct: 1995, jwt: false, shape: 'drop:str:hex', presence: 1, perCall: 1, score: 50, signals: ['id_shape', 'most_calls'], excluded: 'per_call', observeSafe: true },
  { from: 'header', name: 'x-tenant', calls: 2000, distinct: 4, jwt: false, shape: 'drop:str:l8', presence: 1, perCall: 0, score: 43, signals: ['short_shape', 'most_calls'], excluded: 'few_values', observeSafe: true },
  { from: 'header', name: 'x-session-key', calls: 1200, distinct: 150, jwt: false, score: 80, signals: ['repeats'], excluded: 'credential', observeSafe: false },
  { from: 'cookie', name: 'uid', calls: 1200, distinct: 150, jwt: false, score: 70, signals: ['repeats'], excluded: 'cookie', observeSafe: false },
];

describe('identity helpers', () => {
  it('any header that is not a credential applies at once; cookies, bare bearer and credentials do not', () => {
    expect(identityVerdict({ from: 'header', name: 'X-Kunden-Nr' })).toBe('safe');
    expect(identityVerdict({ from: 'header', name: 'authorization', claim: 'member_no' })).toBe('safe');
    expect(identityVerdict({ from: 'header', name: 'authorization' })).toBe('bearer');
    expect(identityVerdict({ from: 'header', name: 'x-auth-token' })).toBe('credential');
    expect(identityVerdict({ from: 'header', name: 'x-auth-token', claim: 'sub' })).toBe('safe');
    expect(identityVerdict({ from: 'cookie', name: 'uid' })).toBe('cookie');
    expect(identityVerdict({ from: 'header', name: 'bad name' })).toBe('invalid');
    expect(identityVerdict({ from: 'header', name: 'x-id', claim: '9bad' })).toBe('invalid');
  });
  it('normalizes and compares sources like the server', () => {
    expect(normalizeSource({ from: 'header', name: ' X-User ', claim: ' ' })).toEqual({ from: 'header', name: 'x-user' });
    expect(sameSource({ from: 'header', name: 'X-User' }, { from: 'header', name: 'x-user' })).toBe(true);
    expect(sameSource({ from: 'header', name: 'authorization', claim: 'sub' }, { from: 'header', name: 'authorization' })).toBe(false);
    expect(candidateSource({ from: 'header', name: 'authorization', calls: 1, distinct: 1, jwt: true })).toEqual({ from: 'header', name: 'authorization', claim: 'sub' });
    expect(sourceText({ from: 'header', name: 'authorization', claim: 'sub' }).key).toBe('id.source.jwt');
    expect(sourceText({ from: 'cookie', name: 'uid' }).key).toBe('id.source.cookie');
  });
  it('splits the ranking into usable and left-out candidates, also for an older server without reasons', () => {
    const s = splitCandidates(cands);
    expect(s.usable.map((c) => c.name)).toEqual(['x-qz-ref']);
    expect(s.excluded.map((c) => c.excluded)).toEqual(['per_call', 'few_values', 'credential', 'cookie']);
    const old = splitCandidates([{ from: 'cookie', name: 'sid', calls: 1, distinct: 30, jwt: false }, { from: 'header', name: 'x-session', calls: 1, distinct: 30, jwt: false }, { from: 'header', name: 'x-member', calls: 1, distinct: 30, jwt: false }]);
    expect(old.usable.map((c) => c.name)).toEqual(['x-member']);
    expect(old.excluded.map((c) => c.excluded)).toEqual(['cookie', 'credential']);
  });
});

const ME = {
  user: { id: 'usr_1', username: 'olivia', display_name: 'Olivia', auth_method: 'local', roles: ['operator'] },
  roles: ['operator'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-27T18:00:00Z',
  idle_expires_at: '2026-10-27T13:00:00Z',
  session_idle_timeout_ms: 1800000,
};

describe('console flow on the REST adapter (admin-api 1.18.0)', () => {
  const OBS = {
    group: 'app',
    policy_id: 'p-app',
    enabled: true,
    auto: true,
    phase: 'masked',
    min_events: 200,
    events: 2000,
    sampling_bp: 1000,
    services: [],
    masked: [],
    identity_candidates: [
      { from: 'header', name: 'x-qz-ref', calls: 2000, distinct_estimate: 140, jwt: false, shape: 'drop:str:uuid', presence: 1, distinct_per_call: 0.13, score: 85, signals: ['repeats', 'id_shape', 'most_calls'], observe_safe: true, best: true },
      { from: 'cookie', name: 'uid', calls: 1200, distinct_estimate: 150, jwt: false, score: 70, signals: ['repeats'], excluded: 'cookie', observe_safe: false },
    ],
    identity_best: { from: 'header', name: 'x-qz-ref' },
  };
  const VERSION = { policy_id: 'p-app', version: 5, status: 'active', groups: ['app'], classification: 'closing', opens_values: false, approvals_required: 0, approvals: [], diff: [], author_yaml: 'x: 1' };
  function make() {
    const s = scripted(on('GET', '/api/v1/auth/me', json(ME)), on('GET', '/api/v1/fleet/groups/app/observe', json(OBS)), on('PUT', '/api/v1/fleet/groups/app/identity', json(VERSION)));
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-27T12:30:00Z'), docTtlMs: 0, retryDelayMs: 0 });
    return { api, ...s };
  }

  it('reads the ranking with its reasons and the detected source', async () => {
    const { api } = make();
    const st = await api.onboarding.observe('app');
    expect(st.identityBest).toEqual({ from: 'header', name: 'x-qz-ref' });
    expect(st.identityCandidates[0]).toMatchObject({ name: 'x-qz-ref', score: 85, best: true, observeSafe: true, perCall: 0.13, signals: ['repeats', 'id_shape', 'most_calls'] });
    expect(st.identityCandidates[1]).toMatchObject({ from: 'cookie', excluded: 'cookie', observeSafe: false });
  });

  it('PUTs the chosen source (header names in lower case, the claim as jwt_claim) and maps the version', async () => {
    const { api, calls } = make();
    const v = await api.onboarding.setIdentity('app', { from: 'header', name: ' X-Kunden-Nr ', claim: 'sub' });
    expect(v).toMatchObject({ policyId: 'p-app', version: 5, status: 'active', opensValues: false });
    const sent = calls.at(-1) as Recorded;
    expect(sent.method).toBe('PUT');
    expect(JSON.parse(sent.body ?? '{}')).toEqual({ from: 'header', name: 'x-kunden-nr', jwt_claim: 'sub' });
  });
});

describe('console flow on the demo adapter', () => {
  let api: Api;
  beforeEach(async () => {
    api = createMockApi({ latencyMs: 0, now: () => Date.parse('2026-10-27T10:00:00Z'), storage: null });
    await api.auth.login({ username: 'olga.operator', password: 'demo' });
  });

  it('a header of any name applies at once and becomes the identity; a cookie waits for approvals', async () => {
    const before = await api.onboarding.observe('shop');
    expect(before.identityCandidates.length).toBeGreaterThan(0);
    const v = await api.onboarding.setIdentity('shop', { from: 'header', name: 'X-Member-Ref' });
    expect(v.status).toBe('active');
    expect(v.approvalsRequired).toBe(0);
    expect((await api.onboarding.observe('shop')).identity).toMatchObject({ from: 'header', name: 'x-member-ref' });
    const d = await api.onboarding.setIdentity('shop', { from: 'cookie', name: 'sid' });
    expect(d.status).toBe('draft');
    expect(d.valueReasons).toEqual([{ code: 'identity', where: 'identity.subject' }]);
    expect((await api.onboarding.observe('shop')).identity).toMatchObject({ name: 'x-member-ref' });
  });
});

describe('IdentityControl', () => {
  const status: ObserveStatus = {
    group: 'app',
    policyId: 'p-app',
    enabled: true,
    auto: true,
    phase: 'masked',
    minEvents: 200,
    events: 2000,
    samplingBp: 1000,
    services: [],
    masked: [],
    identityCandidates: cands,
    identityBest: { from: 'header', name: 'x-qz-ref' },
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const html = (props: Record<string, unknown>): string => render(IdentityControl as any, { props }).body;

  it('shows what is in use, the detected source with its reasons and the left-out candidates with why', () => {
    setLang('it');
    const out = html({ groups: ['app'], status });
    expect(out).toContain('Nessuna identità scelta');
    expect(out).toContain('Rilevato dai dati: l’header x-qz-ref (punteggio 85/100).');
    expect(out).toContain('molti valori, si ripetono per utente');
    expect(out).toContain('Scartati dal rilevamento (4)');
    expect(out).toContain('un valore nuovo a quasi ogni chiamata: un id di richiesta o di traccia');
    expect(out).toContain('pochi valori distinti: un tenant, un canale o una versione');
    expect(out).toContain('è un cookie: serve un’approvazione');
    expect(out).toContain('Un altro: scrivi il nome');
  });

  it('says when nothing is convincing, in English too', () => {
    setLang('en');
    const out = html({ groups: ['app'], status: { ...status, identityBest: undefined, identityCandidates: cands.slice(1), identity: { from: 'header', name: 'authorization', claim: 'sub' } } });
    expect(out).toContain('In use: the sub claim of the JWT in the authorization header.');
    expect(out).toContain('No candidate is convincing enough');
    setLang('it');
  });
});
