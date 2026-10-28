// Lab: two teams each with an "order"; the demo group's rules needed the other team's service and its
// world came out empty, silently. Now the generation refuses with no_usable_rules (the rules and the services they
// miss, also through the job) or reports the group's rules it left out.
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../types';
import { errorMessage } from '../../stores.svelte';
import { i18n } from '../../i18n/index.svelte';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted } from './testkit';

const ME = {
  user: { id: 'usr_1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['operator'] },
  roles: ['operator'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-25T12:00:00Z',
  idle_expires_at: '2026-10-25T10:00:00Z',
  session_idle_timeout_ms: 1800000,
};
const loggedIn = on('GET', '/api/v1/auth/me', json(ME));

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  return createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-25T09:30:00Z'), docTtlMs: 0 });
}

const DETAILS = [
  { rule: 'r-0008', services: ['orders-api'], reason: 'out_of_scope' },
  { rule: 'r-0011', reason: 'unusable', detail: 'effect e1: unknown entity' },
];

describe('a world with no usable rule of the group', () => {
  it('the failed job keeps the code and the details', async () => {
    const api = make(loggedIn, on('POST', '/api/v1/worlds', json({ job_id: 'j', kind: 'world.generate', status: 'failed', error: 'no_usable_rules', details: DETAILS }, 202)));
    const e = await api.worlds.generate({ seed: 1, customers: 1, group: 'demo' }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).serverCode).toBe('no_usable_rules');
    expect((e as ApiError).details).toEqual(DETAILS);
  });
  it('says which rules, which services, and what to do, in Italian and English', () => {
    const e = new ApiError('server', 'no_usable_rules', undefined, 'no_usable_rules', DETAILS);
    i18n.lang = 'it';
    const it = errorMessage(e);
    expect(it).toMatch(/Nessuna regola approvata di questo gruppo/);
    expect(it).toMatch(/r-0008 usa orders-api/);
    expect(it).toMatch(/r-0011 non si può usare: effect e1: unknown entity/);
    expect(it).toMatch(/Cerca nuove regole/);
    i18n.lang = 'en';
    expect(errorMessage(e)).toMatch(/Rule r-0008 uses orders-api, which is not a service of this group/);
    i18n.lang = 'it';
  });
  it('the rules left out of a world are read back', async () => {
    const WORLD = { world_id: 'w-0009', seed: 1, customers: 10, archetypes_used: false, rules: ['r-0007'], created_at: '2026-10-25T00:00:00Z', t0: 'x', locale: 'it', entities: 12, history: 0, pending: 0, sha256: 'a', excluded_rules: [{ id: 'r-0030', services: ['billing-api'] }] };
    const api = make(loggedIn, on('POST', '/api/v1/worlds', json({ job_id: 'j', kind: 'world.generate', status: 'done', result: WORLD }, 202)));
    const w = await api.worlds.generate({ seed: 1, customers: 10, group: 'demo' });
    expect(w.excludedRules).toEqual([{ id: 'r-0030', services: ['billing-api'] }]);
  });
});
