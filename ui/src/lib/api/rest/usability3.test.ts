// Usability round 3 (library loans): the miner explains each operation in the user's words, the members are a
// reference that never blocks a rule, and the sampling card does not count tokens as users.
import { describe, expect, it, vi } from 'vitest';
import { i18n, tk } from '../../i18n/index.svelte';
import { createRestApi, minerExplanations } from './adapter';
import { json, noSleep, on, scripted } from './testkit';

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
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-24T19:30:00Z'), docTtlMs: 0 });
  return { api, ...s };
}

const RULE_DIAG = [
  { decision: 'proposed', code: 'mined', service: 'library-loans-api', op: 'POST /loans', entity: 'loan', signature: 'causal|library-loans-api|POST /loans|loan' },
  { decision: 'not_mined', code: 'no_effect', service: 'library-catalog', op: 'POST /v1/reservations', entity: 'reservation', causes: 930, reason: 'no object created by a nested call and no lifecycle observed' },
  { decision: 'not_mined', code: 'undecided', service: 'shop-api', op: 'POST /orders', entity: 'order', causes: 300, decided: 0, subjects: 41, horizon_s: 3600, reason: 'no outcome with enough subjects (none decided yet)' },
];
const ENTITIES = [
  { name: 'loan', op: 'library-loans-api POST /loans', accepted: true, reason: 'ok', code: 'accepted' },
  { name: 'member', op: 'library-loans-api POST /loans', accepted: false, reference: true, code: 'reference', born: 45, reason: 'the identifier of the user making the request' },
];

describe('miner explanations', () => {
  it('map every candidate with its code, service and figures', () => {
    const out = minerExplanations(RULE_DIAG, ENTITIES);
    expect(out.map((d) => [d.kind, d.code, d.service, d.entity])).toEqual([
      ['rule', 'mined', 'library-loans-api', 'loan'],
      ['rule', 'no_effect', 'library-catalog', 'reservation'],
      ['rule', 'undecided', 'shop-api', 'order'],
      ['entity', 'reference', 'library-loans-api', 'member'],
    ]);
    expect(out[2]).toMatchObject({ causes: 300, decided: 0, subjects: 41, horizonS: 3600 });
    expect(out[3].op).toBe('POST /loans');
  });
  it('have a human text in both languages for every code, without jargon', () => {
    for (const lang of ['it', 'en'] as const) {
      i18n.lang = lang;
      for (const code of ['mined', 'few_causes', 'no_effect', 'few_subjects', 'undecided', 'outcome_few_subjects', 'no_outcome', 'entity_not_accepted', 'few_births', 'low_birth_share', 'reference', 'other']) {
        const txt = tk(`rules.why.${code}`, { service: 'library-loans-api', op: 'POST /loans', entity: 'member', causes: '17', decided: '0', subjects: '40', horizon: '1 min', k: 20 }, 'MISSING');
        expect(txt, `${lang} ${code}`).not.toBe('MISSING');
        expect(txt).not.toMatch(/dropped|objects seen being created/);
      }
    }
    i18n.lang = 'it';
    expect(tk('rules.why.reference', { service: 'library-loans-api', op: 'POST /loans', entity: 'member' })).toContain('non blocca nessuna regola');
  });
  it('come with the status and with the result of "Cerca nuove regole"', async () => {
    const status = { state: 'ok', min_hours: 1, observed_hours: 1.1, events: 15000, subjects: 40, k_min: 20, last_run_at: '2026-10-24T19:05:00Z', rules: { draft: 1 }, warnings: [], entities: ENTITIES, rule_diagnostics: RULE_DIAG };
    const { api } = make(
      loggedIn,
      on('GET', '/api/v1/rules/status', json(status)),
      on('POST', '/api/v1/rules/mine', json({ job_id: 'j', kind: 'rules.mine', status: 'done', result: { events: 15000, new: ['r-0001'], updated: [], stale: [], entities: ENTITIES, rule_diagnostics: RULE_DIAG, status } }, 202)),
    );
    const st = await api.rules.status();
    expect(st.diagnostics).toHaveLength(4);
    const r = await api.rules.mine();
    expect(r.newRules).toBe(1);
    expect(r.finishedAt).toBe('2026-10-24T19:05:00Z');
    expect(r.diagnostics.find((d) => d.entity === 'member')?.code).toBe('reference');
  });
});

describe('sampling card', () => {
  it('says that users cannot be counted before the identity is configured', async () => {
    const assist = {
      policy_id: 'p-library-loans',
      min_calls: 20,
      ready: true,
      need_calls: 0,
      message: '',
      has_identity: false,
      identity_candidates: [{ from: 'header', name: 'authorization', calls: 803, distinct_estimate: 322, jwt: true }],
      services: [],
      sampling: { current_bp: 1500, sampled_subjects: 0, source: 'no_identity', k_min: 20, target_subjects: 40, enough: false, population_estimate: 0, suggested_bp: 1500, message: 'user identity not configured' },
    };
    const group = { name: 'library-loans', policy_id: 'p-library-loans', allowed_service_names: ['library-loans-api'], sampling_override_bp: null, killed: false };
    const { api } = make(loggedIn, on('GET', '/api/v1/fleet/groups/library-loans', json(group)), on('GET', '/api/v1/fleet/policies/p-library-loans/assist', json(assist)));
    const a = await api.onboarding.assist('library-loans');
    expect(a.sampling).toMatchObject({ source: 'no_identity', sampledSubjects: 0, enough: false });
    i18n.lang = 'it';
    expect(tk('wiz.samp.noIdentity')).toContain('impossibile contare gli utenti');
  });
});
