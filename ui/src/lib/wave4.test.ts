// Rules v1.9 in the console (wave 4): conditions in words, candidates below k, editor templates, the REST mapping of
// the new members and endpoints, the identity from a JSON header.
import { describe, expect, it, vi } from 'vitest';
import { buildTemplate, candidateDraft, matchText, matchesText, parseValues, templateMissing, templateOf, templateParams, type TemplateParams } from './rule-templates';
import { finalize, localProblems, preview, simpleOutcomes } from './rule-editor';
import { identityVerdict, normalizeSource, sameSource, sourceText, validSource } from './identity';
import { mapCandidates, mapObserve, mapRule, ruleDefinition } from './api/rest/map';
import type { WireObserveStatus, WireRule } from './api/rest/wire';
import { createRestApi } from './api/rest/adapter';
import { json, noSleep, on, scripted } from './api/rest/testkit';
import { setLang } from './i18n/index.svelte';

setLang('it');

const cause = { service: 'app-api', op: 'POST /contracts/{id}/suspend', status: 200 };

describe('conditions in words (rules v1.9)', () => {
  it('reads request values, customer attributes and ranges', () => {
    expect(matchText({ at: { from: 'req.body', path: '$.channel' }, in: ['WEB'] })).toBe('se channel della richiesta è WEB');
    expect(matchText({ customer: 'segment', in: ['GOLD'] })).toBe('se segment del cliente è GOLD');
    expect(matchText({ at: { from: 'req.query', name: 'amount' }, min: 100, max: 500 })).toBe('se amount della richiesta è tra 100 e 500');
    expect(matchText({ at: { from: 'req.headers', name: 'x-channel' }, in: ['APP', 'WEB'] })).toContain('uno tra APP, WEB');
    expect(matchText({ customer: 'tier', min: 3 })).toBe('se tier del cliente è almeno 3');
    expect(matchesText([{ customer: 'segment', in: ['GOLD'] }, { at: { from: 'req.body', path: '$.channel' }, in: ['WEB'] }])).toContain(' e ');
  });
  it('types the values a person writes', () => {
    expect(parseValues(' WEB, 100 ,true,, x ')).toEqual(['WEB', 100, true, 'x']);
  });
  it('puts the conditions in the preview and keeps conditional branches out of the simple form', () => {
    const def = buildTemplate({ ...cause, template: 'write_changes_field', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'status', value: 'SUSPENDED' }, 'x');
    def.cause!.when.match = [{ at: { from: 'req.body', path: '$.reason' }, in: ['FRAUD'] }];
    expect(preview(def)[0]).toContain('se reason della richiesta è FRAUD');
    def.outcomes = [
      { name: 'gold', p: 0.4, effects: def.outcomes![0].effects, when: [{ customer: 'segment', in: ['GOLD'] }] },
      { name: 'always', p: 0.6, effects: [] },
    ];
    expect(simpleOutcomes(def)).toBe(false);
    expect(preview(def).at(-1)).toContain('«gold»');
    expect(finalize(def).cause!.when.match).toEqual([{ at: { from: 'req.body', path: '$.reason' }, in: ['FRAUD'] }]);
  });
});

describe('editor templates (C18)', () => {
  it('a write changes a field: target_id, a literal or a copy of the request', () => {
    const lit = buildTemplate({ ...cause, template: 'write_changes_field', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'status', value: 'SUSPENDED' });
    expect(lit.cause!.bind).toEqual({ contract: { from: 'req.path', name: 'id' } });
    expect(lit.effects).toEqual([{ id: 'contract-updated', entity: 'contract', target_id: '${contract}', set: { status: 'SUSPENDED' }, after: '0s' }]);
    expect(lit.outcomes).toEqual([{ name: 'always', p: 1, effects: ['contract-updated'] }]);
    expect(lit.title).toContain('POST /contracts/{id}/suspend');
    expect(localProblems(lit)).toEqual([]);
    const copy = buildTemplate({ ...cause, template: 'write_changes_field', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'plan', copy: { from: 'req.body', path: '$.plan' } }, 'Piano');
    expect(copy.effects![0].set).toEqual({ plan: '${plan}' });
    expect(copy.cause!.bind!.plan).toEqual({ from: 'req.body', path: '$.plan' });
    expect(Object.keys(finalize(copy).cause!.bind!).sort()).toEqual(['contract', 'plan']);
  });
  it('all the customer objects (target_all) need no id', () => {
    const all = buildTemplate({ ...cause, op: 'POST /notifications/read-all', template: 'write_changes_field', entity: 'notification', all: true, field: 'read', value: 'true' }, 'Tutte lette');
    expect(all.effects![0]).toEqual({ id: 'notification-updated', entity: 'notification', target_all: true, set: { read: true }, after: '0s' });
    expect(all.cause!.bind).toEqual({});
    expect(localProblems(all)).toEqual([]);
    expect(preview(all)[1]).toContain('tutti gli oggetti notification');
  });
  it('expires after: a set and its revert guarded by where, after the first', () => {
    const d = buildTemplate({ ...cause, template: 'expires_after', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'status', value: 'SUSPENDED', revertTo: 'ACTIVE', expiresAfter: '1d' }, 'Sospensione');
    expect(d.effects).toHaveLength(2);
    expect(d.effects![1]).toMatchObject({ target_id: '${contract}', set: { status: 'ACTIVE' }, where: { status: 'SUSPENDED' }, after_effect: 'contract-updated', after: '1d' });
    expect(d.outcomes![0].effects).toEqual(['contract-updated', 'contract-status-reverted']);
    expect(templateOf(d)).toBe('expires_after');
  });
  it('at most n: a counter per key or per customer', () => {
    const d = buildTemplate({ service: 'app-api', op: 'POST /login', status: 401, template: 'at_most_n', n: 3, window: '15m', key: { from: 'req.body', path: '$.username' }, answer: 423 }, 'Blocco');
    expect(d.effects).toEqual([{ id: 'limit-423', respond: { service: 'app-api', op: 'POST /login', status: 423, limit: { n: 3, window: '15m', key: '${username}' } }, after: '0s' }]);
    expect(finalize(d).cause!.bind).toEqual({ username: { from: 'req.body', path: '$.username' } });
    const perUser = buildTemplate({ service: 'app-api', op: 'POST /quotes', status: 200, template: 'at_most_n', n: 3, window: '1m', answer: 429 }, 'x');
    expect(perUser.effects![0].respond!.limit).toEqual({ n: 3, window: '1m' });
  });
  it('until: a precondition on another call', () => {
    const d = buildTemplate({ service: 'app-api', op: 'POST /cart/items', status: 201, template: 'until', targetOp: 'POST /checkout', answer: 409 });
    expect(d.effects).toEqual([{ id: 'until-409', respond: { service: 'app-api', op: 'POST /checkout', status: 409, until: true }, after: '0s' }]);
    expect(preview(d)[1]).toContain('finché questa causa non si vede');
    expect(localProblems({ ...d, title: 'x' })).toEqual([]);
  });
  it('reads the parameters back from a draft (prefill), also from a mined C2/C7 draft', () => {
    const p: TemplateParams = { ...cause, template: 'expires_after', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'status', value: 'SUSPENDED', revertTo: 'ACTIVE', expiresAfter: '4h', after: '0s' };
    const back = templateParams(buildTemplate(p, 'x'));
    expect(back).toMatchObject({ template: 'expires_after', entity: 'contract', which: { from: 'req.path', name: 'id' }, field: 'status', value: 'SUSPENDED', revertTo: 'ACTIVE', expiresAfter: '4h' });
    const lim = templateParams(buildTemplate({ service: 'a', op: 'POST /login', status: 401, template: 'at_most_n', n: 5, key: { from: 'req.body', path: '$.u' }, answer: 423 }));
    expect(lim).toMatchObject({ template: 'at_most_n', n: 5, answer: 423, key: { from: 'req.body', path: '$.u' } });
    expect(templateParams({ kind: 'causal', title: '', cause: { service: 's', op: 'POST /x', when: { status: [201] } }, effects: [{ id: 'c', entity: 'x', create: {}, after: '0s' }], outcomes: [] })).toBeNull();
  });
  it('says what is missing', () => {
    expect(templateMissing({ template: 'write_changes_field', service: '', op: '', status: 0 })).toEqual(['cause', 'entity', 'which', 'field', 'value']);
    expect(templateMissing({ template: 'expires_after', ...cause, entity: 'c', all: true, field: 'f', value: 'A', revertTo: 'B', expiresAfter: 'soon' })).toEqual(['delay']);
    expect(templateMissing({ template: 'until', ...cause, answer: 99 })).toEqual(['target', 'answer']);
  });
});

describe('candidates below k (C0)', () => {
  const wire: WireRule = {
    id: 'r-0001', kind: 'causal', status: 'draft', title: '', origin: 'manual',
    cause: { service: 'app-api', op: 'POST /contracts/{id}/suspend', when: { status: [200] }, bind: { contract: { from: 'req.path', name: 'id' } } },
    effects: [{ id: 'contract-updated', entity: 'contract', target_id: '${contract}', set: { status: 'SUSPENDED' }, after: '0s' }],
    outcomes: [{ name: 'always', p: 1, effects: ['contract-updated'] }],
    evidence: { counts: { causes: 0, distinct_subjects: 0, outcomes: {} } },
  };
  it('maps the structure and turns the skeleton into a definition', () => {
    const [c] = mapCandidates([{ group: 'app', signature: 'causal|app-api|POST /contracts/{id}/suspend|contract|update', kind: 'update', template: 'write_changes_field', service: 'app-api', op: 'POST /contracts/{id}/suspend', entity: 'contract', fields: ['status'], states: ['SUSPENDED'], subjects: '2-4', draft: wire }]);
    expect(c).toMatchObject({ group: 'app', kind: 'update', subjects: '2-4', fields: ['status'], states: ['SUSPENDED'] });
    expect(c.draft!.effects![0].set).toEqual({ status: 'SUSPENDED' });
    const d = candidateDraft(c);
    expect(d.title).toBe('Bozza da POST /contracts/{id}/suspend');
    expect(templateParams(d, c.template)).toMatchObject({ entity: 'contract', field: 'status', value: 'SUSPENDED' });
    expect(mapCandidates(null)).toEqual([]);
    expect(c.missingEntities).toBeUndefined();
    const [m] = mapCandidates([{ signature: 's', kind: 'update_all', template: 'write_changes_field', service: 'app-api', op: 'POST /notifications/read', subjects: '5-9', missing_entities: ['notification'] }]);
    expect(m.missingEntities).toEqual(['notification']);
  });
  it('without a skeleton the draft is the cause alone', () => {
    const d = candidateDraft({ signature: 's', kind: 'limit', template: 'at_most_n', service: 'app-api', op: 'POST /login', subjects: '1' });
    expect(d.cause).toEqual({ service: 'app-api', op: 'POST /login', when: { status: [] }, bind: {} });
  });
});

describe('rules 1.9 members in the REST mapping', () => {
  const r: WireRule = {
    id: 'r-0009', kind: 'causal', status: 'draft', title: 't',
    cause: { service: 'app-api', op: 'POST /orders', when: { status: [201], match: [{ at: { from: 'req.headers', name: 'x-channel' }, in: ['APP'] }] }, bind: {} },
    effects: [
      { id: 'n-read', entity: 'notification', target_all: true, where: { read: false }, set: { read: true }, after: '0s' },
      { id: 'until-409', respond: { service: 'app-api', op: 'POST /checkout', status: 409, until: true }, after: '0s' },
    ],
    outcomes: [
      { name: 'gold', p: 0.3, effects: ['n-read', 'until-409'], when: [{ customer: 'segment', in: ['GOLD'] }] },
      { name: 'always', p: 0.7, effects: ['n-read', 'until-409'] },
    ],
    evidence: { counts: { causes: 0, outcomes: {} } },
  };
  it('keeps conditions, target_all and until in the definition (editor round trip) and in the view', () => {
    const def = ruleDefinition(r);
    expect(def.cause!.when.match).toEqual([{ at: { from: 'req.headers', name: 'x-channel' }, in: ['APP'] }]);
    expect(def.outcomes![0].when).toEqual([{ customer: 'segment', in: ['GOLD'] }]);
    expect(def.outcomes![1].when).toBeUndefined();
    expect(def.effects![0].target_all).toBe(true);
    expect(def.effects![1].respond!.until).toBe(true);
    const view = mapRule(r);
    expect(view.cause!.match).toHaveLength(1);
    expect(view.effects[0].targetAll).toBe(true);
    expect(view.effects[1].respond!.until).toBe(true);
    expect(view.outcomes[0].when).toEqual([{ customer: 'segment', in: ['GOLD'] }]);
  });
  it('reads the families, the test k and a JSON-header identity of a group', () => {
    const w = { group: 'shop', enabled: true, phase: 'masked', min_events: 200, events: 10, sampling_bp: 1000, identity: { from: 'header', name: 'x-user-context', json_path: 'user.id' }, families: { customer: ['client', 'customer'] }, test_k_min: 3, k_min: 20 } as WireObserveStatus;
    const o = mapObserve(w);
    expect(o.identity).toEqual({ from: 'header', name: 'x-user-context', jsonPath: 'user.id' });
    expect(o.families).toEqual({ customer: ['client', 'customer'] });
    expect(o.testKMin).toBe(3);
    expect(o.kMin).toBe(20);
  });
});

describe('REST endpoints of admin-api 1.21.0', () => {
  const PV = { policy_id: 'p-shop', version: 4, issued_seq: 9, status: 'active', origin: 'propose', proposed_by: 'olga', proposed_at: '2026-10-28T09:00:00Z', approvals_required: 0, approvals: [], targets: { groups: ['shop'] }, groups: ['shop'], diff: [] };
  const OBS = { group: 'shop', enabled: true, phase: 'masked', min_events: 200, events: 10, sampling_bp: 1000, test_k_min: 3, k_min: 20 };
  it('joins and splits families, sets the test k and a json_path identity', async () => {
    const s = scripted(
      on('PUT', '/api/v1/fleet/groups/shop/families', json(PV)),
      on('DELETE', '/api/v1/fleet/groups/shop/families/customer', json(PV)),
      on('PUT', '/api/v1/fleet/groups/shop/test-k', json(OBS)),
      on('PUT', '/api/v1/fleet/groups/shop/identity', json(PV)),
      on('GET', '/api/v1/rules/status', json({ state: 'ok', min_hours: 1, observed_hours: 2, events: 3, rules: {}, warnings: [], candidates: [{ signature: 's', kind: 'limit', template: 'at_most_n', service: 'a', op: 'POST /x', status: 429, subjects: '5-9' }], families: [{ domains: ['a', 'b'], subjects: 30, signals: ['same_ops'], score: 0.7 }], test_k: { shop: 3 } })),
    );
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null });
    expect((await api.onboarding.setFamily('shop', ' customer ', ['client', 'customer'])).version).toBe(4);
    expect(JSON.parse(s.calls.at(-1)!.body!)).toEqual({ family: 'customer', domains: ['client', 'customer'] });
    await api.onboarding.removeFamily('shop', 'customer');
    expect(s.calls.at(-1)!.method).toBe('DELETE');
    expect((await api.onboarding.setTestK('shop', 3, ' 5 tester ')).testKMin).toBe(3);
    expect(JSON.parse(s.calls.at(-1)!.body!)).toEqual({ k_min: 3, reason: '5 tester' });
    await api.onboarding.setIdentity('shop', { from: 'header', name: 'X-User-Context', claim: 'sub', jsonPath: 'user.id' });
    expect(JSON.parse(s.calls.at(-1)!.body!)).toEqual({ from: 'header', name: 'x-user-context', json_path: 'user.id' });
    const st = await api.rules.status();
    expect(st.candidates).toEqual([{ signature: 's', kind: 'limit', template: 'at_most_n', service: 'a', op: 'POST /x', status: 429, subjects: '5-9' }]);
    expect(st.families).toEqual([{ domains: ['a', 'b'], subjects: 30, signals: ['same_ops'], score: 0.7 }]);
    expect(st.testK).toEqual({ shop: 3 });
  });
});

describe('identity from a JSON header (C14)', () => {
  it('normalizes, validates and judges a json_path', () => {
    expect(normalizeSource({ from: 'header', name: 'X-User-Context', claim: 'sub', jsonPath: ' user.id ' })).toEqual({ from: 'header', name: 'x-user-context', jsonPath: 'user.id' });
    expect(validSource({ from: 'header', name: 'x-ctx', jsonPath: 'user..id' })).toBe(false);
    expect(validSource({ from: 'cookie', name: 'ctx', jsonPath: 'user.id' })).toBe(false);
    // a credential-like name is observe-safe with a member of its JSON (only that member's token leaves)
    expect(identityVerdict({ from: 'header', name: 'x-auth-context', jsonPath: 'user.id' })).toBe('safe');
    expect(identityVerdict({ from: 'header', name: 'x-auth-context' })).toBe('credential');
    expect(identityVerdict({ from: 'header', name: 'authorization', jsonPath: 'sub' })).toBe('bearer');
    expect(sameSource({ from: 'header', name: 'x-ctx', jsonPath: 'a.b' }, { from: 'header', name: 'X-CTX', jsonPath: 'a.b' })).toBe(true);
    expect(sameSource({ from: 'header', name: 'x-ctx', jsonPath: 'a.b' }, { from: 'header', name: 'x-ctx' })).toBe(false);
    expect(sourceText({ from: 'header', name: 'x-ctx', jsonPath: 'user.id' }).key).toBe('w4.id.source.json');
  });
});
