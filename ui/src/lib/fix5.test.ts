// Usability round 5 (deliveries-api, Python, not an admin, statuses already in clear as codes): the pure parts behind the
// fixes. «Rivedi in blocco» never turns a code into keep and counts only what really opens values, the approvals are
// said before applying, the messages about states follow the policy, the server's English is said in Italian, hosts are
// listed once, the rule editor has a partial catalog, the preparation of the mock is found again. Invented data only.
import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import type { GroupApprover, HostEntry, HostsRegistry, OperationSummary, PolicySuggestion, PolicyVersion, Rule } from './api';
import { applyGroupAction, keepsCode, opensField, safeProposal } from './observe';
import { approvalPlan, bulkRow, defaultSelected, summarizeRows } from './bulk';
import { canWithdraw } from './approval';
import { codeFieldsOf, fieldOfLocation, hasLifecycleRule, openedFieldsOf, statesFacts } from './codes';
import { serverText } from './server-text';
import { dedupeHosts, summarize } from './hosts';
import { catalogFromOperations, forgetCatalogs, keepCatalog, keptCatalog, normalizeCatalog } from './rule-catalog';
import { forgetPreparations, lastPreparation, rememberPreparation } from './prepare-memory';
import { setLang } from './i18n/index.svelte';
import ApprovalNextStep from '../components/ApprovalNextStep.svelte';
import RetireRule from '../components/RetireRule.svelte';
import WithdrawDraft from '../components/WithdrawDraft.svelte';
import { features } from './features.svelte';
import { session } from './stores.svelte';

const sg = (id: string, path: string, current: PolicySuggestion['current'], suggestion: PolicySuggestion['suggestion'], reasonCode = 'enum'): PolicySuggestion => ({
  id, service: 'restaurants-ext', op: 'GET /menu', part: 'response', path, shape: 'str enum', observed: 800, distinct: 3, suggestion, current, reason: '', reasonCode,
});

// 27 fields of a group, as in the test: statuses already code, headers drop, and two categories that need keep.
const FIELDS: PolicySuggestion[] = [
  sg('s1', '$.status', { action: 'code' }, { action: 'keep' }),
  sg('s2', '$.reason', { action: 'code' }, { action: 'keep' }),
  sg('s3', 'headers.content-type', { action: 'drop' }, { action: 'keep' }),
  sg('s4', '$.cuisine', { action: 'drop' }, { action: 'keep' }),
  sg('s5', '$.course', { action: 'drop' }, { action: 'keep' }),
  sg('s6', '$.id', { action: 'drop' }, { action: 'hmac', arg: 'id' }, 'id'),
];

describe('«Rivedi in blocco» never downgrades a code (M2)', () => {
  it('a field that already is code stays code under the assistant proposal', () => {
    expect(safeProposal(FIELDS[0])).toEqual({ action: 'code' });
    expect(keepsCode(FIELDS[0])).toBe(true);
    expect(keepsCode(FIELDS[3])).toBe(false);
    expect(applyGroupAction(FIELDS[0], 'proposal')).toEqual({ action: 'code' });
    // and under the masking action: code stays, a drop field becomes hmac
    expect(applyGroupAction(FIELDS[0], 'hmac')).toEqual({ action: 'code' });
    expect(applyGroupAction(FIELDS[3], 'hmac')).toEqual({ action: 'hmac', arg: 'id' });
    // only an explicit drop closes it
    expect(applyGroupAction(FIELDS[0], 'drop')).toEqual({ action: 'drop' });
  });

  it('counts only the fields that really open values', () => {
    const rows = FIELDS.map((f) => bulkRow(f, 'proposal'));
    const s = summarizeRows(rows);
    // status and reason stay (code), content-type, cuisine and course open (keep), the id is masked (no approval)
    expect(s.changed).toBe(4);
    expect(s.opening).toBe(3);
    expect(s.quiet).toBe(1);
    expect(rows[0].protectedCode).toBe(true);
    expect(rows[0].changes).toBe(false);
    expect(rows[3].opens).toBe(true);
    expect(rows[5].opens).toBe(false);
  });

  it('the box of a field decides: only cuisine and course, nothing else', () => {
    const picks: Record<string, boolean> = { s3: false, s6: false };
    const rows = FIELDS.map((f) => bulkRow(f, 'proposal', picks[f.id]));
    expect(rows.filter((r) => r.changes).map((r) => r.field.path)).toEqual(['$.cuisine', '$.course']);
    expect(summarizeRows(rows)).toMatchObject({ changed: 2, opening: 2, quiet: 0, openingIds: ['s4', 's5'] });
    // with the group action «keep as is» no box changes anything
    expect(summarizeRows(FIELDS.map((f) => bulkRow(f, 'keep-current', true))).changed).toBe(0);
    expect(defaultSelected(FIELDS[0], 'proposal')).toBe(false);
    expect(defaultSelected(FIELDS[3], 'proposal')).toBe(true);
  });

  it('opensField follows the classifier: keep opens from anything but keep, code and hmac never', () => {
    expect(opensField({ action: 'drop' }, { action: 'keep' })).toBe(true);
    expect(opensField({ action: 'code' }, { action: 'keep' })).toBe(true);
    expect(opensField({ action: 'keep' }, { action: 'keep' })).toBe(false);
    expect(opensField({ action: 'drop' }, { action: 'code' })).toBe(false);
    expect(opensField({ action: 'drop' }, { action: 'hmac', arg: 'id' })).toBe(false);
    expect(opensField({ action: 'keep' }, { action: 'drop' })).toBe(false);
  });
});

describe('who approves, before applying (M2)', () => {
  const a = (name: string, roles: GroupApprover['roles'], self = false): GroupApprover => ({ name, displayName: name, roles, self });
  it('says nothing is needed when nothing opens', () => {
    expect(approvalPlan(0, 2, [a('anna.approver', ['policy-approver'])], false)).toMatchObject({ need: 0, short: false });
  });
  it('one approver for two approvals: the draft would wait, an admin can approve alone', () => {
    const p = approvalPlan(2, 2, [a('anna.approver', ['policy-approver']), a('marco', ['policy-approver'], true)], false);
    expect(p).toMatchObject({ need: 2, names: ['anna.approver'], short: true, adminOnly: false });
  });
  it('enough approvers, administrators only, nobody, unknown', () => {
    expect(approvalPlan(1, 2, [a('x', ['policy-approver']), a('y', ['policy-approver'])], false).short).toBe(false);
    expect(approvalPlan(1, 2, [a('ada', ['admin'])], false)).toMatchObject({ adminOnly: true, short: true, names: ['ada'] });
    expect(approvalPlan(1, 2, [a('marco', ['policy-approver'], true)], false)).toMatchObject({ names: [], short: true });
    expect(approvalPlan(1, 2, null, true)).toMatchObject({ unknown: true, selfAdmin: true, short: false });
    expect(approvalPlan(1, 1, [a('x', ['policy-approver'])], false).short).toBe(false);
  });
});

describe('who may withdraw a draft (major 2)', () => {
  const draft = { status: 'draft' as const, proposedBy: 'marco.dev' };
  it('the proposer or an admin, only while it is a draft', () => {
    expect(canWithdraw(draft, { username: 'marco.dev' }, false)).toBe(true);
    expect(canWithdraw(draft, { username: 'altra', displayName: 'Altra' }, false)).toBe(false);
    expect(canWithdraw(draft, { username: 'altra' }, true)).toBe(true);
    expect(canWithdraw({ ...draft, status: 'active' }, { username: 'marco.dev' }, true)).toBe(false);
    expect(canWithdraw({ status: 'draft' }, { username: 'marco.dev' }, false)).toBe(false);
    expect(canWithdraw(draft, null, false)).toBe(false);
  });
});

// ---------------------------------------------------------------- M3: messages follow the policy

const policy = (over: Partial<PolicyVersion> = {}): PolicyVersion => ({
  policyId: 'p-deliveries', version: 11, status: 'active', groups: ['deliveries'], proposedBy: 'system', opensData: false, opensValues: false, valueReasons: [], approvalsRequired: 0, approvals: [], diff: [], yamlBefore: '',
  yamlAfter: [
    'format: tt.policy/v1',
    'services:',
    '  couriers-ext:',
    '    ops:',
    '      POST /v1/assignments:',
    '        response:',
    '          $.status: code',
    "          '$.delivery_ref': hmac(id)",
    '          "$.reason": code # states',
    '  payments-ext:',
    '    ops:',
    '      POST /v1/payments:',
    '        response:',
    '          $.status: code',
    '          $.amount: bucket(num, [0, 100])',
  ].join('\n'),
  ...over,
});
const rule = (over: Partial<Rule> = {}): Pick<Rule, 'status' | 'kind' | 'effects'> => ({
  status: 'approved', kind: 'causal', effects: [{ id: 'e1', entity: 'assignment', kind: 'set', values: { status: 'PICKED_UP' }, after: '30s' }], ...over,
});

describe('the messages about states follow the policy (M3)', () => {
  it('reads the code fields of the author policy, once each', () => {
    expect(codeFieldsOf(policy().yamlAfter)).toEqual(['$.status', '$.reason']);
    expect(codeFieldsOf('services: {}')).toEqual([]);
    expect(codeFieldsOf(undefined)).toEqual([]);
  });

  it('statuses in clear and lifecycle rules: no approval to ask for', () => {
    const f = statesFacts([policy(), policy({ version: 9, status: 'superseded', yamlAfter: '$.x: code' })], ['deliveries'], [rule()]);
    expect(f).toEqual({ inClear: true, fields: ['$.status', '$.reason'], lifecycle: true });
    // a draft is not the policy in force; another group is not the group
    expect(statesFacts([policy({ status: 'draft' })], ['deliveries'], []).inClear).toBe(false);
    expect(statesFacts([policy()], ['orders'], []).inClear).toBe(false);
    expect(statesFacts([policy()], null, null)).toMatchObject({ inClear: true, lifecycle: false });
  });

  it('a lifecycle rule is an effect that sets a state, not a rejected or a plain creation', () => {
    expect(hasLifecycleRule([rule()])).toBe(true);
    expect(hasLifecycleRule([rule({ status: 'rejected' })])).toBe(false);
    expect(hasLifecycleRule([rule({ effects: [{ id: 'e1', entity: 'a', kind: 'create', values: {}, after: '0s' }] })])).toBe(false);
    expect(hasLifecycleRule([])).toBe(false);
  });

  it('names the fields a draft opens from the locations of the server', () => {
    expect(fieldOfLocation('services.restaurants-ext.ops.GET /menu.response.body.$.cuisine')).toBe('cuisine');
    expect(fieldOfLocation('services.x.ops.GET /a.request.headers.x-tenant')).toBe('x-tenant');
    expect(openedFieldsOf({ valueReasons: [{ code: 'keep', where: 'services.r.ops.GET /m.response.body.$.cuisine' }, { code: 'keep', where: 'services.r.ops.GET /m.response.body.$.course' }, { code: 'identity', where: 'identity.subject' }] })).toEqual(['cuisine', 'course']);
  });

  const draft: PolicyVersion = policy({
    version: 12, status: 'draft', origin: 'propose', opensData: true, opensValues: true, approvalsRequired: 2, proposedBy: 'marco.dev',
    valueReasons: [{ code: 'keep', where: 'services.restaurants-ext.ops.GET /menu.response.body.$.cuisine' }, { code: 'keep', where: 'services.restaurants-ext.ops.GET /menu.response.body.$.course' }],
  });

  it('the Panoramica card does not ask for keep on the statuses when they are codes', () => {
    setLang('it');
    session.user = { id: 'u1', username: 'marco.dev', displayName: 'Marco', authMethod: 'local', roles: ['operator'] } as never;
    const out = render(ApprovalNextStep, { props: { drafts: [draft], required: 2, facts: { inClear: true, fields: ['$.status', '$.reason'], lifecycle: true } } }).body;
    session.user = null;
    expect(out).toContain('già in chiaro, senza approvazione');
    expect(out).toContain('le regole con stati ci sono');
    expect(out).toContain('cuisine, course');
    expect(out).not.toContain('niente regole con stati');
    expect(out).not.toContain('valori finti e statici');
    expect(out).toContain('Ritira bozza');
    // the message to the approver names the two fields, not «stati e codici»
    expect(out).toContain('Fa uscire in chiaro cuisine, course');
  });

  it('without codes the card says what is lost, as before', () => {
    setLang('it');
    const out = render(ApprovalNextStep, { props: { drafts: [draft], required: 2, facts: { inClear: false, fields: [], lifecycle: false } } }).body;
    expect(out).toContain('niente regole con stati');
    expect(out).toContain('Prossimo passo: fai approvare i valori in chiaro');
  });
});

// ---------------------------------------------------------------- m6 / m13: the server's English, said in the console's language

describe('server texts in the language of the console (m6, m13)', () => {
  it('the drift of the test: header and enum', () => {
    setLang('it');
    expect(serverText("resp 200 header 'content-length' required changed: false -> true")).toBe('risposta 200 header «content-length»: obbligatorio cambiato (no → sì)');
    expect(serverText("req header 'server' required changed: true -> false")).toBe('richiesta header «server»: obbligatorio cambiato (sì → no)');
    expect(serverText('resp 402 body $ enum: 1 value(s) added')).toBe('risposta 402 corpo $: 1 valore aggiunto all’elenco dei valori');
    expect(serverText("field 'reason' enum: 1 value(s) added")).toBe('campo «reason»: 1 valore aggiunto all’elenco dei valori');
    setLang('en');
    expect(serverText("resp 200 header 'content-length' required changed: false -> true")).toBe('response 200 header «content-length»: required changed (no → yes)');
    setLang('it');
  });

  it('the gaps and the rule check', () => {
    setLang('it');
    expect(serverText('no 4xx or 5xx response observed')).toBe('nessuna risposta 4xx o 5xx osservata');
    expect(serverText('only 7 calls observed (minimum 20)')).toBe('solo 7 chiamate osservate (ne servono almeno 20)');
    expect(serverText('status 503 was never observed for GET /v1/assignments/{id}')).toContain('lo status 503 non è mai stato osservato per GET /v1/assignments/{id}');
    expect(serverText('resp 201 body $.status: every observed value is below the k threshold')).toContain('ogni valore osservato è sotto la soglia k');
  });

  it('status changes, fields and the warnings of the miner', () => {
    setLang('it');
    expect(serverText('new error status 503 (4.5% of calls)')).toBe('nuovo status di errore 503 (4.5% delle chiamate)');
    expect(serverText("field 'eta' added (optional, presence 12.0%)")).toBe('campo «eta» aggiunto (facoltativo, presente nel 12.0% dei casi)');
    expect(serverText('rule r-0018 stale: its cause was not seen in the window: nothing to judge')).toBe('la regola r-0018 è da riconfermare: la sua causa non si è vista nella finestra: niente da giudicare');
    expect(serverText('few distinct sampled users: 12 < k=20; raise the policy sampling or wait for more traffic')).toBe('pochi utenti campionati distinti: 12 su 20 necessari; alza il campionamento della policy o aspetta più traffico');
    expect(serverText('rule r-0003 confidence fell from 0.91 to 0.40 (outcome drift)')).toBe('la regola r-0003 è meno affidabile: confidenza da 0.91 a 0.40 (outcome drift)');
  });

  it('a text it does not know is shown as it came', () => {
    setLang('it');
    expect(serverText('something the server invented')).toBe('something the server invented');
    expect(serverText(undefined)).toBe('');
  });
});

// ---------------------------------------------------------------- m10: hosts listed once, with counters

describe('hosts without doubles and with counters (m10)', () => {
  const host = (pattern: string, over: Partial<HostEntry> = {}): HostEntry => ({
    pattern, group: 'deliveries', service: `host:${pattern}`, declared: false, declaredBy: [], exact: false, quarantined: false, calls: 100, serverErrors: 1, clientErrors: 0, errorRate: 0.01, latencyP50Ms: 20,
    firstSeen: '2026-10-25T14:00:00Z', lastSeen: '2026-10-25T15:00:00Z', callers: [{ service: 'deliveries-api', calls: 100 }], policies: ['p-deliveries'], ...over,
  });
  const reg = (patterns: HostEntry[]): HostsRegistry => ({
    domains: [{ domain: 'ip:private', calls: patterns.reduce((n, h) => n + h.calls, 0), firstSeen: null, lastSeen: null, patterns }],
    unlisted: host('unlisted', { calls: 0 }), invalid: host('invalid', { calls: 0 }), discovery: {},
  });

  it('a declared host and its history are one row, «dichiarato come …», with the calls added', () => {
    const before = host('ip:private:9731', { nowDeclaredAs: 'restaurants-ext', calls: 60, callers: [{ service: 'deliveries-api', calls: 60 }] });
    const after = host('ip:private:9731', { service: 'restaurants-ext', declared: true, declaredBy: ['p-deliveries'], exact: true, calls: 40, callers: [{ service: 'deliveries-api', calls: 40 }], firstSeen: '2026-10-25T15:10:00Z', lastSeen: '2026-10-25T16:00:00Z' });
    const other = host('ip:private:9732');
    const out = dedupeHosts(reg([before, after, other]));
    const rows = out.domains[0].patterns;
    expect(rows.map((h) => h.service)).toEqual(['restaurants-ext', 'host:ip:private:9732']);
    expect(rows[0]).toMatchObject({ declared: true, calls: 100, mergedCalls: 60, firstSeen: '2026-10-25T14:00:00Z', lastSeen: '2026-10-25T16:00:00Z' });
    expect(rows[0].callers).toEqual([{ service: 'deliveries-api', calls: 100 }]);
    expect(rows[0].nowDeclaredAs).toBeUndefined();
  });

  it('two groups calling the same pattern stay two rows; a plain repeat folds', () => {
    const a = host('ip:private:9731');
    const b = host('ip:private:9731', { group: 'orders' });
    expect(dedupeHosts(reg([a, b])).domains[0].patterns).toHaveLength(2);
    expect(dedupeHosts(reg([a, { ...a }])).domains[0].patterns).toHaveLength(1);
  });

  it('the counters count the IP hosts too, and the server counters win when it sends them', () => {
    const r = reg([host('ip:private:9731'), host('ip:private:9732'), host('ip:private:9733')]);
    expect(summarize(r, Date.parse('2026-10-25T17:00:00Z'))).toMatchObject({ domains: 0, hosts: 0, ips: 3, all: 3 });
    expect(summarize({ ...r, counters: { domains: 2, hosts: 5, ips: 3, undeclared: 4 } }, 0)).toMatchObject({ domains: 2, hosts: 5, ips: 3, all: 8, undeclared: 4 });
    // a missing or odd counter falls back to the local count
    expect(summarize({ ...r, counters: { hosts: -1 } }, 0)).toMatchObject({ hosts: 0, ips: 3 });
  });
});

// ---------------------------------------------------------------- M4: the rule editor catalog

describe('the rule editor does not wait for nothing (M4)', () => {
  const op = (service: string, o: string, statuses: number[]): OperationSummary =>
    ({ service, op: o, method: 'GET', pathTemplate: '/x', calls: 10, firstSeen: '', lastSeen: '', latencyMs: { p50: 1, p95: 1, p99: 1 }, statuses: statuses.map((status) => ({ status, frequency: 0.5, calls: 5 })), fewSamples: false });

  it('a partial catalog from the operations: services, operations and the statuses seen, no entities', () => {
    const c = catalogFromOperations([op('couriers-ext', 'POST /v1/assignments', [201, 503]), op('couriers-ext', 'GET /v1/assignments/{id}', [200]), op('payments-ext', 'POST /v1/payments', [201, 402])]);
    expect(c.entities).toEqual([]);
    expect(c.services.map((s) => s.name)).toEqual(['couriers-ext', 'payments-ext']);
    expect(c.services[0].ops.map((o) => [o.op, o.statuses])).toEqual([['POST /v1/assignments', [201, 503]], ['GET /v1/assignments/{id}', [200]]]);
    // the editor can use it as it is
    expect(normalizeCatalog(c)?.services).toHaveLength(2);
  });

  it('the catalog read once is kept per group selection for the next opening', () => {
    forgetCatalogs();
    expect(keptCatalog(['deliveries'])).toBeUndefined();
    keepCatalog(['deliveries'], { services: [], entities: [] }, 1000);
    expect(keptCatalog(['deliveries'])?.at).toBe(1000);
    expect(keptCatalog(['orders'])).toBeUndefined();
    expect(keptCatalog(null)).toBeUndefined();
    keepCatalog(undefined, { services: [], entities: [] }, 2000);
    expect(keptCatalog(null)?.at).toBe(2000);
    forgetCatalogs();
  });
});

// ---------------------------------------------------------------- m7: the preparation is found again

describe('the preparation of the mock survives leaving the page (m7)', () => {
  it('is found again by group even when the browser storage is unavailable', () => {
    forgetPreparations();
    expect(lastPreparation('deliveries')).toBeNull();
    const run = { jobId: 'job-1', status: 'running' as const, steps: [{ id: 'archetypes' as const, status: 'done' as const }, { id: 'world' as const, status: 'running' as const }] };
    rememberPreparation('deliveries', run, '2026-10-25T16:00:00Z');
    const back = lastPreparation('deliveries');
    expect(back?.jobId).toBe('job-1');
    expect(back?.run.steps.map((s) => s.status)).toEqual(['done', 'running']);
    // the newer steps replace the older
    rememberPreparation('deliveries', { ...run, steps: [...run.steps, { id: 'pack' as const, status: 'running' as const }] }, '2026-10-25T16:00:00Z');
    expect(lastPreparation('deliveries')?.run.steps).toHaveLength(3);
    // another group has its own
    expect(lastPreparation('orders')).toBeNull();
    // a run without a job id is not kept
    rememberPreparation('orders', { ...run, jobId: '' }, '2026-10-25T16:00:00Z');
    expect(lastPreparation('orders')).toBeNull();
    forgetPreparations();
  });
});

describe('the buttons to take back a draft and a rule (major 1 and 2)', () => {
  const approved = (id: string, over: Partial<Rule> = {}) => ({ id, status: 'approved', ...over }) as Rule;
  const draft = (over: Partial<PolicyVersion> = {}): PolicyVersion => ({
    policyId: 'p-deliveries', version: 12, status: 'draft', groups: ['deliveries'], proposedBy: 'marco.dev', opensData: true, opensValues: true, valueReasons: [], approvalsRequired: 2, approvals: [], diff: [], yamlBefore: '', yamlAfter: '', ...over,
  });

  it('the page of a replaced rule says both are in the packs and offers to retire it', () => {
    setLang('it');
    const out = render(RetireRule, { props: { rule: approved('r-0018'), replacedBy: approved('r-0019') } }).body;
    expect(out).toContain('Ritira regola');
    expect(out).toContain('r-0019');
    expect(out).toContain('restano attive tutte e due');
    const waiting = render(RetireRule, { props: { rule: approved('r-0018'), replacedBy: approved('r-0019', { status: 'draft' }) } }).body;
    expect(waiting).toContain('quando viene approvata, questa regola esce dai pacchetti');
    expect(waiting).not.toContain('restano attive tutte e due');
  });

  it('a server without the route turns the button into an explanation', () => {
    setLang('it');
    features.retire = false;
    const out = render(RetireRule, { props: { rule: approved('r-0018') } }).body;
    features.retire = true;
    expect(out).toContain('non offre ancora il ritiro delle regole');
    expect(out).not.toContain('data-testid="retire-rule-button"');
  });

  it('the draft can be withdrawn by its proposer, not by another person; nothing for a draft already decided', () => {
    setLang('it');
    session.user = { id: 'u1', username: 'marco.dev', displayName: 'Marco', authMethod: 'local', roles: ['operator'] } as never;
    expect(render(WithdrawDraft, { props: { version: draft() } }).body).toContain('Ritira bozza');
    expect(render(WithdrawDraft, { props: { version: draft({ status: 'active' }) } }).body).not.toContain('Ritira bozza');
    session.user = { id: 'u2', username: 'altra', displayName: 'Altra', authMethod: 'local', roles: ['policy-approver'] } as never;
    const other = render(WithdrawDraft, { props: { version: draft(), explain: true } }).body;
    expect(other).not.toContain('data-testid="withdraw-draft"');
    expect(other).toContain('chi l’ha proposta o un amministratore');
    session.user = { id: 'u3', username: 'ada', displayName: 'Ada', authMethod: 'local', roles: ['admin'] } as never;
    expect(render(WithdrawDraft, { props: { version: draft() } }).body).toContain('Ritira bozza');
    features.withdraw = false;
    expect(render(WithdrawDraft, { props: { version: draft() } }).body).toContain('non offre ancora il ritiro delle bozze');
    features.withdraw = true;
    session.user = null;
  });
});
