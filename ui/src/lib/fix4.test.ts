// Usability round 4: the pure parts behind the fixes (rule editor catalog, assistant rows, approval card, rates).
// Invented data only.
import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import { catalogNotice, normalizeCatalog } from './rule-catalog';
import { dedupeAssist, suggestionsOf, uniqBy } from './assist';
import { approverNames, draftLink, pendingOpeningDrafts } from './approval';
import { fmtRate } from './format';
import { setLang } from './i18n/index.svelte';
import type { AssistService, GroupApprover, PolicyVersion, RuleCatalog } from './api';
import Loading from '../components/Loading.svelte';
import Tabs from '../components/Tabs.svelte';
import ApprovalNextStep from '../components/ApprovalNextStep.svelte';

const op = (name: string, statuses: number[], response: { from: string; name: string; values?: string[] }[] = []) => ({ op: name, statuses, params: [], request: [], response });

describe('rule editor catalog (M1)', () => {
  it('has every name once: a repeated service, operation, status or value cannot stop the editor', () => {
    const cat: RuleCatalog = {
      services: [
        { name: 'orders-api', ops: [op('POST /orders', [201, 402, 201]), op('POST /orders', [409])] },
        { name: 'orders-api', ops: [op('GET /orders/{id}', [200])] },
      ],
      entities: [
        { name: 'order', service: 'orders-api', idField: 'id', idDomain: 'order', ops: ['POST /orders', 'POST /orders'], fields: [{ from: 'response', name: 'status', values: ['created', 'created', 'paid'] }] },
        { name: 'order', service: 'orders-api', idField: 'id', idDomain: 'order', ops: ['GET /orders/{id}'], fields: [{ from: 'response', name: 'status', values: ['shipped'] }] },
        // an entity of a service that is not in the catalog (another team's) stays out
        { name: 'ticket', service: 'support-api', idField: 'id', idDomain: 'ticket', ops: [], fields: [] },
      ],
    };
    const n = normalizeCatalog(cat)!;
    expect(n.services.map((s) => s.name)).toEqual(['orders-api']);
    expect(n.services[0].ops.map((o) => o.op)).toEqual(['POST /orders', 'GET /orders/{id}']);
    expect(n.services[0].ops[0].statuses).toEqual([201, 402, 409]);
    expect(n.entities.map((e) => e.name)).toEqual(['order']);
    expect(n.entities[0].ops).toEqual(['POST /orders', 'GET /orders/{id}']);
    expect(n.entities[0].fields).toHaveLength(1);
    expect(n.entities[0].fields[0].values).toEqual(['created', 'paid', 'shipped']);
    expect(normalizeCatalog(undefined)).toBeUndefined();
  });

  it('says what is missing and never leaves the editor without an answer', () => {
    expect(catalogNotice(undefined)).toEqual({ noServices: true, noEntities: true, noValues: false });
    const noStates = normalizeCatalog({ services: [{ name: 'orders-api', ops: [op('POST /orders', [201])] }], entities: [] })!;
    expect(catalogNotice(noStates)).toEqual({ noServices: false, noEntities: true, noValues: false });
    const noValues = normalizeCatalog({ services: [{ name: 'orders-api', ops: [] }], entities: [{ name: 'order', service: 'orders-api', idField: 'id', idDomain: 'o', ops: [], fields: [{ from: 'response', name: 'status' }] }] })!;
    expect(catalogNotice(noValues)).toEqual({ noServices: false, noEntities: false, noValues: true });
    const full = normalizeCatalog({ services: [{ name: 'orders-api', ops: [] }], entities: [{ name: 'order', service: 'orders-api', idField: 'id', idDomain: 'o', ops: [], fields: [{ from: 'response', name: 'status', values: ['created'] }] }] })!;
    expect(catalogNotice(full)).toEqual({ noServices: false, noEntities: false, noValues: false });
  });
});

describe('policy assistant rows (M2)', () => {
  const f = (path: string, part: 'request' | 'response' = 'response') => ({ id: 'x', service: 's', op: 'o', part, path, shape: 'str', observed: 1, distinctEstimate: 1, suggestion: 'drop', reason: '', reasonCode: 'id', current: { action: 'drop' } }) as never;
  const opOf = (name: string, fields: unknown[]) => ({ op: name, declared: true, calls: 10, needCalls: 0, rawOps: [name], fields }) as never;
  const svc = (service: string, name: string, ops: unknown[], calls = 10) => ({ service, kind: 'external', declared: true, name, calls, ops }) as unknown as AssistService;

  it('lists a field once even when the server sends it twice', () => {
    const out = dedupeAssist([svc('catalog-api', 'catalog-api', [opOf('GET /p', [f('$.id'), f('$.id'), f('$.category')])])]);
    expect(suggestionsOf(out).map((s) => s.path)).toEqual(['$.id', '$.category']);
  });

  it('folds the old host row into the declared service and drops it when nothing is left', () => {
    const out = dedupeAssist([
      svc('host:ip:private:9301', 'catalog-api', [opOf('GET /p', [f('$.id'), f('$.price')])], 300),
      svc('catalog-api', 'catalog-api', [opOf('GET /p', [f('$.id'), f('$.category')])], 500),
    ]);
    expect(out.map((s) => s.service)).toEqual(['host:ip:private:9301', 'catalog-api']);
    // the old row keeps only what the main block lacks; the main block is untouched
    expect(out[0].ops[0].fields.map((x) => x.path)).toEqual(['$.price']);
    const gone = dedupeAssist([svc('host:ip:private:9301', 'catalog-api', [opOf('GET /p', [f('$.id')])], 3), svc('catalog-api', 'catalog-api', [opOf('GET /p', [f('$.id')])], 5)]);
    expect(gone.map((s) => s.service)).toEqual(['catalog-api']);
  });

  it('uniqBy keeps the first of each key (BulkReview and wizard rows)', () => {
    expect(uniqBy([{ k: 'a', v: 1 }, { k: 'b', v: 2 }, { k: 'a', v: 3 }], (x) => x.k)).toEqual([{ k: 'a', v: 1 }, { k: 'b', v: 2 }]);
    expect(uniqBy([], (x: string) => x)).toEqual([]);
  });
});

describe('the approval next step (B1)', () => {
  const v = (over: Partial<PolicyVersion>): PolicyVersion => ({
    policyId: 'p-orders', version: 7, status: 'draft', groups: ['orders'], proposedBy: 'marta.dev', opensData: true, opensValues: true, valueReasons: [], approvalsRequired: 2, approvals: [], diff: [], yamlBefore: '', yamlAfter: '', ...over,
  });

  it('picks the newest waiting draft that opens values, one per group, only for the groups in view', () => {
    const list = [
      v({ version: 5 }),
      v({ version: 7 }),
      v({ policyId: 'p-shop', version: 3, groups: ['shop'] }),
      v({ version: 8, opensValues: false, approvalsRequired: 0 }),
      v({ version: 9, status: 'active' }),
      v({ version: 10, origin: 'starter' }),
      v({ policyId: 'p-x', version: 4, groups: ['x'], approvals: [{ by: 'a', at: '' }, { by: 'b', at: '' }] }),
    ];
    expect(pendingOpeningDrafts(list, null).map((d) => `${d.policyId}@${d.version}`)).toEqual(['p-orders@7', 'p-shop@3']);
    expect(pendingOpeningDrafts(list, ['orders']).map((d) => d.version)).toEqual([7]);
    expect(pendingOpeningDrafts(list, [])).toEqual([]);
  });

  it('links to the draft panel of Sorgenti', () => {
    expect(draftLink({ policyId: 'p-orders', version: 7 }, 'https://tt.example.test/')).toBe('https://tt.example.test/#/sources?tab=policy&draft=p-orders%407');
  });

  it('asks the approvers, not yourself, and an admin only when nobody else can', () => {
    const a = (name: string, roles: GroupApprover['roles'], self = false): GroupApprover => ({ name, displayName: name.toUpperCase(), roles, self });
    expect(approverNames([a('ada', ['admin']), a('piero', ['policy-approver']), a('marta', ['policy-approver'], true)])).toEqual({ names: ['PIERO'], adminOnly: false });
    expect(approverNames([a('ada', ['admin']), a('marta', ['policy-approver'], true)])).toEqual({ names: ['ADA'], adminOnly: true });
    expect(approverNames([a('marta', ['admin'], true)])).toEqual({ names: [], adminOnly: false });
  });

  it('renders the card with what is lost, and nothing without a draft', () => {
    setLang('it');
    const out = render(ApprovalNextStep, { props: { drafts: [v({})], required: 2 } }).body;
    expect(out).toContain('Prossimo passo');
    expect(out).toContain('p-orders v7');
    expect(out).toContain('niente regole con stati');
    expect(out).toContain('niente campi collegati');
    expect(out).toContain('#/sources?tab=policy&amp;draft=p-orders%407');
    // The card is generic: it names a draft waiting for approval, not what the values are.
    expect(out).not.toMatch(/status code|codici di stato in chiaro/i);
    expect(render(ApprovalNextStep, { props: { drafts: [] } }).body).not.toContain('Prossimo passo');
    const wiz = render(ApprovalNextStep, { props: { drafts: [v({})], capturing: 6 } }).body;
    expect(wiz).toContain('La cattura è già attiva con la policy v6');
  });
});

describe('cosmetics', () => {
  it('shows events per minute with at most one decimal, never a lookalike thousands separator', () => {
    setLang('it');
    expect(fmtRate(584.943)).toBe('585');
    expect(fmtRate(58.4943)).toBe('58,5');
    expect(fmtRate(0.25)).toBe('0,3');
    expect(fmtRate(0)).toBe('0');
    setLang('en');
    expect(fmtRate(58.4943)).toBe('58.5');
    setLang('it');
  });

  it('a skeleton says what is being computed, and the Policy tab says what its count counts', () => {
    setLang('it');
    expect(render(Loading, { props: { label: 'Sto calcolando i campi' } }).body).toContain('Sto calcolando i campi');
    expect(render(Loading, { props: {} }).body).toContain('Sto caricando');
    const tabs = render(Tabs, { props: { tabs: [{ id: 'sources', label: 'Sorgenti', count: 3 }, { id: 'policy', label: 'Policy', count: 0, countLabel: 'bozze in attesa' }], value: 'policy', label: 'x', children: (() => {}) as never } }).body;
    expect(tabs).toContain('bozze in attesa');
  });
});
