import { describe, expect, it } from 'vitest';
import {
  addEffect, errorBodyProblem, errorBodyText, finalize, localProblems, newDefinition, newEffect, parseDelay, parseErrorBody, preview, removeEffect, renameRow, rowProblems, setChance,
  setRowText, setRowValue, setWhich, simpleOutcomes, whichOf,
} from './rule-editor';
import { ruleDefinition } from './api/rest/map';
import type { WireRule } from './api/rest/wire';
import { linkedFields } from './api/rest/contract';
import { ruleCatalog } from './api/mock/fixtures';
import { createMockApi } from './api/mock/adapter';

// Invented demo data only.

function cancelRule() {
  const cat = ruleCatalog();
  const def = newDefinition();
  def.title = 'Un ordine annullato blocca la spedizione';
  def.cause = { service: 'shop-api', op: 'POST /orders/{id}/cancel', when: { status: [200] }, bind: {} };
  const state = newEffect(def, 'state', cat);
  state.entity = 'order';
  state.set = { status: 'CANCELLED' };
  addEffect(def, state);
  setWhich(def, state, 'ref:req.path|id');
  const next = newEffect(def, 'next', cat);
  next.respond = { service: 'shipping-ext', op: 'GET /v1/shipments', status: 503, times: 1, example: 'carrier-unavailable' };
  addEffect(def, next);
  return def;
}

describe('rule editor', () => {
  it('builds a definition the server accepts', () => {
    const def = cancelRule();
    expect(localProblems(def)).toEqual([]);
    expect(whichOf(def, def.effects![0])).toBe('ref:req.path|id');
    const out = finalize(def);
    expect(out.cause!.bind).toEqual({ order: { from: 'req.path', name: 'id' } });
    expect(out.effects![0]).toMatchObject({ entity: 'order', target_id: '${order}', set: { status: 'CANCELLED' } });
    expect(out.effects![1].respond).toEqual({ service: 'shipping-ext', op: 'GET /v1/shipments', status: 503, times: 1, example: 'carrier-unavailable' });
    expect(out.outcomes).toEqual([{ name: 'always', p: 1, effects: ['effect-1', 'effect-2'] }]);
  });

  it('keeps the binds of keyed targets and counters (rules v1.8)', () => {
    const def = newDefinition();
    def.title = 'Signing gives the consent';
    def.cause = { service: 'app-api', op: 'POST /documents/{documentId}/sign', when: { status: [200] }, bind: {
      doc: { from: 'req.path', name: 'documentId' }, email: { from: 'req.body', path: '$.email' }, unused: { from: 'req.path', name: 'x' } } };
    def.effects = [
      { id: 'consent-updated', entity: 'consent', target_key: { documentId: '${doc}' }, set: { signed: true }, after: '0s' },
      { id: 'unique', respond: { service: 'app-api', op: 'POST /documents/{documentId}/sign', status: 409, limit: { n: 1, key: '${email}' } }, after: '0s' },
    ];
    def.outcomes = [{ name: 'always', p: 1, effects: ['consent-updated', 'unique'] }];
    expect(localProblems(def)).toEqual([]);
    const out = finalize(def);
    expect(Object.keys(out.cause!.bind!).sort()).toEqual(['doc', 'email']);
    expect(out.effects![1].respond!.limit).toEqual({ n: 1, key: '${email}' });
  });

  it('writes the rule in plain words', () => {
    const lines = preview(cancelRule());
    expect(lines[0]).toContain('POST /orders/{id}/cancel');
    expect(lines[1]).toContain('CANCELLED');
    expect(lines[2]).toContain('GET /v1/shipments');
    expect(lines[2]).toContain('503');
  });

  it('keeps the branches coherent', () => {
    const def = cancelRule();
    setChance(def, 0.25);
    expect(def.outcomes).toEqual([
      { name: 'always', p: 0.25, effects: ['effect-1', 'effect-2'] },
      { name: 'never', p: 0.75, effects: [] },
    ]);
    expect(simpleOutcomes(def)).toBe(true);
    def.effects![1].after_effect = 'effect-1';
    removeEffect(def, 'effect-1');
    expect(def.effects![0].after_effect).toBeUndefined();
    expect(def.outcomes![0].effects).toEqual(['effect-2']);
  });

  it('says what is missing before asking the server', () => {
    const def = newDefinition();
    expect(localProblems(def).length).toBeGreaterThan(1);
    const r = cancelRule();
    r.effects![0].after = 'soon' as never;
    expect(localProblems(r).join(' ')).toMatch(/1/);
    expect(parseDelay('2m-10m')).toEqual({ min: '2m', max: '10m' });
    expect(parseDelay('5m')).toBe('5m');
    expect(parseDelay('5 minutes')).toBeNull();
  });

  it('stores a manual rule in the demo and refuses an unknown operation', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.auth.login({ username: 'elena.admin', password: 'demo' });
    const r = await api.rules.create(finalize(cancelRule()));
    expect(r.origin).toBe('manual');
    expect(r.status).toBe('draft');
    expect(r.effects.map((e) => e.kind)).toEqual(['set', 'respond']);
    const bad = finalize(cancelRule());
    bad.cause!.op = 'POST /ordini';
    await expect(api.rules.create(bad)).rejects.toMatchObject({ serverCode: 'invalid_rule' });
    expect((await api.rules.check(bad)).problems[0].code).toBe('unknown_op');
  });
});

describe('rule editor: derived values and error bodies (rules 1.10)', () => {
  const eta = { $derive: { fn: 'date', offset: '+3d', format: 'date' } };
  function plannedRule() {
    const cat = ruleCatalog();
    const def = newDefinition();
    def.title = 'Una spedizione creata riceve la consegna prevista';
    def.cause = { service: 'shop-api', op: 'POST /orders', when: { status: [201] }, bind: { order: { from: 'resp.body', path: '$.id' } } };
    const c = newEffect(def, 'create', cat);
    c.entity = 'shipment';
    c.create = { status: 'CREATED', orderId: { $derive: { fn: 'copy', args: ['${order}'] } }, eta: structuredClone(eta) };
    addEffect(def, c);
    return def;
  }

  it('keeps derived objects through the form, finalize and the server mapping, and keeps the variables they read', () => {
    const def = plannedRule();
    expect(localProblems(def)).toEqual([]);
    const out = finalize(def);
    expect(out.cause!.bind).toEqual({ order: { from: 'resp.body', path: '$.id' } });
    expect(out.effects![0].create).toEqual({ status: 'CREATED', orderId: { $derive: { fn: 'copy', args: ['${order}'] } }, eta });
    // The server answers the stored rule: the editor reads it back unchanged (JSON round-trip).
    const wire = JSON.parse(JSON.stringify({ id: 'r-0100', status: 'draft', ...out })) as WireRule;
    expect(ruleDefinition(wire).effects).toEqual(out.effects);
    expect(preview(def)[1]).toContain('date(now +3d)');
  });

  it('renames a field without turning its derived value into a text', () => {
    const vals = { status: 'CREATED', eta: structuredClone(eta) };
    expect(renameRow(vals, 'eta', 'deliveryEta')).toEqual({ status: 'CREATED', deliveryEta: eta });
    expect(Object.keys(renameRow(vals, 'status', 'state'))).toEqual(['state', 'eta']);
    expect(setRowText(vals, 'status', '3')).toEqual({ status: 3, eta });
    expect(setRowText(vals, 'eta', JSON.stringify(eta))).toEqual({ status: 'CREATED', eta });
    expect(setRowValue(vals, 'total', { $derive: { fn: 'sum', args: ['${field:items[*].price}'] } }).total).toEqual({ $derive: { fn: 'sum', args: ['${field:items[*].price}'] } });
  });

  it('says what is wrong in a derived value before asking the server, and puts the server problems on the field', () => {
    const def = plannedRule();
    def.effects![0].create!.eta = { $derive: { fn: 'date', offset: 'soon' } };
    expect(localProblems(def).join(' ')).toContain('eta');
    const problems = [
      { path: 'effects[0].create.eta', code: 'derived_type', message: 'date computes a text, but field eta is a number' },
      { path: 'effects[0].create', code: 'bad_derived', message: 'field "orderId": copy takes 1 argument(s)' },
      { path: 'effects[1].create.eta', code: 'unknown_field', message: 'other effect' },
    ];
    expect(rowProblems(problems, 0, 'create', 'eta').map((p) => p.code)).toEqual(['derived_type']);
    expect(rowProblems(problems, 0, 'create', 'orderId').map((p) => p.code)).toEqual(['bad_derived']);
    expect(rowProblems(problems, 0, 'set', 'eta')).toEqual([]);
  });

  it('demo: checks derived values like the server and stores them', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.auth.login({ username: 'elena.admin', password: 'demo' });
    const def = finalize(plannedRule());
    const r = await api.rules.create(def);
    expect(r.definition.effects![0].create!.eta).toEqual(eta);
    const bad = finalize(plannedRule());
    bad.effects![0].create!.status = { $derive: { fn: 'sum', args: ['${field:items[*].price}'] } };
    const check = await api.rules.check(bad);
    expect(check.problems.map((p) => [p.path, p.code])).toEqual([['effects[0].create.status', 'unknown_field']]);
    const demo = (await api.rules.list()).find((x) => x.id === 'r-0016')!;
    expect(demo.definition.effects![0].create!.eta).toEqual({ $derive: { fn: 'date', offset: '+3d', format: 'date-time' } });
  });

  it('reads, checks and keeps the error body of a respond effect', () => {
    expect(parseErrorBody('')).toEqual({});
    expect(parseErrorBody('{"code":"OUT_OF_STOCK"}')).toEqual({ body: { code: 'OUT_OF_STOCK' } });
    expect(parseErrorBody('[1, 2]')).toEqual({ body: [1, 2] });
    expect(parseErrorBody('"busy"')).toEqual({ body: 'busy' });
    expect(parseErrorBody('Service unavailable')).toEqual({ body: 'Service unavailable' });
    expect(parseErrorBody('{"code":')).toEqual({ error: 'json' });
    expect(errorBodyProblem(undefined)).toBeNull();
    expect(errorBodyProblem(42)).toBe('type');
    expect(errorBodyProblem({ message: 'x'.repeat(17000) })).toBe('size');
    expect(errorBodyText({ code: 'OUT_OF_STOCK' })).toBe('{\n  "code": "OUT_OF_STOCK"\n}');
    const def = cancelRule();
    def.effects![1].respond!.body = { code: 'CARRIER_DOWN', message: 'Corriere non raggiungibile' };
    expect(finalize(def).effects![1].respond!.body).toEqual({ code: 'CARRIER_DOWN', message: 'Corriere non raggiungibile' });
    def.effects![1].respond!.body = 42;
    expect(localProblems(def).join(' ')).toMatch(/2/);
    delete def.effects![1].respond!.body;
    expect('body' in finalize(def).effects![1].respond!).toBe(false);
  });
});

describe('linked fields', () => {
  it('reads x-tt-dependencies of nested objects and list items', () => {
    const schema = {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          items: {
            type: 'object',
            properties: { macro: { type: 'string' }, category: { type: 'string' } },
            'x-tt-dependencies': [
              { fields: ['category', 'macro'], partial: true, combinations: [{ values: ['Forni', 'Grandi elettrodomestici'], at_least: 100 }, { values: ['Smartphone', 'Telefonia'], at_least: 20 }] },
              { fields: ['category', 'price'], combinations: [{ values: ['Forni', { min: 200, max: 500 }], at_least: 20 }] },
            ],
          },
        },
      },
    };
    const l = linkedFields(schema);
    expect(l).toHaveLength(2);
    expect(l[0]).toEqual({ at: 'items[]', fields: ['category', 'macro'], partial: true, combos: [{ values: ['Forni', 'Grandi elettrodomestici'], atLeast: 100 }, { values: ['Smartphone', 'Telefonia'], atLeast: 20 }] });
    expect(l[1].combos[0].values[1]).toBe('200–500');
  });
});
