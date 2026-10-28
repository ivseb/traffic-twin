import { describe, expect, it } from 'vitest';
import {
  argKind, checkDerived, derivedFormula, derivedRefs, evalDerived, exampleEnv, exampleInputs, isDerived, makeArg, newDerived, switchFn, typedValue, withSpec,
  DERIVE_FNS, type DerivedValue,
} from './derive';

// Invented e-commerce data only. The cases mirror internal/derive (derive_test.go).

const d = (spec: Record<string, unknown>) => ({ $derive: spec }) as unknown as DerivedValue;
const NOW = new Date('2026-10-28T10:00:00Z');
const order = { items: [{ price: 10.1, qty: 2 }, { price: 12.2, qty: 1 }, { price: 8, qty: 3 }], total: 30.3, shipping: 4.9, placedAt: '2026-10-01T08:00:00Z' };
const run = (v: DerivedValue, env: Partial<Parameters<typeof evalDerived>[1]> = {}) => evalDerived(v, { now: NOW, object: order, vars: { order: 'ORD-SYN-0042', qty: 3 }, effects: { 'shipment-created': 'SHP-SYN-0091' }, ...env });

describe('derived values: checks', () => {
  it('recognises the object with the only key $derive', () => {
    expect(isDerived(d({ fn: 'sum' }))).toBe(true);
    expect(isDerived({ $derive: {}, x: 1 })).toBe(false);
    expect(isDerived('${order}')).toBe(false);
  });
  it('accepts every function with the arity of the server', () => {
    for (const fn of DERIVE_FNS) expect(checkDerived(newDerived(fn)), fn).toBeNull();
    expect(checkDerived(d({ fn: 'sub', args: [1] }))).toMatchObject({ code: 'args', params: { fn: 'sub', lo: 2, hi: 2 } });
    expect(checkDerived(d({ fn: 'add', args: [1, 2, 3, 4, 5, 6, 7, 8, 9] }))?.code).toBe('args');
    expect(checkDerived(d({ fn: 'template', args: [1], template: 'NNNN' }))?.code).toBe('args');
    expect(checkDerived(d({ fn: 'avg', args: [1] }))?.code).toBe('fn');
  });
  it('refuses the options of another function, unknown keys and bad offsets', () => {
    expect(checkDerived(d({ fn: 'sum', args: [1], offset: '+1d' }))?.code).toBe('onlyDate');
    expect(checkDerived(d({ fn: 'sum', args: [1], digits: 2 }))?.code).toBe('onlyRound');
    expect(checkDerived(d({ fn: 'sum', args: [1], template: 'NNNN' }))?.code).toBe('onlyTemplate');
    expect(checkDerived(d({ fn: 'sum', args: [1], extra: true }))).toMatchObject({ code: 'unknownKey', params: { key: 'extra' } });
    expect(checkDerived(d({ fn: 'date', offset: 'tomorrow' }))?.code).toBe('offset');
    expect(checkDerived(d({ fn: 'date', format: 'iso' }))?.code).toBe('format');
    expect(checkDerived(d({ fn: 'round', args: [1], digits: 7 }))?.code).toBe('digits');
    expect(checkDerived(d({ fn: 'template', template: '' }))?.code).toBe('template');
  });
  it('checks the arguments: texts only for copy, known references, nesting at most 4 levels', () => {
    expect(checkDerived(d({ fn: 'sum', args: ['hello'] }))).toMatchObject({ code: 'argText', params: { n: 1 } });
    expect(checkDerived(d({ fn: 'copy', args: ['hello'] }))).toBeNull();
    expect(checkDerived(d({ fn: 'sum', args: ['${field:items[*]price}'] }))?.code).toBe('argRef');
    expect(checkDerived(d({ fn: 'add', args: [true, 1] }))?.code).toBe('argType');
    let v: DerivedValue = d({ fn: 'add', args: [1, 1] });
    for (let i = 0; i < 4; i++) v = d({ fn: 'add', args: [v, 1] });
    expect(checkDerived(v)).toBeNull();
    expect(checkDerived(d({ fn: 'add', args: [v, 1] }))?.code).toBe('depth');
  });
  it('tells the kinds of arguments apart', () => {
    expect(['${now}', '${order}', '${field:items[*].price}', '${effect:shipment-created}', 'x', 3, { $derive: { fn: 'sum' } }].map(argKind)).toEqual(['now', 'var', 'field', 'effect', 'text', 'number', 'nested']);
    expect(makeArg('field', 'items[*].price')).toBe('${field:items[*].price}');
    expect(makeArg('number', '2.5')).toBe(2.5);
    expect(makeArg('var', 'order')).toBe('${order}');
  });
});

describe('derived values: evaluation', () => {
  it('sums a list field, counts, and renders numbers as the server', () => {
    expect(run(d({ fn: 'sum', args: ['${field:items[*].price}'] }))).toEqual({ ok: true, value: 30.3 });
    expect(run(d({ fn: 'sum', args: ['${field:items[*].price}', '${field:shipping}'] }))).toEqual({ ok: true, value: 35.2 });
    expect(run(d({ fn: 'count', args: ['${field:items}'] }))).toEqual({ ok: true, value: 3 });
    expect(run(d({ fn: 'count', args: ['${field:missing}'] }))).toEqual({ ok: true, value: 0 });
    expect(run(d({ fn: 'mul', args: ['${field:total}', 100] }))).toEqual({ ok: true, value: 3030 });
    expect(run(d({ fn: 'round', args: [d({ fn: 'div', args: ['${field:total}', 3] })] }))).toEqual({ ok: true, value: 10.1 });
    expect(run(d({ fn: 'round', args: [2.345678], digits: 0 }))).toEqual({ ok: true, value: 2 });
    expect(run(d({ fn: 'min', args: [3, '${qty}', 7] }))).toEqual({ ok: true, value: 3 });
    expect(run(d({ fn: 'max', args: [3, '${field:shipping}'] }))).toEqual({ ok: true, value: 4.9 });
    expect(run(d({ fn: 'sub', args: ['${field:total}', '${field:shipping}'] }))).toEqual({ ok: true, value: 25.4 });
  });
  it('fails like the server: division by zero, a list where one value is needed, a text that is not a number', () => {
    expect(run(d({ fn: 'div', args: [1, 0] }))).toMatchObject({ ok: false, error: 'division by zero' });
    expect(run(d({ fn: 'add', args: ['${field:items[*].price}', 1] }))).toMatchObject({ ok: false, error: 'add needs one value per argument' });
    expect(run(d({ fn: 'add', args: ['${order}', 1] }))).toMatchObject({ ok: false, error: 'add of a value that is not a number' });
  });
  it('leaves the field out when a reference has no value', () => {
    expect(run(d({ fn: 'copy', args: ['${missing}'] }))).toEqual({ ok: false, missing: true });
    expect(run(d({ fn: 'sum', args: ['${field:nothing[*].price}'] }))).toEqual({ ok: false, missing: true });
  });
  it('copies values, effects and lists', () => {
    expect(run(d({ fn: 'copy', args: ['${order}'] }))).toEqual({ ok: true, value: 'ORD-SYN-0042' });
    expect(run(d({ fn: 'copy', args: ['${effect:shipment-created}'] }))).toEqual({ ok: true, value: 'SHP-SYN-0091' });
    expect(run(d({ fn: 'copy', args: ['${field:items[*].qty}'] }))).toEqual({ ok: true, value: [2, 1, 3] });
  });
  it('computes dates from the virtual clock or a base date', () => {
    expect(run(d({ fn: 'date', offset: '+30d', format: 'date' }))).toEqual({ ok: true, value: '2026-11-27' });
    expect(run(d({ fn: 'date', offset: '-12h' }))).toEqual({ ok: true, value: '2026-10-27T22:00:00Z' });
    expect(run(d({ fn: 'date' }))).toEqual({ ok: true, value: '2026-10-28T10:00:00Z' });
    expect(run(d({ fn: 'date', args: ['${field:placedAt}'], offset: '+90m' }))).toEqual({ ok: true, value: '2026-10-01T09:30:00Z' });
    expect(run(d({ fn: 'date', args: ['${order}'] }))).toMatchObject({ ok: false, error: 'the base of a date is not a date' });
  });
  it('shows the template of an id (the mock generates it)', () => {
    expect(run(d({ fn: 'template', template: "'INV'-NNNN" }))).toEqual({ ok: true, value: "'INV'-NNNN" });
  });
});

describe('derived values: editor helpers', () => {
  it('lists the references and writes a short formula', () => {
    const v = d({ fn: 'add', args: [d({ fn: 'sum', args: ['${field:items[*].price}'] }), '${field:shipping}', '${qty}'] });
    expect(derivedRefs(v)).toEqual({ vars: ['qty'], fields: ['items[*].price', 'shipping'], effects: [], now: false });
    expect(derivedFormula(v)).toBe('add(sum(items[*].price), shipping, qty)');
    expect(derivedFormula(d({ fn: 'date', offset: '+30d' }))).toBe('date(now +30d)');
    expect(derivedRefs(d({ fn: 'date' })).now).toBe(true);
  });
  it('builds the example of the preview from the references, with the literal values of the effect', () => {
    const v = d({ fn: 'add', args: [d({ fn: 'sum', args: ['${field:items[*].price}'] }), '${field:shipping}'] });
    const inputs = exampleInputs(v, { shipping: 4.9 });
    expect(inputs.map((i) => [i.key, i.sample])).toEqual([
      ['field:items[*].price', '10.10, 12.20, 8'],
      ['field:shipping', '4.9'],
    ]);
    const env = exampleEnv(inputs, {}, NOW);
    expect(env.object).toEqual({ items: [{ price: 10.1 }, { price: 12.2 }, { price: 8 }], shipping: 4.9 });
    expect(evalDerived(v, env)).toEqual({ ok: true, value: 35.2 });
    expect(evalDerived(v, exampleEnv(inputs, { 'field:shipping': '0' }, NOW))).toEqual({ ok: true, value: 30.3 });
  });
  it('switches function keeping the arguments that fit', () => {
    const sum = d({ fn: 'sum', args: ['${field:items[*].price}'] });
    expect(switchFn(sum, 'add')).toEqual(d({ fn: 'add', args: ['${field:items[*].price}', 1] }));
    expect(switchFn(sum, 'date')).toEqual(d({ fn: 'date', offset: '+30d', format: 'date' }));
    expect(switchFn(sum, 'round')).toEqual(d({ fn: 'round', args: ['${field:items[*].price}'], digits: 2 }));
    expect(switchFn(d({ fn: 'copy', args: ['x'] }), 'sum').$derive.args).toEqual(['${field:items[*].price}']);
    for (const fn of DERIVE_FNS) expect(checkDerived(switchFn(sum, fn)), fn).toBeNull();
    expect(withSpec(d({ fn: 'date', offset: '+1d' }), { offset: '' })).toEqual(d({ fn: 'date' }));
  });
  it('reads a derived value typed as JSON in a plain value field', () => {
    expect(typedValue('{"$derive":{"fn":"count","args":["${field:items}"]}}')).toEqual(d({ fn: 'count', args: ['${field:items}'] }));
    expect(typedValue('{"$derive":')).toBe('{"$derive":');
    expect(typedValue('12')).toBe(12);
    expect(typedValue('PAID')).toBe('PAID');
  });
});
