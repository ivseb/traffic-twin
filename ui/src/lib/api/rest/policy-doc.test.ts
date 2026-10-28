import { describe, expect, it } from 'vitest';
import type { PolicyChoice } from '../types';
import { actionSpec, parseAction } from './map';
import { applyChoices, currentChoice, locate, parsePolicy } from './policy-doc';

const POLICY = `# policy of the shop
format: tt.policy/v1
policy_id: p-shop
default: drop
hmac: { kid: k1, epoch: "2026-10" }
sampling: { rate: 0.05 }
services:
  shop-api:
    match: { inbound: true }
    ops:
      "POST /orders":
        request:
          body:
            $.sku: keep
        response:
          $.status: keep            # enum
          $.total: bucket(num, [0, 50, 100])
  shipping-ext:
    match: { base: "https://api.carrier.example" }
`;

const sug = (service: string, op: string, part: 'request' | 'response', path: string) => ({ service, op, part, path, id: `${service}|${op}|${part}|${path}` });
const run = (items: ReturnType<typeof sug>[], choices: Record<string, PolicyChoice>, text = POLICY) => applyChoices(text, items, choices, (s) => s.id);

describe('actions', () => {
  it.each([
    ['drop', { action: 'drop' }],
    ['keep', { action: 'keep' }],
    // a code rule read and written back stays a code rule (it never becomes drop)
    ['code', { action: 'code' }],
    // spec v1.19: the code shape with digits survives a round trip
    ['code(alnum)', { action: 'code', arg: 'alnum' }],
    ['hmac', { action: 'hmac', arg: 'id' }],
    ['hmac(order)', { action: 'hmac', arg: 'order' }],
    ['bucket(num, [0, 10, 100])', { action: 'bucket', arg: '0, 10, 100' }],
    ['bucket(time, day)', { action: 'bucket', arg: 'time:day' }],
  ] as [string, PolicyChoice][])('parses %s and writes it back', (spec, choice) => {
    expect(parseAction(spec)).toEqual(choice);
    expect(actionSpec(choice)).toBe(spec);
  });
  it('treats an unknown action as closed', () => {
    expect(parseAction('banana').action).toBe('drop');
    expect(parseAction(undefined).action).toBe('drop');
  });
});

describe('locations', () => {
  it('knows body paths, query, headers, cookies, and path words that cannot be edited', () => {
    expect(locate('$.items[*].id')).toEqual({ kind: 'body', key: '$.items[*].id' });
    expect(locate('query.orderId')).toEqual({ kind: 'query', key: 'orderId' });
    expect(locate('headers.x-tenant')).toEqual({ kind: 'headers', key: 'x-tenant' });
    expect(locate('cookies.sid')).toEqual({ kind: 'cookies', key: 'sid' });
    expect(locate('path.1')).toEqual({ kind: 'segment' });
  });
  it('reads what the policy does today, from the shortcut or the body map', () => {
    const doc = parsePolicy(POLICY);
    expect(currentChoice(doc, sug('shop-api', 'POST /orders', 'response', '$.status'))).toEqual({ action: 'keep' });
    expect(currentChoice(doc, sug('shop-api', 'POST /orders', 'response', '$.total'))).toEqual({ action: 'bucket', arg: '0, 50, 100' });
    expect(currentChoice(doc, sug('shop-api', 'POST /orders', 'request', '$.sku'))).toEqual({ action: 'keep' });
    expect(currentChoice(doc, sug('shop-api', 'POST /orders', 'request', '$.other'))).toEqual({ action: 'drop' });
    expect(currentChoice(doc, sug('nope', 'GET /x', 'request', '$.a'))).toEqual({ action: 'drop' });
  });
});

describe('applying choices', () => {
  it('adds a rule next to the others and keeps comments and layout', () => {
    const a = sug('shop-api', 'POST /orders', 'response', '$.id');
    const r = run([a], { [a.id]: { action: 'hmac', arg: 'order' } });
    expect(r.skipped).toEqual([]);
    expect(r.yaml).toContain('# policy of the shop');
    expect(r.yaml).toContain('# enum');
    expect(r.yaml).toMatch(/\$\.id: hmac\(order\)/);
    expect(parsePolicy(r.yaml).getIn(['services', 'shop-api', 'ops', 'POST /orders', 'response', '$.id'])).toBe('hmac(order)');
  });
  it('changes a rule where it is written (the body map, not a duplicate shortcut)', () => {
    const a = sug('shop-api', 'POST /orders', 'request', '$.sku');
    const r = run([a], { [a.id]: { action: 'hmac', arg: 'sku' } });
    const doc = parsePolicy(r.yaml);
    expect(doc.getIn(['services', 'shop-api', 'ops', 'POST /orders', 'request', 'body', '$.sku'])).toBe('hmac(sku)');
    expect(doc.hasIn(['services', 'shop-api', 'ops', 'POST /orders', 'request', '$.sku'])).toBe(false);
  });
  it('drops a rule and removes the empty containers it leaves behind', () => {
    const a = sug('shop-api', 'POST /orders', 'request', '$.sku');
    const r = run([a], { [a.id]: { action: 'drop' } });
    const doc = parsePolicy(r.yaml);
    expect(doc.hasIn(['services', 'shop-api', 'ops', 'POST /orders', 'request'])).toBe(false);
    expect(doc.hasIn(['services', 'shop-api', 'ops', 'POST /orders', 'response', '$.status'])).toBe(true);
    expect(() => parsePolicy(r.yaml)).not.toThrow();
  });
  it('writes query, header and cookie rules into their maps', () => {
    const items = [sug('shop-api', 'GET /orders', 'request', 'query.orderId'), sug('shop-api', 'GET /orders', 'request', 'headers.x-tenant')];
    const r = run(items, { [items[0].id]: { action: 'hmac', arg: 'order' }, [items[1].id]: { action: 'keep' } });
    const doc = parsePolicy(r.yaml);
    expect(doc.getIn(['services', 'shop-api', 'ops', 'GET /orders', 'request', 'query', 'orderId'])).toBe('hmac(order)');
    expect(doc.getIn(['services', 'shop-api', 'ops', 'GET /orders', 'request', 'headers', 'x-tenant'])).toBe('keep');
  });
  it('does not touch what did not change', () => {
    const a = sug('shop-api', 'POST /orders', 'response', '$.status');
    expect(run([a], { [a.id]: { action: 'keep' } }).yaml).toBe(POLICY);
  });
  it('skips path words and services that are not in the policy, and says so', () => {
    const items = [sug('shop-api', 'GET /orders/x', 'request', 'path.1'), sug('billing', 'GET /x', 'response', '$.a')];
    const r = run(items, { [items[0].id]: { action: 'hmac' }, [items[1].id]: { action: 'keep' } });
    expect(r.yaml).toBe(POLICY);
    expect(r.skipped).toEqual(['shop-api · GET /orders/x · request · path.1', 'billing · GET /x · response · $.a']);
  });
  it('can open a field of an external service that is already in the policy', () => {
    const a = sug('shipping-ext', 'GET /v1/shipments', 'response', '$.items[*].status');
    const r = run([a], { [a.id]: { action: 'keep' } });
    expect(parsePolicy(r.yaml).getIn(['services', 'shipping-ext', 'ops', 'GET /v1/shipments', 'response', '$.items[*].status'])).toBe('keep');
  });
  it('refuses a text that is not YAML', () => {
    expect(() => run([], {}, 'a: [unclosed')).toThrow();
  });
});
