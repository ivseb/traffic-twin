import { describe, expect, it } from 'vitest';
import { idDomains, fingerprint, ID_FORMAT_ERROR_CODES } from './api/idfmt';
import { exampleIdOf, idFormatErrorText } from './idfmt';
import { demoPreview, parseTemplate } from './api/mock/idfmt';
import { mapIdentity, mapIdPreview, mapIdFormat } from './api/rest/idfmt';
import { createMockApi } from './api/mock/adapter';

const id = (domain: string) => ({ type: 'string', 'x-tt-value': { kind: 'id', domain } });

describe('idDomains', () => {
  it('lists every id domain of a contract once, with its fields and parameters', () => {
    const doc = {
      openapi: '3.1.0',
      paths: {
        '/orders/{id}': {
          get: {
            parameters: [{ name: 'id', in: 'path', schema: id('order') }],
            responses: {
              200: {
                content: {
                  'application/json': {
                    schema: { $ref: '#/components/schemas/Order' },
                    example: { id: 'ORD-SYN-0042', note: { 'x-tt-value': { kind: 'id', domain: 'decoy' } } },
                  },
                },
              },
            },
          },
        },
        '/v1/shipments': {
          get: {
            responses: {
              200: { content: { 'application/json': { schema: { type: 'object', properties: { items: { type: 'array', items: { type: 'object', properties: { shipmentId: id('shipment'), orderId: id('order'), status: { type: 'string', enum: ['A'] } } } } } } } } },
            },
          },
        },
      },
      components: { schemas: { Order: { type: 'object', properties: { id: id('order'), storeId: id('store'), self: { $ref: '#/components/schemas/Order' } } } } },
    };
    expect(idDomains(doc)).toEqual([
      { domain: 'order', fields: ['id', 'orderId'] },
      { domain: 'shipment', fields: ['shipmentId'] },
      { domain: 'store', fields: ['storeId'] },
    ]);
  });
  it('is empty for a contract without ids or for garbage', () => {
    expect(idDomains({ paths: { '/x': { get: { responses: { 200: { content: { 'application/json': { schema: { type: 'string' } } } } } } } } })).toEqual([]);
    expect(idDomains(null)).toEqual([]);
    expect(idDomains('x')).toEqual([]);
  });
});

describe('id format helpers', () => {
  it('writes the default id of a domain as the inference does', () => {
    expect(exampleIdOf('order')).toBe('ORD-SYN-0042');
    expect(exampleIdOf('shipment')).toBe('SHP-SYN-0042');
    expect(exampleIdOf('id')).toBe('OBJ-SYN-0042');
    expect(exampleIdOf('ab')).toBe('ABX-SYN-0042');
  });
  it('translates error codes, falling back to the code', () => {
    const tk = (k: string, _p?: unknown, fb?: string) => (k === 'idf.err.bad_char' ? 'Carattere non ammesso' : (fb ?? k));
    expect(idFormatErrorText('bad_char', tk)).toBe('Carattere non ammesso');
    expect(idFormatErrorText('mystery', tk)).toBe('mystery');
  });
  it('shortens hashes to a fingerprint', () => {
    expect(fingerprint('0123456789abcdef0123456789abcdef')).toBe('01234567…');
    expect(fingerprint('abc')).toBe('abc');
  });
});

describe('demo template reader', () => {
  it('gives the server error codes', () => {
    const cases: Record<string, string> = { '': 'empty', NNNN$: 'bad_char', "'AB": 'unclosed_quote', "''NNNN": 'empty_literal', '{x NNNN': 'unclosed_ref', '{1}NNNN': 'bad_ref', '<NNNN': 'unclosed_b64', '<>NNNN': 'empty_b64', '<N<N>>NNNN': 'nested_b64', NN: 'too_small' };
    for (const [f, code] of Object.entries(cases)) {
      const r = parseTemplate(f);
      expect('code' in r && r.code, f).toBe(code);
    }
    for (const c of Object.values(cases)) expect(ID_FORMAT_ERROR_CODES).toContain(c);
  });
  it('previews ids of the right shape', () => {
    const p = demoPreview('NN-NNNNNN-NNNN-NNNNNN', 'order');
    expect(p.valid).toBe(true);
    if (p.valid) {
      expect(p.preview).toHaveLength(3);
      for (const x of p.preview) expect(x).toMatch(/^[0-9]{2}-[0-9]{6}-[0-9]{4}-[0-9]{6}$/);
      expect(p.capacityLabel).toBe('more than 10^18');
    }
    const q = demoPreview("'ABC'.{customerNo|pad6}NNN");
    expect(q.valid && q.preview[0]).toMatch(/^ABC\.[0-9]{9}$/);
    const b = demoPreview("<'Contract':NNNNNN>");
    expect(b.valid && atob((b.preview[0] as string).replaceAll('-', '+').replaceAll('_', '/'))).toMatch(/^Contract:[0-9]{6}$/);
  });
});

describe('wire mapping', () => {
  it('maps formats, previews and identity settings', () => {
    expect(mapIdFormat({ group: 'demo', domain: 'order', format: 'NNNN', capacity_label: '10000', preview: ['1234'], updated_by: 'elena', updated_at: 't' })).toEqual({ group: 'demo', domain: 'order', format: 'NNNN', capacityLabel: '10000', preview: ['1234'], updatedBy: 'elena', updatedAt: 't' });
    expect(mapIdPreview({ valid: false, error: { code: 'too_small', at: 0 } })).toEqual({ valid: false, error: { code: 'too_small', at: 0 } });
    expect(mapIdPreview({ valid: true, preview: ['a'], capacity_label: '1000' })).toEqual({ valid: true, preview: ['a'], capacityLabel: '1000' });
    expect(mapIdentity({ group: 'demo', enabled: false })).toEqual({ group: 'demo', enabled: false, header: '', claim: '', map: [], updatedBy: undefined, updatedAt: undefined });
  });
});

describe('demo adapter', () => {
  it('stores formats per group and refuses invalid ones with the code and position', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.auth.login({ username: 'olga.operator', password: 'demo' });
    const saved = await api.idFormats.set('demo', 'shipment', 'NN-NNNNNN');
    expect(saved.preview).toHaveLength(3);
    expect((await api.idFormats.list('demo')).map((f) => f.domain).sort()).toContain('shipment');
    await expect(api.idFormats.set('demo', 'shipment', 'NN?')).rejects.toMatchObject({ serverCode: 'invalid_format', details: [{ code: 'bad_char', at: 2 }] });
    await api.idFormats.remove('demo', 'shipment');
    expect((await api.idFormats.list('demo')).map((f) => f.domain)).not.toContain('shipment');
  });
  it('keeps only hashes of the mapped test users', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.auth.login({ username: 'olga.operator', password: 'demo' });
    let v = await api.mocks.setIdentity('team', 'x-user-id', '');
    expect(v).toMatchObject({ enabled: true, header: 'x-user-id' });
    v = await api.mocks.addIdentityUser('team', 'mario.tester', 'CUS-SYN-0009');
    expect(v.map).toHaveLength(1);
    expect(JSON.stringify(v)).not.toContain('mario.tester');
    await expect(api.mocks.addIdentityUser('team', 'x', 'nope')).rejects.toMatchObject({ serverCode: 'invalid_customer' });
    v = await api.mocks.removeIdentityUser('team', v.map[0].hash);
    expect(v.map).toEqual([]);
    expect((await api.mocks.setIdentity('team', '', '')).enabled).toBe(false);
  });
  it('marks the tokenized ids of the demo contracts with their domain, so the id format card has rows', async () => {
    const api = createMockApi({ latencyMs: 0, storage: null });
    await api.auth.login({ username: 'olga.operator', password: 'demo' });
    const domains = idDomains(await api.contracts.openapi('shipping-ext')).map((d) => d.domain);
    expect(domains).toEqual(expect.arrayContaining(['order', 'shipment']));
  });
});
