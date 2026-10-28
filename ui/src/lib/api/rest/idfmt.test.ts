import { describe, expect, it } from 'vitest';
import { ApiError } from '../types';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted } from './testkit';

const ME = { user: { id: 'usr_1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['operator'] }, roles: ['operator'], csrf_token: 'csrf-1', csrf_header: 'X-CSRF-Token' };

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(on('GET', '/api/v1/auth/me', json(ME)), ...h);
  return { api: createRestApi({ fetch: s.fetch, sleep: noSleep, eventSource: null, pollMs: 5, docTtlMs: 0 }), ...s };
}

describe('id formats and identity sessions (admin-api 1.18.0)', () => {
  it('call the id-format routes with the group', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/id-formats', json({ formats: [{ group: 'demo', domain: 'order', format: 'NNNN', capacity_label: '10000', preview: ['1234'] }] })),
      on('PUT', '/api/v1/id-formats/order', json({ group: 'demo', domain: 'order', format: 'NN-NNNN', capacity_label: '1000000' })),
      on('POST', '/api/v1/id-formats/preview', json({ valid: false, error: { code: 'bad_char', at: 3 } })),
      on('DELETE', '/api/v1/id-formats/order', json(null, 204)),
    );
    expect((await api.idFormats.list('demo'))[0]).toMatchObject({ domain: 'order', capacityLabel: '10000', preview: ['1234'] });
    expect(await api.idFormats.set('demo', 'order', 'NN-NNNN')).toMatchObject({ format: 'NN-NNNN' });
    expect(await api.idFormats.preview('NNN?', 'order')).toEqual({ valid: false, error: { code: 'bad_char', at: 3 } });
    await api.idFormats.remove('demo', 'order');
    const list = calls.find((c) => c.method === 'GET' && c.path === '/api/v1/id-formats');
    expect(list?.query.get('group')).toBe('demo');
    const del = calls.find((c) => c.method === 'DELETE');
    expect(del?.query.get('group')).toBe('demo');
    const put = calls.find((c) => c.method === 'PUT');
    expect(JSON.parse(put?.body ?? 'null')).toEqual({ group: 'demo', format: 'NN-NNNN' });
    const pv = calls.find((c) => c.path === '/api/v1/id-formats/preview');
    expect(JSON.parse(pv?.body ?? 'null')).toEqual({ format: 'NNN?', domain: 'order' });
  });

  it('maps a refused format to its code and position', async () => {
    const { api } = make(on('PUT', '/api/v1/id-formats/order', json({ code: 'invalid_format', message: 'id format: character not allowed (at 2)', details: [{ code: 'bad_char', at: 2 }] }, 422)));
    const e = await api.idFormats.set('demo', 'order', 'NN?').catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({ serverCode: 'invalid_format', details: [{ code: 'bad_char', at: 2 }] });
  });

  it('call the mock identity routes', async () => {
    const hash = 'ab'.repeat(16);
    const { api, calls } = make(
      on('GET', '/api/v1/mocks/identity', json({ group: 'demo', enabled: true, header: 'x-user-id', claim: '', map: [] })),
      on('PUT', '/api/v1/mocks/identity', json({ group: 'demo', enabled: true, header: 'x-user-id', claim: 'sub', map: [] })),
      on('POST', '/api/v1/mocks/identity/map', json({ group: 'demo', enabled: true, header: 'x-user-id', map: [{ hash, customer: 'CUS-SYN-0007' }] })),
      on('DELETE', `/api/v1/mocks/identity/map/${hash}`, json({ group: 'demo', enabled: true, header: 'x-user-id', map: [] })),
    );
    expect(await api.mocks.identity('demo')).toMatchObject({ enabled: true, header: 'x-user-id', claim: '', map: [] });
    expect(await api.mocks.setIdentity('demo', 'x-user-id', 'sub')).toMatchObject({ claim: 'sub' });
    expect((await api.mocks.addIdentityUser('demo', 'mario', 'CUS-SYN-0007')).map).toEqual([{ hash, customer: 'CUS-SYN-0007' }]);
    expect((await api.mocks.removeIdentityUser('demo', hash)).map).toEqual([]);
    expect(calls.find((c) => c.method === 'GET' && c.path === '/api/v1/mocks/identity')?.query.get('group')).toBe('demo');
    expect(JSON.parse(calls.find((c) => c.method === 'PUT')?.body ?? 'null')).toEqual({ group: 'demo', header: 'x-user-id', claim: 'sub' });
    expect(JSON.parse(calls.find((c) => c.method === 'POST' && c.path.endsWith('/map'))?.body ?? 'null')).toEqual({ group: 'demo', user: 'mario', customer: 'CUS-SYN-0007' });
    expect(calls.find((c) => c.method === 'DELETE')?.query.get('group')).toBe('demo');
  });
});
