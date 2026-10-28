import { describe, expect, it } from 'vitest';
import { ApiError } from '../types';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted } from './testkit';

const ME = { user: { id: 'usr_1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['operator'] }, roles: ['operator'], csrf_token: 'csrf-1', csrf_header: 'X-CSRF-Token' };

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(on('GET', '/api/v1/auth/me', json(ME)), ...h);
  return { api: createRestApi({ fetch: s.fetch, sleep: noSleep, eventSource: null, pollMs: 5, docTtlMs: 0 }), ...s };
}

const PAGE = {
  id: 'pay',
  title: 'Pagamento simulato',
  ref: '{query.paymentId}',
  return_url: 'https://app.test/pay/return?ref={ref}&outcome={action}',
  buttons: [{ action: 'approve', label: 'Approva', values: { code: 'AUTHORISED' } }],
  callback: { method: 'POST', url: 'https://app.test/api/pay/notify', body: '{"ref":"{ref}"}', body_type: 'json', hmac: { header: 'X-Signature', key: '', prefix: 'sha256=' } },
};

describe('relative dates and third-party pages (REST)', () => {
  it('call the date-offset routes with the group', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/date-offsets', json({ offsets: [{ group: 'shop', field: 'renewsOn', min: '+300d', max: '+365d', updated_by: 'olga', updated_at: '2026-10-28T09:00:00Z' }] })),
      on('PUT', '/api/v1/date-offsets/renewsOn', json({ group: 'shop', field: 'renewsOn', min: '+30d', max: '+60d', updated_by: 'olga', updated_at: '2026-10-28T10:00:00Z' })),
      on('DELETE', '/api/v1/date-offsets/renewsOn', json(null, 204)),
    );
    expect(await api.dateOffsets.list('shop')).toEqual([{ group: 'shop', field: 'renewsOn', min: '+300d', max: '+365d', updatedBy: 'olga', updatedAt: '2026-10-28T09:00:00Z' }]);
    expect(await api.dateOffsets.set('shop', 'renewsOn', '+30d', '+60d')).toMatchObject({ min: '+30d', max: '+60d' });
    await api.dateOffsets.remove('shop', 'renewsOn');
    expect(calls.find((c) => c.method === 'GET' && c.path === '/api/v1/date-offsets')?.query.get('group')).toBe('shop');
    expect(JSON.parse(calls.find((c) => c.method === 'PUT')?.body ?? 'null')).toEqual({ group: 'shop', min: '+30d', max: '+60d' });
    expect(calls.find((c) => c.method === 'DELETE')?.query.get('group')).toBe('shop');
  });

  it('map a refused range to its server code', async () => {
    const { api } = make(on('PUT', '/api/v1/date-offsets/renewsOn', json({ code: 'invalid_offset', message: 'min is after max' }, 422)));
    const e = await api.dateOffsets.set('shop', 'renewsOn', '+2d', '+1d').catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({ status: 422, serverCode: 'invalid_offset' });
  });

  it('read and replace the pages of a group, sending the whole list', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/mocks/pages', json({ group: 'shop', pages: [PAGE], updated_by: 'olga', updated_at: '2026-10-28T09:00:00Z' })),
      on('PUT', '/api/v1/mocks/pages', (r) => json({ group: 'shop', ...JSON.parse(r.body ?? '{}') })),
    );
    const v = await api.mocks.pages('shop');
    expect(v).toMatchObject({ group: 'shop', updatedBy: 'olga', updatedAt: '2026-10-28T09:00:00Z' });
    expect(v.pages[0]).toEqual(PAGE);
    const saved = await api.mocks.setPages('shop', v.pages);
    expect(saved.pages).toHaveLength(1);
    expect(saved.updatedBy).toBeUndefined();
    expect(calls.find((c) => c.method === 'GET' && c.path === '/api/v1/mocks/pages')?.query.get('group')).toBe('shop');
    expect(JSON.parse(calls.find((c) => c.method === 'PUT')?.body ?? 'null')).toEqual({ group: 'shop', pages: [PAGE] });
  });

  it('keep the server message of refused pages', async () => {
    const { api } = make(
      on('GET', '/api/v1/mocks/pages', json({ group: 'shop', pages: null })),
      on('PUT', '/api/v1/mocks/pages', json({ code: 'invalid_pages', message: 'pages[0] (pay): one to six buttons' }, 422)),
    );
    expect((await api.mocks.pages('shop')).pages).toEqual([]);
    const e = await api.mocks.setPages('shop', [{ ...PAGE, buttons: [] }] as never).catch((x: unknown) => x);
    expect(e).toMatchObject({ serverCode: 'invalid_pages', message: 'pages[0] (pay): one to six buttons' });
  });
});
