import { describe, expect, it, vi } from 'vitest';
import { createOpKindsRest, mapOpKinds } from './opkinds';
import { opKindState, readByMethod } from '../opkinds';
import type { Http } from './http';

describe('operation kinds (rules v1.6)', () => {
  const wire = {
    decisions: [{ group: 'demo', service: 'app-api', op: 'POST /orders/{id}/cancel', read: true, set_by: 'usr_rev', set_at: '2026-10-28T10:00:00Z' }],
    auto: [{ group: 'demo', service: 'app-api', op: 'POST /orders/lookup', read: true, auto: true }],
  };
  it('maps the wire form and tells the state of an operation', () => {
    const k = mapOpKinds(wire);
    expect(k.decisions[0]).toEqual({ group: 'demo', service: 'app-api', op: 'POST /orders/{id}/cancel', read: true, setBy: 'usr_rev', setAt: '2026-10-28T10:00:00Z' });
    expect(opKindState(k, 'demo', 'app-api', 'POST /orders/{id}/cancel')).toMatchObject({ choice: 'read', autoRead: false });
    expect(opKindState(k, 'demo', 'app-api', 'POST /orders/lookup')).toMatchObject({ choice: 'auto', autoRead: true });
    expect(opKindState(k, 'other', 'app-api', 'POST /orders/lookup')).toMatchObject({ choice: 'auto', autoRead: false });
    expect(mapOpKinds(null)).toEqual({ decisions: [], auto: [] });
  });
  it('reads by method when nobody decided', () => {
    expect(readByMethod('GET')).toBe(true);
    expect(readByMethod('POST')).toBe(false);
    expect(readByMethod('POST', 'query')).toBe(true);
    expect(readByMethod('POST', 'mutation')).toBe(false);
  });
  it('sends read true, false or null', async () => {
    const put = vi.fn().mockResolvedValue({});
    const api = createOpKindsRest({ put } as unknown as Http);
    await api.set('demo', 'app-api', 'POST /x', 'read');
    await api.set('', 'app-api', 'POST /x', 'write');
    await api.set('demo', 'app-api', 'POST /x', 'auto');
    expect(put.mock.calls.map((c) => c[1])).toEqual([
      { group: 'demo', service: 'app-api', op: 'POST /x', read: true },
      { service: 'app-api', op: 'POST /x', read: false },
      { group: 'demo', service: 'app-api', op: 'POST /x', read: null },
    ]);
    expect(put.mock.calls[0][0]).toBe('/api/v1/rules/op-kinds');
  });
});
