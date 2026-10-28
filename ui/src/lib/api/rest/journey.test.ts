// Journey round: the Postman download, the world explorer calls and the archetype build of the REST adapter.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted } from './testkit';

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-25T10:00:00Z'), docTtlMs: 0 });
  return { api, ...s };
}

describe('contracts.postman', () => {
  it('downloads the collection of the service, for the group of the row', async () => {
    const body = JSON.stringify({ info: { name: 'shipping-ext' }, item: [] });
    const { api, calls } = make(on('GET', '/api/v1/contracts/shipping-ext/postman', () => new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } })));
    const { filename, blob } = await api.contracts.postman('shipping-ext', 'shop');
    expect(filename).toBe('shipping-ext.postman_collection.json');
    expect(await blob.text()).toBe(body);
    expect(calls[0].query.get('group')).toBe('shop');
  });
  it('encodes the service name', async () => {
    const { api, calls } = make(on('GET', /postman$/, () => new Response('{}')));
    await api.contracts.postman('host:{*}.tracking.example');
    expect(calls[0].path).toBe('/api/v1/contracts/host%3A%7B*%7D.tracking.example/postman');
  });
});

describe('worlds explorer', () => {
  it('pages the customers with search, offset and limit', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/worlds/w-20261025-0001/customers', json({ world_id: 'w-20261025-0001', total: 2, all: 30, offset: 20, limit: 20, customers: [{ id: 'CUS-SYN-0021', name: 'Giulia Rossi', email: 'giulia@example.com', archetype: 'arch-01', entities: { order: 2 } }, { id: 'CUS-SYN-0022' }] })),
    );
    const page = await api.worlds.customers('w-20261025-0001', { q: 'rossi', offset: 20, limit: 20 });
    expect(calls[0].query.get('q')).toBe('rossi');
    expect(calls[0].query.get('offset')).toBe('20');
    expect(calls[0].query.get('limit')).toBe('20');
    expect(page).toMatchObject({ total: 2, all: 30, offset: 20, limit: 20 });
    expect(page.customers[0]).toEqual({ id: 'CUS-SYN-0021', name: 'Giulia Rossi', email: 'giulia@example.com', archetype: 'arch-01', entities: { order: 2 } });
    // missing optional fields become empty values, never undefined
    expect(page.customers[1]).toEqual({ id: 'CUS-SYN-0022', name: '', email: '', archetype: '', entities: {} });
  });
  it('sends no empty parameters', async () => {
    const { api, calls } = make(on('GET', /customers$/, json({ world_id: 'w', total: 0, all: 0, offset: 0, limit: 50, customers: [] })));
    await api.worlds.customers('w-20261025-0001');
    expect([...calls[0].query.keys()]).toEqual([]);
  });
  it('turns the lines of one customer into entities with their timelines', async () => {
    const lines = [
      { type: 'customer', id: 'CUS-SYN-0001', archetype: 'arch-02', profile: { name: 'Marco Verdi', email: 'marco@example.com' } },
      { type: 'entity', entity: 'order', id: 'ORD-SYN-0001', customer_id: 'CUS-SYN-0001', state: { status: 'PAID' } },
      { type: 'entity', entity: 'shipment', id: 'SHP-SYN-0001', customer_id: 'CUS-SYN-0001', state: { status: 'DELIVERED', orderId: 'ORD-SYN-0001' } },
      { type: 'history', entity: 'shipment', id: 'SHP-SYN-0001', seq: 2, at: '2026-10-20T10:00:00Z', state: { status: 'DELIVERED' }, rule_id: 'r-0007', outcome: 'happy' },
      { type: 'history', entity: 'shipment', id: 'SHP-SYN-0001', seq: 1, at: '2026-10-19T10:00:00Z', state: { status: 'CREATED' }, rule_id: 'r-0007' },
      { type: 'history', entity: 'order', id: 'ORD-SYN-0001', seq: 1, at: '2026-10-19T08:00:00Z', state: { status: 'PAID' } },
    ];
    const { api, calls } = make(on('GET', '/api/v1/worlds/w-20261025-0001/customers/CUS-SYN-0001', json({ world_id: 'w-20261025-0001', customer: 'CUS-SYN-0001', lines })));
    const c = await api.worlds.customer('w-20261025-0001', 'CUS-SYN-0001');
    expect(calls).toHaveLength(1);
    expect(c).toMatchObject({ id: 'CUS-SYN-0001', name: 'Marco Verdi', email: 'marco@example.com', archetype: 'arch-02' });
    // the order first, then what a rule created from it
    expect(c.entities.map((e) => e.id)).toEqual(['ORD-SYN-0001', 'SHP-SYN-0001']);
    // steps are in time order whatever the order of the lines
    expect(c.entities[1].steps.map((s) => s.status)).toEqual(['CREATED', 'DELIVERED']);
    expect(c.entities[1].steps[1]).toMatchObject({ rule: 'r-0007', outcome: 'happy', seq: 2 });
    expect(c.entities[0].steps[0].rule).toBeUndefined();
  });
});

describe('archetypes.build', () => {
  const ARCH = { k_min: 20, built: true, profiles: 100, dropped_subjects: 0, archetypes: [{ id: 'arch-01', label: 'x', size: 60, features: { orders_per_month: '1-2', active_hours: '8-12' } }] };
  it('builds with the configured k and the group, then returns the new set', async () => {
    let built = false;
    const { api, calls } = make(
      on('POST', '/api/v1/archetypes/build', () => {
        built = true;
        return json({ job_id: 'job_1', kind: 'archetypes.build', status: 'done', result: {} }, 202);
      }),
      on('GET', '/api/v1/archetypes', () => json(built ? ARCH : { ...ARCH, built: false, archetypes: [] })),
    );
    const before = await api.archetypes.get('shop');
    expect(before.built).toBe(false);
    const after = await api.archetypes.build('shop');
    const post = calls.find((c) => c.method === 'POST');
    expect(JSON.parse(post?.body ?? '{}')).toEqual({ k_min: 20, group: 'shop' });
    expect(after.built).toBe(true);
    expect(after.archetypes).toHaveLength(1);
  });
  it('reports a failed build', async () => {
    const { api } = make(
      on('GET', '/api/v1/archetypes', json({ ...ARCH, built: false, archetypes: [] })),
      on('POST', '/api/v1/archetypes/build', json({ job_id: 'job_2', kind: 'archetypes.build', status: 'failed', error: 'no events' }, 202)),
    );
    await expect(api.archetypes.build()).rejects.toThrow(/no events/);
  });
});
