// The demo Mock page: the same flow a user follows, with the permissions of the roles.
import { describe, expect, it } from 'vitest';
import { createMockApi } from './adapter';

async function as(role: 'operator' | 'admin' | 'publisher' | 'auditor') {
  const api = createMockApi({ latencyMs: 0, storage: null });
  await api.demo!.loginAs(role);
  return api;
}

describe('demo Mock page', () => {
  it('an operator prepares but a publisher releases', async () => {
    const api = await as('operator');
    const seen: string[] = [];
    const r = await api.mocks.prepare({ group: 'shop-api' }, (p) => seen.push(p.steps.map((s) => s.status[0]).join('')));
    expect(r.waiting).toBe('needs_publisher');
    expect(r.steps.map((s) => s.status)).toEqual(['done', 'done', 'done', 'waiting', 'skipped']);
    expect(seen.length).toBeGreaterThan(5);
    expect((await api.mocks.overview()).mocks).toEqual([]);
  });

  it('an admin needs a reason, then gets a managed mock with the URLs that replace the real ones', async () => {
    const api = await as('admin');
    expect((await api.mocks.prepare({ group: 'shop-api' })).error).toBe('admin_reason_required');
    const r = await api.mocks.prepare({ group: 'shop-api', reason: 'demo' });
    expect(r.status).toBe('done');
    expect(r.steps.at(-1)).toMatchObject({ id: 'mock', status: 'done', code: 'managed' });
    const o = await api.mocks.overview(['shop-api']);
    expect(o.environment.kubernetes).toBe(true);
    const m = o.mocks[0];
    expect(m).toMatchObject({ group: 'shop-api', managed: true, online: true, packId: r.packId, upToDate: true });
    expect(m.services.find((s) => s.name === 'shipping-ext')).toMatchObject({ realBase: 'https://api.carrier.example', mockUrl: `${m.publicUrl}/__svc/carrier` });
    const c = await api.mocks.calls(m.id);
    expect(c.calls.length).toBeGreaterThan(0);
    expect(c.calls.every((x) => !('body' in x) && !x.path.includes('?'))).toBe(true);

    // Sessions, scenarios, clock.
    expect((await api.mocks.command(m.id, 'POST', '/__tt/sessions', { id: 't1' })).status).toBe(201);
    expect((await api.mocks.command(m.id, 'POST', '/__tt/sessions/t1/scenario', { preset: 'sc-carrier-down' })).status).toBe(200);
    const adv = await api.mocks.command(m.id, 'POST', '/__tt/sessions/t1/clock/advance', { by: '2d' });
    expect(adv.status).toBe(200);
    expect((await api.mocks.command(m.id, 'POST', '/__tt/sessions/t1/clock/advance', { by: 'tomorrow' })).status).toBe(400);
    const after = (await api.mocks.overview()).mocks[0].sessions.find((s) => s.id === 't1')!;
    expect(after.scenario).toBe('sc-carrier-down');

    await api.mocks.stopManaged('shop-api');
    expect((await api.mocks.overview()).mocks).toEqual([]);
  });

  it('a self-installed mock gets a token shown once, revocable', async () => {
    const api = await as('operator');
    const t = await api.mocks.createToken('shop-api', 'CI');
    expect(t.token).toMatch(/^ttm_[0-9a-f]{24}\.[A-Za-z0-9_-]{43}$/);
    expect(t.setup.docker).toContain(t.token);
    expect(t.setup.helmValues).toContain('group: shop-api');
    const list = await api.mocks.tokens();
    expect(list[0]).not.toHaveProperty('token');
    await api.mocks.revokeToken(t.id);
    expect((await api.mocks.tokens())[0].revoked).toBe(true);
  });

  it('an auditor reads but changes nothing', async () => {
    const api = await as('auditor');
    await expect(api.mocks.createToken('shop-api')).rejects.toMatchObject({ code: 'forbidden' });
    await expect(api.mocks.prepare({ group: 'shop-api' })).rejects.toMatchObject({ code: 'forbidden' });
    expect((await api.mocks.overview()).mocks).toEqual([]);
  });
});
