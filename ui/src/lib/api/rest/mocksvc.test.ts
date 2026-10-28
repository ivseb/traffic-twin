// The Mock page API over REST (admin-api 1.12.0): mapping, the prepare job followed step by step, control
// commands answered by the mock, tokens shown once.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { err, json, noSleep, on, scripted } from './testkit';
import { clockStep, replacementOf } from '../mocksvc';

const ME = {
  user: { id: 'usr_1', username: 'olga', display_name: 'Olga', auth_method: 'local', roles: ['operator'] },
  roles: ['operator'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-25T12:00:00Z',
  idle_expires_at: '2026-10-25T10:00:00Z',
  session_idle_timeout_ms: 1800000,
};
const loggedIn = on('GET', '/api/v1/auth/me', json(ME));

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(loggedIn, ...h);
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5 });
  return { api, ...s };
}

const LIST = {
  mocks: [
    {
      mock_id: 'mtk-0123456789abcdef01234567.ci-1', group: 'shop', instance: 'ci-1', token_id: 'mtk-0123456789abcdef01234567', managed: false, online: true,
      status: 'serving', version: '0.1.0', pack_id: 'pk-20261025-0002', latest_pack_id: 'pk-20261025-0002', up_to_date: true, public_url: 'http://mock.ci:8480',
      services: [{ name: 'shipping-ext', alias: 'carrier', mock_url: 'http://mock.ci:8480/__svc/carrier', real_base: 'https://api.carrier.example' }, { name: 'shop-api', mock_url: 'http://mock.ci:8480/__svc/shop-api' }],
      sessions: [{ id: 'default', clock: '2026-10-19T00:00:00Z', calls: 3, faults: 'observed' }], calls_total: 3, last_seen: '2026-10-25T09:00:00Z',
    },
  ],
  managed: [{ group: 'shop', name: 'tt-mock-shop', namespace: 'mocks', token_id: 'mtk-x', url: 'https://tt-mock-shop.apps.example', created_by: 'olga', updated_at: '2026-10-25T08:00:00Z', pods: { found: true, ready_replicas: 1, replicas: 1 } }],
  environment: { kubernetes: true, namespace: 'mocks', console_url: 'https://tt.example', image: 'ghcr.io/ivseb/traffic-twin:0.1.0', report_interval_s: 3 },
  latest_packs: { shop: 'pk-20261025-0002' },
};

describe('mock page over REST', () => {
  it('maps the overview with the group filter', async () => {
    const { api, calls } = make(on('GET', '/api/v1/mocks', json(LIST)));
    const o = await api.mocks.overview(['shop']);
    expect(calls.find((c) => c.path === '/api/v1/mocks')?.query.get('group')).toBe('shop');
    expect(o.environment).toEqual({ kubernetes: true, namespace: 'mocks', consoleUrl: 'https://tt.example', image: 'ghcr.io/ivseb/traffic-twin:0.1.0', reportIntervalS: 3 });
    const m = o.mocks[0];
    expect(m.upToDate).toBe(true);
    expect(m.services[0]).toEqual({ name: 'shipping-ext', alias: 'carrier', mockUrl: 'http://mock.ci:8480/__svc/carrier', realBase: 'https://api.carrier.example' });
    expect(replacementOf(m.services[0])).toEqual({ from: 'https://api.carrier.example', to: 'http://mock.ci:8480/__svc/carrier' });
    expect(replacementOf(m.services[1])).toBeNull();
    expect(o.managed[0]).toMatchObject({ name: 'tt-mock-shop', ready: 1, replicas: 1, found: true });
  });

  it('follows the prepare job and reports every step', async () => {
    let polls = 0;
    const steps = (publish: string) => [
      { id: 'archetypes', status: 'done', detail: { archetypes: '4', profiles: '600' } },
      { id: 'world', status: 'done' },
      { id: 'pack', status: 'done' },
      { id: 'publish', status: publish },
      { id: 'mock', status: 'pending' },
    ];
    const { api, calls } = make(
      on('POST', '/api/v1/mocks/prepare', json({ job_id: 'job_1', kind: 'mock.prepare', status: 'running', progress: { steps: steps('running') } }, 202)),
      on('GET', '/api/v1/jobs/job_1', () => {
        polls++;
        return polls < 2
          ? json({ job_id: 'job_1', status: 'running', progress: { steps: steps('running') } })
          : json({ job_id: 'job_1', status: 'done', result: { result: { pack_id: 'pk-3', url: 'https://tt-mock-shop.apps.example' }, steps: [...steps('done').slice(0, 4), { id: 'mock', status: 'done', code: 'managed' }] } });
      }),
    );
    const seen: string[] = [];
    const r = await api.mocks.prepare({ group: 'shop', reason: 'test release' }, (p) => seen.push(`${p.status}:${p.steps.find((s) => s.id === 'publish')?.status}`));
    expect(JSON.parse(calls.find((c) => c.path === '/api/v1/mocks/prepare')!.body!)).toEqual({ group: 'shop', reason: 'test release' });
    expect(r).toMatchObject({ status: 'done', packId: 'pk-3', url: 'https://tt-mock-shop.apps.example' });
    expect(r.steps.at(-1)).toEqual({ id: 'mock', status: 'done', code: 'managed' });
    expect(seen).toEqual(['running:running', 'running:running', 'done:done']);
  });

  it('runs a command on the mock and waits for its answer', async () => {
    let n = 0;
    const { api, calls } = make(
      on('POST', '/api/v1/mocks/mtk-0123456789abcdef01234567.ci-1/commands', json({ command_id: 'cmd_1', status: 'pending' }, 202)),
      on('GET', '/api/v1/mocks/mtk-0123456789abcdef01234567.ci-1/commands/cmd_1', () =>
        ++n < 3 ? json({ command_id: 'cmd_1', status: 'pending', method: 'POST', path: '/__tt/sessions/default/clock/advance' }) : json({ command_id: 'cmd_1', status: 'done', result: { status: 200, body: { now: '2026-10-20T00:00:00Z' } } }),
      ),
    );
    const r = await api.mocks.command('mtk-0123456789abcdef01234567.ci-1', 'POST', '/__tt/sessions/default/clock/advance', { by: '1d' });
    expect(r).toEqual({ status: 200, body: { now: '2026-10-20T00:00:00Z' } });
    const post = calls.find((c) => c.method === 'POST' && c.path.endsWith('/commands'))!;
    expect(JSON.parse(post.body!)).toEqual({ method: 'POST', path: '/__tt/sessions/default/clock/advance', body: { by: '1d' } });
    expect(post.headers['x-csrf-token']).toBe('csrf-1');
  });

  it('shows a new token once with its setup, and maps errors', async () => {
    const { api } = make(
      on('POST', '/api/v1/mocks/tokens', json({
        token_id: 'mtk-0123456789abcdef01234567', group: 'shop', label: 'CI', managed: false, created_by: 'olga', created_at: '2026-10-25T09:00:00Z',
        expires_at: '2027-04-23T09:00:00Z', revoked: false, last_used: null, token: 'ttm_0123456789abcdef01234567.secret',
        setup: { console_url: 'https://tt.example', group: 'shop', image: 'img:1', gate_pubkeys: 'g:1', env: 'E', docker: 'docker run …', helm_values: 'console:', helm: 'helm install', openshift: 'oc project' },
      }, 201)),
      on('POST', '/api/v1/mocks/managed', err(409, 'kubernetes_disabled')),
    );
    const t = await api.mocks.createToken('shop', 'CI');
    expect(t).toMatchObject({ id: 'mtk-0123456789abcdef01234567', token: 'ttm_0123456789abcdef01234567.secret', lastUsed: undefined });
    expect(t.setup).toMatchObject({ consoleUrl: 'https://tt.example', helmValues: 'console:', openshift: 'oc project' });
    await expect(api.mocks.startManaged('shop')).rejects.toMatchObject({ status: 409, serverCode: 'kubernetes_disabled' });
  });

  it('downloads the Postman collection pointed at the running mock', async () => {
    const { api, calls } = make(on('GET', '/api/v1/contracts/shipping-ext/postman', json({ info: {} })));
    await api.contracts.postman('shipping-ext', 'shop', 'http://mock.ci:8480/__svc/carrier');
    const c = calls.find((x) => x.path.endsWith('/postman'))!;
    expect(c.query.get('base_url')).toBe('http://mock.ci:8480/__svc/carrier');
    expect(c.query.get('group')).toBe('shop');
  });

  it('builds clock steps the control API accepts', () => {
    expect(clockStep(2, 'h')).toBe('2h');
    expect(clockStep(0, 'd')).toBeNull();
    expect(clockStep(1.5, 'd')).toBeNull();
    expect(clockStep(1000000, 's')).toBeNull();
  });
});
