import { describe, expect, it, vi } from 'vitest';
import { tk } from '../../i18n/index.svelte';
import { ApiError, type Api } from '../types';
import { createRestApi } from './adapter';
import { err, json, noSleep, on, scripted, text, type Recorded } from './testkit';

const ME = {
  user: { id: 'usr_1', username: 'olga', display_name: 'Olga Operatrice', auth_method: 'local', roles: ['operator', 'bogus-role'] },
  roles: ['operator', 'bogus-role'],
  csrf_token: 'csrf-1',
  csrf_header: 'X-CSRF-Token',
  expires_at: '2026-10-24T12:00:00Z',
  idle_expires_at: '2026-10-24T10:00:00Z',
  session_idle_timeout_ms: 1800000,
};

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  const onUnauthorized = vi.fn();
  const api = createRestApi({
    fetch: s.fetch,
    sleep: noSleep,
    onUnauthorized,
    eventSource: null,
    pollMs: 5,
    now: () => new Date('2026-10-24T09:30:00Z'),
    docTtlMs: 0,
  });
  return { api, onUnauthorized, ...s };
}

const body = (r: Recorded) => JSON.parse(r.body ?? 'null') as Record<string, unknown>;
const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? e.code : 'other';
  }
};
const loggedIn = on('GET', '/api/v1/auth/me', json(ME));

// ---------------------------------------------------------------- auth and session

describe('auth', () => {
  it('maps the principal to the server roles and drops unknown ones', async () => {
    const { api } = make(loggedIn);
    expect(await api.auth.me()).toEqual({ id: 'usr_1', username: 'olga', displayName: 'Olga Operatrice', roles: ['operator'], authMethod: 'local' });
  });
  it('me() answers null, without redirect, when there is no session', async () => {
    const { api, onUnauthorized } = make(on('GET', '/api/v1/auth/me', err(401, 'unauthenticated')));
    expect(await api.auth.me()).toBeNull();
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
  it('login sends credentials, keeps the CSRF token for the next write and maps oidc users to sso', async () => {
    const { api, calls } = make(
      on('POST', '/api/v1/auth/login', json({ ...ME, user: { ...ME.user, auth_method: 'oidc' } })),
      on('POST', '/api/v1/fleet/kill', json(null, 204)),
    );
    const u = await api.auth.login({ username: 'olga', password: 'pw-pw-pw-pw-pw' });
    expect(u.authMethod).toBe('sso');
    expect(body(calls[0])).toEqual({ username: 'olga', password: 'pw-pw-pw-pw-pw' });
    await api.sources.kill({ all: true }, true);
    expect(calls[1].headers['x-csrf-token']).toBe('csrf-1');
  });
  it('a wrong password is a 401 with a readable code and no redirect', async () => {
    const { api, onUnauthorized } = make(on('POST', '/api/v1/auth/login', err(401, 'invalid_credentials', 'invalid username or password')));
    const e = await api.auth.login({ username: 'x', password: 'y' }).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: 'unauthenticated', serverCode: 'invalid_credentials' });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
  it('logout drops the token', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/auth/logout', json(null, 204)), on('POST', '/api/v1/fleet/kill', json(null, 204)));
    await api.auth.me();
    await api.auth.logout();
    expect(calls[1].headers['x-csrf-token']).toBe('csrf-1');
    // the next write has no token until me() is asked again (it asks by itself)
    await api.sources.kill({ all: true }, false).catch(() => undefined);
    expect(calls.some((c) => c.path === '/api/v1/auth/me' && calls.indexOf(c) > 1)).toBe(true);
  });
  it('a write before any me() fetches the token first', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/fleet/sources/src-1/revoke', json(null, 204)));
    await api.sources.revoke('src-1');
    expect(calls.map((c) => c.path)).toEqual(['/api/v1/auth/me', '/api/v1/fleet/sources/src-1/revoke']);
    expect(calls[1].headers['x-csrf-token']).toBe('csrf-1');
  });
  it('a lost session on any other call goes to the 401 hook', async () => {
    const { api, onUnauthorized } = make(on('GET', '/api/v1/fleet/sources', err(401, 'unauthenticated')));
    expect(await code(api.sources.list())).toBe('unauthenticated');
    expect(onUnauthorized).toHaveBeenCalled();
  });
  it('403 is a role problem, not a lost session', async () => {
    const { api, onUnauthorized } = make(on('GET', '/api/v1/gaps', err(403, 'forbidden', 'insufficient role')));
    expect(await code(api.gaps.list())).toBe('forbidden');
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
  it('the SSO button redirects the whole page to the identity provider', () => {
    const assign = vi.fn();
    vi.stubGlobal('window', { location: { assign } });
    const { api } = make();
    void api.auth.ssoLogin();
    expect(assign).toHaveBeenCalledWith(expect.stringContaining('/api/v1/auth/oidc/start'));
    vi.unstubAllGlobals();
  });
});

describe('system', () => {
  it('reads setup state and login methods from /auth/config', async () => {
    const { api } = make(on('GET', '/api/v1/auth/config', json({ local: true, oidc: false, setup_required: true })), on('GET', '/api/v1/version', err(404, 'not_found')));
    expect(await api.system.status()).toEqual({ initialized: false, version: '', ssoEnabled: false, localEnabled: true, adapter: 'rest' });
  });
  it('reads the version when the server has the endpoint', async () => {
    const { api } = make(on('GET', '/api/v1/auth/config', json({ local: true, oidc: true, setup_required: false })), on('GET', '/api/v1/version', json({ version: '0.4.0', spec: '1.1' })));
    expect(await api.system.status()).toMatchObject({ initialized: true, version: '0.4.0', ssoEnabled: true });
  });
  it('shows the installation name and the environment label the server reports', async () => {
    const { api } = make(
      on('GET', '/api/v1/auth/config', json({ local: true, oidc: false, setup_required: false })),
      on('GET', '/api/v1/version', json({ version: '0.5.0', installation_name: 'Acme Lab', environment: 'staging' })),
    );
    expect(await api.system.status()).toMatchObject({ version: '0.5.0', installation: 'Acme Lab', environment: 'staging' });
  });
  it('an empty or unknown environment label is no badge', async () => {
    const { api } = make(
      on('GET', '/api/v1/auth/config', json({ local: true, oidc: false, setup_required: false })),
      on('GET', '/api/v1/version', json({ version: '0.5.0', installation_name: '', environment: '' })),
    );
    const s = await api.system.status();
    expect(s.installation).toBeUndefined();
    expect(s.environment).toBeUndefined();
  });
  it('setup posts the token and keeps the session the server opens', async () => {
    const { api, calls } = make(on('POST', '/api/v1/setup', json(ME, 201)), on('POST', '/api/v1/fleet/kill', json(null, 204)));
    await api.system.setup({ setupToken: 'tts_abc', username: 'admin', password: 'a-long-password' });
    expect(body(calls[0])).toEqual({ setup_token: 'tts_abc', username: 'admin', password: 'a-long-password' });
    await api.sources.kill({ all: true }, true);
    expect(calls[1].headers['x-csrf-token']).toBe('csrf-1');
  });
  it('setup twice is already_initialized, a bad token is a plain 401', async () => {
    const a = make(on('POST', '/api/v1/setup', err(409, 'setup_done')));
    expect(await code(a.api.system.setup({ setupToken: 't', username: 'a', password: 'p' }))).toBe('already_initialized');
    const b = make(on('POST', '/api/v1/setup', err(401, 'invalid_setup_token')));
    expect(await code(b.api.system.setup({ setupToken: 't', username: 'a', password: 'p' }))).toBe('unauthenticated');
    expect(b.onUnauthorized).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------- fleet

const SRC = {
  source_id: 'src-1',
  kind: 'sdk-node',
  version: '1.2.0',
  service_name: 'shop-api',
  group: 'shop',
  state: 'capturing',
  killed: false,
  revoked: false,
  policy: { id: 'p-shop', version: 3, issued_seq: 9 },
  last_seen: '2026-10-24T09:29:00Z',
  events_per_min: 120,
  drop_ratio: 0.01,
  sanitizer_errors: 0,
  sampling_override_bp: null,
  overhead_us: { p50: 800 },
  last_errors: [{ code: 'send_error', at: '2026-10-24T09:00:00Z', first_seen: '2026-10-24T08:58:00Z', last_seen: '2026-10-24T09:00:00Z', count: 3 }],
  problems: [{ code: 'no_policy', message: 'x', hint: 'y' }],
};
const POLICY_YAML = `# starter
format: tt.policy/v1
policy_id: p-shop
default: drop
hmac:
  kid: k1
  epoch: "2026-10"
sampling:
  rate: 0.05
services:
  shop-api:
    match: { inbound: true }
    ops:
      "POST /orders":
        response:
          $.status: keep
`;
const PV = (over: Record<string, unknown> = {}) => ({
  policy_id: 'p-shop',
  version: 3,
  issued_seq: 9,
  status: 'active',
  origin: 'propose',
  proposed_by: 'Olga Operatrice',
  proposed_at: '2026-10-20T10:00:00Z',
  classification: 'opening',
  approvals_required: 2,
  approvals: [
    { by: 'Paolo', at: '2026-10-20T11:00:00Z', verified: false },
    { by: 'Elena', at: '2026-10-20T12:00:00Z', verified: false, admin_override: true, reason: 'incident' },
  ],
  targets: { groups: ['shop'] },
  diff: [{ change: 'added', where: 'shop-api · POST /orders · $.id', to: 'hmac(order)', opens: true }],
  author_yaml: POLICY_YAML,
  ...over,
});

describe('sources', () => {
  it('maps the admin view, with the sampling rate of the policy', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/sources', json([SRC, { ...SRC, source_id: 'src-2', state: 'weird', last_seen: null, policy: undefined, overhead_us: undefined, sampling_override_bp: 100 }])), on('GET', '/api/v1/fleet/policies', json([PV()])));
    const [a, b] = await api.sources.list();
    expect(a).toMatchObject({
      id: 'src-1',
      serviceName: 'shop-api',
      group: 'shop',
      state: 'capturing',
      policy: { id: 'p-shop', version: 3 },
      policyRateBp: 500,
      samplingBp: 500,
      overheadUs: { p50: 800, p99: 0 },
      lastErrors: [{ code: 'send_error', at: '2026-10-24T09:00:00Z', firstSeen: '2026-10-24T08:58:00Z', count: 3 }],
      // The server's English text is replaced by the console's translation of the code.
      problems: [{ code: 'no_policy', message: tk('problem.no_policy'), hint: tk('problem.no_policy.hint') }],
      instances: 1,
    });
    expect(b).toMatchObject({ state: 'capturing', policyRateBp: 10000, samplingBp: 100, lastSeen: '1970-01-01T00:00:00.000Z' });
    expect(b.overheadUs).toBeUndefined();
  });
  it('revoke, sampling and kill use the fleet endpoints', async () => {
    const { api, calls } = make(loggedIn, on('POST', /\/revoke$/, json(null, 204)), on('PUT', /\/sampling$/, json(null, 204)), on('POST', '/api/v1/fleet/kill', json(null, 204)));
    await api.sources.revoke('src-1');
    await api.sources.setSampling('src-1', 250);
    await api.sources.kill({ group: 'shop' }, true);
    await api.sources.kill({ sourceId: 'src-1' }, false);
    await api.sources.kill({ all: true }, true);
    const w = calls.filter((c) => c.method !== 'GET');
    expect(w.map((c) => [c.method, c.path])).toEqual([
      ['POST', '/api/v1/fleet/sources/src-1/revoke'],
      ['PUT', '/api/v1/fleet/sources/src-1/sampling'],
      ['POST', '/api/v1/fleet/kill'],
      ['POST', '/api/v1/fleet/kill'],
      ['POST', '/api/v1/fleet/kill'],
    ]);
    expect(body(w[1])).toEqual({ sampling_override_bp: 250 });
    expect(body(w[2])).toEqual({ active: true, scope: { group: 'shop' } });
    expect(body(w[3])).toEqual({ active: false, scope: { source_id: 'src-1' } });
    expect(body(w[4])).toEqual({ active: true, scope: { all: true } });
  });
});

describe('onboarding', () => {
  const GROUP = { name: 'shop', description: '', policy_id: 'p-shop', allowed_service_names: ['shop-api'], sampling_override_bp: null, killed: false };
  const TOKEN = { token_id: 'tok-1', token: 'tte_secret.pin', expires_at: '2026-10-24T10:30:00Z', snippets: [{ title: 'Node.js (18+)', language: 'bash', text: 'npm i' }] };

  it('creates the group when missing, then the token, then the starter policy for a group without one', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/fleet/groups/new-group', err(404, 'not_found')),
      on('POST', '/api/v1/fleet/groups', (r) => json({ ...GROUP, ...(body(r) as object), policy_id: null }, 201)),
      on('POST', '/api/v1/fleet/enrollment-tokens', json(TOKEN, 201)),
      on('POST', '/api/v1/fleet/groups/new-group/starter-policy', json(PV({ version: 1, status: 'draft' }), 201)),
    );
    const t = await api.onboarding.createToken('sdk-node', 'new-group', ['shop-api', 'shop-worker']);
    expect(t).toMatchObject({ tokenId: 'tok-1', token: 'tte_secret.pin', choice: 'sdk-node', group: 'new-group', starterPolicy: { policyId: 'p-shop', version: 1 } });
    expect(t.snippets[0]).toEqual({ title: 'Node.js (18+)', language: 'bash', text: 'npm i' });
    const w = calls.filter((c) => c.method === 'POST' && c.path !== '/api/v1/auth/me');
    expect(body(w[0])).toMatchObject({ name: 'new-group', allowed_service_names: ['shop-api', 'shop-worker'] });
    expect(body(w[1])).toEqual({ kind: 'sdk-node', group: 'new-group', token_type: 'one_time' });
    // tt-core picks the HMAC kid (keyguard) and the epoch (month): the starter policy opens no value (policy.md §7).
    expect(body(w[2])).toEqual({});
  });
  it('widens an existing group when a new service name is needed, keeping its other fields', async () => {
    const { api, calls } = make(loggedIn, on('GET', '/api/v1/fleet/groups/shop', json(GROUP)), on('PUT', '/api/v1/fleet/groups/shop', (r) => json({ ...GROUP, ...(body(r) as object) })), on('POST', '/api/v1/fleet/enrollment-tokens', json(TOKEN, 201)));
    const t = await api.onboarding.createToken('egress', 'shop', ['shop-api', 'billing']);
    expect(t.starterPolicy).toBeUndefined();
    const put = calls.find((c) => c.method === 'PUT');
    expect(body(put as Recorded)).toMatchObject({ name: 'shop', policy_id: 'p-shop', allowed_service_names: ['shop-api', 'billing'] });
  });
  it('the Kubernetes injection card creates a group token of its own kind and shows the server snippets', async () => {
    const snippets = [
      { title: 'Kubernetes secret (namespace of the application)', language: 'bash', text: 'kubectl create secret generic tt-enroll --from-literal=token=tte_secret.pin' },
      { title: 'Pod template annotations (injection webhook)', language: 'yaml', text: 'traffic-twin.io/inject: node' },
    ];
    const { api, calls } = make(loggedIn, on('GET', '/api/v1/fleet/groups/shop', json(GROUP)), on('POST', '/api/v1/fleet/enrollment-tokens', json({ ...TOKEN, snippets }, 201)));
    const t = await api.onboarding.createToken('k8s-inject', 'shop');
    expect(body(calls.find((c) => c.path.endsWith('enrollment-tokens')) as Recorded)).toEqual({ kind: 'k8s-inject', group: 'shop', token_type: 'group' });
    expect(t.snippets.map((s) => s.title)).toEqual(snippets.map((s) => s.title)); // nothing added by the UI
  });
  it('maps the onboarding status', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/onboarding/tok-1/status', json({ steps: { enrolled: true, policy_received: false, first_events: 4 }, sources: ['src-1'], problems: [{ code: 'no_policy', message: 'm' }] })));
    expect(await api.onboarding.status('tok-1')).toEqual({ enrolled: true, policyReceived: false, firstEvents: 4, problems: [{ code: 'no_policy', message: tk('problem.no_policy'), hint: undefined }] });
  });
  it('watch polls when there is no EventSource, and stops when asked', async () => {
    let n = 0;
    const { api, calls } = make(on('GET', '/api/v1/fleet/onboarding/tok-1/status', () => json({ steps: { enrolled: true, policy_received: true, first_events: ++n }, sources: [], problems: [] })));
    const seen: number[] = [];
    const stop = api.onboarding.watch('tok-1', (s) => seen.push(s.firstEvents));
    await vi.waitFor(() => expect(seen.length).toBeGreaterThanOrEqual(3));
    stop();
    const after = calls.length;
    await new Promise((r) => setTimeout(r, 30));
    expect(calls.length).toBe(after);
    expect(seen.slice(0, 3)).toEqual([1, 2, 3]);
  });
  it('watch uses server-sent events when available and falls back to polling when the stream breaks', async () => {
    class FakeES {
      static last: FakeES;
      listeners = new Map<string, (e: MessageEvent<string>) => void>();
      onerror: (() => void) | null = null;
      closed = false;
      constructor(public url: string, public init?: EventSourceInit) {
        FakeES.last = this;
      }
      addEventListener(t: string, f: (e: MessageEvent<string>) => void) {
        this.listeners.set(t, f);
      }
      close() {
        this.closed = true;
      }
    }
    const s = scripted(on('GET', '/api/v1/fleet/onboarding/tok-1/status', json({ steps: { enrolled: true, policy_received: true, first_events: 99 }, sources: [], problems: [] })));
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, eventSource: FakeES as unknown as typeof EventSource, pollMs: 5 });
    const seen: number[] = [];
    const stop = api.onboarding.watch('tok-1', (st) => seen.push(st.firstEvents));
    expect(FakeES.last.url).toBe('/api/v1/fleet/onboarding/tok-1/status');
    expect(FakeES.last.init).toEqual({ withCredentials: true });
    FakeES.last.listeners.get('status')?.({ data: JSON.stringify({ steps: { enrolled: true, policy_received: false, first_events: 7 }, sources: [], problems: [] }) } as MessageEvent<string>);
    FakeES.last.listeners.get('status')?.({ data: 'not json' } as MessageEvent<string>); // skipped
    expect(seen).toEqual([7]);
    expect(s.calls).toHaveLength(0);
    FakeES.last.onerror?.();
    expect(FakeES.last.closed).toBe(true);
    await vi.waitFor(() => expect(seen).toContain(99));
    stop();
  });
  it('discovered services come from the service list: inbound is own, anything else external', async () => {
    const { api } = make(
      on(
        'GET',
        '/api/v1/services',
        json([
          { service: 'shop-api', kind: 'inbound', calls: 2310, ops: 6, in_policy: true, first_seen: 'a', last_seen: 'b', twin: true },
          { service: 'host:api.carrier.example', kind: 'outbound-host', calls: 1180, ops: 3, in_policy: false, first_seen: 'a', last_seen: 'b', twin: true },
        ]),
      ),
    );
    expect(await api.onboarding.discovered('tok-1')).toEqual([
      { name: 'shop-api', kind: 'own', baseUrl: undefined, calls: 2310, operations: 6, proposeTwin: false },
      { name: 'host:api.carrier.example', kind: 'external', baseUrl: 'api.carrier.example', hostPattern: 'api.carrier.example', calls: 1180, operations: 3, proposeTwin: true },
    ]);
  });
});

describe('policy assistant and policies', () => {
  const GROUP = { name: 'shop', policy_id: 'p-shop', allowed_service_names: ['shop-api'], sampling_override_bp: null, killed: false };
  const F = (op: string, part: string, path: string, shape: string, distinct: number, suggestion: string, reason: string) => ({
    service: 'x',
    op,
    part,
    path,
    shape,
    observed: 500,
    distinct_estimate: distinct,
    suggestion,
    reason,
  });
  const ASSIST = {
    policy_id: 'p-shop',
    min_calls: 20,
    ready: false,
    need_calls: 12,
    message: 'more traffic is needed',
    has_identity: false,
    identity: { from: 'header', name: 'authorization', jwt_claim: 'sub', service: 'shop-api', calls: 500, with_header: 490, reason: 'jwt' },
    services: [
      {
        service: 'shop-api',
        kind: 'inbound',
        declared: true,
        name: 'shop-api',
        exact: false,
        calls: 1000,
        ops: [
          {
            op: 'POST /orders',
            declared: true,
            calls: 500,
            need_calls: 0,
            raw_ops: ['POST /orders'],
            fields: [
              F('POST /orders', 'response', '$.id', 'drop:str:uuid', 500, 'hmac(order)', 'identifier'),
              F('POST /orders', 'response', '$.status', 'drop:str:l8', 5, 'keep', 'enum'),
              F('POST /orders', 'response', '$.total', 'drop:int', 300, 'bucket(num, [0, 10, 100, 1000])', 'number'),
            ],
          },
          { op: 'GET /orders/{id}', declared: false, calls: 8, need_calls: 12, raw_ops: ['GET /orders/{drop:str:l32}'], fields: [F('GET /orders/{id}', 'request', 'path.id', 'drop:str:l32', 8, 'hmac(order)', 'segment')] },
        ],
      },
      {
        service: 'host:localhost:8080',
        kind: 'external',
        declared: false,
        name: 'localhost-8080',
        host_pattern: 'localhost:8080',
        exact: true,
        calls: 300,
        ops: [{ op: 'GET /v1/shipments', declared: false, calls: 300, need_calls: 0, raw_ops: null, fields: [F('GET /v1/shipments', 'request', 'query.orderId', 'drop:str:l32', 200, 'hmac(order)', 'identifier')] }],
      },
    ],
  };
  const routes = [loggedIn, on('GET', '/api/v1/fleet/groups/shop', json(GROUP)), on('GET', '/api/v1/fleet/policies/p-shop/assist', json(ASSIST)), on('GET', '/api/v1/fleet/policies', json([PV()]))];
  const AFTER = POLICY_YAML + '      "GET /orders/{id}": {}\n';
  const draftRoute = on('POST', '/api/v1/fleet/policies/p-shop/assist/draft', (r) => {
    const b = JSON.parse(r.body ?? '{}') as { dry_run?: boolean };
    return b.dry_run ? json({ before: POLICY_YAML, after: AFTER }) : json(PV({ version: 4, status: 'draft', approvals: [], author_yaml: AFTER }), 201);
  });

  it('groups the operations per service, turns the strings into choices and reads what the active policy does today', async () => {
    const { api } = make(...routes);
    const a = await api.onboarding.assist('shop');
    expect(a).toMatchObject({ policyId: 'p-shop', minCalls: 20, ready: false, needCalls: 12, hasIdentity: false, identity: { header: 'authorization', claim: 'sub' } });
    expect(a.services.map((s) => [s.service, s.kind, s.declared, s.name, s.exact, s.ops.map((o) => [o.op, o.needCalls])])).toEqual([
      ['shop-api', 'own', true, 'shop-api', false, [['POST /orders', 0], ['GET /orders/{id}', 12]]],
      ['host:localhost:8080', 'external', false, 'localhost-8080', true, [['GET /v1/shipments', 0]]],
    ]);
    expect(a.services[1]).toMatchObject({ hostPattern: 'localhost:8080' });
    expect(a.services[1].ops[0].rawOps).toEqual([]);
    expect(a.suggestions.map((s) => [s.service, s.op, s.path, s.suggestion, s.current])).toEqual([
      ['x', 'POST /orders', '$.id', { action: 'hmac', arg: 'order' }, { action: 'drop' }],
      ['x', 'POST /orders', '$.status', { action: 'keep' }, { action: 'keep' }], // already kept by the active policy
      ['x', 'POST /orders', '$.total', { action: 'bucket', arg: '0, 10, 100, 1000' }, { action: 'drop' }],
      ['x', 'GET /orders/{id}', 'path.id', { action: 'hmac', arg: 'order' }, { action: 'drop' }],
      ['x', 'GET /v1/shipments', 'query.orderId', { action: 'hmac', arg: 'order' }, { action: 'drop' }],
    ]);
    expect(a.suggestions[0]).toMatchObject({ id: 'sg-1', part: 'response', distinct: 500, observed: 500 });
    // The fields of an operation are the same objects as the flat list.
    expect(a.services[0].ops[0].fields[1].id).toBe('sg-2');
  });
  it('a group without a policy has nothing to assist', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/groups/shop', json({ ...GROUP, policy_id: null })));
    const a = await api.onboarding.assist('shop');
    expect(a.services).toEqual([]);
    expect(a.ready).toBe(false);
  });
  it('proposes through the server: operations to declare, only the changed actions, the scheme chosen for the host', async () => {
    const { api, calls } = make(...routes, draftRoute);
    const a = await api.onboarding.assist('shop');
    const choices = a.suggestions.map((s) => ({ suggestionId: s.id, choice: s.path === '$.status' ? { action: 'drop' as const } : s.suggestion }));
    const pv = await api.policies.propose({
      group: 'shop',
      choices,
      hostsDiscovery: 'auto',
      services: [
        { service: 'shop-api', name: 'shop-api', ops: ['POST /orders', 'GET /orders/{id}'] },
        { service: 'host:localhost:8080', name: 'carrier', base: 'http://localhost:8080', ops: ['GET /v1/shipments'] },
      ],
      identity: { from: 'header', name: 'authorization', claim: 'sub' },
    });
    expect(pv).toMatchObject({ policyId: 'p-shop', version: 4, status: 'draft', yamlBefore: POLICY_YAML });
    const posts = calls.filter((c) => c.method === 'POST' && c.path === '/api/v1/fleet/policies/p-shop/assist/draft');
    expect(posts).toHaveLength(2); // dry run (before/after), then the draft
    const body = JSON.parse(posts[1].body ?? '{}');
    expect(body).toEqual({
      services: [
        {
          service: 'shop-api',
          name: 'shop-api',
          ops: [
            {
              op: 'POST /orders',
              rules: [
                { part: 'response', path: '$.id', action: 'hmac(order)' },
                { part: 'response', path: '$.status', action: 'drop' }, // removes the keep of the active policy
                { part: 'response', path: '$.total', action: 'bucket(num, [0, 10, 100, 1000])' },
              ],
            },
            { op: 'GET /orders/{id}', rules: [{ part: 'request', path: 'path.id', action: 'hmac(order)' }] },
          ],
        },
        { service: 'host:localhost:8080', name: 'carrier', base: 'http://localhost:8080', ops: [{ op: 'GET /v1/shipments', rules: [{ part: 'request', path: 'query.orderId', action: 'hmac(order)' }] }] },
      ],
      hosts_discovery: 'auto',
      identity: { from: 'header', name: 'authorization', jwt_claim: 'sub' },
    });
    expect(JSON.parse(posts[0].body ?? '{}').dry_run).toBe(true);
    expect(posts[1].headers['x-csrf-token']).toBe('csrf-1');
    // Never "(raw)": every operation is a template.
    expect(posts[1].body).not.toContain('(raw)');
  });
  it('refuses to propose an empty change', async () => {
    const { api } = make(...routes, on('POST', '/api/v1/fleet/policies/p-shop/assist/draft', json({ before: POLICY_YAML, after: POLICY_YAML })));
    const a = await api.onboarding.assist('shop');
    expect(await code(api.policies.propose({ group: 'shop', choices: a.suggestions.map((s) => ({ suggestionId: s.id, choice: s.current })) }))).toBe('invalid');
  });
  it('previews the text before and after as tt-core writes it', async () => {
    const { api, calls } = make(...routes, draftRoute);
    const a = await api.onboarding.assist('shop');
    const pv = await api.policies.preview({ group: 'shop', choices: a.suggestions.map((s) => ({ suggestionId: s.id, choice: s.current })), services: [{ service: 'shop-api', name: 'shop-api', ops: ['GET /orders/{id}'] }] });
    expect(pv).toEqual({ before: POLICY_YAML, after: AFTER, skipped: [] });
    const body = JSON.parse((calls.at(-1) as Recorded).body ?? '{}');
    expect(body).toEqual({ dry_run: true, services: [{ service: 'shop-api', name: 'shop-api', ops: [{ op: 'GET /orders/{id}', rules: [] }] }] });
  });
  it('lists versions with the text of the version they replace and admin approvals flagged', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/policies', json([PV({ version: 2, status: 'superseded', author_yaml: 'old: 1' }), PV({ version: 3, classification: 'closing', approvals_required: 1 })])));
    const list = await api.policies.list();
    expect(list[1]).toMatchObject({ version: 3, status: 'active', opensData: false, approvalsRequired: 1, yamlBefore: 'old: 1', groups: ['shop'] });
    expect(list[1].approvals).toEqual([
      { by: 'Paolo', at: '2026-10-20T11:00:00Z', mode: 'standard', reason: undefined },
      { by: 'Elena', at: '2026-10-20T12:00:00Z', mode: 'admin', reason: 'incident' },
    ]);
  });
  it('maps token_fresh of approvals only when the server sends it (OIDC)', async () => {
    const draft = PV({ status: 'draft', approvals: [{ by: 'Paolo', at: '2026-10-20T11:00:00Z', verified: true, token_fresh: false }, { by: 'Pia', at: '2026-10-20T11:05:00Z', verified: false }] });
    const { api } = make(loggedIn, on('POST', /approve$/, json(draft)));
    const v = await api.policies.approve('p-shop', 3);
    expect(v.approvals[0]).toMatchObject({ by: 'Paolo', tokenFresh: false });
    expect('tokenFresh' in v.approvals[1]).toBe(false);
  });
  it('approve sends no body for a normal approval and the reason for an admin one', async () => {
    const { api, calls } = make(loggedIn, on('POST', /approve$/, json(PV({ status: 'draft' }))));
    await api.policies.approve('p-shop', 3);
    await api.policies.approve('p-shop', 3, '  incident 42  ');
    const w = calls.filter((c) => c.path.endsWith('/approve'));
    expect(w[0].body).toBeUndefined();
    expect(body(w[1])).toEqual({ reason: 'incident 42' });
    expect(w[0].path).toBe('/api/v1/fleet/policies/p-shop/versions/3/approve');
  });
  it('maps the server refusals of an approval to readable codes', async () => {
    const { api } = make(loggedIn, on('POST', /approve$/, err(409, 'self_approval', 'the author of a change cannot approve it')));
    const e = await api.policies.approve('p-shop', 3).catch((x: unknown) => x);
    expect(e).toMatchObject({ code: 'conflict', serverCode: 'self_approval' });
  });
});

describe('OIDC step-up of approvals', () => {
  function withStepUp(...h: Parameters<typeof scripted>) {
    const s = scripted(...h);
    const stepUp = vi.fn();
    const api = createRestApi({ fetch: s.fetch, sleep: noSleep, eventSource: null, now: () => new Date('2026-10-24T09:30:00Z'), stepUp });
    return { api, stepUp, ...s };
  }
  const pending = async (p: Promise<unknown>) => Promise.race([p.then(() => 'settled', () => 'settled'), new Promise((r) => setTimeout(() => r('pending'), 20))]);

  it('stepup_required starts the step-up with the call to repeat, for approve, publish and dismiss', async () => {
    const { api, stepUp } = withStepUp(loggedIn, on('POST', /\/(approve|publish|resolve)$/, err(403, 'stepup_required', 'step-up required')));
    expect(await pending(api.policies.approve('p-shop', 3, '  why  '))).toBe('pending');
    expect(await pending(api.publications.publish('pk-1'))).toBe('pending');
    expect(await pending(api.quarantine.resolve('q-12', 'dismiss', 'n'))).toBe('pending');
    expect(stepUp.mock.calls.map((c) => c[0])).toEqual([
      { kind: 'policy-approve', policyId: 'p-shop', version: 3, reason: 'why' },
      { kind: 'pack-publish', packId: 'pk-1' },
      { kind: 'quarantine-dismiss', itemId: 'q-12', note: 'n' },
    ]);
  });
  it('a close never steps up; other refusals reach the caller', async () => {
    const { api, stepUp } = withStepUp(
      loggedIn,
      on('POST', /resolve$/, err(403, 'stepup_required')),
      on('POST', /approve$/, err(403, 'oidc_required', 'local accounts cannot approve')),
    );
    expect(await api.quarantine.resolve('q-1', 'close').catch((x: unknown) => x)).toMatchObject({ code: 'forbidden', serverCode: 'stepup_required' });
    expect(await api.policies.approve('p-shop', 3).catch((x: unknown) => x)).toMatchObject({ code: 'forbidden', serverCode: 'oidc_required' });
    expect(stepUp).not.toHaveBeenCalled();
  });
});

describe('settings and keys', () => {
  const SETTINGS = {
    general: { installation_name: 'Acme Lab', environment: 'staging' },
    privacy: { events_retention_days: 30, aggregates_days: 400, k_min: { contract: 20, miner: 20, world: 25, gate: 20 }, min_samples: 20 },
    access: {
      local_enabled: true,
      oidc: { enabled: true, issuer_url: 'https://sso.example/realms/it', client_id: 'traffic-twin', scopes: ['openid'], roles_claim: 'groups' },
      session: { idle_timeout_s: 1800, absolute_timeout_s: 43200 },
    },
  };
  const APPROVALS = on('GET', '/api/v1/fleet/approval-settings', json({ opening_required: 1, admin_override: true, approvals_unverified: true, known: true }));
  it('reads the approval settings and what the server runs with', async () => {
    const { api } = make(APPROVALS, on('GET', '/api/v1/settings', json(SETTINGS)));
    expect(await api.settings.get()).toEqual({
      approvals: { openingRequired: 1, adminOverride: true, identitiesVerified: false },
      server: {
        installation: 'Acme Lab',
        environment: 'staging',
        privacy: { eventsRetentionDays: 30, aggregatesDays: 400, kMin: { contract: 20, miner: 20, world: 25, gate: 20 }, minSamples: 20 },
        access: { localEnabled: true, sso: { enabled: true, issuer: 'https://sso.example/realms/it', clientId: 'traffic-twin', roleClaim: 'groups' }, sessionIdleSeconds: 1800, sessionAbsoluteSeconds: 43200 },
      },
    });
    expect(api.capabilities).toEqual({ alertResolve: true, webhookToggle: true, settingsEdit: true, twinOnServer: true });
  });
  it('saving sends the two labels and nothing else, and forgets the cached labels', async () => {
    const { api, calls } = make(
      APPROVALS,
      on('GET', '/api/v1/settings', json(SETTINGS)),
      loggedIn,
      on('PATCH', '/api/v1/settings', json({ ...SETTINGS, general: { installation_name: 'Beta', environment: '' } })),
    );
    const s = await api.settings.get();
    const saved = await api.settings.save({ ...s, server: { ...(s.server as NonNullable<typeof s.server>), installation: 'Beta', environment: undefined } });
    expect(body(calls.find((c) => c.method === 'PATCH') as Recorded)).toEqual({ installation_name: 'Beta', environment: '' });
    expect(saved.server).toMatchObject({ installation: 'Beta', environment: undefined });
    expect(await code(api.settings.save({ approvals: s.approvals }))).toBe('unsupported');
  });
  it('a role that cannot read them gets the strict defaults and no server settings', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/approval-settings', err(403, 'forbidden')), on('GET', '/api/v1/settings', err(403, 'forbidden')));
    expect(await api.settings.get()).toEqual({ approvals: { openingRequired: 2, adminOverride: false, identitiesVerified: false, known: false } });
  });
  it('lists signing keys', async () => {
    const { api } = make(on('GET', '/api/v1/fleet/signing-keys', json([{ kid: 'pk1', alg: 'ed25519', public_key: 'AAA', endorsed_by: 'keyguard', revoked: false }])));
    expect(await api.fleet.signingKeys()).toEqual([{ kid: 'pk1', alg: 'ed25519', publicKey: 'AAA', endorsedBy: 'keyguard', revoked: false, active: false, trustedBy: 0, revoke: undefined }]);
  });
  it('maps the rotation state of signing keys and revokes one', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/fleet/signing-keys', json([
        { kid: 'k1', alg: 'Ed25519', public_key: 'AAA', revoked: false, active: false, trusted_by: 3,
          revoke: { seen_sources: 4, confirmed_sources: 3, required_fraction: 1, ok: false, blocker: 'rotation_unconfirmed' } },
        { kid: 'k2', alg: 'Ed25519', public_key: 'BBB', endorsed_by: 'k1', revoked: false, active: true, trusted_by: 3 },
      ])),
      loggedIn,
      on('POST', '/api/v1/fleet/signing-keys/k1/revoke', json(null, 204)),
    );
    const ks = await api.fleet.signingKeys();
    expect(ks[0]!.revoke).toEqual({ seen: 4, confirmed: 3, required: 1, ok: false, blocker: 'rotation_unconfirmed' });
    expect(ks[1]!.active).toBe(true);
    await api.fleet.revokeSigningKey('k1');
    expect(calls.some((c) => c.path === '/api/v1/fleet/signing-keys/k1/revoke')).toBe(true);
  });
});

// ---------------------------------------------------------------- contracts

const SHOP_DOC = {
  openapi: '3.1.0',
  info: { title: 'shop-api', version: '1.0.0' },
  paths: {
    '/orders': {
      post: {
        operationId: 'post_orders',
        'x-tt-observed': { calls: 1000, first_seen: '2026-10-01', last_seen: '2026-10-23' },
        'x-tt-latency-ms': { p50: 40, p95: 120, p99: 300 },
        'x-tt-entity': 'order',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' }, note: { type: 'string', 'x-tt-presence': 0.37 } } } } },
        },
        responses: {
          '201': {
            description: 'Created',
            'x-tt-frequency': 0.9,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['id', 'status'],
                  properties: {
                    id: { type: 'string', 'x-tt-value': { kind: 'id', domain: 'order' } },
                    status: { type: 'string', enum: ['CREATED', 'PAID'], 'x-tt-value': { kind: 'enum', enum: ['CREATED', 'PAID'] } },
                    eta: { type: ['string', 'null'], format: 'date-time', 'x-tt-presence': 0.5 },
                    items: { type: 'array', items: { type: 'object', required: ['sku'], properties: { sku: { type: 'string' }, qty: { type: 'integer', 'x-tt-presence': 0.8 } } } },
                    tags: { type: 'array', items: { type: 'string' } },
                  },
                },
                examples: { typical: { value: { id: 'ORD-SYN-1', status: 'CREATED' } } },
              },
            },
          },
          '503': { description: 'Service Unavailable', 'x-tt-frequency': 0.1 },
        },
      },
    },
    '/orders/{id}': { get: { operationId: 'get_orders_id', 'x-tt-observed': { calls: 5, first_seen: '2026-10-20', last_seen: '2026-10-22' }, responses: { '200': { description: 'OK', 'x-tt-frequency': 1 } } } },
  },
};
const SERVICES = [
  { service: 'shop-api', kind: 'inbound', calls: 1005, ops: 2, in_policy: true, first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-23T00:00:00Z', twin: true },
  { service: 'host:api.carrier.example', kind: 'outbound-host', calls: 80, ops: 1, in_policy: false, first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-22T00:00:00Z', twin: true },
];
const GAPS = [
  { id: 'gp-000000000001', kind: 'few-samples', service: 'shop-api', op: 'GET /orders/{id}', scope: 'op', detail: 'only 5 calls observed (minimum 20)', count: 5, threshold: 20 },
  { id: 'gp-000000000002', kind: 'few-samples', service: 'shop-api', op: 'POST /orders', scope: 'field', detail: 'resp 201 body $.eta: optional field observed in only 14 objects', count: 14, threshold: 20 },
  { id: 'gp-000000000003', kind: 'status-unseen', service: 'shop-api', op: 'POST /orders', scope: 'op', detail: 'no 4xx response observed', count: 1000 },
  { id: 'gp-000000000004', kind: 'rule-low-support', service: 'shop-api', op: 'POST /orders', scope: 'op', detail: 'x', count: 3, threshold: 40 },
  { id: 'gp-000000000005', kind: 'value-unknown', service: 'shop-api', op: 'POST /orders', scope: 'field', detail: 'y', threshold: 20 },
];
const contractRoutes = [
  on('GET', '/api/v1/services', json(SERVICES)),
  on('GET', '/api/v1/contracts/shop-api', (r) => (r.query.get('format') === 'yaml' ? text('openapi: 3.1.0\n', 200, 'application/yaml') : json(SHOP_DOC))),
  on('GET', '/api/v1/contracts/host%3Aapi.carrier.example', err(404, 'not_found')),
  on('GET', '/api/v1/gaps', json(GAPS)),
];

describe('contracts', () => {
  it('summarizes operations from the OpenAPI document and its x-tt extensions', async () => {
    const { api } = make(...contractRoutes);
    const ops = await api.contracts.operations('shop-api');
    expect(ops).toHaveLength(2);
    const post = ops.find((o) => o.op === 'POST /orders');
    expect(post).toMatchObject({
      service: 'shop-api',
      method: 'POST',
      pathTemplate: '/orders',
      calls: 1000,
      firstSeen: '2026-10-01T00:00:00Z',
      latencyMs: { p50: 40, p95: 120, p99: 300 },
      entity: 'order',
      fewSamples: false,
    });
    expect(post?.statuses).toEqual([
      { status: 201, frequency: 0.9, calls: 900, example: 'typical' },
      { status: 503, frequency: 0.1, calls: 100, example: undefined },
    ]);
    expect(ops.find((o) => o.op === 'GET /orders/{id}')?.fewSamples).toBe(true); // from the gaps list
  });
  it('lists the operations of every service, skipping the ones without a contract yet', async () => {
    const { api } = make(...contractRoutes);
    expect((await api.contracts.operations()).map((o) => o.op)).toEqual(['GET /orders/{id}', 'POST /orders']);
  });
  it('builds the schema tree with presence, formats, enums, nesting and examples', async () => {
    const { api } = make(...contractRoutes);
    const d = await api.contracts.operation('shop-api', 'POST /orders');
    expect(d.request?.children?.map((c) => [c.name, c.presence, c.format])).toEqual([
      ['email', 1, 'email'],
      ['note', 0.37, undefined],
    ]);
    const r = d.responses[0];
    expect(r.status).toBe(201);
    const by = Object.fromEntries((r.schema.children ?? []).map((c) => [c.name, c]));
    expect(by.id).toMatchObject({ type: 'string', format: 'tt-token', presence: 1 });
    expect(by.status).toMatchObject({ enumValues: ['CREATED', 'PAID'] });
    expect(by.eta).toMatchObject({ type: 'string', format: 'date-time', presence: 0.5 });
    expect(by.items).toMatchObject({ type: 'array', itemType: 'object' });
    expect(by.items.children?.map((c) => [c.name, c.presence])).toEqual([
      ['sku', 1],
      ['qty', 0.8],
    ]);
    expect(by.tags).toMatchObject({ type: 'array', itemType: 'string' });
    expect(r.examples).toEqual([{ name: 'typical', value: { id: 'ORD-SYN-1', status: 'CREATED' } }]);
    expect(d.responses[1].schema.children).toBeUndefined(); // 503 has no body
    expect(await code(api.contracts.operation('shop-api', 'GET /nope'))).toBe('not_found');
  });
  it('fetches the contract JSON and YAML from the server', async () => {
    const { api, calls } = make(...contractRoutes);
    expect((await api.contracts.openapi('shop-api')).openapi).toBe('3.1.0');
    expect(await api.contracts.rawDocument('shop-api', 'yaml')).toBe('openapi: 3.1.0\n');
    expect(calls.at(-1)?.query.get('format')).toBe('yaml');
    expect(calls.at(-1)?.headers.accept).toBe('application/yaml');
  });
  it('summarizes a service: aggregates, drift, coverage and snapshots', async () => {
    const alerts = [{ drift_id: 'dr-00000001', service: 'shop-api', op: 'POST /orders', severity: 'breaking', change: 'c', first_seen: '2026-10-22T03:00:00Z', evidence: { calls_after_change: 10 }, state: 'open' }];
    const { api } = make(...contractRoutes, on('GET', '/api/v1/drift', json(alerts)), on('GET', /snapshots$/, json([{ snapshot_id: 's1' }, { snapshot_id: 's2' }])), on('GET', '/api/v1/fleet/sources', json([SRC])));
    const s = await api.contracts.service('shop-api');
    expect(s.service).toMatchObject({ name: 'shop-api', kind: 'own', operations: 2, sources: 1 });
    expect(s).toMatchObject({ operations: 2, calls: 1005, snapshots: 2, lastDrift: { severity: 'breaking', open: true }, coverage: { fewSamples: 1, statusesNeverSeen: 1, lowSupportRules: 1 } });
    expect(s.errorRate).toBeCloseTo(100 / 1005, 5);
    expect(s.latencyMs.p50).toBe(40);
  });
  it('snapshots carry the count of breaking and non-breaking changes the server reports, in one call', async () => {
    const infos = [
      { service: 'shop-api', snapshot_id: 's2', window: { from: '2026-10-23T00:00:00Z', to: '2026-10-24T00:00:00Z' }, ops: 2, calls: 900, created_at: 'x', hash: 'h2', breaking: 1, non_breaking: 2 },
      { service: 'shop-api', snapshot_id: 's1', window: { from: '2026-10-22T00:00:00Z', to: '2026-10-23T00:00:00Z' }, ops: 2, calls: 800, created_at: 'x', hash: 'h1', breaking: 0, non_breaking: 0 },
    ];
    const { api, calls } = make(on('GET', '/api/v1/contracts/shop-api/snapshots', json(infos)));
    expect(await api.contracts.snapshots('shop-api')).toEqual([
      { id: 's1', date: '2026-10-22T00:00:00Z', calls: 800, breaking: 0, nonBreaking: 0 },
      { id: 's2', date: '2026-10-23T00:00:00Z', calls: 900, breaking: 1, nonBreaking: 2 },
    ]);
    expect(calls).toHaveLength(1);
  });
  it('diffs two snapshots and shows the affected operations before and after', async () => {
    const after = structuredClone(SHOP_DOC) as typeof SHOP_DOC;
    const diff = {
      service: 'shop-api',
      from: { snapshot_id: 's1' },
      to: { snapshot_id: 's2' },
      breaking: 1,
      non_breaking: 0,
      changes: [{ op: 'POST /orders', where: 'resp 201 application/json $.eta', kind: 'type-changed', severity: 'breaking', change: "field 'eta' type changed", calls_after: 900 }],
    };
    const { api } = make(
      on('GET', '/api/v1/contracts/shop-api/snapshots/s2', (r) => (r.query.get('diff_against') ? json(diff) : json(after))),
      on('GET', '/api/v1/contracts/shop-api/snapshots/s1', json(SHOP_DOC)),
    );
    const d = await api.contracts.diff('shop-api', 's1', 's2');
    expect(d).toMatchObject({ from: 's1', to: 's2', changes: [{ severity: 'breaking', op: 'POST /orders', path: 'resp 201 application/json $.eta', kind: 'type-changed', detail: "field 'eta' type changed" }] });
    expect(JSON.parse(d.before)).toHaveProperty(['/orders', 'post']);
    expect(JSON.parse(d.before)).not.toHaveProperty(['/orders/{id}']);
  });
  it('gaps keep the server kinds, with the ones the UI knows renamed', async () => {
    const { api } = make(on('GET', '/api/v1/gaps', json(GAPS)));
    const g = await api.gaps.list();
    expect(g.map((x) => x.kind)).toEqual(['few-samples', 'few-samples', 'status-never-seen', 'low-support-rule', 'value-unknown']);
    expect(g[0]).toMatchObject({ id: 'gp-000000000001', scope: 'op', service: 'shop-api', op: 'GET /orders/{id}', count: 5, threshold: 20 });
    expect(g.map((x) => x.id)).toEqual(GAPS.map((x) => x.id)); // the server's ids, not made up here
    expect(g.map((x) => x.scope)).toEqual(['op', 'field', 'op', 'op', 'field']);
    expect(g[2].threshold).toBeUndefined();
  });
  it('only operation-level gaps make an operation rare; without access to the gaps the default threshold applies', async () => {
    const { api } = make(...contractRoutes);
    const ops = await api.contracts.operations('shop-api');
    expect(ops.find((o) => o.op === 'GET /orders/{id}')?.fewSamples).toBe(true);
    expect(ops.find((o) => o.op === 'POST /orders')?.fewSamples).toBe(false); // a field-level gap only
    const denied = make(on('GET', '/api/v1/services', json(SERVICES)), on('GET', '/api/v1/contracts/shop-api', json(SHOP_DOC)), on('GET', '/api/v1/gaps', err(403, 'forbidden')));
    expect((await denied.api.contracts.operations('shop-api')).find((o) => o.op === 'GET /orders/{id}')?.fewSamples).toBe(true); // 5 calls < 20
  });
});

// ---------------------------------------------------------------- rules, drift, webhooks

const RULE = {
  id: 'r-0001',
  kind: 'causal',
  status: 'draft',
  title: 'Order created, shipment follows',
  cause: { service: 'shop-api', op: 'POST /orders', when: { status: [201] }, bind: { order: { from: 'resp.body', path: '$.id' } } },
  effects: [
    { id: 'shipment-created', entity: 'shipment', create: { orderId: '${order}', status: 'CREATED' }, after: '5m' },
    { id: 'shipment-delivered', entity: 'shipment', target: 'shipment', set: { status: 'DELIVERED' }, after_effect: 'shipment-created', after: { min: '1h', max: '2d' } },
  ],
  outcomes: [
    { name: 'happy', p: 0.9, effects: ['shipment-created', 'shipment-delivered'] },
    { name: 'cancelled', p: 0.1, effects: ['shipment-created'] },
  ],
  evidence: { counts: { causes: 100, distinct_subjects: 80, outcomes: { happy: 90, cancelled: 10 }, key_matches: 95 }, hints: { magnitude: { 'shipment-created': 'minutes' } } },
};

describe('rules', () => {
  it('maps a causal rule', async () => {
    const { api } = make(on('GET', '/api/v1/rules', json([RULE])));
    const [r] = await api.rules.list();
    expect(r).toMatchObject({
      id: 'r-0001',
      kind: 'causal',
      status: 'draft',
      cause: { service: 'shop-api', op: 'POST /orders', whenStatus: [201], bind: { order: 'resp.body $.id' } },
      counts: { causes: 100, distinctSubjects: 80, keyMatches: 95 },
      review: { by: [], at: null, note: '' },
    });
    expect(r.effects[0]).toMatchObject({ kind: 'create', values: { orderId: '${order}', status: 'CREATED' }, after: '5m', magnitude: 'minutes' });
    expect(r.effects[1]).toMatchObject({ kind: 'set', afterEffect: 'shipment-created', after: '1h–2d' });
    expect(r.outcomes).toEqual([
      { name: 'happy', p: 0.9, effects: ['shipment-created', 'shipment-delivered'], count: 90 },
      { name: 'cancelled', p: 0.1, effects: ['shipment-created'], count: 10 },
    ]);
  });
  it('maps a batch rule', async () => {
    const { api } = make(on('GET', '/api/v1/rules/r-0002', json({ id: 'r-0002', kind: 'batch', status: 'approved', title: 't', schedule: '0 3 * * *', entity: 'order', where: { status: 'PAID' }, set: { status: 'ARCHIVED' }, fraction: 0.5, evidence: { counts: { runs: 12, entities_changed: 300 }, hints: { schedule_confidence: 'high' } }, review: { by: ['usr_9'], at: '2026-10-22T00:00:00Z', note: 'ok' } })));
    expect(await api.rules.get('r-0002')).toMatchObject({ kind: 'batch', batch: { schedule: '0 3 * * *', entity: 'order', where: { status: 'PAID' }, set: { status: 'ARCHIVED' }, fraction: 0.5, runs: 12, entitiesChanged: 300 }, hints: { scheduleConfidence: 'high' }, review: { by: ['usr_9'], note: 'ok' } });
  });
  it('edits a delay with PATCH and returns the (possibly new) draft', async () => {
    const { api, calls } = make(loggedIn, on('PATCH', '/api/v1/rules/r-0001', json({ ...RULE, id: 'r-0004' })));
    const r = await api.rules.setAfter('r-0001', 'shipment-created', '10m');
    expect(r.id).toBe('r-0004');
    expect(body(calls.at(-1) as Recorded)).toEqual({ after: { 'shipment-created': '10m' } });
  });
  it('edits a delay as a range: "1h–2d" travels as {min, max}', async () => {
    const { api, calls } = make(loggedIn, on('PATCH', '/api/v1/rules/r-0001', json(RULE)));
    await api.rules.setAfter('r-0001', 'shipment-delivered', '1h–2d');
    await api.rules.setAfter('r-0001', 'shipment-delivered', '2m - 10m');
    await api.rules.setAfter('r-0001', 'shipment-delivered', ' 90s ');
    const sent = calls.filter((c) => c.method === 'PATCH').map((c) => body(c).after);
    expect(sent).toEqual([{ 'shipment-delivered': { min: '1h', max: '2d' } }, { 'shipment-delivered': { min: '2m', max: '10m' } }, { 'shipment-delivered': '90s' }]);
  });
  it('shows when the miner proposed a rule', async () => {
    const { api } = make(on('GET', '/api/v1/rules', json([{ ...RULE, proposed_at: '2026-10-22T03:00:00Z' }, { ...RULE, id: 'r-0002' }])));
    const [a, b] = await api.rules.list();
    expect(a.proposedAt).toBe('2026-10-22T03:00:00Z');
    expect(b.proposedAt).toBeUndefined();
  });
  it('approve and confirm both approve; reject and retire both reject, with the note', async () => {
    const { api, calls } = make(loggedIn, on('POST', /\/(approve|reject)$/, json(RULE)));
    await api.rules.review('r-0001', 'approve', 'ignored');
    await api.rules.review('r-0001', 'confirm', '');
    await api.rules.review('r-0001', 'reject', ' too weak ');
    await api.rules.review('r-0001', 'retire', '');
    const w = calls.filter((c) => c.path.startsWith('/api/v1/rules/'));
    expect(w.map((c) => c.path.split('/').pop())).toEqual(['approve', 'approve', 'reject', 'reject']);
    expect(w[0].body).toBeUndefined();
    expect(body(w[2])).toEqual({ note: 'too weak' });
    expect(w[3].body).toBeUndefined();
  });
  it('a conflict (rule not in a reviewable state) keeps the server code', async () => {
    const { api } = make(loggedIn, on('POST', /approve$/, err(409, 'rule_state')));
    expect(await api.rules.review('r-0001', 'approve', '').catch((e: unknown) => e)).toMatchObject({ code: 'conflict', serverCode: 'rule_state' });
  });
});

describe('alerts and webhooks', () => {
  const ALERT = (id: string, over = {}) => ({ drift_id: id, kind: 'contract.drift', service: 'shop-api', op: 'POST /orders', severity: 'breaking', change: 'c', first_seen: '2026-10-22T03:00:00Z', evidence: { calls_after_change: 1840 }, state: 'open', ...over });
  it('lists contract drift and stale rules in one call, newest first, with the type the server reports', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/drift', json([ALERT('dr-00000001'), ALERT('dr-00000002', { state: 'acknowledged', severity: 'non-breaking' }), ALERT('dr-00000003', { kind: 'rule.stale', severity: 'info', first_seen: '2026-10-23T00:00:00Z' })])),
    );
    const list = await api.alerts.list();
    expect(calls).toHaveLength(1);
    expect(calls[0].query.get('kind')).toBe('all');
    expect(list.map((a) => [a.id, a.type, a.severity, a.state])).toEqual([
      ['dr-00000003', 'rule.stale', 'info', 'open'],
      ['dr-00000001', 'contract.drift', 'breaking', 'open'],
      ['dr-00000002', 'contract.drift', 'non-breaking', 'acknowledged'],
    ]);
    expect(list[1]).toMatchObject({ callsAfterChange: 1840, service: 'shop-api', op: 'POST /orders' });
  });
  it('acknowledges and resolves with PATCH; going back is a conflict', async () => {
    const { api, calls } = make(loggedIn, on('PATCH', '/api/v1/drift/dr-00000001', (r) => (body(r).state === 'open' ? err(409, 'invalid_transition') : json(ALERT('dr-00000001', { state: body(r).state })))), on('PATCH', '/api/v1/drift/dr-00000002', err(409, 'invalid_transition')));
    await api.alerts.setState('dr-00000001', 'acknowledged');
    await api.alerts.setState('dr-00000001', 'resolved');
    expect(calls.filter((c) => c.method === 'PATCH').map((c) => body(c))).toEqual([{ state: 'acknowledged' }, { state: 'resolved' }]);
    expect(await api.alerts.setState('dr-00000002', 'acknowledged').catch((e: unknown) => e)).toMatchObject({ code: 'conflict', serverCode: 'invalid_transition' });
    expect(await code(api.alerts.setState('dr-00000001', 'open'))).toBe('invalid');
    expect(api.capabilities.alertResolve).toBe(true);
  });
  it('lists webhooks with the last delivery', async () => {
    const { api } = make(
      on('GET', '/api/v1/webhooks', json([{ webhook_id: 'wh-00000001', name: 'ops', url: 'https://hooks.example/x', events: ['contract.drift', 'pack.published'], enabled: true, secret_set: true }, { webhook_id: 'wh-00000002', name: 'off', url: 'https://hooks.example/y', events: [], enabled: false, secret_set: true }])),
      on('GET', '/api/v1/webhooks/wh-00000002/deliveries', json([])),
      on('GET', '/api/v1/webhooks/wh-00000001/deliveries', json([{ delivery_id: 5, webhook_id: 'wh-00000001', event: 'contract.drift', state: 'failed', attempts: 3, last_status: 502, created_at: '2026-10-23T00:00:00Z' }])),
    );
    expect(await api.webhooks.list()).toEqual([
      { id: 'wh-00000001', name: 'ops', url: 'https://hooks.example/x', events: ['contract.drift', 'pack.published'], enabled: true, secretSet: true, secret: undefined, lastDelivery: { at: '2026-10-23T00:00:00Z', ok: false, httpStatus: 502 } },
      { id: 'wh-00000002', name: 'off', url: 'https://hooks.example/y', events: [], enabled: false, secretSet: true, secret: undefined, lastDelivery: undefined },
    ]);
  });
  it('creating returns the generated secret once; updating sends name, url, events and the switch', async () => {
    const { api, calls } = make(
      loggedIn,
      on('POST', '/api/v1/webhooks', json({ webhook_id: 'wh-00000002', name: 'n', url: 'https://h.example', events: ['rule.stale'], secret_set: true, secret: 'whsec_123' }, 201)),
      on('PUT', '/api/v1/webhooks/wh-00000002', json({ webhook_id: 'wh-00000002', name: 'n2', url: 'https://h.example', events: ['rule.stale'], secret_set: true })),
    );
    const created = await api.webhooks.save({ name: 'n', url: 'https://h.example', events: ['rule.stale'], enabled: true });
    expect(created.secret).toBe('whsec_123');
    const updated = await api.webhooks.save({ id: 'wh-00000002', name: 'n2', url: 'https://h.example', events: ['rule.stale'], enabled: true, secretSet: true });
    expect(updated.secret).toBeUndefined();
    expect(body(calls.filter((c) => c.method === 'PUT')[0])).toEqual({ name: 'n2', url: 'https://h.example', events: ['rule.stale'], enabled: true });
  });
  it('switching a webhook off keeps everything else and is sent as enabled=false', async () => {
    const { api, calls } = make(loggedIn, on('PUT', '/api/v1/webhooks/wh-00000002', json({ webhook_id: 'wh-00000002', name: 'n', url: 'https://h.example', events: ['rule.stale'], enabled: false, secret_set: true })));
    const w = await api.webhooks.save({ id: 'wh-00000002', name: 'n', url: 'https://h.example', events: ['rule.stale'], enabled: false });
    expect(w.enabled).toBe(false);
    expect(body(calls.filter((c) => c.method === 'PUT')[0]).enabled).toBe(false);
    expect(api.capabilities.webhookToggle).toBe(true);
  });
  it('a test that the destination refuses is reported as a failed delivery, not as an error', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/webhooks', json([{ webhook_id: 'wh-00000001', name: 'ops', url: 'https://h.example', events: [], secret_set: true }])), on('POST', '/api/v1/webhooks/wh-00000001/test', err(502, 'delivery_failed')));
    expect((await api.webhooks.test('wh-00000001')).lastDelivery).toMatchObject({ ok: false, httpStatus: 502 });
  });
  it('a test that works is reported as delivered', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/webhooks', json([{ webhook_id: 'wh-00000001', name: 'ops', url: 'https://h.example', events: [], secret_set: true }])), on('POST', '/api/v1/webhooks/wh-00000001/test', json(null, 204)));
    expect((await api.webhooks.test('wh-00000001')).lastDelivery).toMatchObject({ ok: true, httpStatus: 204 });
  });
});

// ---------------------------------------------------------------- worlds, archetypes

describe('archetypes and worlds', () => {
  it('maps archetypes with the k the server built them with', async () => {
    const { api } = make(on('GET', '/api/v1/archetypes', json({ k_min: 20, built: true, profiles: 90, dropped_subjects: 12, archetypes: [{ id: 'arch-01', label: 'Frequent', size: 55, features: { orders_per_month: '5-10', active_hours: 'evening', error_rate: 'low', primary_op: 'POST /orders', outcomes_mix: { 'r-0001/happy': 0.9 } } }, { id: 'arch-02', label: 'Rare', size: 23, features: { orders_per_month: '0-1', active_hours: 'day', error_rate: 'low', primary_op: 'GET /orders' } }] })));
    const set = await api.archetypes.get();
    expect(set.kMin).toBe(20); // not the smallest group (23)
    expect(set.archetypes[0]).toMatchObject({ id: 'arch-01', size: 55, belowK: false, features: { ordersPerMonth: '5-10', activeHours: 'evening', outcomesMix: { 'r-0001/happy': 0.9 } } });
    expect(set.archetypes[1].features.outcomesMix).toEqual({});
  });
  const WORLD = { world_id: 'w-0001', seed: 42, customers: 200, archetypes_used: true, rules: ['r-0001'], created_at: '2026-10-20T00:00:00Z', t0: 'x', locale: 'it', entities: 640, history: 1, pending: 0, sha256: 'abc' };
  it('lists and generates worlds (the job carries the result)', async () => {
    const { api, calls } = make(loggedIn, on('GET', '/api/v1/worlds', json([WORLD])), on('POST', '/api/v1/worlds', json({ job_id: 'job_1', kind: 'world.generate', status: 'done', result: { ...WORLD, world_id: 'w-0002', seed: 7 } }, 202)));
    expect((await api.worlds.list())[0]).toMatchObject({ id: 'w-0001', seed: 42, customers: 200, entities: 640, createdAt: '2026-10-20T00:00:00Z' });
    const w = await api.worlds.generate({ seed: 7, customers: 10 });
    expect(w.id).toBe('w-0002');
    expect(body(calls.at(-1) as Recorded)).toEqual({ seed: 7, customers: 10 });
  });
  it('builds the archetypes with the configured k when the first world has none, then generates again', async () => {
    let tries = 0;
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/archetypes', json({ k_min: 20, built: false, archetypes: [] })),
      on('POST', '/api/v1/archetypes/build', json({ job_id: 'j1', kind: 'archetypes.build', status: 'done', result: {} }, 202)),
      on('POST', '/api/v1/worlds', () => (tries++ === 0 ? err(409, 'no_archetypes') : json({ job_id: 'j2', kind: 'world.generate', status: 'done', result: { ...WORLD, world_id: 'w-0003' } }, 202))),
    );
    expect((await api.worlds.generate({ seed: 42, customers: 100 })).id).toBe('w-0003');
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.path)).toEqual(['/api/v1/worlds', '/api/v1/archetypes/build', '/api/v1/worlds']);
    expect(body(calls.find((c) => c.path === '/api/v1/archetypes/build') as Recorded)).toEqual({ k_min: 20 });
  });
  it('a failed job is an error', async () => {
    const { api } = make(loggedIn, on('POST', '/api/v1/worlds', json({ job_id: 'j', kind: 'k', status: 'failed', error: 'boom' }, 202)));
    expect(await code(api.worlds.generate({ seed: 1, customers: 1 }))).toBe('server');
  });
  it('draws a customer from the preview lines of world.jsonl', async () => {
    const lines = [
      { type: 'customer', id: 'CUS-SYN-0004', archetype: 'arch-01' },
      { type: 'entity', entity: 'order', id: 'ORD-SYN-0042', customer_id: 'CUS-SYN-0004', state: { status: 'CONFIRMED', shipmentId: 'SHP-SYN-0091' } },
      { type: 'entity', entity: 'shipment', id: 'SHP-SYN-0091', customer_id: 'CUS-SYN-0004', state: { status: 'IN_TRANSIT', orderId: 'ORD-SYN-0042' } },
      { type: 'history', entity: 'shipment', id: 'SHP-SYN-0091', rule_id: 'r-0007', seq: 1 },
    ];
    const { api, calls } = make(on('GET', '/api/v1/worlds/w-0001/customers/CUS-SYN-0004', json({ world_id: 'w-0001', customer: 'CUS-SYN-0004', lines })));
    const g = await api.worlds.graph('w-0001', 3);
    expect(calls[0].path).toBe('/api/v1/worlds/w-0001/customers/CUS-SYN-0004');
    expect(g).toMatchObject({ customerId: 'CUS-SYN-0004', archetype: 'arch-01' });
    expect(g.nodes.map((n) => [n.id, n.type, n.state])).toEqual([
      ['CUS-SYN-0004', 'customer', 'arch-01'],
      ['ORD-SYN-0042', 'order', 'CONFIRMED'],
      ['SHP-SYN-0091', 'shipment', 'IN_TRANSIT'],
    ]);
    // customer -> order -> shipment, whichever side holds the reference
    expect(g.edges).toEqual(expect.arrayContaining([{ from: 'CUS-SYN-0004', to: 'ORD-SYN-0042' }, { from: 'ORD-SYN-0042', to: 'SHP-SYN-0091', rule: 'r-0007' }]));
    expect(g.edges).toHaveLength(2);
  });
});

// ---------------------------------------------------------------- packs

const GATE = {
  format: 'tt.gate-report/v1',
  pack_id: 'pk-1',
  verdict: 'pass',
  k_min: 20,
  checks: [
    { id: 'provenance', status: 'pass', findings: [], by: 'tt-core' },
    { id: 'reverse-hmac', status: 'pass', findings: [], strings_checked: 48211, by: 'tt-core' },
    { id: 'pii-detectors', status: 'pass', findings: [], by: 'tt-core' },
    { id: 'k-thresholds', status: 'pass', findings: [], by: 'tt-core' },
  ],
};
const PACK = (over: Record<string, unknown> = {}) => ({
  pack_id: 'pk-1',
  status: 'signed',
  created_at: '2026-10-24T09:00:00Z',
  world_id: 'w-0001',
  published_at: null,
  manifest: { format: 'tt.pack/v1', pack_id: 'pk-1', created_at: '2026-10-24T09:00:00Z', not_after: '2027-01-24T09:00:00Z', tt_version: '0.1.0', seed: 42, k_min: 20, rules: { path: 'rules.json', approved: ['r-0001'] }, files: [{ path: 'world.jsonl', sha256: 'aa', bytes: 100 }] },
  gate_report: GATE,
  residual_risk: { note: 'n', profiles: 300, archetypes: 5, min_archetype_size: 23, suppressed_subjects: 4, uniqueness_rate: 0.1, singling_out_rate: 0, exact_match_share: 0.2, max_homogeneity: 0.5 },
  ...over,
});

describe('packs', () => {
  it('maps a signed pack: verdict, checks, manifest data and residual risk', async () => {
    const { api } = make(on('GET', '/api/v1/packs/pk-1', json(PACK())));
    const p = await api.publications.get('pk-1');
    expect(p).toMatchObject({
      id: 'pk-1',
      packId: 'pk-1',
      status: 'signed',
      verdict: 'pass',
      worldId: 'w-0001',
      seed: 42,
      kMin: 20,
      notAfter: '2027-01-24T09:00:00Z',
      rulesApproved: ['r-0001'],
      files: [{ path: 'world.jsonl', bytes: 100, sha256: 'aa' }],
    });
    expect(p.checks.map((c) => c.id)).toEqual(['provenance', 'reverse-hmac', 'pii-detectors', 'k-thresholds']);
    expect(p.checks[1].stringsChecked).toBe(48211);
    expect(p.residualRisk).toMatchObject({ minArchetypeSize: 23, suppressedSubjects: 4, uniquenessRate: 0.1 });
    expect(p.publishedAt).toBeUndefined();
  });
  it('keeps the rules-approved warning of a pack without approved rules: it passes, with a warning', async () => {
    const warn = { id: 'rules-approved', status: 'warn', findings: [{ file: 'rules.json', pointer: '/rules', reason: 'no approved rules' }], by: 'tt-core' };
    const { api } = make(on('GET', '/api/v1/packs/pk-1', json(PACK({ gate_report: { ...GATE, checks: [...GATE.checks, warn] } }))));
    const p = await api.publications.get('pk-1');
    expect(p.verdict).toBe('pass');
    expect(p.checks.at(-1)).toMatchObject({ id: 'rules-approved', status: 'warn' });
  });
  it('maps a pack the gate refused, with findings that carry a location and never a value', async () => {
    const failed = PACK({ status: 'gate-failed', manifest: undefined, gate_report: { ...GATE, verdict: 'fail', checks: [GATE.checks[0], { id: 'reverse-hmac', status: 'fail', findings: [{ file: 'world.jsonl', pointer: 'line 113 /profile/name', reason: 'matches a known token' }], by: 'tt-core' }, { id: 'pii-detectors', status: 'skipped', findings: [], by: 'x' }, { id: 'k-thresholds', status: 'skipped', findings: [], by: 'x' }] } });
    const { api } = make(on('GET', '/api/v1/packs', json([PACK({ pack_id: 'pk-0', created_at: '2026-10-01T00:00:00Z' }), failed])));
    const list = await api.publications.list();
    expect(list.map((p) => p.id)).toEqual(['pk-1', 'pk-0']); // newest first
    expect(list[0]).toMatchObject({ status: 'gate-failed', verdict: 'fail', kMin: 20, signedBy: undefined });
    expect(list[0].checks.map((c) => c.status)).toEqual(['pass', 'fail', 'skipped', 'skipped']);
    expect(Object.keys(list[0].checks[1].findings[0]).sort()).toEqual(['file', 'pointer', 'reason']);
  });
  it('building sends the world and the validity only: the services to twin are the server\'s stored selection', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/packs', json({ job_id: 'j', kind: 'pack.build', status: 'done', result: PACK() }, 202)));
    await api.publications.run('w-0001', { validDays: 90 });
    expect(body(calls.at(-1) as Recorded)).toEqual({ world_id: 'w-0001', valid_days: 90 });
    await api.publications.run('w-0001');
    expect(body(calls.at(-1) as Recorded)).toEqual({ world_id: 'w-0001' });
    expect(calls.some((c) => c.path === '/api/v1/services')).toBe(false);
  });
  it('the twin choice is stored by the server and shown by the service list', async () => {
    let stored = true;
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/services', () => json(SERVICES.map((s) => (s.service === 'host:api.carrier.example' ? { ...s, twin: stored } : s)))),
      on('GET', '/api/v1/fleet/sources', json([SRC])),
      on('PUT', '/api/v1/services/host%3Aapi.carrier.example/twin', (r) => {
        stored = body(r).twin === true;
        return json({ service: 'host:api.carrier.example', twin: stored });
      }),
    );
    expect((await api.services.list()).map((s) => [s.name, s.twin, s.sources])).toEqual([
      ['shop-api', true, 1],
      ['host:api.carrier.example', true, 0],
    ]);
    await api.services.setTwin('host:api.carrier.example', false);
    expect(body(calls.filter((c) => c.method === 'PUT')[0])).toEqual({ twin: false });
    expect((await api.services.list())[1].twin).toBe(false);
    expect(api.capabilities.twinOnServer).toBe(true);
  });
  it('releasing sends no body, or the reason of an administrator', async () => {
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/packs/pk-1/publish', json(PACK({ status: 'published', published_at: '2026-10-24T09:30:00Z' }))));
    const p = await api.publications.publish('pk-1');
    expect(p).toMatchObject({ status: 'published', publishedAt: '2026-10-24T09:30:00Z' });
    expect(calls.at(-1)?.body).toBeUndefined();
    await api.publications.publish('pk-1', { reason: ' incident ' });
    expect(body(calls.at(-1) as Recorded)).toEqual({ reason: 'incident' });
  });
  it('an admin without a reason is refused by the server and the code says why', async () => {
    const { api } = make(loggedIn, on('POST', '/api/v1/packs/pk-1/publish', err(403, 'admin_reason_required')));
    expect(await api.publications.publish('pk-1').catch((e: unknown) => e)).toMatchObject({ code: 'forbidden', serverCode: 'admin_reason_required' });
  });
  it('downloads the archive with the file name of the server', async () => {
    const { api } = make(on('GET', '/api/v1/packs/pk-1/download', new Response('GZ', { status: 200, headers: { 'Content-Type': 'application/gzip', 'Content-Disposition': 'attachment; filename="pk-1.ttpack"' } })));
    const { filename, blob } = await api.publications.download('pk-1');
    expect(filename).toBe('pk-1.ttpack');
    expect(await blob.text()).toBe('GZ');
  });
  it('export: not served yet means "unsupported", served means polling until done', async () => {
    const a = make(loggedIn, on('POST', '/api/v1/exports', err(404, 'not_found')));
    expect(await code(a.api.publications.export('pk-1', 'prism'))).toBe('unsupported');
    let n = 0;
    const b = make(
      loggedIn,
      on('POST', '/api/v1/exports', json({ job_id: 'j', kind: 'export', status: 'running', export_id: 'ex-1' }, 202)),
      on('GET', '/api/v1/exports/ex-1', () =>
        ++n < 2
          ? json({ export_id: 'ex-1', status: 'running' })
          : json({ export_id: 'ex-1', status: 'done', report: { exported: [{ kind: 'operation', element: 'GET /x', count: 3 }], losses: [{ kind: 'clock', element: 'virtual clock', detail: 'not supported', count: 1 }], files: [{ path: 'openapi/shop.json', kind: 'contract' }] } }),
      ),
    );
    const rep = await b.api.publications.export('pk-1', 'prism');
    expect(rep).toEqual({ exportId: 'ex-1', target: 'prism', produced: [{ path: 'openapi/shop.json', description: 'contract' }], preserved: ['GET /x (operation) × 3'], lost: [{ item: 'virtual clock (clock) × 1', reason: 'not supported' }] });
  }, 10000);
});

// ---------------------------------------------------------------- audit, users, scenarios

const AUDIT = (seq: number) => ({ seq, ts: `2026-10-24T09:${String(seq % 60).padStart(2, '0')}:00Z`, actor: { kind: 'user', id: 'usr_1', name: 'Olga' }, action: 'policy.approve', target: { type: 'policy', id: 'p-shop' }, outcome: seq % 2 ? 'success' : 'denied', prev_hash: 'p'.repeat(64), hash: 'h'.repeat(64) });

describe('audit', () => {
  it('reads the NDJSON export, newest first, and maps outcomes', async () => {
    const nd = [AUDIT(1), AUDIT(2), { ...AUDIT(3), outcome: 'failure' }].map((e) => JSON.stringify(e)).join('\n') + '\n';
    const { api, calls } = make(on('GET', '/api/v1/audit/export', text(nd, 200, 'application/x-ndjson')));
    const list = await api.audit.list();
    expect(list.map((e) => [e.seq, e.result])).toEqual([
      [3, 'error'],
      [2, 'denied'],
      [1, 'ok'],
    ]);
    expect(list[2]).toMatchObject({ actor: 'Olga', action: 'policy.approve', target: 'policy:p-shop', at: '2026-10-24T09:01:00Z' });
    expect(calls[0].headers.accept).toBe('application/x-ndjson');
  });
  it('reads a long log from its end in one call: the newest 500, not a walk from the first entry', async () => {
    const tail = Array.from({ length: 500 }, (_, i) => JSON.stringify(AUDIT(1521 + i))).join('\n');
    const { api, calls } = make(on('GET', '/api/v1/audit/export', (r) => (r.query.get('last') === '500' && !r.query.has('after_seq') ? text(tail, 200, 'application/x-ndjson') : err(400, 'invalid_query'))));
    const list = await api.audit.list();
    expect(calls).toHaveLength(1);
    expect(list).toHaveLength(500);
    expect(list[0].seq).toBe(2020);
    expect(list.at(-1)?.seq).toBe(1521);
  });
  it('ignores a truncated last line', async () => {
    const { api } = make(on('GET', '/api/v1/audit/export', text(JSON.stringify(AUDIT(1)) + '\n{"seq":2,"ts"', 200)));
    expect((await api.audit.list()).map((e) => e.seq)).toEqual([1]);
  });
  it('verify maps the chain head and a break', async () => {
    const { api } = make(on('GET', '/api/v1/audit/verify', json({ ok: false, entries: 12, head_seq: 12, head_hash: 'abc', error: 'chain broken at seq 7' })));
    expect(await api.audit.verify()).toEqual({ ok: false, entries: 12, headHash: 'abc', verifiedAt: '2026-10-24T09:30:00.000Z', error: 'chain broken at seq 7' });
  });
  it('a user without the auditor role gets 403', async () => {
    const { api } = make(on('GET', '/api/v1/audit/export', err(403, 'forbidden')));
    expect(await code(api.audit.list())).toBe('forbidden');
  });
});

describe('endpoints the server does not serve yet', () => {
  it('users: unsupported on a 404, and the roles come from the local model', async () => {
    const { api } = make(on('GET', '/api/v1/users', err(404, 'not_found')));
    expect(await code(api.users.list())).toBe('unsupported');
    expect((await api.users.roles()).map((r) => r.role)).toEqual(['admin', 'operator', 'rule-reviewer', 'policy-approver', 'publisher', 'auditor', 'event-exporter']);
  });
  it('users: create and update follow the spec', async () => {
    const U = { id: 'usr_2', username: 'new', display_name: 'New', auth_method: 'local', roles: ['auditor'] };
    const { api, calls } = make(loggedIn, on('POST', '/api/v1/users', json(U, 201)), on('PATCH', '/api/v1/users/usr_2', json({ ...U, roles: ['operator'], disabled: true })));
    const u = await api.users.create({ username: 'new', displayName: 'New', roles: ['auditor'], authMethod: 'local', password: 'a-long-password' });
    expect(u).toMatchObject({ id: 'usr_2', roles: ['auditor'] });
    expect(body(calls.at(-1) as Recorded)).toEqual({ username: 'new', display_name: 'New', roles: ['auditor'], password: 'a-long-password' });
    expect(await api.users.update('usr_2', { roles: ['operator'], disabled: true })).toMatchObject({ roles: ['operator'], disabled: true });
  });
  it('scenario presets: unsupported on a 404; a served list maps faults and forced outcomes', async () => {
    const a = make(on('GET', '/api/v1/scenario-presets', err(404, 'not_found')));
    expect(await code(a.api.scenarios.list())).toBe('unsupported');
    const b = make(on('GET', '/api/v1/scenario-presets', json([{ preset_id: 'carrier-down', name: 'Carrier down', faults: { mode: 'custom', rules: [{ service: 'host:api.carrier.example', op: 'GET /v1/shipments', status: 503, p: 1 }] }, outcomes: [{ rule: 'r-0001', outcome: 'cancelled' }] }])));
    expect((await b.api.scenarios.list())[0]).toMatchObject({ id: 'carrier-down', faults: [{ service: 'host:api.carrier.example', op: 'GET /v1/shipments', status: 503, p: 1 }], forcedOutcomes: [{ rule: 'r-0001', outcome: 'cancelled' }], deterministic: true });
  });
});

// A real wiring check: the production adapter never touches anything but same-origin /api/v1 paths.
describe('requests', () => {
  it('only call /api/v1', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', /.*/, json([])),
    );
    await Promise.all([api.sources.list(), api.rules.list(), api.gaps.list(), api.publications.list(), api.worlds.list()]).catch(() => undefined);
    expect(calls.length).toBeGreaterThan(4);
    for (const c of calls) expect(c.path.startsWith('/api/v1/')).toBe(true);
  });
  it('is typed as the whole contract', () => {
    const { api } = make();
    const a: Api = api;
    expect(Object.keys(a).sort()).toEqual(['alerts', 'archetypes', 'audit', 'auth', 'capabilities', 'contracts', 'dateOffsets', 'events', 'fleet', 'gaps', 'gate', 'hosts', 'idFormats', 'keyguard', 'mocks', 'onboarding', 'opKinds', 'policies', 'publications', 'quarantine', 'rules', 'scenarios', 'scope', 'services', 'settings', 'sources', 'store', 'system', 'users', 'webhooks', 'worlds']);
    expect(a.demo).toBeUndefined();
  });
});

// ---------------------------------------------------------------- the composed tt-core (internal/core)

describe('quarantine, retention, keyguard, events, mining', () => {
  const Q = { item_id: 'q-3', kind: 'keep-value', service: 'shop-api', op: 'GET /orders/{id}', where: 'resp.body $.status', distinct_estimate: 80, state: 'dismiss-pending', since: '2026-10-24T08:00:00Z', approvals: [{ by: 'pia', at: '2026-10-24T09:00:00Z' }] };
  it('lists the quarantine and resolves with close or dismiss', async () => {
    const { api, calls } = make(loggedIn, on('GET', '/api/v1/quarantine', json([Q, { ...Q, item_id: 'q-4', state: 'weird', approvals: undefined }])), on('POST', '/api/v1/quarantine/q-3/resolve', json({ ...Q, state: 'resolved' })));
    const list = await api.quarantine.list();
    expect(list[0]).toEqual({ id: 'q-3', kind: 'keep-value', service: 'shop-api', op: 'GET /orders/{id}', where: 'resp.body $.status', distinctEstimate: 80, state: 'dismiss-pending', since: '2026-10-24T08:00:00Z', approvals: [{ by: 'pia', at: '2026-10-24T09:00:00Z' }] });
    expect(list[1]).toMatchObject({ state: 'quarantined', approvals: [] });
    expect((await api.quarantine.resolve('q-3', 'dismiss', ' ok ')).state).toBe('resolved');
    expect(body(calls.at(-1) as Recorded)).toEqual({ resolution: 'dismiss', note: 'ok' });
  });
  it('a second approval by the same person is a conflict the UI can show', async () => {
    const { api } = make(loggedIn, on('POST', /resolve$/, err(409, 'duplicate_approval')));
    expect(await api.quarantine.resolve('q-3', 'dismiss').catch((e: unknown) => e)).toMatchObject({ code: 'conflict', serverCode: 'duplicate_approval' });
  });
  it('retention: read, change, purge', async () => {
    const { api, calls } = make(
      loggedIn,
      on('GET', '/api/v1/store/retention', json({ events_days: 30, aggregates_days: 400 })),
      on('PUT', '/api/v1/store/retention', json({ events_days: 60, aggregates_days: 400 })),
      on('POST', '/api/v1/store/purge', json({ job_id: 'job_1', kind: 'store.purge', status: 'done', result: { events: 12, tokens: 3 } }, 202)),
    );
    expect(await api.store.retention()).toEqual({ eventsDays: 30, aggregatesDays: 400 });
    expect(await api.store.setRetention(60)).toEqual({ eventsDays: 60, aggregatesDays: 400 });
    expect(body(calls.at(-1) as Recorded)).toEqual({ events_days: 60 });
    expect(await api.store.purge('2026-10-01T00:00:00.000Z')).toEqual({ events: 12, tokens: 3 });
    expect(body(calls.at(-1) as Recorded)).toEqual({ before: '2026-10-01T00:00:00.000Z' });
  });
  it('storage usage and the maintenance job', async () => {
    const { api } = make(
      loggedIn,
      on('GET', '/api/v1/store/usage', json({
        db: { file: 'tt-core.db', file_bytes: 100, wal_bytes: 10, free_bytes: 5, used_bytes: 105, max_bytes: 200, used_pct: 52.5, high_watermark_pct: 80, critical_watermark_pct: 90, level: 'ok', auto_vacuum: 'incremental' },
        datasets: [{ name: 'events', bytes: 80, over_quota: false, policy: { code: 'raw_events', params: { days: 7 } }, last_run: { name: 'events', outcome: { deleted: 12 }, duration_ms: 3 } }, { name: 'audit', bytes: 4, file_bytes: 9, over_quota: false, policy: { code: 'audit_forever' } }],
        last_run: { trigger: 'schedule', started_at: 'a', finished_at: 'b', deleted: 12, reclaimed_bytes: 4096, errors: 0, shed: [{ name: 'events_beyond_miner_window' }] },
        next_run: '0001-01-01T00:00:00Z', running: false, interval_seconds: 3600, rollups: [{ tier: 'hour', rows: 3, oldest: '2026-10-01T00:00:00Z' }],
      })),
      on('POST', '/api/v1/store/maintenance', json({ job_id: 'job_m', kind: 'store.maintenance', status: 'done', result: { deleted: 7, reclaimed_bytes: 8192, level: 'high' } }, 202)),
    );
    const u = await api.store.usage();
    expect(u.db).toMatchObject({ usedBytes: 105, maxBytes: 200, highPct: 80, criticalPct: 90, level: 'ok', autoVacuum: 'incremental' });
    expect(u.datasets[0]).toEqual({ name: 'events', bytes: 80, fileBytes: 0, quotaBytes: undefined, overQuota: false, policy: { code: 'raw_events', params: { days: 7 } }, lastRun: { deleted: 12, error: undefined, durationMs: 3 } });
    expect(u.datasets[1]).toMatchObject({ fileBytes: 9, policy: { code: 'audit_forever', params: {} }, lastRun: undefined });
    expect(u.lastRun).toMatchObject({ reclaimedBytes: 4096, shed: ['events_beyond_miner_window'] });
    expect(u.nextRun).toBeUndefined();
    expect(await api.store.maintenance()).toEqual({ deleted: 7, reclaimedBytes: 8192, level: 'high' });
  });
  it('keyguard status and audit (newest first)', async () => {
    const { api } = make(
      on('GET', '/api/v1/keyguard/status', json({ reachable: true, hmac_kids: ['k1'], epochs: ['2026-10'], approvals_unverified: true, match_budget_left: 5, policy_kid: 'p1', pack_kid: 'g1', revoked_kids: [], opening_approvals: 2, admin_override: true, transport: 'unix' })),
      on('GET', '/api/v1/keyguard/audit', json([{ seq: 1, at: 'a', op: 'startup', outcome: 'success', hash: 'h' }, { seq: 2, at: 'b', op: 'policy.sign', outcome: 'success', detail: { v: '1' }, hash: 'h2' }])),
    );
    expect(await api.keyguard.status()).toMatchObject({ reachable: true, hmacKids: ['k1'], epochs: ['2026-10'], policyKid: 'p1', packKid: 'g1', openingApprovals: 2, adminOverride: true, transport: 'unix', matchBudgetLeft: 5 });
    expect((await api.keyguard.audit()).map((e) => e.seq)).toEqual([2, 1]);
  });
  it('an unreachable keyguard is reported, not thrown', async () => {
    const { api } = make(on('GET', '/api/v1/keyguard/status', json({ reachable: false })));
    expect(await api.keyguard.status()).toMatchObject({ reachable: false, hmacKids: [], openingApprovals: 2 });
  });
  it('event export: asks for the format, downloads with the server file name', async () => {
    const { api, calls } = make(
      loggedIn,
      on('POST', '/api/v1/events/export', json({ job_id: 'job_9', kind: 'events.export', status: 'done', result: { format: 'jsonl', bytes: 123, events: 4, notice: 'n' } }, 202)),
      on('GET', '/api/v1/events/export/job_9/download', new Response('{}\n', { headers: { 'Content-Disposition': 'attachment; filename="job_9.jsonl"' } })),
    );
    const job = await api.events.export({ from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z', format: 'jsonl', service: 'shop-api' });
    expect(job).toEqual({ jobId: 'job_9', format: 'jsonl', bytes: 123, events: 4, notice: 'n' });
    expect(body(calls.at(-1) as Recorded)).toEqual({ from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z', format: 'jsonl', service: 'shop-api' });
    expect((await api.events.download(job)).filename).toBe('job_9.jsonl');
  });
  it('the mining status says when the traffic is too short to decide', async () => {
    const { api } = make(loggedIn, on('GET', '/api/v1/rules/status', json({ state: 'insufficient_data', min_hours: 1, observed_hours: 0.33, events: 517949, last_run_at: '2026-10-24T08:00:00Z', rules: { draft: 0 } })));
    expect(await api.rules.status()).toEqual({ state: 'insufficient_data', minHours: 1, observedHours: 0.33, events: 517949, lastRunAt: '2026-10-24T08:00:00Z', rules: { draft: 0 }, warnings: [], diagnostics: [] });
  });
  it('a purge is a background job that is followed until it ends', async () => {
    let polls = 0;
    const { api } = make(
      loggedIn,
      on('POST', '/api/v1/store/purge', json({ job_id: 'job_7', kind: 'store.purge', status: 'running' }, 202)),
      on('GET', '/api/v1/jobs/job_7', () => json(++polls < 2 ? { job_id: 'job_7', kind: 'store.purge', status: 'running', progress: { events: 5000 } } : { job_id: 'job_7', kind: 'store.purge', status: 'done', result: { events: 9000, tokens: 40 } })),
    );
    expect(await api.store.purge('2026-10-01T00:00:00.000Z')).toEqual({ events: 9000, tokens: 40 });
    expect(polls).toBe(2);
  });
  it('mining now reports the new rules', async () => {
    const { api } = make(loggedIn, on('POST', '/api/v1/rules/mine', json({ job_id: 'j', kind: 'rules.mine', status: 'done', result: { new: ['r-0001', 'r-0002'], updated: [] } }, 202)));
    expect(await api.rules.mine()).toMatchObject({ newRules: 2, updatedRules: 0, state: 'ok', reasons: [] });
  });
  it('the export answer already carries the report, and the zip downloads by export id', async () => {
    const { api } = make(
      loggedIn,
      on('POST', '/api/v1/exports', json({ job_id: 'job_5', kind: 'pack.export', status: 'done', result: { export_id: 'ex_5', report: { exported: [], losses: [{ kind: 'clock', element: 'virtual clock', detail: 'x' }], files: [] } } }, 202)),
      on('GET', '/api/v1/exports/ex_5/download', new Response('PK', { headers: { 'Content-Disposition': 'attachment; filename="ex_5.zip"' } })),
    );
    const rep = await api.publications.export('pk-1', 'wiremock');
    expect(rep).toMatchObject({ exportId: 'ex_5', target: 'wiremock', lost: [{ item: 'virtual clock (clock)', reason: 'x' }] });
    expect((await api.publications.downloadExport('ex_5')).filename).toBe('ex_5.zip');
  });
  it('user sessions can be revoked', async () => {
    const U = { id: 'usr_2', username: 'new', display_name: 'New', auth_method: 'local', roles: ['auditor'] };
    const { api, calls } = make(loggedIn, on('PATCH', '/api/v1/users/usr_2', json(U)));
    await api.users.update('usr_2', { revokeSessions: true });
    expect(body(calls.at(-1) as Recorded)).toEqual({ revoke_sessions: true });
  });
  it('the version is read after sign-in and cached once known', async () => {
    let n = 0;
    const { api } = make(
      on('GET', '/api/v1/auth/config', json({ local: true, oidc: false, setup_required: false })),
      on('GET', '/api/v1/version', () => (++n === 1 ? err(401, 'unauthenticated') : json({ version: '0.5.0', commit: 'c', spec: '1.2' }))),
    );
    expect((await api.system.status()).version).toBe('');
    expect((await api.system.status()).version).toBe('0.5.0');
    await api.system.status();
    expect(n).toBe(2);
  });
});

describe('observe phase (policy.md §7)', () => {
  it('maps opens_values, value_reasons and approvals_required 0 of a version', async () => {
    const { api } = make(
      on('GET', '/api/v1/fleet/policies', json([
        PV({ version: 4, status: 'active', origin: 'observe-auto', approvals_required: 0, approval_mode: 'observe', opens_values: false, value_reasons: [], approvals: [] }),
        PV({ version: 5, status: 'draft', approvals_required: 2, opens_values: true, value_reasons: [{ code: 'keep', where: 'services.shop-api.ops.POST /orders.response.body.$.status' }], approvals: [] }),
        PV({ version: 3, status: 'superseded', classification: 'opening' }),
      ])),
    );
    const vs = await api.policies.list();
    const v4 = vs.find((v) => v.version === 4)!;
    expect(v4).toMatchObject({ origin: 'observe-auto', approvalsRequired: 0, approvalMode: 'observe', opensValues: false, valueReasons: [] });
    expect(vs.find((v) => v.version === 5)).toMatchObject({ opensValues: true, approvalsRequired: 2, valueReasons: [{ code: 'keep' }] });
    // an older server without opens_values: an opening change counts as opening values
    expect(vs.find((v) => v.version === 3)).toMatchObject({ opensValues: true, valueReasons: [] });
  });
  it('reads the observe status of a group', async () => {
    const { api } = make(
      on('GET', '/api/v1/fleet/groups/shop/observe', json({
        group: 'shop', policy_id: 'p-shop', enabled: true, phase: 'masked', active_version: 2, started_at: '2026-10-25T08:00:00Z', due_at: '2026-10-25T08:15:00Z',
        min_events: 200, events: 412, observe_version: 2, observe_activated_at: '2026-10-25T08:06:00Z', sampling_bp: 1000,
        services: [{ service: 'shop-api', kind: 'inbound', calls: 300, ops: 4 }, { service: 'host:api.carrier.example', kind: 'external', calls: 112, ops: 2 }],
        masked: [{ service: 'shop-api', op: 'POST /orders', part: 'response', kind: 'body', field: '$.id', domain: 'order' }],
        identity: { from: 'header', name: 'authorization', jwt_claim: 'sub' },
      })),
    );
    const st = await api.onboarding.observe('shop');
    expect(st).toMatchObject({ phase: 'masked', observeVersion: 2, events: 412, minEvents: 200, identity: { name: 'authorization', claim: 'sub' } });
    expect(st.services.map((s) => s.kind)).toEqual(['inbound', 'external']);
    expect(st.masked[0]).toEqual({ service: 'shop-api', op: 'POST /orders', part: 'response', kind: 'body', field: '$.id', domain: 'order' });
    // an older server without the switch: automation counts as on
    expect(st.auto).toBe(true);
  });
  it('turns the automatic observe versions of a group off (setObserveAuto)', async () => {
    const { api, calls } = make(
      on('PUT', '/api/v1/fleet/groups/shop/observe', json({
        group: 'shop', enabled: true, auto: false, phase: 'managed', min_events: 200, events: 412, sampling_bp: 1000, services: [], masked: [],
      })),
    );
    const st = await api.onboarding.setObserveAuto('shop', false);
    expect(body(calls.find((c) => c.method === 'PUT')!)).toEqual({ auto: false });
    expect(st).toMatchObject({ group: 'shop', auto: false, phase: 'managed' });
  });
});
