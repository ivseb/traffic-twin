// In-memory Mock page API for the demo build and the tests: invented mocks, calls and tokens. The demo console
// runs "in Kubernetes" (managed mocks available); setKubernetes(false) shows the self-installed path.

import { ApiError, type Permission, type User } from '../types';
import type {
  ManagedMock,
  MockCall,
  MockCommandResult,
  MockOverview,
  MockServiceApi,
  MockToken,
  NewMockToken,
  PrepareRun,
  PrepareStep,
  RunningMock,
} from '../mocksvc';
import { PREPARE_STEPS } from '../mocksvc';
import { createDemoIdentity } from './idfmt';
import { createDemoPages } from './mock2';

export interface DemoMockDeps {
  /** The signed-in user holding perm (throws like the server otherwise). */
  need(perm: Permission): User;
  authed(): User;
  audit(actor: string, action: string, target: string): void;
  now(): number;
  wait(): Promise<void>;
  /** Time a prepare step takes (ms). */
  stepMs?: number;
}

const SERVICES = [
  { name: 'shop-api' },
  { name: 'shipping-ext', alias: 'carrier', realBase: 'https://api.carrier.example' },
  { name: 'payments-ext', realBase: 'https://api.pay.example' },
];
const PRESETS = [
  { id: 'sc-observed', name: 'Come in produzione', description: 'Guasti e latenze alle frequenze osservate.' },
  { id: 'sc-carrier-down', name: 'Corriere non disponibile', description: 'Le chiamate al corriere rispondono 503.' },
];
const PATHS = ['/__svc/shop-api/orders', '/__svc/shop-api/orders/ORD-SYN-0007', '/__svc/carrier/shipments', '/__svc/carrier/shipments/SHP-SYN-0012', '/__svc/payments-ext/charges'];

export function createDemoMockService(d: DemoMockDeps): MockServiceApi & { setKubernetes(on: boolean): void } {
  const stepMs = d.stepMs ?? 700;
  let kubernetes = true;
  let packSeq = 0;
  const latest: Record<string, string> = {};
  const mocks = new Map<string, RunningMock>();
  const managed = new Map<string, ManagedMock>();
  const calls = new Map<string, MockCall[]>();
  const tokens: (MockToken & { secret: string })[] = [];
  // Preparations by job id (the page resumes the last one after a reload).
  const runs = new Map<string, PrepareRun>();
  const iso = (ms = d.now()) => new Date(ms).toISOString();
  const rnd = (n: number) => Math.floor(Math.random() * n);

  function mockFor(group: string, managedMock: boolean, url: string): RunningMock {
    const id = `mtk-${(group + '000000000000000000000000').replace(/[^0-9a-f]/g, 'a').slice(0, 24)}.${managedMock ? 'tt-mock-' + group : 'ci-runner-1'}`;
    const m: RunningMock = {
      id, group, instance: id.split('.')[1], tokenId: id.split('.')[0], managed: managedMock, online: true, status: 'serving', version: '0.1.0',
      packId: latest[group] ?? '', latestPackId: latest[group] ?? '', upToDate: true, publicUrl: url,
      services: SERVICES.map((s) => ({ name: s.name, alias: s.alias, mockUrl: `${url}/__svc/${s.alias ?? s.name}`, realBase: s.realBase })),
      sessions: [{ id: 'default', clock: iso(), calls: 0, faults: 'observed' }], callsTotal: 0, lastSeen: iso(),
    };
    mocks.set(id, m);
    calls.set(id, []);
    return m;
  }

  /** Invented traffic of the tests since the last look. */
  function simulate(m: RunningMock): void {
    if (!m.online || m.status !== 'serving') return;
    const list = calls.get(m.id) ?? [];
    for (let i = 0, n = 1 + rnd(3); i < n; i++) {
      const path = PATHS[rnd(PATHS.length)];
      const fail = rnd(10) === 0;
      const sess = m.sessions[rnd(m.sessions.length)];
      list.push({
        seq: (list.at(-1)?.seq ?? 0) + 1, wall: iso(), at: sess.clock, session: sess.id, scenario: sess.scenario, service: path.split('/')[2],
        method: path.endsWith('s') && rnd(2) ? 'POST' : 'GET', path, status: fail ? 503 : 200, matched: true, fault: fail ? 'status 503' : undefined,
      });
      sess.calls++;
      m.callsTotal++;
    }
    calls.set(m.id, list.slice(-500));
    m.lastSeen = iso();
  }

  function publish(group: string): string {
    packSeq++;
    const day = iso().slice(0, 10).replace(/-/g, '');
    latest[group] = `pk-${day}-${String(100 + packSeq).padStart(4, '0')}`;
    for (const m of mocks.values()) if (m.group === group) Object.assign(m, { packId: latest[group], latestPackId: latest[group], upToDate: true, sessions: [{ id: 'default', clock: iso(), calls: 0, faults: 'observed' }] });
    return latest[group];
  }

  function startManaged(group: string, by: string): ManagedMock {
    const url = `https://tt-mock-${group}-mocks.apps.demo.example`;
    const mm: ManagedMock = { group, name: `tt-mock-${group}`, namespace: 'mocks', url, createdBy: by, updatedAt: iso(), found: true, ready: 1, replicas: 1 };
    managed.set(group, mm);
    if (![...mocks.values()].some((m) => m.group === group && m.managed)) mockFor(group, true, url);
    return mm;
  }

  return {
    ...createDemoIdentity({ authed: d.authed, audit: d.audit, now: d.now, wait: d.wait }),
    ...createDemoPages({ authed: d.authed, audit: d.audit, now: d.now, wait: d.wait }),
    setKubernetes(on) {
      kubernetes = on;
    },
    async overview(groups) {
      await d.wait();
      d.authed();
      const sel = groups == null ? null : typeof groups === 'string' ? [groups] : [...groups];
      const keep = (g: string) => !sel || sel.length === 0 || sel.includes(g);
      for (const m of mocks.values()) simulate(m);
      const out: MockOverview = {
        mocks: [...mocks.values()].filter((m) => keep(m.group)).map((m) => structuredClone(m)),
        managed: [...managed.values()].filter((m) => keep(m.group)).map((m) => ({ ...m })),
        environment: { kubernetes, namespace: kubernetes ? 'mocks' : undefined, consoleUrl: 'https://tt.demo.example', image: 'ghcr.io/ivseb/traffic-twin:0.1.0', reportIntervalS: 3 },
        latestPacks: Object.fromEntries(Object.entries(latest).filter(([g]) => keep(g))),
      };
      return out;
    },
    async calls(mockId, since = 0) {
      d.authed();
      const m = mocks.get(mockId);
      if (!m) throw new ApiError('not_found', 'Mock non trovato');
      simulate(m);
      const list = calls.get(mockId) ?? [];
      return { calls: list.filter((c) => c.seq > since), lastSeq: list.at(-1)?.seq ?? 0 };
    },
    async command(mockId, method, path, body): Promise<MockCommandResult> {
      await d.wait();
      const u = method === 'GET' ? d.authed() : d.need('scenarios.edit');
      const m = mocks.get(mockId);
      if (!m) throw new ApiError('not_found', 'Mock non trovato');
      if (!m.online) throw new ApiError('conflict', 'Il mock non risponde');
      const b = (body ?? {}) as Record<string, unknown>;
      const seg = path.split('/').filter(Boolean); // __tt, sessions, id, sub...
      if (method !== 'GET') d.audit(u.username, 'mock.command', mockId);
      if (path === '/__tt/scenarios') return { status: 200, body: PRESETS };
      if (path === '/__tt/sessions' && method === 'POST') {
        const id = typeof b.id === 'string' && b.id ? b.id : `s-${m.sessions.length}`;
        if (m.sessions.some((s) => s.id === id)) return { status: 409, body: { code: 'session_exists', message: 'session id already used' } };
        const s = { id, scenario: typeof b.scenario === 'string' ? b.scenario : undefined, clock: iso(), calls: 0, faults: 'observed' };
        m.sessions.push(s);
        return { status: 201, body: { id, now: s.clock } };
      }
      const s = m.sessions.find((x) => x.id === seg[2]);
      if (seg[1] === 'sessions' && !s) return { status: 404, body: { code: 'session_not_found', message: 'unknown session' } };
      if (!s) return { status: 404, body: { code: 'not_found', message: 'unknown control path' } };
      switch (seg.slice(3).join('/')) {
        case '':
          if (method === 'DELETE') {
            if (s.id === 'default') return { status: 400, body: { code: 'bad_request', message: 'the default session is reset, not deleted' } };
            m.sessions = m.sessions.filter((x) => x !== s);
            return { status: 204, body: null };
          }
          return { status: 200, body: s };
        case 'reset':
          Object.assign(s, { clock: iso(), calls: 0 });
          return { status: 200, body: s };
        case 'clock/advance': {
          const by = String(b.by ?? '');
          const mm = /^([0-9]{1,6})(s|m|h|d)$/.exec(by);
          if (!mm) return { status: 400, body: { code: 'bad_request', message: 'by must match ^[0-9]{1,6}(s|m|h|d)$', pointer: '/by' } };
          const ms = Number(mm[1]) * { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[mm[2] as 's' | 'm' | 'h' | 'd'];
          s.clock = new Date(Date.parse(s.clock) + ms).toISOString();
          return { status: 200, body: { now: s.clock, applied: [{ rule: 'r-0007', effect: 'in_transit', entity: 'shipment' }] } };
        }
        case 'faults':
          s.faults = String(b.mode ?? 'observed');
          return { status: 200, body: { mode: s.faults } };
        case 'scenario':
          if (typeof b.preset === 'string') {
            if (!PRESETS.some((p) => p.id === b.preset)) return { status: 404, body: { code: 'preset_not_found', message: 'unknown preset' } };
            Object.assign(s, { scenario: b.preset, clock: iso(), calls: 0 });
          }
          return { status: 200, body: s };
      }
      return { status: 404, body: { code: 'not_found', message: 'unknown control path' } };
    },
    async tokens(groups) {
      await d.wait();
      d.authed();
      const sel = groups == null ? null : typeof groups === 'string' ? [groups] : [...groups];
      return tokens.filter((t) => !sel || sel.length === 0 || sel.includes(t.group)).map(({ secret: _s, ...t }) => ({ ...t }));
    },
    async createToken(group, label, days = 180) {
      await d.wait();
      const u = d.need('publish.build');
      const idHex = Array.from({ length: 24 }, () => '0123456789abcdef'[rnd(16)]).join('');
      const secret = Array.from({ length: 43 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'[rnd(64)]).join('');
      const t = { id: `mtk-${idHex}`, group, label: label ?? '', managed: false, createdBy: u.username, createdAt: iso(), expiresAt: iso(d.now() + days * 864e5), revoked: false, secret };
      tokens.unshift(t);
      d.audit(u.username, 'mock.token_create', t.id);
      const token = `ttm_${idHex}.${secret}`;
      const keys = 'gate-2026-1:Xz9kQ2demo0demo0demo0demo0demo0demo0demo0de';
      const console = 'https://tt.demo.example';
      const { secret: _s, ...info } = t;
      const nt: NewMockToken = {
        ...info, token,
        setup: {
          consoleUrl: console, group, image: 'ghcr.io/ivseb/traffic-twin:0.1.0', gatePubKeys: keys,
          env: `TT_MOCK_CONSOLE=${console}\nTT_MOCK_GROUP=${group}\nTT_MOCK_TOKEN=${token}\nTT_GATE_PUBKEYS=${keys}\n`,
          docker: `# console-ca.pem: the CA of the console certificate (PEM). With a certificate of a\n# public CA, drop the -v line and --console-ca.\ndocker run --rm -p 8480:8480 \\\n  -v "$PWD/console-ca.pem:/etc/tt/console-ca.pem:ro" \\\n  -e TT_MOCK_TOKEN='${token}' \\\n  -e TT_GATE_PUBKEYS='${keys}' \\\n  ghcr.io/ivseb/traffic-twin:0.1.0 mock --console ${console} --group ${group} \\\n  --console-ca /etc/tt/console-ca.pem \\\n  --addr 0.0.0.0:8480 --public-url http://localhost:8480\n`,
          version: '0.1.0',
          helmValues: `image:\n  repository: ghcr.io/ivseb/traffic-twin\n  tag: "0.1.0"\nconsole:\n  url: ${console}\n  group: ${group}\n  tokenSecret: tt-mock-token\ngatePubKeys: "${keys}"\n`,
          helm: `kubectl create secret generic tt-mock-token --from-literal=token='${token}'\nhelm install tt-mock deploy/helm/tt-mock -f values-mock.yaml\n`,
          openshift: `oc project <your-test-namespace>\noc create secret generic tt-mock-token --from-literal=token='${token}'\nhelm install tt-mock deploy/helm/tt-mock -f values-mock.yaml --set route.enabled=true\n`,
        },
      };
      return nt;
    },
    async revokeToken(id) {
      await d.wait();
      const u = d.need('publish.build');
      const t = tokens.find((x) => x.id === id);
      if (!t) throw new ApiError('not_found', 'Token non trovato');
      t.revoked = true;
      for (const m of mocks.values()) if (m.tokenId === id) Object.assign(m, { status: 'revoked', online: false });
      d.audit(u.username, 'mock.token_revoke', id);
    },
    async startManaged(group) {
      await d.wait();
      const u = d.need('publish.build');
      if (!kubernetes) throw new ApiError('conflict', 'Questa console non avvia i mock da sola', 409, 'kubernetes_disabled');
      d.audit(u.username, 'mock.start', `tt-mock-${group}`);
      return { ...startManaged(group, u.username) };
    },
    async restartManaged(group) {
      await d.wait();
      const u = d.need('publish.build');
      const mm = managed.get(group);
      if (!mm) throw new ApiError('not_found', 'Nessun mock gestito per il gruppo');
      mm.updatedAt = iso();
      for (const m of mocks.values()) if (m.group === group && m.managed) m.sessions = [{ id: 'default', clock: iso(), calls: 0, faults: 'observed' }];
      d.audit(u.username, 'mock.restart', mm.name);
      return { ...mm };
    },
    async stopManaged(group) {
      await d.wait();
      const u = d.need('publish.build');
      const mm = managed.get(group);
      if (!mm) throw new ApiError('not_found', 'Nessun mock gestito per il gruppo');
      managed.delete(group);
      for (const [id, m] of mocks) if (m.group === group && m.managed) mocks.delete(id);
      d.audit(u.username, 'mock.stop', mm.name);
    },
    async preparation(jobId, onProgress) {
      await d.wait();
      d.need('publish.build');
      const r = runs.get(jobId);
      if (!r) return null;
      onProgress?.(structuredClone(r));
      // A run that goes on is followed to its end, as the server does (usability test #5, m7: back on the page).
      for (let i = 0; r.status === 'running' && i < 600; i++) {
        await new Promise<void>((ok) => setTimeout(ok, Math.max(20, stepMs / 2)));
        onProgress?.(structuredClone(r));
      }
      return structuredClone(r);
    },
    async prepare(input, onProgress) {
      const u = d.need('publish.build');
      const steps: PrepareStep[] = PREPARE_STEPS.map((id) => ({ id, status: 'pending' }));
      const run: PrepareRun = { jobId: `job_demo${packSeq}_${runs.size + 1}`, status: 'running', steps };
      runs.set(run.jobId, run);
      const emit = () => onProgress?.(structuredClone(run));
      const set = (id: PrepareStep['id'], status: PrepareStep['status'], code?: string, detail?: Record<string, string>) => {
        Object.assign(steps.find((s) => s.id === id)!, { status, code, detail });
        emit();
      };
      const pause = () => new Promise<void>((ok) => setTimeout(ok, stepMs));
      emit();
      for (const id of ['archetypes', 'world', 'pack'] as const) {
        set(id, 'running');
        await pause();
        set(id, 'done', undefined, id === 'archetypes' ? { archetypes: '4', profiles: '600' } : id === 'world' ? { world_id: 'w-demo', customers: '50', entities: '412' } : { services: String(SERVICES.length) });
      }
      set('publish', 'running');
      await pause();
      const perms = u.roles;
      if (!perms.includes('publisher') && !perms.includes('admin')) {
        set('publish', 'waiting', 'needs_publisher');
        set('mock', 'skipped');
        run.status = 'done';
        run.waiting = 'needs_publisher';
        emit();
        return structuredClone(run);
      }
      if (perms.includes('admin') && !input.reason?.trim()) {
        set('publish', 'failed', 'admin_reason_required');
        set('mock', 'skipped');
        run.status = 'failed';
        run.error = 'admin_reason_required';
        emit();
        return structuredClone(run);
      }
      run.packId = publish(input.group);
      d.audit(u.username, 'pack.publish', run.packId);
      set('publish', 'done', undefined, { pack_id: run.packId });
      set('mock', 'running');
      await pause();
      if (input.start !== false && kubernetes) {
        const mm = managed.get(input.group) ?? startManaged(input.group, u.username);
        run.url = mm.url;
        set('mock', 'done', 'managed', { url: mm.url });
      } else {
        const connected = [...mocks.values()].some((m) => m.group === input.group && m.online);
        set('mock', 'done', connected ? 'connected' : 'none_connected');
      }
      run.status = 'done';
      emit();
      return structuredClone(run);
    },
  };
}
