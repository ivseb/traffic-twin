// REST implementation of the Mock page API (admin-api 1.12.0, /api/v1/mocks).

import { ApiError } from '../types';
import type { MockCall, MockCommandResult, MockOverview, MockServiceApi, MockToken, ManagedMock, NewMockToken, PrepareRun, PrepareStep, RunningMock } from '../mocksvc';
import type { Http } from './http';
import { groupQuery } from './map';
import { createIdentityRest } from './idfmt';
import { createPagesRest } from './mock2';

export interface WireMockView {
  mock_id: string;
  group: string;
  instance: string;
  token_id: string;
  managed: boolean;
  online: boolean;
  status: RunningMock['status'];
  version: string;
  pack_id: string;
  latest_pack_id: string;
  up_to_date: boolean;
  pack_error?: string;
  public_url: string;
  services: { name: string; alias?: string; mock_url: string; real_base?: string }[];
  sessions: { id: string; scenario?: string; clock: string; calls: number; faults: string }[];
  calls_total: number;
  last_seen: string;
}

export interface WireManagedMock {
  group: string;
  name: string;
  namespace?: string;
  token_id: string;
  url: string;
  created_by: string;
  updated_at: string;
  pods: { found: boolean; ready_replicas: number; replicas: number };
  error?: string;
}

export interface WireMockList {
  mocks: WireMockView[];
  managed: WireManagedMock[];
  environment: { kubernetes: boolean; namespace?: string; console_url: string; image: string; report_interval_s: number };
  latest_packs: Record<string, string>;
}

export interface WireMockCall {
  seq: number;
  wall: string;
  at?: string;
  session: string;
  scenario?: string;
  service?: string;
  op?: string;
  method: string;
  path: string;
  status: number;
  matched: boolean;
  reason?: string;
  fault?: string;
  latency_ms?: number;
}

export interface WireMockToken {
  token_id: string;
  group: string;
  label: string;
  managed: boolean;
  created_by: string;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  last_used: string | null;
}

export interface WireNewMockToken extends WireMockToken {
  token: string;
  setup: { console_url: string; group: string; image: string; gate_pubkeys: string; env: string; docker: string; cli?: string; version?: string; helm_values: string; helm: string; openshift: string };
}

interface WirePrepareJob {
  job_id: string;
  status: string;
  error?: string;
  progress?: { steps?: PrepareStep[] };
  result?: { result?: { pack_id?: string; world_id?: string; url?: string; waiting?: string }; steps?: PrepareStep[] };
}

const enc = encodeURIComponent;

export function mapMock(w: WireMockView): RunningMock {
  return {
    id: w.mock_id,
    group: w.group,
    instance: w.instance,
    tokenId: w.token_id,
    managed: w.managed,
    online: w.online,
    status: w.status,
    version: w.version,
    packId: w.pack_id,
    latestPackId: w.latest_pack_id,
    upToDate: w.up_to_date,
    packError: w.pack_error || undefined,
    publicUrl: w.public_url,
    services: (w.services ?? []).map((s) => ({ name: s.name, alias: s.alias || undefined, mockUrl: s.mock_url, realBase: s.real_base || undefined })),
    sessions: w.sessions ?? [],
    callsTotal: w.calls_total,
    lastSeen: w.last_seen,
  };
}

export function mapManaged(w: WireManagedMock): ManagedMock {
  return {
    group: w.group,
    name: w.name,
    namespace: w.namespace,
    url: w.url,
    createdBy: w.created_by,
    updatedAt: w.updated_at,
    found: w.pods?.found ?? false,
    ready: w.pods?.ready_replicas ?? 0,
    replicas: w.pods?.replicas ?? 0,
    error: w.error || undefined,
  };
}

export function mapCall(w: WireMockCall): MockCall {
  return {
    seq: w.seq,
    wall: w.wall,
    at: w.at,
    session: w.session,
    scenario: w.scenario || undefined,
    service: w.service || undefined,
    op: w.op || undefined,
    method: w.method,
    path: w.path,
    status: w.status,
    matched: w.matched,
    reason: w.reason || undefined,
    fault: w.fault || undefined,
    latencyMs: w.latency_ms,
  };
}

export function mapMockToken(w: WireMockToken): MockToken {
  return {
    id: w.token_id,
    group: w.group,
    label: w.label,
    managed: w.managed,
    createdBy: w.created_by,
    createdAt: w.created_at,
    expiresAt: w.expires_at,
    revoked: w.revoked,
    lastUsed: w.last_used ?? undefined,
  };
}

export function mapPrepare(j: WirePrepareJob): PrepareRun {
  const steps = j.result?.steps ?? j.progress?.steps ?? [];
  const r = j.result?.result ?? {};
  const status = j.status === 'done' || j.status === 'failed' ? j.status : 'running';
  return { jobId: j.job_id, status, error: j.error || undefined, steps, packId: r.pack_id, worldId: r.world_id, url: r.url, waiting: r.waiting };
}

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));

export function createMockServiceRest(http: Http, wait: (ms: number) => Promise<void> = sleep): MockServiceApi {
  async function followPrepare(j: WirePrepareJob, onProgress?: (r: PrepareRun) => void): Promise<PrepareRun> {
    for (let i = 0; (j.status === 'running' || j.status === 'queued') && i < 3600; i++) {
      await wait(i < 10 ? 500 : 1000);
      j = await http.get<WirePrepareJob>(`/api/v1/jobs/${enc(j.job_id)}`);
      onProgress?.(mapPrepare(j));
    }
    return mapPrepare(j);
  }
  return {
    ...createIdentityRest(http),
    ...createPagesRest(http),
    async overview(groups) {
      const l = await http.get<WireMockList>('/api/v1/mocks', { query: groupQuery(groups) });
      return {
        mocks: l.mocks.map(mapMock),
        managed: l.managed.map(mapManaged),
        environment: {
          kubernetes: l.environment.kubernetes,
          namespace: l.environment.namespace,
          consoleUrl: l.environment.console_url,
          image: l.environment.image,
          reportIntervalS: l.environment.report_interval_s,
        },
        latestPacks: l.latest_packs ?? {},
      };
    },
    async calls(mockId, since = 0) {
      const r = await http.get<{ calls: WireMockCall[]; last_seq: number }>(`/api/v1/mocks/${enc(mockId)}/calls`, { query: { since } });
      return { calls: r.calls.map(mapCall), lastSeq: r.last_seq };
    },
    async command(mockId, method, path, body) {
      const q = await http.post<{ command_id: string }>(`/api/v1/mocks/${enc(mockId)}/commands`, body === undefined ? { method, path } : { method, path, body });
      // The console holds the mock's report until a command arrives: the answer is usually there in well under a second.
      for (let i = 0; i < 60; i++) {
        await wait(i < 5 ? 150 : 500);
        const c = await http.get<{ status: string; result?: { status: number; body?: unknown } }>(`/api/v1/mocks/${enc(mockId)}/commands/${enc(q.command_id)}`);
        if (c.status === 'done' && c.result) return { status: c.result.status, body: c.result.body ?? null } satisfies MockCommandResult;
      }
      throw new ApiError('unavailable', 'The mock did not answer the command in time.');
    },
    async tokens(groups) {
      return (await http.get<WireMockToken[]>('/api/v1/mocks/tokens', { query: groupQuery(groups) })).map(mapMockToken);
    },
    async createToken(group, label, days) {
      const w = await http.post<WireNewMockToken>('/api/v1/mocks/tokens', { group, ...(label ? { label } : {}), ...(days ? { expires_in_days: days } : {}) });
      const s = w.setup;
      return {
        ...mapMockToken(w),
        token: w.token,
        setup: { consoleUrl: s.console_url, group: s.group, image: s.image, gatePubKeys: s.gate_pubkeys, env: s.env, docker: s.docker, ...(s.cli ? { cli: s.cli } : {}), ...(s.version ? { version: s.version } : {}), helmValues: s.helm_values, helm: s.helm, openshift: s.openshift },
      } satisfies NewMockToken;
    },
    async revokeToken(id) {
      await http.del<void>(`/api/v1/mocks/tokens/${enc(id)}`);
    },
    async startManaged(group) {
      return mapManaged(await http.post<WireManagedMock>('/api/v1/mocks/managed', { group }));
    },
    async restartManaged(group) {
      return mapManaged(await http.post<WireManagedMock>(`/api/v1/mocks/managed/${enc(group)}/restart`));
    },
    async stopManaged(group) {
      await http.del<void>(`/api/v1/mocks/managed/${enc(group)}`);
    },
    async prepare(input, onProgress) {
      let j = await http.post<WirePrepareJob>('/api/v1/mocks/prepare', { group: input.group, ...(input.reason ? { reason: input.reason } : {}), ...(input.start === false ? { start: false } : {}) });
      onProgress?.(mapPrepare(j));
      return followPrepare(j, onProgress);
    },
    async preparation(jobId, onProgress) {
      let j: WirePrepareJob;
      try {
        j = await http.get<WirePrepareJob>(`/api/v1/jobs/${enc(jobId)}`, { retries: 0 });
      } catch (e) {
        if (e instanceof ApiError && (e.code === 'not_found' || e.code === 'forbidden')) return null;
        throw e;
      }
      onProgress?.(mapPrepare(j));
      return followPrepare(j, onProgress);
    },
  };
}
