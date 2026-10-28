// The "Mock" page: mocks connected to the console (tt mock --console), mock tokens, managed mocks in Kubernetes,
// "Prepara e avvia il mock" and the control calls sent to a running mock (admin-api 1.12.0, /api/v1/mocks).

import type { GroupSel } from './types';
import type { MockIdentity } from './idfmt';
import type { MockPages, ThirdPartyPage } from './pages';

/** A simulated service: the base URL that replaces the real one in the tests. */
export interface MockServiceUrl {
  name: string;
  alias?: string;
  mockUrl: string;
  /** The real endpoint (match.base of the policy), when known. */
  realBase?: string;
}

export interface MockSessionInfo {
  id: string;
  scenario?: string;
  /** Virtual time of the session. */
  clock: string;
  calls: number;
  faults: string;
}

export type MockStatus = 'waiting' | 'serving' | 'error' | 'revoked';

/** A mock that reports to the console. */
export interface RunningMock {
  id: string;
  group: string;
  instance: string;
  tokenId: string;
  /** Started by tt-core in Kubernetes (otherwise installed by the user). */
  managed: boolean;
  online: boolean;
  status: MockStatus;
  version: string;
  packId: string;
  latestPackId: string;
  upToDate: boolean;
  /** Why the mock refused the latest pack. */
  packError?: string;
  publicUrl: string;
  services: MockServiceUrl[];
  sessions: MockSessionInfo[];
  callsTotal: number;
  lastSeen: string;
}

/** A mock tt-core runs in Kubernetes. */
export interface ManagedMock {
  group: string;
  name: string;
  namespace?: string;
  url: string;
  createdBy: string;
  updatedAt: string;
  found: boolean;
  ready: number;
  replicas: number;
  error?: string;
}

export interface MockEnvironment {
  /** tt-core can start mocks itself (mock.kubernetes.enabled). */
  kubernetes: boolean;
  namespace?: string;
  consoleUrl: string;
  image: string;
  reportIntervalS: number;
}

export interface MockOverview {
  mocks: RunningMock[];
  managed: ManagedMock[];
  environment: MockEnvironment;
  /** Newest published pack per group ('' none). */
  latestPacks: Record<string, string>;
}

/** One call received by a mock (no headers, bodies or query strings). */
export interface MockCall {
  seq: number;
  wall: string;
  at?: string;
  session: string;
  scenario?: string;
  service?: string;
  op?: string;
  method: string;
  path: string;
  /** 0: simulated network failure. */
  status: number;
  matched: boolean;
  reason?: string;
  fault?: string;
  latencyMs?: number;
}

export interface MockToken {
  id: string;
  group: string;
  label: string;
  managed: boolean;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  revoked: boolean;
  lastUsed?: string;
}

/** What a user needs to run the mock himself, the token filled in. */
export interface MockSetup {
  consoleUrl: string;
  group: string;
  image: string;
  gatePubKeys: string;
  env: string;
  docker: string;
  /** `tt mock --console …` with the tt of the kit (admin-api 1.15.0; built here for an older server). */
  cli?: string;
  /** Tag of the image: the tt of the kit should be this version. */
  version?: string;
  helmValues: string;
  helm: string;
  openshift: string;
}

export interface NewMockToken extends MockToken {
  /** Shown once. */
  token: string;
  setup: MockSetup;
}

export type PrepareStepId = 'archetypes' | 'world' | 'pack' | 'publish' | 'mock';
export type PrepareStepStatus = 'pending' | 'running' | 'done' | 'skipped' | 'failed' | 'waiting';

export interface PrepareStep {
  id: PrepareStepId;
  status: PrepareStepStatus;
  /** Why skipped / failed / waiting, or how the mock was refreshed (managed, connected, none_connected). */
  code?: string;
  detail?: Record<string, string>;
}

export interface PrepareRun {
  jobId: string;
  status: 'running' | 'done' | 'failed';
  error?: string;
  steps: PrepareStep[];
  packId?: string;
  worldId?: string;
  url?: string;
  /** The run stopped before the publication (needs_publisher). */
  waiting?: string;
}

export interface PrepareInput {
  group: string;
  /** Mandatory for an administrator (the publication is an admin approval). */
  reason?: string;
  /** Start the managed mock when the console can (default true). */
  start?: boolean;
}

export interface MockCommandResult {
  status: number;
  body: unknown;
}

export interface MockServiceApi {
  overview(groups?: GroupSel): Promise<MockOverview>;
  calls(mockId: string, since?: number): Promise<{ calls: MockCall[]; lastSeq: number }>;
  /** Runs a control call (/__tt/...) on the mock and waits for its answer. */
  command(mockId: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown): Promise<MockCommandResult>;
  tokens(groups?: GroupSel): Promise<MockToken[]>;
  createToken(group: string, label?: string, days?: number): Promise<NewMockToken>;
  revokeToken(id: string): Promise<void>;
  startManaged(group: string): Promise<ManagedMock>;
  restartManaged(group: string): Promise<ManagedMock>;
  stopManaged(group: string): Promise<void>;
  /** "Prepara e avvia il mock": archetypes, world, pack, publication, mock. onProgress follows the steps. */
  prepare(input: PrepareInput, onProgress?: (r: PrepareRun) => void): Promise<PrepareRun>;
  /**
   * A preparation started earlier (its job id): its outcome, followed to the end when it still runs (the page after a
   * reload). null when the server no longer has the job.
   */
  preparation(jobId: string, onProgress?: (r: PrepareRun) => void): Promise<PrepareRun | null>;
  /** "Sessione per utente": the identity header (or JWT claim) that picks the session of a call, per group. */
  identity(group: string): Promise<MockIdentity>;
  /** header "" turns it off. 422 invalid_header / invalid_claim. */
  setIdentity(group: string, header: string, claim: string): Promise<MockIdentity>;
  /** Assigns a synthetic customer to a test user: the console keeps only a keyed hash of `user`. */
  addIdentityUser(group: string, user: string, customer: string): Promise<MockIdentity>;
  removeIdentityUser(group: string, hash: string): Promise<MockIdentity>;
  /** "Pagine di terzi": the payment / e-signature pages of the group's mocks (HMAC keys always empty). */
  pages(group: string): Promise<MockPages>;
  /** Replaces the whole list. An empty HMAC key keeps the stored one. 422 invalid_pages. */
  setPages(group: string, pages: ThirdPartyPage[]): Promise<MockPages>;
}

/** The tt command of the kit for a mock token (console mode), when the server does not give one. */
export function cliCommand(s: Pick<MockSetup, 'consoleUrl' | 'group' | 'gatePubKeys' | 'image' | 'cli' | 'version'>, token: string): string {
  if (s.cli) return s.cli;
  const q = (v: string) => `'${v.replaceAll("'", `'\\''`)}'`;
  const version = s.version ?? s.image.split(':')[1] ?? '';
  const tls = s.consoleUrl.startsWith('https://');
  return [
    version && version !== 'latest' ? `# tt of the traffic-twin kit, version ${version} like the console (tt version)` : '# tt of the traffic-twin kit, the same version as the console (tt version)',
    `export TT_MOCK_TOKEN=${q(token)}`,
    `export TT_GATE_PUBKEYS=${q(s.gatePubKeys)}`,
    `tt mock --console ${s.consoleUrl} --group ${s.group} \\`,
    ...(tls ? ['  --console-ca ./console-ca.pem \\'] : []),
    '  --addr 127.0.0.1:8480',
    '',
  ].join('\n');
}

export const PREPARE_STEPS: PrepareStepId[] = ['archetypes', 'world', 'pack', 'publish', 'mock'];

/** "sostituisci https://api.carrier.example con …": the base the tests use instead of the real one. */
export function replacementOf(s: MockServiceUrl): { from: string; to: string } | null {
  return s.realBase ? { from: s.realBase, to: s.mockUrl } : null;
}

/** A virtual-clock advance as the control API wants it (^[0-9]{1,6}(s|m|h|d)$), or null. */
export function clockStep(amount: number, unit: 's' | 'm' | 'h' | 'd'): string | null {
  if (!Number.isInteger(amount) || amount < 1 || amount > 999999) return null;
  return `${amount}${unit}`;
}
