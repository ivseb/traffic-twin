// REST adapter: implements `Api` against the admin API of tt-core
// (/api/v1/...), session cookie + X-CSRF-Token. Payload shapes follow the Go
// handlers (wire.ts); mapping is in map.ts / contract.ts.

import { dedupeAssist, suggestionsOf } from '../../assist';
import { ROLE_PERMISSIONS } from '../../rbac';
import {
  ApiError,
  type Api,
  type AuditEntry,
  type DriftAlert,
  type ExportTarget,
  type MiningStatus,
  type MinerExplanation,
  type AssistService,
  type PolicyAssist,
  type PolicySuggestion,
  type ProposePolicyInput,
  type PolicyVersion,
  type Publication,
  type Rule,
  type ScenarioPreset,
  type Settings,
  type WorldGraph,
  type WorldNode,
  type Role,
  type SourceChoice,
  type QuarantineItem,
  type StorageLevel,
  type GroupSel,
  serviceKey,
} from '../types';
import { Http, type HttpOptions } from './http';
import { createMockServiceRest } from './mocksvc';
import { createIdFormatsRest } from './idfmt';
import { createDateOffsetsRest } from './mock2';
import { createOpKindsRest } from './opkinds';
import { encodePattern, hostPatternOfService, exactBaseUrl } from '../../hosts';
import { customerDetailOf } from '../../world-explorer';
import { beginStepUp, bindingOf, shouldStepUp, type StepUpPayload } from '../../stepup';
import {
  kindOfChoice,
  mapAlert,
  mapArchetype,
  mapAuditEntry,
  mapAuditVerify,
  mapExportReport,
  mapGaps,
  mapHosts,
  mapMe,
  mapOnboarding,
  mapPack,
  mapPolicy,
  mapObserve,
  mapIdentityCandidate,
  mapIdentitySource,
  mapRule,
  mapServerSettings,
  mapSigningKey,
  mapSource,
  mapSuggestion,
  mapToken,
  mapUser,
  mapWebhook,
  mapWorld,
  actionSpec,
  parseNdjson,
  samplingBpOf,
  mapScope,
  mapContractStatus,
  withKeyCheck,
  mapStoreUsage,
  groupQuery,
  mapCandidates,
  mapFamilyCandidates,
} from './map';
import {
  aggregate,
  DEFAULT_MIN_SAMPLES,
  fragmentOf,
  operationDetail,
  operationSummaries,
  serviceInfoOf,
  type OpenApiDoc,
} from './contract';
import type {
  WireAlert,
  WireApprovalSettings,
  WireArchetypeList,
  WireCustomerPage,
  WireAssist,
  WireAssistDraftResult,
  WireObserveStatus,
  WireAuditEntry,
  WireAuditVerify,
  WireAuthConfig,
  WireDelivery,
  WireDiff,
  WireGap,
  WireGroup,
  WireHostsRegistry,
  WireJob,
  WireMineResult,
  WireMiningStatus,
  WireEntityDiag,
  WireRuleDiag,
  WireMe,
  WireNewToken,
  WireOnboarding,
  WirePack,
  WirePolicyVersion,
  WirePreset,
  WireRule,
  WireCatalog,
  WireRuleCheck,
  WireServiceEntry,
  WireSettings,
  WireSigningKey,
  WireSnapshotInfo,
  WireStoreUsage,
  WireSource,
  WireUser,
  WireVersion,
  WireWebhook,
  WireWorld,
  WireScope,
  WireGateKeys,
  WireKeyCheck,
  WireContractStatus,
} from './wire';

export interface RestOptions extends HttpOptions {
  now?: () => Date;
  /** EventSource implementation for the onboarding stream; null disables SSE (polling only). */
  eventSource?: typeof EventSource | null;
  /** Polling period of the onboarding status when SSE is unavailable. */
  pollMs?: number;
  /** How long a contract document is reused between calls. */
  docTtlMs?: number;
  /**
   * Starts the OIDC step-up of an approval (keyguard verifies approvals with OIDC and tt-core answered
   * 403 stepup_required): by default saves the call and navigates to the identity provider.
   */
  stepUp?: (payload: StepUpPayload) => void;
}

const enc = encodeURIComponent;
const FLEET = '/api/v1/fleet';

const lazyPolicyDoc = () => import('./policy-doc');

/** Delay between two polls of a running job (exported for tests). */
export const JOB_POLL_MS = [500, 1000, 2000, 3000];

/**
 * Follows a Job answered "running" (admin-api 1.9.0: a long operation that
 * does not finish within the server's wait) until it is done or failed.
 */
export async function followJob<T>(http: Http, job: WireJob<T>, sleep: (ms: number) => Promise<void> = (ms) => new Promise((ok) => setTimeout(ok, ms))): Promise<WireJob<T>> {
  for (let i = 0; (job.status === 'running' || job.status === 'queued') && i < 7200; i++) {
    await sleep(JOB_POLL_MS[Math.min(i, JOB_POLL_MS.length - 1)]);
    job = await http.get<WireJob<T>>(`/api/v1/jobs/${encodeURIComponent(job.job_id)}`);
  }
  return job;
}

/** Errors that say the server is busy or briefly away, not that the operation failed. */
const transient = (e: unknown) => e instanceof ApiError && (e.code === 'network' || e.code === 'unavailable' || e.code === 'server');

/**
 * followJob for a job the person waits for on the page (mining): a poll that fails because the server is busy or
 * restarting is tried again (up to `patience` times in a row) instead of turning a running job into «Errore del
 * server»; `onStatus` is told the job's status at every poll (usability test #4, M3).
 */
export async function followJobPatient<T>(
  http: Http,
  job: WireJob<T>,
  o: { sleep?: (ms: number) => Promise<void>; onStatus?: (status: string, retrying: boolean) => void; patience?: number } = {},
): Promise<WireJob<T>> {
  const sleep = o.sleep ?? ((ms) => new Promise((ok) => setTimeout(ok, ms)));
  const patience = o.patience ?? 12;
  let misses = 0;
  for (let i = 0; (job.status === 'running' || job.status === 'queued') && i < 7200; i++) {
    await sleep(misses ? 3000 : JOB_POLL_MS[Math.min(i, JOB_POLL_MS.length - 1)]);
    try {
      job = await http.get<WireJob<T>>(`/api/v1/jobs/${encodeURIComponent(job.job_id)}`, { retries: 0 });
      misses = 0;
      o.onStatus?.(job.status, false);
    } catch (e) {
      if (!transient(e) || ++misses > patience) throw e;
      o.onStatus?.(job.status, true);
    }
  }
  return job;
}

export function createRestApi(opts: RestOptions = {}): Api {
  const http = new Http(opts);
  const now = opts.now ?? (() => new Date());
  const pollMs = opts.pollMs ?? 2000;
  const docTtl = opts.docTtlMs ?? 8000;
  const stepUp = opts.stepUp ?? ((p: StepUpPayload) => beginStepUp(p));
  const ES = opts.eventSource === undefined ? (typeof EventSource === 'undefined' ? null : EventSource) : opts.eventSource;

  http.refreshCsrf = async () => {
    await me();
  };

  // ------------------------------------------------------------ helpers
  async function me() {
    try {
      const m = await http.get<WireMe>('/api/v1/auth/me', { quiet401: true });
      http.setCsrf(m.csrf_token, m.csrf_header);
      return mapMe(m);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'unauthenticated') {
        http.setCsrf(null);
        return null;
      }
      throw e;
    }
  }

  /**
   * Runs an approval call; on 403 stepup_required starts the step-up (the page then leaves, so the
   * returned promise never settles), unless a step-up for the same change has just completed: then the
   * error goes to the caller instead of looping through the identity provider.
   */
  async function withStepUp<T>(payload: StepUpPayload, call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (e) {
      const b = bindingOf(payload);
      if (e instanceof ApiError && e.serverCode === 'stepup_required' && shouldStepUp(b.purpose, b.ref)) {
        stepUp(payload);
        return new Promise<T>(() => undefined);
      }
      throw e;
    }
  }

  /** The route is not served by this tt-core (the generic JSON 404 of /api/). */
  function unsupported(what: string): never {
    throw new ApiError('unsupported', `This server does not provide ${what} (yet).`, 404, 'not_found');
  }
  async function orUnsupported<T>(what: string, p: Promise<T>): Promise<T> {
    try {
      return await p;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'not_found') unsupported(what);
      throw e;
    }
  }

  /**
   * A route this tt-core does not have (405, or the generic 404 of /api/: no JSON code, or «no such endpoint») is
   * `unsupported`; the 404 of a version or a rule that does not exist stays `not_found`.
   */
  async function orNoRoute<T>(what: string, p: Promise<T>): Promise<T> {
    try {
      return await p;
    } catch (e) {
      if (e instanceof ApiError && (e.status === 405 || (e.status === 404 && (!e.serverCode || /no such endpoint/i.test(e.message))))) unsupported(what);
      throw e;
    }
  }

  // GET /api/v1/version needs a session: before sign-in it answers 401 and the footer and the badge stay empty.
  // Once known it is kept; changing the labels in the settings drops it.
  let versionCache: WireVersion | null = null;
  async function versionInfo(): Promise<WireVersion> {
    if (versionCache?.version) return versionCache;
    try {
      versionCache = await http.get<WireVersion>('/api/v1/version', { quiet401: true, retries: 0 });
    } catch {
      versionCache = null;
    }
    return versionCache ?? {};
  }

  // contract documents are fetched often (list, detail, summary): reuse them briefly. One per (group, service):
  // the contract of a group's traffic only.
  const docs = new Map<string, { at: number; p: Promise<OpenApiDoc> }>();
  function contractDoc(service: string, group?: GroupSel, fresh = false): Promise<OpenApiDoc> {
    const query = groupQuery(group);
    const key = serviceKey(query.group, service);
    const hit = docs.get(key);
    if (!fresh && hit && Date.now() - hit.at < docTtl) return hit.p;
    const p = http.get<OpenApiDoc>(`/api/v1/contracts/${enc(service)}`, { query });
    docs.set(key, { at: Date.now(), p });
    p.catch(() => docs.delete(key));
    return p;
  }

  /** null when the role cannot read gaps: the call counts then fall back to the default threshold. */
  async function gapsRaw(group?: GroupSel): Promise<WireGap[] | null> {
    try {
      return await http.get<WireGap[]>('/api/v1/gaps', { query: groupQuery(group) });
    } catch {
      return null;
    }
  }
  async function fewSamplesFn(group?: GroupSel): Promise<(service: string, group?: string) => (op: string, calls: number) => boolean> {
    const gaps = await gapsRaw(group);
    // Only operation-level gaps make an operation rare; "optional field seen in few objects" is scope=field.
    // A gap without a group (older server) counts for the service of every group.
    const key = (g: string | undefined, service: string, op: string) => `${g ?? '*'}\u0000${service}\u0000${op}`;
    const few = new Set((gaps ?? []).filter((g) => g.kind === 'few-samples' && g.scope === 'op' && g.op).map((g) => key(g.group, g.service, g.op ?? '')));
    return (service, grp) => (op, calls) => (gaps ? few.has(key(undefined, service, op)) || few.has(key(grp ?? '', service, op)) : calls < DEFAULT_MIN_SAMPLES);
  }

  async function groupOf(name: string): Promise<WireGroup | null> {
    try {
      return await http.get<WireGroup>(`${FLEET}/groups/${enc(name)}`);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'not_found') return null;
      throw e;
    }
  }

  async function policyVersions(groups?: GroupSel): Promise<WirePolicyVersion[]> {
    return http.get<WirePolicyVersion[]>(`${FLEET}/policies`, { query: groupQuery(groups) });
  }
  /** Service name -> host of its base, for the services the policies of the group declare. The registry is for operators and admins: anyone else gets an empty map. */
  async function declaredHosts(group?: GroupSel): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    try {
      const reg = await http.get<WireHostsRegistry>('/api/v1/hosts', { query: groupQuery(group) });
      for (const d of reg.domains ?? []) for (const p of d.patterns ?? []) if (p.declared) out.set(p.service, p.pattern);
    } catch {
      /* not an operator, or an older server: the services page works without the link */
    }
    return out;
  }
  const activeOf = (all: WirePolicyVersion[], pid: string) => all.filter((v) => v.policy_id === pid && v.status === 'active').sort((a, b) => b.version - a.version)[0];

  /**
   * The mining job to follow after a lost answer: one queued or running, else the newest finished one whose run ended
   * after `since` (its result says when). The list has no results: the job is read by id.
   */
  async function mineJobSince(since: number): Promise<WireJob<WireMineResult> | null> {
    const l = await http.get<{ jobs?: WireJob<unknown>[] }>('/api/v1/jobs', { retries: 1 });
    const mining = (l.jobs ?? []).filter((j) => j.kind === 'rules.mine');
    const live = mining.find((j) => j.status === 'queued' || j.status === 'running');
    if (live) return live as WireJob<WireMineResult>;
    const last = mining.find((j) => j.status === 'done');
    if (!last) return null;
    const j = await http.get<WireJob<WireMineResult>>(`/api/v1/jobs/${enc(last.job_id)}`);
    const at = Date.parse(j.result?.status?.last_run_at ?? '');
    return Number.isFinite(at) && at >= since - 5000 ? j : null;
  }

  // last assistant result per group: propose() refers to its suggestion ids
  const lastAssist = new Map<string, PolicyAssist>();

  async function assistFor(group: string): Promise<PolicyAssist | null> {
    const g = await groupOf(group);
    if (!g?.policy_id) return null;
    const pid = g.policy_id;
    const [w, all, pd] = await Promise.all([
      http.get<WireAssist>(`${FLEET}/policies/${enc(pid)}/assist`, { query: groupQuery(group) }),
      policyVersions(group).catch(() => [] as WirePolicyVersion[]),
      lazyPolicyDoc(),
    ]);
    const active = activeOf(all, pid);
    const doc = active?.author_yaml ? pd.parsePolicy(active.author_yaml) : null;
    const seen: PolicySuggestion[] = [];
    const raw: AssistService[] = (w.services ?? []).map((ws) => ({
      service: ws.service,
      kind: ws.kind === 'inbound' ? ('own' as const) : ('external' as const),
      declared: ws.declared,
      name: ws.name ?? '',
      ...(ws.host_pattern ? { hostPattern: ws.host_pattern } : {}),
      exact: !!ws.exact,
      ...(ws.base ? { base: ws.base } : {}),
      calls: ws.calls ?? 0,
      ...(typeof ws.preselect === 'boolean' ? { preselect: ws.preselect } : {}),
      ...(ws.merged_patterns?.length ? { mergedPatterns: ws.merged_patterns } : {}),
      ...(ws.stale ? { stale: true } : {}),
      ops: (ws.ops ?? []).map((wo) => ({
        op: wo.op,
        declared: wo.declared,
        calls: wo.calls,
        needCalls: wo.need_calls,
        rawOps: wo.raw_ops ?? [],
        fields: (wo.fields ?? []).map((f) => {
          const part = f.part === 'request' || f.part === 'response' ? f.part : 'response';
          // The policy names the service as declared (`name`); a host not declared yet has no rules.
          const current = doc && ws.declared ? pd.currentChoice(doc, { service: ws.name, op: wo.op, part, path: f.path }) : { action: 'drop' as const };
          const sg = mapSuggestion(f, seen.length, current);
          seen.push(sg);
          return sg;
        }),
      })),
    }));
    // The same service, operation or field twice (an old `host:` row of a service declared since): once.
    const services = dedupeAssist(raw);
    const suggestions = suggestionsOf(services);
    const out: PolicyAssist = {
      policyId: pid,
      minCalls: w.min_calls,
      ready: w.ready,
      needCalls: w.need_calls,
      hasIdentity: w.has_identity,
      ...(w.identity ? { identity: { header: w.identity.name, claim: w.identity.jwt_claim, calls: w.identity.calls, withHeader: w.identity.with_header } } : {}),
      identityCandidates: (w.identity_candidates ?? []).map(mapIdentityCandidate),
      ...(mapIdentitySource(w.identity_best) ? { identityBest: mapIdentitySource(w.identity_best) } : {}),
      ...(w.sampling
        ? {
            sampling: {
              currentBp: w.sampling.current_bp,
              sampledSubjects: w.sampling.sampled_subjects,
              source: (['subject', 'no_identity'] as const).find((s) => s === w.sampling?.source) ?? ('none' as const),
              kMin: w.sampling.k_min,
              targetSubjects: w.sampling.target_subjects,
              enough: w.sampling.enough,
              populationEstimate: w.sampling.population_estimate,
              suggestedBp: w.sampling.suggested_bp,
            },
          }
        : {}),
      services,
      suggestions,
    };
    lastAssist.set(group, out);
    return out;
  }

  /**
   * The decisions of the wizard as the body of POST .../assist/draft: the operations to declare and, per field, the
   * action when it differs from what the policy does today (drop is the default, so a new drop is not sent).
   */
  async function draftBody(input: ProposePolicyInput): Promise<{ pid: string; body: Record<string, unknown> }> {
    if (!input.group) throw new ApiError('invalid', 'The group of the policy is required.');
    const cached = lastAssist.get(input.group) ?? (await assistFor(input.group));
    if (!cached) throw new ApiError('invalid', 'The group has no policy yet: create the starter policy first.');
    const choices = new Map(input.choices.map((c) => [c.suggestionId, c.choice]));
    const wanted = input.services ?? cached.services.map((s) => ({ service: s.service, name: s.name, base: s.base, ops: s.ops.map((o) => o.op) }));
    const services = wanted.map((w) => {
      const svc = cached.services.find((s) => s.service === w.service);
      const ops = w.ops.map((op) => {
        const ao = svc?.ops.find((o) => o.op === op);
        const rules = (ao?.fields ?? []).flatMap((f) => {
          const c = choices.get(f.id);
          if (!c || actionSpec(c) === actionSpec(f.current)) return [];
          return [{ part: f.part, path: f.path, action: actionSpec(c) }];
        });
        return { op, rules };
      });
      return { service: w.service, ...(w.name ? { name: w.name } : {}), ...(svc && !svc.declared && w.base ? { base: w.base } : {}), ops };
    });
    const body: Record<string, unknown> = { services };
    if (input.hostsDiscovery) body.hosts_discovery = input.hostsDiscovery;
    if (input.identity) body.identity = { from: input.identity.from, name: input.identity.name, ...(input.identity.claim ? { jwt_claim: input.identity.claim } : {}) };
    if (input.samplingBp) body.sampling_rate_bp = input.samplingBp;
    return { pid: input.policyId ?? cached.policyId, body };
  }

  // ------------------------------------------------------------ the API
  const api: Api = {
    capabilities: { alertResolve: true, webhookToggle: true, settingsEdit: true, twinOnServer: true },
    mocks: createMockServiceRest(http, opts.sleep),
    idFormats: createIdFormatsRest(http),
    dateOffsets: createDateOffsetsRest(http),
    opKinds: createOpKindsRest(http),

    system: {
      async status() {
        const cfg = await http.get<WireAuthConfig>('/api/v1/auth/config', { quiet401: true });
        const v = await versionInfo();
        const env = v.environment === 'production' || v.environment === 'staging' || v.environment === 'development' ? v.environment : undefined;
        return {
          initialized: !cfg.setup_required,
          version: v.version ?? '',
          ...(v.installation_name ? { installation: v.installation_name } : {}),
          ...(env ? { environment: env } : {}),
          ssoEnabled: cfg.oidc,
          localEnabled: cfg.local,
          adapter: 'rest',
        };
      },
      async setup(req) {
        const m = await http.post<WireMe>('/api/v1/setup', { setup_token: req.setupToken, username: req.username, password: req.password }, { quiet401: true, noCsrf: true });
        http.setCsrf(m.csrf_token, m.csrf_header);
      },
    },

    auth: {
      me,
      async login(c) {
        const m = await http.post<WireMe>('/api/v1/auth/login', { username: c.username, password: c.password }, { quiet401: true, noCsrf: true });
        http.setCsrf(m.csrf_token, m.csrf_header);
        return mapMe(m);
      },
      ssoLogin() {
        // Full-page redirect to the identity provider; the callback comes back to "/".
        if (typeof window !== 'undefined') window.location.assign('/api/v1/auth/oidc/start?return_to=%2F');
        return new Promise(() => {});
      },
      async logout() {
        try {
          await http.post<void>('/api/v1/auth/logout', undefined, { quiet401: true });
        } finally {
          http.setCsrf(null);
        }
      },
    },

    sources: {
      async list() {
        const [ws, versions] = await Promise.all([http.get<WireSource[]>(`${FLEET}/sources`), policyVersions().catch(() => [] as WirePolicyVersion[])]);
        const rates = new Map<string, number>();
        if (ws.some((s) => s.policy)) {
          const pd = await lazyPolicyDoc();
          for (const s of ws) {
            if (!s.policy) continue;
            const key = `${s.policy.id}@${s.policy.version}`;
            if (rates.has(key)) continue;
            const v = versions.find((x) => x.policy_id === s.policy?.id && x.version === s.policy.version);
            if (!v?.author_yaml) continue;
            try {
              const doc = pd.parsePolicy(v.author_yaml);
              // Authored as a share (sampling.rate: 0.05) or in basis points (sampling.rate_bp: 500).
              const rbp = Number(doc.getIn(['sampling', 'rate_bp']));
              const bp = Number.isInteger(rbp) && rbp >= 0 && rbp <= 10000 ? rbp : samplingBpOf(doc.getIn(['sampling', 'rate']));
              if (bp !== undefined) rates.set(key, bp);
            } catch {
              /* unreadable policy: assume the full rate */
            }
          }
        }
        const kc = await http.get<WireKeyCheck>('/api/v1/sources/key-check').catch(() => null);
        return withKeyCheck(
          ws.map((s) => mapSource(s, s.policy ? rates.get(`${s.policy.id}@${s.policy.version}`) : undefined)),
          kc,
        );
      },
      async revoke(id) {
        await http.post<void>(`${FLEET}/sources/${enc(id)}/revoke`);
      },
      async setSampling(id, bp) {
        await http.put<void>(`${FLEET}/sources/${enc(id)}/sampling`, { sampling_override_bp: bp });
      },
      async kill(scope, active) {
        const s = scope.all ? { all: true } : scope.group ? { group: scope.group } : { source_id: scope.sourceId };
        await http.post<void>(`${FLEET}/kill`, { active, scope: s });
      },
    },

    onboarding: {
      async createToken(choice: SourceChoice, group: string, serviceNames?: string[], opts?: { samplingRate?: string }) {
        // Names asked for by the user. A new group without names takes the name of its first source (tt-core
        // binds it at the enrollment); an existing group is only widened.
        const asked = [...new Set((serviceNames ?? []).map((n) => n.trim()).filter(Boolean))];
        let g = await groupOf(group);
        if (!g) {
          g = await http.post<WireGroup>(`${FLEET}/groups`, { name: group, allowed_service_names: asked, policy_id: null, sampling_override_bp: null, killed: false });
        } else if (asked.some((n) => !g?.allowed_service_names.includes(n))) {
          g = await http.put<WireGroup>(`${FLEET}/groups/${enc(group)}`, {
            name: g.name,
            description: g.description ?? '',
            policy_id: g.policy_id,
            allowed_service_names: [...new Set([...g.allowed_service_names, ...asked])],
            sampling_override_bp: g.sampling_override_bp,
            killed: g.killed,
          });
        }
        // The Kubernetes card gets a token of its own kind (any SDK language), shared by every pod: a group token.
        const tok = await http.post<WireNewToken>(`${FLEET}/enrollment-tokens`, { kind: kindOfChoice(choice), group, token_type: choice === 'k8s-inject' ? 'group' : 'one_time' });
        const out = mapToken(tok, choice, group);
        if (!g.policy_id) {
          try {
            // tt-core takes the HMAC kid from keyguard and the epoch of the month; the starter policy opens no value,
            // so it is active at once (policy.md §7).
            const v = await http.post<WirePolicyVersion>(`${FLEET}/groups/${enc(group)}/starter-policy`, {
              ...(opts?.samplingRate ? { sampling_rate: opts.samplingRate } : {}),
            });
            out.starterPolicy = { policyId: v.policy_id, version: v.version };
          } catch {
            /* the operator can create it from the policies tab; the token is valid anyway */
          }
        }
        return out;
      },

      async status(tokenId) {
        return mapOnboarding(await http.get<WireOnboarding>(`${FLEET}/onboarding/${enc(tokenId)}/status`));
      },

      watch(tokenId, onStatus, onError) {
        let stopped = false;
        let es: EventSource | undefined;
        let timer: ReturnType<typeof setInterval> | undefined;
        const poll = async () => {
          try {
            const s = await api.onboarding.status(tokenId);
            if (!stopped) onStatus(s);
          } catch (e) {
            if (!stopped) onError?.(e instanceof Error ? e : new Error(String(e)));
          }
        };
        const startPolling = () => {
          if (stopped || timer) return;
          void poll();
          timer = setInterval(poll, pollMs);
        };
        if (ES) {
          try {
            es = new ES(http.url(`${FLEET}/onboarding/${enc(tokenId)}/status`), { withCredentials: true });
            es.addEventListener('status', (ev) => {
              try {
                onStatus(mapOnboarding(JSON.parse((ev as MessageEvent<string>).data) as WireOnboarding));
              } catch {
                /* a malformed frame is skipped */
              }
            });
            // The stream ends after a few minutes or on a proxy hiccup: continue by polling.
            es.onerror = () => {
              es?.close();
              es = undefined;
              startPolling();
            };
          } catch {
            startPolling();
          }
        } else startPolling();
        return () => {
          stopped = true;
          es?.close();
          if (timer) clearInterval(timer);
        };
      },

      async discovered() {
        const svcs = await http.get<WireServiceEntry[]>('/api/v1/services');
        return svcs.map((e) => ({
          name: e.service,
          kind: e.kind === 'inbound' ? ('own' as const) : ('external' as const),
          baseUrl: e.kind === 'inbound' ? undefined : exactBaseUrl(hostPatternOfService(e.service) ?? ''),
          ...(e.kind !== 'inbound' && hostPatternOfService(e.service) ? { hostPattern: hostPatternOfService(e.service) } : {}),
          calls: e.calls,
          operations: e.ops,
          proposeTwin: e.kind !== 'inbound' && e.twin,
        }));
      },

      async assist(group) {
        return (await assistFor(group)) ?? { policyId: '', minCalls: 20, ready: false, needCalls: 20, hasIdentity: false, identityCandidates: [], services: [], suggestions: [] };
      },

      async observe(group) {
        return mapObserve(await http.get<WireObserveStatus>(`${FLEET}/groups/${enc(group)}/observe`));
      },
      async setObserveAuto(group, auto) {
        return mapObserve(await http.put<WireObserveStatus>(`${FLEET}/groups/${enc(group)}/observe`, { auto }));
      },
      async setIdentity(group, identity) {
        // spec v1.18: json_path (a member of a JSON header) excludes jwt_claim.
        const path = identity.jsonPath?.trim();
        const body = {
          from: identity.from,
          name: identity.from === 'header' ? identity.name.trim().toLowerCase() : identity.name.trim(),
          ...(path ? { json_path: path } : identity.claim?.trim() ? { jwt_claim: identity.claim.trim() } : {}),
        };
        return mapPolicy(await orNoRoute('user identity choice', http.put<WirePolicyVersion>(`${FLEET}/groups/${enc(group)}/identity`, body)));
      },
      async setFamily(group, family, domains) {
        const body = { family: family.trim(), domains: domains.map((d) => d.trim()).filter(Boolean) };
        return mapPolicy(await orNoRoute('HMAC domain families', http.put<WirePolicyVersion>(`${FLEET}/groups/${enc(group)}/families`, body)));
      },
      async removeFamily(group, family) {
        return mapPolicy(await orNoRoute('HMAC domain families', http.del<WirePolicyVersion>(`${FLEET}/groups/${enc(group)}/families/${enc(family)}`)));
      },
      async setTestK(group, kMin, reason) {
        const body = { k_min: kMin, ...(reason.trim() ? { reason: reason.trim() } : {}) };
        return mapObserve(await orNoRoute('test groups', http.put<WireObserveStatus>(`${FLEET}/groups/${enc(group)}/test-k`, body)));
      },
    },

    policies: {
      async list(groups) {
        const all = await policyVersions(groups);
        return all.map((v) => {
          const before = all.filter((x) => x.policy_id === v.policy_id && x.version < v.version && (x.status === 'active' || x.status === 'superseded')).sort((a, b) => b.version - a.version)[0];
          return mapPolicy(v, before?.author_yaml ?? '');
        });
      },
      async propose(input) {
        // tt-core writes the decisions into the latest policy (comments kept) and checks the result.
        const { pid, body } = await draftBody(input);
        const prev = await http.post<WireAssistDraftResult>(`${FLEET}/policies/${enc(pid)}/assist/draft`, { ...body, dry_run: true });
        if (prev.before.trim() === prev.after.trim()) throw new ApiError('invalid', 'No change from the active policy.');
        const w = await http.post<WirePolicyVersion>(`${FLEET}/policies/${enc(pid)}/assist/draft`, body);
        return mapPolicy(w, prev.before);
      },
      async preview(input) {
        const { pid, body } = await draftBody(input);
        const r = await http.post<WireAssistDraftResult>(`${FLEET}/policies/${enc(pid)}/assist/draft`, { ...body, dry_run: true });
        return {
          before: r.before,
          after: r.after,
          skipped: [],
          ...(typeof r.opens_values === 'boolean'
            ? { opensValues: r.opens_values, valueReasons: (r.value_reasons ?? []).map((v) => ({ code: v.code, where: v.where })), approvalsRequired: r.approvals_required ?? 0 }
            : {}),
        };
      },
      async hostsDiscovery(group) {
        const g = await groupOf(group);
        if (!g?.policy_id) return 'auto';
        const active = activeOf(await policyVersions(), g.policy_id);
        if (!active?.author_yaml) return 'auto';
        return (await lazyPolicyDoc()).hostsDiscoveryOf(active.author_yaml);
      },
      async approvers(group) {
        const w = await http.get<{ approvers?: { name?: string; display_name?: string; roles?: string[]; self?: boolean }[] }>(`${FLEET}/groups/${enc(group)}/approvers`);
        return (w.approvers ?? []).map((a) => ({
          name: a.name ?? '',
          displayName: a.display_name || a.name || '',
          roles: (a.roles ?? []).filter((r): r is 'policy-approver' | 'admin' => r === 'policy-approver' || r === 'admin'),
          self: !!a.self,
        }));
      },
      async withdraw(policyId, version, reason): Promise<PolicyVersion> {
        // The body is `{note}` (admin-api 1.17.0 withdrawPolicy, no other property allowed).
        const n = reason?.trim() || undefined;
        return mapPolicy(await orNoRoute('policy withdrawal', http.post<WirePolicyVersion>(`${FLEET}/policies/${enc(policyId)}/versions/${version}/withdraw`, n ? { note: n } : undefined)));
      },
      async approve(policyId, version, reason): Promise<PolicyVersion> {
        const r = reason?.trim() || undefined;
        const w = await withStepUp({ kind: 'policy-approve', policyId, version, ...(r ? { reason: r } : {}) }, () =>
          http.post<WirePolicyVersion>(`${FLEET}/policies/${enc(policyId)}/versions/${version}/approve`, r ? { reason: r } : undefined),
        );
        return mapPolicy(w);
      },
    },

    services: {
      async list(groups) {
        const query = groupQuery(groups);
        const [svcs, srcs, reg] = await Promise.all([
          http.get<WireServiceEntry[]>('/api/v1/services', { query }),
          http.get<WireSource[]>(`${FLEET}/sources`).catch(() => [] as WireSource[]),
          http.get<WireHostsRegistry>('/api/v1/hosts', { query }).catch(() => null),
        ]);
        // Keyed by (group, service): the same host called by two groups is two entries, each with its own policy.
        // An older server without groups keys everything under "".
        const hosts = new Map<string, string>();
        const later = new Map<string, string>();
        for (const d of reg?.domains ?? [])
          for (const p of d.patterns ?? []) {
            const k = serviceKey(p.group, p.service);
            if (p.declared) hosts.set(k, p.pattern);
            else if (p.now_declared_as) later.set(k, p.now_declared_as);
          }
        const of = (m: Map<string, string>, group: string | undefined, service: string) => m.get(serviceKey(group, service)) ?? m.get(serviceKey(undefined, service));
        // Sources counted per (group, service) once (not a filter of all sources per service).
        const perService = new Map<string, number>();
        const bump = (k: string) => perService.set(k, (perService.get(k) ?? 0) + 1);
        for (const s of srcs) {
          if (s.revoked) continue;
          bump(serviceKey(s.group, s.service_name));
          bump(serviceKey('\u0001', s.service_name));
        }
        return svcs.map((e) => {
          const nowAs = of(later, e.group, e.service);
          const sources = perService.get(serviceKey(e.group ?? '\u0001', e.service)) ?? 0;
          return {
            ...serviceInfoOf(e, e.twin, sources, { get: (n) => of(hosts, e.group, n) }),
            ...(nowAs ? { nowDeclaredAs: nowAs } : {}),
          };
        });
      },
      async setTwin(name, twin, group) {
        await http.put<unknown>(`/api/v1/services/${enc(name)}/twin`, { twin, ...(group ? { group } : {}) });
      },
    },

    scope: {
      async get() {
        return mapScope(await http.get<WireScope>('/api/v1/scope'));
      },
    },

    gate: {
      async keys() {
        const w = await http.get<WireGateKeys>('/api/v1/gate/keys');
        return { value: w.tt_gate_pubkeys, command: w.command, keys: w.keys.map((k) => ({ kid: k.kid, publicKey: k.public_key })) };
      },
      async keyFile() {
        const res = await http.raw('GET', '/api/v1/gate/keys', { query: { format: 'txt' }, accept: 'text/plain', retries: 0 });
        return { filename: 'gate-keys.txt', blob: await res.blob() };
      },
    },

    hosts: {
      async list(groups) {
        return mapHosts(await http.get<WireHostsRegistry>('/api/v1/hosts', { query: groupQuery(groups) }));
      },
      async twin(input) {
        const body: Record<string, string> = {};
        if (input.policyId) body.policy_id = input.policyId;
        if (input.group) body.group = input.group;
        if (input.service?.trim()) body.service = input.service.trim();
        if (input.base?.trim()) body.base = input.base.trim();
        else if (input.scheme) body.scheme = input.scheme;
        const w = await http.post<WirePolicyVersion>(`/api/v1/hosts/${encodePattern(input.pattern)}/twin`, body);
        return mapPolicy(w);
      },
      async twinPreview(input) {
        // The same change as the assistant's draft that declares the host (dry run): the server says whether it opens
        // values. Without the host among the assistant's services (or a group) there is nothing to ask yet.
        if (!input.group) return null;
        const a = await assistFor(input.group);
        const svc = a?.services.find((s) => s.hostPattern === input.pattern || s.service === `host:${input.pattern}`);
        if (!a || !svc) return null;
        const base = input.base?.trim() || (input.scheme ? (exactBaseUrl(input.pattern, input.scheme) ?? '') : '');
        const body = {
          services: [{ service: svc.service, ...(input.service?.trim() ? { name: input.service.trim() } : svc.name ? { name: svc.name } : {}), ...(!svc.declared && base ? { base } : {}), ops: svc.ops.map((o) => ({ op: o.op, rules: [] })) }],
          dry_run: true,
        };
        const r = await http.post<WireAssistDraftResult>(`${FLEET}/policies/${enc(input.policyId ?? a.policyId)}/assist/draft`, body);
        if (typeof r.opens_values !== 'boolean') return null;
        return { opensValues: r.opens_values, valueReasons: (r.value_reasons ?? []).map((v) => ({ code: v.code, where: v.where })), approvalsRequired: r.approvals_required ?? 0 };
      },
    },

    contracts: {
      async status(service, group) {
        return mapContractStatus(await http.get<WireContractStatus>(`/api/v1/contracts/${enc(service)}/status`, { query: groupQuery(group) }));
      },
      async refreshNow(service, group) {
        // A busy service takes longer than the server's wait: the answer is
        // then a running Job (contract.snapshot) to follow, else the snapshot.
        const res = await http.post<WireJob<unknown> | { snapshot_id: string }>(`/api/v1/contracts/${enc(service)}/snapshots`, { recent: true }, { query: groupQuery(group) });
        if (res && 'job_id' in res) {
          const job = await followJob(http, res);
          if (job.status === 'failed') throw new ApiError('server', job.error || 'Snapshot failed');
        }
      },
      async operations(service, group) {
        const few = await fewSamplesFn(group);
        if (service) {
          const g = singleGroup(group);
          const ops = operationSummaries(service, await contractDoc(service, group), few(service, g));
          return g === undefined ? ops : ops.map((o) => ({ ...o, group: g }));
        }
        // One contract per (group, service): the services of the selected groups, each read with its own group.
        const svcs = await http.get<WireServiceEntry[]>('/api/v1/services', { query: groupQuery(group) });
        const all = await Promise.all(
          svcs.map(async (s) => {
            try {
              const ops = operationSummaries(s.service, await contractDoc(s.service, s.group), few(s.service, s.group));
              return s.group === undefined ? ops : ops.map((o) => ({ ...o, group: s.group }));
            } catch (e) {
              if (e instanceof ApiError && (e.code === 'not_found' || e.code === 'forbidden')) return [];
              throw e;
            }
          }),
        );
        return all.flat();
      },
      async operation(service, op, group) {
        const few = await fewSamplesFn(group);
        const d = operationDetail(service, await contractDoc(service, group), op, few(service, singleGroup(group)));
        if (!d) throw new ApiError('not_found', 'Operation not found', 404, 'not_found');
        return d;
      },
      async snapshots(service, group) {
        const infos = await http.get<WireSnapshotInfo[]>(`/api/v1/contracts/${enc(service)}/snapshots`, { query: { limit: 30, ...groupQuery(group) } });
        const asc = [...infos].sort((a, b) => a.window.to.localeCompare(b.window.to));
        return asc.map((s) => ({ id: s.snapshot_id, date: s.window.from, calls: s.calls, breaking: s.breaking, nonBreaking: s.non_breaking }));
      },
      async diff(service, from, to, group) {
        const gq = groupQuery(group);
        const d = await http.get<WireDiff>(`/api/v1/contracts/${enc(service)}/snapshots/${enc(to)}`, { query: { diff_against: from, ...gq } });
        const ops = [...new Set(d.changes.map((c) => c.op).filter((o): o is string => !!o))];
        const [a, b] = await Promise.all([
          http.get<OpenApiDoc>(`/api/v1/contracts/${enc(service)}/snapshots/${enc(d.from?.snapshot_id ?? from)}`, { query: gq }),
          http.get<OpenApiDoc>(`/api/v1/contracts/${enc(service)}/snapshots/${enc(d.to?.snapshot_id ?? to)}`, { query: gq }),
        ]);
        return {
          service,
          from: d.from?.snapshot_id ?? from,
          to: d.to?.snapshot_id ?? to,
          changes: d.changes.map((c) => ({
            severity: c.severity === 'breaking' ? ('breaking' as const) : ('non-breaking' as const),
            op: c.op ?? '',
            path: c.where,
            kind: c.kind,
            detail: c.change,
          })),
          before: fragmentOf(a, ops),
          after: fragmentOf(b, ops),
        };
      },
      async service(name, group) {
        const gq = groupQuery(group);
        const [svcs, doc, few, snaps, alerts, srcs, hosts] = await Promise.all([
          http.get<WireServiceEntry[]>('/api/v1/services', { query: gq }),
          contractDoc(name, group),
          fewSamplesFn(group),
          http.get<WireSnapshotInfo[]>(`/api/v1/contracts/${enc(name)}/snapshots`, { query: { limit: 100, ...gq } }).catch(() => [] as WireSnapshotInfo[]),
          http.get<WireAlert[]>('/api/v1/drift', { query: gq }).catch(() => [] as WireAlert[]),
          http.get<WireSource[]>(`${FLEET}/sources`).catch(() => [] as WireSource[]),
          declaredHosts(group),
        ]);
        // The row of the asked group (an older server without groups answers one row per service).
        const one = singleGroup(group);
        const entry = svcs.find((s) => s.service === name && (one === undefined || s.group === undefined || s.group === one)) ?? svcs.find((s) => s.service === name);
        if (!entry) throw new ApiError('not_found', 'Service not found', 404, 'not_found');
        const gaps = await gapsRaw(group);
        const ops = operationSummaries(name, doc, few(name, entry.group));
        const drifts = alerts.filter((a) => a.service === name).sort((a, b) => b.first_seen.localeCompare(a.first_seen));
        const mine = (gaps ?? []).filter((g) => g.service === name);
        const ofGroup = (s: WireSource) => !entry.group || s.group === entry.group;
        return {
          service: serviceInfoOf(entry, entry.twin, srcs.filter((s) => s.service_name === name && !s.revoked && ofGroup(s)).length, hosts),
          ...aggregate(ops),
          lastDrift: drifts[0] ? { at: drifts[0].first_seen, severity: drifts[0].severity === 'breaking' ? ('breaking' as const) : ('non-breaking' as const), open: drifts[0].state === 'open' } : undefined,
          coverage: {
            fewSamples: ops.filter((o) => o.fewSamples).length,
            statusesNeverSeen: mine.filter((g) => g.kind === 'status-unseen').length,
            lowSupportRules: mine.filter((g) => g.kind === 'rule-low-support').length,
          },
          snapshots: snaps.length,
        };
      },
      openapi: (service, group) => contractDoc(service, group, true),
      async postman(service, group, baseUrl) {
        const res = await http.raw('GET', `/api/v1/contracts/${enc(service)}/postman`, { query: { ...groupQuery(group), ...(baseUrl ? { base_url: baseUrl } : {}) }, accept: 'application/json', retries: 0 });
        return { filename: `${service}.postman_collection.json`, blob: await res.blob() };
      },
      rawDocument: (service, format, group) =>
        http.text('GET', `/api/v1/contracts/${enc(service)}`, { query: { format, ...groupQuery(group) }, accept: format === 'yaml' ? 'application/yaml' : 'application/json' }),
    },

    rules: {
      async list(groups) {
        return (await http.get<WireRule[]>('/api/v1/rules', { query: groupQuery(groups) })).map(mapRule);
      },
      async get(id) {
        return mapRule(await http.get<WireRule>(`/api/v1/rules/${enc(id)}`));
      },
      async setAfter(id, effectId, after): Promise<Rule> {
        return mapRule(await http.patch<WireRule>(`/api/v1/rules/${enc(id)}`, { after: { [effectId]: delayOf(after) } }));
      },
      async review(id, action, note) {
        // confirm = approve a stale rule; retire = reject it (the server has two verbs).
        if (action === 'approve' || action === 'confirm') return mapRule(await http.post<WireRule>(`/api/v1/rules/${enc(id)}/approve`));
        return mapRule(await http.post<WireRule>(`/api/v1/rules/${enc(id)}/reject`, note.trim() ? { note: note.trim() } : undefined));
      },
      async retire(id, note) {
        const n = note?.trim() || undefined;
        return mapRule(await orNoRoute('rule retirement', http.post<WireRule>(`/api/v1/rules/${enc(id)}/retire`, n ? { note: n } : undefined)));
      },
      async status(groups) {
        const w = await http.get<WireMiningStatus>('/api/v1/rules/status', { query: groupQuery(groups) });
        return {
          state: w.state,
          minHours: w.min_hours,
          observedHours: w.observed_hours,
          events: w.events,
          lastRunAt: w.last_run_at,
          ...(typeof w.subjects === 'number' ? { subjects: w.subjects } : {}),
          ...(typeof w.k_min === 'number' ? { kMin: w.k_min } : {}),
          rules: w.rules ?? {},
          warnings: w.warnings ?? [],
          diagnostics: minerExplanations(w.rule_diagnostics, w.entities),
          // admin-api 1.21.0 (rules v1.9): absent from an older server.
          ...(w.candidates ? { candidates: mapCandidates(w.candidates) } : {}),
          ...(w.families ? { families: mapFamilyCandidates(w.families) } : {}),
          ...(w.test_k && Object.keys(w.test_k).length ? { testK: { ...w.test_k } } : {}),
        };
      },
      async catalog(groups) {
        const w = await http.get<WireCatalog>('/api/v1/rules/catalog', { query: groupQuery(groups) });
        return {
          services: w.services ?? [],
          entities: (w.entities ?? []).map((e) => ({ name: e.name, service: e.service, idField: e.id_field, idDomain: e.id_domain, ops: e.ops ?? [], fields: e.fields ?? [] })),
        };
      },
      async check(def, groups) {
        const w = await http.post<WireRuleCheck>('/api/v1/rules/check', def, { query: groupQuery(groups) });
        return { valid: w.valid, problems: w.problems ?? [], warnings: w.warnings ?? [] };
      },
      async create(def, groups) {
        return mapRule(await http.post<WireRule>('/api/v1/rules', def, { query: groupQuery(groups) }));
      },
      async update(id, def, groups) {
        return mapRule(await http.put<WireRule>(`/api/v1/rules/${enc(id)}`, def, { query: groupQuery(groups) }));
      },
      async mine(onProgress) {
        const started = Date.now();
        const tell = (status: string, retrying = false) =>
          onProgress?.({ status: status === 'queued' ? 'queued' : 'running', elapsedS: Math.round((Date.now() - started) / 1000), ...(retrying ? { retrying } : {}) });
        tell('running');
        let job: WireJob<WireMineResult>;
        try {
          job = await http.post<WireJob<WireMineResult>>('/api/v1/rules/mine');
        } catch (e) {
          // The answer was lost (a proxy cut the request, the server was busy): the run may go on. Follow the mining
          // job the server has, or take the one that finished since the request; an error only when there is none.
          if (!transient(e)) throw e;
          const found = await mineJobSince(started).catch(() => null);
          if (!found) throw e;
          job = found;
        }
        tell(job.status);
        job = await followJobPatient(http, job, { sleep: opts.sleep, onStatus: (st, retrying) => tell(st, retrying) });
        if (job.status === 'failed') throw new ApiError('server', job.error || 'Mining failed', undefined, job.error || 'mining_failed');
        const r = job.result ?? {};
        const count = (n: string[] | number | undefined) => (Array.isArray(n) ? n.length : typeof n === 'number' ? n : 0);
        // Why candidates produced no rule: the miner's reasons (English, technical), without repeats.
        const reasons = [
          ...(r.rule_diagnostics ?? []).filter((d) => d.decision === 'not_mined' && d.reason).map((d) => d.reason as string),
          ...(r.entities ?? []).filter((e) => !e.accepted && e.reason).map((e) => `${e.name}: ${e.reason}`),
        ].filter((x, i, all) => all.indexOf(x) === i);
        return {
          newRules: count(r.new),
          updatedRules: count(r.updated),
          staleRules: count(r.stale),
          events: r.events ?? 0,
          state: r.status?.state ?? 'ok',
          ...(typeof r.status?.subjects === 'number' ? { subjects: r.status.subjects } : {}),
          ...(typeof r.status?.k_min === 'number' ? { kMin: r.status.k_min } : {}),
          reasons: reasons.slice(0, 8),
          warnings: r.status?.warnings ?? [],
          diagnostics: minerExplanations(r.rule_diagnostics ?? r.status?.rule_diagnostics, r.entities ?? r.status?.entities),
          ...(r.status?.last_run_at ? { finishedAt: r.status.last_run_at } : {}),
        };
      },
    },

    quarantine: {
      async list(groups) {
        return (await http.get<WireQuarantine[]>('/api/v1/quarantine', { query: groupQuery(groups) })).map(mapQuarantine);
      },
      async resolve(id, resolution, note) {
        const n = note?.trim() || undefined;
        const call = () => http.post<WireQuarantine>(`/api/v1/quarantine/${enc(id)}/resolve`, { resolution, ...(n ? { note: n } : {}) });
        // Only a dismissal opens data again and needs the step-up.
        const w = resolution === 'dismiss' ? await withStepUp({ kind: 'quarantine-dismiss', itemId: id, ...(n ? { note: n } : {}) }, call) : await call();
        return mapQuarantine(w);
      },
    },

    store: {
      async retention() {
        const r = await http.get<{ events_days: number; aggregates_days: number }>('/api/v1/store/retention');
        return { eventsDays: r.events_days, aggregatesDays: r.aggregates_days };
      },
      async setRetention(eventsDays) {
        const r = await http.put<{ events_days: number; aggregates_days: number }>('/api/v1/store/retention', { events_days: eventsDays });
        return { eventsDays: r.events_days, aggregatesDays: r.aggregates_days };
      },
      async purge(before) {
        // The purge of millions of events runs in the background: follow the job.
        let job = await http.post<WireJob<{ events: number; tokens: number }>>('/api/v1/store/purge', { before });
        for (let i = 0; (job.status === 'running' || job.status === 'queued') && i < 3600; i++) {
          await new Promise((ok) => setTimeout(ok, i < 5 ? 500 : 2000));
          job = await http.get<WireJob<{ events: number; tokens: number }>>(`/api/v1/jobs/${enc(job.job_id)}`);
        }
        if (job.status === 'failed' || !job.result) throw new ApiError('server', job.error || 'Purge failed');
        return { events: job.result.events, tokens: job.result.tokens };
      },
      async usage() {
        return mapStoreUsage(await http.get<WireStoreUsage>('/api/v1/store/usage'));
      },
      async maintenance() {
        type R = { deleted: number; reclaimed_bytes: number; level: StorageLevel };
        let job = await http.post<WireJob<R>>('/api/v1/store/maintenance', {});
        for (let i = 0; (job.status === 'running' || job.status === 'queued') && i < 3600; i++) {
          await new Promise((ok) => setTimeout(ok, i < 5 ? 500 : 2000));
          job = await http.get<WireJob<R>>(`/api/v1/jobs/${enc(job.job_id)}`);
        }
        if (job.status === 'failed' || !job.result) throw new ApiError('server', job.error || 'Maintenance failed');
        return { deleted: job.result.deleted, reclaimedBytes: job.result.reclaimed_bytes, level: job.result.level };
      },
    },

    keyguard: {
      async status() {
        const k = await http.get<Record<string, unknown>>('/api/v1/keyguard/status');
        const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
        return {
          reachable: k.reachable === true,
          hmacKids: list(k.hmac_kids),
          epochs: list(k.epochs),
          approvalsUnverified: k.approvals_unverified === true,
          matchBudgetLeft: typeof k.match_budget_left === 'number' ? k.match_budget_left : undefined,
          policyKid: typeof k.policy_kid === 'string' ? k.policy_kid : undefined,
          packKid: typeof k.pack_kid === 'string' ? k.pack_kid : undefined,
          revokedKids: list(k.revoked_kids),
          openingApprovals: typeof k.opening_approvals === 'number' ? k.opening_approvals : 2,
          adminOverride: k.admin_override === true,
          transport: typeof k.transport === 'string' ? k.transport : undefined,
        };
      },
      async audit() {
        const rows = await http.get<{ seq: number; at: string; op: string; outcome: string; detail?: Record<string, string>; hash: string }[]>('/api/v1/keyguard/audit');
        return rows.map((e) => ({ seq: e.seq, at: e.at, op: e.op, outcome: e.outcome, detail: e.detail ?? {}, hash: e.hash })).reverse();
      },
    },

    events: {
      async export(input) {
        const job = await followJob(
          http,
          await http.post<WireJob<{ format: 'ocel2-json' | 'jsonl'; bytes: number; events?: number; notice?: string; download?: string }>>('/api/v1/events/export', {
            from: input.from,
            to: input.to,
            format: input.format,
            ...(input.service ? { service: input.service } : {}),
          }),
        );
        if (job.status === 'failed' || !job.result) throw new ApiError('server', job.error || 'Event export failed');
        // A job followed in the background has its own id: the file belongs to the export's.
        const fileJob = /\/events\/export\/([^/]+)\/download$/.exec(job.result.download ?? '')?.[1] ?? job.job_id;
        return { jobId: decodeURIComponent(fileJob), format: job.result.format, bytes: job.result.bytes, events: job.result.events, notice: job.result.notice };
      },
      async download(job) {
        const res = await http.raw('GET', `/api/v1/events/export/${enc(job.jobId)}/download`, { accept: '*/*', retries: 0 });
        const cd = res.headers.get('Content-Disposition') ?? '';
        const filename = /filename="?([^";]+)"?/.exec(cd)?.[1] ?? `${job.jobId}.${job.format === 'jsonl' ? 'jsonl' : 'json'}`;
        return { filename, blob: await res.blob() };
      },
    },

    archetypes: {
      async get(group) {
        const set = await http.get<WireArchetypeList>('/api/v1/archetypes', { query: groupQuery(group) });
        return { ...(set.group !== undefined ? { group: set.group } : {}), built: set.built, kMin: set.k_min, archetypes: set.archetypes.map((a) => mapArchetype(a, set.k_min)), mergedCount: 0 };
      },
      async build(group) {
        const q = typeof group === 'string' && group ? group : undefined;
        const cur = await http.get<WireArchetypeList>('/api/v1/archetypes', { query: groupQuery(q) });
        const build = await followJob(http, await http.post<WireJob<unknown>>('/api/v1/archetypes/build', { k_min: cur.k_min, ...(q ? { group: q } : {}) }));
        if (build.status === 'failed') throw new ApiError('server', build.error || 'Archetype build failed');
        return api.archetypes.get(q);
      },
    },

    worlds: {
      async list(groups) {
        return (await http.get<WireWorld[]>('/api/v1/worlds', { query: groupQuery(groups) })).map((w) => mapWorld(w));
      },
      async generate(input) {
        const body = { seed: input.seed, customers: input.customers, ...(input.services?.length ? { services: input.services } : {}), ...(input.group ? { group: input.group } : {}) };
        let job: WireJob<WireWorld>;
        try {
          job = await followJob(http, await http.post<WireJob<WireWorld>>('/api/v1/worlds', body));
        } catch (e) {
          // No archetypes yet (first world): build them with the configured k, then try once more.
          if (!(e instanceof ApiError) || e.serverCode !== 'no_archetypes') throw e;
          const set = await http.get<WireArchetypeList>('/api/v1/archetypes', { query: groupQuery(input.group) });
          const build = await followJob(http, await http.post<WireJob<unknown>>('/api/v1/archetypes/build', { k_min: set.k_min, ...(input.group ? { group: input.group } : {}) }));
          if (build.status === 'failed') throw new ApiError('server', build.error || 'Archetype build failed');
          job = await followJob(http, await http.post<WireJob<WireWorld>>('/api/v1/worlds', body));
        }
        if (job.status === 'failed' || !job.result) throw new ApiError('server', job.error || 'World generation failed', undefined, job.error || undefined, job.details);
        return mapWorld(job.result);
      },
      async graph(worldId, customerIndex) {
        const cid = `CUS-SYN-${String(customerIndex + 1).padStart(4, '0')}`;
        const r = await http.get<{ world_id: string; customer: string; lines: Record<string, unknown>[] }>(`/api/v1/worlds/${enc(worldId)}/customers/${enc(cid)}`);
        return worldGraphOf(cid, r.lines);
      },
      async customers(worldId, query) {
        const r = await http.get<WireCustomerPage>(`/api/v1/worlds/${enc(worldId)}/customers`, {
          query: { ...(query?.q ? { q: query.q } : {}), ...(query?.offset ? { offset: String(query.offset) } : {}), ...(query?.limit ? { limit: String(query.limit) } : {}) },
        });
        return { total: r.total, all: r.all, offset: r.offset, limit: r.limit, customers: r.customers.map((c) => ({ id: c.id, name: c.name ?? '', email: c.email ?? '', archetype: c.archetype ?? '', entities: c.entities ?? {} })) };
      },
      async customer(worldId, customerId) {
        const r = await http.get<{ lines: Record<string, unknown>[] }>(`/api/v1/worlds/${enc(worldId)}/customers/${enc(customerId)}`);
        return customerDetailOf(customerId, r.lines);
      },
    },

    publications: {
      async list(groups) {
        const ps = await http.get<WirePack[]>('/api/v1/packs', { query: groupQuery(groups) });
        return ps.map(mapPack).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      },
      async get(id) {
        return mapPack(await http.get<WirePack>(`/api/v1/packs/${enc(id)}`));
      },
      async run(worldId, o) {
        // The services to twin are the server's stored selection (no list in the request).
        const job = await followJob(
          http,
          await http.post<WireJob<WirePack>>('/api/v1/packs', {
            world_id: worldId,
            ...(o?.validDays ? { valid_days: o.validDays } : {}),
            ...(o?.services?.length ? { services: o.services } : {}),
            ...(o?.excludeServices?.length ? { exclude_services: o.excludeServices } : {}),
            ...(o?.group ? { group: o.group } : {}),
            ...(o?.multiGroup ? { multi_group: true } : {}),
          }),
        );
        if (job.status === 'failed' || !job.result) throw new ApiError('server', job.error || 'Pack build failed');
        return mapPack(job.result);
      },
      async publish(id, o): Promise<Publication> {
        const r = o?.reason?.trim() || undefined;
        return mapPack(
          await withStepUp({ kind: 'pack-publish', packId: id, ...(r ? { reason: r } : {}) }, () =>
            http.post<WirePack>(`/api/v1/packs/${enc(id)}/publish`, r ? { reason: r } : undefined),
          ),
        );
      },
      async download(id) {
        const res = await http.raw('GET', `/api/v1/packs/${enc(id)}/download`, { accept: 'application/gzip', retries: 0 });
        const cd = res.headers.get('Content-Disposition') ?? '';
        const filename = /filename="?([^";]+)"?/.exec(cd)?.[1] ?? `${id}.ttpack`;
        return { filename, blob: await res.blob() };
      },
      async export(id, target: ExportTarget) {
        let job = await orUnsupported('pack export', http.post<WireJob<{ export_id?: string; report?: unknown }> & { export_id?: string }>('/api/v1/exports', { pack_id: id, target }));
        // A long export answered as a running core job (admin-api 1.9.0): follow it first.
        if ((job.status === 'running' || job.status === 'queued') && !(job.result?.export_id ?? job.export_id)) job = { ...(await followJob(http, job)) };
        if (job.status === 'failed') throw new ApiError('server', job.error || 'The export failed');
        const exportId = job.result?.export_id ?? job.export_id;
        let report: unknown = job.result?.report;
        // The answer of a synchronous job is final; a server that answers "running" is polled.
        for (let i = 0; report === undefined && exportId && i < 40; i++) {
          const r = await http.get<{ status: string; report?: unknown }>(`/api/v1/exports/${enc(exportId)}`);
          if (r.status === 'failed') throw new ApiError('server', 'The export failed');
          if (r.status === 'done') report = r.report;
          else await new Promise((res) => setTimeout(res, 1000));
        }
        if (report === undefined) throw new ApiError('unavailable', 'The export is taking too long');
        return { ...mapExportReport(target, report), exportId };
      },
      async downloadExport(exportId) {
        const res = await http.raw('GET', `/api/v1/exports/${enc(exportId)}/download`, { accept: 'application/zip', retries: 0 });
        const cd = res.headers.get('Content-Disposition') ?? '';
        return { filename: /filename="?([^";]+)"?/.exec(cd)?.[1] ?? `${exportId}.zip`, blob: await res.blob() };
      },
    },

    scenarios: {
      async list() {
        return (await orUnsupported('scenario presets', http.get<WirePreset[]>('/api/v1/scenario-presets'))).map(presetFromWire);
      },
      async save(p) {
        if (p.id) return presetFromWire(await http.put<WirePreset>(`/api/v1/scenario-presets/${enc(p.id)}`, presetToWire(p)));
        // A new preset gets its id from the name (the server wants ^[a-z0-9][a-z0-9-]{0,62}$); a taken id gets a suffix.
        const slug = p.name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 56) || 'preset';
        for (let i = 0; ; i++) {
          const id = i === 0 ? slug : `${slug}-${i + 1}`;
          try {
            return presetFromWire(await http.post<WirePreset>('/api/v1/scenario-presets', presetToWire({ ...p, id })));
          } catch (e) {
            if (!(e instanceof ApiError && e.code === 'conflict') || i >= 20) throw e;
          }
        }
      },
      async remove(id) {
        await http.del<void>(`/api/v1/scenario-presets/${enc(id)}`);
      },
    },

    alerts: {
      async list(groups) {
        const all = await http.get<WireAlert[]>('/api/v1/drift', { query: { kind: 'all', limit: 1000, ...groupQuery(groups) } });
        return all.map(mapAlert).sort((a, b) => b.firstSeen.localeCompare(a.firstSeen));
      },
      async setState(id, state) {
        if (state === 'open') throw new ApiError('invalid', 'An alert cannot be reopened.');
        await http.patch<unknown>(`/api/v1/drift/${enc(id)}`, { state });
      },
    },

    webhooks: {
      async list() {
        const ws = await http.get<WireWebhook[]>('/api/v1/webhooks');
        return Promise.all(
          ws.map(async (w) => {
            const last = await http.get<WireDelivery[]>(`/api/v1/webhooks/${enc(w.webhook_id)}/deliveries`, { query: { limit: 1 } }).catch(() => [] as WireDelivery[]);
            return mapWebhook(w, last[0]);
          }),
        );
      },
      async save(w) {
        const body = { name: w.name, url: w.url, events: w.events, enabled: w.enabled };
        const out = w.id ? await http.put<WireWebhook>(`/api/v1/webhooks/${enc(w.id)}`, body) : await http.post<WireWebhook>('/api/v1/webhooks', body);
        return mapWebhook(out);
      },
      async remove(id) {
        await http.del<void>(`/api/v1/webhooks/${enc(id)}`);
      },
      async test(id) {
        const ws = await http.get<WireWebhook[]>('/api/v1/webhooks');
        const w = ws.find((x) => x.webhook_id === id);
        if (!w) throw new ApiError('not_found', 'Webhook not found', 404, 'not_found');
        const at = now().toISOString();
        try {
          await http.post<void>(`/api/v1/webhooks/${enc(id)}/test`);
          return { ...mapWebhook(w), lastDelivery: { at, ok: true, httpStatus: 204 } };
        } catch (e) {
          if (e instanceof ApiError && e.serverCode === 'delivery_failed') return { ...mapWebhook(w), lastDelivery: { at, ok: false, httpStatus: 502 } };
          throw e;
        }
      },
    },

    audit: {
      async list() {
        // The newest entries, read from the end of the log (no walk from the first one).
        const text = await http.text('GET', '/api/v1/audit/export', { query: { last: 500 }, accept: 'application/x-ndjson' });
        return parseNdjson<WireAuditEntry>(text)
          .map(mapAuditEntry)
          .sort((a, b) => b.seq - a.seq);
      },
      async verify() {
        return mapAuditVerify(await http.get<WireAuditVerify>('/api/v1/audit/verify'), now());
      },
    },

    users: {
      async list() {
        return (await orUnsupported('user management', http.get<WireUser[]>('/api/v1/users'))).map(mapUser);
      },
      async roles() {
        return (Object.keys(ROLE_PERMISSIONS) as Role[]).map((role) => ({ role, permissions: ROLE_PERMISSIONS[role] }));
      },
      async create(u) {
        const body = { username: u.username, display_name: u.displayName, roles: u.roles, ...(u.password ? { password: u.password } : {}) };
        return mapUser(await orUnsupported('user management', http.post<WireUser>('/api/v1/users', body)));
      },
      async update(id, patch) {
        const { revokeSessions, ...rest } = patch;
        return mapUser(await http.patch<WireUser>(`/api/v1/users/${enc(id)}`, { ...rest, ...(revokeSessions ? { revoke_sessions: true } : {}) }));
      },
    },

    settings: {
      async get(): Promise<Settings> {
        let w: WireApprovalSettings | undefined;
        try {
          w = await http.get<WireApprovalSettings>(`${FLEET}/approval-settings`);
        } catch (e) {
          // Roles without access to the fleet settings still get a page; strict defaults, as the server assumes.
          if (!(e instanceof ApiError && e.code === 'forbidden')) throw e;
        }
        let server: WireSettings | undefined;
        try {
          server = await http.get<WireSettings>('/api/v1/settings');
        } catch (e) {
          // Only admin and operator read them; the other roles still get the approvals.
          if (!(e instanceof ApiError && (e.code === 'forbidden' || e.code === 'not_found'))) throw e;
        }
        return {
          approvals: {
            openingRequired: w?.opening_required === 1 ? 1 : 2,
            adminOverride: w?.admin_override ?? false,
            identitiesVerified: w ? !w.approvals_unverified : false,
            ...(w?.known === false || !w ? { known: false as const } : {}),
          },
          ...(server ? { server: mapServerSettings(server) } : {}),
        };
      },
      async save(s) {
        // Only the two labels travel: everything else is configuration (the server refuses other fields).
        if (!s.server) throw new ApiError('unsupported', 'This server has no editable settings.');
        const out = await http.patch<WireSettings>('/api/v1/settings', { installation_name: s.server.installation, environment: s.server.environment ?? '' });
        versionCache = null;
        return { approvals: s.approvals, server: mapServerSettings(out) };
      },
    },

    fleet: {
      async signingKeys() {
        return (await http.get<WireSigningKey[]>(`${FLEET}/signing-keys`)).map(mapSigningKey);
      },
      async revokeSigningKey(kid) {
        await http.post<void>(`${FLEET}/signing-keys/${enc(kid)}/revoke`);
      },
    },

    gaps: {
      async list(groups) {
        return mapGaps(await http.get<WireGap[]>('/api/v1/gaps', { query: groupQuery(groups) }));
      },
    },
  };

  return api;
}

// ---------------------------------------------------------------- helpers

interface WireQuarantine {
  item_id: string;
  group?: string;
  kind: string;
  service: string;
  op?: string;
  where: string;
  alert?: string;
  distinct_estimate: number;
  state: string;
  since: string;
  approvals?: { by: string; at: string }[];
}

/** The one group of a selection, if it names exactly one. */
function singleGroup(g: GroupSel): string | undefined {
  const q = groupQuery(g).group;
  return q && !q.includes(',') ? q : undefined;
}

/**
 * The miner's diagnostics as explanations for a person: one per rule candidate that produced no rule (or was
 * proposed), plus the entity candidates that are references (a member id: never blocking) or were dropped.
 */
export function minerExplanations(rules: WireRuleDiag[] | undefined, entities: WireEntityDiag[] | undefined): MinerExplanation[] {
  const out: MinerExplanation[] = [];
  const seen = new Set<string>();
  for (const d of rules ?? []) {
    if (d.decision !== 'not_mined' && d.decision !== 'proposed') continue;
    const code = d.code ?? (d.decision === 'proposed' ? 'mined' : 'other');
    const k = `${d.service ?? ''} ${d.op ?? ''} ${d.entity ?? ''} ${code}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ kind: 'rule', code, service: d.service ?? '', op: d.op ?? '', entity: d.entity ?? '', causes: d.causes ?? 0, decided: d.decided ?? 0, subjects: d.subjects ?? 0, horizonS: d.horizon_s ?? 0, reason: d.reason ?? '', ...(d.values === 'in_clear' || d.values === 'dropped' ? { values: d.values } : {}), ...(d.clear_fields?.length ? { clearFields: d.clear_fields } : {}) });
  }
  for (const e of entities ?? []) {
    if (e.accepted) continue;
    const [service, ...op] = (e.op ?? '').split(' ');
    out.push({ kind: 'entity', code: e.reference ? 'reference' : (e.code ?? 'other'), service: service ?? '', op: op.join(' '), entity: e.name, causes: e.born ?? 0, decided: 0, subjects: 0, horizonS: 0, reason: e.reason });
  }
  return out;
}

function mapQuarantine(q: WireQuarantine): QuarantineItem {
  const state = q.state === 'dismiss-pending' || q.state === 'resolved' ? q.state : 'quarantined';
  return { id: q.item_id, ...(q.group !== undefined ? { group: q.group } : {}), kind: q.kind, service: q.service, op: q.op, where: q.where, ...(q.alert === 'host_cardinality' || q.alert === 'value_cardinality' ? { alert: q.alert } : {}), distinctEstimate: q.distinct_estimate, state, since: q.since, approvals: q.approvals ?? [] };
}

/** "5m" -> "5m"; "1h–2d" (or "1h-2d", "1h to 2d") -> {min, max}. The server checks the durations and min <= max. */
export function delayOf(text: string): string | { min: string; max: string } {
  const m = /^\s*(\S+?)\s*(?:–|—|-|\.\.|to)\s*(\S+?)\s*$/.exec(text);
  return m ? { min: m[1], max: m[2] } : text.trim();
}

function presetFromWire(w: WirePreset): ScenarioPreset {
  return {
    id: w.preset_id,
    name: w.name,
    description: w.description ?? '',
    builtin: false,
    faults: (w.faults?.rules ?? []).map((r) => ({ service: r.service, op: r.op, status: r.status ?? 0, p: r.p ?? 1 })),
    forcedOutcomes: (w.outcomes ?? []).map((o) => ({ rule: o.rule, outcome: o.outcome })),
    // custom: only the listed faults (the observed random ones off); off: no fault at all.
    deterministic: w.faults?.mode === 'off' || w.faults?.mode === 'custom',
    ...(w.faults?.mode === 'off' && (w.faults.rules?.length ?? 0) > 0 ? { faultsIgnored: true } : {}),
  };
}

/**
 * The session faults of a preset. A preset with its own faults is `custom` (they fire, the observed random ones do
 * not); without: `off` for repeatable tests, `observed` to keep the faults copied from the traffic. `off` with faults
 * would switch the preset's own faults off too (usability test #4, M4).
 */
export function presetFaultsMode(p: Pick<ScenarioPreset, 'deterministic' | 'faults'>): 'custom' | 'off' | 'observed' {
  if (p.faults.length) return 'custom';
  return p.deterministic ? 'off' : 'observed';
}

function presetToWire(p: ScenarioPreset): Record<string, unknown> {
  const mode = presetFaultsMode(p);
  return {
    ...(p.id ? { preset_id: p.id } : {}),
    name: p.name,
    description: p.description,
    faults: { mode, ...(p.faults.length ? { rules: p.faults.map((f) => ({ service: f.service, op: f.op, status: f.status, p: f.p })) } : {}) },
    outcomes: p.forcedOutcomes.map((o) => ({ rule: o.rule, outcome: o.outcome })),
  };
}

/** Graph of one customer from the preview lines of world.jsonl (customer, entity, history). */
export function worldGraphOf(customerId: string, lines: Record<string, unknown>[]): WorldGraph {
  const customer = lines.find((l) => l.type === 'customer');
  const nodes: WorldNode[] = [{ id: customerId, type: 'customer', label: customerId, state: typeof customer?.archetype === 'string' ? customer.archetype : undefined }];
  const entities = lines.filter((l) => l.type === 'entity' && typeof l.id === 'string');
  const ids = new Set(entities.map((e) => String(e.id)));
  // An entity a rule created has history rows with a rule id from the start; the one an operation
  // created (the order) has not. The first is the child of the second.
  const ruleOf = new Map<string, string>();
  for (const l of lines) if (l.type === 'history' && typeof l.rule_id === 'string' && typeof l.id === 'string' && !ruleOf.has(l.id)) ruleOf.set(l.id, l.rule_id);
  const entityOf = new Map(entities.map((e) => [String(e.id), String(e.entity)]));
  for (const e of entities) {
    const id = String(e.id);
    const state = (e.state ?? {}) as Record<string, unknown>;
    nodes.push({ id, type: String(e.entity), label: id, state: typeof state.status === 'string' ? state.status : undefined });
  }
  const rank = (id: string): [number, string, string] => [ruleOf.has(id) ? 1 : 0, entityOf.get(id) ?? '', id];
  const before = (a: string, b: string): boolean => {
    const x = rank(a);
    const y = rank(b);
    return x[0] !== y[0] ? x[0] < y[0] : x[1] !== y[1] ? x[1] < y[1] : x[2] < y[2];
  };
  const pairs = new Map<string, WorldGraph['edges'][number]>();
  for (const e of entities) {
    const id = String(e.id);
    for (const v of Object.values((e.state ?? {}) as Record<string, unknown>)) {
      if (typeof v !== 'string' || v === id || !ids.has(v)) continue;
      const [parent, child] = before(id, v) ? [id, v] : [v, id];
      pairs.set(`${parent}\u0000${child}`, { from: parent, to: child, rule: ruleOf.get(child) });
    }
  }
  const edges = [...pairs.values()];
  const children = new Set(edges.map((e) => e.to));
  for (const e of entities) if (!children.has(String(e.id))) edges.unshift({ from: customerId, to: String(e.id) });
  return { customerId, archetype: nodes[0].state ?? '', nodes, edges };
}
