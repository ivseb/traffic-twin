// Pure mapping from the Go payloads (wire.ts) to the UI domain types (types.ts).

import type {
  StoreUsage,
  AlertType,
  Archetype,
  AuditEntry,
  AuditVerification,
  DiffEntry,
  DriftAlert,
  EnrollmentToken,
  Gap,
  GateCheck,
  HostDomain,
  HostEntry,
  HostsDiscovery,
  HostsRegistry,
  OnboardingStatus,
  PolicyActionKind,
  PolicyChoice,
  PolicyVersion,
  ObserveStatus,
  IdentityCandidate,
  IdentitySource,
  Problem,
  Publication,
  ResidualRisk,
  Role,
  Rule,
  ServerSettings,
  RuleEffect,
  RuleEffectDef,
  RuleDefinition,
  SigningKey,
  Snippet,
  Source,
  SourceChoice,
  SourceKind,
  SourceState,
  User,
  Webhook,
  World,
  CheckId,
  CheckStatus,
  PackStatus,
  ExportReport,
  ExportTarget,
  ContractStatus,
  ScopeData,
  GroupSel,
  RuleMatch,
  MinerCandidate,
  FamilyCandidate,
} from '../types';
import { groupNames } from '../types';
import type {
  WireStoreUsage,
  WireAlert,
  WireArchetype,
  WireAuditEntry,
  WireAuditVerify,
  WireDelay,
  WireDelivery,
  WireGap,
  WireHostPattern,
  WireHostsRegistry,
  WireMe,
  WireNewToken,
  WireOnboarding,
  WirePack,
  WirePolicyVersion,
  WireObserveStatus,
  WireIdentityCandidate,
  WirePrincipal,
  WireProblem,
  WireRule,
  WireSettings,
  WireSigningKey,
  WireSource,
  WireSuggestion,
  WireUser,
  WireWebhook,
  WireWorld,
  WireScope,
  WireContractStatus,
  WireKeyCheck,
  WireMatch,
  WireCandidate,
  WireFamilyCandidate,
} from './wire';
import type { PolicySuggestion } from '../types';
import { tk } from '../../i18n/index.svelte';
import { localizeSnippet, snippetTitle } from './snippets';

export const EPOCH_ISO = '1970-01-01T00:00:00.000Z';

/**
 * Query of a group selection: `{group: 'a,b'}`, or nothing for every group (null, undefined, no names). The group ""
 * of a source of unknown group is not a filter.
 */
export function groupQuery(g: GroupSel): { group?: string } {
  const names = groupNames(g);
  return names ? { group: names.join(',') } : {};
}

export const KNOWN_ROLES: readonly Role[] = ['admin', 'operator', 'rule-reviewer', 'policy-approver', 'publisher', 'auditor', 'event-exporter'];

export function mapRoles(roles: readonly string[] | undefined): Role[] {
  return (roles ?? []).filter((r): r is Role => (KNOWN_ROLES as readonly string[]).includes(r));
}

// ---------------------------------------------------------------- users

export function mapPrincipal(p: WirePrincipal, roles?: readonly string[]): User {
  return {
    id: p.id,
    username: p.username || p.display_name,
    displayName: p.display_name || p.username || p.id,
    roles: mapRoles(roles ?? p.roles),
    authMethod: p.auth_method === 'local' ? 'local' : 'sso',
  };
}
export function mapMe(m: WireMe): User {
  return mapPrincipal(m.user, m.roles);
}
export function mapUser(u: WireUser): User {
  return { id: u.id, username: u.username, displayName: u.display_name || u.username, roles: mapRoles(u.roles), authMethod: u.auth_method === 'local' ? 'local' : 'sso', disabled: u.disabled };
}

// ---------------------------------------------------------------- sources

const SOURCE_STATES: readonly SourceState[] = ['starting', 'capturing', 'no_policy', 'policy_rejected', 'key_missing', 'key_mismatch', 'killed', 'expired_policy'];

/** The server's English text is replaced by the console's translation of the code (problem.<code>, problem.<code>.hint). */
export function mapProblem(p: WireProblem): Problem {
  return { code: p.code as Problem['code'], message: tk(`problem.${p.code}`, undefined, p.message), hint: p.hint === undefined ? undefined : tk(`problem.${p.code}.hint`, undefined, p.hint) };
}

export function mapSource(s: WireSource, policyRateBp = 10000): Source {
  const state = (SOURCE_STATES as readonly string[]).includes(s.state) ? (s.state as SourceState) : 'capturing';
  const hasOverhead = s.overhead_us && (s.overhead_us.p50 !== undefined || s.overhead_us.p99 !== undefined);
  const override = s.sampling_override_bp;
  return {
    id: s.source_id,
    kind: s.kind as SourceKind,
    version: s.version,
    updateAvailable: false,
    serviceName: s.service_name,
    group: s.group,
    instance: s.instance ?? '',
    instances: 1,
    state,
    killed: s.killed,
    revoked: s.revoked,
    policy: s.policy ? { id: s.policy.id, version: s.policy.version } : undefined,
    lastSeen: s.last_seen ?? EPOCH_ISO,
    eventsPerMin: s.events_per_min,
    dropRatio: s.drop_ratio,
    overheadUs: hasOverhead ? { p50: s.overhead_us?.p50 ?? 0, p99: s.overhead_us?.p99 ?? 0 } : undefined,
    samplingBp: override ?? policyRateBp,
    policyRateBp,
    problems: s.problems.map(mapProblem),
    lastErrors: s.last_errors.map((e) => ({ code: e.code, at: e.last_seen ?? e.at, firstSeen: e.first_seen, count: e.count })),
    series: [],
  };
}

/** Sampling rate (0..1, at most 4 decimals) of an author policy, in basis points. */
export function samplingBpOf(rate: unknown): number | undefined {
  const n = typeof rate === 'number' ? rate : typeof rate === 'string' ? Number(rate) : NaN;
  if (!Number.isFinite(n) || n < 0 || n > 1) return undefined;
  return Math.round(n * 10000);
}

// ---------------------------------------------------------------- onboarding

/**
 * SourceChoice -> the kind a token is created for (Fleet API). The Kubernetes injection card has a kind of its
 * own: its token enrolls the SDK of any language, since each workload picks it with a pod annotation.
 */
export function kindOfChoice(choice: SourceChoice): SourceKind | 'k8s-inject' {
  return choice;
}

export function mapToken(w: WireNewToken, choice: SourceChoice, group: string, extra: Snippet[] = []): EnrollmentToken {
  return {
    tokenId: w.token_id,
    token: w.token,
    expiresAt: w.expires_at,
    choice,
    group,
    snippets: [...w.snippets.map((s) => ({ title: snippetTitle(s.id, s.title), language: normLang(s.language), text: localizeSnippet(s.text) })), ...extra],
  };
}

function normLang(l: string): Snippet['language'] {
  return l === 'bash' || l === 'yaml' || l === 'dockerfile' ? l : 'text';
}

export function mapOnboarding(o: WireOnboarding): OnboardingStatus {
  return {
    enrolled: o.steps.enrolled,
    policyReceived: o.steps.policy_received,
    firstEvents: o.steps.first_events,
    problems: o.problems.map(mapProblem),
  };
}

// ---------------------------------------------------------------- policies

/** "hmac(order)" / "bucket(num, [0, 10])" / "keep" -> PolicyChoice. */
export function parseAction(spec: string | undefined | null): PolicyChoice {
  const s = (spec ?? 'drop').trim();
  let m = /^hmac(?:\(\s*([a-z][a-z0-9_-]*)\s*\))?$/.exec(s);
  if (m) return { action: 'hmac', arg: m[1] ?? 'id' };
  m = /^bucket\(\s*num\s*,\s*\[(.*)\]\s*\)$/.exec(s);
  if (m) return { action: 'bucket', arg: m[1].trim() };
  m = /^bucket\(\s*time\s*,\s*([a-z]+)\s*\)$/.exec(s);
  if (m) return { action: 'bucket', arg: `time:${m[1]}` };
  // The assistant writes "bucket(time, day)" and "bucket(num, [..])"; anything else is kept as typed.
  if (s === 'keep') return { action: 'keep' };
  if (s === 'code') return { action: 'code' };
  // spec v1.19 (sanitizer.md 5.6): the code shape with digits
  if (/^code\(\s*alnum\s*\)$/.test(s)) return { action: 'code', arg: 'alnum' };
  if (s === 'drop') return { action: 'drop' };
  const bare = /^(\w+)/.exec(s)?.[1];
  const act = (['drop', 'keep', 'code', 'hmac', 'bucket'] as PolicyActionKind[]).find((a) => a === bare);
  return { action: act ?? 'drop', arg: act && act !== 'drop' && act !== 'keep' && act !== 'code' ? s : undefined };
}

/** PolicyChoice -> the action as written in an author policy. */
export function actionSpec(c: PolicyChoice): string {
  if (c.action === 'hmac') return c.arg && c.arg !== 'id' ? `hmac(${c.arg})` : 'hmac';
  if (c.action === 'bucket') {
    const a = (c.arg ?? '').trim();
    if (a.startsWith('time:')) return `bucket(time, ${a.slice(5)})`;
    if (a.startsWith('bucket(')) return a;
    return `bucket(num, [${a}])`;
  }
  if (c.action === 'code' && c.arg === 'alnum') return 'code(alnum)';
  return c.action;
}

export function mapSuggestion(w: WireSuggestion, i: number, current: PolicyChoice): PolicySuggestion {
  const part = w.part === 'request' || w.part === 'response' ? w.part : 'response';
  return {
    id: `sg-${i + 1}`,
    service: w.service,
    op: w.op,
    part,
    path: w.path,
    shape: w.shape,
    observed: w.observed,
    distinct: w.distinct_estimate,
    suggestion: parseAction(w.suggestion),
    current,
    reason: w.reason,
    ...(w.reason_code ? { reasonCode: w.reason_code } : {}),
  };
}

function mapDiff(d: { change: string; where: string; from?: string; to?: string }): DiffEntry {
  const change = d.change === 'added' || d.change === 'removed' ? d.change : 'changed';
  return { change, where: d.where, from: d.from, to: d.to };
}

export function mapPolicy(w: WirePolicyVersion, yamlBefore = ''): PolicyVersion {
  // admin-api 1.17.0 says a withdrawn draft as `rejected` + `withdrawn: true`; a plain `withdrawn` status is read too.
  const status = w.status === 'rejected' && w.withdrawn ? 'withdrawn' : ((['draft', 'active', 'superseded', 'rejected', 'withdrawn'] as const).find((s) => s === w.status) ?? 'draft');
  const mode = (['admin', 'single', 'standard', 'observe'] as const).find((m) => m === w.approval_mode);
  const valueReasons = (w.value_reasons ?? []).map((r) => ({ code: r.code, where: r.where }));
  return {
    policyId: w.policy_id,
    version: w.version,
    status,
    proposedBy: w.proposed_by || undefined,
    proposedAt: w.proposed_at,
    groups: w.groups ?? w.targets?.groups ?? [],
    origin: w.origin as PolicyVersion['origin'],
    opensData: w.classification === 'opening',
    // Older servers (before spec v1.6) do not say: an opening change counts as opening values.
    opensValues: typeof w.opens_values === 'boolean' ? w.opens_values : w.classification === 'opening',
    valueReasons,
    approvalsRequired: w.approvals_required === 0 ? 0 : w.approvals_required === 1 ? 1 : 2,
    approvals: (w.approvals ?? []).map((a) => ({
      by: a.by,
      at: a.at,
      mode: a.admin_override ? 'admin' : 'standard',
      reason: a.reason,
      ...(typeof a.token_fresh === 'boolean' ? { tokenFresh: a.token_fresh } : {}),
    })),
    approvalMode: mode,
    diff: (w.diff ?? []).map(mapDiff),
    yamlBefore,
    yamlAfter: w.author_yaml ?? '',
    hash: w.hash,
  };
}

export function mapSigningKey(k: WireSigningKey): SigningKey {
  return {
    kid: k.kid,
    alg: k.alg,
    publicKey: k.public_key,
    endorsedBy: k.endorsed_by,
    revoked: k.revoked,
    active: k.active ?? false,
    trustedBy: k.trusted_by ?? 0,
    revoke: k.revoke
      ? { seen: k.revoke.seen_sources, confirmed: k.revoke.confirmed_sources, required: k.revoke.required_fraction, ok: k.revoke.ok, blocker: k.revoke.blocker }
      : undefined,
  };
}

// ---------------------------------------------------------------- gaps

const GAP_KIND: Record<string, Gap['kind']> = {
  'few-samples': 'few-samples',
  'status-unseen': 'status-never-seen',
  'rule-low-support': 'low-support-rule',
  'value-unknown': 'value-unknown',
  'entity-without-creator': 'entity-without-creator',
};

export function mapGaps(ws: WireGap[]): Gap[] {
  return ws.map((g) => ({
    id: g.id,
    ...(g.group !== undefined ? { group: g.group } : {}),
    kind: GAP_KIND[g.kind] ?? 'few-samples',
    scope: g.scope === 'field' ? ('field' as const) : ('op' as const),
    service: g.service || undefined,
    op: g.op || undefined,
    count: g.count ?? 0,
    threshold: g.threshold || undefined,
    detail: g.detail,
  }));
}

// ---------------------------------------------------------------- alerts, webhooks

export function mapAlert(a: WireAlert): DriftAlert {
  const type: AlertType = a.kind === 'rule.stale' ? 'rule.stale' : 'contract.drift';
  const sev = a.severity === 'breaking' || a.severity === 'non-breaking' ? a.severity : 'info';
  const state = a.state === 'acknowledged' || a.state === 'resolved' ? a.state : 'open';
  return {
    id: a.drift_id,
    ...(a.group !== undefined ? { group: a.group } : {}),
    type,
    severity: sev,
    service: a.service,
    op: a.op || undefined,
    change: a.change,
    firstSeen: a.first_seen,
    callsAfterChange: a.evidence?.calls_after_change,
    state,
  };
}

export function mapWebhook(w: WireWebhook, last?: WireDelivery): Webhook {
  return {
    id: w.webhook_id,
    name: w.name,
    url: w.url,
    events: (w.events ?? []) as AlertType[],
    enabled: w.enabled !== false,
    secretSet: w.secret_set,
    secret: w.secret,
    lastDelivery: last && last.state !== 'pending' ? { at: last.created_at, ok: last.state === 'delivered', httpStatus: last.last_status ?? 0 } : undefined,
  };
}

// ---------------------------------------------------------------- rules

const delayText = (d: WireDelay): string => (typeof d === 'string' ? d : `${d.min}–${d.max}`);
const valueText = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v));
const mapValues = (o: Record<string, unknown> | undefined): Record<string, string> => Object.fromEntries(Object.entries(o ?? {}).map(([k, v]) => [k, valueText(v)]));
const refText = (r: { from: string; path?: string; name?: string; field?: string }): string => `${r.from} ${r.path ?? r.name ?? r.field ?? ''}`.trim();

/** The editable definition of a rule: the rules.v1 object without the header the server owns. */
export function ruleDefinition(r: WireRule): RuleDefinition {
  if (r.kind === 'batch') {
    return { kind: 'batch', title: r.title, schedule: r.schedule ?? '', entity: r.entity ?? '', where: r.where ?? {}, set: r.set ?? {}, fraction: r.fraction ?? 1 };
  }
  // Rules v1.9: the conditions of the cause and of the outcomes stay in the definition (the editor round trip).
  const match = r.cause?.when?.match?.length ? { match: matchesOf(r.cause.when.match) } : {};
  return {
    kind: 'causal',
    title: r.title,
    cause: r.cause ? { service: r.cause.service, op: r.cause.op, when: { status: [...(r.cause.when?.status ?? [])], ...match }, bind: { ...(r.cause.bind ?? {}) } } : undefined,
    effects: (r.effects ?? []).map((e) => JSON.parse(JSON.stringify(e)) as RuleEffectDef),
    outcomes: (r.outcomes ?? []).map((o) => ({ name: o.name, p: o.p, effects: [...o.effects], ...(o.when?.length ? { when: matchesOf(o.when) } : {}) })),
  };
}

/** A copy of the conditions of a rule (rules v1.9). */
export const matchesOf = (ms: WireMatch[]): RuleMatch[] => ms.map((m) => JSON.parse(JSON.stringify(m)) as RuleMatch);

/** The candidates and domain families of a mining status (admin-api 1.21.0); empty from an older server. */
export function mapCandidates(w: WireCandidate[] | null | undefined): MinerCandidate[] {
  return (w ?? []).map((c) => ({
    ...(c.group ? { group: c.group } : {}),
    signature: c.signature,
    kind: c.kind,
    template: c.template,
    service: c.service,
    op: c.op,
    ...(c.entity ? { entity: c.entity } : {}),
    ...(c.fields?.length ? { fields: [...c.fields] } : {}),
    ...(c.states?.length ? { states: [...c.states] } : {}),
    ...(c.status ? { status: c.status } : {}),
    ...(c.target ? { target: c.target } : {}),
    subjects: c.subjects,
    ...(c.draft ? { draft: ruleDefinition(c.draft) } : {}),
    ...(c.missing_entities?.length ? { missingEntities: [...c.missing_entities] } : {}),
  }));
}

export function mapFamilyCandidates(w: WireFamilyCandidate[] | null | undefined): FamilyCandidate[] {
  return (w ?? []).map((f) => ({ ...(f.group ? { group: f.group } : {}), domains: [...f.domains], subjects: f.subjects, signals: [...(f.signals ?? [])], score: f.score }));
}

export function mapRule(r: WireRule): Rule {
  // Out of the packs on purpose: `superseded` (replaced at the approval of a newer rule) or `rejected` + `retired: true`
  // (a reviewer retired it, admin-api 1.17.0). Both are «Ritirata» in the console.
  const status = r.status === 'superseded' || (r.status === 'rejected' && r.retired) ? 'retired' : ((['draft', 'approved', 'rejected', 'stale', 'retired'] as const).find((s) => s === r.status) ?? 'draft');
  const counts = r.evidence?.counts ?? {};
  const base = {
    id: r.id,
    ...(r.groups ? { groups: r.groups } : {}),
    kind: r.kind,
    status,
    title: r.title,
    origin: r.origin === 'manual' ? ('manual' as const) : ('mined' as const),
    definition: ruleDefinition(r),
    supersedes: r.supersedes,
    ...(r.superseded_by ? { supersededBy: r.superseded_by } : {}),
    proposedAt: r.proposed_at,
    staleReason: r.stale_reason,
    failedRuns: r.failed_runs,
    review: { by: r.review?.by ?? [], at: r.review?.at ?? null, note: r.review?.note ?? '' },
  };
  if (r.kind === 'batch') {
    return {
      ...base,
      effects: [],
      outcomes: [],
      counts: { causes: 0, distinctSubjects: 0, keyMatches: 0 },
      hints: { magnitude: {}, scheduleConfidence: r.evidence?.hints?.schedule_confidence },
      batch: {
        schedule: r.schedule ?? '',
        entity: r.entity ?? '',
        where: mapValues(r.where),
        set: mapValues(r.set),
        fraction: r.fraction ?? 1,
        runs: counts.runs ?? 0,
        entitiesChanged: counts.entities_changed ?? 0,
      },
    };
  }
  const magnitude = r.evidence?.hints?.magnitude ?? {};
  const effects: RuleEffect[] = (r.effects ?? []).map((e) => ({
    id: e.id,
    entity: e.entity ?? '',
    kind: e.respond ? 'respond' : e.remove ? 'remove' : e.create ? 'create' : 'set',
    ...(e.respond ? { respond: { ...e.respond, ...(e.respond.limit ? { limit: { ...e.respond.limit } } : {}) } } : {}),
    values: mapValues(e.create ?? e.set),
    ...(e.where ? { where: mapValues(e.where) } : {}),
    ...(e.target_key ? { targetKey: { ...e.target_key } } : {}),
    ...(e.target_all ? { targetAll: true } : {}),
    target: e.target,
    afterEffect: e.after_effect,
    after: delayText(e.after),
    magnitude: (['seconds', 'minutes', 'hours', 'days'] as const).find((m) => m === magnitude[e.id]),
  }));
  return {
    ...base,
    cause: r.cause && {
      service: r.cause.service,
      op: r.cause.op,
      whenStatus: r.cause.when?.status ?? [],
      bind: Object.fromEntries(Object.entries(r.cause.bind ?? {}).map(([k, v]) => [k, refText(v)])),
      ...(r.cause.when?.match?.length ? { match: matchesOf(r.cause.when.match) } : {}),
    },
    effects,
    outcomes: (r.outcomes ?? []).map((o) => ({ name: o.name, p: o.p, effects: o.effects, count: counts.outcomes?.[o.name] ?? 0, ...(o.when?.length ? { when: matchesOf(o.when) } : {}) })),
    counts: { causes: counts.causes ?? 0, distinctSubjects: counts.distinct_subjects ?? 0, keyMatches: counts.key_matches ?? 0 },
    hints: { magnitude: magnitude },
  };
}

// ---------------------------------------------------------------- settings

export function mapServerSettings(w: WireSettings): ServerSettings {
  const env = w.general.environment;
  return {
    installation: w.general.installation_name,
    environment: env === 'production' || env === 'staging' || env === 'development' ? env : undefined,
    privacy: {
      eventsRetentionDays: w.privacy.events_retention_days,
      aggregatesDays: w.privacy.aggregates_days,
      kMin: w.privacy.k_min,
      minSamples: w.privacy.min_samples,
    },
    access: {
      localEnabled: w.access.local_enabled,
      sso: { enabled: w.access.oidc.enabled, issuer: w.access.oidc.issuer_url, clientId: w.access.oidc.client_id, roleClaim: w.access.oidc.roles_claim },
      sessionIdleSeconds: w.access.session.idle_timeout_s,
      sessionAbsoluteSeconds: w.access.session.absolute_timeout_s,
    },
  };
}

// ---------------------------------------------------------------- archetypes, worlds

export function mapArchetype(a: WireArchetype, kMin: number): Archetype {
  // The server publishes aggregates only (size >= k_min by construction); a smaller group would be hidden.
  const belowK = a.size < kMin;
  return {
    id: a.id,
    label: a.label,
    size: belowK ? null : a.size,
    belowK,
    features: { ordersPerMonth: a.features.orders_per_month, activeHours: a.features.active_hours, outcomesMix: a.features.outcomes_mix ?? {} },
  };
}

export function mapWorld(w: WireWorld, createdBy = ''): World {
  return { id: w.world_id, ...(w.group !== undefined ? { group: w.group } : {}), seed: w.seed, customers: w.customers, createdAt: w.created_at, createdBy, entities: w.entities, rules: w.rules ?? [], services: w.services ?? [], ...(w.excluded_rules?.length ? { excludedRules: w.excluded_rules } : {}) };
}

// ---------------------------------------------------------------- packs

const CHECK_IDS: readonly CheckId[] = ['provenance', 'reverse-hmac', 'pii-detectors', 'k-thresholds', 'rules-approved'];
const CHECK_STATUS: readonly CheckStatus[] = ['pending', 'running', 'pass', 'warn', 'fail', 'skipped'];

export function mapPack(p: WirePack): Publication {
  const status = (['building', 'gate-failed', 'signed', 'published'] as const).find((s) => s === p.status) ?? ('building' satisfies PackStatus);
  const checks: GateCheck[] = (p.gate_report?.checks ?? []).map((c) => ({
    id: (CHECK_IDS as readonly string[]).includes(c.id) ? (c.id as CheckId) : ('provenance' as CheckId),
    status: (CHECK_STATUS as readonly string[]).includes(c.status) ? (c.status as CheckStatus) : 'pending',
    findings: c.findings ?? [],
    stringsChecked: c.strings_checked,
  }));
  const verdict: Publication['verdict'] = status === 'building' ? 'running' : status === 'gate-failed' ? 'fail' : 'pass';
  const m = p.manifest;
  const rr = p.residual_risk;
  return {
    id: p.pack_id,
    packId: p.pack_id,
    status,
    publishedAt: p.published_at ?? undefined,
    residualRisk: rr && mapRisk(rr),
    createdAt: p.created_at,
    createdBy: '',
    worldId: p.world_id ?? '',
    seed: m?.seed ?? 0,
    kMin: m?.k_min ?? p.gate_report?.k_min ?? 0,
    verdict,
    checks,
    rulesApproved: m?.rules?.approved ?? [],
    notAfter: m?.not_after,
    adminOverride: p.approval_mode === 'admin' ? { by: '', reason: '' } : undefined,
    files: (m?.files ?? []).map((f) => ({ path: f.path, bytes: f.bytes, sha256: f.sha256 })),
    signedBy: status === 'signed' || status === 'published' ? 'gate' : undefined,
    services: p.services ?? (m?.services ?? []).map((x) => x.name),
    ...(p.group !== undefined ? { group: p.group } : {}),
    ...(p.groups ? { groups: p.groups } : {}),
  };
}

export function mapScope(w: WireScope): ScopeData {
  return { groups: w.groups ?? [], mine: w.mine ?? [], services: w.services ?? {} };
}

export function mapContractStatus(w: WireContractStatus): ContractStatus {
  return {
    service: w.service,
    calls: w.calls,
    operations: w.operations,
    readyOperations: w.ready_operations,
    bestOpCalls: w.best_op_calls,
    minCalls: w.min_calls,
    kMin: w.k_min,
    inferredOperations: w.inferred_operations,
    snapshot: w.snapshot ? { id: w.snapshot.snapshot_id, createdAt: w.snapshot.created_at, ops: w.snapshot.ops } : undefined,
    nextSnapshotAt: w.next_snapshot_at,
    windowHours: w.window_hours,
  };
}

/** Adds the problem "HMAC key unknown to keyguard" to the sources the key check lists. */
export function withKeyCheck(sources: Source[], kc: WireKeyCheck | null): Source[] {
  if (!kc?.reachable) return sources;
  const unknown = new Map(kc.sources.map((s) => [s.source_id, s.unknown_kids]));
  return sources.map((s) => {
    const kids = unknown.get(s.id);
    if (!kids?.length) return s;
    const p = mapProblem({ code: 'hmac_kid_unknown', message: `HMAC key id ${kids.join(', ')} unknown to keyguard`, hint: 'distribute the installation key file' });
    p.message = tk('problem.hmac_kid_unknown', { kids: kids.join(', '), held: kc.keyguard_kids.join(', ') || '—' }, p.message);
    return { ...s, problems: [...s.problems, p] };
  });
}

function mapRisk(r: NonNullable<WirePack['residual_risk']>): ResidualRisk {
  return {
    note: r.note,
    profiles: r.profiles,
    archetypes: r.archetypes,
    minArchetypeSize: r.min_archetype_size,
    suppressedSubjects: r.suppressed_subjects,
    uniquenessRate: r.uniqueness_rate,
    singlingOutRate: r.singling_out_rate,
    exactMatchShare: r.exact_match_share,
    maxHomogeneity: r.max_homogeneity,
  };
}

/** export-report.json (tt.export-report/v1) -> the UI report. */
export function mapExportReport(target: ExportTarget, r: unknown): ExportReport {
  const rep = (r ?? {}) as {
    exported?: { kind: string; element: string; count: number }[];
    losses?: { kind: string; element: string; detail: string; count?: number }[];
    files?: { path?: string; kind?: string }[];
  };
  return {
    target,
    produced: (rep.files ?? []).filter((f) => f.path).map((f) => ({ path: String(f.path), description: f.kind ?? '' })),
    preserved: (rep.exported ?? []).map((e) => `${e.element} (${e.kind}) × ${e.count}`),
    lost: (rep.losses ?? []).map((l) => ({ item: `${l.element} (${l.kind})${l.count ? ` × ${l.count}` : ''}`, reason: l.detail })),
  };
}

// ---------------------------------------------------------------- audit

export function mapAuditEntry(e: WireAuditEntry): AuditEntry {
  const actor = e.actor?.name || e.actor?.id || e.actor?.kind || '';
  const target = e.target?.id ? `${e.target.type}:${e.target.id}` : (e.target?.type ?? '');
  return {
    seq: e.seq,
    at: e.ts,
    actor,
    action: e.action,
    target,
    result: e.outcome === 'success' ? 'ok' : e.outcome === 'denied' ? 'denied' : 'error',
    prevHash: e.prev_hash,
    hash: e.hash,
  };
}

export function mapAuditVerify(v: WireAuditVerify, now: Date): AuditVerification {
  return { ok: v.ok, entries: v.entries, headHash: v.head_hash, verifiedAt: now.toISOString(), error: v.error };
}

/** NDJSON (one object per line), tolerant of blank lines and a truncated last line. */
export function parseNdjson<T>(text: string): T[] {
  const out: T[] = [];
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try {
      out.push(JSON.parse(s) as T);
    } catch {
      /* truncated stream: the verify call reports the break */
    }
  }
  return out;
}

// ---------------------------------------------------------------- hosts

function mapHost(w: WireHostPattern, fallbackPattern = w.pattern): HostEntry {
  return {
    pattern: w.pattern || fallbackPattern,
    ...(w.group !== undefined ? { group: w.group } : {}),
    service: w.service,
    declared: !!w.declared,
    declaredBy: w.declared_by ?? [],
    exact: !!w.exact,
    quarantined: !!w.quarantined,
    calls: w.calls ?? 0,
    serverErrors: w.server_errors ?? 0,
    clientErrors: w.client_errors ?? 0,
    errorRate: w.error_rate ?? 0,
    latencyP50Ms: w.latency_p50_ms ?? null,
    firstSeen: w.first_seen ?? null,
    lastSeen: w.last_seen ?? null,
    callers: w.callers ?? [],
    policies: w.policies ?? [],
    ...(w.now_declared_as ? { nowDeclaredAs: w.now_declared_as } : {}),
    ...(w.folded_from?.length ? { foldedFrom: w.folded_from } : {}),
  };
}

/**
 * The counters of the page from the server's `counts` (admin-api 1.17.0). The server counts the IP classes as domains
 * and their entries as hosts; the console shows named domains, named hosts and the IP hosts apart.
 */
export function mapHostCounts(c: NonNullable<WireHostsRegistry['counts']>, domains: readonly { domain: string }[]): NonNullable<HostsRegistry['counters']> {
  const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined);
  const ipDomains = domains.filter((d) => d.domain.startsWith('ip:')).length;
  const all = num(c.hosts);
  const ips = num(c.ip_hosts);
  const doms = num(c.domains);
  const out: NonNullable<HostsRegistry['counters']> = {};
  if (doms !== undefined) out.domains = Math.max(0, doms - ipDomains);
  if (all !== undefined) out.all = all;
  if (ips !== undefined) out.ips = ips;
  if (all !== undefined && ips !== undefined) out.hosts = Math.max(0, all - ips);
  const und = num(c.undeclared);
  if (und !== undefined) out.undeclared = und;
  return out;
}

const EMPTY_HOST = (pattern: string): WireHostPattern => ({
  pattern,
  service: `host:${pattern}`,
  declared: false,
  exact: false,
  quarantined: false,
  calls: 0,
  server_errors: 0,
  client_errors: 0,
  error_rate: 0,
  latency_p50_ms: null,
  first_seen: null,
  last_seen: null,
});

export function mapHosts(w: WireHostsRegistry): HostsRegistry {
  const domains: HostDomain[] = (w.domains ?? []).map((d) => ({
    domain: d.domain,
    calls: d.calls,
    firstSeen: d.first_seen ?? null,
    lastSeen: d.last_seen ?? null,
    patterns: (d.patterns ?? []).map((p) => mapHost(p)),
  }));
  const discovery: Record<string, HostsDiscovery> = {};
  for (const [id, mode] of Object.entries(w.discovery ?? {})) discovery[id] = mode === 'off' ? 'off' : 'auto';
  return { domains, unlisted: mapHost(w.unlisted ?? EMPTY_HOST('unlisted'), 'unlisted'), invalid: mapHost(w.invalid ?? EMPTY_HOST('invalid'), 'invalid'), discovery, ...(w.counts ? { counters: mapHostCounts(w.counts, domains) } : {}) };
}

const ZERO_TIME = '0001-01-01T00:00:00Z';

export function mapStoreUsage(w: WireStoreUsage): StoreUsage {
  const d = w.db;
  return {
    db: { file: d.file, fileBytes: d.file_bytes, walBytes: d.wal_bytes, freeBytes: d.free_bytes, usedBytes: d.used_bytes, maxBytes: d.max_bytes, usedPct: d.used_pct, highPct: d.high_watermark_pct, criticalPct: d.critical_watermark_pct, level: d.level, autoVacuum: d.auto_vacuum },
    datasets: (w.datasets ?? []).map((x) => ({
      name: x.name,
      bytes: x.bytes,
      fileBytes: x.file_bytes ?? 0,
      quotaBytes: x.quota_bytes || undefined,
      overQuota: x.over_quota,
      policy: { code: x.policy.code, params: x.policy.params ?? {} },
      lastRun: x.last_run ? { deleted: x.last_run.outcome?.deleted ?? 0, error: x.last_run.error || undefined, durationMs: x.last_run.duration_ms } : undefined,
    })),
    measuredAt: w.measured_at,
    lastRun: w.last_run
      ? { trigger: w.last_run.trigger, startedAt: w.last_run.started_at, finishedAt: w.last_run.finished_at, deleted: w.last_run.deleted, reclaimedBytes: w.last_run.reclaimed_bytes, reclaimNote: w.last_run.reclaim_note || undefined, errors: w.last_run.errors, shed: (w.last_run.shed ?? []).map((s) => s.name) }
      : undefined,
    nextRun: w.next_run && w.next_run !== ZERO_TIME ? w.next_run : undefined,
    running: w.running,
    jobId: w.job_id || undefined,
    intervalSeconds: w.interval_seconds,
    rollups: (w.rollups ?? []).map((r) => ({ tier: r.tier, rows: r.rows, oldest: r.oldest && r.oldest !== ZERO_TIME ? r.oldest : undefined })),
    auditArchive: w.audit_archive,
  };
}

/** The observe phase of a group (policy.md §7). */
/** A ranked identity candidate (admin-api 1.18.0); the fields an older server lacks stay absent. */
export function mapIdentityCandidate(c: WireIdentityCandidate): IdentityCandidate {
  return {
    from: c.from === 'cookie' ? 'cookie' : 'header',
    name: c.name,
    ...(c.jwt_claim ? { claim: c.jwt_claim } : {}),
    calls: c.calls,
    distinct: c.distinct_estimate,
    jwt: c.jwt,
    ...(c.shape ? { shape: c.shape } : {}),
    ...(typeof c.presence === 'number' ? { presence: c.presence } : {}),
    ...(typeof c.distinct_per_call === 'number' ? { perCall: c.distinct_per_call } : {}),
    ...(typeof c.score === 'number' ? { score: c.score } : {}),
    ...(c.signals ? { signals: c.signals } : {}),
    ...(c.excluded ? { excluded: c.excluded } : {}),
    ...(typeof c.observe_safe === 'boolean' ? { observeSafe: c.observe_safe } : {}),
    ...(c.best ? { best: true } : {}),
  };
}

/** identity_best of the server, or undefined. */
export function mapIdentitySource(s: { from: string; name: string; jwt_claim?: string } | null | undefined): IdentitySource | undefined {
  if (!s?.name) return undefined;
  return { from: s.from === 'cookie' ? 'cookie' : 'header', name: s.name, ...(s.jwt_claim ? { claim: s.jwt_claim } : {}) };
}

export function mapObserve(w: WireObserveStatus): ObserveStatus {
  const phase = (['no_policy', 'waiting_approval', 'listening', 'masked', 'managed'] as const).find((p) => p === w.phase) ?? 'no_policy';
  const part = (p: string) => (p === 'request' || p === 'errors' ? p : 'response');
  const kind = (k: string) => (['path', 'query', 'headers', 'cookies'] as const).find((x) => x === k) ?? 'body';
  return {
    group: w.group,
    ...(w.policy_id ? { policyId: w.policy_id } : {}),
    enabled: w.enabled,
    auto: w.auto ?? true,
    phase,
    ...(w.active_version ? { activeVersion: w.active_version } : {}),
    ...(w.started_at ? { startedAt: w.started_at } : {}),
    ...(w.due_at ? { dueAt: w.due_at } : {}),
    minEvents: w.min_events,
    events: w.events,
    ...(w.observe_version ? { observeVersion: w.observe_version } : {}),
    ...(w.observe_activated_at ? { observeActivatedAt: w.observe_activated_at } : {}),
    ...(w.discovery_until ? { discoveryUntil: w.discovery_until } : {}),
    samplingBp: w.sampling_bp,
    services: (w.services ?? []).map((s) => ({ service: s.service, kind: s.kind === 'inbound' ? ('inbound' as const) : ('external' as const), calls: s.calls, ops: s.ops })),
    masked: (w.masked ?? []).map((m) => ({ service: m.service, ...(m.op ? { op: m.op } : {}), part: part(m.part), kind: kind(m.kind), field: m.field, domain: m.domain })),
    ...(w.identity
      ? { identity: { from: w.identity.from, name: w.identity.name, ...(w.identity.jwt_claim ? { claim: w.identity.jwt_claim } : {}), ...(w.identity.json_path ? { jsonPath: w.identity.json_path } : {}) } }
      : {}),
    ...(w.families && Object.keys(w.families).length ? { families: Object.fromEntries(Object.entries(w.families).map(([f, ds]) => [f, [...ds]])) } : {}),
    ...(typeof w.test_k_min === 'number' ? { testKMin: w.test_k_min } : {}),
    ...(typeof w.k_min === 'number' ? { kMin: w.k_min } : {}),
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
  };
}
