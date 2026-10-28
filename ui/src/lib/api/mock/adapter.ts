// In-memory adapter implementing `Api` with invented fixtures. It enforces
// permissions like a server would, so the UI can be exercised per role.

import { isAdmin, permissionsOf, ROLE_PERMISSIONS } from '../../rbac';
import { mulberry32, sha256Hex } from '../../hash';
import { currentChoices, diffChoices as diffChoicesOf, hostsDiff, opensData, policyYaml as policyYamlOf } from '../../policy';
import { identityObserveSafe, valueReasonsOf } from '../../observe';
import { checkBase, defaultServiceName, exactBaseUrl, isSystemPattern, validServiceName, STAR } from '../../hosts';
import { parseDocument } from 'yaml';
import {
  ApiError,
  type Api,
  type AssistService,
  type PolicyAssist,
  type AuditEntry,
  type DiscoveredService,
  type HostsDiscovery,
  type EnrollmentToken,
  type ExportReport,
  type ExportTarget,
  type GateCheck,
  type CheckId,
  type Permission,
  type PolicyChoice,
  type PolicyVersion,
  type Publication,
  type Role,
  type Rule,
  type SourceChoice,
  type User,
  type World,
  type WorldGraph,
  type WorldNode,
  type WorldCustomerRow,
  type WorldCustomerDetail,
  type WorldEntity,
  type Settings,
  type GeneralSettings,
  type OnboardingStatus,
  type ObserveStatus,
  type IdentityCandidate,
  type IdentitySource,
  type Problem,
  type ServiceSummary,
  type QuarantineItem,
  type KeyguardAuditEntry,
  type SigningKey,
  type GroupSel,
  groupNames,
} from '../types';
import * as fx from './fixtures';
import { hostsRegistry } from './fixtures';
import { buildOpenApi } from './openapi';
import { createDemoIdFormats } from './idfmt';
import { createDemoDateOffsets } from './mock2';
import { checkDerived, derivedRefs, isDerived, resultType } from '../../derive';
import { createDemoOpKinds } from './opkinds';
import { createDemoMockService } from './mocksvc';
import { toYaml } from '../../yaml';
import { postmanOf } from './postman';
import { mapRule } from '../rest/map';
import type { WireRule } from '../rest/wire';
import type { RuleDefinition, RuleProblem } from '../types';

/** A display rule from a definition written in the editor (no evidence: nothing observed yet). */
function ruleFromDef(def: RuleDefinition, id: string, status: Rule['status'], origin: Rule['origin']): Rule {
  const w: WireRule = {
    id,
    status,
    origin,
    review: { by: [], at: null, note: '' },
    ...(JSON.parse(JSON.stringify(def)) as Omit<WireRule, 'id' | 'status'>),
    evidence: { counts: { causes: 0, distinct_subjects: 0, outcomes: Object.fromEntries((def.outcomes ?? []).map((o) => [o.name, 0])) } },
  };
  return { ...mapRule(w), proposedAt: new Date().toISOString() };
}

/** The demo's checks of a rule against the demo contracts (the server does the real ones). */
function checkRuleDef(def: RuleDefinition): RuleProblem[] {
  const cat = fx.ruleCatalog();
  const out: RuleProblem[] = [];
  const op = (svc: string, key: string) => cat.services.find((s) => s.name === svc)?.ops.find((o) => o.op === key);
  if (!def.title?.trim()) out.push({ path: 'title', code: 'invalid', message: 'the title is required' });
  if (def.kind === 'batch') {
    if (!cat.entities.some((e) => e.name === def.entity)) out.push({ path: 'entity', code: 'unknown_entity', message: `entity ${def.entity} is not known` });
    return out;
  }
  if (!def.cause || !op(def.cause.service, def.cause.op)) out.push({ path: 'cause.op', code: 'unknown_op', message: `operation ${def.cause?.op ?? ''} is not in the contract of ${def.cause?.service ?? ''}` });
  (def.effects ?? []).forEach((e, i) => {
    if (e.respond) {
      if (!op(e.respond.service, e.respond.op)) out.push({ path: `effects[${i}].respond.op`, code: 'unknown_op', message: `operation ${e.respond.op} is not in the contract of ${e.respond.service}` });
      return;
    }
    const ent = cat.entities.find((x) => x.name === e.entity);
    if (!ent) return out.push({ path: `effects[${i}].entity`, code: 'unknown_entity', message: `entity ${e.entity} is not known` });
    const kind = e.create ? 'create' : 'set';
    const vals = e.create ?? e.set ?? {};
    for (const [k, v] of Object.entries(vals)) {
      const f = ent.fields.find((x) => x.name === k);
      if (!f) out.push({ path: `effects[${i}].${kind}.${k}`, code: 'unknown_field', message: `entity ${e.entity} has no field ${k}` });
      if (!isDerived(v)) continue;
      // Derived values (rules 1.10): the same checks as the server, in its words.
      const bad = checkDerived(v);
      if (bad) {
        out.push({ path: `effects[${i}].${kind}`, code: 'bad_derived', message: `field "${k}": ${bad.code}` });
        continue;
      }
      for (const r of derivedRefs(v).fields) {
        const name = r.replaceAll('[*]', '');
        if (!(name in vals) && !(name.split('.')[0] in vals) && !ent.fields.some((x) => x.name === name || x.name === name.split('.')[0]))
          out.push({ path: `effects[${i}].${kind}.${k}`, code: 'unknown_field', message: `derived value of ${k} reads ${name}, which entity ${e.entity} does not have` });
      }
      const rt = resultType(v.$derive.fn);
      if (f?.type && rt === 'number' && f.type !== 'number' && f.type !== 'integer') out.push({ path: `effects[${i}].${kind}.${k}`, code: 'derived_type', message: `${v.$derive.fn} computes a number, but field ${k} is a ${f.type}` });
      if (f?.type && rt === 'string' && f.type !== 'string') out.push({ path: `effects[${i}].${kind}.${k}`, code: 'derived_type', message: `${v.$derive.fn} computes a text, but field ${k} is a ${f.type}` });
    }
  });
  const sum = (def.outcomes ?? []).reduce((a, o) => a + o.p, 0);
  if (Math.abs(sum - 1) > 0.001) out.push({ path: 'outcomes', code: 'invalid', message: 'outcome probabilities must sum to 1' });
  return out;
}

export interface MockOptions {
  /** Artificial latency per call, ms. */
  latencyMs?: number;
  now?: () => number;
  storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null;
}

const GATE_STEP_MS = 1400;
const CHECKS: CheckId[] = ['provenance', 'reverse-hmac', 'pii-detectors', 'k-thresholds'];
const GENESIS = '0'.repeat(64);

export function auditHash(prev: string, e: Omit<AuditEntry, 'hash' | 'prevHash'>): string {
  return sha256Hex([prev, e.seq, e.at, e.actor, e.action, e.target, e.result].join('|'));
}

export function createMockApi(opts: MockOptions = {}): Api {
  const latency = opts.latencyMs ?? 120;
  const now = opts.now ?? (() => Date.now());
  const storage = opts.storage === undefined ? safeSession() : opts.storage;

  // ------------------------------------------------------------ state
  const t0 = now();
  let initialized = true;
  const usersList = fx.users(t0);
  let current: User | null = null;
  const savedUser = storage?.getItem('tt.mock.user');
  if (savedUser) current = usersList.find((u) => u.username === savedUser) ?? null;

  // Flat internal copy: `approvals` is read-only (keyguard), the rest is the editable configuration.
  let settings: GeneralSettings & Pick<Settings, 'approvals'> = {
    environment: 'staging',
    approvals: { openingRequired: 2, adminOverride: true, identitiesVerified: false },
    retentionDays: 30,
    kMin: 20,
    defaultSamplingBp: 500,
    anonymizeHosts: false,
    minSamples: fx.MIN_SAMPLES,
    sso: { enabled: true, issuer: 'https://sso.internal.example/realms/it', clientId: 'traffic-twin', roleClaim: 'groups' },
  };

  let sourcesList = fx.sources(t0);
  let servicesList = fx.services(t0);
  let rulesList: Rule[] = fx.rules(t0);
  let scenarioList = fx.scenarioPresets();
  let alertsList = fx.alerts(t0);
  let hooks = fx.webhooks(t0);
  const tokens = new Map<string, { at: number; choice: SourceChoice; group: string; expiresAt: number }>();
  // Groups whose automatic observe versions were turned off (setObserveAuto).
  const observeOff = new Set<string>();
  // Who the user is per group, as a person chose it (setIdentity).
  const identityChosen = new Map<string, IdentitySource>();
  // Rules v1.9 / admin-api 1.21.0: HMAC domain families per group (setFamily) and the lower k of test groups (setTestK).
  const familiesOf = new Map<string, Record<string, string[]>>();
  const testKOf = new Map<string, number>();
  // A family change is observe-safe: a new active version of the group's policy at once.
  function familyVersion(group: string, by: string, where: string, to: string): PolicyVersion {
    const policyId = policyList.find((p) => p.status === 'active' && (p.groups ?? []).includes(group))?.policyId ?? 'p-shop';
    const version = Math.max(...policyList.filter((p) => p.policyId === policyId).map((p) => p.version), 0) + 1;
    const fams = familiesOf.get(group) ?? {};
    const yamlAfter = `hmac:\n  families:\n${Object.entries(fams).map(([f, ds]) => `    ${f}: [${ds.join(', ')}]\n`).join('') || '    {}\n'}`;
    for (const p of policyList) if (p.policyId === policyId && p.status === 'active') p.status = 'superseded';
    const pv: PolicyVersion = {
      policyId,
      version,
      groups: policyList.find((p) => p.policyId === policyId)?.groups ?? [group],
      status: 'active',
      proposedBy: by,
      proposedAt: iso(now()),
      origin: 'propose',
      opensData: false,
      opensValues: false,
      valueReasons: [],
      approvalsRequired: 0,
      approvals: [],
      approvalMode: 'observe',
      diff: [{ change: to ? 'changed' : 'removed', where, from: '', to }],
      yamlBefore: '',
      yamlAfter,
      hash: 'sha256:' + sha256Hex(yamlAfter).slice(0, 8),
    };
    policyList.push(pv);
    return pv;
  }
  // The ranking of the automatic detection on the demo traffic (invented names and counts, never values).
  const demoIdentityCandidates: IdentityCandidate[] = [
    { from: 'header', name: 'authorization', claim: 'sub', calls: 4120, distinct: 1290, jwt: true, presence: 0.97, score: 100, signals: ['jwt_bearer', 'most_calls'], observeSafe: true, best: true },
    { from: 'header', name: 'x-member-ref', calls: 3980, distinct: 310, jwt: false, shape: 'drop:str:uuid', presence: 0.94, perCall: 0.08, score: 85, signals: ['repeats', 'id_shape', 'most_calls'], observeSafe: true },
    { from: 'header', name: 'x-tenant', calls: 4120, distinct: 3, jwt: false, shape: 'drop:str:l8', presence: 1, perCall: 0, score: 43, signals: ['short_shape', 'most_calls'], excluded: 'few_values', observeSafe: true },
    { from: 'header', name: 'x-request-ref', calls: 4120, distinct: 4100, jwt: false, shape: 'drop:str:hex', presence: 1, perCall: 1, score: 50, signals: ['id_shape', 'most_calls'], excluded: 'per_call', observeSafe: true },
    { from: 'cookie', name: 'sid', calls: 2010, distinct: 900, jwt: false, shape: 'drop:str:l32', presence: 0.49, perCall: 0.45, score: 70, signals: ['repeats', 'short_shape', 'some_calls'], excluded: 'cookie', observeSafe: false },
  ];
  let seq = 100;
  const quarantine: QuarantineItem[] = [
    { id: 'q-1', kind: 'keep-value', service: 'shop-api', op: 'GET /orders/{id}', where: 'resp.body $.status', distinctEstimate: 214, state: 'quarantined', since: iso(t0 - 3600000 * 5), approvals: [] },
    { id: 'q-2', kind: 'path-segment', service: 'shipping-ext', where: 'path position 2', distinctEstimate: 61, state: 'dismiss-pending', since: iso(t0 - 86400000), approvals: [{ by: 'paolo.approver', at: iso(t0 - 3600000) }] },
    // The intake collapsed the first label under tracking.example: tenant ids as sub-domains (spec v1.5).
    // A code field with digits that turned out to be an identifier (spec v1.19): more than 50 distinct values.
    { id: 'q-4', kind: 'keep-value', alert: 'value_cardinality', service: 'shop-api', op: 'GET /items/{id}', where: 'resp.body $.item.refCode', distinctEstimate: 380, state: 'quarantined', since: iso(t0 - 3600000 * 2), approvals: [] },
    { id: 'q-3', kind: 'host-label', alert: 'host_cardinality', service: 'host:*', where: 'hosts under tracking.example position 1', distinctEstimate: 1850, state: 'quarantined', since: iso(t0 - 3600000 * 20), approvals: [] },
  ];
  let retentionDays = 30;
  const nextId = (p: string) => `${p}${++seq}`;

  // Policies: active v7 (keep status), draft v8 waiting for a second person.
  const suggestions = fx.policySuggestions();
  const activeChoices: Record<string, PolicyChoice> = currentChoices(suggestions);
  let policyList: PolicyVersion[] = [];
  const policyYaml = (choices: Record<string, PolicyChoice>) => policyYamlOf(suggestions, choices);
  const diffChoices = (from: Record<string, PolicyChoice>, to: Record<string, PolicyChoice>) => diffChoicesOf(suggestions, from, to);
  const opens = opensData;
  // hosts.discovery per policy version (`policyId@version`): the active one decides what the hosts registry shows.
  const versionHosts = new Map<string, HostsDiscovery>([['p-shop@7', 'auto'], ['p-shop@8', 'auto']]);
  const hostsOf = (policyId: string): HostsDiscovery => {
    const active = policyList.find((p) => p.policyId === policyId && p.status === 'active');
    return (active && versionHosts.get(`${policyId}@${active.version}`)) || 'auto';
  };

  policyList.push({
    policyId: 'p-shop',
    version: 7,
    status: 'active',
    proposedBy: 'olga.operator',
    proposedAt: iso(t0 - 86400000 * 6),
    opensData: false,
    opensValues: true,
    valueReasons: [{ code: 'keep', where: 'services.shop-api.ops.POST /orders.response.body.$.status' }],
    approvalsRequired: 2,
    approvals: [
      { by: 'paolo.approver', at: iso(t0 - 86400000 * 6 + 3600000) },
      { by: 'anna.approver', at: iso(t0 - 86400000 * 6 + 7200000) },
    ],
    groups: ['shop-api'],
    diff: [],
    yamlBefore: policyYaml({}),
    yamlAfter: policyYaml(activeChoices),
    hash: 'sha256:9c1e4b7d',
  });
  // Another team's policy with a draft of its own: the Policy tab of a group never offers to approve it.
  policyList.push({
    policyId: 'p-legacy',
    version: 2,
    status: 'active',
    proposedBy: 'lea.legacy',
    proposedAt: iso(t0 - 86400000 * 9),
    opensData: false,
    opensValues: false,
    valueReasons: [],
    approvalsRequired: 1,
    approvals: [{ by: 'paolo.approver', at: iso(t0 - 86400000 * 9 + 3600000) }],
    groups: ['legacy'],
    diff: [],
    yamlBefore: '',
    yamlAfter: 'policy_id: p-legacy\nservices:\n  legacy-app:\n    match: { inbound: true }\n',
    hash: 'sha256:51ab02c3',
  });
  policyList.push({
    policyId: 'p-legacy',
    version: 3,
    status: 'draft',
    proposedBy: 'lea.legacy',
    proposedAt: iso(t0 - 3600000 * 2),
    opensData: true,
    opensValues: true,
    valueReasons: [{ code: 'keep', where: 'services.legacy-app.ops.GET /status.response.body.$.state' }],
    approvalsRequired: 2,
    approvals: [],
    groups: ['legacy'],
    diff: [{ change: 'added', where: 'services.legacy-app.ops.GET /status', to: 'declared' }],
    yamlBefore: 'policy_id: p-legacy\nservices:\n  legacy-app:\n    match: { inbound: true }\n',
    yamlAfter: 'policy_id: p-legacy\nservices:\n  legacy-app:\n    match: { inbound: true }\n    ops:\n      GET /status: {}\n',
  });
  {
    const draftChoices = { ...activeChoices, 'sg-6': { action: 'hmac', arg: 'order' } as PolicyChoice };
    const d = diffChoices(activeChoices, draftChoices);
    policyList.push({
      policyId: 'p-shop',
      version: 8,
      groups: ['shop-api'],
      status: 'draft',
      proposedBy: 'olga.operator',
      proposedAt: iso(t0 - 3600000 * 5),
      opensData: opens(d),
      opensValues: true,
      valueReasons: [{ code: 'keep', where: 'shop-api · POST /orders · response · $.currency' }],
      approvalsRequired: 2,
      approvals: [{ by: 'paolo.approver', at: iso(t0 - 3600000 * 4) }],
      diff: d,
      yamlBefore: policyYaml(activeChoices),
      yamlAfter: policyYaml(draftChoices),
    });
  }

  // Worlds & publications
  let worldList: World[] = [
    { id: 'w-0001', group: 'shop-api', seed: 42, customers: 200, createdAt: iso(t0 - 86400000 * 4), createdBy: 'pia.publisher', entities: 640 },
    { id: 'w-0002', group: 'shop-api', seed: 13, customers: 50, createdAt: iso(t0 - 86400000 * 2), createdBy: 'olga.operator', entities: 158 },
  ];
  const pubStart = new Map<string, number>();
  const pubFails = new Map<string, boolean>();
  const pubPublished = new Map<string, string>();
  const pubList: Publication[] = [];

  function buildPublication(id: string, packId: string, world: World, by: string, start: number): Publication {
    const fails = world.seed % 13 === 0;
    pubStart.set(id, start);
    pubFails.set(id, fails);
    return {
      id,
      packId,
      status: 'building',
      createdAt: iso(start),
      createdBy: by,
      worldId: world.id,
      seed: world.seed,
      kMin: settings.kMin,
      verdict: 'running',
      checks: CHECKS.map((c) => ({ id: c, status: 'pending', findings: [] })),
      rulesApproved: rulesList.filter((r) => r.status === 'approved').map((r) => r.id),
      files: [
        { path: 'contracts/shop-api.openapi.json', bytes: 41233, sha256: sha256Hex(packId + 'a') },
        { path: 'contracts/shipping-ext.openapi.json', bytes: 18234, sha256: sha256Hex(packId + 'b') },
        { path: 'rules.json', bytes: 9120, sha256: sha256Hex(packId + 'c') },
        { path: 'world.jsonl', bytes: 884736, sha256: sha256Hex(packId + 'd') },
        { path: 'faults.json', bytes: 2210, sha256: sha256Hex(packId + 'e') },
        { path: 'scenarios.json', bytes: 1630, sha256: sha256Hex(packId + 'g') },
        { path: 'gate-report.json', bytes: 1180, sha256: sha256Hex(packId + 'f') },
      ],
      signedBy: fails ? undefined : 'gate-2026-1',
      ...(world.group ? { group: world.group, groups: [world.group], services: servicesList.filter((s) => s.group === world.group && s.twin).map((s) => s.name) } : {}),
    };
  }

  function computePublication(p: Publication): Publication {
    const start = pubStart.get(p.id) ?? 0;
    const fails = pubFails.get(p.id) ?? false;
    const elapsed = now() - start;
    const checks: GateCheck[] = CHECKS.map((id, i) => {
      const failAt = fails ? 1 : -1;
      if (failAt >= 0 && i > failAt && elapsed >= (failAt + 1) * GATE_STEP_MS) return { id, status: 'skipped', findings: [] };
      if (elapsed < i * GATE_STEP_MS) return { id, status: 'pending', findings: [] };
      if (elapsed < (i + 1) * GATE_STEP_MS) return { id, status: 'running', findings: [] };
      if (i === failAt) {
        return {
          id,
          status: 'fail',
          stringsChecked: 48211,
          findings: [
            { file: 'world.jsonl', pointer: 'line 113 /profile/name', reason: 'L’HMAC di una stringa coincide con un token reale noto.' },
            { file: 'contracts/shipping-ext.openapi.json', pointer: '/paths/~1v1~1shipments/get/responses/200/content/application~1json/examples/in-transit/value/items/0/orderId', reason: 'Stringa non sintetica e non dichiarata come enum.' },
          ],
        };
      }
      return { id, status: 'pass', findings: [], stringsChecked: id === 'reverse-hmac' ? 48211 : undefined };
    });
    if (checks.every((c) => c.status === 'pass') && p.rulesApproved.length === 0) {
      // like the real gate: a pack without approved rules passes with a warning
      checks.push({ id: 'rules-approved', status: 'warn', findings: [{ file: 'rules.json', pointer: '/rules', reason: 'no approved rules: the mock will not evolve state over time' }] });
    }
    const done = checks.every((c) => c.status !== 'pending' && c.status !== 'running');
    const verdict: Publication['verdict'] = !done ? 'running' : checks.some((c) => c.status === 'fail') ? 'fail' : 'pass';
    const publishedAt = pubPublished.get(p.id);
    const status: Publication['status'] = verdict === 'running' ? 'building' : verdict === 'fail' ? 'gate-failed' : publishedAt ? 'published' : 'signed';
    return { ...p, checks, verdict, status, publishedAt, signedBy: verdict === 'pass' ? 'gate-2026-1' : undefined };
  }

  pubList.push(buildPublication('pub-0001', 'pk-20261019-0001', worldList[0], 'pia.publisher', t0 - 86400000 * 4));
  pubList.push(buildPublication('pub-0002', 'pk-20261021-0002', worldList[1], 'olga.operator', t0 - 86400000 * 2));
  pubPublished.set('pub-0001', iso(t0 - 86400000 * 4 + 3600000));

  // Audit chain
  const auditList: AuditEntry[] = [];
  function appendAudit(actor: string, action: string, target: string, result: AuditEntry['result'] = 'ok', at = now()): void {
    const prev = auditList.length ? auditList[auditList.length - 1].hash : GENESIS;
    const base = { seq: auditList.length + 1, at: iso(at), actor, action, target, result };
    auditList.push({ ...base, prevHash: prev, hash: auditHash(prev, base) });
  }
  const seedAudit: [string, string, string, AuditEntry['result']][] = [
    ['elena.admin', 'auth.login', 'elena.admin', 'ok'],
    ['elena.admin', 'user.create', 'olga.operator', 'ok'],
    ['elena.admin', 'user.create', 'rita.reviewer', 'ok'],
    ['olga.operator', 'source.token.create', 'sdk-node/shop-api', 'ok'],
    ['olga.operator', 'policy.propose', 'p-shop@7', 'ok'],
    ['paolo.approver', 'policy.approve', 'p-shop@7', 'ok'],
    ['anna.approver', 'policy.approve', 'p-shop@7', 'ok'],
    ['rita.reviewer', 'rule.approve', 'r-0003', 'ok'],
    ['rita.reviewer', 'rule.reject', 'r-0002', 'ok'],
    ['pia.publisher', 'world.generate', 'w-0001', 'ok'],
    ['pia.publisher', 'publish.run', 'pk-20261019-0001', 'ok'],
    ['pia.publisher', 'pack.download', 'pk-20261019-0001', 'ok'],
    ['vera.exporter', 'rule.approve', 'r-0007', 'denied'],
    ['olga.operator', 'world.generate', 'w-0002', 'ok'],
    ['olga.operator', 'publish.run', 'pk-20261021-0002', 'ok'],
    ['olga.operator', 'policy.propose', 'p-shop@8', 'ok'],
    ['paolo.approver', 'policy.approve', 'p-shop@8', 'ok'],
  ];
  seedAudit.forEach(([a, b, c, d], i) => appendAudit(a, b, c, d, t0 - (seedAudit.length - i) * 3600000 * 3));

  // Policy signing keys: a rotation in progress (pk2 endorsed by pk1, 11 of 12
  // sources confirmed it), pk0 revoked long ago.
  const mockSigningKeys: SigningKey[] = [
    { kid: 'pk0', alg: 'Ed25519', publicKey: 'Q2xvc2VkLWRlbW8tb25seS1rZXktMDAwMDAwMDAwMDA', revoked: true, active: false, trustedBy: 0 },
    {
      kid: 'pk1', alg: 'Ed25519', publicKey: 'RGVtby1vbmx5LWtleS0xLW5vdC1hLXJlYWwta2V5MDA', endorsedBy: 'pk0', revoked: false, active: false, trustedBy: 12,
      revoke: { seen: 12, confirmed: 11, required: 1, ok: false, blocker: 'rotation_unconfirmed' },
    },
    {
      kid: 'pk2', alg: 'Ed25519', publicKey: 'RGVtby1vbmx5LWtleS0yLW5vdC1hLXJlYWwta2V5MDA', endorsedBy: 'pk1', revoked: false, active: true, trustedBy: 11,
      revoke: { seen: 12, confirmed: 12, required: 1, ok: false, blocker: 'active_signing_key' },
    },
  ];

  // ------------------------------------------------------------ helpers
  const wait = () => (latency > 0 ? new Promise<void>((r) => setTimeout(r, latency)) : Promise.resolve());
  function need(perm: Permission): User {
    if (!current) throw new ApiError('unauthenticated', 'Non autenticato');
    if (!permissionsOf(current.roles).has(perm)) {
      appendAudit(current.username, perm, '-', 'denied');
      throw new ApiError('forbidden', `Permesso mancante: ${perm}`);
    }
    return current;
  }
  function authed(): User {
    if (!current) throw new ApiError('unauthenticated', 'Non autenticato');
    return current;
  }
  function iso(ms: number): string {
    return new Date(ms).toISOString();
  }
  function setCurrent(u: User | null): void {
    current = u;
    try {
      if (u) storage?.setItem('tt.mock.user', u.username);
      else storage?.removeItem('tt.mock.user');
    } catch {
      /* ignore */
    }
  }
  const clone = <T>(x: T): T => structuredClone(x);

  function ruleIndex(id: string): number {
    const i = rulesList.findIndex((r) => r.id === id);
    if (i < 0) throw new ApiError('not_found', `Regola ${id} non trovata`);
    return i;
  }

  // ------------------------------------------------------------ world graph
  function worldGraph(world: World, customerIndex: number): WorldGraph {
    const r = mulberry32(world.seed * 7919 + customerIndex);
    const arch = fx.archetypes().filter((a) => !a.belowK);
    const archetype = arch[Math.floor(r() * arch.length)].id;
    const num = (n: number) => String(n).padStart(4, '0');
    const cid = `CUS-SYN-${num(customerIndex + 1)}`;
    const nodes: WorldNode[] = [{ id: cid, type: 'customer', label: cid, state: archetype }];
    const edges: WorldGraph['edges'] = [];
    const orders = 1 + Math.floor(r() * 3);
    for (let i = 0; i < orders; i++) {
      const oid = `ORD-SYN-${num(Math.floor(r() * 9000) + 100)}`;
      nodes.push({ id: oid, type: 'order', label: oid, state: r() < 0.8 ? 'PAID' : 'CREATED' });
      edges.push({ from: cid, to: oid });
      const roll = r();
      if (roll < 0.03) continue; // never shipped
      const sid = `SHP-SYN-${num(Math.floor(r() * 9000) + 100)}`;
      const state = roll < 0.07 ? 'CANCELLED' : roll < 0.4 ? 'IN_TRANSIT' : roll < 0.9 ? 'DELIVERED' : 'CREATED';
      nodes.push({ id: sid, type: 'shipment', label: sid, state });
      edges.push({ from: oid, to: sid, rule: 'r-0007' });
    }
    return { customerId: cid, archetype, nodes, edges };
  }

  // ------------------------------------------------------------ world explorer (invented customers)
  const FIRST = ['Marta', 'Marco', 'Elena', 'Marco', 'Sara', 'Paolo', 'Chiara', 'Andrea', 'Marta', 'Davide'];
  const LAST = ['Rossi', 'Bianchi', 'Verdi', 'Neri', 'Galli', 'Conti', 'Ferri', 'Longo', 'Serra', 'Costa'];
  function worldCustomer(world: World, i: number): WorldCustomerRow {
    const g = worldGraph(world, i);
    const r = mulberry32(world.seed * 104729 + i);
    const first = FIRST[Math.floor(r() * FIRST.length)];
    const last = LAST[Math.floor(r() * LAST.length)];
    const entities: Record<string, number> = {};
    for (const n of g.nodes) if (n.type !== 'customer') entities[n.type] = (entities[n.type] ?? 0) + 1;
    return { id: g.customerId, name: `${first} ${last}`, email: `${first}.${last}.${i + 1}@example.com`.toLowerCase(), archetype: g.archetype, entities };
  }
  function worldCustomerDetail(world: World, i: number): WorldCustomerDetail {
    const g = worldGraph(world, i);
    const row = worldCustomer(world, i);
    const FLOW: Record<string, string[]> = { order: ['CREATED', 'PAID'], shipment: ['CREATED', 'IN_TRANSIT', 'DELIVERED'] };
    const t0 = Date.parse('2026-10-19T08:00:00Z');
    const entities: WorldEntity[] = g.nodes
      .filter((n) => n.type !== 'customer')
      .map((n, k) => {
        const flow = FLOW[n.type] ?? ['CREATED'];
        const stop = Math.max(0, flow.indexOf(n.state ?? ''));
        const upto = n.state && flow.includes(n.state) ? stop + 1 : flow.length;
        const steps = flow.slice(0, upto).map((status, j) => ({
          at: new Date(t0 + (k * 3 + j) * 3600_000 * 5).toISOString(),
          seq: j + 1,
          status: n.state && j === upto - 1 ? n.state : status,
          ...(n.type === 'shipment' && j > 0 ? { rule: 'r-0007' } : {}),
        }));
        return { id: n.id, entity: n.type, state: { status: n.state ?? steps[steps.length - 1].status }, steps };
      });
    return { id: row.id, name: row.name, email: row.email, archetype: row.archetype, entities };
  }

  // ------------------------------------------------------------ onboarding snippets
  function snippetsFor(choice: SourceChoice, token: string, group: string) {
    const core = 'https://tt-core.internal';
    const env = `TT_ENROLL_URL=${core} TT_ENROLL_TOKEN=${token} TT_HMAC_KEY=$(cat /run/secrets/tt-hmac-key)`;
    const keyNote = {
      title: 'Chiave HMAC (resta sulla macchina)',
      language: 'text' as const,
      text: '# La chiave HMAC non passa da tt-core: va creata e montata in locale (secret).\n# Serve a rendere stabili i token tra servizi. Non va mai nel repository.',
    };
    const by: Record<SourceChoice, { title: string; language: 'bash' | 'yaml' | 'text'; text: string }[]> = {
      'sdk-node': [{ title: 'Node.js', language: 'bash', text: `npm install @traffic-twin/sdk\n${env} \\\n  node --import @traffic-twin/sdk/register app.js` }],
      'sdk-python': [{ title: 'Python', language: 'bash', text: `pip install ./traffic_twin-<versione>-py3-none-any.whl\n${env} \\\n  python -m traffic_twin run -- uvicorn app:app` }],
      'sdk-java': [{ title: 'Java', language: 'bash', text: `curl -fsSLO https://tt-core.internal/dl/tt-sdk-java.jar\n${env} \\\n  java -javaagent:tt-sdk-java.jar -jar app.jar` }],
      'sdk-dotnet': [
        { title: '.NET', language: 'bash', text: 'dotnet add package TrafficTwin.Sdk' },
        { title: 'Program.cs', language: 'text', text: 'builder.Services.AddTrafficTwin();\napp.UseTrafficTwin();' },
        { title: 'Ambiente', language: 'bash', text: env },
      ],
      'sdk-go': [
        { title: 'Go', language: 'bash', text: 'go get github.com/ivseb/traffic-twin/sdk/go' },
        { title: 'main.go', language: 'text', text: 'srv := http.Server{Handler: tt.Middleware(mux)}\nclient := &http.Client{Transport: tt.RoundTripper(nil)}' },
        { title: 'Ambiente', language: 'bash', text: env },
      ],
      'sdk-php': [{ title: 'PHP', language: 'bash', text: `composer require traffic-twin/sdk\n${env} \\\n  php -d auto_prepend_file=vendor/traffic-twin/sdk/prepend.php public/index.php` }],
      egress: [
        { title: 'Helm', language: 'bash', text: `helm install tt-egress traffic-twin/egress \\\n  --set enroll.url=${core} \\\n  --set enroll.token=${token}` },
        { title: 'Base URL del servizio esterno', language: 'yaml', text: 'env:\n  - name: SHIPPING_BASE_URL\n    value: http://tt-egress/shipping   # prima: https://api.carrier.example' },
      ],
      obi: [{ title: 'OBI (eBPF)', language: 'yaml', text: `# DaemonSet di OBI con l'adattatore tt\nenv:\n  - { name: TT_ENROLL_URL, value: ${core} }\n  - { name: TT_ENROLL_TOKEN, value: ${token} }` }],
      'k8s-inject': [{ title: 'Annotazione sul deployment', language: 'yaml', text: `metadata:\n  annotations:\n    traffic-twin.io/inject: node\n    traffic-twin.io/enroll-token: ${token}\n    traffic-twin.io/group: ${group}` }],
      'import-har': [{ title: 'Import HAR', language: 'bash', text: `tt import har ./export.har --core ${core} --token ${token}` }],
    };
    const list = by[choice];
    return [...list, ...(choice.startsWith('sdk') || choice === 'k8s-inject' ? [keyNote] : [])];
  }

  const own = (id: string) => rulesList[ruleIndex(id)];

  // ------------------------------------------------------------ groups (group-scoped API)
  const inSel = (group: string | undefined, sel: string[] | null): boolean => !sel || (group !== undefined && sel.includes(group));
  const anySel = (groups: readonly string[] | undefined, sel: string[] | null): boolean => !sel || (groups ?? []).some((g) => sel.includes(g));
  /** Group of a service name in the demo (the first row; a service of unknown group has none). */
  const groupOfService = (name: string | undefined): string | undefined =>
    name ? (servicesList.find((s) => s.name === name)?.group ?? sourcesList.find((s) => s.serviceName === name)?.group) : undefined;
  const servicesOfRule = (r: Rule): string[] => [...new Set([r.cause?.service, ...r.effects.map((e) => e.target)].filter((s): s is string => !!s))];
  const ruleGroups = (r: Rule): string[] => [...new Set(servicesOfRule(r).map(groupOfService).filter((g): g is string => !!g))].sort();
  /** The row of a service for one group (the first row of the name without a group). */
  const serviceOf = (name: string, group: GroupSel) => {
    const sel = groupNames(group);
    return servicesList.find((x) => x.name === name && inSel(x.group, sel)) ?? (sel ? undefined : servicesList.find((x) => x.name === name));
  };
  const withGroup = <T extends { service: string }>(x: T): T & { group?: string } => {
    const g = groupOfService(x.service);
    return g === undefined ? x : { ...x, group: g };
  };

  // ------------------------------------------------------------ the API
  const api: Api = {
    capabilities: { alertResolve: true, webhookToggle: true, settingsEdit: true, twinOnServer: true },
    mocks: createDemoMockService({ need, authed, audit: (a, act, tg) => appendAudit(a, act, tg), now, wait, stepMs: latency > 0 ? 700 : 0 }),
    idFormats: createDemoIdFormats({ authed, audit: (a, act, tg) => appendAudit(a, act, tg), now, wait }),
    dateOffsets: createDemoDateOffsets({ authed, audit: (a, act, tg) => appendAudit(a, act, tg), now, wait }),
    opKinds: createDemoOpKinds({ authed, audit: (a, act, tg) => appendAudit(a, act, tg), now, wait }),
    system: {
      async status() {
        await wait();
        return { initialized, version: '0.1.0-dev', installation: 'shop-eu', environment: settings.environment, ssoEnabled: settings.sso.enabled, localEnabled: true, adapter: 'mock' };
      },
      async setup(req) {
        await wait();
        if (initialized) throw new ApiError('already_initialized', 'Il sistema è già configurato');
        if (!req.setupToken.startsWith('tts_')) throw new ApiError('invalid', 'Token di setup non valido');
        if (req.password.length < 12) throw new ApiError('invalid', 'Password troppo corta');
        usersList.push({ id: nextId('u-'), username: req.username, displayName: req.username, roles: ['admin'], authMethod: 'local' });
        initialized = true;
        appendAudit(req.username, 'system.setup', '-');
      },
    },
    auth: {
      async me() {
        await wait();
        return current ? clone(current) : null;
      },
      async login(c) {
        await wait();
        const u = usersList.find((x) => x.username === c.username && !x.disabled);
        if (!u || c.password !== fx.DEMO_PASSWORD || u.authMethod === 'sso') {
          appendAudit(c.username || '?', 'auth.login', c.username, 'denied');
          throw new ApiError('unauthenticated', 'Credenziali non valide');
        }
        setCurrent(u);
        appendAudit(u.username, 'auth.login', u.username);
        return clone(u);
      },
      async ssoLogin() {
        await wait();
        const u = usersList.find((x) => x.authMethod === 'sso' && x.roles.includes('rule-reviewer'))!;
        setCurrent(u);
        appendAudit(u.username, 'auth.sso', u.username);
        return clone(u);
      },
      async logout() {
        await wait();
        if (current) appendAudit(current.username, 'auth.logout', current.username);
        setCurrent(null);
      },
    },
    sources: {
      async list() {
        await wait();
        authed();
        return clone(sourcesList);
      },
      async revoke(id) {
        await wait();
        const u = need('sources.manage');
        const s = sourcesList.find((x) => x.id === id);
        if (!s) throw new ApiError('not_found', 'Sorgente non trovata');
        s.revoked = true;
        appendAudit(u.username, 'source.revoke', id);
      },
      async setSampling(id, bp) {
        await wait();
        const u = need('sources.manage');
        const s = sourcesList.find((x) => x.id === id);
        if (!s) throw new ApiError('not_found', 'Sorgente non trovata');
        if (bp < 0 || bp > s.policyRateBp) throw new ApiError('invalid', 'Si può solo abbassare il tasso della policy');
        s.samplingBp = bp;
        appendAudit(u.username, 'source.sampling', `${id}=${bp}bp`);
      },
      async kill(scope, active) {
        await wait();
        const u = need('sources.kill');
        for (const s of sourcesList) {
          if (scope.all || (scope.group && s.group === scope.group) || (scope.sourceId && s.id === scope.sourceId)) {
            s.killed = active;
            s.state = active ? 'killed' : 'capturing';
          }
        }
        appendAudit(u.username, active ? 'kill.on' : 'kill.off', scope.all ? 'all' : (scope.group ?? scope.sourceId ?? '-'));
      },
    },
    onboarding: {
      async createToken(choice, group) {
        await wait();
        const u = need('sources.manage');
        if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(group)) throw new ApiError('invalid', 'Nome gruppo non valido');
        const r = mulberry32(seq * 31 + group.length);
        const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
        const body = Array.from({ length: 28 }, () => alphabet[Math.floor(r() * alphabet.length)]).join('');
        const tokenId = nextId('tok-');
        const token = `tte_${body}`;
        const at = now();
        tokens.set(tokenId, { at, choice, group, expiresAt: at + 3600_000 });
        appendAudit(u.username, 'source.token.create', `${choice}/${group}`);
        const out: EnrollmentToken = { tokenId, token, expiresAt: iso(at + 3600_000), choice, group, snippets: snippetsFor(choice, token, group) };
        return out;
      },
      async status(tokenId) {
        await wait();
        authed();
        const tk = tokens.get(tokenId);
        if (!tk) throw new ApiError('not_found', 'Token sconosciuto');
        const t = (now() - tk.at) / 1000;
        const problems: Problem[] = [];
        if (now() > tk.expiresAt) problems.push({ code: 'token_expired', message: 'Il token di iscrizione è scaduto.', hint: 'Torna al passo 2 e generane uno nuovo.' });
        if (tk.choice === 'sdk-php' && t >= 7)
          problems.push({ code: 'no_subject_found', message: 'Nessun utente riconosciuto nell’header configurato.', hint: 'Controlla identity.subject nella policy: header "authorization" con claim "sub".' });
        const out: OnboardingStatus = {
          enrolled: t >= 3,
          policyReceived: t >= 5,
          firstEvents: t < 6 ? 0 : Math.min(20, Math.floor((t - 6) * 4)),
          problems,
        };
        return out;
      },
      watch(tokenId, onStatus, onError) {
        let stopped = false;
        const poll = async () => {
          try {
            const s = await api.onboarding.status(tokenId);
            if (!stopped) onStatus(s);
          } catch (e) {
            if (!stopped) onError?.(e instanceof Error ? e : new Error(String(e)));
          }
        };
        void poll();
        const h = setInterval(poll, 1500);
        return () => {
          stopped = true;
          clearInterval(h);
        };
      },
      async discovered(tokenId) {
        await wait();
        authed();
        const tk = tokens.get(tokenId);
        const ownName = tk?.group ?? 'shop-api';
        const list: DiscoveredService[] = [
          { name: ownName, kind: 'own', calls: 2310, operations: 6, proposeTwin: false },
          { name: 'shipping-ext', kind: 'external', baseUrl: 'https://api.carrier.example', hostPattern: 'api.carrier.example', calls: 1180, operations: 3, proposeTwin: true },
          { name: 'payments-ext', kind: 'external', baseUrl: 'https://api.pay.example', hostPattern: 'api.pay.example', calls: 842, operations: 2, proposeTwin: true },
          { name: 'tax-ext', kind: 'external', baseUrl: 'https://tax.example', hostPattern: 'tax.example', calls: 14, operations: 1, proposeTwin: false },
        ];
        return list;
      },
      async observe(group) {
        await wait();
        authed();
        // The demo listens for a few seconds after the token, then shows the observe version (policy.md §7).
        const tk = [...tokens.values()].filter((x) => x.group === group).sort((a, b) => b.at - a.at)[0];
        const started = tk ? tk.at + 5000 : t0 - 86400000 * 6;
        const elapsed = (now() - started) / 1000;
        const listening = elapsed < 12;
        const events = Math.max(0, Math.min(400, Math.floor(elapsed * 25)));
        const masked: ObserveStatus['masked'] = listening
          ? []
          : suggestions
              .filter((s) => s.suggestion.action === 'hmac')
              .map((s) => ({ service: s.service, op: s.op, part: s.part, kind: s.path.startsWith('$') ? ('body' as const) : s.path.startsWith('path.') ? ('path' as const) : ('query' as const), field: s.path.replace(/^(path|query)\./, ''), domain: s.suggestion.arg || 'id' }));
        const out: ObserveStatus = {
          group,
          policyId: `p-${group}`,
          enabled: true,
          auto: !observeOff.has(group),
          phase: elapsed < 0 ? 'no_policy' : listening ? 'listening' : 'masked',
          activeVersion: listening ? 1 : 2,
          startedAt: iso(started),
          dueAt: iso(started + 15 * 60_000),
          minEvents: 200,
          events,
          ...(listening ? {} : { observeVersion: 2, observeActivatedAt: iso(started + 12_000) }),
          discoveryUntil: iso(started + 72 * 3600_000),
          samplingBp: 1000,
          services: elapsed < 3 ? [] : [
            { service: group, kind: 'inbound', calls: Math.floor(events * 0.6), ops: 4 },
            { service: 'host:api.carrier.example', kind: 'external', calls: Math.floor(events * 0.3), ops: 2 },
            { service: 'host:api.pay.example', kind: 'external', calls: Math.floor(events * 0.1), ops: 1 },
          ],
          masked,
          ...(identityChosen.has(group)
            ? { identity: { ...identityChosen.get(group)! } }
            : listening
              ? {}
              : { identity: { from: 'header', name: 'authorization', claim: 'sub' } }),
          ...(Object.keys(familiesOf.get(group) ?? {}).length ? { families: clone(familiesOf.get(group)!) } : {}),
          testKMin: testKOf.get(group) ?? 0,
          kMin: 20,
          identityCandidates: elapsed < 3 ? [] : demoIdentityCandidates.map((c) => ({ ...c })),
          ...(elapsed < 3 ? {} : { identityBest: { from: 'header' as const, name: 'authorization', claim: 'sub' } }),
          sampling: { currentBp: 1000, sampledSubjects: listening ? 0 : 31, source: listening ? 'no_identity' : 'subject', kMin: 20, targetSubjects: 40, enough: false, populationEstimate: 310, suggestedBp: 1300 },
        };
        return out;
      },
      async setObserveAuto(group, auto) {
        await wait();
        authed();
        if (auto) observeOff.delete(group);
        else observeOff.add(group);
        return this.observe(group);
      },
      async setIdentity(group, identity) {
        await wait();
        const u = need('policy.propose');
        const name = identity.from === 'header' ? identity.name.trim().toLowerCase() : identity.name.trim();
        const jsonPath = identity.jsonPath?.trim() || undefined;
        const claim = jsonPath ? undefined : identity.claim?.trim() || undefined;
        if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(name) || (claim !== undefined && !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(claim))) {
          throw new ApiError('invalid', 'identity needs from (header or cookie), a valid name and, optionally, a valid JWT claim');
        }
        // spec v1.18: a member of a JSON header, header only.
        if (jsonPath !== undefined && (identity.from !== 'header' || !/^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,7}$/.test(jsonPath))) {
          throw new ApiError('invalid', 'json_path is a dotted path of 1 to 8 members, read from a header');
        }
        const policyId = policyList.find((p) => p.status === 'active' && (p.groups ?? []).includes(group))?.policyId ?? 'p-shop';
        const cur = identityChosen.get(group) ?? { from: 'header' as const, name: 'authorization', claim: 'sub' };
        const label = (s: IdentitySource) => `${s.from} ${s.name}${s.claim ? ` · ${s.claim}` : ''}${s.jsonPath ? ` · json ${s.jsonPath}` : ''}`;
        const next: IdentitySource = { from: identity.from, name, ...(claim ? { claim } : {}), ...(jsonPath ? { jsonPath } : {}) };
        if (label(cur) === label(next)) throw new ApiError('invalid', 'the decisions do not change the policy');
        const safe = identityObserveSafe(next.from, next.name, next.claim, next.jsonPath);
        const version = Math.max(...policyList.filter((p) => p.policyId === policyId).map((p) => p.version), 0) + 1;
        const pv: PolicyVersion = {
          policyId,
          version,
          groups: policyList.find((p) => p.policyId === policyId)?.groups ?? [group],
          status: safe ? 'active' : 'draft',
          proposedBy: u.username,
          proposedAt: iso(now()),
          origin: 'propose',
          opensData: !safe,
          opensValues: !safe,
          valueReasons: safe ? [] : [{ code: 'identity', where: 'identity.subject' }],
          approvalsRequired: safe ? 0 : settings.approvals.openingRequired,
          approvals: [],
          diff: [{ change: 'changed', where: 'identity.subject', from: label(cur), to: label(next) }],
          yamlBefore: `identity:\n  subject: {from: ${cur.from}, name: ${cur.name}${cur.claim ? `, jwt_claim: ${cur.claim}` : ''}}\n`,
          yamlAfter: `identity:\n  subject: {from: ${next.from}, name: ${next.name}${next.claim ? `, jwt_claim: ${next.claim}` : ''}}\n`,
        };
        if (safe) {
          for (const p of policyList) if (p.policyId === policyId && p.status === 'active') p.status = 'superseded';
          pv.approvalMode = 'observe';
          pv.hash = 'sha256:' + sha256Hex(pv.yamlAfter).slice(0, 8);
          identityChosen.set(group, next);
        }
        policyList.push(pv);
        appendAudit(u.username, 'policy.identity_set', `${group} ${label(next)}`);
        return pv;
      },
      async setFamily(group, family, domains) {
        await wait();
        const u = need('policy.propose');
        const name = family.trim();
        const ds = [...new Set(domains.map((d) => d.trim()).filter(Boolean))].sort();
        const re = /^[a-z][a-z0-9_-]{0,31}$/;
        if (!re.test(name) || ds.length < 2 || ds.length > 16 || ds.some((d) => !re.test(d)) || [name, ...ds].includes('subject')) {
          throw new ApiError('invalid', 'a family has a domain name and 2 to 16 domains (subject is reserved)', 422, 'invalid_family');
        }
        const fams = familiesOf.get(group) ?? {};
        for (const [f, list] of Object.entries(fams)) if (f !== name && list.some((d) => ds.includes(d))) throw new ApiError('conflict', `a domain is already in family ${f}`, 409, 'domain_in_family');
        familiesOf.set(group, { ...fams, [name]: ds });
        appendAudit(u.username, 'policy.families_set', `${group} ${name}: ${ds.join(', ')}`);
        return familyVersion(group, u.username, `hmac.families.${name}`, ds.join(', '));
      },
      async removeFamily(group, family) {
        await wait();
        const u = need('policy.propose');
        const fams = { ...(familiesOf.get(group) ?? {}) };
        if (!fams[family]) throw new ApiError('not_found', 'the policy has no such family', 404, 'unknown_family');
        delete fams[family];
        familiesOf.set(group, fams);
        appendAudit(u.username, 'policy.families_removed', `${group} ${family}`);
        return familyVersion(group, u.username, `hmac.families.${family}`, '');
      },
      async setTestK(group, kMin, reason) {
        await wait();
        const u = need('policy.propose');
        if (!isAdmin(u)) throw new ApiError('forbidden', 'only an administrator marks a group as test', 403, 'forbidden');
        if (!Number.isInteger(kMin) || (kMin !== 0 && (kMin < 2 || kMin >= 20))) throw new ApiError('invalid', 'k_min is 0 or between 2 and k − 1', 422, 'invalid_k_min');
        if (kMin > 0 && !reason.trim()) throw new ApiError('invalid', 'a reason is required', 422, 'reason_required');
        if (kMin > 0) testKOf.set(group, kMin);
        else testKOf.delete(group);
        appendAudit(u.username, 'fleet.group_test_k', `${group} k=${kMin}`);
        return this.observe(group);
      },
      async assist(_group) {
        await wait();
        authed();
        // Operations per service, as tt-core templates them from the traffic (the fixtures are already templates).
        const list = clone(suggestions);
        const services: AssistService[] = [];
        for (const sg of list) {
          let svc = services.find((x) => x.service === sg.service);
          if (!svc) {
            const ext = sg.service.endsWith('-ext');
            svc = { service: sg.service, kind: ext ? 'external' : 'own', declared: true, name: sg.service, exact: true, calls: 0, ops: [] };
            services.push(svc);
          }
          let op = svc.ops.find((o) => o.op === sg.op);
          if (!op) {
            op = { op: sg.op, declared: true, calls: sg.observed, needCalls: 0, rawOps: [sg.op], fields: [] };
            svc.ops.push(op);
            svc.calls += sg.observed;
          }
          op.fields.push(sg);
          // The server proposes declared services as they are (preselect only for undeclared hosts called by the group).
          svc.preselect = false;
        }
        // An old `host:` row of the carrier, folded into the declared service, and a host not called lately.
        const carrier = services.find((x) => x.service === 'shipping-ext');
        if (carrier) carrier.mergedPatterns = ['webhooks.carrier.example:8443'];
        services.push({
          service: 'host:sandbox.carrier.example',
          kind: 'external',
          declared: false,
          name: 'sandbox.carrier.example',
          hostPattern: 'sandbox.carrier.example',
          exact: true,
          calls: 380,
          preselect: false,
          stale: true,
          ops: [{ op: 'GET /v1/ping', declared: false, calls: 380, needCalls: 0, rawOps: ['GET /v1/ping'], fields: [] }],
        });
        const out: PolicyAssist = { policyId: 'p-shop', minCalls: 20, ready: true, needCalls: 0, hasIdentity: true, identityCandidates: demoIdentityCandidates.map((c) => ({ ...c })), identityBest: { from: 'header', name: 'authorization', claim: 'sub' }, services, suggestions: list };
        return out;
      },
    },
    policies: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return clone(policyList.filter((p) => anySel(p.groups, sel)));
      },
      async propose(input) {
        await wait();
        const u = need('policy.propose');
        const chosen: Record<string, PolicyChoice> = {};
        for (const c of input.choices) chosen[c.suggestionId] = c.choice;
        const policyId = input.policyId ?? 'p-shop';
        const hostsFrom = hostsOf(policyId);
        const hostsTo = input.hostsDiscovery ?? hostsFrom;
        const diff = [...diffChoices(activeChoices, chosen), ...hostsDiff(hostsFrom, hostsTo)];
        if (diff.length === 0) throw new ApiError('invalid', 'Nessuna modifica rispetto alla policy attiva');
        const version = Math.max(...policyList.filter((p) => p.policyId === policyId).map((p) => p.version), 0) + 1;
        const o = opens(diff);
        // policy.md §7: only a change that opens values waits for approvals; the others apply at once.
        const reasons = valueReasonsOf(diff, input.identity);
        const now0 = iso(now());
        versionHosts.set(`${policyId}@${version}`, hostsTo);
        const pv: PolicyVersion = {
          policyId,
          version,
          groups: policyList.find((p) => p.policyId === policyId)?.groups ?? [],
          status: reasons.length ? 'draft' : 'active',
          proposedBy: u.username,
          proposedAt: now0,
          opensData: o,
          opensValues: reasons.length > 0,
          valueReasons: reasons,
          approvalsRequired: reasons.length ? settings.approvals.openingRequired : 0,
          approvals: [],
          diff,
          yamlBefore: policyYamlOf(suggestions, activeChoices, hostsFrom),
          yamlAfter: policyYamlOf(suggestions, chosen, hostsTo),
        };
        if (!reasons.length) {
          for (const p of policyList) if (p.policyId === policyId && p.status === 'active') p.status = 'superseded';
          pv.approvalMode = 'observe';
          pv.hash = 'sha256:' + sha256Hex(pv.yamlAfter).slice(0, 8);
          Object.assign(activeChoices, chosen);
        }
        policyList.push(pv);
        appendAudit(u.username, 'policy.propose', `${policyId}@${version}`);
        if (!reasons.length) appendAudit(u.username, 'policy.activate', `${policyId}@${version} observe`);
        return clone(pv);
      },
      async preview(input) {
        await wait();
        authed();
        const chosen: Record<string, PolicyChoice> = {};
        for (const c of input.choices) chosen[c.suggestionId] = c.choice;
        const from = hostsOf('p-shop');
        const reasons = valueReasonsOf([...diffChoices(activeChoices, chosen), ...hostsDiff(from, input.hostsDiscovery ?? from)], input.identity);
        return {
          before: policyYamlOf(suggestions, activeChoices, from),
          after: policyYamlOf(suggestions, chosen, input.hostsDiscovery ?? from),
          skipped: [],
          opensValues: reasons.length > 0,
          valueReasons: reasons,
          approvalsRequired: reasons.length ? settings.approvals.openingRequired : 0,
        };
      },
      async hostsDiscovery(_group) {
        await wait();
        authed();
        return hostsOf('p-shop');
      },
      async approvers(_group) {
        await wait();
        const u = need('sources.manage');
        return usersList
          .filter((x) => !x.disabled && (x.roles.includes('policy-approver') || x.roles.includes('admin')))
          .map((x) => ({ name: x.authMethod === 'local' ? x.username : '', displayName: x.displayName.split('@')[0] || x.username, roles: x.roles.filter((r): r is 'policy-approver' | 'admin' => r === 'policy-approver' || r === 'admin'), self: x.id === u.id }))
          .sort((a, b) => Number(b.roles.includes('policy-approver')) - Number(a.roles.includes('policy-approver')) || a.displayName.localeCompare(b.displayName));
      },
      async withdraw(policyId, version, _reason) {
        await wait();
        const u = authed();
        const pv = policyList.find((p) => p.policyId === policyId && p.version === version);
        if (!pv) throw new ApiError('not_found', 'Versione non trovata');
        if (pv.status !== 'draft') throw new ApiError('conflict', 'La versione non è più in bozza');
        const mine = pv.proposedBy === u.username || pv.proposedBy === u.displayName;
        if (!mine && !isAdmin(current)) throw new ApiError('forbidden', 'Solo chi ha proposto la bozza o un amministratore può ritirarla');
        pv.status = 'withdrawn';
        appendAudit(u.username, 'policy.withdraw', `${policyId}@${version}`);
        return clone(pv);
      },
      async approve(policyId, version, reason) {
        await wait();
        // An approval by an admin is always the admin override (reason, alert),
        // as in tt-core; keyguard may switch it off.
        const override = isAdmin(current);
        if (override && !settings.approvals.adminOverride) throw new ApiError('forbidden', 'L’approvazione dell’amministratore è disattivata in keyguard');
        const u = override ? authed() : need('policy.approve');
        const pv = policyList.find((p) => p.policyId === policyId && p.version === version);
        if (!pv) throw new ApiError('not_found', 'Versione non trovata');
        if (pv.status !== 'draft') throw new ApiError('conflict', 'La versione non è più in bozza');
        if (pv.approvals.some((a) => a.by === u.username)) throw new ApiError('conflict', 'Hai già approvato questa versione');
        if (override && !reason?.trim()) throw new ApiError('invalid', 'L’approvazione dell’amministratore richiede una motivazione');
        if (!override && pv.approvalsRequired === 2 && pv.proposedBy === u.username) throw new ApiError('conflict', 'Chi propone non può approvare una modifica che apre dati');
        pv.approvals.push(override ? { by: u.username, at: iso(now()), mode: 'admin', reason: reason!.trim() } : { by: u.username, at: iso(now()), mode: 'standard' });
        if (override || pv.approvals.length >= pv.approvalsRequired) {
          for (const p of policyList) if (p.policyId === policyId && p.status === 'active') p.status = 'superseded';
          pv.status = 'active';
          pv.hash = 'sha256:' + sha256Hex(pv.yamlAfter).slice(0, 8);
          pv.approvalMode = override ? 'admin' : pv.approvalsRequired === 1 && pv.opensData ? 'single' : 'standard';
        }
        if (override) {
          alertsList.unshift({ id: nextId('al-'), type: 'policy.admin_approval', severity: 'warning', service: policyId, change: `approvazione dell’amministratore ${u.username} su ${policyId}@${version}: «${reason!.trim()}»`, firstSeen: iso(now()), state: 'open' });
        }
        appendAudit(u.username, override ? 'policy.approve.admin' : 'policy.approve', `${policyId}@${version}`);
        return clone(pv);
      },
    },
    scope: {
      async get() {
        await wait();
        authed();
        const groups = [...new Set(sourcesList.map((x) => x.group))].sort();
        const services: Record<string, string[]> = {};
        for (const sv of servicesList) {
          const own = sourcesList.filter((x) => x.serviceName === sv.name).map((x) => x.group);
          services[sv.name] = [...new Set([...(services[sv.name] ?? []), ...own, ...(sv.group ? [sv.group] : [])])].sort();
        }
        return { groups, mine: groups.includes('shop-api') ? ['shop-api'] : groups.slice(0, 1), services };
      },
    },
    gate: {
      async keys() {
        await wait();
        authed();
        const value = 'pack-1:' + 'D'.repeat(43);
        return { value, command: `TT_GATE_PUBKEYS='${value}' tt mock --pack <file.ttpack>`, keys: [{ kid: 'pack-1', publicKey: 'D'.repeat(43) }] };
      },
      async keyFile() {
        await wait();
        authed();
        return { filename: 'gate-keys.txt', blob: new Blob(['# traffic-twin: public keys of the publication gate (demo)\npack-1:' + 'D'.repeat(43) + '\n'], { type: 'text/plain' }) };
      },
    },
    hosts: {
      async list(groups) {
        await wait();
        need('hosts.twin');
        const reg = hostsRegistry(now(), hostsOf('p-shop') === 'off');
        const sel = groupNames(groups);
        if (!sel) return reg;
        // One entry per (group, pattern): only the entries of the selected groups, domains recomputed.
        const domains = reg.domains
          .map((d) => {
            const patterns = d.patterns.filter((p) => inSel(p.group, sel));
            return { ...d, patterns, calls: patterns.reduce((a, p) => a + p.calls, 0) };
          })
          .filter((d) => d.patterns.length > 0);
        return { ...reg, domains };
      },
      async twinPreview(input) {
        await wait();
        need('hosts.twin');
        // As twin() below: the demo's draft opens values and waits for the approvals.
        const name = input.service?.trim() || 'servizio';
        return { opensValues: true, valueReasons: [{ code: 'keep', where: `services.${name}` }], approvalsRequired: settings.approvals.openingRequired };
      },
      async twin(input) {
        await wait();
        const u = need('hosts.twin');
        const pattern = input.pattern.replace(/^host:/, '');
        const fail = (status: 'invalid' | 'conflict', serverCode: string, message: string): never => {
          appendAudit(u.username, 'host.twin', pattern.replaceAll(STAR, '_'), 'error');
          throw new ApiError(status, message, status === 'conflict' ? 409 : 422, serverCode);
        };
        const reg = hostsRegistry(now(), hostsOf('p-shop') === 'off');
        const all = reg.domains.flatMap((d) => d.patterns);
        const entry = all.find((p) => p.pattern === pattern && (!input.group || p.group === input.group));
        if (isSystemPattern(pattern) || !entry) return fail('invalid', 'invalid_pattern', 'not a host pattern');
        const policyId = input.policyId ?? (entry.policies.length === 1 ? entry.policies[0] : '');
        if (!policyId) return fail('invalid', 'policy_required', 'policy_id is required');
        let base = input.base?.trim() ?? '';
        if (!base) {
          if (!exactBaseUrl(pattern)) return fail('invalid', 'base_required', 'the pattern has {*} labels or is an IP class: give the exact base');
          // The scheme is never guessed: the events do not carry it.
          if (!input.scheme) return fail('invalid', 'scheme_required', 'choose the scheme of the host (http or https)');
          base = exactBaseUrl(pattern, input.scheme) ?? '';
        }
        const chk = checkBase(pattern, base);
        if (!chk.ok) return fail('invalid', chk.code, chk.code === 'invalid_base' ? 'base must be http(s)://host[:port][/segment...]' : 'the base is not described by the pattern');
        const name = input.service?.trim() || defaultServiceName(base) || '';
        if (!validServiceName(name)) return fail('invalid', 'invalid_service', 'service must match ^[a-z0-9][a-z0-9._-]{0,62}$');
        if (servicesList.some((x) => x.name === name)) return fail('conflict', 'service_exists', 'the policy already has a service with this name');
        const hostPort = chk.port ? `${chk.host}:${chk.port}` : chk.host;
        if (all.some((p) => p.declared && p.pattern === hostPort)) return fail('conflict', 'already_declared', 'the policy already declares a service with this base');

        const active = policyList.find((p) => p.policyId === policyId && p.status === 'active');
        if (!active) return fail('invalid', 'invalid_policy', 'the policy has no version to extend');
        const doc = parseDocument(active.yamlAfter);
        doc.setIn(['services', name, 'match', 'base'], base);
        const version = Math.max(...policyList.filter((p) => p.policyId === policyId).map((p) => p.version), 0) + 1;
        const pv: PolicyVersion = {
          policyId,
          version,
          groups: active.groups ?? [],
          status: 'draft',
          origin: 'host-twin',
          proposedBy: u.username,
          proposedAt: iso(now()),
          opensData: true,
          opensValues: true,
          valueReasons: [{ code: 'keep', where: `services.${name}` }],
          approvalsRequired: settings.approvals.openingRequired,
          approvals: [],
          diff: [{ change: 'added', where: `services.${name}.match.base`, to: base }],
          yamlBefore: active.yamlAfter,
          yamlAfter: String(doc),
        };
        versionHosts.set(`${policyId}@${version}`, hostsOf(policyId));
        policyList.push(pv);
        appendAudit(u.username, 'host.twin', pattern.replaceAll(STAR, '_'));
        appendAudit(u.username, 'policy.host-twin', `${policyId}@${version}`);
        return clone(pv);
      },
    },
    services: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return clone(servicesList.filter((s) => inSel(s.group, sel)));
      },
      async setTwin(name, twin, group) {
        await wait();
        const u = need('sources.manage');
        const s = servicesList.find((x) => x.name === name && (!group || x.group === group));
        if (!s) throw new ApiError('not_found', 'Servizio non trovato');
        s.twin = twin;
        appendAudit(u.username, 'service.twin', `${group ? `${group}/` : ''}${name}=${twin}`);
      },
    },
    contracts: {
      async status(name, group) {
        await wait();
        authed();
        const ops = fx.operationSummaries(now()).filter((o) => o.service === name);
        const info = serviceOf(name, group);
        if (!info) throw new ApiError('not_found', 'Servizio non trovato');
        const snaps = fx.snapshots(name);
        return {
          service: name,
          calls: info.calls,
          operations: ops.length || info.operations,
          readyOperations: ops.filter((o) => o.calls >= 20).length,
          bestOpCalls: Math.max(0, ...ops.map((o) => o.calls)),
          minCalls: 20,
          kMin: 20,
          inferredOperations: 0,
          snapshot: snaps.length ? { id: snaps[snaps.length - 1].id, createdAt: snaps[snaps.length - 1].date, ops: ops.length } : undefined,
          nextSnapshotAt: iso(Math.ceil(now() / 86400000) * 86400000 + 300000),
          windowHours: 24,
        };
      },
      async refreshNow() {
        await wait();
        need('sources.manage');
      },
      async service(name, group) {
        await wait();
        authed();
        const info = serviceOf(name, group);
        if (!info) throw new ApiError('not_found', 'Servizio non trovato');
        const ops = fx.operationSummaries(now()).filter((o) => o.service === name);
        const calls = ops.reduce((a, o) => a + o.calls, 0) || 1;
        const errCalls = ops.reduce((a, o) => a + o.statuses.filter((s) => s.status >= 400).reduce((b, s) => b + s.calls, 0), 0);
        const w = (k: 'p50' | 'p95') => Math.round(ops.reduce((a, o) => a + o.latencyMs[k] * o.calls, 0) / calls);
        const drifts = alertsList.filter((x) => x.type === 'contract.drift' && x.service === name).sort((p, q) => q.firstSeen.localeCompare(p.firstSeen));
        const gaps = fx.gaps().filter((g) => g.service === name);
        const out: ServiceSummary = {
          service: clone(info),
          alias: settings.anonymizeHosts && info.kind === 'external' ? info.name.replace(/-ext$/, '') : undefined,
          operations: ops.length,
          calls: ops.reduce((a, o) => a + o.calls, 0),
          errorRate: errCalls / calls,
          latencyMs: { p50: w('p50'), p95: w('p95') },
          lastDrift: drifts[0] ? { at: drifts[0].firstSeen, severity: drifts[0].severity === 'breaking' ? 'breaking' : 'non-breaking', open: drifts[0].state !== 'resolved' } : undefined,
          coverage: {
            fewSamples: ops.filter((o) => o.fewSamples).length,
            statusesNeverSeen: gaps.filter((g) => g.kind === 'status-never-seen').length,
            lowSupportRules: rulesList.filter((r) => r.cause?.service === name && r.counts.causes < fx.LOW_SUPPORT_MIN).length,
          },
          snapshots: fx.snapshots(name).length,
        };
        return out;
      },
      async openapi(name, group) {
        await wait();
        authed();
        const info = serviceOf(name, group);
        if (!info) throw new ApiError('not_found', 'Servizio non trovato');
        const details = fx.operationSummaries(now()).filter((o) => o.service === name).map((o) => fx.operationDetail(now(), name, o.op)!);
        return buildOpenApi(info, details, settings.anonymizeHosts && info.kind === 'external' ? name.replace(/-ext$/, '') : undefined);
      },
      async postman(name, group, baseUrl) {
        await wait();
        authed();
        const doc = await api.contracts.openapi(name, group);
        return { filename: `${name}.postman_collection.json`, blob: new Blob([JSON.stringify(postmanOf(name, doc, baseUrl), null, 2)], { type: 'application/json' }) };
      },
      async rawDocument(name, format, group) {
        await wait();
        authed();
        const doc = await api.contracts.openapi(name, group);
        return format === 'json' ? JSON.stringify(doc, null, 2) : toYaml(doc);
      },
      async operations(service, group) {
        await wait();
        authed();
        const sel = groupNames(group);
        // Each operation carries the group of its service; a filter keeps the services of the groups.
        const all = fx.operationSummaries(now()).map(withGroup).filter((o) => inSel(o.group, sel));
        return clone(service ? all.filter((o) => o.service === service) : all);
      },
      async operation(service, op) {
        await wait();
        authed();
        const d = fx.operationDetail(now(), service, op);
        if (!d) throw new ApiError('not_found', 'Operazione non trovata');
        return d;
      },
      async snapshots(service) {
        await wait();
        authed();
        return service === 'shipping-ext' ? fx.snapshots(service) : fx.snapshots(service).map((s) => ({ ...s, breaking: 0, nonBreaking: 0 }));
      },
      async diff(service, from, to) {
        await wait();
        authed();
        const snaps = fx.snapshots(service);
        const a = snaps.findIndex((s) => s.id === from);
        const b = snaps.findIndex((s) => s.id === to);
        if (a < 0 || b < 0) throw new ApiError('not_found', 'Fotografia non trovata');
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        const changes = service === 'shipping-ext' ? fx.SNAPSHOT_CHANGES.slice(lo + 1, hi + 1).flat() : [];
        return {
          service,
          from: snaps[lo].id,
          to: snaps[hi].id,
          changes,
          before: service === 'shipping-ext' ? fx.snapshotFragment(lo) : '{}',
          after: service === 'shipping-ext' ? fx.snapshotFragment(hi) : '{}',
        };
      },
    },
    rules: {
      async status(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        const mine = rulesList.filter((r) => anySel(ruleGroups(r), sel));
        const approved = mine.filter((r) => r.status === 'approved').length;
        // Rules v1.9: the demo shows one structure below k (C0) and one pair of domains to join (C15), invented.
        const testK = Object.fromEntries([...testKOf].filter(([g]) => !sel || sel.includes(g)));
        return {
          state: 'ok' as const, minHours: 1, observedHours: 336, events: 52_000, lastRunAt: iso(now()), rules: { approved, draft: mine.length - approved }, warnings: [] as string[], diagnostics: [],
          candidates: fx.demoCandidates().filter((c) => !sel || !c.group || sel.includes(c.group)),
          families: fx.demoFamilies().filter((f) => !sel || !f.group || sel.includes(f.group)).filter((f) => ![...familiesOf.values()].some((fs) => Object.values(fs).some((ds) => f.domains.every((d) => ds.includes(d))))),
          ...(Object.keys(testK).length ? { testK } : {}),
        };
      },
      async mine(onProgress) {
        onProgress?.({ status: 'running', elapsedS: 0 });
        await wait();
        const u = need('rules.mine');
        appendAudit(u.username, 'rules.mine', '-');
        return { newRules: 0, updatedRules: 0, staleRules: 0, events: 52_000, state: 'ok' as const, reasons: [] as string[], warnings: [] as string[], diagnostics: [], finishedAt: iso(now()) };
      },
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return clone(rulesList.map((r) => ({ ...r, groups: ruleGroups(r) })).filter((r) => anySel(r.groups, sel)));
      },
      async get(id) {
        await wait();
        authed();
        return clone(own(id));
      },
      async setAfter(id, effectId, after) {
        await wait();
        const u = need('rules.edit');
        if (!/^[0-9]+(s|m|h|d)$/.test(after)) throw new ApiError('invalid', 'Ritardo non valido (es. 5m, 4h, 2d)');
        const r = own(id);
        if (r.status === 'approved' || r.status === 'rejected') throw new ApiError('conflict', 'Una regola approvata o rifiutata non si modifica: serve una nuova bozza');
        const e = r.effects.find((x) => x.id === effectId);
        if (!e) throw new ApiError('not_found', 'Effetto non trovato');
        e.after = after;
        appendAudit(u.username, 'rule.edit', `${id}/${effectId}=${after}`);
        return clone(r);
      },
      async catalog(groups) {
        await wait();
        authed();
        // A group with no source yet (a new team): contracts and states are still unknown, so the catalog is empty and
        // the editor says so (usability test #4, M1).
        const gs = groups === null || groups === undefined ? [] : typeof groups === 'string' ? [groups] : [...groups];
        if (gs.length && !gs.some((g) => sourcesList.some((x) => x.group === g))) return { services: [], entities: [] };
        // `reports` is the demo's group whose status never left in clear: contracts, but no states to write rules on.
        if (gs.length && gs.every((g) => g === 'reports')) return { ...clone(fx.ruleCatalog()), entities: [] };
        return clone(fx.ruleCatalog());
      },
      async check(def) {
        await wait();
        authed();
        const problems = checkRuleDef(def);
        return { valid: problems.length === 0, problems, warnings: [] };
      },
      async create(def) {
        await wait();
        const u = need('rules.edit');
        const problems = checkRuleDef(def);
        if (problems.length) throw new ApiError('invalid', problems[0].message, 422, 'invalid_rule', problems);
        const id = `r-${String(rulesList.reduce((m, r) => Math.max(m, Number(r.id.slice(2)) || 0), 0) + 1).padStart(4, '0')}`;
        const r = ruleFromDef(def, id, 'draft', 'manual');
        rulesList = [r, ...rulesList];
        appendAudit(u.username, 'rule.create', id);
        return clone(r);
      },
      async update(id, def) {
        await wait();
        const u = need('rules.edit');
        const old = own(id);
        if (old.status === 'rejected') throw new ApiError('conflict', 'Una regola rifiutata non si modifica');
        const problems = checkRuleDef(def);
        if (problems.length) throw new ApiError('invalid', problems[0].message, 422, 'invalid_rule', problems);
        if (old.status === 'draft') {
          const r = { ...ruleFromDef(def, id, 'draft', old.origin), counts: old.counts, proposedAt: old.proposedAt, supersedes: old.supersedes };
          rulesList = rulesList.map((x) => (x.id === id ? r : x));
          appendAudit(u.username, 'rule.edit', id);
          return clone(r);
        }
        const nid = `r-${String(rulesList.reduce((m, r) => Math.max(m, Number(r.id.slice(2)) || 0), 0) + 1).padStart(4, '0')}`;
        const r = { ...ruleFromDef(def, nid, 'draft', old.origin), supersedes: id };
        rulesList = [r, ...rulesList];
        appendAudit(u.username, 'rule.edit', `${id}->${nid}`);
        return clone(r);
      },
      async retire(id, note) {
        await wait();
        const u = need('rules.review');
        const r = own(id);
        if (r.status !== 'approved' && r.status !== 'stale') throw new ApiError('conflict', `Una regola ${r.status} non si ritira`);
        r.status = 'retired';
        r.review = { by: [...new Set([...r.review.by, u.username])], at: iso(now()), note: note ?? '' };
        appendAudit(u.username, 'rule.retire', id);
        return clone(r);
      },
      async review(id, action, note) {
        await wait();
        const u = need('rules.review');
        const r = own(id);
        const allowed: Record<string, Rule['status'][]> = { approve: ['draft'], reject: ['draft'], confirm: ['stale'], retire: ['stale'] };
        if (!allowed[action].includes(r.status)) throw new ApiError('conflict', `Azione ${action} non ammessa nello stato ${r.status}`);
        r.status = action === 'approve' || action === 'confirm' ? 'approved' : 'rejected';
        r.staleReason = undefined;
        r.review = { by: [...new Set([...r.review.by, u.username])], at: iso(now()), note };
        appendAudit(u.username, `rule.${action}`, id);
        // As tt-core 1.17.0: approving a rule that supersedes another takes the old one out of the packs (superseded).
        if (action === 'approve' && r.supersedes) {
          const old = rulesList.find((x) => x.id === r.supersedes);
          if (old && (old.status === 'approved' || old.status === 'stale')) {
            old.status = 'retired';
            old.supersededBy = r.id;
            appendAudit(u.username, 'rule.supersede', old.id);
          }
        }
        return clone(r);
      },
    },
    archetypes: {
      async get(group) {
        await wait();
        authed();
        const list = fx.archetypes().map((a) => ({ ...a, belowK: a.size === null || a.size < settings.kMin }));
        const one = groupNames(group);
        return { ...(one?.length === 1 ? { group: one[0] } : {}), built: true, kMin: settings.kMin, archetypes: list, mergedCount: list.filter((a) => a.belowK).length };
      },
      async build(group) {
        await wait();
        const u = need('worlds.generate');
        appendAudit(u.username, 'archetypes.build', `k=${settings.kMin}`);
        return api.archetypes.get(group);
      },
    },
    worlds: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return clone(worldList.filter((w) => !sel || !w.group || sel.includes(w.group)));
      },
      async generate(input) {
        await wait();
        const u = need('worlds.generate');
        if (!Number.isInteger(input.seed) || input.seed < 0) throw new ApiError('invalid', 'Seed non valido');
        if (input.customers < 1 || input.customers > 5000) throw new ApiError('invalid', 'Clienti tra 1 e 5000');
        const r = mulberry32(input.seed);
        const w: World = {
          id: `w-${String(worldList.length + 1).padStart(4, '0')}`,
          seed: input.seed,
          customers: input.customers,
          createdAt: iso(now()),
          createdBy: u.username,
          entities: Math.round(input.customers * (2.8 + r() * 0.8)),
          services: input.services ?? (input.group ? [...new Set(servicesList.filter((s) => s.group === input.group).map((s) => s.name))] : []),
          ...(input.group ? { group: input.group } : {}),
        };
        worldList = [...worldList, w];
        appendAudit(u.username, 'world.generate', `${w.id} seed=${w.seed}`);
        return clone(w);
      },
      async graph(worldId, customerIndex) {
        await wait();
        authed();
        const w = worldList.find((x) => x.id === worldId);
        if (!w) throw new ApiError('not_found', 'Mondo non trovato');
        return worldGraph(w, customerIndex);
      },
      async customers(worldId, query) {
        await wait();
        authed();
        const w = worldList.find((x) => x.id === worldId);
        if (!w) throw new ApiError('not_found', 'Mondo non trovato');
        const all = Array.from({ length: w.customers }, (_, i) => worldCustomer(w, i));
        const q = (query?.q ?? '').trim().toLowerCase();
        const hits = q ? all.filter((c) => `${c.id} ${c.name} ${c.email} ${c.archetype}`.toLowerCase().includes(q)) : all;
        const offset = Math.max(0, query?.offset ?? 0);
        const limit = Math.min(200, Math.max(1, query?.limit ?? 50));
        return { total: hits.length, all: all.length, offset, limit, customers: hits.slice(offset, offset + limit) };
      },
      async customer(worldId, customerId) {
        await wait();
        authed();
        const w = worldList.find((x) => x.id === worldId);
        const idx = Number(/-(\d+)$/.exec(customerId)?.[1] ?? 0) - 1;
        if (!w || idx < 0 || idx >= w.customers) throw new ApiError('not_found', 'Cliente non trovato');
        return worldCustomerDetail(w, idx);
      },
    },
    publications: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return pubList
          .filter((p) => !sel || anySel(p.groups ?? (p.group ? [p.group] : []), sel))
          .map(computePublication)
          .reverse();
      },
      async get(id) {
        await wait();
        authed();
        const p = pubList.find((x) => x.id === id);
        if (!p) throw new ApiError('not_found', 'Pubblicazione non trovata');
        return computePublication(p);
      },
      async run(worldId, opts) {
        await wait();
        const u = need('publish.build');
        const w = worldList.find((x) => x.id === worldId);
        if (!w) throw new ApiError('not_found', 'Mondo non trovato');
        // One group per pack: services of other groups only for an administrator who asks for a multi-group pack.
        if (opts?.multiGroup && !isAdmin(u)) throw new ApiError('forbidden', 'multi_group is reserved to administrators', 403, 'multi_group_forbidden');
        const group = opts?.group ?? w.group;
        const chosen = (opts?.services ?? servicesList.filter((s) => s.twin && (!group || s.group === group)).map((s) => s.name)).filter((s) => !(opts?.excludeServices ?? []).includes(s));
        const foreign = group ? [...new Set(chosen)].filter((s) => !servicesList.some((x) => x.name === s && x.group === group)) : [];
        if (foreign.length && !opts?.multiGroup) {
          const details = foreign.map((s) => ({ service: s, groups: [...new Set(servicesList.filter((x) => x.name === s).map((x) => x.group ?? ''))] }));
          throw new ApiError('invalid', 'the selection has services of more than one group', 422, 'mixed_groups', details);
        }
        const n = pubList.length + 1;
        const d = new Date(now());
        const packId = `pk-${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}-${String(n).padStart(4, '0')}`;
        const p = buildPublication(`pub-${String(n).padStart(4, '0')}`, packId, w, u.username, now());
        p.services = [...new Set(chosen)];
        if (group) p.group = group;
        p.groups = [...new Set(p.services.flatMap((s) => servicesList.filter((x) => x.name === s && (opts?.multiGroup || !group || x.group === group)).map((x) => x.group ?? '')))].filter(Boolean).sort();
        if (opts?.validDays) p.notAfter = iso(now() + opts.validDays * 86400000);
        pubList.push(p);
        appendAudit(u.username, 'pack.build', packId);
        return computePublication(p);
      },
      async publish(id, opts) {
        await wait();
        // A release by an admin is always the admin override (reason, alert).
        const override = isAdmin(current);
        if (override && !settings.approvals.adminOverride) throw new ApiError('forbidden', 'La pubblicazione dell’amministratore è disattivata in keyguard');
        const u = override ? authed() : need('publish.run');
        if (override && !opts?.reason?.trim()) throw new ApiError('invalid', 'La pubblicazione dell’amministratore richiede una motivazione');
        const p = pubList.find((x) => x.id === id);
        if (!p) throw new ApiError('not_found', 'Pubblicazione non trovata');
        const c = computePublication(p);
        if (c.status !== 'signed') throw new ApiError('conflict', 'Si rilasciano solo pacchetti firmati e non ancora rilasciati');
        pubPublished.set(p.id, iso(now()));
        if (override) {
          p.adminOverride = { by: u.username, reason: opts!.reason!.trim() };
          alertsList.unshift({ id: nextId('al-'), type: 'policy.admin_approval', severity: 'warning', service: p.packId, change: `pubblicazione dell’amministratore ${u.username}: «${opts!.reason!.trim()}»`, firstSeen: iso(now()), state: 'open' });
        }
        appendAudit(u.username, override ? 'publish.run.admin' : 'publish.run', p.packId);
        return computePublication(p);
      },
      async download(id) {
        await wait();
        const u = need('publish.download');
        const p = pubList.find((x) => x.id === id);
        if (!p) throw new ApiError('not_found', 'Pubblicazione non trovata');
        const c = computePublication(p);
        if (c.status !== 'published') throw new ApiError('conflict', 'Il pacchetto non è ancora stato rilasciato ai test');
        appendAudit(u.username, 'pack.download', c.packId);
        const manifest = {
          format: 'tt.pack/v1',
          pack_id: c.packId,
          created_at: c.createdAt,
          seed: c.seed,
          k_min: c.kMin,
          rules: { path: 'rules.json', approved: c.rulesApproved },
          files: c.files,
          note: 'Mock UI: pacchetto dimostrativo, solo manifest.',
        };
        return { filename: `${c.packId}.manifest.json`, blob: new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' }) };
      },
      async downloadExport(exportId) {
        await wait();
        need('publish.download');
        return { filename: `${exportId}.zip`, blob: new Blob(['Mock UI: archivio dimostrativo'], { type: 'application/zip' }) };
      },
      async export(id, target: ExportTarget) {
        await wait();
        const u = need('publish.download');
        const p = pubList.find((x) => x.id === id);
        if (!p) throw new ApiError('not_found', 'Pubblicazione non trovata');
        if (computePublication(p).verdict !== 'pass') throw new ApiError('conflict', 'Il gate non ha firmato questo pacchetto');
        appendAudit(u.username, 'pack.export', `${p.packId}:${target}`);
        const reports: Record<ExportTarget, ExportReport> = {
          wiremock: {
            target: 'wiremock',
            produced: [
              { path: 'mappings/shipping-ext/*.json', description: 'Un mapping per operazione ed esempio (OK e KO)' },
              { path: 'mappings/scenarios/r-0007-*.json', description: 'Esiti della regola come scenari (scenarioName / stati)' },
            ],
            preserved: ['Esempi OK e KO', 'Latenze come delayDistribution (lognormale)', 'Esiti delle regole come passi di scenario'],
            lost: [
              { item: 'Orologio virtuale', reason: 'WireMock non ha un orologio per sessione: gli effetti diventano passi di scenario.' },
              { item: 'Guasti probabilistici', reason: 'Diventano stub alternativi, non estrazioni con seed.' },
            ],
          },
          microcks: {
            target: 'microcks',
            produced: [
              { path: 'openapi/shipping-ext.openapi.json', description: 'OpenAPI con esempi nominati' },
              { path: 'examples/shipping-ext.apiexamples.yaml', description: 'APIExamples (artefatto secondario)' },
              { path: 'metadata/shipping-ext.apimetadata.yaml', description: 'APIMetadata con delay e dispatcher' },
            ],
            preserved: ['Esempi nominati', 'Ritardo fisso per operazione', 'Stato semplice via dispatcher SCRIPT + store'],
            lost: [
              { item: 'Orologio virtuale', reason: 'Non esiste un orologio per sessione.' },
              { item: 'Guasti', reason: 'Le frequenze di errore non sono rappresentabili.' },
              { item: 'Latenze variabili', reason: 'Solo un ritardo fisso per operazione.' },
            ],
          },
          prism: {
            target: 'prism',
            produced: [{ path: 'openapi/*.json', description: 'OpenAPI con examples nominati, selezionabili con Prefer: example=' }],
            preserved: ['Contratti e schemi', 'Esempi nominati'],
            lost: [
              { item: 'Tutto lo stato', reason: 'Prism è senza stato: nessuna entità né regola.' },
              { item: 'Latenze', reason: 'Non supportate.' },
              { item: 'Guasti', reason: 'Non supportati, salvo scegliere a mano l’esempio KO.' },
            ],
          },
        };
        return { ...reports[target], exportId: `ex_${p.id}_${target}` };
      },
    },
    scenarios: {
      async list() {
        await wait();
        authed();
        return clone(scenarioList);
      },
      async save(p) {
        await wait();
        const u = need('scenarios.edit');
        const copy = { ...clone(p), builtin: false };
        if (!copy.id) copy.id = nextId('sc-');
        const i = scenarioList.findIndex((x) => x.id === copy.id);
        if (i >= 0 && scenarioList[i].builtin) throw new ApiError('conflict', 'I preset predefiniti non si modificano');
        if (i >= 0) scenarioList[i] = copy;
        else scenarioList.push(copy);
        appendAudit(u.username, 'scenario.save', copy.id);
        return clone(copy);
      },
      async remove(id) {
        await wait();
        const u = need('scenarios.edit');
        const s = scenarioList.find((x) => x.id === id);
        if (!s) throw new ApiError('not_found', 'Preset non trovato');
        if (s.builtin) throw new ApiError('conflict', 'I preset predefiniti non si eliminano');
        scenarioList = scenarioList.filter((x) => x.id !== id);
        appendAudit(u.username, 'scenario.delete', id);
      },
    },
    alerts: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        return clone(alertsList.map(withGroup).filter((a) => inSel(a.group, sel)));
      },
      async setState(id, state) {
        await wait();
        const u = need('alerts.manage');
        const a = alertsList.find((x) => x.id === id);
        if (!a) throw new ApiError('not_found', 'Allarme non trovato');
        a.state = state;
        appendAudit(u.username, `alert.${state}`, id);
      },
    },
    webhooks: {
      async list() {
        await wait();
        authed();
        return clone(hooks);
      },
      async save(w) {
        await wait();
        const u = need('webhooks.manage');
        if (!/^https:\/\//.test(w.url)) throw new ApiError('invalid', 'L’URL deve iniziare con https://');
        let out;
        if (w.id) {
          const i = hooks.findIndex((x) => x.id === w.id);
          if (i < 0) throw new ApiError('not_found', 'Webhook non trovato');
          hooks[i] = { ...hooks[i], ...w, id: w.id };
          out = hooks[i];
        } else {
          out = { ...w, id: nextId('wh-') };
          hooks.push(out);
        }
        appendAudit(u.username, 'webhook.save', out.id);
        return clone(out);
      },
      async remove(id) {
        await wait();
        const u = need('webhooks.manage');
        hooks = hooks.filter((x) => x.id !== id);
        appendAudit(u.username, 'webhook.delete', id);
      },
      async test(id) {
        await wait();
        const u = need('webhooks.manage');
        const h = hooks.find((x) => x.id === id);
        if (!h) throw new ApiError('not_found', 'Webhook non trovato');
        const ok = !h.url.includes('fail');
        h.lastDelivery = { at: iso(now()), ok, httpStatus: ok ? 204 : 502 };
        appendAudit(u.username, 'webhook.test', id, ok ? 'ok' : 'error');
        return clone(h);
      },
    },
    audit: {
      async list() {
        await wait();
        need('audit.view');
        return clone(auditList).reverse();
      },
      async verify() {
        await wait();
        need('audit.view');
        let prev = GENESIS;
        for (const e of auditList) {
          const { hash, prevHash, ...base } = e;
          if (prevHash !== prev || hash !== auditHash(prev, base)) return { ok: false, entries: auditList.length, headHash: prev, verifiedAt: iso(now()), brokenAt: e.seq };
          prev = hash;
        }
        return { ok: true, entries: auditList.length, headHash: prev, verifiedAt: iso(now()) };
      },
    },
    users: {
      async list() {
        await wait();
        need('users.manage');
        return clone(usersList);
      },
      async roles() {
        await wait();
        authed();
        return (Object.keys(ROLE_PERMISSIONS) as Role[]).map((role) => ({ role, permissions: ROLE_PERMISSIONS[role] }));
      },
      async create(input) {
        await wait();
        const u = need('users.manage');
        if (!/^[a-z0-9][a-z0-9._-]{1,30}$/.test(input.username)) throw new ApiError('invalid', 'Nome utente non valido');
        if (usersList.some((x) => x.username === input.username)) throw new ApiError('conflict', 'Nome utente già in uso');
        if (input.roles.length === 0) throw new ApiError('invalid', 'Serve almeno un ruolo');
        const { password: _pw, ...rest } = input;
        void _pw;
        const nu: User = { id: nextId('u-'), ...rest };
        usersList.push(nu);
        appendAudit(u.username, 'user.create', nu.username);
        return clone(nu);
      },
      async update(id, patch) {
        await wait();
        const u = need('users.manage');
        const target = usersList.find((x) => x.id === id);
        if (!target) throw new ApiError('not_found', 'Utente non trovato');
        if (patch.roles) {
          if (patch.roles.length === 0) throw new ApiError('invalid', 'Serve almeno un ruolo');
          target.roles = patch.roles;
        }
        if (patch.disabled !== undefined) {
          if (target.id === u.id) throw new ApiError('conflict', 'Non puoi disattivare te stesso');
          target.disabled = patch.disabled;
        }
        appendAudit(u.username, 'user.update', target.username);
        return clone(target);
      },
    },
    settings: {
      async get() {
        await wait();
        authed();
        const { approvals, ...general } = clone(settings);
        return { approvals, general };
      },
      async save(next) {
        await wait();
        const u = need('settings.edit');
        const g = next.general;
        if (!g) throw new ApiError('invalid', 'Impostazioni mancanti');
        if (g.kMin < 5 || g.kMin > 1000) throw new ApiError('invalid', 'k minimo tra 5 e 1000');
        if (g.retentionDays < 1 || g.retentionDays > 365) throw new ApiError('invalid', 'Conservazione tra 1 e 365 giorni');
        settings = { ...clone(g), approvals: settings.approvals }; // approvals live in keyguard: read-only
        appendAudit(u.username, 'settings.save', '-');
        const { approvals, ...general } = clone(settings);
        return { approvals, general };
      },
    },
    quarantine: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        // host:* items (the intake's host collapse) belong to the group that called the hosts: the shop in the demo.
        return clone(quarantine.map((q) => (q.service.startsWith('host:') ? { ...q, group: 'shop-api' } : withGroup(q))).filter((q) => inSel(q.group, sel)));
      },
      async resolve(id, resolution) {
        await wait();
        const u = need('quarantine.resolve');
        const q = quarantine.find((x) => x.id === id);
        if (!q) throw new ApiError('not_found', 'Elemento non trovato');
        if (q.approvals.some((a) => a.by === u.username)) throw new ApiError('conflict', 'Hai già approvato questa risoluzione');
        // An admin resolves alone (admin override, audited and alerted).
        const override = isAdmin(u);
        q.approvals.push({ by: u.username, at: iso(now()) });
        q.state = override || resolution === 'close' || q.approvals.length >= 2 ? 'resolved' : 'dismiss-pending';
        appendAudit(u.username, override ? `quarantine.${resolution}.admin` : `quarantine.${resolution}`, id);
        if (override && resolution === 'dismiss') {
          alertsList.unshift({ id: nextId('al-'), type: 'keyguard.alert', severity: 'warning', service: q.service, change: `scioglimento della quarantena da parte dell’amministratore ${u.username}`, firstSeen: iso(now()), state: 'open' });
        }
        return clone(q);
      },
    },
    store: {
      async retention() {
        await wait();
        authed();
        return { eventsDays: retentionDays, aggregatesDays: 365 };
      },
      async setRetention(days) {
        await wait();
        const u = need('store.manage');
        if (!Number.isInteger(days) || days < 1 || days > 365) throw new ApiError('invalid', 'Giorni tra 1 e 365');
        retentionDays = days;
        appendAudit(u.username, 'store.retention', `${days}d`);
        return { eventsDays: days, aggregatesDays: 365 };
      },
      async purge(before) {
        await wait();
        const u = need('store.manage');
        if (Number.isNaN(Date.parse(before))) throw new ApiError('invalid', 'Data non valida');
        appendAudit(u.username, 'store.purge', before);
        return { events: 1240, tokens: 87 };
      },
      async usage() {
        await wait();
        const perms = permissionsOf(authed().roles);
        if (!perms.has('store.manage') && !perms.has('audit.view')) throw new ApiError('forbidden', 'Permesso negato');
        const now = Date.now();
        const mib = 1024 * 1024;
        const ds = (name: string, bytes: number, code: string, params: Record<string, number> = {}, deleted = 0, fileBytes = 0) => ({
          name, bytes, fileBytes, overQuota: false, policy: { code, params }, lastRun: { deleted, durationMs: 120 },
        });
        return {
          db: { file: 'tt-core.db', fileBytes: 2210 * mib, walBytes: 12 * mib, freeBytes: 30 * mib, usedBytes: 2192 * mib, maxBytes: 4096 * mib, usedPct: 53.5, highPct: 80, criticalPct: 90, level: 'ok' as const, autoVacuum: 'incremental' as const },
          datasets: [
            ds('events', 1650 * mib, 'raw_events', { days: retentionDays, miner_window_days: 7, floor_hours: 24 }, 412000),
            ds('rollups', 96 * mib, 'rollup_tiers', { hourly_days: 30, daily_days: 365 }, 18400),
            ds('tokens', 280 * mib, 'with_events'),
            ds('aggregates', 2 * mib, 'stored_events'),
            ds('sketches', 18 * mib, 'sketches', { released_days: 365 }),
            ds('deliveries', 3 * mib, 'ttl', { days: 30 }, 210),
            ds('drift', 1 * mib, 'resolved_alerts', { days: 365 }),
            ds('snapshots', 64 * mib, 'snapshot_compaction', { keep_all_days: 30, weekly_days: 180, max: 400 }, 21),
            ds('miner', 9 * mib, 'miner_runs', { days: 90, keep: 50 }, 4),
            ds('packs', 41 * mib, 'packs', { keep: 20, days: 180 }, 2),
            ds('worlds', 22 * mib, 'worlds', { keep: 20, days: 30 }, 1),
            ds('fleet', 1 * mib, 'fleet', { revoked_days: 90, tokens_days: 30, certs_days: 30 }),
            ds('auth', 0.2 * mib, 'expired'),
            ds('audit', 4 * mib, 'audit_archive', { days: 180, segment_entries: 50000 }, 50000, 7 * mib),
            ds('exports', 0, 'ttl_hours', { hours: 24 }, 0, 3 * mib),
            ds('other', 0.5 * mib, 'bounded'),
          ],
          measuredAt: iso(now - 40 * 60_000),
          lastRun: { trigger: 'schedule', startedAt: iso(now - 41 * 60_000), finishedAt: iso(now - 40 * 60_000), deleted: 480000, reclaimedBytes: 690 * mib, errors: 0, shed: [] },
          nextRun: iso(now + 19 * 60_000),
          running: false,
          intervalSeconds: 3600,
          rollups: [
            { tier: 'hour' as const, rows: 182000, oldest: iso(now - 30 * 86400_000) },
            { tier: 'day' as const, rows: 61000, oldest: iso(now - 365 * 86400_000) },
            { tier: 'month' as const, rows: 4200, oldest: iso(now - 700 * 86400_000) },
          ],
          auditArchive: { enabled: true, dir: 'audit-archive', segments: 3, entries: 150000 },
        };
      },
      async maintenance() {
        await wait();
        const u = need('store.manage');
        appendAudit(u.username, 'store.maintenance', 'api');
        return { deleted: 1200, reclaimedBytes: 8 * 1024 * 1024, level: 'ok' as const };
      },
    },
    keyguard: {
      async status() {
        await wait();
        authed();
        return {
          reachable: true,
          hmacKids: ['k1'],
          epochs: ['2026-10'],
          approvalsUnverified: !settings.approvals.identitiesVerified,
          matchBudgetLeft: 9800,
          policyKid: 'policy-2026-1',
          packKid: 'gate-2026-1',
          revokedKids: [],
          openingApprovals: settings.approvals.openingRequired,
          adminOverride: settings.approvals.adminOverride,
          transport: 'mtls',
        };
      },
      async audit() {
        await wait();
        need('audit.view');
        const rows: KeyguardAuditEntry[] = [
          { seq: 3, at: iso(t0 - 3600000), op: 'pack.sign', outcome: 'success', detail: { pack: 'pk-20261021-0002' }, hash: sha256Hex('kg3') },
          { seq: 2, at: iso(t0 - 86400000), op: 'policy.sign', outcome: 'success', detail: { policy: 'p-shop', version: '7' }, hash: sha256Hex('kg2') },
          { seq: 1, at: iso(t0 - 86400000 * 6), op: 'startup', outcome: 'success', detail: {}, hash: sha256Hex('kg1') },
        ];
        return rows;
      },
    },
    events: {
      async export(input) {
        await wait();
        const u = need('events.export');
        if (Date.parse(input.from) >= Date.parse(input.to)) throw new ApiError('invalid', 'L’intervallo non è valido');
        appendAudit(u.username, 'events.export', input.format);
        return { jobId: nextId('job_'), format: input.format, bytes: 2048, events: input.format === 'jsonl' ? 12 : undefined, notice: 'pseudonymous personal data: it must not leave zone B' };
      },
      async download(job) {
        await wait();
        need('events.export');
        return { filename: `${job.jobId}.${job.format === 'jsonl' ? 'jsonl' : 'json'}`, blob: new Blob(['{"demo":"Mock UI: nessun evento reale"}\n'], { type: 'application/json' }) };
      },
    },
    fleet: {
      async signingKeys() {
        await wait();
        authed();
        return mockSigningKeys.map((k) => ({ ...k }));
      },
      async revokeSigningKey(kid) {
        await wait();
        need('settings.edit');
        const k = mockSigningKeys.find((x) => x.kid === kid);
        if (!k) throw new ApiError('not_found', 'Chiave sconosciuta');
        if (k.revoked) throw new ApiError('conflict', 'already revoked', 409, 'already_revoked');
        if (k.revoke && !k.revoke.ok) throw new ApiError('conflict', k.revoke.blocker ?? 'refused', 409, k.revoke.blocker);
        k.revoked = true;
        k.revoke = undefined;
      },
    },
    gaps: {
      async list(groups) {
        await wait();
        authed();
        const sel = groupNames(groups);
        const low = rulesList
          .filter((r) => anySel(ruleGroups(r), sel))
          .filter((r) => r.kind === 'causal' && (r.status === 'draft' || r.status === 'approved' || r.status === 'stale') && r.counts.causes < fx.LOW_SUPPORT_MIN)
          .map((r) => ({
            id: `gp-r-${r.id}`,
            kind: 'low-support-rule' as const,
            scope: 'op' as const,
            ruleId: r.id,
            count: r.counts.causes,
            threshold: fx.LOW_SUPPORT_MIN,
            detail: 'Poche cause osservate: gli esiti alternativi hanno probabilità poco affidabili.',
          }));
        const ops = fx
          .gaps()
          .map((g) => (g.service ? withGroup({ ...g, service: g.service }) : g))
          .filter((g) => inSel(g.group, sel));
        return [...ops, ...low].map((g) => (g.kind === 'few-samples' ? { ...g, threshold: settings.minSamples } : g));
      },
    },
    demo: {
      async loginAs(role) {
        await wait();
        const u = usersList.find((x) => x.roles.length === 1 && x.roles[0] === role) ?? usersList.find((x) => x.roles.includes(role))!;
        setCurrent(u);
        appendAudit(u.username, 'auth.login', u.username);
        return clone(u);
      },
      resetFirstRun() {
        initialized = false;
        setCurrent(null);
      },
    },
  };
  return api;
}

// localStorage, not sessionStorage: the viewer page opens in a new tab and must find the demo user.
function safeSession(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}
