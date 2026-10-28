// Domain types and the data-layer contract. Pages talk only to `Api`; the
// in-memory mock implements it today, the REST adapter (admin-api.v1) later.

import type { GraphQLOpInfo } from '../graphql';
import type { SoapOpInfo } from '../soap';

// ---------------------------------------------------------------- auth / rbac

/** Exactly the roles of tt-core (internal/auth/roles.go). */
export type Role = 'admin' | 'operator' | 'rule-reviewer' | 'policy-approver' | 'publisher' | 'auditor' | 'event-exporter';

export type Permission =
  | 'sources.manage' // revoke, sampling, enrollment tokens
  | 'sources.kill' // emergency kill switch
  | 'policy.propose'
  | 'policy.approve'
  | 'rules.edit' // edit figurative delays
  | 'rules.review' // approve / reject / confirm
  | 'worlds.generate'
  | 'publish.build' // assemble, gate and sign a pack
  | 'publish.run' // release a signed pack to the tests
  | 'publish.download'
  | 'scenarios.edit'
  | 'alerts.manage'
  | 'webhooks.manage'
  | 'users.manage'
  | 'rules.mine' // run the miner now
  | 'quarantine.resolve' // close or dismiss a quarantined element
  | 'hosts.twin' // see the hosts registry and propose a policy draft for a host
  | 'store.manage' // retention and purge
  | 'events.export' // event-level export (zone B)
  | 'settings.edit'
  | 'audit.view'
  | 'override.admin'; // admin single approval / single publication, with a mandatory reason

export interface User {
  id: string;
  username: string;
  displayName: string;
  roles: Role[];
  authMethod: 'local' | 'sso';
  disabled?: boolean;
  lastLogin?: string;
}

export type EnvName = 'production' | 'staging' | 'development';

export interface SystemStatus {
  initialized: boolean;
  version: string;
  /** Name of this installation, shown next to the environment badge (the server does not expose it). */
  installation?: string;
  /** Deployment environment (the server does not expose it: absent = no badge). */
  environment?: EnvName;
  ssoEnabled: boolean;
  /** Local (password) login is enabled. */
  localEnabled: boolean;
  adapter: 'mock' | 'rest';
}

/** What the connected server offers. The REST adapter reports the endpoints that tt-core does not serve (yet). */
export interface Capabilities {
  /** Alerts can be marked "resolved" (the server only acknowledges them). */
  alertResolve: boolean;
  /** Webhooks can be switched off without deleting them. */
  webhookToggle: boolean;
  /** Settings can be edited through the API (otherwise they live in the server configuration file). */
  settingsEdit: boolean;
  /** The twin flag of a service is stored by the server (otherwise it is a browser-side selection). */
  twinOnServer: boolean;
}

export interface Credentials {
  username: string;
  password: string;
}

export interface SetupRequest {
  setupToken: string;
  username: string;
  password: string;
}

// ---------------------------------------------------------------- sources

export type SourceKind =
  | 'sdk-node'
  | 'sdk-python'
  | 'sdk-java'
  | 'sdk-dotnet'
  | 'sdk-go'
  | 'sdk-php'
  | 'egress'
  | 'obi'
  | 'import-har'
  | 'import-otlp';

/** What the wizard offers: SDK kinds, proxy, OBI, Kubernetes injection, HAR. */
export type SourceChoice =
  | 'sdk-node'
  | 'sdk-python'
  | 'sdk-java'
  | 'sdk-dotnet'
  | 'sdk-go'
  | 'sdk-php'
  | 'egress'
  | 'obi'
  | 'k8s-inject'
  | 'import-har';

export interface Problem {
  code:
    | 'token_expired'
    | 'cert_rejected'
    | 'no_policy'
    | 'policy_rejected'
    | 'key_missing'
    | 'key_mismatch'
    | 'no_subject_found'
    | 'intake_rejecting'
    | 'clock_skew'
    | 'double_capture'
    | 'inbound_not_captured'
    | 'hmac_kid_unknown';
  message: string;
  hint?: string;
}

export type SourceState =
  | 'starting'
  | 'capturing'
  | 'no_policy'
  | 'policy_rejected'
  | 'key_missing'
  | 'key_mismatch'
  | 'killed'
  | 'expired_policy';

export interface Source {
  id: string;
  kind: SourceKind;
  version: string;
  updateAvailable: boolean;
  serviceName: string;
  group: string;
  instance: string;
  instances: number;
  state: SourceState;
  killed: boolean;
  revoked: boolean;
  policy?: { id: string; version: number };
  lastSeen: string;
  eventsPerMin: number;
  dropRatio: number;
  overheadUs?: { p50: number; p99: number };
  /** Effective sampling rate in basis points (0-10000). */
  samplingBp: number;
  /** Rate set by the policy; the override can only lower it. */
  policyRateBp: number;
  problems: Problem[];
  /** Errors within the recent window: one per code, `at` is the last occurrence. */
  lastErrors: { code: string; at: string; firstSeen?: string; count?: number }[];
  /** Events per minute, last 30 minutes. */
  series: number[];
}

/** waiting: enrolled, no policy approved yet (neutral, not a fault). */
export type SourceHealth = 'healthy' | 'waiting' | 'degraded' | 'offline' | 'killed' | 'revoked';

export interface KillScope {
  all?: true;
  group?: string;
  sourceId?: string;
}

// ---------------------------------------------------------------- onboarding

export interface Snippet {
  title: string;
  language: 'bash' | 'yaml' | 'dockerfile' | 'text';
  text: string;
}

export interface EnrollmentToken {
  tokenId: string;
  token: string;
  /** When the console received the token (the server does not say): shown as «creato alle HH:MM». */
  createdAt?: string;
  expiresAt: string;
  choice: SourceChoice;
  group: string;
  snippets: Snippet[];
  /** A starter policy draft was created for the group (it still needs approval). */
  starterPolicy?: { policyId: string; version: number };
}

export interface OnboardingStatus {
  enrolled: boolean;
  policyReceived: boolean;
  firstEvents: number;
  problems: Problem[];
}

export interface DiscoveredService {
  name: string;
  kind: 'own' | 'external';
  baseUrl?: string;
  /** Host pattern, for `host:<pattern>` entries. */
  hostPattern?: string;
  calls: number;
  operations: number;
  /** Proposed as "external service to twin". */
  proposeTwin: boolean;
}

/** code: in clear only values shaped like a code (DELIVERED, card_declined), on status-like fields (sanitizer.md 5.6). */
export type PolicyActionKind = 'drop' | 'keep' | 'code' | 'hmac' | 'bucket';

export interface PolicyChoice {
  action: PolicyActionKind;
  /** hmac domain, or bucket boundaries "0, 50, 100". */
  arg?: string;
}

export interface PolicySuggestion {
  id: string;
  service: string;
  op: string;
  part: 'request' | 'response' | 'errors';
  path: string;
  /** Observed shape, e.g. "drop:str:l16" or "str enum". Never a value. */
  shape: string;
  observed: number;
  distinct: number;
  suggestion: PolicyChoice;
  /** What the active policy does with this field today. */
  current: PolicyChoice;
  reason: string;
  /** Heuristic behind the proposal (translated by the UI; `reason` is the server's English text). */
  reasonCode?: string;
}

/** One operation template seen in discovery mode, with its field proposals. */
export interface AssistOp {
  /** Template, e.g. "GET /orders/{id}" (never a raw path with shapes). */
  op: string;
  /** The policy already declares the operation. */
  declared: boolean;
  calls: number;
  /** Calls still needed before the proposals rest on enough evidence (0 = enough). */
  needCalls: number;
  /** Some of the paths the template merges, as they left the source (shapes, never values). */
  rawOps: string[];
  fields: PolicySuggestion[];
}

/** One service seen under the policy (own or an external host). */
export interface AssistService {
  /** As in the events: a service name or `host:<pattern>`. */
  service: string;
  kind: 'own' | 'external';
  declared: boolean;
  /** Policy service name: the declared one or a proposal ('' = to be chosen). */
  name: string;
  /** Host pattern of an external service not declared yet. */
  hostPattern?: string;
  /** No `{*}` label and not an IP class: the base is scheme + pattern. */
  exact: boolean;
  /** Declared base. */
  base?: string;
  calls: number;
  ops: AssistOp[];
  /**
   * Default of the "Declare in the policy" checkbox (server): true only for hosts this group's sources called that
   * are not declared yet. Absent on older servers.
   */
  preselect?: boolean;
  /** Host patterns folded into this block (duplicates, old `host:` rows of a service declared since). */
  mergedPatterns?: string[];
  /** No recent calls: never checked by default. */
  stale?: boolean;
}

/** Where the source reads the user from (identity.subject): a request header or cookie, optionally a JWT claim. */
export interface IdentitySource {
  from: 'header' | 'cookie';
  name: string;
  claim?: string;
  /** Spec v1.18: a dotted path of members inside a header whose value is JSON (header only, excludes `claim`). */
  jsonPath?: string;
}

/**
 * A request header or cookie that may carry the user (identity.subject), with the evidence of the automatic detection
 * (policy.md §7.4): names, counts, shapes and scores, never a value.
 */
export interface IdentityCandidate {
  from: 'header' | 'cookie';
  name: string;
  /** The JWT claim to read when the values are JWTs (`sub`). */
  claim?: string;
  calls: number;
  distinct: number;
  /** The values are JWTs (a bearer token, or a header of JWTs): the subject is a claim, usually `sub`. */
  jwt: boolean;
  /** Dominant drop shape of the values ("drop:str:uuid"). */
  shape?: string;
  /** Share of the inbound calls carrying it (0..1). */
  presence?: number;
  /** Distinct values per call (0..1): near 1 a request id, low a value repeated per user. */
  perCall?: number;
  /** 0..100: how much it looks like the user. */
  score?: number;
  /** Why (codes: jwt_bearer, id_shape, repeats, most_calls, name_hint...). */
  signals?: string[];
  /** Why it is never chosen by itself (credential, cookie, few_values, per_call, not_id_shape, rare). */
  excluded?: string;
  /** Choosing it applies at once, without approvals. */
  observeSafe?: boolean;
  /** The source the detection picks. */
  best?: boolean;
}

/**
 * The sampling of a policy is per user. A value or a rule is published only when at least `kMin` distinct users
 * produced it: with a low rate and few users nothing can be proposed. The advice compares the users seen with `kMin`
 * and suggests a rate (basis points) from the traffic observed so far.
 */
export interface SamplingAdvice {
  /** Rate of the policy, in basis points (500 = 5 %). */
  currentBp: number;
  /** Distinct users seen, from the subject tokens; 'no_identity': identity.subject is not set, users cannot be counted. */
  sampledSubjects: number;
  source: 'subject' | 'no_identity' | 'none';
  kMin: number;
  /** What the suggestion aims at (twice kMin). */
  targetSubjects: number;
  enough: boolean;
  /** Users in the traffic seen so far (sampled / rate). */
  populationEstimate: number;
  /** The rate to ask for (the current one when enough), in basis points; 10000 when even everyone would not be enough yet. */
  suggestedBp: number;
}

/** The policy assistant: operations per service, never values. */
export interface PolicyAssist {
  policyId: string;
  /** Calls an operation needs (min_calls). */
  minCalls: number;
  ready: boolean;
  /** The most calls still missing for one operation. */
  needCalls: number;
  hasIdentity: boolean;
  /** Proposed identity.subject (a request header holding a JWT). */
  identity?: { header: string; claim: string; calls: number; withHeader: number };
  /** Headers and cookies of the own services ranked as who the user is (names, counts and scores only), best first. */
  identityCandidates: IdentityCandidate[];
  /** The source the automatic detection picks (absent when none is convincing). */
  identityBest?: IdentitySource;
  /** Whether the sampling of the policy lets enough distinct users through for rules (k-anonymity), and which rate to ask for. */
  sampling?: SamplingAdvice;
  services: AssistService[];
  /** Every field proposal, flat (ids referenced by the choices). */
  suggestions: PolicySuggestion[];
}

export interface DiffEntry {
  change: 'added' | 'removed' | 'changed';
  where: string;
  from?: string;
  to?: string;
}

export interface PolicyVersion {
  policyId: string;
  version: number;
  /** `withdrawn`: the proposer or an admin took the draft back (POST .../versions/{v}/withdraw, usability test #5). */
  status: 'draft' | 'active' | 'superseded' | 'rejected' | 'withdrawn';
  proposedBy?: string;
  proposedAt?: string;
  /** Groups bound to / targeted by the policy (the Group column of the "every group" view). */
  groups?: string[];
  origin?: 'propose' | 'rollback' | 'retarget' | 'renew' | 'starter' | 'host-twin' | 'observe-auto';
  opensData: boolean;
  /**
   * The change lets values out beyond observe-safe (policy.md §7): only these need approvals. false = it applies at
   * once (approvalsRequired 0). Older servers: same as opensData.
   */
  opensValues: boolean;
  /** Why it opens values (codes and policy locations, never values); empty when it does not. */
  valueReasons: ValueReason[];
  /** 0: observe-safe, applied without approval. */
  approvalsRequired: 0 | 1 | 2;
  /** tokenFresh (OIDC only): false when the approver's identity check expired and the approval must be renewed. */
  approvals: { by: string; at: string; mode?: 'standard' | 'admin'; reason?: string; tokenFresh?: boolean }[];
  /** How the version got signed: standard (2), single (config = 1), admin override, or observe (no approval needed). */
  approvalMode?: 'standard' | 'single' | 'admin' | 'observe';
  diff: DiffEntry[];
  /** Author policy before / after as YAML text, for the diff view. */
  yamlBefore: string;
  yamlAfter: string;
  hash?: string;
}

/** A person who can approve the policy drafts of a group (names only, never an e-mail address). */
export interface GroupApprover {
  /** Username of a local account ('' for OIDC). */
  name: string;
  displayName: string;
  roles: ('policy-approver' | 'admin')[];
  /** The current user. */
  self: boolean;
}

/** One reason why a policy change opens values (policy.md §7): a code the UI translates and a location in the policy. */
export interface ValueReason {
  code: string;
  where: string;
}

/** How a change would be applied (server classification, policy.md §7). */
export interface ChangeClass {
  /** false: «Questa modifica non apre dati: si applica subito». */
  opensValues: boolean;
  valueReasons: ValueReason[];
  /** 0 when it applies at once. */
  approvalsRequired: number;
}

/** A field the active policy turns into a token (hmac): names only, never a value. */
export interface MaskedField {
  service: string;
  op?: string;
  part: 'request' | 'response' | 'errors';
  kind: 'path' | 'query' | 'headers' | 'cookies' | 'body';
  field: string;
  domain: string;
}

/** Live state of the observe phase of a group (GET /api/v1/fleet/groups/{group}/observe). */
export interface ObserveStatus {
  group: string;
  policyId?: string;
  /** tt-core derives the observe version by itself and keyguard signs it without approvals. */
  enabled: boolean;
  /** The group's switch of the automatic observe versions (setObserveAuto; default on). */
  auto: boolean;
  phase: 'no_policy' | 'waiting_approval' | 'listening' | 'masked' | 'managed';
  activeVersion?: number;
  startedAt?: string;
  /** The observe version is derived at the latest then (earlier after minEvents calls). */
  dueAt?: string;
  minEvents: number;
  events: number;
  observeVersion?: number;
  observeActivatedAt?: string;
  discoveryUntil?: string;
  samplingBp: number;
  services: { service: string; kind: 'inbound' | 'external'; calls: number; ops: number }[];
  masked: MaskedField[];
  identity?: { from: string; name: string; claim?: string; jsonPath?: string };
  /** admin-api 1.21.0: hmac.families of the active policy (family → joined domains). */
  families?: Record<string, string[]>;
  /** admin-api 1.21.0: the lower k of a group marked as test (0: not a test group) and the installation k. */
  testKMin?: number;
  kMin?: number;
  /** Who the user may be, ranked by the automatic detection (admin-api 1.18.0); empty on an older server. */
  identityCandidates: IdentityCandidate[];
  /** The source the detection picks. */
  identityBest?: IdentitySource;
  sampling?: SamplingAdvice;
}

/** `hosts.discovery` of a policy: `auto` (default) shows every host as a pattern, `off` is the strict mode (host:unlisted). */
export type HostsDiscovery = 'auto' | 'off';

export interface ProposePolicyInput {
  /** Defaults to the policy bound to `group` (the REST adapter) or to the demo policy (mock). */
  policyId?: string;
  /** Group whose policy is edited (the REST adapter resolves the policy id from it). */
  group?: string;
  choices: { suggestionId: string; choice: PolicyChoice }[];
  /** New `hosts.discovery`; absent = unchanged. `off` -> `auto` opens data. */
  hostsDiscovery?: HostsDiscovery;
  /**
   * Services and operations of the assistant to declare. `service` as in the assistant, `name` the policy service
   * name, `base` the match.base of an external service not declared yet (`http(s)://host[:port]`: the scheme is
   * chosen by the person). Choices of operations not listed are ignored.
   */
  services?: { service: string; name: string; base?: string; ops: string[] }[];
  /** identity.subject from a request header or cookie, optionally a JWT claim (only when the policy has none). */
  identity?: { from: 'header' | 'cookie'; name: string; claim?: string };
  /** New sampling rate of the policy in basis points (1..10000); raising it opens data. Absent = unchanged. */
  samplingBp?: number;
}

// ---------------------------------------------------------------- services & contracts

export interface ServiceInfo {
  name: string;
  /**
   * Group whose sources produced the traffic ("" = a source of unknown group). The identity of an observed service is
   * (group, service): two groups calling the same host are two rows.
   */
  group?: string;
  kind: 'own' | 'external';
  /** Only for an external service whose host is exactly known (never for `{*}`, IP classes, unlisted, invalid). */
  baseUrl?: string;
  /** Host pattern of the hosts registry this service belongs to (a declared service or a `host:<pattern>` entry). */
  hostPattern?: string;
  operations: number;
  calls: number;
  twin: boolean;
  lastSeen: string;
  sources: number;
  /** A `host:<pattern>` entry that a policy has declared since: the name of that external service (merged view). */
  nowDeclaredAs?: string;
}

/** Why a service has (no) contract yet: GET /api/v1/contracts/{service}/status. */
export interface ContractStatus {
  service: string;
  calls: number;
  operations: number;
  readyOperations: number;
  bestOpCalls: number;
  /** Calls an operation needs for a reliable schema. */
  minCalls: number;
  kMin: number;
  inferredOperations: number;
  snapshot?: { id: string; createdAt: string; ops: number };
  nextSnapshotAt: string;
  windowHours: number;
}

/** Public keys of the publication gate, for tt mock (TT_GATE_PUBKEYS). */
export interface GateKeys {
  value: string;
  command: string;
  keys: { kid: string; publicKey: string }[];
}

/** Groups and the groups of each observed service: the console's Group/Team filter. */
export interface ScopeData {
  groups: string[];
  /** Groups the user created tokens for or proposed a policy of. */
  mine: string[];
  services: Record<string, string[]>;
}

export interface StatusStat {
  status: number;
  frequency: number;
  calls: number;
  example?: string;
}

export interface ServiceSummary {
  service: ServiceInfo;
  /** Alias shown in packs instead of the real host, when host anonymization is on. */
  alias?: string;
  operations: number;
  calls: number;
  /** Share of calls answered with 4xx/5xx. */
  errorRate: number;
  latencyMs: { p50: number; p95: number };
  lastDrift?: { at: string; severity: 'breaking' | 'non-breaking'; open: boolean };
  coverage: { fewSamples: number; statusesNeverSeen: number; lowSupportRules: number };
  snapshots: number;
}

export interface OperationSummary {
  service: string;
  /** Group of the service the operation belongs to (lists of every group). */
  group?: string;
  op: string;
  method: string;
  pathTemplate: string;
  calls: number;
  firstSeen: string;
  lastSeen: string;
  latencyMs: { p50: number; p95: number; p99: number };
  statuses: StatusStat[];
  /** Operation seen fewer times than the confidence threshold. */
  fewSamples: boolean;
  entity?: string;
  /** A logical GraphQL operation of a GraphQL endpoint (x-tt-graphql). */
  graphql?: GraphQLOpInfo;
  /** A logical SOAP (or XML) operation of an endpoint with many operations (x-tt-xml, mock.md 10). */
  soap?: SoapOpInfo;
}

export interface SchemaNode {
  name: string;
  type: 'object' | 'array' | 'string' | 'integer' | 'number' | 'boolean';
  format?: string;
  enumValues?: string[];
  /** Share of observed objects that contain the field, 0..1. */
  presence: number;
  /** For arrays of objects the children describe the item fields. */
  children?: SchemaNode[];
  itemType?: string;
}

/**
 * Linked fields (x-tt-dependencies): which values of two fields of the same object were seen together, each
 * combination for at least k distinct users. The world and the mock only produce these combinations.
 */
export interface LinkedFields {
  /** Where the object is: "" for the body itself, "items[]" for the elements of a list, "address" for a nested object. */
  at: string;
  fields: string[];
  combos: { values: string[]; atLeast: number }[];
  /** Some combinations were seen by fewer than k users and are not shown (nor produced). */
  partial: boolean;
}

export interface ResponseContract {
  status: number;
  frequency: number;
  schema: SchemaNode;
  /** Linked fields of the response body. */
  linked?: LinkedFields[];
  /** Synthetic examples: shape faithful, values generated. */
  examples: { name: string; value: unknown }[];
}

export interface OperationDetail extends OperationSummary {
  request?: SchemaNode;
  /** Linked fields of the request body. */
  requestLinked?: LinkedFields[];
  responses: ResponseContract[];
  latencySeries: number[];
}

export interface SnapshotInfo {
  id: string;
  date: string;
  calls: number;
  breaking: number;
  nonBreaking: number;
}

export interface ContractChange {
  severity: 'breaking' | 'non-breaking';
  op: string;
  path: string;
  /** Kind from the diff engine ("field-removed", "type-changed", "status-added", ...). */
  kind: string;
  from?: string;
  to?: string;
  detail: string;
}

export interface SnapshotDiff {
  service: string;
  from: string;
  to: string;
  changes: ContractChange[];
  /** Pretty JSON of the affected schema fragments, for the diff view. */
  before: string;
  after: string;
}

// ---------------------------------------------------------------- rules

/** `retired`: an approved rule taken out of the packs (POST /rules/{id}/retire); `superseded` by a newer rule counts as retired. */
export type RuleStatus = 'draft' | 'approved' | 'rejected' | 'stale' | 'retired';

/** A response effect (rules v1.4): later calls of service/op answer `status` (with probability p, at most `times` calls; 0 = no limit). */
export interface RuleRespond {
  service: string;
  op: string;
  status: number;
  p?: number;
  times?: number;
  example?: string;
  /**
   * An error body typed by a person (rules 1.10): a JSON object, array or text up to 16 KiB. It wins over the example
   * of the contract; the publication gate runs the personal-data detectors on it.
   */
  body?: unknown;
  /** Rules v1.8: a counter per key — the call answers status once `n` counted calls with its key fall within `window`. */
  limit?: RuleLimit;
  /** Rules v1.9: a precondition — the calls answer status from the start of the session until the cause is seen. */
  until?: boolean;
}

/**
 * Rules v1.9: one condition — a request value (`at`) or a customer attribute (`customer`) is one of `in`, or a number
 * in [min, max).
 */
export interface RuleMatch {
  at?: RuleRefDef;
  customer?: string;
  in?: (string | number | boolean)[];
  min?: number;
  max?: number;
}

/** Rules v1.8: the counter of a response effect (uniqueness, attempts, rate limits). */
export interface RuleLimit {
  n: number;
  /** Figurative window ("15m"); absent: the whole session. */
  window?: string;
  /** "${var}" bound to the request of the cause; absent: per customer. */
  key?: string;
}

/** A reference into the cause: a body field (`path`, a tt-path such as `$.id`) or a parameter (`name`). */
export interface RuleRefDef {
  from: string;
  path?: string;
  name?: string;
}

/** One effect as the rules format writes it (sent to the server as is). */
export interface RuleEffectDef {
  id: string;
  entity?: string;
  create?: Record<string, unknown>;
  target?: string;
  target_id?: string;
  set?: Record<string, unknown>;
  /** Rules v1.6: removes the target. */
  remove?: boolean;
  /** Rules v1.7: a guard, the literal values the target must have. */
  where?: Record<string, unknown>;
  /** Rules v1.8: the keyed record targeted (key field → "${var}" or literal; {} for the customer's singleton). */
  target_key?: Record<string, string>;
  /** Rules v1.9: every object of the entity owned by the customer of the cause that matches `where`. */
  target_all?: boolean;
  respond?: RuleRespond;
  after_effect?: string;
  after: string | { min: string; max: string };
}

/** The editable definition of a rule (tt.rules/v1 without the header the server owns). */
export interface RuleDefinition {
  kind: 'causal' | 'batch';
  title: string;
  cause?: { service: string; op: string; when: { status: number[]; match?: RuleMatch[] }; bind?: Record<string, RuleRefDef> };
  effects?: RuleEffectDef[];
  /** Rules v1.9: `when` makes an outcome conditional (eligible only when its conditions hold). */
  outcomes?: { name: string; p: number; effects: string[]; when?: RuleMatch[] }[];
  schedule?: string;
  entity?: string;
  where?: Record<string, unknown>;
  set?: Record<string, unknown>;
  fraction?: number;
}

/** A field a rule may name: a parameter (`name`) or a body field (`path`), with the published values of the contract. */
export interface CatalogField {
  from: string;
  name?: string;
  path?: string;
  type?: string;
  kind?: string;
  domain?: string;
  values?: string[];
}

export interface CatalogOp {
  op: string;
  statuses: number[];
  /** Example names by status ("404" → ["order-not-found"]). */
  examples?: Record<string, string[]>;
  params?: CatalogField[];
  request?: CatalogField[];
  response?: CatalogField[];
}

/** What a rule written by hand may name: services and operations of the contracts, entities with their fields and states. */
export interface RuleCatalog {
  services: { name: string; ops: CatalogOp[] }[];
  entities: { name: string; service: string; idField: string; idDomain: string; ops: string[]; fields: CatalogField[] }[];
}

export interface RuleProblem {
  path: string;
  code: string;
  message: string;
}

export interface RuleCheck {
  valid: boolean;
  problems: RuleProblem[];
  warnings: RuleProblem[];
}

export interface RuleEffect {
  id: string;
  entity: string;
  kind: 'create' | 'set' | 'respond' | 'remove';
  /** For a response effect: which call answers what. */
  respond?: RuleRespond;
  values: Record<string, string>;
  /** Rules v1.7: the effect applies only while the entity has these values. */
  where?: Record<string, string>;
  /** Rules v1.8: the keyed record targeted (key field → value). */
  targetKey?: Record<string, string>;
  /** Rules v1.9: all the objects of the customer that match `where`. */
  targetAll?: boolean;
  target?: string;
  afterEffect?: string;
  /** Figurative delay, e.g. "5m". Editable. */
  after: string;
  /** Order of magnitude suggested by the miner. */
  magnitude?: 'seconds' | 'minutes' | 'hours' | 'days';
}

export interface RuleOutcome {
  name: string;
  p: number;
  effects: string[];
  /** Exact count for this branch. */
  count: number;
  /** Rules v1.9: the conditions that make this branch eligible. */
  when?: RuleMatch[];
}

export interface Rule {
  id: string;
  /** Groups owning every service the rule touches. */
  groups?: string[];
  kind: 'causal' | 'batch';
  status: RuleStatus;
  title: string;
  /** Who wrote it: the miner, or a person in the rule editor. */
  origin: 'mined' | 'manual';
  /** The definition as stored, for the rule editor. */
  definition: RuleDefinition;
  cause?: { service: string; op: string; whenStatus: number[]; bind: Record<string, string>; match?: RuleMatch[] };
  effects: RuleEffect[];
  outcomes: RuleOutcome[];
  /** Exact counts from the store. */
  counts: { causes: number; distinctSubjects: number; keyMatches: number };
  /** Estimates, only used to propose delays. */
  hints: { magnitude: Record<string, string>; scheduleConfidence?: string };
  batch?: { schedule: string; entity: string; where: Record<string, string>; set: Record<string, string>; fraction: number; runs: number; entitiesChanged: number };
  review: { by: string[]; at: string | null; note: string };
  supersedes?: string;
  /** The rule that replaced this one (the server says so once it retires it; absent otherwise). */
  supersededBy?: string;
  /** Why it is stale, or what is going wrong while an approved rule is on watch. */
  staleReason?: string;
  /** Consecutive failed mining runs of an approved rule (it goes stale after a few). */
  failedRuns?: number;
  /** When the miner first proposed it. */
  proposedAt?: string;
}

export type ReviewAction = 'approve' | 'reject' | 'confirm' | 'retire';

/** What the last mining run saw: with less traffic than `minHours` no rule can be decided. */
export interface MiningStatus {
  state: 'never_run' | 'no_data' | 'insufficient_data' | 'few_subjects' | 'ok';
  minHours: number;
  observedHours: number;
  events: number;
  /** Distinct sampled users of the last run and the least a rule needs (k-anonymity); `few_subjects` when fewer. */
  subjects?: number;
  kMin?: number;
  lastRunAt?: string;
  rules: Record<string, number>;
  /** What deserves a look: dropped entities, rules on watch or stale, with the reasons (the miner's English texts). */
  warnings: string[];
  /** Why the last run proposed (or not) a rule per candidate, as codes the UI translates; for the Rules page. */
  diagnostics: MinerExplanation[];
  /** Rules v1.9 (admin-api 1.21.0): structures seen by fewer than k users, offered as guided drafts. */
  candidates?: MinerCandidate[];
  /** HMAC domains that look like one identifier under two names (join them in the policy). */
  families?: FamilyCandidate[];
  /** Per group mined with a lower k (marked as test), the k used. */
  testK?: Record<string, number>;
}

/**
 * A structure seen by fewer than k users (C0): structure only — operations, field names, clear states, a status — and
 * the number of users as a bucket ("1", "2-4", "5-9", "10+"), never an example or an exact count.
 */
export interface MinerCandidate {
  group?: string;
  signature: string;
  /** create, update, keyed_update, update_all, remove, limit, precondition, later, revert. */
  kind: string;
  /** The editor template it fills: write_changes_field, expires_after, at_most_n, until, custom. */
  template: string;
  service: string;
  op: string;
  entity?: string;
  fields?: string[];
  states?: string[];
  status?: number;
  /** "service op" whose answers a response effect changes. */
  target?: string;
  subjects: string;
  /** The rule skeleton the editor starts from (a rules.v1 definition). */
  draft?: RuleDefinition;
  /** Entities the draft needs that the run did not accept (seen by fewer than k users): it cannot be saved yet. */
  missingEntities?: string[];
}

/** Two HMAC domains that look like one identifier, judged from structure only (C15). */
export interface FamilyCandidate {
  group?: string;
  domains: string[];
  subjects: number;
  signals: string[];
  score: number;
}

/**
 * One explanation of a mining run, for a person: `code` names the reason (rules.why.<code>), the figures fill it,
 * `reason` is the miner's technical English text. `service` scopes it to a group.
 */
export interface MinerExplanation {
  kind: 'rule' | 'entity';
  code: string;
  service: string;
  op: string;
  entity: string;
  causes: number;
  decided: number;
  subjects: number;
  horizonS: number;
  reason: string;
  /**
   * Causal candidates (admin-api 1.17.0): `in_clear` when the object already has fields in clear (a status leaving as a
   * code counts: no approval to ask for), `dropped` when none (an approval may be what is missing). Absent on older servers.
   */
  values?: 'in_clear' | 'dropped';
  clearFields?: string[];
}

// ---------------------------------------------------------------- archetypes, worlds

export interface Archetype {
  id: string;
  label: string;
  /** Hidden by the server when below k. */
  size: number | null;
  belowK: boolean;
  features: { ordersPerMonth: string; activeHours: string; outcomesMix: Record<string, number> };
}

export interface ArchetypeSet {
  /** Group of the build (absent: every group). */
  group?: string;
  /** False until the profiles have been built once (the Worlds page then builds them itself). */
  built?: boolean;
  kMin: number;
  archetypes: Archetype[];
  mergedCount: number;
}

export interface World {
  id: string;
  /** Group the world was generated for ("" or absent: every group). */
  group?: string;
  seed: number;
  customers: number;
  createdAt: string;
  createdBy: string;
  entities: number;
  /** Rules applied (ids): the group filter keeps the worlds whose rules involve its services. */
  rules?: string[];
  /** Services the world was generated for (empty: every service). */
  services?: string[];
  /** Answer of the generation only: the group's approved rules left out (they need services of another group). */
  excludedRules?: { id: string; services: string[] }[];
}

export interface WorldNode {
  id: string;
  /** Entity name from the world ("order", "shipment", ...) or "customer". */
  type: string;
  label: string;
  state?: string;
}

export interface WorldGraph {
  customerId: string;
  archetype: string;
  nodes: WorldNode[];
  edges: { from: string; to: string; rule?: string }[];
}

/** One synthetic customer of a world, as listed by the world explorer. */
export interface WorldCustomerRow {
  id: string;
  /** Invented name and e-mail (reserved domain). */
  name: string;
  email: string;
  archetype: string;
  /** Entities owned, per kind ("order": 2, "shipment": 2). */
  entities: Record<string, number>;
}

export interface WorldCustomerPage {
  /** Customers matching the search / all customers of the world. */
  total: number;
  all: number;
  offset: number;
  limit: number;
  customers: WorldCustomerRow[];
}

/** One step of an entity's life: the state it entered, in world time. */
export interface WorldStep {
  at: string;
  seq: number;
  /** The status after the step (state.status), or '' when the entity has none. */
  status: string;
  /** Rule that caused the step (absent: created by an operation). */
  rule?: string;
  /** Outcome of the rule effect ("happy", "cancelled", ...). */
  outcome?: string;
}

export interface WorldEntity {
  id: string;
  entity: string;
  /** Final state, field by field. */
  state: Record<string, unknown>;
  steps: WorldStep[];
}

/** A customer of a world with its entities and their state timelines. */
export interface WorldCustomerDetail {
  id: string;
  name: string;
  email: string;
  archetype: string;
  entities: WorldEntity[];
}

export interface GenerateWorldInput {
  seed: number;
  customers: number;
  /** Services of the team: the world holds their rules and contracts only (absent: every service). */
  services?: string[];
  /** Group of the world: contracts, rules and services of that group only (absent: every group). */
  group?: string;
}

/** What a mining run did and, when it proposed nothing, why. */
/** Where a mining run requested from the console is. */
export interface MineProgress {
  status: 'queued' | 'running';
  /** Seconds since the request. */
  elapsedS: number;
  /** The last poll failed (the server is busy or restarting): the job is followed again. */
  retrying?: boolean;
}

export interface MineResult {
  newRules: number;
  updatedRules: number;
  staleRules: number;
  events: number;
  /** State of the mining after the run (see MiningStatus). */
  state: MiningStatus['state'];
  subjects?: number;
  kMin?: number;
  /** Why candidates produced no rule (the miner's own English texts: technical detail). */
  reasons: string[];
  warnings: string[];
  /** The same reasons as codes, per candidate (see MinerExplanation). */
  diagnostics: MinerExplanation[];
  /** When the run finished (ISO). */
  finishedAt?: string;
}

// ---------------------------------------------------------------- publications

export type CheckId = 'provenance' | 'reverse-hmac' | 'pii-detectors' | 'k-thresholds' | 'rules-approved';
/** warn: advisory (rules-approved with no approved rule); it never blocks the pack. */
export type CheckStatus = 'pending' | 'running' | 'pass' | 'warn' | 'fail' | 'skipped';

export interface GateFinding {
  file: string;
  pointer: string;
  reason: string;
}

export interface GateCheck {
  id: CheckId;
  status: CheckStatus;
  findings: GateFinding[];
  stringsChecked?: number;
}

export type PackStatus = 'building' | 'gate-failed' | 'signed' | 'published';

export interface ResidualRisk {
  note: string;
  profiles: number;
  archetypes: number;
  minArchetypeSize: number;
  suppressedSubjects: number;
  uniquenessRate: number;
  singlingOutRate: number;
  exactMatchShare: number;
  maxHomogeneity: number;
}

export interface Publication {
  id: string;
  packId: string;
  /** building -> (gate) -> signed | gate-failed; a signed pack is released to the tests with publish(). */
  status: PackStatus;
  publishedAt?: string;
  residualRisk?: ResidualRisk;
  createdAt: string;
  createdBy: string;
  worldId: string;
  seed: number;
  kMin: number;
  verdict: 'running' | 'pass' | 'fail';
  checks: GateCheck[];
  rulesApproved: string[];
  /** End of validity of the pack (manifest.not_after); absent = never expires. */
  notAfter?: string;
  adminOverride?: { by: string; reason: string };
  files: { path: string; bytes: number; sha256: string }[];
  signedBy?: string;
  /** Services in the pack (manifest). */
  services?: string[];
  /** Group the pack was built for. */
  group?: string;
  /** Groups of the services in the pack (more than one only for a multi-group pack). */
  groups?: string[];
}

/** Options of a pack build (POST /api/v1/packs). */
export interface PackRunOptions {
  validDays?: number;
  /** Explicit include list. */
  services?: string[];
  /** Services left out of the pack. */
  excludeServices?: string[];
  /** Group of the pack (default: the world's group). */
  group?: string;
  /** Services of several groups in one pack (administrators only). */
  multiGroup?: boolean;
}

export type ExportTarget = 'wiremock' | 'microcks' | 'prism';

export interface ExportReport {
  /** Id of the stored export: its zip is downloaded with publications.downloadExport. */
  exportId?: string;
  target: ExportTarget;
  produced: { path: string; description: string }[];
  preserved: string[];
  lost: { item: string; reason: string }[];
}

// ---------------------------------------------------------------- mock scenarios

export interface FaultSetting {
  service: string;
  op: string;
  status: number;
  p: number;
}

export interface ScenarioPreset {
  id: string;
  name: string;
  description: string;
  builtin: boolean;
  faults: FaultSetting[];
  forcedOutcomes: { rule: string; outcome: string }[];
  /**
   * The random faults copied from the traffic are off (repeatable tests). The faults listed in `faults` fire anyway:
   * the session mode is `custom` when there are some, `off` otherwise (usability test #4, M4).
   */
  deterministic: boolean;
  clockAdvance?: string;
  /** Stored by an older console with mode `off` and faults: the mock ignores them until the preset is saved again. */
  faultsIgnored?: boolean;
}

// ---------------------------------------------------------------- alerts, audit, users, settings, gaps

export type AlertType =
  | 'contract.drift'
  | 'rule.stale'
  | 'quarantine.opened'
  | 'source.problem'
  | 'kill.changed'
  | 'keyguard.alert'
  | 'pack.published'
  | 'storage.high_watermark'
  | 'source.health'
  | 'policy.admin_approval';

export interface DriftAlert {
  id: string;
  /** Group of the service (drift of contracts). */
  group?: string;
  type: AlertType;
  severity: 'breaking' | 'non-breaking' | 'info' | 'warning';
  service: string;
  op?: string;
  change: string;
  firstSeen: string;
  callsAfterChange?: number;
  state: 'open' | 'acknowledged' | 'resolved';
}

export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: AlertType[];
  enabled: boolean;
  /** The signing secret is set. */
  secretSet?: boolean;
  /** Returned once, when the server generated it. */
  secret?: string;
  lastDelivery?: { at: string; ok: boolean; httpStatus: number };
}

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  result: 'ok' | 'denied' | 'error';
  prevHash: string;
  hash: string;
}

export interface AuditVerification {
  ok: boolean;
  /** Where the chain breaks, as reported by the server (positions only, never content). */
  error?: string;
  entries: number;
  headHash: string;
  verifiedAt: string;
  brokenAt?: number;
}

export interface RoleInfo {
  role: Role;
  permissions: Permission[];
}

export interface NewUserInput {
  username: string;
  displayName: string;
  roles: Role[];
  authMethod: 'local' | 'sso';
  /** Local users only (the server stores a hash). */
  password?: string;
}

export interface GeneralSettings {
  environment: EnvName;
  retentionDays: number;
  kMin: number;
  defaultSamplingBp: number;
  anonymizeHosts: boolean;
  minSamples: number;
  sso: { enabled: boolean; issuer: string; clientId: string; roleClaim: string };
}

export interface Settings {
  /** Read-only: lives in keyguard, not in tt-core, so a compromised core cannot lower it. */
  approvals: {
    openingRequired: 1 | 2;
    adminOverride: boolean;
    identitiesVerified: boolean;
    /** false when this role cannot read them or keyguard was not reached yet: the values are the strict defaults. */
    known?: false;
  };
  /** Absent when the server does not expose its configuration through the API. */
  general?: GeneralSettings;
  /**
   * What tt-core reports: two labels that can be edited at run time, the rest mirrors the configuration
   * file and is read-only (it is changed there, never from the console).
   */
  server?: ServerSettings;
}

export interface ServerSettings {
  /** Editable (admin). Empty when none is set. */
  installation: string;
  /** Editable (admin). Absent when none is set. */
  environment?: EnvName;
  /** Read-only. */
  privacy: {
    eventsRetentionDays: number;
    aggregatesDays: number;
    kMin: { contract: number; miner: number; world: number; gate: number };
    minSamples: number;
  };
  /** Read-only. */
  access: {
    localEnabled: boolean;
    sso: { enabled: boolean; issuer: string; clientId: string; roleClaim: string };
    sessionIdleSeconds: number;
    sessionAbsoluteSeconds: number;
  };
}

export interface SigningKey {
  kid: string;
  alg: string;
  publicKey: string;
  endorsedBy?: string;
  revoked: boolean;
  /** keyguard signs new policies with this key: it cannot be revoked. */
  active?: boolean;
  /** Sources seen in the confirmation window (default 24 h) that trust this key. */
  trustedBy?: number;
  /** Whether a revocation would be accepted now (absent for revoked keys). */
  revoke?: SigningKeyRevoke;
}

export interface SigningKeyRevoke {
  /** Sources seen in the window. */
  seen: number;
  /** Of those, how many already trust the key that signs after the revocation. */
  confirmed: number;
  /** Fraction required (0..1, default 1). */
  required: number;
  ok: boolean;
  /** last_signing_key, active_signing_key or rotation_unconfirmed. */
  blocker?: string;
}

export interface QuarantineItem {
  id: string;
  /** Group of the source the item comes from. */
  group?: string;
  kind: 'keep-value' | 'name' | 'path-segment' | 'host' | 'host-label' | string;
  /** host_cardinality for the two host kinds: the intake collapsed host labels (spec v1.5); value_cardinality for a keep-value item (spec v1.19). */
  alert?: 'host_cardinality' | 'value_cardinality';
  service: string;
  op?: string;
  /** Part and path, e.g. "resp.body $.status". Never a value. */
  where: string;
  distinctEstimate: number;
  state: 'quarantined' | 'dismiss-pending' | 'resolved';
  since: string;
  approvals: { by: string; at: string }[];
}

export interface Retention {
  eventsDays: number;
  aggregatesDays: number;
}

/** Budget level of the database (GET /api/v1/store/usage). */
export type StorageLevel = 'ok' | 'high' | 'critical' | 'over';

/** One growing dataset with its size and retention (docs/DATA_LIFECYCLE.md). */
export interface StoreDataset {
  name: string;
  bytes: number;
  /** Bytes kept outside the database (audit archive, export files). */
  fileBytes: number;
  quotaBytes?: number;
  overQuota: boolean;
  /** Retention policy: a stable code and its parameters (days, counts). */
  policy: { code: string; params: Record<string, number> };
  lastRun?: { deleted: number; error?: string; durationMs: number };
}

export interface StoreUsage {
  db: { file: string; fileBytes: number; walBytes: number; freeBytes: number; usedBytes: number; maxBytes: number; usedPct: number; highPct: number; criticalPct: number; level: StorageLevel; autoVacuum: 'incremental' | 'none' };
  datasets: StoreDataset[];
  measuredAt?: string;
  lastRun?: { trigger: string; startedAt: string; finishedAt: string; deleted: number; reclaimedBytes: number; reclaimNote?: string; errors: number; shed: string[] };
  nextRun?: string;
  running: boolean;
  jobId?: string;
  intervalSeconds: number;
  rollups: { tier: 'hour' | 'day' | 'month'; rows: number; oldest?: string }[];
  auditArchive?: { enabled: boolean; dir: string; segments: number; entries: number };
}

export interface KeyguardStatus {
  reachable: boolean;
  hmacKids: string[];
  epochs: string[];
  approvalsUnverified: boolean;
  matchBudgetLeft?: number;
  policyKid?: string;
  packKid?: string;
  revokedKids: string[];
  openingApprovals: number;
  adminOverride: boolean;
  transport?: string;
}

export interface KeyguardAuditEntry {
  seq: number;
  at: string;
  op: string;
  outcome: string;
  detail: Record<string, string>;
  hash: string;
}

export interface EventsExportInput {
  from: string;
  to: string;
  service?: string;
  format: 'ocel2-json' | 'jsonl';
}

export interface EventsExportJob {
  jobId: string;
  format: 'ocel2-json' | 'jsonl';
  bytes: number;
  events?: number;
  notice?: string;
}

export interface Gap {
  id: string;
  /** Group of the service. */
  group?: string;
  kind: 'few-samples' | 'status-never-seen' | 'low-support-rule' | 'value-unknown' | 'entity-without-creator';
  /** What the gap is about: the operation as a whole, or one field of it. */
  scope: 'op' | 'field';
  service?: string;
  op?: string;
  ruleId?: string;
  /** Observed count and the threshold it is compared to (when the server reports one). */
  count: number;
  threshold?: number;
  detail: string;
}

// ---------------------------------------------------------------- hosts (spec v1.5)

/** One host pattern of the registry (admin-api HostPattern). `{*}` stands for a label that looked like a value and was hidden. */
export interface HostEntry {
  /** `api.carrier.example`, `{*}.tracking.example:8443`, `ip:private`; `unlisted` / `invalid` for the two special entries. */
  pattern: string;
  /** Group whose sources called the host: the same pattern called by two groups is two entries. */
  group?: string;
  /** The `service` of the events: `host:<pattern>` or the name of the declared service. */
  service: string;
  /** A service of a policy already describes this host ("censito"). */
  declared: boolean;
  declaredBy: string[];
  /** No `{*}` label and not an IP class: the twin needs no typed base. */
  exact: boolean;
  /** The intake collapses a position of this registrable domain (`host-label` quarantine). */
  quarantined: boolean;
  calls: number;
  serverErrors: number;
  clientErrors: number;
  /** server errors (5xx, network) / calls. */
  errorRate: number;
  latencyP50Ms: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
  callers: { service: string; calls: number }[];
  policies: string[];
  /** Undeclared pattern that a policy has declared since: the name of that external service (older calls). */
  nowDeclaredAs?: string;
  /** Calls of earlier entries of the same host folded into this one (the history before its declaration). */
  mergedCalls?: number;
  /** The older `host:<pattern>` rows the server folded into this declared entry (admin-api 1.17.0). */
  foldedFrom?: string[];
}

export interface HostDomain {
  /** Registrable domain, or the IP class (`ip:private`, `ip:public`). */
  domain: string;
  calls: number;
  firstSeen: string | null;
  lastSeen: string | null;
  patterns: HostEntry[];
}

export interface HostsRegistry {
  domains: HostDomain[];
  /** Calls that left as `host:unlisted` (strict mode). */
  unlisted: HostEntry;
  invalid: HostEntry;
  /** `hosts.discovery` of the latest signed version of each policy. */
  discovery: Record<string, HostsDiscovery>;
  /**
   * Counters computed by the server (`counts` of GET /api/v1/hosts, admin-api 1.17.0, mapped by the REST adapter; every
   * field optional): the tiles of the page use them when present. `hosts` is the named hosts, `all` named and IP ones.
   */
  counters?: { domains?: number; hosts?: number; ips?: number; all?: number; undeclared?: number; new?: number; quarantined?: number };
}

export interface HostTwinInput {
  /** The pattern as listed (`{*}.tracking.example`). */
  pattern: string;
  /** Needed when the host was seen under several policies or none. */
  policyId?: string;
  /** Service name; default derived by the server from the base. */
  service?: string;
  /** Exact base `http(s)://host[:port][/segment]`; required for `{*}` and IP classes. */
  base?: string;
  /** Scheme of an exact pattern when no base is given: required, never guessed (the events do not carry it). */
  scheme?: 'http' | 'https';
  /** Group of the registry entry: picks the policy of that group. */
  group?: string;
}

/**
 * Group selection of a call: one group (a row's own group), the groups of the header filter, or null / undefined for
 * every group (no `group` parameter). Sent as `group=a,b`.
 */
export type GroupSel = string | readonly string[] | null | undefined;

/** The group names of a selection, or null for every group (null, undefined, no names; "" is no filter). */
export function groupNames(g: GroupSel): string[] | null {
  if (g === null || g === undefined) return null;
  const names = [...new Set((typeof g === 'string' ? [g] : [...g]).map((x) => x.trim()).filter(Boolean))];
  return names.length ? names : null;
}

/** Key of an observed service, (group, service): rows of lists, Svelte each keys. */
export const serviceKey = (group: string | undefined, service: string): string => `${group ?? ''}\u0000${service}`;

// ---------------------------------------------------------------- the Api contract

export * from './mocksvc';
import type { MockServiceApi } from './mocksvc';
export * from './idfmt';
import type { IdFormatsApi } from './idfmt';
export * from './dates';
import type { DateOffsetsApi } from './dates';
export * from './pages';
export * from './opkinds';
import type { OpKindsApi } from './opkinds';

export interface Api {
  system: { status(): Promise<SystemStatus>; setup(req: SetupRequest): Promise<void> };
  auth: {
    me(): Promise<User | null>;
    login(c: Credentials): Promise<User>;
    ssoLogin(): Promise<User>;
    logout(): Promise<void>;
  };
  sources: {
    list(): Promise<Source[]>;
    revoke(id: string): Promise<void>;
    setSampling(id: string, bp: number): Promise<void>;
    kill(scope: KillScope, active: boolean): Promise<void>;
  };
  onboarding: {
    /**
     * `serviceNames`: names the group may use (the REST adapter creates or widens the group); none = the name of the
     * first source that enrolls. `samplingRate`: sampling of the starter policy ("0.05" default).
     */
    createToken(choice: SourceChoice, group: string, serviceNames?: string[], opts?: { samplingRate?: string }): Promise<EnrollmentToken>;
    status(tokenId: string): Promise<OnboardingStatus>;
    /** Live status: server-sent events when the server offers them, polling otherwise. Returns the stop function. */
    watch(tokenId: string, onStatus: (s: OnboardingStatus) => void, onError?: (e: Error) => void): () => void;
    discovered(tokenId: string): Promise<DiscoveredService[]>;
    /** Policy assistant for the policy bound to a group: operations per service, each with its fields. */
    assist(group: string): Promise<PolicyAssist>;
    /** Live state of the observe phase of a group (policy.md §7). */
    observe(group: string): Promise<ObserveStatus>;
    /** Turns the automatic observe versions of a group on or off (operator, policy-approver). */
    setObserveAuto(group: string, auto: boolean): Promise<ObserveStatus>;
    /**
     * Sets who the user is for the group's policy (admin-api 1.18.0 setIdentity): any header that is not a credential
     * applies at once (an `active` version); a cookie or a credential waits for approvals (a `draft`).
     */
    setIdentity(group: string, identity: IdentitySource): Promise<PolicyVersion>;
    /** Joins HMAC domains in a family of the group's policy (admin-api 1.21.0 setFamily; observe-safe, applies at once). */
    setFamily(group: string, family: string, domains: string[]): Promise<PolicyVersion>;
    /** Separates a family again (removeFamily). */
    removeFamily(group: string, family: string): Promise<PolicyVersion>;
    /** Marks a group as test with a lower k (admin only, with a reason; 0 turns it off). */
    setTestK(group: string, kMin: number, reason: string): Promise<ObserveStatus>;
  };
  policies: {
    /** Versions of the policies serving the groups (every policy without a selection). */
    list(groups?: GroupSel): Promise<PolicyVersion[]>;
    propose(input: ProposePolicyInput): Promise<PolicyVersion>;
    approve(policyId: string, version: number, reason?: string): Promise<PolicyVersion>;
    /** The policy text before and after the choices, as the server will receive it, with how it would apply. */
    preview(input: ProposePolicyInput): Promise<{ before: string; after: string; skipped: string[] } & Partial<ChangeClass>>;
    /** `hosts.discovery` of the policy bound to a group (active version; `auto` when the policy does not say). */
    hostsDiscovery(group: string): Promise<HostsDiscovery>;
    /**
     * Who can approve the policy drafts of a group (GET /fleet/groups/{group}/approvers, admin-api 1.15.0): the
     * policy-approvers, then the administrators; names only. Members of the group (operator) and admins.
     */
    approvers(group: string): Promise<GroupApprover[]>;
    /**
     * Takes a pending draft back (proposer or admin): POST /fleet/policies/{id}/versions/{v}/withdraw, body `{reason?}`.
     * A server without the route answers with an `unsupported` error: the UI says so and offers nothing else.
     */
    withdraw(policyId: string, version: number, reason?: string): Promise<PolicyVersion>;
  };
  hosts: {
    /** Every outbound host seen, grouped by registrable domain (operator, admin). */
    list(groups?: GroupSel): Promise<HostsRegistry>;
    /** A new policy version with an external service for the host: applied at once or a draft, as the server classifies it. */
    twin(input: HostTwinInput): Promise<PolicyVersion>;
    /**
     * How the server would classify that version (dry run of the assistant's draft), before creating it: null when it
     * cannot say yet (the assistant has not seen the host, or an older server).
     */
    twinPreview(input: HostTwinInput): Promise<ChangeClass | null>;
  };
  services: {
    /** One row per (group, service). */
    list(groups?: GroupSel): Promise<ServiceInfo[]>;
    /** The twin choice of one service of one group. */
    setTwin(name: string, twin: boolean, group?: string): Promise<void>;
  };
  /** Group/Team filter data (any user). */
  scope: { get(): Promise<ScopeData> };
  /** Public keys of the publication gate (any user): the value tt mock needs, and gate-keys.txt. */
  gate: { keys(): Promise<GateKeys>; keyFile(): Promise<{ filename: string; blob: Blob }> };
  contracts: {
    /** Calls seen and needed, latest snapshot, next scheduled snapshot. */
    // `group`: the contract of that group's traffic only (a row's own group); absent = every group.
    status(service: string, group?: GroupSel): Promise<ContractStatus>;
    /** Snapshot of the last window up to now ("Aggiorna contratto ora", operator). */
    refreshNow(service: string, group?: GroupSel): Promise<void>;
    /** Operations of one service, or of every service of the groups. */
    operations(service?: string, group?: GroupSel): Promise<OperationSummary[]>;
    operation(service: string, op: string, group?: GroupSel): Promise<OperationDetail>;
    snapshots(service: string, group?: GroupSel): Promise<SnapshotInfo[]>;
    diff(service: string, from: string, to: string, group?: GroupSel): Promise<SnapshotDiff>;
    service(name: string, group?: GroupSel): Promise<ServiceSummary>;
    /** OpenAPI 3.1 document of one service (as in the pack, with x-tt-* extensions). */
    openapi(service: string, group?: GroupSel): Promise<Record<string, unknown>>;
    /** The same document as text, serialized by the server. */
    rawDocument(service: string, format: 'json' | 'yaml', group?: GroupSel): Promise<string>;
    /** Postman Collection v2.1 generated from the contract (requests with example bodies, base URL in {{baseUrl}}). */
    /** baseUrl: the {{baseUrl}} of the collection (the Mock page passes the running mock's URL of the service). */
    postman(service: string, group?: GroupSel, baseUrl?: string): Promise<{ filename: string; blob: Blob }>;
  };
  rules: {
    list(groups?: GroupSel): Promise<Rule[]>;
    get(id: string): Promise<Rule>;
    setAfter(id: string, effectId: string, after: string): Promise<Rule>;
    review(id: string, action: ReviewAction, note: string): Promise<Rule>;
    /**
     * One mining run now (operator). Returns how many rules are new. A run takes from seconds to minutes: it is followed
     * as a job (queued, running) and `onProgress` says where it is; a brief failure of the server while it runs is not
     * an error (usability test #4, M3).
     */
    mine(onProgress?: (p: MineProgress) => void): Promise<MineResult>;
    /** Coverage of the last run: `insufficient_data` explains an empty list. `groups`: the run seen by those groups (`?group=`). */
    status(groups?: GroupSel): Promise<MiningStatus>;
    /** What a rule written by hand may name (contracts, entities, states) for the rule editor's dropdowns. */
    catalog(groups?: GroupSel): Promise<RuleCatalog>;
    /** Validates a definition against the contracts without storing it. */
    check(def: RuleDefinition, groups?: GroupSel): Promise<RuleCheck>;
    /** Stores a rule written by hand: a draft with origin manual (rule-reviewer). */
    create(def: RuleDefinition, groups?: GroupSel): Promise<Rule>;
    /** Replaces the definition of a rule: a draft in place, an approved one gets a new superseding draft. */
    update(id: string, def: RuleDefinition, groups?: GroupSel): Promise<Rule>;
    /**
     * Takes an approved rule out of the packs (rule-reviewer, admin): POST /rules/{id}/retire, body `{note?}`. A server
     * without the route answers with an `unsupported` error.
     */
    retire(id: string, note?: string): Promise<Rule>;
  };
  quarantine: {
    list(groups?: GroupSel): Promise<QuarantineItem[]>;
    /** close: one policy-approver, the rewrite stays for good. dismiss: opens data again, two distinct policy-approvers. */
    resolve(id: string, resolution: 'close' | 'dismiss', note?: string): Promise<QuarantineItem>;
  };
  store: {
    retention(): Promise<Retention>;
    setRetention(eventsDays: number): Promise<Retention>;
    /** Delete the stored events older than `before` (ISO time). */
    purge(before: string): Promise<{ events: number; tokens: number }>;
    /** Sizes per dataset, retention, budget and maintenance runs (admin, auditor). */
    usage(): Promise<StoreUsage>;
    /** Run the data lifecycle now (a background job, followed until it ends). */
    maintenance(): Promise<{ deleted: number; reclaimedBytes: number; level: StorageLevel }>;
  };
  keyguard: { status(): Promise<KeyguardStatus>; audit(): Promise<KeyguardAuditEntry[]> };
  events: {
    /** Event-level export (pseudonymous personal data: zone B only), for the event-exporter. */
    export(input: EventsExportInput): Promise<EventsExportJob>;
    download(job: EventsExportJob): Promise<{ filename: string; blob: Blob }>;
  };
  /** The latest archetype build of a group (every group without one). */
  archetypes: {
    get(group?: GroupSel): Promise<ArchetypeSet>;
    /** Build the profiles from the group's traffic with the configured k (operator). The Worlds page calls it when there are none. */
    build(group?: string): Promise<ArchetypeSet>;
  };
  worlds: {
    list(groups?: GroupSel): Promise<World[]>;
    generate(input: GenerateWorldInput): Promise<World>;
    graph(worldId: string, customerIndex: number): Promise<WorldGraph>;
    /** World explorer: a page of the synthetic customers (search by id, name, e-mail or archetype). */
    customers(worldId: string, query?: { q?: string; offset?: number; limit?: number }): Promise<WorldCustomerPage>;
    /** World explorer: one customer with its entities and their state timelines. */
    customer(worldId: string, customerId: string): Promise<WorldCustomerDetail>;
  };
  publications: {
    list(groups?: GroupSel): Promise<Publication[]>;
    get(id: string): Promise<Publication>;
    /** Assemble, gate and sign a pack from a world (operator). */
    run(worldId: string, opts?: PackRunOptions): Promise<Publication>;
    /** Release a signed pack to the tests: a publisher, or an admin with a mandatory reason. */
    publish(id: string, opts?: { reason?: string }): Promise<Publication>;
    download(id: string): Promise<{ filename: string; blob: Blob }>;
    downloadExport(exportId: string): Promise<{ filename: string; blob: Blob }>;
    export(id: string, target: ExportTarget): Promise<ExportReport>;
  };
  scenarios: { list(): Promise<ScenarioPreset[]>; save(p: ScenarioPreset): Promise<ScenarioPreset>; remove(id: string): Promise<void> };
  /** The Mock page: connected mocks, mock tokens, managed mocks, "Prepara e avvia il mock", control calls. */
  mocks: MockServiceApi;
  /** "Formato degli id": the shape of the synthetic ids of an id domain, per group (world and mock). */
  idFormats: IdFormatsApi;
  /** "Date relative": the range of a date field chosen by a person, per field name and group (world and mock). */
  dateOffsets: DateOffsetsApi;
  /** "Questa operazione è una lettura": the kind of an operation for the miner, decided by the traffic or by a person. */
  opKinds: OpKindsApi;
  alerts: { list(groups?: GroupSel): Promise<DriftAlert[]>; setState(id: string, state: DriftAlert['state']): Promise<void> };
  webhooks: {
    list(): Promise<Webhook[]>;
    save(w: Omit<Webhook, 'id'> & { id?: string }): Promise<Webhook>;
    remove(id: string): Promise<void>;
    test(id: string): Promise<Webhook>;
  };
  audit: { list(): Promise<AuditEntry[]>; verify(): Promise<AuditVerification> };
  users: {
    list(): Promise<User[]>;
    roles(): Promise<RoleInfo[]>;
    create(u: NewUserInput): Promise<User>;
    update(id: string, patch: { roles?: Role[]; disabled?: boolean; revokeSessions?: boolean }): Promise<User>;
  };
  settings: { get(): Promise<Settings>; save(s: Settings): Promise<Settings> };
  fleet: { signingKeys(): Promise<SigningKey[]>; revokeSigningKey(kid: string): Promise<void> };
  gaps: { list(groups?: GroupSel): Promise<Gap[]> };
  capabilities: Capabilities;
  /** Present only on the mock adapter of the demo build: demo helpers. */
  demo?: { loginAs(role: Role): Promise<User>; resetFirstRun(): void };
}

export type ApiErrorCode =
  | 'unauthenticated'
  /**
   * The CSRF token of this tab does not match the session cookie: the session expired, or another login in the same
   * browser replaced it (another tab). Not a missing role: reloading the page fixes it.
   */
  | 'session'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'invalid'
  | 'already_initialized'
  /** The server does not serve this endpoint (yet). */
  | 'unsupported'
  | 'rate_limited'
  | 'unavailable'
  | 'network'
  | 'server';

/** One entry of the `details` of an error: a missing service with the rules that need it, or a rule out of scope. */
export interface ApiErrorDetail {
  service?: string;
  rules?: string[];
  entities?: string[];
  rule?: string;
  services?: string[];
  /** mixed_groups: the groups of `service`. */
  groups?: string[];
  /** invalid_rule: where in the rule, the problem code and the server's English message. */
  path?: string;
  code?: string;
  message?: string;
  /** no_usable_rules: why the rule is left out (out_of_scope, unusable) and, for unusable, the server's reason. */
  reason?: string;
  detail?: string;
  /** invalid_format: 0-based position of the template error (`code` is the template error code). */
  at?: number;
}

export class ApiError extends Error {
  constructor(
    public code: ApiErrorCode,
    message: string,
    /** HTTP status, when the error comes from a response. */
    public status?: number,
    /** The server's own error code (`{code, message}` body), e.g. "invalid_credentials". */
    public serverCode?: string,
    /** Structured details of the error (service names, rule ids), when the server gives them. */
    public details?: ApiErrorDetail[],
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
