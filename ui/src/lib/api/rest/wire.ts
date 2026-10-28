// Payloads exactly as the Go handlers of tt-core send them (snake_case).
// Hand-written from the code (internal/auth, fleet, contract, drift, miner,
// world, gate, packwriter, audit), not from api/admin-api.v1.openapi.yaml:
// where the two differ the Go code wins (see the report of the UI integration).

import type { ApiErrorDetail } from '../types';

export type WireTime = string;

// ---------------------------------------------------------------- auth

export interface WirePrincipal {
  id: string;
  username?: string;
  display_name: string;
  auth_method: string;
  roles: string[];
}
export interface WireMe {
  user: WirePrincipal;
  roles: string[];
  csrf_token: string;
  csrf_header: string;
  expires_at: WireTime;
  idle_expires_at: WireTime;
  session_idle_timeout_ms: number;
}
export interface WireAuthConfig {
  local: boolean;
  oidc: boolean;
  setup_required: boolean;
}

// ---------------------------------------------------------------- fleet

export interface WireGroup {
  name: string;
  description?: string;
  policy_id: string | null;
  allowed_service_names: string[];
  sampling_override_bp: number | null;
  killed: boolean;
  policy_draft?: { policy_id: string; version: number };
}
export interface WireProblem {
  code: string;
  message: string;
  hint?: string;
}
export interface WireLastError {
  code: string;
  at: WireTime;
  first_seen?: WireTime;
  last_seen?: WireTime;
  count?: number;
}
export interface WireSource {
  source_id: string;
  kind: string;
  version: string;
  service_name: string;
  group: string;
  instance?: string;
  state: string;
  killed: boolean;
  revoked: boolean;
  policy?: { id: string; version: number; issued_seq: number };
  last_seen: WireTime | null;
  events_per_min: number;
  drop_ratio: number;
  sanitizer_errors: number;
  sampling_override_bp: number | null;
  overhead_us?: { p50?: number; p99?: number };
  last_errors: WireLastError[];
  problems: WireProblem[];
}
export interface WireSnippet {
  id?: string;
  title: string;
  language: string;
  text: string;
}
export interface WireNewToken {
  token_id: string;
  token: string;
  expires_at: WireTime;
  snippets: WireSnippet[];
}
export interface WireOnboarding {
  steps: { enrolled: boolean; policy_received: boolean; first_events: number };
  sources: string[];
  problems: WireProblem[];
}
export interface WireApproval {
  by: string;
  at: WireTime;
  verified: boolean;
  admin_override?: boolean;
  reason?: string;
  note?: string;
  /** Present only when keyguard verifies approvals with OIDC: false = the approver's ID token expired, the approval must be renewed. */
  token_fresh?: boolean;
}
export interface WireDiffEntry {
  change: string;
  where: string;
  from?: string;
  to?: string;
  opens: boolean;
}
export interface WirePolicyVersion {
  policy_id: string;
  version: number;
  issued_seq: number | null;
  status: string;
  origin: string;
  proposed_by: string;
  proposed_at: WireTime;
  classification: string;
  /** Spec v1.6 (policy.md §7): the change opens values and needs approvals. */
  opens_values?: boolean;
  value_reasons?: { code: string; where: string }[] | null;
  approvals_required: number;
  approval_mode?: string;
  approvals: WireApproval[];
  targets: { groups: string[] };
  /** Groups bound to / targeted by the policy (group-scoped API). */
  groups?: string[];
  not_after?: WireTime;
  diff: WireDiffEntry[];
  hash?: string;
  note?: string;
  /** admin-api 1.17.0: a rejected draft its proposer (or an admin) took back (withdrawPolicy). */
  withdrawn?: boolean;
  author_yaml?: string;
}
export interface WireSuggestion {
  service: string;
  op: string;
  part: string;
  path: string;
  shape: string;
  observed: number;
  distinct_estimate: number;
  suggestion: string;
  reason: string;
  reason_code?: string;
}
export interface WireAssistOp {
  op: string;
  declared: boolean;
  calls: number;
  need_calls: number;
  raw_ops: string[] | null;
  fields: WireSuggestion[] | null;
}
export interface WireAssistService {
  service: string;
  kind: string;
  declared: boolean;
  name: string;
  host_pattern?: string;
  exact: boolean;
  base?: string;
  calls: number;
  ops: WireAssistOp[] | null;
  preselect?: boolean;
  merged_patterns?: string[] | null;
  stale?: boolean;
}
export interface WireAssist {
  policy_id: string;
  min_calls: number;
  ready: boolean;
  need_calls: number;
  message: string;
  has_identity: boolean;
  identity?: { from: string; name: string; jwt_claim: string; service: string; calls: number; with_header: number; reason: string };
  identity_candidates?: WireIdentityCandidate[] | null;
  identity_best?: { from: string; name: string; jwt_claim?: string } | null;
  sampling?: { current_bp: number; sampled_subjects: number; source: string; k_min: number; target_subjects: number; enough: boolean; population_estimate: number; suggested_bp: number; message: string };
  services: WireAssistService[] | null;
}
export interface WireMiningStatus {
  state: 'never_run' | 'no_data' | 'insufficient_data' | 'few_subjects' | 'ok';
  min_hours: number;
  observed_hours: number;
  events: number;
  subjects?: number;
  k_min?: number;
  last_run_at?: string;
  rules?: Record<string, number>;
  warnings?: string[];
  entities?: WireEntityDiag[];
  rule_diagnostics?: WireRuleDiag[];
  /** admin-api 1.21.0 (rules v1.9): structures seen by fewer than k users (C0) and domains to join (C15). */
  candidates?: WireCandidate[] | null;
  families?: WireFamilyCandidate[] | null;
  test_k?: Record<string, number> | null;
}
/** A structure seen by fewer than k users: structure only, the users as a bucket. */
export interface WireCandidate {
  group?: string;
  signature: string;
  kind: string;
  template: string;
  service: string;
  op: string;
  entity?: string;
  fields?: string[] | null;
  states?: string[] | null;
  status?: number;
  target?: string;
  subjects: string;
  /** The rule skeleton (a rules.v1 rule: counts zeroed, origin manual, status draft). */
  draft?: WireRule | null;
  /** Entities the draft needs that the run did not accept. */
  missing_entities?: string[] | null;
}
export interface WireFamilyCandidate {
  group?: string;
  domains: string[];
  subjects: number;
  signals?: string[] | null;
  score: number;
}
export interface WireEntityDiag {
  name: string;
  op?: string;
  accepted: boolean;
  reason: string;
  code?: string;
  reference?: boolean;
  born?: number;
}
export interface WireRuleDiag {
  decision: string;
  reason?: string;
  code?: string;
  service?: string;
  op?: string;
  entity?: string;
  causes?: number;
  decided?: number;
  subjects?: number;
  horizon_s?: number;
  /** admin-api 1.17.0, causal candidates: the object has fields in clear (`in_clear`) or none (`dropped`). */
  values?: string;
  clear_fields?: string[];
}
/** Result of a mining run (job `rules.mine`). */
export interface WireMineResult {
  events?: number;
  new?: string[] | number;
  updated?: string[] | number;
  stale?: string[] | number;
  entities?: WireEntityDiag[];
  rule_diagnostics?: WireRuleDiag[];
  status?: WireMiningStatus;
}
export interface WireAssistDraftResult {
  before: string;
  after: string;
  opens_values?: boolean;
  value_reasons?: { code: string; where: string }[] | null;
  approvals_required?: number;
}
/** A ranked identity candidate (admin-api 1.18.0; older servers send only from, name, calls, distinct_estimate, jwt). */
export interface WireIdentityCandidate {
  from: string;
  name: string;
  jwt_claim?: string;
  calls: number;
  distinct_estimate: number;
  jwt: boolean;
  shape?: string;
  presence?: number;
  distinct_per_call?: number;
  score?: number;
  signals?: string[] | null;
  excluded?: string;
  observe_safe?: boolean;
  best?: boolean;
}
/** GET /api/v1/fleet/groups/{group}/observe (admin-api 1.10.0). */
export interface WireObserveStatus {
  group: string;
  policy_id?: string;
  enabled: boolean;
  phase: string;
  auto?: boolean;
  active_version?: number;
  started_at?: string;
  due_at?: string;
  min_events: number;
  events: number;
  observe_version?: number;
  observe_activated_at?: string;
  discovery_until?: string;
  sampling_bp: number;
  services?: { service: string; kind: string; calls: number; ops: number }[] | null;
  masked?: { service: string; op?: string; part: string; kind: string; field: string; domain: string }[] | null;
  identity?: { from: string; name: string; jwt_claim?: string; json_path?: string };
  /** admin-api 1.21.0: hmac.families of the active policy; the lower k of a test group and the installation k. */
  families?: Record<string, string[]> | null;
  test_k_min?: number;
  k_min?: number;
  identity_candidates?: WireIdentityCandidate[] | null;
  identity_best?: { from: string; name: string; jwt_claim?: string } | null;
  sampling?: { current_bp: number; sampled_subjects: number; source: string; k_min: number; target_subjects: number; enough: boolean; population_estimate: number; suggested_bp: number; message: string };
}
export interface WireApprovalSettings {
  opening_required: number;
  admin_override: boolean;
  approvals_unverified: boolean;
  known: boolean;
}
export interface WireSigningKey {
  kid: string;
  alg: string;
  public_key: string;
  endorsed_by?: string;
  revoked: boolean;
  active?: boolean;
  trusted_by?: number;
  revoke?: { seen_sources: number; confirmed_sources: number; required_fraction: number; ok: boolean; blocker?: string };
}

// ---------------------------------------------------------------- contracts

export interface WireServiceEntry {
  service: string;
  /** Group of the sources of the traffic ("" = unknown group). */
  group?: string;
  kind: 'inbound' | 'outbound-host' | 'outbound-policy' | string;
  calls: number;
  ops: number;
  in_policy: boolean;
  first_seen: WireTime;
  last_seen: WireTime;
  /** The service is in the packs by default (stored by the server). */
  twin: boolean;
}
export interface WireSnapshotInfo {
  service: string;
  snapshot_id: string;
  window: { from: WireTime; to: WireTime };
  ops: number;
  calls: number;
  created_at: WireTime;
  hash: string;
  /** Changes against the previous snapshot of the service. */
  breaking: number;
  non_breaking: number;
}
export interface WireChange {
  op?: string;
  where: string;
  kind: string;
  severity: string;
  change: string;
  values?: string[];
  calls_after: number;
}
export interface WireDiff {
  service: string;
  from?: WireSnapshotInfo;
  to?: WireSnapshotInfo;
  breaking: number;
  non_breaking: number;
  changes: WireChange[];
}
export interface WireGap {
  /** Stable while the same hole exists. */
  id: string;
  group?: string;
  kind: string;
  service: string;
  op?: string;
  scope: 'op' | 'field';
  detail: string;
  count?: number;
  /** The value `count` is compared to, when the kind has one. */
  threshold?: number;
}

// ---------------------------------------------------------------- drift

export interface WireAlert {
  drift_id: string;
  group?: string;
  kind: 'contract.drift' | 'rule.stale';
  service: string;
  op: string;
  severity: string;
  change: string;
  first_seen: WireTime;
  evidence: { calls_after_change: number };
  state: string;
  affected_rules?: string[];
  where?: string;
  change_kind?: string;
  ack_by?: string;
  resolved_by?: string;
}
export interface WireWebhook {
  webhook_id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  secret_set: boolean;
  secret?: string;
}
export interface WireDelivery {
  delivery_id: number;
  webhook_id: string;
  event: string;
  drift_id?: string;
  state: string;
  attempts: number;
  last_status?: number;
  last_error?: string;
  created_at: WireTime;
}

// ---------------------------------------------------------------- rules (rules.v1)

export interface WireRef {
  from: string;
  path?: string;
  name?: string;
  field?: string;
  owner?: boolean;
}
export type WireDelay = string | { min: string; max: string };
export interface WireEffect {
  id: string;
  entity?: string;
  respond?: {
    service: string;
    op: string;
    status: number;
    p?: number;
    times?: number;
    example?: string;
    /** Rules v1.8: a counter per key. */
    limit?: { n: number; window?: string; key?: string };
    /** Rules v1.9: a precondition (the status until the cause is seen in the session). */
    until?: boolean;
  };
  remove?: boolean;
  /** Rules v1.8: the keyed record targeted. */
  target_key?: Record<string, string>;
  /** Rules v1.9: all the objects of the customer that match where. */
  target_all?: boolean;
  create?: Record<string, unknown>;
  target?: string;
  target_id?: string;
  set?: Record<string, unknown>;
  /** Rules v1.7: the effect applies only while the entity has these values. */
  where?: Record<string, unknown>;
  after_effect?: string;
  after: WireDelay;
}
/** Rules v1.9: a condition on the request or on the customer. */
export interface WireMatch {
  at?: WireRef;
  customer?: string;
  in?: (string | number | boolean)[];
  min?: number;
  max?: number;
}
export interface WireOutcome {
  name: string;
  p: number;
  effects: string[];
  /** Rules v1.9: the conditions that make the outcome eligible. */
  when?: WireMatch[];
}
export interface WireReview {
  by: string[];
  at: string | null;
  note: string;
}
export interface WireRule {
  id: string;
  /** Groups owning every service the rule touches. */
  groups?: string[] | null;
  kind: 'causal' | 'batch';
  status: string;
  title: string;
  /** mined (absent) or manual: written in the rule editor (rules v1.4). */
  origin?: string;
  /** Problems the server accepted but flagged (a status never observed). */
  warnings?: { path: string; code: string; message: string }[];
  /** When the miner first proposed the rule. */
  proposed_at?: WireTime;
  /** Why the rule is stale, or what is going wrong while it is on watch. */
  stale_reason?: string;
  /** Consecutive failed mining runs of an approved rule. */
  failed_runs?: number;
  supersedes?: string;
  superseded_by?: string;
  /** admin-api 1.17.0: a rejected rule a reviewer retired (retireRule). */
  retired?: boolean;
  review?: WireReview;
  // causal
  cause?: { service: string; op: string; when: { status: number[]; match?: WireMatch[] }; bind?: Record<string, WireRef> };
  effects?: WireEffect[];
  outcomes?: WireOutcome[];
  evidence?: {
    counts: { causes?: number; distinct_subjects?: number; outcomes?: Record<string, number>; key_matches?: number; runs?: number; entities_changed?: number };
    keys?: unknown[];
    hints?: { magnitude?: Record<string, string>; schedule_confidence?: string };
  };
  // batch
  schedule?: string;
  entity?: string;
  where?: Record<string, unknown>;
  set?: Record<string, unknown>;
  fraction?: number;
}

// ---------------------------------------------------------------- worlds, archetypes

export interface WireFeatures {
  orders_per_month: string;
  active_hours: string;
  error_rate: string;
  primary_op: string;
  outcome?: string;
  endpoint_mix?: Record<string, number>;
  outcomes_mix?: Record<string, number>;
}
export interface WireArchetype {
  id: string;
  label: string;
  size: number;
  features: WireFeatures;
}
export interface WireArchetypeList {
  group?: string;
  /** k of the latest build (the configured one while there is none). */
  k_min: number;
  built: boolean;
  profiles: number;
  dropped_subjects: number;
  archetypes: WireArchetype[];
}
export interface WireCustomerPage {
  world_id: string;
  total: number;
  all: number;
  offset: number;
  limit: number;
  customers: { id: string; name?: string; email?: string; archetype?: string; entities?: Record<string, number> }[];
}
export interface WireWorld {
  world_id: string;
  group?: string;
  seed: number;
  customers: number;
  archetypes_used: boolean;
  rules: string[];
  services?: string[] | null;
  created_at: WireTime;
  t0: WireTime;
  locale: string;
  entities: number;
  history: number;
  pending: number;
  sha256: string;
  excluded_rules?: { id: string; services: string[] }[];
}
export interface WireStoreUsage {
  db: { file: string; file_bytes: number; wal_bytes: number; free_bytes: number; used_bytes: number; max_bytes: number; used_pct: number; high_watermark_pct: number; critical_watermark_pct: number; level: 'ok' | 'high' | 'critical' | 'over'; auto_vacuum: 'incremental' | 'none' };
  datasets: { name: string; bytes: number; file_bytes?: number; quota_bytes?: number; over_quota: boolean; policy: { code: string; params?: Record<string, number> }; last_run?: { outcome: { deleted: number }; error?: string; duration_ms: number } }[];
  measured_at?: string;
  last_run?: { trigger: string; started_at: string; finished_at: string; deleted: number; reclaimed_bytes: number; reclaim_note?: string; errors: number; shed?: { name: string }[] };
  next_run?: string;
  running: boolean;
  job_id?: string;
  interval_seconds: number;
  rollups?: { tier: 'hour' | 'day' | 'month'; rows: number; oldest?: string }[];
  audit_archive?: { enabled: boolean; dir: string; segments: number; entries: number };
}
export interface WireJob<T> {
  job_id: string;
  kind: string;
  status: string;
  result?: T;
  error?: string;
  /** Details of the error answer of a failed long request (which rules, which services). */
  details?: ApiErrorDetail[];
}

// ---------------------------------------------------------------- packs

export interface WireGateCheck {
  id: string;
  status: string;
  findings: { file: string; pointer: string; reason: string }[];
  strings_checked?: number;
  by: string;
}
export interface WireGateReport {
  format: string;
  pack_id: string;
  verdict: string;
  k_min: number;
  checks: WireGateCheck[];
}
export interface WireManifest {
  format: string;
  pack_id: string;
  created_at: string;
  not_after?: string;
  tt_version: string;
  seed: number;
  k_min: number;
  source?: { window: { from: string; to: string }; policies: { id: string; version: number }[] };
  services?: { name: string; contract: string; upstream_alias?: string }[];
  rules?: { path: string; approved: string[] };
  world?: { path: string; customers: number };
  files?: { path: string; sha256: string; bytes: number }[];
}
export interface WireResidualRisk {
  note: string;
  profiles: number;
  archetypes: number;
  min_archetype_size: number;
  suppressed_subjects: number;
  uniqueness_rate: number;
  singling_out_rate: number;
  exact_match_share: number;
  max_homogeneity: number;
}
export interface WirePack {
  pack_id: string;
  group?: string;
  groups?: string[] | null;
  /** Services in the pack (also in the manifest). */
  services?: string[] | null;
  status: string;
  created_at: WireTime;
  world_id?: string;
  manifest?: WireManifest;
  gate_report?: WireGateReport;
  published_at: WireTime | null;
  residual_risk?: WireResidualRisk;
  approval_mode?: string;
}

// ---------------------------------------------------------------- audit

export interface WireAuditEntry {
  seq: number;
  ts: WireTime;
  actor: { kind: string; id: string; name: string };
  action: string;
  target: { type: string; id: string };
  outcome: string;
  reason?: string;
  request_id?: string;
  details?: Record<string, string>;
  prev_hash: string;
  hash: string;
}
export interface WireAuditVerify {
  ok: boolean;
  entries: number;
  head_seq: number;
  head_hash: string;
  error?: string;
}

// ---------------------------------------------------------------- spec-only endpoints (not served by tt-core yet)

export interface WireSettings {
  general: { installation_name: string; environment: '' | 'production' | 'staging' | 'development' };
  privacy: {
    events_retention_days: number;
    aggregates_days: number;
    k_min: { contract: number; miner: number; world: number; gate: number };
    min_samples: number;
  };
  access: {
    local_enabled: boolean;
    oidc: { enabled: boolean; issuer_url: string; client_id: string; scopes: string[]; roles_claim: string };
    session: { idle_timeout_s: number; absolute_timeout_s: number };
  };
}
export interface WireVersion {
  version?: string;
  commit?: string;
  spec?: string;
  installation_name?: string;
  environment?: string;
}

export interface WireUser {
  id: string;
  username: string;
  display_name: string;
  auth_method: string;
  roles: string[];
  disabled?: boolean;
}
export interface WirePreset {
  preset_id: string;
  name: string;
  description?: string;
  customer?: string;
  archetype?: string;
  seed?: number;
  faults?: { mode?: string; rules?: { service: string; op: string; status?: number; p?: number; times?: number; net_error?: string }[] };
  outcomes?: { rule: string; outcome: string; times?: number }[];
}

// ---------------------------------------------------------------- hosts (GET /api/v1/hosts, spec v1.5)

export interface WireHostPattern {
  pattern: string;
  group?: string;
  service: string;
  declared: boolean;
  declared_by?: string[];
  exact: boolean;
  quarantined: boolean;
  calls: number;
  server_errors: number;
  client_errors: number;
  error_rate: number;
  latency_p50_ms: number | null;
  first_seen: WireTime | null;
  last_seen: WireTime | null;
  callers?: { service: string; calls: number }[];
  policies?: string[];
  now_declared_as?: string;
  /** admin-api 1.17.0: the older host:<pattern> rows of the same group folded into this declared entry. */
  folded_from?: string[];
}
export interface WireHostsRegistry {
  domains?: { domain: string; calls: number; first_seen: WireTime | null; last_seen: WireTime | null; patterns?: WireHostPattern[] }[];
  unlisted?: WireHostPattern;
  invalid?: WireHostPattern;
  discovery?: Record<string, string>;
  /**
   * admin-api 1.17.0, over the entries listed: `domains` and `hosts` include the IP classes (`ip:private` is a domain row,
   * its entries are hosts), `ip_hosts` the entries of an IP class, `undeclared` those not declared nor replaced.
   */
  counts?: { domains?: number; hosts?: number; ip_hosts?: number; declared?: number; undeclared?: number; folded?: number };
}

// ---------------------------------------------------------------- installed-console helpers (core/scope.go, contract status)

export interface WireScope {
  groups: string[];
  mine: string[];
  services: Record<string, string[]>;
}
export interface WireGateKeys {
  tt_gate_pubkeys: string;
  command: string;
  file_name?: string;
  keys: { kid: string; public_key: string }[];
}
export interface WireKeyCheck {
  reachable: boolean;
  keyguard_kids: string[];
  sources: { source_id: string; unknown_kids: string[] }[];
}
export interface WireContractStatus {
  service: string;
  calls: number;
  operations: number;
  ready_operations: number;
  best_op_calls: number;
  min_calls: number;
  k_min: number;
  inferred_operations: number;
  snapshot: { snapshot_id: string; created_at: WireTime; ops: number } | null;
  next_snapshot_at: WireTime;
  window_hours: number;
}

// ---------------------------------------------------------------- rule editor

export interface WireCatalog {
  services: { name: string; ops: { op: string; statuses: number[]; examples?: Record<string, string[]>; params?: WireCatalogField[]; request?: WireCatalogField[]; response?: WireCatalogField[] }[] }[];
  entities: { name: string; service: string; id_field: string; id_domain: string; ops: string[]; fields: WireCatalogField[] }[];
}
export interface WireCatalogField {
  from: string;
  name?: string;
  path?: string;
  type?: string;
  kind?: string;
  domain?: string;
  values?: string[];
}
export interface WireRuleCheck {
  valid: boolean;
  problems: { path: string; code: string; message: string }[];
  warnings: { path: string; code: string; message: string }[];
}
