// The agent: Fleet lifecycle (policy.md 4, fleet-api), capture gate, asynchronous
// sanitization and export. Fail-closed everywhere: any doubt means "do not capture".

import https from 'node:https';
import { hostname } from 'node:os';
import { readFileSync } from 'node:fs';
import { verify as cryptoVerify, type KeyObject } from 'node:crypto';
import type { CaptureHost, RawExchange } from './capture/common.js';
import { loadOtelApi } from './capture/context.js';
import { installInbound } from './capture/inbound.js';
import { installOutboundHttp } from './capture/outbound-http.js';
import { installOutboundUndici } from './capture/outbound-undici.js';
import { sanitizeToRecord, type JobMeta } from './export/pipeline.js';
import { SanitizerPool } from './worker/pool.js';
import type { Job } from './worker/protocol.js';
import { availableParallelism } from 'node:os';
import { Exporter } from './export/exporter.js';
import { enroll, FleetClient, FleetError, mtlsAgent, type Enrollment, type SigningKey } from './fleet/client.js';
import { StateStore, defaultStateDir } from './fleet/store.js';
import { debug, setDebug, warn } from './log.js';
import { nodeToPlain, parseJson, type Plain } from './sanitizer/json.js';
import {
  Policy, Refused, UNSAFE_DETAIL, b64urlDecodeStrict, checkAcceptance, ed25519PublicKey, parseKeyRing, selectKey, verifyEnvelope, type KeyRing,
} from './sanitizer/policy.js';
import { Sanitizer, normalizeUrlBase } from './sanitizer/sanitizer.js';
import { asciiLower } from './sanitizer/utf8.js';
import { SDK_VERSION, SOURCE_KIND } from './version.js';

export type SourceState =
  | 'starting' | 'capturing' | 'no_policy' | 'policy_rejected' | 'expired_policy' | 'key_missing' | 'key_mismatch' | 'killed';

export interface AgentOptions {
  /** Fleet base URL used for enrollment (TT_ENROLL_URL). */
  enrollUrl?: string;
  /** Enrollment token `tte_<secret>.<pin>` (TT_ENROLL_TOKEN). */
  enrollToken?: string;
  /** Content of the HMAC key (TT_HMAC_KEY). */
  hmacKey?: string;
  /** File holding the HMAC key (TT_HMAC_KEY_FILE). */
  hmacKeyFile?: string;
  /** Service name requested at enrollment (TT_SERVICE_NAME, else OTEL_SERVICE_NAME). */
  serviceName?: string;
  /** Where certificates, keys and the policy cache are kept (TT_STATE_DIR). */
  stateDir?: string;
  /** Informational instance name (TT_INSTANCE, default hostname). */
  instance?: string;
  /** Send a CSR at enrollment so the private key never leaves the process (default true). */
  useCsr?: boolean;
  debug?: boolean;
  /** Overrides for tests and benchmarks. */
  heartbeatIntervalMs?: number;
  policyPollIntervalMs?: number;
  exportFlushMs?: number;
  /** Sanitizer worker threads: 0 = always inline, default min(2, cores - 1) (TT_SANITIZER_THREADS). */
  sanitizerThreads?: number;
  /** Sampling rate (basis points) from which sanitization moves to the workers (default 200 = 2%). */
  workerMinBp?: number;
}

interface PersistedState {
  kill?: boolean;
  revoked?: boolean;
  min_issued_seq?: number;
  last_issued_seq?: number;
  revoked_kids?: string[];
  added_keys?: SigningKey[];
}

const PENDING_MAX = 2000;
const PENDING_MAX_BYTES = 64 << 20;
const DRAIN_BUDGET_MS = 2;
const WORKER_BATCH = 256;
const WORKER_BATCH_MS = 8;
const WORKER_MIN_BP = 200;
const RAW_PATH_SVC = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export function serviceNameFromEnv(env: NodeJS.ProcessEnv): string | undefined {
  const raw = env.TT_SERVICE_NAME || env.OTEL_SERVICE_NAME;
  if (!raw) return undefined;
  const s = asciiLower(raw).replace(/[^a-z0-9._-]/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 63);
  return RAW_PATH_SVC.test(s) ? s : undefined;
}

export function optionsFromEnv(env: NodeJS.ProcessEnv = process.env): AgentOptions {
  return {
    enrollUrl: env.TT_ENROLL_URL,
    enrollToken: env.TT_ENROLL_TOKEN,
    hmacKey: env.TT_HMAC_KEY,
    hmacKeyFile: env.TT_HMAC_KEY_FILE,
    serviceName: serviceNameFromEnv(env),
    stateDir: env.TT_STATE_DIR,
    instance: env.TT_INSTANCE,
    useCsr: env.TT_ENROLL_CSR !== '0',
    debug: /^(1|true|yes|debug)$/i.test(env.TT_DEBUG ?? ''),
    heartbeatIntervalMs: msEnv(env.TT_HEARTBEAT_INTERVAL_MS),
    policyPollIntervalMs: msEnv(env.TT_POLICY_POLL_INTERVAL_MS),
    exportFlushMs: msEnv(env.TT_EXPORT_FLUSH_MS),
    sanitizerThreads: /^[0-9]{1,2}$/.test(env.TT_SANITIZER_THREADS ?? '') ? Number(env.TT_SANITIZER_THREADS) : undefined,
  };
}

function msEnv(v: string | undefined): number | undefined {
  if (!v || !/^[0-9]{1,9}$/.test(v)) return undefined;
  return Math.max(100, Number(v));
}

export class Agent implements CaptureHost {
  readonly counters = {
    exchanges_seen: 0,
    exchanges_sampled: 0,
    events_sent: 0,
    events_dropped_queue: 0,
    events_rejected: 0,
    send_errors: 0,
    sanitizer_errors: 0,
  };
  state: SourceState = 'starting';

  private san: Sanitizer | null = null;
  private policy: Policy | null = null;
  private policyKid = '';
  private rejected: SourceState | null = null;
  private ring: KeyRing | null = null;
  private keyState: 'key_missing' | 'key_mismatch' | null = null;
  private heartbeatOk = false;
  private lastContact = 0;
  private persisted: PersistedState = {};
  private overrideBp: number | null = null;
  private decisionNames: Set<string> = new Set(['cookie', 'baggage']);
  private readonly overhead = new Float64Array(1024);
  private overheadN = 0;
  private lastErrors: Array<{ code: string; at: string }> = [];
  private pending: RawExchange[] = [];
  private pendingBytes = 0;
  private drainScheduled = false;
  private pool: SanitizerPool | null = null;
  /** The last drain handed its work to the workers: the next one is batched on a timer. */
  private workerMode = false;
  private inflight = 0;
  private inflightBytes = 0;
  private uninstall: Array<() => void> = [];
  private timers: NodeJS.Timeout[] = [];
  private stopped = false;

  private store: StateStore | null = null;
  private enrollment: Enrollment | null = null;
  private keyPem = '';
  private httpsAgent: https.Agent | null = null;
  private fleet: FleetClient | null = null;
  private exporter: Exporter | null = null;
  private etag: string | undefined;
  // A heartbeat said a newer policy is current (a normal policy change): capture pauses until it
  // is fetched, and only a failed fetch is an error (policy.md 4).
  private switching = false;
  // Hashes of the last policies accepted: a response that brings one of them again (a poll that
  // started before the change) is stale, not a replay.
  private acceptedHashes: string[] = [];
  private polling: Promise<void> | null = null;
  private pollAgain = false;

  constructor(readonly opts: AgentOptions) {
    if (opts.debug) setDebug(true);
  }

  // --- CaptureHost (hot path) --------------------------------------------------------

  active(): Sanitizer | null {
    return this.san;
  }
  serviceName(): string {
    return this.enrollment?.service_name ?? '';
  }
  decisionHeaders(): ReadonlySet<string> {
    return this.decisionNames;
  }
  propagates(): boolean {
    const p = this.policy;
    return p !== null && p.propagateTo.size > 0;
  }
  mayPropagate(urlBase: string): boolean {
    const p = this.policy;
    if (!p || p.propagateTo.size === 0) return false;
    if (this.propMemoFor !== p) {
      this.propMemoFor = p;
      this.propMemo.clear();
    }
    let r = this.propMemo.get(urlBase);
    if (r === undefined) {
      r = this.mayPropagateUncached(p, urlBase);
      if (this.propMemo.size >= 1024) this.propMemo.clear();
      this.propMemo.set(urlBase, r);
    }
    return r;
  }
  private propMemoFor: Policy | null = null;
  private readonly propMemo = new Map<string, boolean>();
  private mayPropagateUncached(p: Policy, urlBase: string): boolean {
    const u = normalizeUrlBase(urlBase);
    // propagate_to and bases hold names, never IPv6 literals (v1.5).
    if (u.invalid || u.ip6) return false;
    const host = u.hostport.replace(/:[0-9]+$/, '');
    // D-M8: never toward a host that matches a policy base (external service).
    if (p.baseHosts.has(u.hostport) || p.baseHosts.has(host)) return false;
    return p.propagateTo.has(u.hostport) || p.propagateTo.has(host);
  }
  noteSeen(): void {
    this.counters.exchanges_seen++;
  }
  noteSampled(): void {
    this.counters.exchanges_sampled++;
  }
  noteOverhead(ns: number): void {
    this.overhead[this.overheadN++ % this.overhead.length] = ns;
  }
  noteError(code: string): void {
    this.lastErrors.push({ code: code.slice(0, 64), at: new Date().toISOString() });
    if (this.lastErrors.length > 20) this.lastErrors.shift();
    debug('error', code);
  }
  submit(raw: RawExchange): void {
    if (this.san === null || this.pending.length + this.inflight >= PENDING_MAX || this.pendingBytes + this.inflightBytes + raw.heldBytes > PENDING_MAX_BYTES) {
      this.counters.events_dropped_queue++;
      return;
    }
    this.pending.push(raw);
    this.pendingBytes += raw.heldBytes;
    if (!this.drainScheduled) {
      this.drainScheduled = true;
      this.scheduleDrain();
    }
  }

  // --- asynchronous sanitization ------------------------------------------------------

  private threads(): number {
    const t = this.opts.sanitizerThreads;
    if (typeof t === 'number') return t;
    return Math.min(2, Math.max(1, availableParallelism() - 1));
  }

  /** Worker threads pay off only when many exchanges are sampled (high rate). */
  private wantWorkers(): boolean {
    const san = this.san;
    if (!san || this.threads() <= 0) return false;
    if (san.rateBp() < (this.opts.workerMinBp ?? WORKER_MIN_BP)) return false;
    if (!this.pool) {
      this.pool = new SanitizerPool({
        size: this.threads(),
        onOut: (b) => this.onWorkerOut(b),
        onLost: (b) => {
          this.inflight -= b.n;
          this.inflightBytes -= b.bytes;
          this.counters.events_dropped_queue += b.n;
          this.noteError('sanitizer_worker_lost');
        },
      });
    }
    this.pool.warm();
    return this.pool.usable;
  }

  private onWorkerOut(b: { n: number; bytes: number; recs: string[]; errs: string[]; stale: boolean }): void {
    this.inflight -= b.n;
    this.inflightBytes -= b.bytes;
    if (b.stale) {
      this.counters.events_dropped_queue += b.n;
      return;
    }
    const ex = this.exporter;
    if (ex) for (const record of b.recs) ex.enqueue({ json: '', record, size: record.length, tsMs: 0, policyHash: '' });
    for (const code of b.errs) {
      this.counters.sanitizer_errors++;
      this.noteError(code);
    }
  }

  /**
   * Inline sanitization runs right after the response (setImmediate). With worker threads
   * the exchanges are collected for a few milliseconds and posted as one batch: one message
   * and one thread wake-up for many exchanges instead of one each.
   */
  private scheduleDrain(): void {
    if (this.workerMode) {
      const t = setTimeout(() => this.drain(), WORKER_BATCH_MS);
      t.unref();
    } else {
      setImmediate(() => this.drain());
    }
  }

  private drain(): void {
    this.drainScheduled = false;
    this.workerMode = false;
    if (this.pending.length > 0 && this.wantWorkers() && this.drainToWorkers()) {
      this.workerMode = true;
      if (this.pending.length > 0 && !this.drainScheduled) {
        this.drainScheduled = true;
        this.scheduleDrain();
      }
      return;
    }
    const t0 = performance.now();
    while (this.pending.length > 0) {
      const raw = this.pending.shift()!;
      this.pendingBytes -= raw.heldBytes;
      this.process(raw);
      if (performance.now() - t0 > DRAIN_BUDGET_MS) break;
    }
    if (this.pending.length > 0 && !this.drainScheduled) {
      this.drainScheduled = true;
      this.scheduleDrain();
    }
  }

  /** Posts up to WORKER_BATCH pending exchanges to a worker. False when none could be posted. */
  private drainToWorkers(): boolean {
    const pool = this.pool!;
    const enr = this.enrollment;
    if (!enr || !this.exporter) return false;
    const items: Array<{ san: Sanitizer; job: Job }> = [];
    const taken: RawExchange[] = [];
    let bytes = 0;
    while (this.pending.length > 0 && taken.length < WORKER_BATCH) {
      const raw = this.pending[0]!;
      if (!pool.canHandle(raw.sanitizer)) {
        // An exchange captured under a policy the workers cannot rebuild: sanitize it here.
        if (taken.length > 0) break;
        return false;
      }
      this.pending.shift();
      this.pendingBytes -= raw.heldBytes;
      bytes += raw.heldBytes;
      taken.push(raw);
      items.push({ san: raw.sanitizer, job: { gen: 0, decision: raw.decision, meta: metaOf(raw), wire: raw.wire } });
    }
    if (items.length === 0) return false;
    if (pool.post(items, bytes, enr.source_id)) {
      this.inflight += items.length;
      this.inflightBytes += bytes;
      return true;
    }
    // No worker could take them: put them back (in order) and sanitize inline.
    this.pending.unshift(...taken);
    this.pendingBytes += bytes;
    return false;
  }

  private process(raw: RawExchange): void {
    if (!this.exporter || !this.enrollment || this.san === null) return;
    const r = sanitizeToRecord(raw.sanitizer, raw.wire, raw.decision, metaOf(raw), this.enrollment.source_id, Date.now());
    if (r === null) return;
    if ('err' in r) {
      this.counters.sanitizer_errors++;
      this.noteError(r.err);
      return;
    }
    this.exporter.enqueue({ json: '', record: r.record, size: r.record.length, tsMs: raw.tsMs, policyHash: raw.sanitizer.policy.hash });
  }

  // --- lifecycle --------------------------------------------------------------------

  /** Installs the hooks and runs the first Fleet cycle. Never throws. */
  async start(): Promise<void> {
    try {
      loadOtelApi();
      this.uninstall.push(installInbound(this), installOutboundHttp(this), installOutboundUndici(this));
      const o = this.opts;
      const svc = o.serviceName;
      if (!o.enrollUrl || !svc) {
        this.noteError('not_configured');
        return;
      }
      this.store = new StateStore(o.stateDir ?? defaultStateDir(o.enrollUrl, svc));
      this.store.onUntrusted = () => this.noteError('state_untrusted');
      this.persisted = this.store.readJson<PersistedState>('state.json') ?? {};
      this.loadKeys();
      const saved = this.store.readJson<Enrollment>('enrollment.json');
      const savedKey = this.store.readText('client.key');
      if (saved && savedKey && saved.enroll_url === o.enrollUrl) {
        this.enrollment = saved;
        this.keyPem = savedKey;
      } else {
        await this.enrollWithRetry();
        if (!this.enrollment) return;
      }
      this.connect();
      // Re-verify the cached policy (its issued_seq may equal the last accepted one).
      const cached = this.store.readText('policy.envelope.json');
      if (cached !== null) {
        try {
          this.tryAccept(nodeToPlain(parseJson(Buffer.from(cached, 'utf8')), true), true, cached);
        } catch {
          this.noteError('policy_cache_invalid');
        }
      }
      await this.heartbeat();
      await this.pollPolicy();
      this.schedule();
    } catch (e) {
      this.noteError(e instanceof FleetError ? e.code : 'start_failed');
    }
    this.recompute();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
    for (const u of this.uninstall) u();
    this.uninstall = [];
    this.san = null;
    this.pool?.terminate();
    this.exporter?.stop();
    this.httpsAgent?.destroy();
  }

  /** Sanitizes what is pending and sends everything queued (tests, graceful shutdown). */
  async flush(): Promise<void> {
    while (this.pending.length > 0) {
      const raw = this.pending.shift()!;
      this.pendingBytes -= raw.heldBytes;
      this.process(raw);
    }
    await this.pool?.sync();
    await this.exporter?.flush();
  }

  status(): { state: SourceState; counters: Agent['counters']; queue: { events: number; bytes: number } } {
    return { state: this.state, counters: { ...this.counters }, queue: this.exporter?.size ?? { events: 0, bytes: 0 } };
  }

  private async enrollWithRetry(): Promise<void> {
    const o = this.opts;
    if (!o.enrollToken) {
      this.noteError('enroll_token_missing');
      return;
    }
    let delay = 2000;
    for (let attempt = 0; attempt < 8 && !this.stopped; attempt++) {
      try {
        const { enrollment, keyPem } = await enroll({
          enrollUrl: o.enrollUrl!,
          token: o.enrollToken,
          useCsr: o.useCsr !== false,
          source: {
            kind: SOURCE_KIND,
            version: SDK_VERSION,
            service_name: o.serviceName!,
            instance: (o.instance ?? hostname()).slice(0, 128),
            runtime: { lang: 'node', lang_version: process.versions.node, os: process.platform, arch: process.arch },
            hmac_kids: this.ring ? this.ring.order.slice(0, 8) : undefined,
          },
        });
        this.enrollment = enrollment;
        this.keyPem = keyPem;
        this.store!.writeText('client.key', keyPem);
        this.store!.writeJson('enrollment.json', enrollment);
        return;
      } catch (e) {
        const code = e instanceof FleetError ? e.code : 'enroll_failed';
        this.noteError(code);
        // Token or identity errors will not fix themselves.
        if (e instanceof FleetError && e.status !== undefined && e.status < 500) return;
        if (/pin|root|token|chain|bad_/.test(code)) return;
      }
      await new Promise<void>((r) => {
        const t = setTimeout(r, delay);
        t.unref();
      });
      delay = Math.min(delay * 2, 300_000);
    }
  }

  private connect(): void {
    const e = this.enrollment!;
    this.httpsAgent?.destroy();
    this.httpsAgent = mtlsAgent(e, this.keyPem);
    if (this.fleet) this.fleet.setAgent(this.httpsAgent);
    else this.fleet = new FleetClient(e, this.httpsAgent);
    if (this.exporter) this.exporter.setTarget(e.intake_url, this.httpsAgent);
    else {
      this.exporter = new Exporter({
        url: e.intake_url,
        agent: this.httpsAgent,
        resource: { serviceName: e.service_name, sourceId: e.source_id },
        counters: this.counters,
        onError: (c) => this.noteError(c),
        flushMs: this.opts.exportFlushMs,
      });
    }
  }

  private schedule(): void {
    const e = this.enrollment!;
    const hb = this.opts.heartbeatIntervalMs ?? Math.max(5, e.heartbeat_interval_s) * 1000;
    const pp = this.opts.policyPollIntervalMs ?? Math.max(5, e.policy_poll_interval_s) * 1000;
    const loop = (ms: number, fn: () => Promise<void>) => {
      const tick = () => {
        if (this.stopped) return;
        void fn().finally(() => {
          if (this.stopped) return;
          const t = setTimeout(tick, ms);
          t.unref();
          this.timers.push(t);
          if (this.timers.length > 16) this.timers = this.timers.slice(-4);
        });
      };
      const t = setTimeout(tick, ms);
      t.unref();
      this.timers.push(t);
    };
    loop(hb, () => this.heartbeat());
    loop(pp, () => this.pollPolicy());
  }

  // --- keys -------------------------------------------------------------------------

  private loadKeys(): void {
    let text: string | undefined = this.opts.hmacKey;
    let why = 'not_set';
    if (text === undefined && this.opts.hmacKeyFile) {
      try {
        text = readFileSync(this.opts.hmacKeyFile, 'utf8');
      } catch {
        text = undefined;
        why = 'unreadable';
      }
    }
    try {
      this.ring = parseKeyRing(text);
      this.keyWarned = '';
    } catch {
      this.ring = null;
      if (text !== undefined) why = 'malformed';
      this.warnKeyMissing(why);
    }
  }

  /** Said once per cause, whatever TT_DEBUG: without the key nothing is captured. Never prints key material or paths. */
  private keyWarned = '';
  private warnKeyMissing(why: string): void {
    if (this.keyWarned === why) return;
    this.keyWarned = why;
    const cause =
      why === 'unreadable'
        ? 'the file in TT_HMAC_KEY_FILE cannot be read'
        : why === 'malformed'
          ? 'the HMAC key is malformed (want one line <kid>:<base64url of 32+ bytes>, e.g. k1:...)'
          : 'neither TT_HMAC_KEY_FILE nor TT_HMAC_KEY is set';
    warn(
      'key_missing: ' + cause + '. The SDK does not capture anything until the key is there (the application is not affected). ' +
        'The key file is installation-wide and comes from your platform team: same kid as the policy (hmac.kid, e.g. k1) and the same key keyguard holds. ' +
        'Console: Help > "Chiavi HMAC".',
    );
  }

  private signingKeys(): Map<string, KeyObject> {
    const revoked = new Set(this.persisted.revoked_kids ?? []);
    const m = new Map<string, KeyObject>();
    for (const k of [...(this.enrollment?.policy_signing_keys ?? []), ...(this.persisted.added_keys ?? [])]) {
      if (revoked.has(k.kid) || m.has(k.kid)) continue;
      const pk = ed25519PublicKey(k.public_key);
      if (pk) m.set(k.kid, pk);
    }
    return m;
  }

  private persist(): void {
    try {
      this.store?.writeJson('state.json', this.persisted);
    } catch {
      this.noteError('state_write_failed');
    }
  }

  // --- policy (policy.md 4) -----------------------------------------------------------

  private tryAccept(envelope: Plain, fromCache: boolean, rawText: string): void {
    try {
      const v = verifyEnvelope(envelope, this.signingKeys(), true);
      const p = new Policy(v.body);
      p.hash = v.hash;
      p.bodyBytes = v.bodyBytes;
      if (this.policy && this.policy.hash === p.hash && !fromCache) return;
      if (!fromCache && this.acceptedHashes.includes(p.hash) && p.issuedSeq <= (this.persisted.last_issued_seq ?? 0)) {
        // An answer that started before a newer policy was accepted (two polls crossing).
        debug('info', 'policy_stale_response: issued_seq ' + p.issuedSeq + ' already superseded, kept the newer policy');
        return;
      }
      checkAcceptance(p, {
        group: this.enrollment!.group,
        now: Date.now(),
        lastIssuedSeq: this.persisted.last_issued_seq ?? 0,
        minIssuedSeq: this.persisted.min_issued_seq ?? 0,
        allowEqualSeq: fromCache,
      });
      if (this.switching) debug('info', 'policy_changed: now issued_seq ' + p.issuedSeq);
      this.policy = p;
      this.policyKid = String((envelope as { signature?: { kid?: unknown } }).signature?.kid ?? '');
      this.rejected = null;
      this.switching = false;
      this.acceptedHashes = [...this.acceptedHashes.filter((h) => h !== p.hash), p.hash].slice(-4);
      this.persisted.last_issued_seq = p.issuedSeq;
      this.persist();
      // The cache holds the signed envelope exactly as received; it is re-verified at start.
      if (!fromCache) this.store?.writeText('policy.envelope.json', rawText);
      const names = new Set(['cookie', 'baggage']);
      if (p.subject?.from === 'header') names.add(asciiLower(p.subject.name));
      this.decisionNames = names;
    } catch (e) {
      const code = e instanceof Refused ? e.code : 'policy_rejected';
      // hardening.md 2.2: a policy refused for the safety subset is reported as policy_unsafe.
      this.noteError(e instanceof Refused && e.detail.startsWith(UNSAFE_DETAIL) ? 'policy_unsafe' : code);
      // Keep the previous policy if it is still valid; otherwise report the rejection.
      if (!this.policy) this.rejected = code === 'expired_policy' ? 'expired_policy' : 'policy_rejected';
    }
    this.recompute();
  }

  // One poll at a time: a heartbeat that sees a new policy and the periodic poll would otherwise
  // race, and the older answer could arrive last.
  private pollPolicy(): Promise<void> {
    if (this.polling) {
      this.pollAgain = true;
      return this.polling;
    }
    this.polling = (async () => {
      try {
        do {
          this.pollAgain = false;
          await this.pollOnce();
        } while (this.pollAgain && !this.stopped);
      } finally {
        this.polling = null;
      }
    })();
    return this.polling;
  }

  private async pollOnce(): Promise<void> {
    if (!this.fleet || this.stopped) return;
    try {
      const r = await this.fleet.getPolicy(this.policy ? this.etag : undefined);
      if (r.status === 304) {
        this.lastContact = Date.now();
      } else if (r.status === 200 && r.body) {
        this.lastContact = Date.now();
        let env: Plain;
        try {
          env = nodeToPlain(parseJson(r.body), true);
        } catch {
          this.noteError('policy_json');
          if (!this.policy) this.rejected = 'policy_rejected';
          this.recompute();
          return;
        }
        this.tryAccept(env, false, r.body.toString('utf8'));
        if (this.policy && r.etag) this.etag = r.etag;
      } else if (r.status === 404) {
        this.lastContact = Date.now();
        this.policy = null;
        this.rejected = 'no_policy';
      } else if (r.status === 403) {
        this.revoke();
      } else {
        this.noteError('policy_http_' + r.status);
      }
    } catch {
      this.noteError('policy_network');
    }
    if (this.switching && !this.policy) {
      // The newer policy announced by the heartbeat could not be fetched or accepted.
      this.switching = false;
      if (this.rejected === 'starting') {
        this.rejected = 'policy_rejected';
        this.noteError('policy_below_min_issued_seq');
      }
    }
    this.recompute();
  }

  // --- heartbeat --------------------------------------------------------------------

  private overheadUs(): { p50: number; p99: number } {
    const n = Math.min(this.overheadN, this.overhead.length);
    if (n === 0) return { p50: 0, p99: 0 };
    const a = Array.from(this.overhead.subarray(0, n)).sort((x, y) => x - y);
    const q = (f: number) => Math.round(a[Math.min(n - 1, Math.floor(f * n))]! / 1000);
    return { p50: q(0.5), p99: q(0.99) };
  }

  private async heartbeat(): Promise<void> {
    if (!this.fleet || this.stopped) return;
    this.loadKeys();
    this.recompute();
    const p = this.policy;
    const body = {
      source_id: this.enrollment!.source_id,
      state: this.state,
      ...(p ? { policy: { id: p.policyId, version: p.version, issued_seq: p.issuedSeq, hash: p.hash } } : {}),
      counters: { ...this.counters },
      overhead_us: this.overheadUs(),
      queue: this.exporter?.size ?? { events: 0, bytes: 0 },
      last_errors: this.lastErrors.slice(-20),
      runtime: { lang: 'node', lang_version: process.versions.node },
      // The policy signing kids trusted now: tt-core waits for a rotation to reach the source
      // before it lets the old key be revoked.
      signing_kids: [...this.signingKeys().keys()].sort(),
    };
    try {
      const r = await this.fleet.heartbeat(body);
      if (r.status === 403) {
        this.revoke();
      } else if (r.status === 200 && r.json) {
        this.applyHeartbeat(r.json);
      } else {
        this.noteError('heartbeat_http_' + r.status);
      }
    } catch {
      this.noteError('heartbeat_network');
    }
    this.recompute();
  }

  private applyHeartbeat(j: Record<string, unknown>): void {
    this.heartbeatOk = true;
    this.lastContact = Date.now();
    const kill = j.kill === true;
    if (kill !== (this.persisted.kill === true)) {
      this.persisted.kill = kill;
      this.persist();
    }
    if (kill) this.dropQueues();
    if (typeof j.min_issued_seq === 'number' && Number.isInteger(j.min_issued_seq) && j.min_issued_seq >= 0) {
      if (j.min_issued_seq !== this.persisted.min_issued_seq) {
        this.persisted.min_issued_seq = j.min_issued_seq;
        this.persist();
      }
      if (this.policy && this.policy.issuedSeq < j.min_issued_seq) {
        const cur = j.policy_current as { hash?: unknown; issued_seq?: unknown } | null | undefined;
        const newer =
          !!cur && typeof cur.hash === 'string' && cur.hash !== this.policy.hash &&
          typeof cur.issued_seq === 'number' && cur.issued_seq >= j.min_issued_seq;
        // The policy in use is superseded for good: capture stops at once (fail-closed).
        this.policy = null;
        if (newer) {
          // A normal policy change: the newer policy is fetched right away (policy_current below).
          this.switching = true;
          this.rejected = 'starting';
          debug('info', 'policy_superseded: fetching issued_seq ' + String(cur!.issued_seq));
        } else {
          this.rejected = 'policy_rejected';
          this.noteError('policy_below_min_issued_seq');
        }
      }
    }
    const o = j.sampling_override_bp;
    this.overrideBp = typeof o === 'number' && o >= 0 && o <= 10000 ? o : null;
    // Revocations first: they only remove trust, and a key endorsed by a kid revoked in this
    // very response must not be pinned (RT3-KEY-3).
    if (Array.isArray(j.revoke_signing_keys)) {
      const rk = new Set(this.persisted.revoked_kids ?? []);
      const before = rk.size;
      for (const k of j.revoke_signing_keys) if (typeof k === 'string') rk.add(k);
      if (rk.size !== before) {
        this.persisted.revoked_kids = [...rk].sort();
        this.persist();
      }
      if (this.policy && rk.has(this.policyKid)) {
        this.policy = null;
        this.rejected = 'policy_rejected';
        this.noteError('policy_key_revoked');
      }
    }
    if (Array.isArray(j.add_signing_keys)) this.addSigningKeys(j.add_signing_keys);
    const cur = j.policy_current as { hash?: unknown } | null | undefined;
    if (cur && typeof cur.hash === 'string' && cur.hash !== this.policy?.hash) setImmediate(() => void this.pollPolicy());
    if (typeof j.renew_before === 'string' && Date.now() >= Date.parse(j.renew_before)) setImmediate(() => void this.renew());
  }

  // tt-core sends every endorsed key at every heartbeat, an endorser before the keys it
  // endorses: the list is processed in order, so a key pinned earlier in it can endorse a later
  // one. A revoked kid is never pinned again; a kid already pinned with the same key is skipped
  // silently, one pinned with another key is refused.
  private addSigningKeys(list: unknown[]): void {
    const revoked = new Set(this.persisted.revoked_kids ?? []);
    const known = this.signingKeys();
    const pinned = new Map<string, Buffer>();
    for (const k of [...(this.enrollment?.policy_signing_keys ?? []), ...(this.persisted.added_keys ?? [])]) {
      if (revoked.has(k.kid) || pinned.has(k.kid)) continue;
      const raw = b64urlDecodeStrict(k.public_key);
      if (raw) pinned.set(k.kid, raw);
    }
    const added = [...(this.persisted.added_keys ?? [])];
    let changed = false;
    for (const item of list) {
      const k = (item && typeof item === 'object' ? item : {}) as { kid?: unknown; alg?: unknown; public_key?: unknown; endorsed_by?: unknown; endorsement?: unknown };
      // Canonical codes (docs/spec/policy.md §3.1): malformed -> rejected; a kid pinned to
      // other bytes -> conflict; unknown/revoked endorser -> endorser_unknown; bad signature -> endorsement_invalid.
      if (typeof k.kid !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(k.kid)) {
        this.noteError('signing_key_rejected');
        continue;
      }
      if (revoked.has(k.kid)) continue;
      if (k.alg !== 'Ed25519' || typeof k.public_key !== 'string' || typeof k.endorsed_by !== 'string' || typeof k.endorsement !== 'string') {
        this.noteError('signing_key_rejected');
        continue;
      }
      const raw = b64urlDecodeStrict(k.public_key);
      const sig = b64urlDecodeStrict(k.endorsement);
      const pk = raw && raw.length === 32 ? ed25519PublicKey(k.public_key) : undefined;
      if (!raw || raw.length !== 32 || !sig || sig.length !== 64 || !pk) {
        this.noteError('signing_key_rejected');
        continue;
      }
      const have = pinned.get(k.kid);
      if (have) {
        if (!have.equals(raw)) this.noteError('signing_key_conflict');
        continue;
      }
      const endorser = revoked.has(k.endorsed_by) ? undefined : known.get(k.endorsed_by);
      if (!endorser) {
        this.noteError('signing_key_endorser_unknown');
        continue;
      }
      const msg = Buffer.concat([Buffer.from('tt-fleet-key/v1\0' + k.kid + '\0', 'latin1'), raw]);
      let ok = false;
      try {
        ok = cryptoVerify(null, msg, endorser, sig);
      } catch {
        ok = false;
      }
      if (!ok) {
        this.noteError('signing_key_endorsement_invalid');
        continue;
      }
      added.push({ kid: k.kid, alg: 'Ed25519', public_key: k.public_key });
      known.set(k.kid, pk);
      pinned.set(k.kid, raw);
      changed = true;
    }
    if (changed) {
      this.persisted.added_keys = added;
      this.persist();
    }
  }

  private async renew(): Promise<void> {
    if (!this.fleet || !this.enrollment) return;
    try {
      const r = await this.fleet.renew(this.opts.useCsr !== false, this.enrollment.service_name);
      if (!r || !r.keyPem) {
        this.noteError('renew_failed');
        return;
      }
      this.enrollment.client_cert = r.cert;
      if (r.notAfter) this.enrollment.not_after = r.notAfter;
      this.keyPem = r.keyPem;
      this.store?.writeText('client.key', r.keyPem);
      this.store?.writeJson('enrollment.json', this.enrollment);
      this.connect();
    } catch {
      this.noteError('renew_network');
    }
  }

  private revoke(): void {
    this.persisted.revoked = true;
    this.persist();
    this.dropQueues();
    this.noteError('source_revoked');
  }

  private dropQueues(): void {
    this.counters.events_dropped_queue += this.pending.length;
    this.pending = [];
    this.pendingBytes = 0;
    this.pool?.discard();
    this.exporter?.clear();
  }

  /** Recomputes the state and the capture gate. */
  private recompute(): void {
    const now = Date.now();
    const p = this.policy;
    const maxAgeMs = (this.enrollment?.policy_max_age_s ?? 86400) * 1000;
    let st: SourceState;
    let key: { kid: string; key: Buffer } | null = null;
    if (this.persisted.kill || this.persisted.revoked) st = 'killed';
    // A missing key is said first: with or without a policy nothing is captured until it is there.
    else if (!this.ring) st = 'key_missing';
    else if (!p) st = this.rejected ?? 'no_policy';
    else if (!(now < p.notAfter) || (this.lastContact > 0 && now - this.lastContact > maxAgeMs)) st = 'expired_policy';
    else {
      try {
        key = selectKey(this.ring!, p);
        st = this.heartbeatOk ? 'capturing' : 'starting';
      } catch {
        st = 'key_mismatch';
      }
    }
    // Capture only after a heartbeat in this process (kill switch and min_issued_seq known).
    if (st === 'capturing' && key && p && this.lastContact > 0) {
      const cur = this.san;
      if (!cur || cur.policy !== p || cur.key.kid !== key.kid || cur.key.key !== key.key || cur.options.rateOverrideBp !== this.overrideBp) {
        this.san = new Sanitizer(p, key, { rateOverrideBp: this.overrideBp });
      }
    } else {
      if (st === 'capturing') st = 'starting';
      this.san = null;
    }
    if (st !== this.state) debug('state', st);
    this.state = st;
  }
}

function metaOf(raw: RawExchange): JobMeta {
  return {
    dir: raw.dir,
    tsMs: raw.tsMs,
    latencyMs: raw.latencyMs,
    status: raw.status,
    netError: raw.netError,
    traceId: raw.traceId,
    spanId: raw.spanId,
    parentSpanId: raw.parentSpanId,
  };
}
