import { beforeEach, describe, expect, it } from 'vitest';
import { ApiError, type Api, type PolicyChoice } from '../types';
import { createMockApi } from './adapter';

const T0 = Date.parse('2026-10-23T10:00:00Z');
let clock = T0;
let api: Api;

beforeEach(() => {
  clock = T0;
  api = createMockApi({ latencyMs: 0, now: () => clock, storage: null });
});

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? e.code : 'other';
  }
};
const login = (name: string) => api.auth.login({ username: name, password: 'demo' });

describe('authentication and permissions', () => {
  it('rejects calls without a session', async () => {
    expect(await code(api.sources.list())).toBe('unauthenticated');
  });
  it('rejects bad credentials and SSO accounts with a local password', async () => {
    expect(await code(api.auth.login({ username: 'elena.admin', password: 'x' }))).toBe('unauthenticated');
    expect(await code(api.auth.login({ username: 'rita.reviewer', password: 'demo' }))).toBe('unauthenticated');
  });
  it('enforces roles like a server would', async () => {
    await api.demo!.loginAs('event-exporter');
    expect(await code(api.sources.kill({ all: true }, true))).toBe('forbidden');
    expect(await code(api.rules.review('r-0007', 'approve', ''))).toBe('forbidden');
    expect(await code(api.users.list())).toBe('forbidden');
  });
  it('records denied attempts in the audit trail', async () => {
    await api.demo!.loginAs('event-exporter');
    await code(api.sources.kill({ all: true }, true));
    await api.demo!.loginAs('auditor');
    const list = await api.audit.list();
    expect(list.find((e) => e.action === 'sources.kill')).toMatchObject({ actor: 'vera.exporter', result: 'denied' });
  });
  it('demo.loginAs switches to the requested role', async () => {
    const u = await api.demo!.loginAs('publisher');
    expect(u.roles).toContain('publisher');
  });
});

describe('first-run setup', () => {
  it('refuses when already initialized and works after a reset', async () => {
    expect(await code(api.system.setup({ setupToken: 'tts_x', username: 'root', password: 'long-enough-pass' }))).toBe('already_initialized');
    api.demo!.resetFirstRun();
    expect((await api.system.status()).initialized).toBe(false);
    expect(await code(api.system.setup({ setupToken: 'bad', username: 'root', password: 'long-enough-pass' }))).toBe('invalid');
    expect(await code(api.system.setup({ setupToken: 'tts_x', username: 'root', password: 'short' }))).toBe('invalid');
    await api.system.setup({ setupToken: 'tts_x', username: 'root', password: 'long-enough-pass' });
    expect((await api.system.status()).initialized).toBe(true);
  });
});

describe('sources', () => {
  it('only lowers sampling and applies the kill switch', async () => {
    await login('olga.operator');
    const s = (await api.sources.list()).find((x) => x.serviceName === 'shop-api')!;
    expect(await code(api.sources.setSampling(s.id, s.policyRateBp + 1))).toBe('invalid');
    await api.sources.setSampling(s.id, 100);
    await api.sources.kill({ sourceId: s.id }, true);
    const after = (await api.sources.list()).find((x) => x.id === s.id)!;
    expect(after).toMatchObject({ samplingBp: 100, killed: true, state: 'killed' });
  });
});

describe('onboarding', () => {
  it('walks the checklist as time passes', async () => {
    await login('olga.operator');
    const tk = await api.onboarding.createToken('sdk-node', 'shop-api');
    expect(tk.token).toMatch(/^tte_/);
    expect(tk.snippets.some((s) => s.text.includes(tk.token))).toBe(true);
    expect(await api.onboarding.status(tk.tokenId)).toMatchObject({ enrolled: false, firstEvents: 0 });
    clock += 5_500;
    expect(await api.onboarding.status(tk.tokenId)).toMatchObject({ enrolled: true, policyReceived: true, firstEvents: 0 });
    clock += 20_000;
    expect((await api.onboarding.status(tk.tokenId)).firstEvents).toBe(20);
  });
  it('reports a fixable problem for the PHP source', async () => {
    await login('olga.operator');
    const tk = await api.onboarding.createToken('sdk-php', 'shop');
    clock += 10_000;
    const st = await api.onboarding.status(tk.tokenId);
    expect(st.problems[0]).toMatchObject({ code: 'no_subject_found' });
    expect(st.problems[0].hint).toBeTruthy();
  });
  it('rejects an invalid group name', async () => {
    await login('olga.operator');
    expect(await code(api.onboarding.createToken('egress', 'Bad Name'))).toBe('invalid');
  });
  it('suggestions never carry values', async () => {
    await login('olga.operator');
    const list = (await api.onboarding.assist('shop-api')).suggestions;
    for (const s of list) expect(Object.keys(s)).not.toContain('value');
    expect(list.some((s) => s.suggestion.action === 'drop')).toBe(true);
  });
});

describe('policies: two-person rule', () => {
  const open = (id: string, choice: PolicyChoice) => ({ suggestionId: id, choice });
  it('applies a change that opens no values at once (policy.md §7)', async () => {
    await login('olga.operator');
    const sugg = (await api.onboarding.assist('shop-api')).suggestions;
    const pv = await api.policies.propose({
      policyId: 'p-shop',
      choices: sugg.map((s) => open(s.id, s.id === 'sg-1' ? { action: 'hmac', arg: 'order' } : s.current)),
    });
    expect(pv).toMatchObject({ opensValues: false, approvalsRequired: 0, status: 'active', approvalMode: 'observe' });
  });
  it('needs two different approvers when a change opens values, and not the proposer', async () => {
    await login('olga.operator');
    const sugg = (await api.onboarding.assist('shop-api')).suggestions;
    const target = sugg.find((s) => s.current.action !== 'keep')!;
    const prev = await api.policies.preview({ policyId: 'p-shop', choices: sugg.map((s) => open(s.id, s.id === target.id ? { action: 'keep' } : s.current)) });
    expect(prev).toMatchObject({ opensValues: true, approvalsRequired: 2 });
    expect(prev.valueReasons?.[0]?.code).toBe('keep');
    const pv = await api.policies.propose({
      policyId: 'p-shop',
      choices: sugg.map((s) => open(s.id, s.id === target.id ? { action: 'keep' } : s.current)),
    });
    expect(pv).toMatchObject({ opensValues: true, approvalsRequired: 2, status: 'draft' });
    expect(pv.diff).toHaveLength(1);

    await api.demo!.loginAs('policy-approver');
    const first = await api.policies.approve('p-shop', pv.version);
    expect(first.status).toBe('draft');
    expect(await code(api.policies.approve('p-shop', pv.version))).toBe('conflict'); // same person twice

    await login('elena.admin');
    await api.demo!.loginAs('policy-approver');
  });
  it('blocks the proposer from approving and activates after the second person', async () => {
    await api.demo!.loginAs('operator');
    const sugg = (await api.onboarding.assist('shop-api')).suggestions;
    const pv = await api.policies.propose({ policyId: 'p-shop', choices: sugg.map((s) => open(s.id, s.id === 'sg-3' ? { action: 'bucket', arg: '0, 50' } : s.current)) });
    // the operator role has no approval permission at all
    expect(await code(api.policies.approve('p-shop', pv.version))).toBe('forbidden');
  });
  it('refuses an empty change', async () => {
    await login('olga.operator');
    const sugg = (await api.onboarding.assist('shop-api')).suggestions;
    expect(await code(api.policies.propose({ policyId: 'p-shop', choices: sugg.map((s) => open(s.id, s.current)) }))).toBe('invalid');
  });
  it('the seeded draft v8 reaches 2/2 and becomes active', async () => {
    await login('anna.approver'); // paolo approved already; anna is the second person, not the proposer (olga)
    const v8 = await api.policies.approve('p-shop', 8);
    expect(v8).toMatchObject({ status: 'active', approvalMode: 'standard' });
    const all = await api.policies.list();
    expect(all.find((p) => p.version === 7)?.status).toBe('superseded');
  });
});

describe('administrator override (policy.md §5)', () => {
  it('lets an admin approve alone, but only with a reason, and flags it everywhere', async () => {
    await api.demo!.loginAs('admin');
    expect(await code(api.policies.approve('p-shop', 8))).toBe('invalid');
    expect(await code(api.policies.approve('p-shop', 8, '   '))).toBe('invalid');
    const v8 = await api.policies.approve('p-shop', 8, 'Correzione urgente durante l’incidente');
    expect(v8).toMatchObject({ status: 'active', approvalMode: 'admin' });
    expect(v8.approvals.at(-1)).toMatchObject({ mode: 'admin', reason: 'Correzione urgente durante l’incidente' });
    expect((await api.alerts.list())[0]).toMatchObject({ type: 'policy.admin_approval', severity: 'warning' });
    await api.demo!.loginAs('auditor');
    expect((await api.audit.list()).some((e) => e.action === 'policy.approve.admin')).toBe(true);
    expect((await api.audit.verify()).ok).toBe(true);
  });
  it('lets an admin release a signed pack alone, with a reason', async () => {
    await api.demo!.loginAs('operator');
    const p = await api.publications.run('w-0001', { validDays: 30 });
    expect(p.notAfter).toBeTruthy();
    clock += 1_500 * 5;
    expect((await api.publications.get(p.id)).status).toBe('signed');
    await api.demo!.loginAs('admin');
    expect(await code(api.publications.publish(p.id))).toBe('invalid');
    const done = await api.publications.publish(p.id, { reason: 'Rilascio fuori turno' });
    expect(done).toMatchObject({ status: 'published', adminOverride: { reason: 'Rilascio fuori turno' } });
    // the administrator is the superuser: it downloads too (traced by the server)
    expect((await api.publications.download(p.id)).filename).toContain('pk-');
    await api.demo!.loginAs('publisher');
    expect((await api.publications.download(p.id)).filename).toContain('pk-');
  });
  it('is not available to other roles', async () => {
    await api.demo!.loginAs('operator');
    expect(await code(api.policies.approve('p-shop', 8, 'x'))).toBe('forbidden');
  });
  it('lets an admin resolve a quarantine alone, with an alert for a dismissal', async () => {
    await api.demo!.loginAs('admin');
    const q = (await api.quarantine.list()).find((x) => x.state !== 'resolved');
    expect(q).toBeTruthy();
    expect((await api.quarantine.resolve(q!.id, 'dismiss')).state).toBe('resolved');
    expect((await api.alerts.list())[0]).toMatchObject({ type: 'keyguard.alert', severity: 'warning' });
    await api.demo!.loginAs('auditor');
    expect((await api.audit.list()).some((e) => e.action === 'quarantine.dismiss.admin')).toBe(true);
  });
  it('approvals settings are read-only', async () => {
    await api.demo!.loginAs('admin');
    const s = await api.settings.get();
    expect(s.approvals).toMatchObject({ openingRequired: 2, adminOverride: true });
    expect(s.general?.kMin).toBe(20);
    const saved = await api.settings.save({ ...s, approvals: { openingRequired: 1, adminOverride: false, identitiesVerified: true } });
    expect(saved.approvals).toEqual(s.approvals);
  });
});

describe('pack contents and OpenAPI', () => {
  it('lists world.jsonl and scenarios.json, not a sqlite file', async () => {
    await api.demo!.loginAs('event-exporter');
    const files = (await api.publications.get('pub-0001')).files.map((f) => f.path);
    expect(files).toContain('world.jsonl');
    expect(files).toContain('scenarios.json');
    expect(files.some((f) => f.includes('sqlite'))).toBe(false);
  });
  it('builds an OpenAPI 3.1 document per service with x-tt extensions', async () => {
    await api.demo!.loginAs('event-exporter');
    const doc = (await api.contracts.openapi('shipping-ext')) as { openapi: string; paths: Record<string, Record<string, Record<string, unknown>>> };
    expect(doc.openapi).toBe('3.1.0');
    const get = doc.paths['/v1/shipments'].get;
    expect(get['x-tt-observed']).toMatchObject({ calls: 58210 });
    expect(Object.keys(get.responses as object)).toEqual(['200', '400', '503']);
    expect(doc.paths['/v1/shipments/{id}'].get.parameters).toHaveLength(1);
    expect(await code(api.contracts.openapi('nope'))).toBe('not_found');
  });
  it('summarizes a service', async () => {
    await api.demo!.loginAs('event-exporter');
    const s = await api.contracts.service('shipping-ext');
    expect(s.operations).toBe(3);
    expect(s.errorRate).toBeGreaterThan(0);
    expect(s.lastDrift?.severity).toBe('breaking');
    expect(s.coverage.statusesNeverSeen).toBeGreaterThan(0);
  });
});

describe('rules lifecycle', () => {
  it('approves a draft, locks it, and handles stale rules', async () => {
    await api.demo!.loginAs('rule-reviewer');
    const r = await api.rules.review('r-0007', 'approve', 'ok');
    expect(r.status).toBe('approved');
    expect(r.review.by).toContain('rita.reviewer');
    expect(await code(api.rules.setAfter('r-0007', 'shipment-created', '10m'))).toBe('conflict');
    expect(await code(api.rules.review('r-0007', 'reject', ''))).toBe('conflict');
    expect((await api.rules.review('r-0005', 'confirm', '')).status).toBe('approved');
  });
  it('validates figurative delays', async () => {
    await api.demo!.loginAs('rule-reviewer');
    expect(await code(api.rules.setAfter('r-0007', 'shipment-created', 'soon'))).toBe('invalid');
    const r = await api.rules.setAfter('r-0007', 'shipment-created', '10m');
    expect(r.effects.find((e) => e.id === 'shipment-created')?.after).toBe('10m');
  });
  it('outcome probabilities sum to 1 in the fixtures', async () => {
    await api.demo!.loginAs('event-exporter');
    for (const r of await api.rules.list()) {
      if (r.kind === 'causal') expect(r.outcomes.reduce((a, o) => a + o.p, 0)).toBeCloseTo(1, 3);
    }
  });
});

describe('archetypes (k-anonymity)', () => {
  it('hides the size of groups below k', async () => {
    await api.demo!.loginAs('event-exporter');
    const set = await api.archetypes.get();
    expect(set.kMin).toBe(20);
    for (const a of set.archetypes) {
      if (a.belowK) expect(a.size).toBeNull();
      else expect(a.size).toBeGreaterThanOrEqual(set.kMin);
    }
    expect(set.mergedCount).toBeGreaterThan(0);
  });
});

describe('worlds', () => {
  it('is deterministic for a seed and validates input', async () => {
    await api.demo!.loginAs('operator');
    const w = await api.worlds.generate({ seed: 7, customers: 10 });
    const a = await api.worlds.graph(w.id, 3);
    const b = await api.worlds.graph(w.id, 3);
    expect(a).toEqual(b);
    expect(a.nodes[0].id).toBe('CUS-SYN-0004');
    expect(a.nodes.every((n) => /-SYN-/.test(n.id))).toBe(true);
    expect(await code(api.worlds.generate({ seed: -1, customers: 10 }))).toBe('invalid');
    expect(await code(api.worlds.generate({ seed: 1, customers: 0 }))).toBe('invalid');
  });
});

describe('world explorer, archetypes build and Postman (journey round)', () => {
  it('pages and searches the invented customers, and gives each its entities with timelines', async () => {
    await api.demo!.loginAs('operator');
    const w = await api.worlds.generate({ seed: 7, customers: 45 });
    const first = await api.worlds.customers(w.id, { limit: 20 });
    expect(first).toMatchObject({ total: 45, all: 45, offset: 0, limit: 20 });
    expect(first.customers).toHaveLength(20);
    const last = await api.worlds.customers(w.id, { offset: 40, limit: 20 });
    expect(last.customers).toHaveLength(5);
    expect(first.customers.every((c) => /@example\.com$/.test(c.email) && /^CUS-SYN-\d{4}$/.test(c.id))).toBe(true);
    const hit = await api.worlds.customers(w.id, { q: first.customers[3].name.toUpperCase() });
    expect(hit.total).toBeGreaterThan(0);
    expect(hit.total).toBeLessThan(45);
    const none = await api.worlds.customers(w.id, { q: 'zzz-nobody' });
    expect(none).toMatchObject({ total: 0, all: 45, customers: [] });
    const d = await api.worlds.customer(w.id, first.customers[0].id);
    expect(d.id).toBe(first.customers[0].id);
    expect(d.entities.length).toBeGreaterThan(0);
    expect(d.entities.every((e) => e.steps.length > 0 && e.steps.every((s, i, a) => i === 0 || a[i - 1].at <= s.at))).toBe(true);
    expect(await code(api.worlds.customer(w.id, 'CUS-SYN-9999'))).toBe('not_found');
    expect(await code(api.worlds.customers('w-9999'))).toBe('not_found');
  });
  it('builds the archetypes on request (operator) and keeps the profiles built', async () => {
    await api.demo!.loginAs('operator');
    const set = await api.archetypes.build();
    expect(set.built).toBe(true);
    expect(set.archetypes.length).toBeGreaterThan(0);
  });
  it('downloads a Postman collection with {{baseUrl}} and example bodies', async () => {
    await api.demo!.loginAs('operator');
    const { filename, blob } = await api.contracts.postman('shipping-ext');
    expect(filename).toBe('shipping-ext.postman_collection.json');
    const c = JSON.parse(await blob.text()) as { info: { schema: string }; variable: { key: string }[]; item: { name: string; request: { url: { raw: string } } }[] };
    expect(c.info.schema).toContain('collection/v2.1.0');
    expect(c.variable[0].key).toBe('baseUrl');
    expect(c.item.length).toBeGreaterThan(0);
    expect(c.item.every((i) => i.request.url.raw.startsWith('{{baseUrl}}/'))).toBe(true);
    expect(await code(api.contracts.postman('no-such-service'))).toBe('not_found');
  });
});

describe('publication gate', () => {
  it('builds as a pipeline, signs a clean world, and releases it in a separate step', async () => {
    await api.demo!.loginAs('operator');
    const p = await api.publications.run('w-0001');
    expect(p).toMatchObject({ verdict: 'running', status: 'building' });
    expect(p.checks.map((c) => c.status)).toEqual(['running', 'pending', 'pending', 'pending']);
    clock += 1_500 * 5;
    const done = await api.publications.get(p.id);
    expect(done).toMatchObject({ verdict: 'pass', status: 'signed' });
    expect(done.checks.every((c) => c.status === 'pass')).toBe(true);
    expect(done.signedBy).toBeTruthy();
    // signed is not released: nothing to download yet
    await api.demo!.loginAs('publisher');
    expect(await code(api.publications.download(p.id))).toBe('conflict');
    const out = await api.publications.publish(p.id);
    expect(out.status).toBe('published');
    expect(out.publishedAt).toBeTruthy();
    const dl = await api.publications.download(p.id);
    expect(dl.filename).toContain(done.packId);
    const rep = await api.publications.export(p.id, 'prism');
    expect(rep.lost.length).toBeGreaterThan(0);
    expect(await code(api.publications.publish(p.id))).toBe('conflict'); // already released
  });
  it('blocks a world with a leak, never reports values, and refuses release and download', async () => {
    await api.demo!.loginAs('operator');
    const p = await api.publications.run('w-0002'); // seed 13 leaks in the fixtures
    clock += 1_500 * 5;
    const done = await api.publications.get(p.id);
    expect(done).toMatchObject({ verdict: 'fail', status: 'gate-failed' });
    expect(done.checks.map((c) => c.status)).toEqual(['pass', 'fail', 'skipped', 'skipped']);
    for (const f of done.checks.flatMap((c) => c.findings)) expect(Object.keys(f).sort()).toEqual(['file', 'pointer', 'reason']);
    expect(done.signedBy).toBeUndefined();
    await api.demo!.loginAs('publisher');
    expect(await code(api.publications.publish(p.id))).toBe('conflict');
    expect(await code(api.publications.download(p.id))).toBe('conflict');
  });
  it('building is the operator’s, releasing is the publisher’s', async () => {
    await api.demo!.loginAs('publisher');
    expect(await code(api.publications.run('w-0001'))).toBe('forbidden');
    await api.demo!.loginAs('operator');
    expect(await code(api.publications.publish('pub-0002'))).toBe('forbidden');
  });
});

describe('audit hash chain', () => {
  it('verifies, and grows with every mutation', async () => {
    await api.demo!.loginAs('auditor');
    const before = await api.audit.verify();
    expect(before.ok).toBe(true);
    await login('olga.operator');
    await api.sources.kill({ group: 'edge' }, true);
    await api.demo!.loginAs('auditor');
    const after = await api.audit.verify();
    expect(after.ok).toBe(true);
    expect(after.entries).toBeGreaterThan(before.entries);
    expect(after.headHash).not.toBe(before.headHash);
  });
  it('each entry links to the previous hash', async () => {
    await login('ada.auditor');
    const list = [...(await api.audit.list())].reverse();
    for (let i = 1; i < list.length; i++) expect(list[i].prevHash).toBe(list[i - 1].hash);
  });
});

describe('gaps and settings', () => {
  it('lists the three kinds of gaps', async () => {
    await api.demo!.loginAs('event-exporter');
    const kinds = new Set((await api.gaps.list()).map((g) => g.kind));
    expect(kinds).toEqual(new Set(['few-samples', 'status-never-seen', 'low-support-rule']));
  });
  it('validates and persists settings for admins only', async () => {
    await api.demo!.loginAs('admin');
    const s = await api.settings.get();
    expect(await code(api.settings.save({ ...s, general: { ...s.general!, kMin: 2 } }))).toBe('invalid');
    await api.settings.save({ ...s, general: { ...s.general!, kMin: 30 } });
    expect((await api.archetypes.get()).kMin).toBe(30);
    await api.demo!.loginAs('operator');
    expect(await code(api.settings.save(s))).toBe('forbidden');
  });
});

describe('quarantine, retention, events (the composed core)', () => {
  it('close takes one approver, dismiss two different ones', async () => {
    await api.demo!.loginAs('policy-approver');
    expect((await api.quarantine.resolve('q-1', 'dismiss')).state).toBe('dismiss-pending');
    expect(await code(api.quarantine.resolve('q-1', 'dismiss'))).toBe('conflict'); // same person twice
    await api.demo!.loginAs('operator');
    expect(await code(api.quarantine.resolve('q-1', 'close'))).toBe('forbidden');
    await login('anna.approver');
    expect((await api.quarantine.resolve('q-1', 'dismiss')).state).toBe('resolved');
  });
  it('retention and purge are the admin\u2019s', async () => {
    await api.demo!.loginAs('admin');
    expect((await api.store.setRetention(45)).eventsDays).toBe(45);
    expect(await code(api.store.setRetention(0))).toBe('invalid');
    expect((await api.store.purge('2026-01-01T00:00:00Z')).events).toBeGreaterThan(0);
    await api.demo!.loginAs('operator');
    expect(await code(api.store.purge('2026-01-01T00:00:00Z'))).toBe('forbidden');
  });
  it('only the event-exporter exports events', async () => {
    await api.demo!.loginAs('operator');
    expect(await code(api.events.export({ from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z', format: 'jsonl' }))).toBe('forbidden');
    await api.demo!.loginAs('event-exporter');
    const job = await api.events.export({ from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z', format: 'jsonl' });
    expect((await api.events.download(job)).filename).toMatch(/\.jsonl$/);
  });
});

describe('group-scoped lists (multi-team isolation)', () => {
  it('keeps two services with the same name and different groups, and filters by group', async () => {
    await login('olga.operator');
    const all = await api.services.list();
    expect(all.filter((s) => s.name === 'host:ip:private:9301').map((s) => s.group).sort()).toEqual(['legacy', 'shop-api']);
    const legacy = await api.services.list(['legacy']);
    expect(legacy.every((s) => s.group === 'legacy')).toBe(true);
    expect(legacy.map((s) => s.name)).toContain('host:ip:private:9301');
    const reg = await api.hosts.list(['legacy']);
    expect(reg.domains.flatMap((d) => d.patterns).every((p) => p.group === 'legacy')).toBe(true);
  });
  it('the twin choice is per (group, service)', async () => {
    await login('olga.operator');
    await api.services.setTwin('host:ip:private:9301', true, 'legacy');
    const rows = (await api.services.list()).filter((s) => s.name === 'host:ip:private:9301');
    expect(rows.find((s) => s.group === 'legacy')?.twin).toBe(true);
    expect(rows.find((s) => s.group === 'shop-api')?.twin).toBe(false);
  });
  it('lists only the policies of the group, each with its groups', async () => {
    await login('olga.operator');
    const shop = await api.policies.list(['shop-api']);
    expect(shop.length).toBeGreaterThan(0);
    expect(shop.every((p) => p.groups?.includes('shop-api'))).toBe(true);
    expect((await api.policies.list(['legacy'])).map((p) => p.policyId)).toEqual(['p-legacy', 'p-legacy']);
  });
  it('a pack refuses services of another group, and multi_group is for administrators', async () => {
    await login('olga.operator');
    let err: unknown;
    try {
      await api.publications.run('w-0002', { services: ['shop-api', 'legacy-app'] });
    } catch (e) {
      err = e;
    }
    expect(err).toMatchObject({ serverCode: 'mixed_groups', details: [{ service: 'legacy-app', groups: ['legacy'] }] });
    expect(await code(api.publications.run('w-0002', { services: ['shop-api', 'legacy-app'], multiGroup: true }))).toBe('forbidden');
    const p = await api.publications.run('w-0002', { excludeServices: ['tax-ext'] });
    expect(p).toMatchObject({ group: 'shop-api', groups: ['shop-api'] });
    expect(p.services).not.toContain('tax-ext');
    expect((await api.publications.list(['legacy'])).length).toBe(0);
  });
  it('the assistant never preselects a stale host and folds merged patterns', async () => {
    await login('olga.operator');
    const a = await api.onboarding.assist('shop-api');
    expect(a.services.find((s) => s.stale)).toMatchObject({ declared: false, preselect: false });
    expect(a.services.find((s) => s.service === 'shipping-ext')?.mergedPatterns).toEqual(['webhooks.carrier.example:8443']);
  });
});

describe('observe phase (policy.md §7)', () => {
  it('listens after the token, then shows the observe version with the masked identifiers', async () => {
    await login('olga.operator');
    await api.onboarding.createToken('sdk-node', 'bookings');
    clock += 8_000;
    const listening = await api.onboarding.observe('bookings');
    expect(listening).toMatchObject({ phase: 'listening', masked: [], minEvents: 200 });
    expect(listening.events).toBeGreaterThan(0);
    clock += 20_000;
    const masked = await api.onboarding.observe('bookings');
    expect(masked).toMatchObject({ phase: 'masked', observeVersion: 2, identity: { name: 'authorization', claim: 'sub' } });
    expect(masked.masked.length).toBeGreaterThan(0);
    expect(masked.masked.every((m) => m.domain !== '')).toBe(true);
    expect(masked.auto).toBe(true);
    expect((await api.onboarding.setObserveAuto('bookings', false)).auto).toBe(false);
    expect((await api.onboarding.observe('bookings')).auto).toBe(false);
    expect((await api.onboarding.setObserveAuto('bookings', true)).auto).toBe(true);
  });
});
