import { beforeEach, describe, expect, it } from 'vitest';
import { ApiError, type Api } from '../types';
import { createMockApi } from './adapter';

const T0 = Date.parse('2026-10-23T10:00:00Z');
let api: Api;

beforeEach(() => {
  api = createMockApi({ latencyMs: 0, now: () => T0, storage: null });
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
const serverCode = async (p: Promise<unknown>) => {
  const e = await p.catch((x: unknown) => x);
  return e instanceof ApiError ? e.serverCode : 'ok';
};

describe('hosts registry and twin (spec v1.5)', () => {
  it('operators and admins see the registry; other roles are refused', async () => {
    await api.demo!.loginAs('auditor');
    expect(await code(api.hosts.list())).toBe('forbidden');
    await api.demo!.loginAs('operator');
    const reg = await api.hosts.list();
    expect(reg.domains.map((d) => d.domain)).toContain('tracking.example');
    expect(reg.domains.find((d) => d.domain === 'ip:private')?.patterns[0].pattern).toBe('ip:private');
    const star = reg.domains.flatMap((d) => d.patterns).find((p) => p.pattern === '{*}.tracking.example');
    expect(star).toMatchObject({ exact: false, quarantined: true, declared: false });
    expect(reg.discovery).toEqual({ 'p-shop': 'auto' });
    await api.demo!.loginAs('admin');
    expect((await api.hosts.list()).invalid.calls).toBeGreaterThan(0);
  });
  it('services point to their host group and no URL is made up', async () => {
    await login('olga.operator');
    const list = await api.services.list();
    expect(list.find((s) => s.name === 'shipping-ext')).toMatchObject({ baseUrl: 'https://api.carrier.example', hostPattern: 'api.carrier.example' });
    expect(JSON.stringify(list)).not.toContain('https://unlisted');
    const registry = JSON.stringify(await api.hosts.list());
    for (const s of list) if (s.hostPattern) expect(registry).toContain(s.hostPattern);
  });
  it('twinning an exact host creates a draft that opens data and needs the normal approvals', async () => {
    await login('olga.operator');
    const pv = await api.hosts.twin({ pattern: 'sandbox.carrier.example', scheme: 'https' });
    expect(pv).toMatchObject({ policyId: 'p-shop', status: 'draft', origin: 'host-twin', opensData: true, approvalsRequired: 2 });
    expect(pv.diff).toEqual([{ change: 'added', where: 'services.sandbox.carrier.example.match.base', to: 'https://sandbox.carrier.example' }]);
    expect(pv.yamlAfter).toContain('https://sandbox.carrier.example');
    expect(pv.yamlBefore).not.toContain('sandbox.carrier.example');
    expect((await api.policies.list()).some((p) => p.version === pv.version && p.origin === 'host-twin')).toBe(true);
    // the operator cannot approve; two approvers can
    expect(await code(api.policies.approve('p-shop', pv.version))).toBe('forbidden');
    await api.demo!.loginAs('policy-approver');
    expect((await api.policies.approve('p-shop', pv.version)).status).toBe('draft');
    await login('anna.approver');
    expect((await api.policies.approve('p-shop', pv.version)).status).toBe('active');
  });
  it('a pattern with {*} or an IP class needs the exact base, and the base must be described by the pattern', async () => {
    await login('olga.operator');
    // An exact host needs its scheme: the events do not carry it, so it is never guessed.
    expect(await serverCode(api.hosts.twin({ pattern: 'sandbox.carrier.example' }))).toBe('scheme_required');
    expect(await serverCode(api.hosts.twin({ pattern: '{*}.tracking.example' }))).toBe('base_required');
    expect(await serverCode(api.hosts.twin({ pattern: 'ip:private' }))).toBe('base_required');
    expect(await serverCode(api.hosts.twin({ pattern: '{*}.tracking.example', base: 'https://acme.other.example' }))).toBe('base_mismatch');
    expect(await serverCode(api.hosts.twin({ pattern: 'ip:private', base: 'https://8.8.8.8' }))).toBe('base_mismatch');
    expect(await serverCode(api.hosts.twin({ pattern: '{*}.tracking.example', base: 'tracking' }))).toBe('invalid_base');
    expect(await serverCode(api.hosts.twin({ pattern: 'unlisted' }))).toBe('invalid_pattern');
    expect(await serverCode(api.hosts.twin({ pattern: 'nothing.example' }))).toBe('invalid_pattern');
    expect(await serverCode(api.hosts.twin({ pattern: '{*}.tracking.example', base: 'https://acme.tracking.example', service: 'Bad Name' }))).toBe('invalid_service');
    const ok = await api.hosts.twin({ pattern: '{*}.tracking.example', base: 'https://acme.tracking.example', service: 'tracking-acme' });
    expect(ok.diff[0].where).toBe('services.tracking-acme.match.base');
    expect((await api.hosts.twin({ pattern: 'ip:private', base: 'https://10.4.7.22' })).yamlAfter).toContain('https://10.4.7.22');
  });
  it('refuses a host that a service already declares, and a name already taken', async () => {
    await login('olga.operator');
    expect(await api.hosts.twin({ pattern: 'api.carrier.example', scheme: 'https' }).catch((x: unknown) => x)).toMatchObject({ code: 'conflict', serverCode: 'already_declared' });
    expect(await api.hosts.twin({ pattern: 'sandbox.carrier.example', scheme: 'https', service: 'shipping-ext' }).catch((x: unknown) => x)).toMatchObject({ code: 'conflict', serverCode: 'service_exists' });
  });
  it('the admin approves a host twin alone, with a reason', async () => {
    await api.demo!.loginAs('admin');
    const pv = await api.hosts.twin({ pattern: '3ds.pay.example', scheme: 'https' });
    expect(await code(api.policies.approve('p-shop', pv.version))).toBe('invalid');
    const done = await api.policies.approve('p-shop', pv.version, 'incident: 3ds timeouts');
    expect(done).toMatchObject({ status: 'active', approvalMode: 'admin' });
  });
  it('is audited with the pattern written without {*}', async () => {
    await login('olga.operator');
    await api.hosts.twin({ pattern: '{*}.tracking.example', base: 'https://acme.tracking.example' });
    await api.demo!.loginAs('auditor');
    const audit = await api.audit.list();
    expect(audit.find((e) => e.action === 'host.twin')?.target).toBe('_.tracking.example');
  });
});

describe('hosts.discovery in the policy assistant', () => {
  it('is auto by default; off closes at once, back to auto opens data', async () => {
    await login('olga.operator');
    expect(await api.policies.hostsDiscovery('shop-api')).toBe('auto');
    const sugg = (await api.onboarding.assist('shop-api')).suggestions;
    const same = sugg.map((s) => ({ suggestionId: s.id, choice: s.current }));
    expect(await code(api.policies.propose({ policyId: 'p-shop', choices: same, hostsDiscovery: 'auto' }))).toBe('invalid');
    const prev = await api.policies.preview({ choices: same, hostsDiscovery: 'off' });
    expect(prev.before).not.toContain('hosts');
    expect(prev.after).toContain('discovery');
    const off = await api.policies.propose({ policyId: 'p-shop', choices: same, hostsDiscovery: 'off' });
    // closing opens no values: applied without approval (policy.md §7)
    expect(off).toMatchObject({ opensData: false, opensValues: false, approvalsRequired: 0, status: 'active' });
    expect(off.diff).toEqual([{ change: 'changed', where: 'hosts.discovery', from: 'auto', to: 'off' }]);
    expect(await api.policies.hostsDiscovery('shop-api')).toBe('off');
    // strict mode: undeclared hosts leave as unlisted and disappear from the groups
    const strict = await api.hosts.list();
    expect(strict.discovery['p-shop']).toBe('off');
    expect(strict.unlisted.calls).toBeGreaterThan(0);
    expect(strict.domains.flatMap((d) => d.patterns).filter((p) => !p.declared && !p.pattern.startsWith('ip:'))).toEqual([]);
    // back to auto opens data again
    await login('olga.operator');
    const again = await api.policies.propose({ policyId: 'p-shop', choices: same, hostsDiscovery: 'auto' });
    expect(again).toMatchObject({ opensData: true, opensValues: true, approvalsRequired: 2, valueReasons: [{ code: 'hosts_discovery', where: 'hosts.discovery' }] });
  });
});

describe('quarantine of host labels', () => {
  it('lists a host-label item with the host_cardinality alert', async () => {
    await api.demo!.loginAs('policy-approver');
    const q =(await api.quarantine.list()).find((x) => x.kind === 'host-label');
    expect(q).toMatchObject({ alert: 'host_cardinality', where: 'hosts under tracking.example position 1', state: 'quarantined' });
    expect((await api.quarantine.resolve(q!.id, 'close')).state).toBe('resolved');
  });
});
