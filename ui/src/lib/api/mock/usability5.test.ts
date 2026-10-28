// Usability round 5 on the demo adapter: withdrawing a draft and retiring an approved rule behave like the server would.
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiError, type Api, type PolicyChoice, type Rule } from '../types';
import { createMockApi } from './adapter';

let api: Api;
beforeEach(() => {
  api = createMockApi({ latencyMs: 0, now: () => Date.parse('2026-10-23T10:00:00Z'), storage: null });
});
const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? e.code : 'other';
  }
};
const choice = (id: string, c: PolicyChoice) => ({ suggestionId: id, choice: c });

async function openingDraft() {
  await api.auth.login({ username: 'olga.operator', password: 'demo' });
  const sugg = (await api.onboarding.assist('shop-api')).suggestions;
  const target = sugg.find((s) => s.current.action !== 'keep')!;
  return api.policies.propose({ policyId: 'p-shop', choices: sugg.map((s) => choice(s.id, s.id === target.id ? { action: 'keep' } : s.current)) });
}

describe('withdrawing a draft', () => {
  it('the proposer takes it back: it is no longer a draft and cannot be approved', async () => {
    const pv = await openingDraft();
    expect(pv.status).toBe('draft');
    const out = await api.policies.withdraw('p-shop', pv.version, 'troppi campi');
    expect(out.status).toBe('withdrawn');
    expect((await api.policies.list()).find((p) => p.version === pv.version)?.status).toBe('withdrawn');
    await api.demo!.loginAs('policy-approver');
    expect(await code(api.policies.approve('p-shop', pv.version))).toBe('conflict');
    // and it cannot be withdrawn twice
    expect(await code(api.policies.withdraw('p-shop', pv.version))).toBe('conflict');
  });

  it('another person cannot, an admin can', async () => {
    const pv = await openingDraft();
    await api.demo!.loginAs('policy-approver');
    expect(await code(api.policies.withdraw('p-shop', pv.version))).toBe('forbidden');
    await api.demo!.loginAs('admin');
    expect((await api.policies.withdraw('p-shop', pv.version)).status).toBe('withdrawn');
  });

  it('an unknown version is not found', async () => {
    await api.auth.login({ username: 'olga.operator', password: 'demo' });
    expect(await code(api.policies.withdraw('p-shop', 999))).toBe('not_found');
  });
});

describe('retiring an approved rule', () => {
  it('a rule-reviewer retires an approved rule; a draft is not retired', async () => {
    await api.demo!.loginAs('rule-reviewer');
    expect(await code(api.rules.retire('r-0007'))).toBe('conflict');
    const r = await api.rules.retire('r-0003', 'sostituita');
    expect(r).toMatchObject({ id: 'r-0003', status: 'retired' });
    expect((await api.rules.get('r-0003')).status).toBe('retired');
    expect(await code(api.rules.retire('r-0003'))).toBe('conflict');
  });

  it('a stale rule can be retired too', async () => {
    await api.demo!.loginAs('rule-reviewer');
    const stale = (await api.rules.list()).find((r) => r.status === 'stale');
    if (stale) expect((await api.rules.retire(stale.id)).status).toBe('retired');
  });

  it('approving a rule that supersedes an approved one takes the old one out of the packs (as tt-core 1.17.0)', async () => {
    await api.demo!.loginAs('admin');
    // r-0007, a draft of the demo, approved, then edited: the edit is a new draft that supersedes it
    await api.rules.review('r-0007', 'approve', '');
    const old: Rule | undefined = await api.rules.get('r-0007');
    const draft: Rule | undefined = await api.rules.update('r-0007', old.definition);
    expect(old && draft).toBeTruthy();
    expect(draft).toMatchObject({ status: 'draft', supersedes: old!.id });
    // until the new one is approved the old one stays in the packs
    expect((await api.rules.get(old!.id)).status).toBe('approved');
    await api.rules.review(draft!.id, 'approve', '');
    expect(await api.rules.get(old!.id)).toMatchObject({ status: 'retired', supersededBy: draft!.id });
    expect((await api.rules.get(draft!.id)).status).toBe('approved');
  });

  it('needs the reviewer role', async () => {
    await api.demo!.loginAs('operator');
    expect(await code(api.rules.retire('r-0003'))).toBe('forbidden');
  });
});
