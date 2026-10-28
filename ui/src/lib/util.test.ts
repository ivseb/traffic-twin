import { describe, expect, it } from 'vitest';
import { collapseContext, diffLines, diffStats } from './diff';
import { sha256Hex, mulberry32 } from './hash';
import { toYaml } from './yaml';
import { healthCounts, sourceHealth } from './health';
import { diffChoices, formatChoice, hostsDiff, opensData, policyYaml } from './policy';
import { ALL_PERMISSIONS, ROLE_PERMISSIONS, isAdmin, userCan } from './rbac';
import type { PolicySuggestion } from './api/types';

describe('sha256', () => {
  it('matches known vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Hex('a'.repeat(1000))).toBe('41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
  });
});

describe('mulberry32', () => {
  it('is deterministic per seed', () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    expect([a(), a(), a()]).toEqual([b(), b(), b()]);
    expect(mulberry32(1)()).not.toBe(mulberry32(2)());
  });
});

describe('diffLines', () => {
  it('marks additions and removals', () => {
    const lines = diffLines('a\nb\nc', 'a\nc\nd');
    expect(lines.map((l) => `${l.kind}:${l.text}`)).toEqual(['same:a', 'del:b', 'same:c', 'add:d']);
    expect(diffStats(lines)).toEqual({ added: 1, removed: 1 });
  });
  it('handles empty sides', () => {
    expect(diffLines('', 'x').map((l) => l.kind)).toEqual(['add']);
    expect(diffLines('x', '').map((l) => l.kind)).toEqual(['del']);
  });
  it('collapses long unchanged runs around the changes', () => {
    const before = Array.from({ length: 20 }, (_, i) => `l${i}`).join('\n');
    const after = before.replace('l10', 'X');
    const out = collapseContext(diffLines(before, after), 2);
    expect(out.some((l) => l.kind === 'gap')).toBe(true);
    expect(out.length).toBeLessThan(20);
  });
});

describe('toYaml', () => {
  it('serializes nested objects and quotes awkward strings', () => {
    const y = toYaml({ a: 1, b: { c: 'x y', d: ['p', 'q'] }, e: 'hmac(order)', f: '$.id', g: 'true', h: '' });
    expect(y).toContain('a: 1');
    expect(y).toContain('  c: x y');
    expect(y).toContain('  d:\n    - p\n    - q');
    expect(y).toContain('e: hmac(order)');
    expect(y).toContain('g: "true"');
    expect(y).toContain('h: ""');
  });
});

describe('sourceHealth', () => {
  const now = Date.parse('2026-10-23T10:00:00Z');
  const base = { revoked: false, killed: false, lastSeen: new Date(now - 10_000).toISOString(), problems: [], dropRatio: 0, state: 'capturing' as const };
  it('classifies sources', () => {
    expect(sourceHealth(base, now)).toBe('healthy');
    expect(sourceHealth({ ...base, dropRatio: 0.2 }, now)).toBe('degraded');
    expect(sourceHealth({ ...base, state: 'key_mismatch' }, now)).toBe('degraded');
    expect(sourceHealth({ ...base, lastSeen: new Date(now - 3600_000).toISOString() }, now)).toBe('offline');
    expect(sourceHealth({ ...base, killed: true }, now)).toBe('killed');
    expect(sourceHealth({ ...base, revoked: true, killed: true }, now)).toBe('revoked');
  });
  it('counts per class', () => {
    const counts = healthCounts([{ ...base }, { ...base, killed: true }] as never, now);
    expect(counts).toMatchObject({ healthy: 1, killed: 1, degraded: 0 });
  });
});

describe('hosts.discovery in the policy helpers', () => {
  it('has no diff when the mode does not change', () => {
    expect(hostsDiff('auto', 'auto')).toEqual([]);
    expect(hostsDiff('off', 'off')).toEqual([]);
  });
  it('auto -> off closes (hosts go back to unlisted), off -> auto opens data', () => {
    const closing = hostsDiff('auto', 'off');
    expect(closing).toEqual([{ change: 'changed', where: 'hosts.discovery', from: 'auto', to: 'off' }]);
    expect(opensData(closing)).toBe(false);
    const opening = hostsDiff('off', 'auto');
    expect(opening[0]).toMatchObject({ from: 'off', to: 'auto' });
    expect(opensData(opening)).toBe(true);
  });
  it('writes the hosts block only for off', () => {
    expect(policyYaml([], {})).not.toContain('hosts');
    expect(policyYaml([], {}, 'auto')).not.toContain('hosts');
    expect(policyYaml([], {}, 'off')).toMatch(/hosts:\n\s+discovery: "?off"?/);
  });
});

describe('policy helpers', () => {
  const s = (id: string, current: 'drop' | 'keep'): PolicySuggestion => ({
    id,
    service: 'svc',
    op: 'GET /x',
    part: 'response',
    path: `$.${id}`,
    shape: 'str',
    observed: 10,
    distinct: 3,
    suggestion: { action: 'keep' },
    current: { action: current },
    reason: '',
  });
  it('formats choices', () => {
    expect(formatChoice({ action: 'hmac', arg: 'order' })).toBe('hmac(order)');
    expect(formatChoice({ action: 'bucket', arg: '0, 50' })).toBe('bucket(num, [0, 50])');
    expect(formatChoice({ action: 'code', arg: 'alnum' })).toBe('code(alnum)');
    expect(formatChoice({ action: 'drop' })).toBe('drop');
  });
  it('opens data only when something is added or widened', () => {
    const list = [s('a', 'drop'), s('b', 'keep')];
    const cur = { a: { action: 'drop' as const }, b: { action: 'keep' as const } };
    expect(diffChoices(list, cur, cur)).toEqual([]);
    const closing = diffChoices(list, cur, { ...cur, b: { action: 'drop' } });
    expect(closing[0].change).toBe('removed');
    expect(opensData(closing)).toBe(false);
    const opening = diffChoices(list, cur, { ...cur, a: { action: 'keep' } });
    expect(opensData(opening)).toBe(true);
  });
});

describe('rbac', () => {
  it('uses exactly the roles of tt-core', () => {
    expect(Object.keys(ROLE_PERMISSIONS).sort()).toEqual(['admin', 'auditor', 'event-exporter', 'operator', 'policy-approver', 'publisher', 'rule-reviewer']);
  });
  it('gives each role only its own permissions', () => {
    expect(userCan({ roles: ['auditor'] }, 'rules.review')).toBe(false);
    expect(userCan({ roles: ['rule-reviewer'] }, 'rules.review')).toBe(true);
    expect(userCan({ roles: ['operator', 'policy-approver'] }, 'policy.approve')).toBe(true);
    expect(userCan({ roles: ['operator'] }, 'policy.approve')).toBe(false);
    expect(userCan(null, 'audit.view')).toBe(false);
  });
  it('keeps the duties apart: building packs, releasing them and approving policies', () => {
    expect(userCan({ roles: ['operator'] }, 'publish.build')).toBe(true);
    expect(userCan({ roles: ['operator'] }, 'publish.run')).toBe(false);
    expect(userCan({ roles: ['publisher'] }, 'publish.build')).toBe(false);
    expect(userCan({ roles: ['publisher'] }, 'publish.run')).toBe(true);
    // only admin, the superuser, holds both (it is traced instead)
    for (const [role, perms] of Object.entries(ROLE_PERMISSIONS)) {
      if (role === 'admin') continue;
      expect(perms.includes('publish.build') && perms.includes('publish.run'), role).toBe(false);
    }
  });
  it('makes admin the superuser: every permission, and the override flag', () => {
    for (const p of ALL_PERMISSIONS) expect(userCan({ roles: ['admin'] }, p), p).toBe(true);
    for (const perms of Object.values(ROLE_PERMISSIONS)) for (const p of perms) expect(ALL_PERMISSIONS).toContain(p);
    expect(isAdmin({ roles: ['admin', 'policy-approver'] })).toBe(true);
    expect(isAdmin({ roles: ['policy-approver'] })).toBe(false);
    // the override (reason, alert) stays the admin's only
    expect(userCan({ roles: ['policy-approver', 'publisher', 'operator', 'auditor', 'rule-reviewer', 'event-exporter'] }, 'override.admin')).toBe(false);
  });
});
