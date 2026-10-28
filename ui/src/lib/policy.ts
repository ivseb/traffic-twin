import type { DiffEntry, HostsDiscovery, PolicyChoice, PolicySuggestion } from './api/types';
import { toYaml } from './yaml';

export function formatChoice(c: PolicyChoice): string {
  if (c.action === 'hmac') return `hmac(${c.arg || 'id'})`;
  if (c.action === 'bucket') return `bucket(num, [${c.arg ?? ''}])`;
  if (c.action === 'code' && c.arg === 'alnum') return 'code(alnum)';
  return c.action;
}

export const sameChoice = (a: PolicyChoice, b: PolicyChoice) => formatChoice(a) === formatChoice(b);

const BASE = {
  format: 'tt.policy/v1',
  policy_id: 'p-shop',
  default: 'drop',
  hmac: { kid: 'k1', epoch: '2026-10' },
  sampling: { rate: 0.05 },
  global: { errors: { body: { '$.error.code': 'keep' } } },
};

/** `where` of the diff entry for `hosts.discovery`. */
export const HOSTS_DIFF_KEY = 'hosts.discovery';

/** The change of `hosts.discovery` as a diff entry (none when the mode does not change). */
export function hostsDiff(from: HostsDiscovery, to: HostsDiscovery): DiffEntry[] {
  return from === to ? [] : [{ change: 'changed', where: HOSTS_DIFF_KEY, from, to }];
}

/** Author policy (YAML text) for a set of per-field choices; everything else stays `drop`. `hosts` is written only for `off` (the default is `auto`). */
export function policyYaml(suggestions: PolicySuggestion[], choices: Record<string, PolicyChoice>, hosts: HostsDiscovery = 'auto'): string {
  const services: Record<string, { ops: Record<string, Record<string, Record<string, string>>> }> = {};
  for (const s of suggestions) {
    const c = choices[s.id];
    if (!c || c.action === 'drop') continue;
    const svc = (services[s.service] ??= { ops: {} });
    const op = (svc.ops[s.op] ??= {});
    const part = (op[s.part] ??= {});
    part[s.path] = formatChoice(c);
  }
  return toYaml({ ...BASE, ...(hosts === 'off' ? { hosts: { discovery: 'off' } } : {}), services });
}

export function currentChoices(suggestions: PolicySuggestion[]): Record<string, PolicyChoice> {
  return Object.fromEntries(suggestions.map((s) => [s.id, s.current]));
}

export function diffChoices(suggestions: PolicySuggestion[], from: Record<string, PolicyChoice>, to: Record<string, PolicyChoice>): DiffEntry[] {
  const out: DiffEntry[] = [];
  for (const s of suggestions) {
    const a = from[s.id] ? formatChoice(from[s.id]) : 'drop';
    const b = to[s.id] ? formatChoice(to[s.id]) : 'drop';
    if (a === b) continue;
    out.push({ change: a === 'drop' ? 'added' : b === 'drop' ? 'removed' : 'changed', where: `${s.service} · ${s.op} · ${s.part} · ${s.path}`, from: a, to: b });
  }
  return out;
}

/**
 * True when the diff adds or widens something (keep / hmac / bucket, or `hosts.discovery` off -> auto): needs
 * two people. `auto` -> `off` closes: hosts go back to `host:unlisted`.
 */
export function opensData(diff: DiffEntry[]): boolean {
  return diff.some((e) => {
    if (e.where === HOSTS_DIFF_KEY) return e.to === 'auto';
    // v1.6: dropping, masking (hmac) and codes (sanitizer.md 5.6) let no value out in clear.
    return (e.change === 'added' || e.change === 'changed') && e.to !== undefined && e.to !== 'drop' && e.to !== 'code' && e.to !== 'code(alnum)' && !e.to.startsWith('hmac');
  });
}
