// The console's Group/Team filter (header). A console is shared by several teams: the identity of an observed service
// is (group, service), and the server filters every list by group (`?group=a,b`): services, hosts, contracts,
// policies, archetypes, worlds, packs, rules, gaps, alerts, quarantine. The pages pass `scopeGroups()` to the API
// (null: no parameter) and reload when the filter changes.
//
//   value ''        every group (default for an administrator)
//   value '@mine'   the groups the user works with: tokens created, policies proposed (default otherwise, also before
//                   the user has a group: then the lists show every group with a note, and the home page counts nothing)
//   value '<name>'  one group
//
// The choice is kept in this browser (localStorage 'tt.group').
import { api, type Rule, type ScopeData } from './api';
import { isAdmin } from './rbac';
import { href } from './router';
import { session } from './stores.svelte';

const KEY = 'tt.group';

function readSaved(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export const scope = $state<{ value: string | null; data: ScopeData | null; loading: boolean; loaded: boolean }>({ value: readSaved(), data: null, loading: false, loaded: false });

export const ALL = '';
export const MINE = '@mine';

/** The effective value: the saved choice, else the default of the role. */
export function scopeValue(): string {
  if (scope.value !== null) return scope.value;
  if (isAdmin(session.user)) return ALL;
  // «I miei gruppi» for everyone else, as the guide says (usability test #4, m2): never other teams' counts by default.
  return MINE;
}

/** The filter is known: an explicit choice, an administrator, or the scope data read (or failed). */
export function scopeReady(): boolean {
  const v = scopeValue();
  return v !== MINE || scope.data !== null || scope.loaded;
}

/** «I miei gruppi» while the user works with no group yet (no token created, no policy proposed). */
export function scopeNoGroups(): boolean {
  return scopeValue() === MINE && scope.loaded && (scope.data?.mine.length ?? 0) === 0;
}

export function setScope(v: string): void {
  scope.value = v;
  try {
    localStorage.setItem(KEY, v);
  } catch {
    /* storage unavailable: the choice lasts for this session */
  }
}

export async function loadScope(): Promise<void> {
  if (scope.loading) return;
  scope.loading = true;
  try {
    scope.data = await api.scope.get();
  } catch {
    scope.data = null;
  } finally {
    scope.loading = false;
    scope.loaded = true;
  }
}

/** Groups the filter keeps, or null for every group. One named group needs no scope data. */
export function scopeGroups(): string[] | null {
  const v = scopeValue();
  if (v === ALL) return null;
  if (v !== MINE) return [v];
  if (!scope.data || scope.data.mine.length === 0) return null;
  return [...scope.data.mine];
}

/** The rows of more than one group are listed together: pages show a Group column / badge. */
export function showGroupColumn(): boolean {
  const gs = scopeGroups();
  return !gs || gs.length > 1;
}

/** True when a row of `groups` is inside the filter (always true without one). Rows without groups are outside a filter. */
export function inGroups(groups: readonly (string | undefined)[] | string | undefined): boolean {
  const gs = scopeGroups();
  if (!gs) return true;
  const list = typeof groups === 'string' || groups === undefined ? [groups] : groups;
  return list.some((g) => g !== undefined && gs.includes(g));
}

/**
 * True when a service name belongs to the filtered groups (always true without a filter). Only for data that carries
 * no group (the miner's diagnostics): lists of the group API are filtered by the server.
 */
export function inScope(service: string | undefined): boolean {
  const gs = scopeGroups();
  if (!gs || !service) return true;
  const of = scope.data?.services[service];
  return !!of && of.some((g) => gs.includes(g));
}

/** The groups of the user (tokens created, policies proposed). */
export function myGroups(): string[] {
  return scope.data?.mine ?? [];
}

/** A short label of the active filter, for page subtitles ("" without a filter). */
export function scopeLabel(): string {
  const gs = scopeGroups();
  return gs ? gs.join(', ') : '';
}

/** Link to the contract of one service of one group (the row's group travels as `?group=`). */
export function contractHref(name: string, group?: string, query: Record<string, string> = {}): string {
  return href('/contracts/service/:name', { name }, { ...query, group: group ?? '' });
}

/** Services a rule involves: its cause and the targets of its effects. */
export function ruleServices(r: Pick<Rule, 'cause' | 'effects'>): string[] {
  const out = new Set<string>();
  if (r.cause?.service) out.add(r.cause.service);
  for (const e of r.effects) if (e.target) out.add(e.target);
  return [...out];
}
