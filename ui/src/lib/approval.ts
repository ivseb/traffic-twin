// The «values in clear» step made visible (usability test #4, B1). Rules with states, linked fields and realistic mock
// values need the status and category values in clear: a policy change that opens values, which another person has
// to approve. The wizard («In ascolto») and the Panoramica show a «Prossimo passo» card for such a draft.
import type { GroupApprover, PolicyVersion } from './api';
import { href } from './router';

/**
 * The drafts that open values and still wait for approvals, newest first and one per group, of the groups `groups`
 * (null: every group).
 */
export function pendingOpeningDrafts(policies: readonly PolicyVersion[], groups: readonly string[] | null): PolicyVersion[] {
  const waiting = policies
    .filter((p) => p.status === 'draft' && p.opensValues && p.approvalsRequired > 0 && p.approvals.length < p.approvalsRequired && p.origin !== 'starter')
    .filter((p) => !groups || (p.groups ?? []).some((g) => groups.includes(g)))
    .sort((a, b) => b.version - a.version);
  const seen = new Set<string>();
  const out: PolicyVersion[] = [];
  for (const p of waiting) {
    const key = (p.groups ?? [])[0] ?? p.policyId;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

/** The link a colleague opens to see the draft (Sorgenti > Policy with its panel open). */
export function draftLink(v: Pick<PolicyVersion, 'policyId' | 'version'>, origin: string): string {
  return origin + href('/sources', {}, { tab: 'policy', draft: `${v.policyId}@${v.version}` });
}

/** Who to ask: the approvers other than the user (an admin last), as names to show. */
export function approverNames(list: readonly GroupApprover[]): { names: string[]; adminOnly: boolean } {
  const others = list.filter((a) => !a.self);
  const approvers = others.filter((a) => a.roles.includes('policy-approver'));
  const shown = (approvers.length ? approvers : others).map((a) => a.displayName || a.name);
  return { names: [...new Set(shown)], adminOnly: approvers.length === 0 && others.length > 0 };
}

/**
 * Who may take a pending draft back: the person who proposed it, or an administrator (usability test #5, major 2).
 * Names are compared as the server writes them (username, or the display name of an OIDC account).
 */
export function canWithdraw(v: Pick<PolicyVersion, 'status' | 'proposedBy'>, user: { username?: string; displayName?: string } | null | undefined, admin: boolean): boolean {
  if (v.status !== 'draft') return false;
  if (admin) return true;
  const by = v.proposedBy;
  return !!by && !!user && (by === user.username || by === user.displayName);
}

/** The origin of the console for links in messages ('' outside a browser). */
export function consoleOrigin(): string {
  return typeof window === 'undefined' ? '' : window.location.origin + window.location.pathname;
}
