// Where the values already come out in clear as codes (usability test #5, M3). States and codes (`DELIVERED`,
// `card_declined`) leave the service with the `code` action and no approval (sanitizer.md 5.6): when the active policy
// of a group has fields with `code`, a message must never ask for «keep approved» for the statuses, and the rules with
// states do exist. The decision reads the author policy of the active version, never a value of the traffic.
import type { PolicyVersion, Rule } from './api/types';

/** A rule line of the author policy: `<field>: code`, in any nesting (quotes and a trailing comment allowed). */
const CODE_LINE = /^\s*(?:-\s*)?(?:"([^"]+)"|'([^']+)'|([^\s:#][^:#]*?))\s*:\s*["']?code["']?\s*(?:#.*)?$/;

/** The fields (keys) the author policy writes as `code`, once each. */
export function codeFieldsOf(authorYaml: string | undefined): string[] {
  const out = new Set<string>();
  for (const line of (authorYaml ?? '').split('\n')) {
    const m = CODE_LINE.exec(line);
    if (m) out.add((m[1] ?? m[2] ?? m[3]).trim());
  }
  return [...out];
}

/** The active version of each policy of the groups (`null`: every group), newest first. */
export function activePolicies(policies: readonly PolicyVersion[], groups: readonly string[] | null): PolicyVersion[] {
  return policies
    .filter((p) => p.status === 'active' && (!groups || (p.groups ?? []).some((g) => groups.includes(g))))
    .sort((a, b) => b.version - a.version);
}

/** The fields that already come out as codes in the active policies of the groups. */
export function codeFieldsOfGroups(policies: readonly PolicyVersion[], groups: readonly string[] | null): string[] {
  return [...new Set(activePolicies(policies, groups).flatMap((p) => codeFieldsOf(p.yamlAfter)))];
}

/** A rule that moves an object through states (a lifecycle): an effect that sets or creates an entity, not a rejected rule. */
export function hasLifecycleRule(rules: readonly Pick<Rule, 'status' | 'kind' | 'effects'>[]): boolean {
  return rules.some((r) => r.status !== 'rejected' && r.kind === 'causal' && r.effects.some((e) => e.kind === 'set'));
}

/** What the messages about statuses may say. */
export interface StatesFacts {
  /** Some fields already come out as codes: the statuses are in clear without an approval. */
  inClear: boolean;
  fields: string[];
  /** Rules with a lifecycle exist (the miner found states). */
  lifecycle: boolean;
}

export function statesFacts(policies: readonly PolicyVersion[], groups: readonly string[] | null, rules: readonly Pick<Rule, 'status' | 'kind' | 'effects'>[] | null): StatesFacts {
  const fields = codeFieldsOfGroups(policies, groups);
  return { inClear: fields.length > 0, fields, lifecycle: rules ? hasLifecycleRule(rules) : false };
}

/**
 * The fields a draft opens (`keep`, finer `bucket`) that are not codes: the places where values in clear really wait
 * for an approval. They come from the diff of the draft (`where`: the location of the field in the policy).
 */
export function openedFieldsOf(draft: Pick<PolicyVersion, 'valueReasons'>): string[] {
  return [...new Set(draft.valueReasons.filter((r) => r.code === 'keep' || r.code === 'bucket').map((r) => fieldOfLocation(r.where)))].filter(Boolean);
}

/** The field of a rule location such as `services.menu.ops.GET /menu.response.body.$.cuisine` (`$.cuisine` → `cuisine`). */
export function fieldOfLocation(where: string): string {
  const m = /\.(?:request|response|errors)\.(?:body|path|query|headers|cookies)\.(.+)$/.exec(where);
  return (m ? m[1] : where).replace(/^\$\.?/, '').trim();
}
