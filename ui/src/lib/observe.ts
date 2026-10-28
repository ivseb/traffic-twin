// The observe phase (docs/spec/policy.md §7): which changes open values, how fields are grouped for the bulk review,
// and how a masked field is said in plain words. The server decides (tt-core, then keyguard on its own); the helpers
// here mirror its rules for the mock adapter and for hints shown before the server answers.
import type { DiffEntry, MaskedField, PolicyChoice, PolicySuggestion, ValueReason } from './api/types';
import { formatChoice, HOSTS_DIFF_KEY } from './policy';

// Who the user is (identity.subject, policy.md §7.1): the value leaves only as a token, so any request header that is
// not a credential is observe-safe, whatever its name. Mirrors policy.IdentityObserveSafe and policy.CredentialLikeName
// (generic credential words, never application header names).
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key'];
const CREDENTIAL_PARTS = ['token', 'secret', 'passw', 'pwd', 'apikey', 'api-key', 'api_key', 'session', 'csrf', 'xsrf', 'signature', 'credential', 'auth', 'cookie', 'nonce'];
const CREDENTIAL_WORDS = ['key', 'sig', 'sid', 'pin', 'otp', 'pass', 'jwt', 'bearer', 'code'];

/** The name looks like it carries a credential (token, secret, password, key, session, auth, csrf, signature...). */
export function credentialLikeName(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (CREDENTIAL_HEADERS.includes(n) || CREDENTIAL_PARTS.some((p) => n.includes(p))) return true;
  return n.split(/[^a-z0-9]+/).some((w) => CREDENTIAL_WORDS.includes(w));
}

/**
 * Choosing this source applies at once, without approvals: any request header that is not a credential (with or
 * without a JWT claim), or any claim of the bearer JWT in Authorization. Cookies, credential headers and, without a
 * claim, Authorization and credential-like names open values. Spec v1.18: a member of a JSON header (`jsonPath`) counts
 * like a claim for a credential-like name (only the token of that member leaves); Authorization still needs a claim.
 */
export function identityObserveSafe(from: string, name: string, claim?: string, jsonPath?: string): boolean {
  if (from !== 'header') return false;
  const n = name.trim().toLowerCase();
  const c = (claim ?? '').trim();
  const j = (jsonPath ?? '').trim();
  if (n === 'authorization') return c !== '';
  if (CREDENTIAL_HEADERS.includes(n)) return false;
  if (credentialLikeName(n)) return c !== '' || j !== '';
  return n !== '';
}

const kindOf = (spec: string | undefined) => (spec ?? 'drop').replace(/\(.*$/, '').trim();

/** Bucket bounds of a `bucket(num, [..])` spec, or null. */
function bounds(spec: string): string[] | null {
  const m = /^bucket\(num,\s*\[(.*)\]\)$/.exec(spec.trim());
  return m ? m[1].split(',').map((x) => x.trim()).filter(Boolean) : null;
}

/**
 * The value reasons of a diff (codes as the server's `value_reasons`). Mirrors policy.ClassifyValues for the changes
 * the console makes: a field to keep or to a (finer) bucket, `hosts.discovery` off -> auto, an identity that is not
 * observe-safe (identityObserveSafe). Removing keep or bucket, drop and hmac never open values.
 */
export function valueReasonsOf(diff: DiffEntry[], identity?: { from: string; name: string; claim?: string }): ValueReason[] {
  const out: ValueReason[] = [];
  for (const e of diff) {
    if (e.where === HOSTS_DIFF_KEY) {
      if (e.to === 'auto') out.push({ code: 'hosts_discovery', where: e.where });
      continue;
    }
    if (e.where === 'identity.subject' || e.where === 'sampling.rate') continue;
    const to = kindOf(e.to);
    const from = kindOf(e.from);
    if (to === 'keep' && from !== 'keep') out.push({ code: 'keep', where: e.where });
    if (to === 'bucket' && from !== 'keep') {
      const nb = bounds(e.to ?? '');
      const ob = from === 'bucket' ? bounds(e.from ?? '') : null;
      if (!(nb && ob && nb.every((b) => ob.includes(b)))) out.push({ code: 'bucket', where: e.where });
    }
  }
  if (identity && !identityObserveSafe(identity.from, identity.name, identity.claim)) out.push({ code: 'identity', where: 'identity.subject' });
  return out;
}

/** Groups of the bulk review («Rivedi in blocco»): one action per group of fields. */
export type FieldGroup = 'ids' | 'states' | 'numbers' | 'dates' | 'personal' | 'other';
export const FIELD_GROUPS: FieldGroup[] = ['ids', 'states', 'numbers', 'dates', 'personal', 'other'];

const GROUP_OF: Record<string, FieldGroup> = {
  id: 'ids',
  path_id: 'ids',
  enum_name: 'states',
  enum: 'states',
  flag: 'states',
  path_word: 'states',
  amount: 'numbers',
  quantity: 'numbers',
  number: 'numbers',
  time: 'dates',
  timestamp: 'dates',
  personal_format: 'personal',
  personal_name: 'personal',
  credential: 'personal',
};

/** The group of a field, from the assistant's reason (or, without one, from its proposal). */
export function fieldGroup(s: Pick<PolicySuggestion, 'reasonCode'> & Partial<Pick<PolicySuggestion, 'suggestion'>>): FieldGroup {
  const g = GROUP_OF[s.reasonCode ?? ''];
  if (g) return g;
  if (s.reasonCode || !s.suggestion) return 'other';
  switch (s.suggestion.action) {
    case 'hmac':
      return 'ids';
    case 'keep':
    case 'code':
      return 'states';
    case 'bucket':
      return /^(year|month|day|hour)$/.test(s.suggestion.arg ?? '') ? 'dates' : 'numbers';
  }
  return 'other';
}

/** The action a group takes when the person picks "the proposal": the assistant's own, field by field. */
export type GroupAction = 'keep-current' | 'proposal' | 'drop' | 'hmac';

/**
 * The assistant's proposal for a field, as the person gets it by default. A field that already is `code` (values in
 * clear with the shape of a code, no approval: sanitizer.md 5.6) is never moved to `keep`, which would let any value
 * out and ask for two approvals: the proposal is the field as it is (usability test #5, M2).
 */
export function safeProposal(s: Pick<PolicySuggestion, 'current' | 'suggestion'>): PolicyChoice {
  if (s.current.action === 'code' && s.suggestion.action === 'keep') return { ...s.current };
  return { ...s.suggestion };
}

/** What the group action makes of one field (a `code` field only ever goes to `drop`, and only when asked). */
export function applyGroupAction(s: PolicySuggestion, a: GroupAction): PolicyChoice {
  switch (a) {
    case 'proposal':
      return safeProposal(s);
    case 'drop':
      return { action: 'drop' };
    case 'hmac':
      if (s.current.action === 'code') return { ...s.current };
      return s.suggestion.action === 'hmac' ? { ...s.suggestion } : { action: 'hmac', arg: s.current.action === 'hmac' ? s.current.arg : 'id' };
  }
  return { ...s.current };
}

/** True when moving a field from `from` to `to` lets values out in clear beyond observe-safe (needs approvals). */
export function opensField(from: PolicyChoice, to: PolicyChoice): boolean {
  return valueReasonsOf([{ change: 'changed', where: 'field', from: formatChoice(from), to: formatChoice(to) }]).length > 0;
}

/** True when the assistant proposes `keep` for a field that already is `code`: the bulk review leaves it alone. */
export const keepsCode = (s: Pick<PolicySuggestion, 'current' | 'suggestion'>): boolean => s.current.action === 'code' && s.suggestion.action === 'keep';

/** The actions offered for a group (drop and the current state always; hmac only where it makes sense). */
export function groupActions(g: FieldGroup): GroupAction[] {
  if (g === 'personal') return ['keep-current', 'drop'];
  if (g === 'ids') return ['keep-current', 'proposal', 'drop'];
  return ['keep-current', 'proposal', 'hmac', 'drop'];
}

/** Plain words of a masked field: what it is, where it is, which token family. */
export function maskedWhere(m: MaskedField): { field: string; where: string } {
  const field = m.kind === 'body' ? m.field.replace(/^\$\.?/, '') || m.field : m.field;
  const where = m.op ? `${m.op}` : m.service ? m.service : '';
  return { field, where };
}
