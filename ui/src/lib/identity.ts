// Who the user is (identity.subject, docs/spec/policy.md §7.1 and §7.4): helpers of the «Identità dell'utente» control.
// The server ranks the candidates from the data and decides; these helpers only say how a choice will apply.
import type { IdentityCandidate, IdentitySource } from './api/types';
import { credentialLikeName, identityObserveSafe } from './observe';

/** How a choice applies: at once (observe-safe), or why it opens values; `invalid` when the name is not valid. */
export type IdentityVerdict = 'safe' | 'cookie' | 'bearer' | 'credential' | 'invalid';

const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const COOKIE_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const CLAIM = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
/** Spec v1.18: a dotted path of 1 to 8 members inside a JSON header value (`user.id`). */
export const JSON_PATH = /^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,7}$/;

type SourceLike = { from: string; name: string; claim?: string; jsonPath?: string };

/**
 * The source as the server stores it: header names in lower case, the claim trimmed (absent when empty). A member of a
 * JSON header (`jsonPath`, header only) excludes the claim.
 */
export function normalizeSource(s: IdentitySource): IdentitySource {
  const name = s.from === 'header' ? s.name.trim().toLowerCase() : s.name.trim();
  const jsonPath = s.jsonPath?.trim();
  const claim = s.claim?.trim();
  if (jsonPath) return { from: s.from, name, jsonPath };
  return { from: s.from, name, ...(claim ? { claim } : {}) };
}

export function validSource(s: IdentitySource): boolean {
  const n = normalizeSource(s);
  if (n.jsonPath && (n.from !== 'header' || !JSON_PATH.test(n.jsonPath))) return false;
  return (n.from === 'header' ? HEADER_NAME : COOKIE_NAME).test(n.name) && (!n.claim || CLAIM.test(n.claim));
}

export function identityVerdict(s: IdentitySource): IdentityVerdict {
  const n = normalizeSource(s);
  if (!validSource(n)) return 'invalid';
  if (identityObserveSafe(n.from, n.name, n.claim, n.jsonPath)) return 'safe';
  if (n.from === 'cookie') return 'cookie';
  if (n.name === 'authorization') return 'bearer';
  return 'credential';
}

const norm = (a: SourceLike) => normalizeSource({ from: a.from === 'cookie' ? 'cookie' : 'header', name: a.name, claim: a.claim, jsonPath: a.jsonPath });

/** Same source (header names in any case). */
export function sameSource(a: SourceLike | undefined, b: SourceLike | undefined): boolean {
  if (!a || !b) return false;
  const x = norm(a);
  const y = norm(b);
  return x.from === y.from && x.name === y.name && (x.claim ?? '') === (y.claim ?? '') && (x.jsonPath ?? '') === (y.jsonPath ?? '');
}

/** The source a candidate stands for (a JWT one reads its claim, `sub` by default). */
export function candidateSource(c: IdentityCandidate): IdentitySource {
  return { from: c.from, name: c.name, ...(c.claim || c.jwt ? { claim: c.claim || 'sub' } : {}) };
}

/** The candidates the detection could pick and those it leaves out (each with its reason), in the server's order. */
export function splitCandidates(cands: IdentityCandidate[]): { usable: IdentityCandidate[]; excluded: IdentityCandidate[] } {
  const seen = new Set<string>();
  const usable: IdentityCandidate[] = [];
  const excluded: IdentityCandidate[] = [];
  for (const c of cands) {
    const k = `${c.from}\u0000${c.name.toLowerCase()}\u0000${c.claim ?? ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    // An older server sends no exclusion: a cookie or a credential-like name is still never automatic.
    const ex = c.excluded ?? (c.from === 'cookie' ? 'cookie' : !c.jwt && credentialLikeName(c.name) ? 'credential' : undefined);
    if (ex) excluded.push({ ...c, excluded: ex });
    else usable.push(c);
  }
  return { usable, excluded };
}

/** i18n key and parameters that name a source in words. */
export function sourceText(s: SourceLike): {
  key: 'id.source.header' | 'id.source.jwt' | 'id.source.cookie' | 'w4.id.source.json';
  params: { name: string; claim?: string; path?: string };
} {
  if (s.from === 'cookie') return { key: 'id.source.cookie', params: { name: s.name } };
  if (s.jsonPath) return { key: 'w4.id.source.json', params: { name: s.name, path: s.jsonPath } };
  if (s.claim) return { key: 'id.source.jwt', params: { name: s.name, claim: s.claim } };
  return { key: 'id.source.header', params: { name: s.name } };
}
