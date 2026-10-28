// OIDC step-up for approvals (keyguard.md 3.2, policy.md 5). When keyguard
// verifies approvals with OIDC, an approval, a pack release or a quarantine
// dismissal needs a fresh ID token bound to that change: tt-core answers
// 403 stepup_required and the browser goes to
// GET /api/v1/auth/oidc/stepup?purpose=&ref=&return_to=/. The identity
// provider sends it back to "/?stepup=ok" (or "/?stepup_error=<code>"); the
// verified token stays server side and is consumed by the next identical
// call. The router is hash based and the redirect loses the hash, so the
// call to repeat and the page are kept in sessionStorage meanwhile. The UI
// never sees an ID token.

export type StepUpPurpose = 'policy-approve' | 'pack-publish' | 'quarantine-dismiss';

/** The call to repeat after the step-up. */
export type StepUpPayload =
  | { kind: 'policy-approve'; policyId: string; version: number; reason?: string }
  | { kind: 'pack-publish'; packId: string; reason?: string }
  | { kind: 'quarantine-dismiss'; itemId: string; note?: string };

export interface PendingStepUp {
  purpose: StepUpPurpose;
  ref: string;
  /** location.hash when the step-up started (the page to come back to). */
  hash: string;
  payload: StepUpPayload;
  /** Epoch milliseconds. */
  at: number;
}

export type StepUpReturn = { status: 'ok' } | { status: 'error'; code: string };

export const STEPUP_KEY = 'tt.stepup.pending';
/** The server keeps the verified token for 10 minutes: an older record is useless. */
export const STEPUP_MAX_AGE_MS = 10 * 60 * 1000;

const PURPOSES: StepUpPurpose[] = ['policy-approve', 'pack-publish', 'quarantine-dismiss'];

/** The purpose and ref the server binds the step-up to, for a payload. */
export function bindingOf(p: StepUpPayload): { purpose: StepUpPurpose; ref: string } {
  switch (p.kind) {
    case 'policy-approve':
      return { purpose: p.kind, ref: `${p.policyId}/${p.version}` };
    case 'pack-publish':
      return { purpose: p.kind, ref: p.packId };
    case 'quarantine-dismiss':
      return { purpose: p.kind, ref: p.itemId };
  }
}

/** URL of the step-up start (a browser navigation, never a fetch). */
export function stepUpUrl(purpose: StepUpPurpose, ref: string, returnTo = '/'): string {
  const q = new URLSearchParams({ purpose, ref, return_to: returnTo });
  return `/api/v1/auth/oidc/stepup?${q.toString()}`;
}

/** Reads the result of a step-up from the query string ("?stepup=ok", "?stepup_error=code"). */
export function parseStepUpQuery(search: string): StepUpReturn | null {
  const q = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  const err = q.get('stepup_error');
  if (err !== null) return { status: 'error', code: /^[a-z0-9_]{1,64}$/.test(err) ? err : 'unknown' };
  if (q.get('stepup') === 'ok') return { status: 'ok' };
  return null;
}

/** The search string without the step-up parameters ("" when nothing is left). */
export function stripStepUpQuery(search: string): string {
  const q = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  q.delete('stepup');
  q.delete('stepup_error');
  const s = q.toString();
  return s ? `?${s}` : '';
}

type Store = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function storage(): Store | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

export function savePending(rec: PendingStepUp, s: Store | null = storage()): boolean {
  try {
    if (!s) return false;
    s.setItem(STEPUP_KEY, JSON.stringify(rec));
    return true;
  } catch {
    return false;
  }
}

function valid(v: unknown): v is PendingStepUp {
  if (!v || typeof v !== 'object') return false;
  const r = v as Partial<PendingStepUp>;
  if (typeof r.purpose !== 'string' || !PURPOSES.includes(r.purpose) || typeof r.ref !== 'string' || typeof r.hash !== 'string' || typeof r.at !== 'number') return false;
  const p = r.payload as StepUpPayload | undefined;
  if (!p || p.kind !== r.purpose) return false;
  const b = bindingOf(p);
  return b.ref === r.ref;
}

/** Returns the pending record when it is well formed and younger than STEPUP_MAX_AGE_MS; never removes it. */
export function peekPending(now: number, s: Store | null = storage()): PendingStepUp | null {
  try {
    const raw = s?.getItem(STEPUP_KEY);
    if (!raw) return null;
    const v: unknown = JSON.parse(raw);
    if (!valid(v)) return null;
    if (v.at > now + 60_000 || now - v.at > STEPUP_MAX_AGE_MS) return null;
    return v;
  } catch {
    return null;
  }
}

export function clearPending(s: Store | null = storage()): void {
  try {
    s?.removeItem(STEPUP_KEY);
  } catch {
    /* ignore */
  }
}

/** Reads and removes the pending record. */
export function takePending(now: number, s: Store | null = storage()): PendingStepUp | null {
  const p = peekPending(now, s);
  clearPending(s);
  return p;
}

// The binding of the last completed step-up: a call repeated after it that is
// answered stepup_required again (the change moved meanwhile, or the server
// lost the token) must not loop through the identity provider.
let recent: { key: string; at: number } | null = null;
const RECENT_MS = 60_000;

export function noteStepUpDone(purpose: StepUpPurpose, ref: string, now = Date.now()): void {
  recent = { key: `${purpose}\0${ref}`, at: now };
}

/** False right after a step-up for the same change completed (the caller then reports the error). */
export function shouldStepUp(purpose: StepUpPurpose, ref: string, now = Date.now()): boolean {
  return !(recent && recent.key === `${purpose}\0${ref}` && now - recent.at < RECENT_MS);
}

/** Saves the call to repeat and sends the browser to the step-up. */
export function beginStepUp(payload: StepUpPayload, w: Pick<Window, 'location'> = window, now = Date.now(), s: Store | null = storage()): void {
  const { purpose, ref } = bindingOf(payload);
  savePending({ purpose, ref, hash: w.location.hash, payload, at: now }, s);
  w.location.assign(stepUpUrl(purpose, ref, '/'));
}

/**
 * On app load: when the URL carries a step-up result, removes it from the address bar, puts back the hash
 * saved before the step-up and returns the result with the pending call (null when it expired or is
 * missing). Must run before the router starts.
 */
export function consumeStepUpReturn(
  w: Pick<Window, 'location' | 'history'> = window,
  now = Date.now(),
  s: Store | null = storage(),
): { result: StepUpReturn; pending: PendingStepUp | null } | null {
  const result = parseStepUpQuery(w.location.search);
  if (!result) return null;
  const pending = takePending(now, s);
  if (pending && result.status === 'ok') noteStepUpDone(pending.purpose, pending.ref, now);
  const hash = pending?.hash || w.location.hash;
  try {
    w.history.replaceState(w.history.state, '', w.location.pathname + stripStepUpQuery(w.location.search) + hash);
  } catch {
    /* ignore */
  }
  return { result, pending };
}
