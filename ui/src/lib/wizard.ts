// State of the onboarding wizard kept in the tab (sessionStorage), so that a reload or a visit to another page
// (glossary, policies) resumes where the person was. Only decisions and identifiers: never a value of the traffic.
// sessionStorage ends with the tab; the enrollment token in it is one-time and expires within the hour.

import type { AssistService, EnrollmentToken, HostsDiscovery, PolicyChoice, PolicyVersion, SourceChoice } from './api/types';

export interface WizardState {
  step: number;
  choice: SourceChoice | null;
  group: string;
  svcNames: string;
  samplingRate: string;
  token: EnrollmentToken | null;
  starter: PolicyVersion | null;
  twin: Record<string, boolean>;
  twinBefore: Record<string, boolean>;
  choices: Record<string, PolicyChoice>;
  include: Record<string, boolean>;
  svcName: Record<string, string>;
  svcScheme: Record<string, '' | 'http' | 'https'>;
  svcBase: Record<string, string>;
  idMode: 'none' | 'pick';
  idFrom: 'header' | 'cookie';
  idName: string;
  idClaim: string;
  proposal: PolicyVersion | null;
  hostsCurrent: HostsDiscovery;
  hostsMode: HostsDiscovery;
  hostsLoaded: boolean;
}

const KEY = 'tt.wizard.v1';

function store(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

export function loadWizard(): WizardState | null {
  try {
    const raw = store()?.getItem(KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as WizardState;
    if (typeof s !== 'object' || s === null || typeof s.step !== 'number' || s.step < 0 || s.step > 5 || typeof s.group !== 'string') return null;
    // An expired token cannot enroll anything: the steps that need it start again.
    if (s.token && Date.parse(s.token.expiresAt) < Date.now() && s.step <= 2) return { ...s, step: 0, token: null };
    return s;
  } catch {
    return null;
  }
}

export function saveWizard(s: WizardState): void {
  try {
    store()?.setItem(KEY, JSON.stringify(s));
  } catch {
    /* storage full or disabled: the wizard still works, it just does not resume */
  }
}

export function clearWizard(): void {
  try {
    store()?.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------- policy assistant: "Declare in the policy"

/**
 * Default of the "Declare in the policy" checkbox of an assistant block. A declared service stays in the policy; a
 * host not declared yet follows the server's `preselect` (true only for hosts this group's sources called), and is
 * never checked when stale (no recent calls). An older server without `preselect` keeps the old default (checked).
 */
export function declareDefault(s: Pick<AssistService, 'declared' | 'preselect' | 'stale'>): boolean {
  if (s.declared) return true;
  if (s.stale) return false;
  return s.preselect ?? true;
}

/**
 * The blocks to show: a block folded into another one (its pattern is in that block's `mergedPatterns`) is not shown
 * separately; the other block names it in a note.
 */
export function visibleAssistServices<T extends Pick<AssistService, 'service' | 'hostPattern' | 'mergedPatterns'>>(services: readonly T[]): T[] {
  const merged = new Set(services.flatMap((s) => s.mergedPatterns ?? []));
  if (merged.size === 0) return [...services];
  return services.filter((s) => {
    const pattern = s.hostPattern ?? (s.service.startsWith('host:') ? s.service.slice(5) : undefined);
    return !(pattern && merged.has(pattern) && !(s.mergedPatterns ?? []).includes(pattern));
  });
}

const DECLARE_KEY = 'tt.assist.declare.v1';

function readDeclare(): Record<string, boolean> {
  try {
    const raw = store()?.getItem(DECLARE_KEY);
    const v = raw ? (JSON.parse(raw) as unknown) : null;
    return v && typeof v === 'object' ? (v as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}

/** The person's own "Declare in the policy" choice for a service of a policy, if any (kept for the tab's session). */
export function rememberedDeclare(policyId: string, service: string): boolean | undefined {
  const v = readDeclare()[`${policyId}\u0000${service}`];
  return typeof v === 'boolean' ? v : undefined;
}

/** Keeps the person's choice across reloads of the assistant (new versions of the same policy included). */
export function rememberDeclare(policyId: string, service: string, value: boolean): void {
  try {
    const all = readDeclare();
    all[`${policyId}\u0000${service}`] = value;
    store()?.setItem(DECLARE_KEY, JSON.stringify(all));
  } catch {
    /* storage unavailable: the choice lasts until the assistant reloads */
  }
}

// ---------------------------------------------------------------- the enrollment token: only what is not secret
// The secret of an enrollment token is shown once (the server keeps its hash, never the value): it stays in the tab
// (sessionStorage, above) and nowhere else. What survives a new tab or a browser restart is the metadata: for which
// group and kind, when it was created and when it expires. With it the wizard can say «hai già un token, creato alle
// HH:MM, scade alle HH:MM: il segreto non si può rivedere, rigeneralo» instead of starting again as if nothing happened.

export interface TokenMeta {
  tokenId: string;
  group: string;
  choice: SourceChoice;
  createdAt: string;
  expiresAt: string;
}

const META_KEY = 'tt.wizard.token.v1';

function persistent(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

export function loadTokenMeta(): TokenMeta | null {
  try {
    const raw = persistent()?.getItem(META_KEY);
    if (!raw) return null;
    const m = JSON.parse(raw) as TokenMeta;
    const ok = (v: unknown) => typeof v === 'string' && v !== '';
    if (typeof m !== 'object' || m === null || !ok(m.tokenId) || !ok(m.group) || !ok(m.choice) || !ok(m.createdAt) || !ok(m.expiresAt)) return null;
    if (Number.isNaN(Date.parse(m.createdAt)) || Number.isNaN(Date.parse(m.expiresAt))) return null;
    // A token expired for more than a day is not worth a reminder.
    if (Date.parse(m.expiresAt) < Date.now() - 24 * 3600_000) return null;
    return m;
  } catch {
    return null;
  }
}

export function saveTokenMeta(t: Pick<EnrollmentToken, 'tokenId' | 'group' | 'choice' | 'expiresAt'> & { createdAt?: string }): TokenMeta {
  const m: TokenMeta = { tokenId: t.tokenId, group: t.group, choice: t.choice, createdAt: t.createdAt ?? new Date().toISOString(), expiresAt: t.expiresAt };
  try {
    persistent()?.setItem(META_KEY, JSON.stringify(m));
  } catch {
    /* storage unavailable: the reminder just does not survive */
  }
  return m;
}

export function clearTokenMeta(): void {
  try {
    persistent()?.removeItem(META_KEY);
  } catch {
    /* ignore */
  }
}

/** HH:MM in the local time zone, for «creato alle 10:12, scade alle 11:12». */
export function clockTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** The group name suggested by a service name: `library-loans-api` -> `library-loans`. */
export function suggestGroup(serviceNames: string): string {
  const first = serviceNames.split(/[\s,]+/).filter(Boolean)[0] ?? '';
  const base = first.toLowerCase().replace(/[._]+/g, '-').replace(/-(api|service|svc|server|backend)$/, '');
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(base) ? base : '';
}
