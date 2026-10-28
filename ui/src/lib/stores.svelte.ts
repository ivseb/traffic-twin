import { api, ApiError, onUnauthorized, type Permission, type SystemStatus, type User } from './api';
import { userCan } from './rbac';
import { loc, navigate } from './router.svelte';
import { i18n, tk } from './i18n/index.svelte';
import type { PendingStepUp, StepUpReturn } from './stepup';

// ------------------------------------------------------------------ session

export const session = $state<{ user: User | null; status: SystemStatus | null; ready: boolean }>({ user: null, status: null, ready: false });

export async function initSession(): Promise<void> {
  try {
    session.status = await api.system.status();
    session.user = session.status.initialized ? await api.auth.me() : null;
    // The version (footer) is served to signed-in users only.
    if (session.user) session.status = await api.system.status();
  } catch {
    session.user = null;
  } finally {
    session.ready = true;
  }
}

export function can(perm: Permission): boolean {
  return userCan(session.user, perm);
}

export async function doLogin(username: string, password: string): Promise<void> {
  session.user = await api.auth.login({ username, password });
  void refreshStatus().catch(() => undefined);
}
export async function doSso(): Promise<void> {
  session.user = await api.auth.ssoLogin();
}
export async function doLogout(): Promise<void> {
  await api.auth.logout();
  session.user = null;
  navigate('/login');
}
export async function refreshStatus(): Promise<void> {
  session.status = await api.system.status();
}

/**
 * Errors that name services and rules (the server's `details`): the action in the console's language, with the names.
 * A pack whose rules use a service that is not in it says which service, which rules, and what to do.
 */
function detailedMessage(e: ApiError): string {
  const d = e.details;
  if (!d?.length) return '';
  const parts: string[] = [];
  for (const x of d) {
    switch (e.serverCode) {
      case 'missing_service': {
        const rules = x.rules ?? [];
        const what = rules.length ? rules : (x.entities ?? []);
        if (x.service && what.length) parts.push(tk(rules.length === 1 ? 'err.missing_service.rule' : rules.length ? 'err.missing_service.rules' : 'err.missing_service.entities', { service: x.service, what: what.join(', ') }));
        break;
      }
      case 'rule_out_of_scope':
        if (x.rule && x.services?.length) parts.push(tk('err.rule_out_of_scope.detail', { rule: x.rule, services: x.services.join(', ') }));
        break;
      case 'unknown_service':
        if (x.service) parts.push(tk('err.unknown_service.detail', { service: x.service }));
        break;
      case 'mixed_groups':
        if (x.service) parts.push(tk('err.mixed_groups.detail', { service: x.service, groups: (x.groups ?? []).join(', ') || '—' }));
        break;
      case 'no_usable_rules':
        if (x.rule && x.reason === 'out_of_scope' && x.services?.length) parts.push(tk('err.no_usable_rules.out_of_scope', { rule: x.rule, services: x.services.join(', ') }));
        else if (x.rule) parts.push(tk('err.no_usable_rules.unusable', { rule: x.rule, detail: x.detail ?? '—' }));
        break;
    }
  }
  if (e.serverCode === 'mixed_groups' && parts.length) parts.unshift(tk('err.mixed_groups'));
  if (e.serverCode === 'no_usable_rules' && parts.length) {
    parts.unshift(tk('err.no_usable_rules'));
    parts.push(tk('err.no_usable_rules.fix'));
  }
  return parts.join(' ');
}

/** Readable text of an error: our translation of the server's code when we have one, its own message otherwise. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    const detailed = detailedMessage(e);
    if (detailed) return detailed;
    const byServer = e.serverCode ? tk(`err.${e.serverCode}`, undefined, '') : '';
    if (byServer) return byServer;
    const byCode = tk(`err.code.${e.code}`, undefined, '');
    if (byCode) return byCode;
    // A server code without a translation: never show the server's English text in another language.
    if (e.serverCode && i18n.lang !== 'en') return tk('err.untranslated', { code: e.serverCode });
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return String(e);
}

// The server forgot the session (expired, revoked, logged out elsewhere): go back to the login page,
// which returns here afterwards. Several parallel calls may fail together: act once.
let leaving = false;
onUnauthorized(() => {
  if (leaving || !session.user) return;
  leaving = true;
  const path = loc.path;
  session.user = null;
  navigate('/login', path !== '/' && path !== '/login' && path !== '/setup' ? { next: path } : {}, true);
  setTimeout(() => (leaving = false), 500);
});

/** Where to go after login, honoring ?next=. */
export function afterLoginPath(): string {
  const next = loc.query.next;
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/login') ? next : '/home';
}

// ------------------------------------------------------------------ theme

export type ThemeChoice = 'auto' | 'light' | 'dark';

function readTheme(): ThemeChoice {
  try {
    const v = localStorage.getItem('tt.theme');
    if (v === 'light' || v === 'dark') return v;
  } catch {
    /* ignore */
  }
  return 'auto';
}

export const theme = $state<{ choice: ThemeChoice }>({ choice: typeof localStorage === 'undefined' ? 'auto' : readTheme() });

export function applyTheme(): void {
  const root = document.documentElement;
  if (theme.choice === 'auto') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', theme.choice);
}

export function setTheme(choice: ThemeChoice): void {
  theme.choice = choice;
  try {
    if (choice === 'auto') localStorage.removeItem('tt.theme');
    else localStorage.setItem('tt.theme', choice);
  } catch {
    /* ignore */
  }
  applyTheme();
}

// ------------------------------------------------------------------ toasts

export interface Toast {
  id: number;
  tone: 'success' | 'danger' | 'info' | 'warning';
  text: string;
}
/** `hold`: the pointer or the keyboard focus is on the toasts; they stay until it leaves (WCAG 2.2.1, 2.2.2). */
export const toasts = $state<{ items: Toast[]; hold: boolean }>({ items: [], hold: false });
let toastSeq = 0;

export function toast(text: string, tone: Toast['tone'] = 'success', ms = 4500): void {
  const id = ++toastSeq;
  toasts.items.push({ id, tone, text });
  const expire = (): void => {
    if (toasts.hold) setTimeout(expire, 1000);
    else dismissToast(id);
  };
  setTimeout(expire, ms);
}
export function dismissToast(id: number): void {
  const i = toasts.items.findIndex((t) => t.id === id);
  if (i >= 0) toasts.items.splice(i, 1);
}
export function toastError(e: unknown): void {
  toast(errorMessage(e), 'danger', 7000);
}

// ------------------------------------------------------------------ OIDC step-up of approvals

/** Bumped when a call repeated after a step-up completed: pages showing approvals reload. */
export const stepUpDone = $state<{ tick: number }>({ tick: 0 });

/**
 * Back from the identity provider (see lib/stepup.ts): repeats the saved call, which consumes the verified
 * token kept by tt-core, or explains why the step-up failed.
 */
export async function resumeStepUp(r: { result: StepUpReturn; pending: PendingStepUp | null }): Promise<void> {
  if (r.result.status === 'error') {
    toast(tk(`stepup.err.${r.result.code}`, undefined, '') || tk('stepup.err.other'), 'danger', 7000);
    return;
  }
  if (!r.pending) {
    toast(tk('stepup.expired'), 'warning', 7000);
    return;
  }
  if (!session.user) return;
  const p = r.pending.payload;
  try {
    switch (p.kind) {
      case 'policy-approve': {
        const v = await api.policies.approve(p.policyId, p.version, p.reason);
        toast(v.status === 'active' ? tk('pol.activated', { v: v.version }) : tk('pol.approved'));
        break;
      }
      case 'pack-publish': {
        const pub = await api.publications.publish(p.packId, p.reason ? { reason: p.reason } : undefined);
        toast(tk('pub.released', { name: pub.packId }));
        break;
      }
      case 'quarantine-dismiss': {
        const q = await api.quarantine.resolve(p.itemId, 'dismiss', p.note);
        toast(q.state === 'resolved' ? tk('qu.done') : tk('qu.pending'));
        break;
      }
    }
    stepUpDone.tick++;
  } catch (e) {
    toastError(e);
  }
}

// ------------------------------------------------------------------ help, palette, banner

export const ui = $state<{ helpOpen: boolean; helpPage: string; paletteOpen: boolean; shortcutsOpen: boolean; bannerHidden: boolean; seenTick: number }>({
  helpOpen: false,
  helpPage: 'onboarding',
  paletteOpen: false,
  shortcutsOpen: false,
  bannerHidden: false,
  seenTick: 0,
});

export function openHelp(page?: string): void {
  if (page) ui.helpPage = page;
  ui.helpOpen = true;
}

/** First-visit hints: remembered per page in this browser. */
export function seen(page: string): boolean {
  void ui.seenTick;
  try {
    return localStorage.getItem(`tt.seen.${page}`) === '1';
  } catch {
    return false;
  }
}
export function markSeen(page: string): void {
  try {
    localStorage.setItem(`tt.seen.${page}`, '1');
  } catch {
    /* ignore */
  }
  ui.seenTick++;
}
