import type { Component } from 'svelte';
import type { RouteDef } from './lib/router';
import type { IconName } from './components/Icon.svelte';
import type { MsgKey } from './lib/i18n/index.svelte';

export interface RouteInfo {
  id: string;
  title: MsgKey;
  /** Page guide shown by the Help drawer. */
  guide: string;
  public?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  load: () => Promise<{ default: Component<any> }>;
}

const r = (pattern: string, id: string, title: MsgKey, load: RouteInfo['load'], opts: { public?: boolean; guide?: string } = {}): RouteDef<RouteInfo> => ({
  pattern,
  data: { id, title, load, public: opts.public ?? false, guide: opts.guide ?? id },
});

export const routes: RouteDef<RouteInfo>[] = [
  r('/login', 'login', 'nav.login', () => import('./pages/Login.svelte'), { public: true }),
  r('/setup', 'setup', 'nav.setup', () => import('./pages/Setup.svelte'), { public: true }),
  r('/home', 'home', 'nav.home', () => import('./pages/Home.svelte')),
  r('/onboarding', 'onboarding', 'nav.onboarding', () => import('./pages/Onboarding.svelte')),
  r('/sources', 'sources', 'nav.sources', () => import('./pages/Sources.svelte')),
  r('/services', 'services', 'nav.services', () => import('./pages/Services.svelte')),
  r('/hosts', 'hosts', 'nav.hosts', () => import('./pages/Hosts.svelte')),
  r('/contracts/service/:name/docs', 'contract-docs', 'nav.contracts', () => import('./pages/ContractDocs.svelte'), { guide: 'contract-service' }),
  r('/contracts/service/:name', 'contract-service', 'nav.contracts', () => import('./pages/ContractService.svelte')),
  r('/contracts/:service?/:op?', 'contracts', 'nav.contracts', () => import('./pages/Contracts.svelte')),
  // "Usa il mock": prepare and start the mock, its URLs, live calls, sessions and scenarios.
  r('/mock', 'mock', 'nav.mock', () => import('./pages/Mock.svelte')),
  r('/rules/:id?', 'rules', 'nav.rules', () => import('./pages/Rules.svelte')),
  r('/archetypes', 'archetypes', 'nav.archetypes', () => import('./pages/Archetypes.svelte')),
  r('/worlds', 'worlds', 'nav.worlds', () => import('./pages/Worlds.svelte')),
  r('/packs/:id?', 'packs', 'nav.packs', () => import('./pages/Publications.svelte')),
  // Old name of the section, kept so existing links keep working.
  r('/publications/:id?', 'packs', 'nav.packs', () => import('./pages/Publications.svelte')),
  // The former "Scenari mock" page is a tab of the Mock page now.
  r('/scenarios', 'mock', 'nav.mock', () => import('./pages/ScenariosRedirect.svelte'), { guide: 'mock' }),
  r('/quarantine', 'quarantine', 'nav.quarantine', () => import('./pages/Quarantine.svelte')),
  r('/events', 'events', 'nav.events', () => import('./pages/Events.svelte')),
  r('/alerts', 'alerts', 'nav.alerts', () => import('./pages/Alerts.svelte')),
  r('/audit', 'audit', 'nav.audit', () => import('./pages/Audit.svelte')),
  r('/users', 'users', 'nav.users', () => import('./pages/Users.svelte')),
  r('/settings', 'settings', 'nav.settings', () => import('./pages/Settings.svelte')),
  r('/gaps', 'gaps', 'nav.gaps', () => import('./pages/Gaps.svelte')),
  r('/glossary', 'glossary', 'nav.glossary', () => import('./pages/Glossary.svelte')),
  r('/manual', 'manual', 'nav.manual', () => import('./pages/Manual.svelte'), { guide: 'manual' }),
  r('/help/hmac-keys', 'hmac-keys', 'nav.hmacKeys', () => import('./pages/HmacKeys.svelte'), { guide: 'hmac-keys' }),
];

/** Where an item sits in the sidebar: the home page, the 4 steps of the journey, or the collapsed "Avanzate" group. */
export type NavSection = 'home' | 'connect' | 'observe' | 'review' | 'mock' | 'advanced';

export interface NavItem {
  path: string;
  /** Query that selects the item among those sharing a path (a tab). */
  query?: Record<string, string>;
  label: MsgKey;
  icon: IconName;
  section: NavSection;
}

/** The steps of the journey, in order (the sidebar shows them numbered). */
export const JOURNEY: { id: Exclude<NavSection, 'home' | 'advanced'>; title: MsgKey }[] = [
  { id: 'connect', title: 'journey.step.connect' },
  { id: 'observe', title: 'journey.step.observe' },
  { id: 'review', title: 'journey.step.review' },
  { id: 'mock', title: 'journey.step.mock' },
];

export const NAV: NavItem[] = [
  { path: '/home', label: 'nav.home', icon: 'home', section: 'home' },
  // 1 Collega
  { path: '/onboarding', label: 'nav.connectService', icon: 'onboarding', section: 'connect' },
  { path: '/sources', label: 'nav.sources', icon: 'sources', section: 'connect' },
  // 2 Osserva
  { path: '/services', label: 'nav.services', icon: 'services', section: 'observe' },
  { path: '/hosts', label: 'nav.hosts', icon: 'hosts', section: 'observe' },
  // 3 Rivedi
  { path: '/contracts', label: 'nav.contracts', icon: 'contracts', section: 'review' },
  { path: '/rules', label: 'nav.rules', icon: 'rules', section: 'review' },
  { path: '/gaps', label: 'nav.gaps', icon: 'gaps', section: 'review' },
  { path: '/alerts', label: 'nav.alerts', icon: 'alerts', section: 'review' },
  // 4 Usa il mock
  { path: '/mock', label: 'nav.mock', icon: 'mock', section: 'mock' },
  // Avanzate
  { path: '/sources', query: { tab: 'policy' }, label: 'nav.policy', icon: 'lock', section: 'advanced' },
  { path: '/archetypes', label: 'nav.archetypes', icon: 'archetypes', section: 'advanced' },
  { path: '/worlds', label: 'nav.worlds', icon: 'worlds', section: 'advanced' },
  { path: '/packs', label: 'nav.packs', icon: 'publications', section: 'advanced' },
  // A shortcut to the "Scenari salvati" tab of the Mock page (the old page redirects there).
  { path: '/scenarios', label: 'nav.scenarios', icon: 'scenarios', section: 'advanced' },
  { path: '/quarantine', label: 'nav.quarantine', icon: 'lock', section: 'advanced' },
  { path: '/events', label: 'nav.events', icon: 'download', section: 'advanced' },
  { path: '/audit', label: 'nav.audit', icon: 'audit', section: 'advanced' },
  { path: '/users', label: 'nav.users', icon: 'users', section: 'advanced' },
  { path: '/settings', label: 'nav.settings', icon: 'settings', section: 'advanced' },
  { path: '/glossary', label: 'nav.glossary', icon: 'book', section: 'advanced' },
  { path: '/manual', label: 'nav.manual', icon: 'book', section: 'advanced' },
  { path: '/help/hmac-keys', label: 'nav.hmacKeys', icon: 'lock', section: 'advanced' },
];

/** Whether the current location is this item: same path (or below it) and, for a tab entry, the same tab. */
export function navActive(item: NavItem, path: string, query: Record<string, string>): boolean {
  if (path !== item.path && !path.startsWith(item.path + '/')) return false;
  const tabbed = NAV.filter((n) => n.path === item.path && n.query);
  if (item.query) return Object.entries(item.query).every(([k, v]) => query[k] === v);
  // The plain entry of a path that also has a tab entry is not active on that tab.
  return !tabbed.some((n) => Object.entries(n.query ?? {}).every(([k, v]) => query[k] === v));
}
