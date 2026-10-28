import { describe, expect, it } from 'vitest';
import { JOURNEY, NAV, navActive, routes } from './routes';
import { matchRoute } from './lib/router';
import { it as itBase } from './lib/i18n/it';
import { itConsole } from './lib/i18n/it-console';
import { itUx } from './lib/i18n/it-ux';
import { itJourney } from './lib/i18n/it-journey';

const labels: Record<string, string> = { ...itBase, ...itConsole, ...itUx, ...itJourney };

describe('navigation', () => {
  it('has the home page, the four steps in order and a collapsed advanced group', () => {
    expect(JOURNEY.map((s) => s.id)).toEqual(['connect', 'observe', 'review', 'mock']);
    expect(JOURNEY.map((s) => labels[s.title])).toEqual(['Collega', 'Osserva', 'Rivedi', 'Usa il mock']);
    expect(NAV[0]).toMatchObject({ path: '/home', section: 'home' });
    for (const s of JOURNEY) expect(NAV.some((n) => n.section === s.id), s.id).toBe(true);
    expect(NAV.filter((n) => n.section === 'advanced').length).toBeGreaterThan(8);
  });

  it('puts the right pages in each step', () => {
    const of = (id: string) => NAV.filter((n) => n.section === id).map((n) => n.path);
    expect(of('connect')).toEqual(['/onboarding', '/sources']);
    expect(of('observe')).toEqual(['/services', '/hosts']);
    expect(of('review')).toEqual(['/contracts', '/rules', '/gaps', '/alerts']);
    expect(of('mock')).toEqual(['/mock']);
    const adv = of('advanced');
    for (const p of ['/archetypes', '/worlds', '/packs', '/scenarios', '/quarantine', '/events', '/audit', '/users', '/settings', '/glossary']) expect(adv, p).toContain(p);
  });

  it('every entry opens an existing route and has a label in the dictionary', () => {
    for (const n of NAV) {
      expect(matchRoute(routes, n.path), n.path).not.toBeNull();
      expect(labels[n.label], n.label).toBeTruthy();
    }
  });

  it('lists every page of the product somewhere in the menu', () => {
    const inMenu = new Set(NAV.map((n) => n.path));
    const hidden = routes.filter((r) => !r.data.public && !r.pattern.includes(':') && !inMenu.has(r.pattern)).map((r) => r.pattern);
    expect(hidden).toEqual([]);
  });

  it('shows no entry twice for the same path and tab', () => {
    const keys = NAV.map((n) => n.path + '?' + (n.query?.tab ?? ''));
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('marks the current page, and tells the policy tab from the sources page', () => {
    const sources = NAV.find((n) => n.path === '/sources' && !n.query)!;
    const policy = NAV.find((n) => n.path === '/sources' && n.query)!;
    expect(navActive(sources, '/sources', {})).toBe(true);
    expect(navActive(policy, '/sources', {})).toBe(false);
    expect(navActive(policy, '/sources', { tab: 'policy' })).toBe(true);
    expect(navActive(sources, '/sources', { tab: 'policy' })).toBe(false);
    const contracts = NAV.find((n) => n.path === '/contracts')!;
    expect(navActive(contracts, '/contracts/service/shop-api', {})).toBe(true);
    expect(navActive(contracts, '/contractsx', {})).toBe(false);
  });

  it('routes /home and /mock', () => {
    expect(matchRoute(routes, '/home')?.route.data.id).toBe('home');
    expect(matchRoute(routes, '/mock')?.route.data.id).toBe('mock');
  });
});
