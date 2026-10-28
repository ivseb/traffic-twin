import { describe, expect, it } from 'vitest';
import { href, matchRoute, parseLocation, type RouteDef } from './router';

const routes: RouteDef<string>[] = [
  { pattern: '/login', data: 'login' },
  { pattern: '/contracts/:service?/:op?', data: 'contracts' },
  { pattern: '/rules/:id?', data: 'rules' },
];

describe('parseLocation', () => {
  it('handles empty and root hashes', () => {
    expect(parseLocation('')).toEqual({ path: '/', query: {} });
    expect(parseLocation('#/')).toEqual({ path: '/', query: {} });
  });
  it('splits path and query, decoding values', () => {
    expect(parseLocation('#/sources?tab=policy&q=a%20b')).toEqual({ path: '/sources', query: { tab: 'policy', q: 'a b' } });
  });
  it('drops a trailing slash and tolerates a missing leading one', () => {
    expect(parseLocation('#rules/')).toEqual({ path: '/rules', query: {} });
  });
  it('survives malformed escapes', () => {
    expect(parseLocation('#/x?a=%E0%A4%A').query.a).toBe('%E0%A4%A');
  });
});

describe('matchRoute', () => {
  it('matches static routes', () => {
    expect(matchRoute(routes, '/login')?.route.data).toBe('login');
  });
  it('matches optional params', () => {
    expect(matchRoute(routes, '/rules')?.params).toEqual({});
    expect(matchRoute(routes, '/rules/r-0007')?.params).toEqual({ id: 'r-0007' });
  });
  it('decodes encoded segments (operations contain spaces and slashes)', () => {
    const m = matchRoute(routes, '/contracts/shipping-ext/GET%20%2Fv1%2Fshipments');
    expect(m?.params).toEqual({ service: 'shipping-ext', op: 'GET /v1/shipments' });
  });
  it('rejects extra segments and unknown paths', () => {
    expect(matchRoute(routes, '/rules/a/b')).toBeNull();
    expect(matchRoute(routes, '/nope')).toBeNull();
  });
});

describe('href', () => {
  it('encodes params and appends the query', () => {
    expect(href('/contracts/:service/:op', { service: 'shipping-ext', op: 'GET /v1/shipments' }, { tab: 'diff' })).toBe(
      '#/contracts/shipping-ext/GET%20%2Fv1%2Fshipments?tab=diff',
    );
  });
  it('round-trips through parse + match', () => {
    const h = href('/contracts/:service/:op', { service: 's', op: 'POST /orders/{id}' });
    const loc = parseLocation(h);
    expect(matchRoute(routes, loc.path)?.params).toEqual({ service: 's', op: 'POST /orders/{id}' });
  });
  it('omits empty query values', () => {
    expect(href('/sources', {}, { tab: '' })).toBe('#/sources');
  });
});
