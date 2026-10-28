import { describe, expect, it } from 'vitest';
import type { HostDomain, HostEntry, HostsRegistry } from './api/types';
import {
  baseHint,
  checkBase,
  defaultServiceName,
  encodePattern,
  exactBaseUrl,
  filterDomains,
  findHost,
  hostPatternOfService,
  hostQuarantine,
  ipv4Class,
  isNewHost,
  parseBase,
  patternMatches,
  patternParts,
  sortDomains,
  splitPort,
  strictPolicies,
  summarize,
  validServiceName,
} from './hosts';

const NOW = Date.parse('2026-10-24T12:00:00Z');
const ago = (h: number) => new Date(NOW - h * 3600_000).toISOString();

function host(pattern: string, over: Partial<HostEntry> = {}): HostEntry {
  return {
    pattern,
    service: `host:${pattern}`,
    declared: false,
    declaredBy: [],
    exact: !pattern.includes('{*}') && !pattern.startsWith('ip:'),
    quarantined: false,
    calls: 10,
    serverErrors: 0,
    clientErrors: 0,
    errorRate: 0,
    latencyP50Ms: 50,
    firstSeen: ago(24 * 30),
    lastSeen: ago(1),
    callers: [{ service: 'shop-api', calls: 10 }],
    policies: ['p-shop'],
    ...over,
  };
}
const dom = (domain: string, patterns: HostEntry[]): HostDomain => ({
  domain,
  calls: patterns.reduce((a, p) => a + p.calls, 0),
  firstSeen: patterns.map((p) => p.firstSeen).filter((x): x is string => !!x).sort()[0] ?? null,
  lastSeen: patterns.map((p) => p.lastSeen).filter((x): x is string => !!x).sort().at(-1) ?? null,
  patterns,
});

const REG: HostsRegistry = {
  domains: [
    dom('carrier.example', [host('api.carrier.example', { declared: true, declaredBy: ['p-shop'], service: 'shipping-ext', calls: 1000, errorRate: 0.01 }), host('sandbox.carrier.example', { calls: 30, firstSeen: ago(5), errorRate: 0.2 })]),
    dom('tracking.example', [host('{*}.tracking.example', { calls: 500, quarantined: true, firstSeen: ago(24 * 3) })]),
    dom('ip:private', [host('ip:private', { calls: 7 })]),
  ],
  unlisted: host('unlisted', { calls: 0, exact: false }),
  invalid: host('invalid', { calls: 0, exact: false }),
  discovery: { 'p-shop': 'auto', 'p-legacy': 'off' },
};

describe('reading a pattern', () => {
  it('splits the port like the server (1-5 digits after the last colon)', () => {
    expect(splitPort('api.carrier.example')).toEqual({ host: 'api.carrier.example', port: '' });
    expect(splitPort('{*}.tracking.example:8443')).toEqual({ host: '{*}.tracking.example', port: '8443' });
    expect(splitPort('ip:private')).toEqual({ host: 'ip:private', port: '' });
    expect(splitPort('ip:private:8080')).toEqual({ host: 'ip:private', port: '8080' });
    expect(splitPort('a:123456')).toEqual({ host: 'a:123456', port: '' });
  });
  it('turns {*} into a wildcard piece, keeping consecutive ones one by one', () => {
    expect(patternParts('{*}.api.{*}.tracking.example:8443')).toEqual([
      { kind: 'star' },
      { kind: 'text', value: '.api.' },
      { kind: 'star' },
      { kind: 'text', value: '.tracking.example' },
      { kind: 'port', value: ':8443' },
    ]);
    expect(patternParts('{*}.{*}.x.example').filter((p) => p.kind === 'star')).toHaveLength(2);
    expect(patternParts('api.carrier.example')).toEqual([{ kind: 'text', value: 'api.carrier.example' }]);
    expect(patternParts('ip:private:8080')).toEqual([{ kind: 'text', value: 'ip:private' }, { kind: 'port', value: ':8080' }]);
  });
  it('a base URL exists only for a pattern that names exactly one host', () => {
    // No scheme is guessed: without one the host alone, with one the base.
    expect(exactBaseUrl('api.carrier.example')).toBe('api.carrier.example');
    expect(exactBaseUrl('api.carrier.example', 'https')).toBe('https://api.carrier.example');
    expect(exactBaseUrl('localhost:8080', 'http')).toBe('http://localhost:8080');
    expect(exactBaseUrl('webhooks.carrier.example:8443', 'https')).toBe('https://webhooks.carrier.example:8443');
    for (const p of ['{*}.tracking.example', 'ip:private', 'ip:public:8080', 'unlisted', 'invalid', '']) expect(exactBaseUrl(p), p).toBeUndefined();
  });
  it('finds the pattern behind the service of an event', () => {
    expect(hostPatternOfService('host:{*}.x.example')).toBe('{*}.x.example');
    expect(hostPatternOfService('shipping-ext')).toBeUndefined();
    expect(findHost(REG, 'shipping-ext')?.host.pattern).toBe('api.carrier.example');
    expect(findHost(REG, 'host:sandbox.carrier.example')?.domain).toBe('carrier.example');
    expect(findHost(REG, 'nope')).toBeUndefined();
  });
});

describe('new hosts', () => {
  it('is new when first seen in the window and not declared', () => {
    expect(isNewHost(host('a.example', { firstSeen: ago(5) }), NOW)).toBe(true);
    expect(isNewHost(host('a.example', { firstSeen: ago(25) }), NOW)).toBe(false);
    expect(isNewHost(host('a.example', { firstSeen: ago(25) }), NOW, 7 * 86400_000)).toBe(true);
    expect(isNewHost(host('a.example', { firstSeen: ago(5), declared: true }), NOW)).toBe(false);
    expect(isNewHost(host('a.example', { firstSeen: null }), NOW)).toBe(false);
  });
  it('summarizes without counting IP classes as named hosts', () => {
    expect(summarize(REG, NOW)).toEqual({ domains: 2, hosts: 3, ips: 1, all: 4, undeclared: 2, fresh: 1, quarantined: 1 });
  });
  it('lists the policies in strict mode', () => {
    expect(strictPolicies(REG)).toEqual(['p-legacy']);
    expect(strictPolicies({ ...REG, discovery: {} })).toEqual([]);
  });
});

describe('filtering and sorting', () => {
  const none = { range: 'all', q: '', undeclaredOnly: false } as const;
  it('keeps everything without filters', () => {
    expect(filterDomains(REG.domains, none, NOW)).toEqual(REG.domains);
  });
  it('shows only the hosts new in the last 24 hours or 7 days, with the totals of what is left', () => {
    const r24 = filterDomains(REG.domains, { ...none, range: '24h' }, NOW);
    expect(r24.map((d) => [d.domain, d.patterns.map((p) => p.pattern), d.calls])).toEqual([['carrier.example', ['sandbox.carrier.example'], 30]]);
    const r7 = filterDomains(REG.domains, { ...none, range: '7d' }, NOW);
    expect(r7.flatMap((d) => d.patterns.map((p) => p.pattern))).toEqual(['sandbox.carrier.example', '{*}.tracking.example']);
    expect(r7[0].firstSeen).toBe(ago(5));
  });
  it('hides declared hosts on request', () => {
    const r = filterDomains(REG.domains, { ...none, undeclaredOnly: true }, NOW);
    expect(r.flatMap((d) => d.patterns.map((p) => p.pattern))).not.toContain('api.carrier.example');
  });
  it('searches domain, pattern, service name and callers, all words', () => {
    const f = (q: string) => filterDomains(REG.domains, { ...none, q }, NOW).flatMap((d) => d.patterns.map((p) => p.pattern));
    expect(f('tracking')).toEqual(['{*}.tracking.example']);
    expect(f('shipping-ext')).toEqual(['api.carrier.example']);
    expect(f('CARRIER sandbox')).toEqual(['sandbox.carrier.example']);
    expect(f('shop-api')).toHaveLength(4);
    expect(f('zzz')).toEqual([]);
    expect(f('{*}')).toEqual(['{*}.tracking.example']);
  });
  it('sorts domains and the hosts inside them without touching the input', () => {
    const before = JSON.stringify(REG.domains);
    expect(sortDomains(REG.domains, 'calls').map((d) => d.domain)).toEqual(['carrier.example', 'tracking.example', 'ip:private']);
    expect(sortDomains(REG.domains, 'name').map((d) => d.domain)).toEqual(['carrier.example', 'ip:private', 'tracking.example']);
    expect(sortDomains(REG.domains, 'errors')[0].patterns.map((p) => p.pattern)).toEqual(['sandbox.carrier.example', 'api.carrier.example']);
    expect(sortDomains(REG.domains, 'recent')[0].domain).toBe('carrier.example');
    expect(JSON.stringify(REG.domains)).toBe(before);
  });
});

describe('the base typed for a twin', () => {
  it('parses a base like the policy does: lower case host, default port removed', () => {
    expect(parseBase('https://API.Carrier.example:443/v2')).toEqual({ scheme: 'https', host: 'api.carrier.example', port: '' });
    expect(parseBase('http://x.example:80')).toEqual({ scheme: 'http', host: 'x.example', port: '' });
    expect(parseBase('https://x.example:8443')).toEqual({ scheme: 'https', host: 'x.example', port: '8443' });
    for (const bad of ['x.example', 'ftp://x.example', 'https://x.example:0', 'https://x.example:70000', 'https://x_y.example', 'https://x.example/a b', 'https://[::1]', 'https://x.example?q=1']) expect(parseBase(bad), bad).toBeNull();
  });
  it('a base must be described by the pattern: same labels and port, {*} for one label', () => {
    expect(checkBase('{*}.tracking.example', 'https://acme.tracking.example')).toMatchObject({ ok: true, host: 'acme.tracking.example' });
    expect(checkBase('{*}.tracking.example', 'https://a.b.tracking.example')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('{*}.tracking.example', 'https://acme.other.example')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('{*}.tracking.example', 'https://acme.tracking.example:8443')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('{*}.tracking.example:8443', 'https://acme.tracking.example:8443/v1')).toMatchObject({ ok: true, port: '8443' });
    expect(checkBase('api.{*}.example', 'https://api.eu.example')).toMatchObject({ ok: true });
    expect(checkBase('api.carrier.example', 'https://API.carrier.example/v2')).toMatchObject({ ok: true });
    expect(checkBase('api.carrier.example', 'https://sandbox.carrier.example')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('{*}.tracking.example', 'tracking')).toEqual({ ok: false, code: 'invalid_base' });
  });
  it('a port of the pattern is compared after removing the default of the scheme', () => {
    expect(checkBase('x.example:8443', 'https://x.example:8443')).toMatchObject({ ok: true });
    expect(checkBase('x.example', 'https://x.example:443')).toMatchObject({ ok: true });
    expect(checkBase('x.example', 'https://x.example:8443')).toEqual({ ok: false, code: 'base_mismatch' });
  });
  it('an IP class needs an IPv4 of that class and the same port', () => {
    expect(checkBase('ip:private', 'https://10.0.0.5')).toMatchObject({ ok: true });
    expect(checkBase('ip:private', 'https://192.168.1.20/api')).toMatchObject({ ok: true });
    expect(checkBase('ip:private:8080', 'http://172.16.4.2:8080')).toMatchObject({ ok: true });
    expect(checkBase('ip:private:8080', 'http://172.16.4.2')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('ip:private', 'https://8.8.8.8')).toEqual({ ok: false, code: 'base_mismatch' });
    expect(checkBase('ip:public', 'https://8.8.8.8')).toMatchObject({ ok: true });
    expect(checkBase('ip:public', 'https://api.carrier.example')).toEqual({ ok: false, code: 'base_mismatch' });
  });
  it('classes IPv4 with the closed table of the spec', () => {
    const cases: [string, string | null][] = [
      ['10.1.2.3', 'ip:private'],
      ['172.16.0.1', 'ip:private'],
      ['172.31.255.255', 'ip:private'],
      ['172.32.0.1', 'ip:public'],
      ['192.168.0.1', 'ip:private'],
      ['127.0.0.1', 'ip:private'],
      ['169.254.1.1', 'ip:private'],
      ['100.64.0.1', 'ip:private'],
      ['100.128.0.1', 'ip:public'],
      ['198.18.0.1', 'ip:private'],
      ['198.20.0.1', 'ip:public'],
      ['203.0.113.9', 'ip:private'],
      ['203.0.114.9', 'ip:public'],
      ['224.0.0.1', 'ip:private'],
      ['255.255.255.255', 'ip:private'],
      ['8.8.8.8', 'ip:public'],
      ['010.0.0.1', null],
      ['1.2.3', null],
      ['256.1.1.1', null],
    ];
    for (const [ip, cls] of cases) expect(ipv4Class(ip), ip).toBe(cls);
  });
  it('matches concrete hosts against patterns', () => {
    expect(patternMatches('{*}.x.example', 'a.x.example')).toBe(true);
    expect(patternMatches('{*}.{*}.example', 'a.b.example')).toBe(true);
    expect(patternMatches('{*}.{*}.example', 'a.example')).toBe(false);
    expect(patternMatches('ip:private', '10.0.0.1')).toBe(false);
  });
  it('proposes a service name from the base, with the port when it is not the default', () => {
    expect(defaultServiceName('https://acme.tracking.example')).toBe('acme.tracking.example');
    expect(defaultServiceName('https://acme.tracking.example:8443/v1')).toBe('acme.tracking.example-8443');
    expect(defaultServiceName('nope')).toBeUndefined();
    expect(defaultServiceName(`https://${'a'.repeat(70)}.example`)).toBeUndefined();
  });
  it('validates service names like the policy', () => {
    for (const ok of ['a', 'shipping-ext', 'a.b_c-d', '0abc']) expect(validServiceName(ok), ok).toBe(true);
    for (const bad of ['', '-a', '.a', 'A', 'a b', 'a'.repeat(64)]) expect(validServiceName(bad), bad).toBe(false);
  });
  it('shows what to type for a pattern that is not exact', () => {
    expect(baseHint('{*}.tracking.example')).toBe('https://name.tracking.example');
    expect(baseHint('{*}.tracking.example:8443')).toBe('https://name.tracking.example:8443');
    expect(baseHint('ip:private')).toBe('https://10.0.0.5');
    expect(ipv4Class(baseHint('ip:public').replace('https://', ''))).toBe('ip:public');
    expect(ipv4Class(baseHint('ip:private').replace('https://', ''))).toBe('ip:private');
  });
  it('encodes a pattern for the path of the twin call', () => {
    expect(encodePattern('{*}.tracking.example')).toBe('%7B%2A%7D.tracking.example');
    expect(encodePattern('ip:private:8080')).toBe('ip%3Aprivate%3A8080');
  });
});

describe('host quarantines', () => {
  it('reads the host-label item the server describes in English', () => {
    expect(hostQuarantine({ kind: 'host-label', where: 'hosts under tracking.example position 2' })).toEqual({ kind: 'host-label', domain: 'tracking.example', position: 2 });
    expect(hostQuarantine({ kind: 'host-label', where: 'something else' })).toEqual({ kind: 'host-label', domain: '', position: 0 });
    expect(hostQuarantine({ kind: 'host', where: 'registrable domains' })).toEqual({ kind: 'host' });
    expect(hostQuarantine({ kind: 'keep-value', where: 'resp.body $.status' })).toBeNull();
  });
});
