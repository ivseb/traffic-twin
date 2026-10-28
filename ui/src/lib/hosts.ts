// Pure logic of the hosts registry page (spec v1.5, docs/spec/sanitizer.md 3.5): reading host
// patterns, filtering and sorting, and the checks the twin dialog does before asking the server
// (the server decides: these only save a round trip and explain the rule).

import type { HostDomain, HostEntry, HostsRegistry, QuarantineItem } from './api/types';

export const STAR = '{*}';
export const DAY_MS = 86_400_000;
/** A host first seen within this window is "nuovo". */
export const NEW_HOST_MS = DAY_MS;

// ---------------------------------------------------------------- reading a pattern

export type PatternPart = { kind: 'text'; value: string } | { kind: 'star' } | { kind: 'port'; value: string };

/** Splits `pattern[:port]` the way the server does (port = 1-5 digits after the last colon). */
export function splitPort(p: string): { host: string; port: string } {
  const i = p.lastIndexOf(':');
  if (i < 0) return { host: p, port: '' };
  const port = p.slice(i + 1);
  return /^[0-9]{1,5}$/.test(port) ? { host: p.slice(0, i), port } : { host: p, port: '' };
}

export const isIpClass = (host: string): boolean => host === 'ip:private' || host === 'ip:public';
export const isSystemPattern = (p: string): boolean => p === 'unlisted' || p === 'invalid';

/** Text, `{*}` and port pieces of a pattern, for rendering the wildcard as a chip. */
export function patternParts(pattern: string): PatternPart[] {
  const { host, port } = splitPort(pattern);
  const out: PatternPart[] = [];
  let rest = host;
  while (rest.length) {
    const i = rest.indexOf(STAR);
    if (i < 0) {
      out.push({ kind: 'text', value: rest });
      break;
    }
    if (i > 0) out.push({ kind: 'text', value: rest.slice(0, i) });
    out.push({ kind: 'star' });
    rest = rest.slice(i + STAR.length);
  }
  if (port) out.push({ kind: 'port', value: `:${port}` });
  return out;
}

/**
 * The base of a pattern that names exactly one host: `scheme://host[:port]`, or `host[:port]` alone without a scheme
 * (to show it). The events never carry the scheme of a host (the default port of http and https is left out), so it
 * is never guessed: the person chooses it. Undefined for `{*}`, IP classes, unlisted and invalid.
 */
export function exactBaseUrl(pattern: string, scheme?: 'http' | 'https'): string | undefined {
  if (isSystemPattern(pattern)) return undefined;
  const { host } = splitPort(pattern);
  if (!host || isIpClass(host) || host.includes(STAR)) return undefined;
  return scheme ? `${scheme}://${pattern}` : pattern;
}

/** The pattern behind the `service` of an event (`host:<pattern>`), if it is one. */
export function hostPatternOfService(service: string): string | undefined {
  return service.startsWith('host:') ? service.slice(5) : undefined;
}

/** The registry entry (and its domain) that describes a service name or a pattern. */
export function findHost(reg: HostsRegistry, key: string): { domain: string; host: HostEntry } | undefined {
  const pattern = hostPatternOfService(key) ?? key;
  for (const d of reg.domains) {
    const host = d.patterns.find((h) => h.pattern === pattern || h.service === key);
    if (host) return { domain: d.domain, host };
  }
  return undefined;
}

// ---------------------------------------------------------------- new / filtering / sorting

export function isNewHost(h: Pick<HostEntry, 'firstSeen' | 'declared' | 'nowDeclaredAs'>, now: number, windowMs = NEW_HOST_MS): boolean {
  if (h.declared || h.nowDeclaredAs || !h.firstSeen) return false;
  const t = Date.parse(h.firstSeen);
  return !Number.isNaN(t) && now - t <= windowMs;
}

export type NewRange = 'all' | '24h' | '7d';
export const NEW_RANGES: readonly NewRange[] = ['all', '24h', '7d'];
export type HostSort = 'calls' | 'recent' | 'errors' | 'name';
export const HOST_SORTS: readonly HostSort[] = ['calls', 'recent', 'errors', 'name'];

export interface HostFilter {
  /** Only hosts first seen in the window (and not declared). */
  range: NewRange;
  /** Domain / pattern / service / caller search. */
  q: string;
  /** Hide the hosts a policy already declares. */
  undeclaredOnly: boolean;
}

const rangeWindow = (r: NewRange): number => (r === '24h' ? DAY_MS : r === '7d' ? 7 * DAY_MS : Infinity);

function matches(d: HostDomain, h: HostEntry, q: string): boolean {
  if (!q) return true;
  const hay = [d.domain, h.pattern, h.service, ...h.callers.map((c) => c.service), ...h.declaredBy].join(' ').toLowerCase();
  return q
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => hay.includes(w));
}

const maxIso = (a: string | null, b: string | null): string | null => (!a ? b : !b ? a : a > b ? a : b);
const minIso = (a: string | null, b: string | null): string | null => (!a ? b : !b ? a : a < b ? a : b);

/** The domains with only the patterns that pass the filter; calls and times are recomputed over what is left. */
export function filterDomains(domains: HostDomain[], f: HostFilter, now: number): HostDomain[] {
  const win = rangeWindow(f.range);
  const out: HostDomain[] = [];
  for (const d of domains) {
    const patterns = d.patterns.filter((h) => {
      if (f.undeclaredOnly && (h.declared || h.nowDeclaredAs)) return false;
      if (win !== Infinity && !isNewHost(h, now, win)) return false;
      return matches(d, h, f.q.trim());
    });
    if (patterns.length === 0) continue;
    if (patterns.length === d.patterns.length) {
      out.push(d);
      continue;
    }
    out.push({
      ...d,
      patterns,
      calls: patterns.reduce((a, h) => a + h.calls, 0),
      firstSeen: patterns.reduce<string | null>((a, h) => minIso(a, h.firstSeen), null),
      lastSeen: patterns.reduce<string | null>((a, h) => maxIso(a, h.lastSeen), null),
    });
  }
  return out;
}

const time = (iso: string | null): number => (iso ? Date.parse(iso) || 0 : 0);
const worstError = (d: HostDomain): number => Math.max(0, ...d.patterns.map((h) => h.errorRate));

/** Domains (and the patterns inside each) in the chosen order; the input is not changed. */
export function sortDomains(domains: HostDomain[], by: HostSort): HostDomain[] {
  const patternCmp: Record<HostSort, (a: HostEntry, b: HostEntry) => number> = {
    calls: (a, b) => b.calls - a.calls || a.pattern.localeCompare(b.pattern),
    recent: (a, b) => time(b.lastSeen) - time(a.lastSeen) || a.pattern.localeCompare(b.pattern),
    errors: (a, b) => b.errorRate - a.errorRate || b.calls - a.calls,
    name: (a, b) => a.pattern.localeCompare(b.pattern),
  };
  const domainCmp: Record<HostSort, (a: HostDomain, b: HostDomain) => number> = {
    calls: (a, b) => b.calls - a.calls || a.domain.localeCompare(b.domain),
    recent: (a, b) => time(b.lastSeen) - time(a.lastSeen) || a.domain.localeCompare(b.domain),
    errors: (a, b) => worstError(b) - worstError(a) || b.calls - a.calls,
    name: (a, b) => a.domain.localeCompare(b.domain),
  };
  return domains.map((d) => ({ ...d, patterns: [...d.patterns].sort(patternCmp[by]) })).sort(domainCmp[by]);
}

export interface HostsSummary {
  /** Registrable domains with a named host (the IP classes are not domains). */
  domains: number;
  /** Named hosts. */
  hosts: number;
  /** Hosts called by IP address (`ip:private`, `ip:public`): hosts too, with no domain. */
  ips: number;
  /** Every host in the list: named and IP (the number the page shows, usability test #5, m10). */
  all: number;
  /** Hosts no policy declares. */
  undeclared: number;
  /** Undeclared hosts first seen in the last 24 hours. */
  fresh: number;
  quarantined: number;
}

/**
 * Counts for the tiles and for the "N nuovi host scoperti" hint (system rows and IP classes are not hosts to twin by name).
 * The server's own counters (`reg.counters`, when it sends them) win over the local count, field by field.
 */
export function summarize(reg: HostsRegistry, now: number): HostsSummary {
  const named = reg.domains.filter((d) => !isIpClass(d.domain));
  const all = named.flatMap((d) => d.patterns);
  const ipHosts = ipDomains(reg).flatMap((d) => d.patterns);
  const local: HostsSummary = {
    domains: named.length,
    hosts: all.length,
    ips: ipHosts.length,
    all: all.length + ipHosts.length,
    undeclared: all.filter((h) => !h.declared && !h.nowDeclaredAs).length,
    fresh: all.filter((h) => isNewHost(h, now)).length,
    quarantined: all.filter((h) => h.quarantined).length,
  };
  const c = reg.counters;
  if (!c) return local;
  const n = (v: number | undefined, d: number) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : d);
  const ips = n(c.ips, local.ips);
  const hosts = n(c.hosts, local.hosts);
  return { domains: n(c.domains, local.domains), hosts, ips, all: n(c.all, hosts + ips), undeclared: n(c.undeclared, local.undeclared), fresh: n(c.new, local.fresh), quarantined: n(c.quarantined, local.quarantined) };
}

const mergeCallers = (a: HostEntry['callers'], b: HostEntry['callers']): HostEntry['callers'] => {
  const m = new Map<string, number>();
  for (const c of [...a, ...b]) m.set(c.service, (m.get(c.service) ?? 0) + c.calls);
  return [...m].map(([service, calls]) => ({ service, calls })).sort((x, y) => y.calls - x.calls || x.service.localeCompare(y.service));
};

/** `into` takes the calls of `other` (the same host seen before and after its declaration): one row, the counts add up. */
function absorb(into: HostEntry, other: HostEntry): HostEntry {
  const calls = into.calls + other.calls;
  const serverErrors = into.serverErrors + other.serverErrors;
  return {
    ...into,
    calls,
    serverErrors,
    clientErrors: into.clientErrors + other.clientErrors,
    errorRate: calls > 0 ? serverErrors / calls : 0,
    firstSeen: minIso(into.firstSeen, other.firstSeen),
    lastSeen: maxIso(into.lastSeen, other.lastSeen),
    callers: mergeCallers(into.callers, other.callers),
    policies: [...new Set([...into.policies, ...other.policies])],
    declaredBy: [...new Set([...into.declaredBy, ...other.declaredBy])],
    quarantined: into.quarantined || other.quarantined,
    mergedCalls: (into.mergedCalls ?? 0) + (other.mergedCalls ?? 0) + other.calls,
  };
}

/**
 * One row per host (usability test #5, m10): once a host is declared the registry lists it twice, the entry of the
 * calls seen before (undeclared, with `nowDeclaredAs`) and the declared one. The history is folded into the declared
 * row, which says "dichiarato come ..." and how many calls came from before. Two undeclared entries of the same
 * pattern and group (a repeat) fold into one too.
 */
export function dedupeHosts(reg: HostsRegistry): HostsRegistry {
  const SEP = '\u0000';
  const keyOf = (h: HostEntry) => `${h.group ?? ''}${SEP}${h.pattern}`;
  const nameKey = (h: Pick<HostEntry, 'group'>, name: string) => `${h.group ?? ''}${SEP}${name}`;
  // The declared rows of the whole registry, by pattern and by service name (the history may sit in another domain row).
  const declaredBy = new Map<string, HostEntry>();
  for (const d of reg.domains) for (const h of d.patterns) if (h.declared) declaredBy.set(keyOf(h), h);
  const byName = new Map<string, HostEntry>();
  for (const h of declaredBy.values()) byName.set(nameKey(h, h.service), h);
  const merged = new Map<HostEntry, HostEntry>();
  const resolve = (h: HostEntry): HostEntry => merged.get(h) ?? h;
  const domains: HostDomain[] = reg.domains.map((d) => ({ ...d, patterns: [...d.patterns] }));
  // Pass 1: undeclared entries that a declared one now stands for.
  const gone = new Set<HostEntry>();
  for (const d of reg.domains) {
    for (const h of d.patterns) {
      if (h.declared) continue;
      const target = (h.nowDeclaredAs ? byName.get(nameKey(h, h.nowDeclaredAs)) : undefined) ?? declaredBy.get(keyOf(h));
      if (!target) continue;
      merged.set(target, absorb(resolve(target), h));
      gone.add(h);
    }
  }
  // Pass 2: repeats of the same undeclared pattern and group.
  const seen = new Map<string, HostEntry>();
  for (const d of reg.domains) {
    for (const h of d.patterns) {
      if (h.declared || gone.has(h)) continue;
      const first = seen.get(keyOf(h));
      if (!first) {
        seen.set(keyOf(h), h);
        continue;
      }
      merged.set(first, absorb(resolve(first), h));
      gone.add(h);
    }
  }
  for (const d of domains) d.patterns = d.patterns.filter((h) => !gone.has(h)).map(resolve);
  return { ...reg, domains };
}

/** Domains that are IP classes (`ip:private`, `ip:public`): shown apart, with an explanation. */
export const ipDomains = (reg: HostsRegistry): HostDomain[] => reg.domains.filter((d) => isIpClass(d.domain));
export const nameDomains = (reg: HostsRegistry): HostDomain[] => reg.domains.filter((d) => !isIpClass(d.domain));

/** Policies in strict mode (`hosts.discovery: off`). */
export const strictPolicies = (reg: HostsRegistry): string[] =>
  Object.entries(reg.discovery)
    .filter(([, m]) => m === 'off')
    .map(([id]) => id)
    .sort();

// ---------------------------------------------------------------- twin dialog checks

const SERVICE_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
export const validServiceName = (s: string): boolean => SERVICE_RE.test(s);

export type BaseCheck = { ok: true; host: string; port: string } | { ok: false; code: 'invalid_base' | 'base_mismatch' };

const IPV4_PRIVATE: [number, number, number, number, number][] = [
  [0, 0, 0, 0, 8], [10, 0, 0, 0, 8], [100, 64, 0, 0, 10], [127, 0, 0, 0, 8], [169, 254, 0, 0, 16], [172, 16, 0, 0, 12], [192, 0, 0, 0, 24],
  [192, 0, 2, 0, 24], [192, 168, 0, 0, 16], [198, 18, 0, 0, 15], [198, 51, 100, 0, 24], [203, 0, 113, 0, 24], [224, 0, 0, 0, 4], [240, 0, 0, 0, 4],
];

function parseIPv4(s: string): number[] | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** `ip:private` or `ip:public` for an IPv4 literal (the closed table of sanitizer.md 3.6). */
export function ipv4Class(s: string): 'ip:private' | 'ip:public' | null {
  const a = parseIPv4(s);
  if (!a) return null;
  const n = ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0;
  for (const [b0, b1, b2, b3, bits] of IPV4_PRIVATE) {
    const p = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((n & mask) >>> 0 === (p & mask) >>> 0) return 'ip:private';
  }
  return 'ip:public';
}

/** Does a concrete host (lower case) fall under a pattern: same labels, `{*}` for any one label. */
export function patternMatches(pattern: string, hostPort: string): boolean {
  const p = splitPort(pattern);
  const h = splitPort(hostPort);
  if (p.port !== h.port || isIpClass(p.host)) return false;
  const pl = p.host.split('.');
  const hl = h.host.split('.');
  return pl.length === hl.length && pl.every((l, i) => l === STAR || l === hl[i]);
}

/** Parses `https?://host[:port][/segment…]` like the policy does (lower case host, default port removed). */
export function parseBase(base: string): { scheme: string; host: string; port: string } | null {
  const m = /^(https?):\/\/([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?((?:\/[A-Za-z0-9._~-]{1,64})*)$/.exec(base.trim());
  if (!m) return null;
  let port = '';
  if (m[3] !== undefined) {
    const n = Number(m[3]);
    if (n < 1 || n > 65535) return null;
    port = (m[1] === 'http' && n === 80) || (m[1] === 'https' && n === 443) ? '' : String(n);
  }
  return { scheme: m[1], host: m[2].toLowerCase(), port };
}

/** The base typed for a pattern must be described by it (same labels and port; an IPv4 of the class for an IP pattern). */
export function checkBase(pattern: string, base: string): BaseCheck {
  const b = parseBase(base);
  if (!b) return { ok: false, code: 'invalid_base' };
  const p = splitPort(pattern);
  const hp = b.port ? `${b.host}:${b.port}` : b.host;
  if (isIpClass(p.host)) {
    if (ipv4Class(b.host) !== p.host || b.port !== p.port) return { ok: false, code: 'base_mismatch' };
  } else if (!patternMatches(pattern, hp) && hp !== pattern) {
    return { ok: false, code: 'base_mismatch' };
  }
  return { ok: true, host: b.host, port: b.port };
}

/** Default service name of a base: its host, plus `-<port>` for a non-default port; undefined when it is not a valid name. */
export function defaultServiceName(base: string): string | undefined {
  const b = parseBase(base);
  if (!b) return undefined;
  const name = b.port ? `${b.host}-${b.port}` : b.host;
  return validServiceName(name) ? name : undefined;
}

/** What to show in the base field when the pattern is not exact: the shape to fill in. */
export function baseHint(pattern: string): string {
  const { host, port } = splitPort(pattern);
  const suffix = port ? `:${port}` : '';
  if (host === 'ip:private') return `https://10.0.0.5${suffix}`;
  if (host === 'ip:public') return `https://203.0.114.7${suffix}`;
  return `https://${host.replaceAll(STAR, 'name')}${suffix}`;
}

/** Percent-encoding of a pattern for the path of `POST /api/v1/hosts/{pattern}/twin` (`{*}` is `%7B%2A%7D`). */
export const encodePattern = (pattern: string): string => encodeURIComponent(pattern).replaceAll('*', '%2A');

// ---------------------------------------------------------------- quarantine

export type HostQuarantine = { kind: 'host-label'; domain: string; position: number } | { kind: 'host' };

/** What a host quarantine is about; the server writes `where` in English ("hosts under <domain> position <n>"). */
export function hostQuarantine(q: Pick<QuarantineItem, 'kind' | 'where'>): HostQuarantine | null {
  if (q.kind === 'host') return { kind: 'host' };
  if (q.kind !== 'host-label') return null;
  const m = /^hosts under (\S+) position ([0-9]+)$/.exec(q.where.trim());
  return m ? { kind: 'host-label', domain: m[1], position: Number(m[2]) } : { kind: 'host-label', domain: '', position: 0 };
}

/** The registry restricted to the hosts a predicate keeps (the Group/Team filter); domains left empty go away. */
export function scopeRegistry(r: HostsRegistry, keep: (h: HostEntry) => boolean): HostsRegistry {
  const domains: HostDomain[] = [];
  for (const d of r.domains) {
    const patterns = d.patterns.filter(keep);
    if (patterns.length === 0) continue;
    domains.push(patterns.length === d.patterns.length ? d : { ...d, patterns, calls: patterns.reduce((a, h) => a + h.calls, 0) });
  }
  return { ...r, domains };
}
