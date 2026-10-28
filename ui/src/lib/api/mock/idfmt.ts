// In-memory id formats and mock identity settings for the demo build and the tests. The template reader follows the
// grammar of tt-core (internal/idfmt) closely enough for the demo: same error codes, same shapes; the generated ids
// are not byte for byte the server's.

import { ApiError, type Permission, type User } from '../types';
import { CLAIM_RE, CUSTOMER_RE, HEADER_RE, type IdFormat, type IdFormatError, type IdFormatPreview, type IdFormatsApi, type MockIdentity } from '../idfmt';
import { permissionsOf } from '../../rbac';

type Part = { kind: 'rand'; alpha: string } | { kind: 'lit'; text: string } | { kind: 'ref'; pad: number } | { kind: 'b64'; open: boolean };

const ALPHA: Record<string, string> = { N: '0123456789', A: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', a: 'abcdefghijklmnopqrstuvwxyz', X: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' };
const BARE = '0123456789-._:/+=#@';
const REF_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}(#-?[1-9][0-9]?)?((\|trim0)|(\|pad([1-9]|[12][0-9]|3[0-2])))*$/;

/** Reads a template: its parts and the size of its random space, or the first error. */
export function parseTemplate(s: string): { parts: Part[]; capacity: number } | IdFormatError {
  if (!s) return { code: 'empty', at: 0 };
  if (s.length > 64) return { code: 'too_long', at: 64 };
  const parts: Part[] = [];
  let capacity = 1;
  let b64At = -1;
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (ALPHA[c]) {
      parts.push({ kind: 'rand', alpha: ALPHA[c] });
      capacity *= ALPHA[c].length;
      i++;
    } else if (BARE.includes(c)) {
      parts.push({ kind: 'lit', text: c });
      i++;
    } else if (c === "'") {
      const j = s.indexOf("'", i + 1);
      if (j < 0) return { code: 'unclosed_quote', at: i };
      const lit = s.slice(i + 1, j);
      if (!lit) return { code: 'empty_literal', at: i };
      if (!/^[A-Za-z0-9._:/+=#@-]+$/.test(lit)) return { code: 'bad_literal', at: i };
      parts.push({ kind: 'lit', text: lit });
      i = j + 1;
    } else if (c === '{') {
      const j = s.indexOf('}', i + 1);
      if (j < 0) return { code: 'unclosed_ref', at: i };
      const ref = s.slice(i + 1, j);
      if (!REF_RE.test(ref)) return { code: 'bad_ref', at: i };
      const pad = /\|pad([0-9]+)/.exec(ref);
      parts.push({ kind: 'ref', pad: pad ? Number(pad[1]) : 6 });
      i = j + 1;
    } else if (c === '<') {
      if (b64At >= 0) return { code: 'nested_b64', at: i };
      b64At = i;
      parts.push({ kind: 'b64', open: true });
      i++;
    } else if (c === '>') {
      if (b64At < 0) return { code: 'bad_char', at: i };
      const last = parts[parts.length - 1];
      if (last.kind === 'b64' && last.open) return { code: 'empty_b64', at: b64At };
      b64At = -1;
      parts.push({ kind: 'b64', open: false });
      i++;
    } else return { code: 'bad_char', at: i };
    if (parts.length > 64) return { code: 'too_many_parts', at: i };
  }
  if (b64At >= 0) return { code: 'unclosed_b64', at: b64At };
  if (capacity < 1000) return { code: 'too_small', at: 0 };
  return { parts, capacity };
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

/** The n-th id of a template (demo generator: deterministic, not the server's permutation). */
export function demoId(parts: Part[], scope: string, n: number): string {
  let x = hash(`${scope}/${n}`);
  const next = (m: number) => {
    x = Math.imul(x ^ (x >>> 15), 2246822519) >>> 0;
    x = (x ^ (x >>> 13)) >>> 0;
    return x % m;
  };
  let out = '';
  let inner: string | null = null;
  const put = (t: string) => {
    if (inner !== null) inner += t;
    else out += t;
  };
  for (const p of parts) {
    if (p.kind === 'rand') put(p.alpha[next(p.alpha.length)]);
    else if (p.kind === 'lit') put(p.text);
    else if (p.kind === 'ref') put(Array.from({ length: p.pad }, () => String(next(10))).join(''));
    else if (p.open) inner = '';
    else {
      out += btoa(inner ?? '').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
      inner = null;
    }
  }
  return out;
}

function capacityLabel(c: number): string {
  return c >= 1e18 ? 'more than 10^18' : String(Math.floor(c));
}

export function demoPreview(format: string, domain = 'id'): IdFormatPreview {
  const r = parseTemplate(format);
  if ('code' in r) return { valid: false, error: r };
  return { valid: true, preview: [1, 2, 3].map((n) => demoId(r.parts, domain, n)), capacityLabel: capacityLabel(r.capacity) };
}

export interface DemoIdDeps {
  authed(): User;
  audit(actor: string, action: string, target: string): void;
  now(): number;
  wait(): Promise<void>;
}

function needAny(d: DemoIdDeps, perms: Permission[]): User {
  const u = d.authed();
  const have = permissionsOf(u.roles);
  if (!perms.some((p) => have.has(p))) throw new ApiError('forbidden', `Permesso mancante: ${perms.join(' / ')}`, 403);
  return u;
}

export function createDemoIdFormats(d: DemoIdDeps): IdFormatsApi {
  const store = new Map<string, IdFormat>();
  const key = (g: string, dom: string) => `${g}\u0000${dom}`;
  const seed: [string, string, string][] = [['demo', 'order', "'ORD'-NNNNNN"]];
  for (const [g, dom, f] of seed) {
    const p = demoPreview(f, dom);
    if (p.valid) store.set(key(g, dom), { group: g, domain: dom, format: f, capacityLabel: p.capacityLabel, preview: p.preview, updatedBy: 'elena.admin', updatedAt: new Date(d.now() - 86400000).toISOString() });
  }
  return {
    async list(group) {
      await d.wait();
      needAny(d, ['worlds.generate', 'rules.edit', 'publish.run', 'audit.view']);
      return [...store.values()].filter((f) => f.group === group).map((f) => ({ ...f }));
    },
    async set(group, domain, format) {
      await d.wait();
      const u = needAny(d, ['worlds.generate', 'rules.edit']);
      const p = demoPreview(format, domain);
      if (!p.valid) throw new ApiError('invalid', 'invalid id format', 422, 'invalid_format', [{ code: p.error.code, at: p.error.at }]);
      const f: IdFormat = { group, domain, format, capacityLabel: p.capacityLabel, preview: p.preview, updatedBy: u.username, updatedAt: new Date(d.now()).toISOString() };
      store.set(key(group, domain), f);
      d.audit(u.username, 'idformat.set', `${group}/${domain}`);
      return { ...f };
    },
    async remove(group, domain) {
      await d.wait();
      const u = needAny(d, ['worlds.generate', 'rules.edit']);
      if (!store.delete(key(group, domain))) throw new ApiError('not_found', 'not found', 404, 'not_found');
      d.audit(u.username, 'idformat.delete', `${group}/${domain}`);
    },
    async preview(format, domain) {
      d.authed();
      return demoPreview(format, domain);
    },
  };
}

/** A keyed-hash stand-in for the demo (the console uses HMAC-SHA256 with the group's key). */
function demoHash(group: string, user: string): string {
  let out = '';
  for (let i = 0; out.length < 32; i++) out += hash(`${group}\u0000${i}\u0000${user}`).toString(16).padStart(8, '0');
  return out.slice(0, 32);
}

export function createDemoIdentity(d: DemoIdDeps) {
  const store = new Map<string, MockIdentity>();
  store.set('demo', { group: 'demo', enabled: true, header: 'x-user-id', claim: '', map: [{ hash: demoHash('demo', 'tester.anna'), customer: 'CUS-SYN-0007' }], updatedBy: 'elena.admin', updatedAt: new Date(d.now() - 3600000).toISOString() });
  const get = (group: string): MockIdentity => store.get(group) ?? { group, enabled: false, header: '', claim: '', map: [] };
  const write = (group: string, f: (m: MockIdentity) => MockIdentity, action: string): MockIdentity => {
    const u = needAny(d, ['publish.build']);
    const m = { ...f(get(group)), updatedBy: u.username, updatedAt: new Date(d.now()).toISOString() };
    store.set(group, m);
    d.audit(u.username, action, group);
    return { ...m, map: [...m.map] };
  };
  return {
    async identity(group: string): Promise<MockIdentity> {
      await d.wait();
      needAny(d, ['publish.build', 'publish.run', 'audit.view']);
      const m = get(group);
      return { ...m, map: [...m.map] };
    },
    async setIdentity(group: string, header: string, claim: string): Promise<MockIdentity> {
      await d.wait();
      if (header && !HEADER_RE.test(header)) throw new ApiError('invalid', 'invalid header name', 422, 'invalid_header');
      if (claim && (!header || !CLAIM_RE.test(claim))) throw new ApiError('invalid', 'invalid claim', 422, 'invalid_claim');
      return write(group, (m) => ({ ...m, enabled: !!header, header: header.toLowerCase(), claim: header ? claim : '' }), 'mock.identity_set');
    },
    async addIdentityUser(group: string, user: string, customer: string): Promise<MockIdentity> {
      await d.wait();
      if (!user.trim()) throw new ApiError('invalid', 'user is required', 422, 'invalid_user');
      if (!CUSTOMER_RE.test(customer)) throw new ApiError('invalid', 'invalid customer', 422, 'invalid_customer');
      const h = demoHash(group, user);
      return write(group, (m) => ({ ...m, map: [...m.map.filter((x) => x.hash !== h), { hash: h, customer }] }), 'mock.identity_map_add');
    },
    async removeIdentityUser(group: string, hash: string): Promise<MockIdentity> {
      await d.wait();
      return write(group, (m) => ({ ...m, map: m.map.filter((x) => x.hash !== hash) }), 'mock.identity_map_delete');
    },
  };
}
