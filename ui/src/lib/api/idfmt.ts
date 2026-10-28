// Id formats ("Formato degli id", admin-api 1.18.0, /api/v1/id-formats) and the mock sessions chosen by the caller's
// identity ("Sessione per utente", /api/v1/mocks/identity). Types and the pure helpers the pages use.

/** The id format of one id domain of a group: what the world and the mock use instead of PREFIX-SYN-NNNN. */
export interface IdFormat {
  group: string;
  domain: string;
  format: string;
  /** How many different ids the format can give, as the server writes it ("100000000", "more than 10^18"). */
  capacityLabel: string;
  /** The first ids of the format (no copied field). */
  preview: string[];
  updatedBy: string;
  updatedAt: string;
}

/** A template error: a stable code and the 0-based position in the format. */
export interface IdFormatError {
  code: IdFormatErrorCode;
  at: number;
}

export const ID_FORMAT_ERROR_CODES = [
  'empty',
  'too_long',
  'bad_char',
  'unclosed_quote',
  'empty_literal',
  'bad_literal',
  'unclosed_ref',
  'bad_ref',
  'nested_b64',
  'unclosed_b64',
  'empty_b64',
  'too_many_parts',
  'too_small',
] as const;
export type IdFormatErrorCode = (typeof ID_FORMAT_ERROR_CODES)[number];

export type IdFormatPreview = { valid: true; preview: string[]; capacityLabel: string } | { valid: false; error: IdFormatError };

export interface IdFormatsApi {
  list(group: string): Promise<IdFormat[]>;
  /** Saves the format of a domain (422 invalid_format with details [{code, at}] when it does not parse). */
  set(group: string, domain: string, format: string): Promise<IdFormat>;
  remove(group: string, domain: string): Promise<void>;
  /** Checks a format and returns its first ids, without saving. */
  preview(format: string, domain?: string): Promise<IdFormatPreview>;
}

/** The mock sessions of a group chosen by the caller's identity. */
export interface MockIdentity {
  group: string;
  enabled: boolean;
  /** Header that carries the identity (lower case as typed; "" = off). */
  header: string;
  /** JWT claim when the header carries a JWT ("" = the whole header value). */
  claim: string;
  /** Explicit choices: a fingerprint (keyed hash) of the test user and the synthetic customer. */
  map: { hash: string; customer: string }[];
  updatedBy?: string;
  updatedAt?: string;
}

export const HEADER_RE = /^[A-Za-z0-9-]{1,64}$/;
export const CLAIM_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
export const CUSTOMER_RE = /^[A-Z]{2,5}-SYN-[0-9]{4,}$/;

/** One id domain of a contract and the fields (dotted, as the schema names them) that carry it. */
export interface IdDomain {
  domain: string;
  fields: string[];
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * The id domains of an OpenAPI document: every schema (properties, items, parameters) whose x-tt-value has kind "id",
 * once per domain, with the names of the fields and parameters that use it. Local $refs are followed once.
 */
export function idDomains(doc: unknown): IdDomain[] {
  const byDomain = new Map<string, Set<string>>();
  const root = isObj(doc) ? doc : {};
  const resolve = (s: unknown, seen: Set<string>): Obj | null => {
    if (!isObj(s)) return null;
    const ref = s.$ref;
    if (typeof ref === 'string' && ref.startsWith('#/')) {
      if (seen.has(ref)) return null;
      seen.add(ref);
      let cur: unknown = root;
      for (const k of ref.slice(2).split('/')) cur = isObj(cur) ? cur[k.replaceAll('~1', '/').replaceAll('~0', '~')] : undefined;
      return resolve(cur, seen);
    }
    return s;
  };
  const note = (name: string, s: Obj | null): void => {
    const xv = s?.['x-tt-value'];
    if (!isObj(xv) || xv.kind !== 'id') return;
    const d = typeof xv.domain === 'string' && xv.domain ? xv.domain : 'id';
    if (!byDomain.has(d)) byDomain.set(d, new Set());
    if (name) byDomain.get(d)!.add(name);
  };
  const visit = (raw: unknown, name: string, seen: Set<string>, depth: number): void => {
    if (depth > 32) return;
    const s = resolve(raw, new Set(seen));
    if (!s) return;
    note(name, s);
    if (isObj(s.properties)) for (const [k, v] of Object.entries(s.properties)) visit(v, k, seen, depth + 1);
    if (s.items !== undefined) visit(s.items, name, seen, depth + 1);
    for (const key of ['allOf', 'anyOf', 'oneOf'] as const) if (Array.isArray(s[key])) for (const x of s[key] as unknown[]) visit(x, name, seen, depth + 1);
  };
  const walk = (v: unknown, depth: number): void => {
    if (depth > 64) return;
    if (Array.isArray(v)) {
      for (const x of v) walk(x, depth + 1);
      return;
    }
    if (!isObj(v)) return;
    for (const [k, x] of Object.entries(v)) {
      if (k === 'schema') visit(x, typeof v.name === 'string' ? v.name : '', new Set(), 0);
      else if (k !== 'components' && k !== 'examples' && k !== 'example') walk(x, depth + 1);
    }
  };
  walk(root.paths, 0);
  return [...byDomain.entries()].map(([domain, f]) => ({ domain, fields: [...f].sort() })).sort((a, b) => a.domain.localeCompare(b.domain));
}

/** The first `n` characters of a hash, as the list shows a mapped user. */
export const fingerprint = (hash: string, n = 8): string => (hash.length > n ? `${hash.slice(0, n)}…` : hash);
