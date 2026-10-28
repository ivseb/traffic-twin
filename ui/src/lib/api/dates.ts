// Relative dates ("Date relative", admin-api /api/v1/date-offsets): the range of offsets between a date field and the
// moment of the call, learned from the traffic (x-tt-value.date_offset of the contract) or chosen by a person per
// field name and group. The world and the mock generate the date as virtual clock + an offset in that range.
// Types and the pure helpers the page uses.

/** A range chosen by a person for a date field name of a group (wins over the learned one). */
export interface DateOffset {
  group: string;
  field: string;
  /** "+30d", "-2d", "+12h". */
  min: string;
  max: string;
  updatedBy: string;
  updatedAt: string;
}

export interface DateOffsetsApi {
  list(group: string): Promise<DateOffset[]>;
  /** 422 invalid_offset / invalid_field / invalid_group. */
  set(group: string, field: string, min: string, max: string): Promise<DateOffset>;
  /** Back to the range learned from the traffic. */
  remove(group: string, field: string): Promise<void>;
}

export const OFFSET_RE = /^[+-]?[0-9]{1,6}(h|d)$/;
export const DATE_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
/** About 100 years, as the server bounds an offset. */
export const MAX_OFFSET_DAYS = 36600;

/** An offset in hours, or null when it is not one ("+30d" -> 720, "-12h" -> -12). */
export function offsetHours(s: string): number | null {
  const v = s.trim();
  if (!OFFSET_RE.test(v)) return null;
  const n = Number(v.replace(/^[+-]/, '').slice(0, -1));
  const h = (v.startsWith('-') ? -1 : 1) * n * (v.endsWith('d') ? 24 : 1);
  return Math.abs(h) > MAX_OFFSET_DAYS * 24 ? null : h;
}

export type RangeProblem = 'min' | 'max' | 'order';

/** What is wrong with a range, null when the server will accept it. */
export function rangeProblem(min: string, max: string): RangeProblem | null {
  const lo = offsetHours(min);
  if (lo === null) return 'min';
  const hi = offsetHours(max);
  if (hi === null) return 'max';
  return lo > hi ? 'order' : null;
}

/** The two ends of a range applied to an instant (both included). */
export function rangeDates(now: Date, min: string, max: string): { from: Date; to: Date } | null {
  if (rangeProblem(min, max)) return null;
  const h = 3600_000;
  return { from: new Date(now.getTime() + offsetHours(min)! * h), to: new Date(now.getTime() + offsetHours(max)! * h) };
}

/** A date field of a contract: its property name, its format, the range learned from the traffic (if any). */
export interface DateField {
  field: string;
  format: 'date' | 'date-time';
  learned?: { min: string; max: string };
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);

/** Whether a schema is a date field, as tt-core decides it (internal/dateoff.DateLike). */
export function dateLike(s: Obj): boolean {
  if (s.format === 'date' || s.format === 'date-time') return true;
  const xv = s['x-tt-value'];
  if (!isObj(xv)) return false;
  if (xv.kind === 'bucket' && typeof xv.unit === 'string' && xv.unit) return true;
  return xv.format === 'date' || xv.format === 'datetime';
}

/**
 * The date fields (body properties) of an OpenAPI document, once per property name (the override is per name), with the learned range
 * of x-tt-value.date_offset when one of its occurrences has it. Local $refs are followed once.
 */
export function dateFields(doc: unknown): DateField[] {
  const out = new Map<string, DateField>();
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
  const note = (name: string, s: Obj): void => {
    if (!name || !dateLike(s)) return;
    const xv = isObj(s['x-tt-value']) ? s['x-tt-value'] : {};
    const fmt: DateField['format'] = s.format === 'date' || xv.format === 'date' ? 'date' : 'date-time';
    const off = isObj(xv.date_offset) ? xv.date_offset : undefined;
    const learned = off && typeof off.min === 'string' && typeof off.max === 'string' && !rangeProblem(off.min, off.max) ? { min: off.min, max: off.max } : undefined;
    const cur = out.get(name);
    if (!cur) out.set(name, { field: name, format: fmt, ...(learned ? { learned } : {}) });
    else if (!cur.learned && learned) cur.learned = learned;
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
      // Parameters are not overridden (the console range applies to body properties): their own name is left out.
      if (k === 'schema') visit(x, '', new Set(), 0);
      else if (k !== 'components' && k !== 'examples' && k !== 'example') walk(x, depth + 1);
    }
  };
  walk(root.paths, 0);
  return [...out.values()].sort((a, b) => a.field.localeCompare(b.field));
}
