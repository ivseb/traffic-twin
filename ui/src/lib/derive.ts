// Derived values of rules ("Valore calcolato", rules 1.10, docs/spec/rules.md 3.15): a create/set value written as
//
//   {"$derive": {"fn": "sum", "args": ["${field:items[*].price}"]}}
//
// is computed by the world and the mock when the effect applies. This is a mirror of internal/derive (same checks,
// same arithmetic, same rendering of numbers) used by the rule editor for its checks and its preview on an example.
// The server stays the judge: what it refuses comes back as a rule problem (bad_derived, derived_type, unknown_field).

export const DERIVE_KEY = '$derive';
export const DERIVE_FNS = ['copy', 'sum', 'count', 'add', 'sub', 'mul', 'div', 'min', 'max', 'round', 'date', 'template'] as const;
export type DeriveFn = (typeof DERIVE_FNS)[number];
export const DERIVE_MAX_DEPTH = 4;

/** The body of a derived value object, as the rule stores it. */
export interface DeriveSpec {
  fn: string;
  args?: unknown[];
  offset?: string;
  format?: string;
  template?: string;
  digits?: number;
}

export type DerivedValue = { [DERIVE_KEY]: DeriveSpec };

const VAR_RE = /^\$\{([a-z][a-z0-9_]{0,31})\}$/;
const EFFECT_RE = /^\$\{effect:([a-z][a-z0-9_-]{0,63})\}$/;
const FIELD_RE = /^\$\{field:([A-Za-z_][A-Za-z0-9_]{0,63}(?:\[\*\])?(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}(?:\[\*\])?){0,7})\}$/;
const OFFSET_RE = /^[+-]?[0-9]{1,6}(s|m|h|d)$/;
const SPEC_KEYS = new Set(['fn', 'args', 'offset', 'format', 'template', 'digits']);

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Whether v is a derived value object ({"$derive": ...} and nothing else). */
export function isDerived(v: unknown): v is DerivedValue {
  return isObj(v) && Object.keys(v).length === 1 && DERIVE_KEY in v;
}

/** The arity of a function: [min, max]. */
export function arity(fn: string): [number, number] {
  switch (fn) {
    case 'copy':
    case 'count':
    case 'round':
      return [1, 1];
    case 'sum':
      return [1, 8];
    case 'add':
    case 'mul':
    case 'min':
    case 'max':
      return [2, 8];
    case 'sub':
    case 'div':
      return [2, 2];
    case 'date':
      return [0, 1];
    default:
      return [0, 0];
  }
}

/** The JSON type of the result: number, string or any (copy). */
export function resultType(fn: string): 'number' | 'string' | 'any' {
  if (fn === 'copy') return 'any';
  return fn === 'date' || fn === 'template' ? 'string' : 'number';
}

/** The kind of an argument, as the editor offers it. */
export type ArgKind = 'number' | 'var' | 'field' | 'effect' | 'now' | 'text' | 'nested';

export function argKind(a: unknown): ArgKind | null {
  if (typeof a === 'number') return Number.isFinite(a) ? 'number' : null;
  if (typeof a === 'string') {
    if (a === '${now}') return 'now';
    if (VAR_RE.test(a)) return 'var';
    if (EFFECT_RE.test(a)) return 'effect';
    if (FIELD_RE.test(a)) return 'field';
    if (a.startsWith('${')) return null;
    return 'text';
  }
  return isObj(a) ? 'nested' : null;
}

/** The name inside a reference ("${field:items[*].price}" -> "items[*].price"), the text of a text, the number. */
export function argText(a: unknown): string {
  if (typeof a === 'number') return String(a);
  if (typeof a !== 'string') return '';
  return VAR_RE.exec(a)?.[1] ?? EFFECT_RE.exec(a)?.[1] ?? FIELD_RE.exec(a)?.[1] ?? (a === '${now}' ? '' : a);
}

/** An argument of a kind from what the person typed (a number stays a number only when it is one). */
export function makeArg(kind: ArgKind, text: string): unknown {
  const s = text.trim();
  switch (kind) {
    case 'number':
      return s !== '' && Number.isFinite(Number(s)) ? Number(s) : s;
    case 'var':
      return '${' + s + '}';
    case 'field':
      return '${field:' + s + '}';
    case 'effect':
      return '${effect:' + s + '}';
    case 'now':
      return '${now}';
    case 'nested':
      return { [DERIVE_KEY]: { fn: 'add', args: [0, 0] } };
    default:
      return text;
  }
}

/** A new derived value for a function, with arguments that make it valid where possible. */
export function newDerived(fn: string): DerivedValue {
  switch (fn) {
    case 'copy':
    case 'count':
      return { [DERIVE_KEY]: { fn, args: ['${field:items}'] } };
    case 'sum':
      return { [DERIVE_KEY]: { fn, args: ['${field:items[*].price}'] } };
    case 'round':
      return { [DERIVE_KEY]: { fn, args: ['${field:total}'], digits: 2 } };
    case 'date':
      return { [DERIVE_KEY]: { fn, offset: '+30d', format: 'date' } };
    case 'template':
      return { [DERIVE_KEY]: { fn, template: "'INV'-NNNN" } };
    case 'sub':
    case 'div':
      return { [DERIVE_KEY]: { fn, args: ['${field:total}', 1] } };
    default:
      return { [DERIVE_KEY]: { fn, args: ['${field:total}', 1] } };
  }
}

/** Why a derived value is refused: a stable code (translated as drv.err.<code>) and its parameters. */
export interface DeriveError {
  code: 'shape' | 'unknownKey' | 'depth' | 'fn' | 'args' | 'digits' | 'offset' | 'format' | 'template' | 'onlyDate' | 'onlyTemplate' | 'onlyRound' | 'argNumber' | 'argRef' | 'argText' | 'argType';
  params?: Record<string, string | number>;
}

/** Checks a derived value as internal/derive.Parse does (the id format of a template is checked by the server). */
export function checkDerived(v: unknown, depth = 0): DeriveError | null {
  if (depth > DERIVE_MAX_DEPTH) return { code: 'depth', params: { max: DERIVE_MAX_DEPTH } };
  if (!isDerived(v)) return { code: 'shape' };
  const e = v[DERIVE_KEY];
  if (!isObj(e)) return { code: 'shape' };
  for (const k of Object.keys(e)) if (!SPEC_KEYS.has(k)) return { code: 'unknownKey', params: { key: k } };
  const fn = typeof e.fn === 'string' ? e.fn : '';
  if (!(DERIVE_FNS as readonly string[]).includes(fn)) return { code: 'fn', params: { fn, fns: DERIVE_FNS.join(', ') } };
  const args = Array.isArray(e.args) ? e.args : e.args === undefined ? [] : null;
  if (!args) return { code: 'shape' };
  const [lo, hi] = arity(fn);
  if (args.length < lo || args.length > hi) return { code: 'args', params: { fn, lo, hi } };
  if (fn === 'round' && e.digits !== undefined && !(Number.isInteger(e.digits) && (e.digits as number) >= 0 && (e.digits as number) <= 6)) return { code: 'digits' };
  if (fn === 'date') {
    const off = e.offset === undefined || e.offset === '' ? '+0d' : e.offset;
    if (typeof off !== 'string' || !OFFSET_RE.test(off)) return { code: 'offset' };
    if (e.format !== undefined && e.format !== '' && e.format !== 'date' && e.format !== 'date-time') return { code: 'format' };
  }
  if (fn === 'template' && (typeof e.template !== 'string' || !e.template.trim())) return { code: 'template' };
  if (fn !== 'date' && ((e.offset !== undefined && e.offset !== '') || (e.format !== undefined && e.format !== ''))) return { code: 'onlyDate' };
  if (fn !== 'template' && e.template !== undefined && e.template !== '') return { code: 'onlyTemplate' };
  if (fn !== 'round' && e.digits !== undefined) return { code: 'onlyRound' };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const n = i + 1;
    if (typeof a === 'number' && !Number.isFinite(a)) return { code: 'argNumber', params: { n } };
    const k = argKind(a);
    if (k === null) return typeof a === 'string' ? { code: 'argRef', params: { n } } : { code: 'argType', params: { n } };
    if (k === 'text' && fn !== 'copy') return { code: 'argText', params: { n } };
    if (k === 'nested') {
      const inner = checkDerived(a, depth + 1);
      if (inner) return inner;
    }
  }
  return null;
}

/** The references of a derived value and of its nested values (field paths keep their [*]). */
export function derivedRefs(v: unknown): { vars: string[]; fields: string[]; effects: string[]; now: boolean } {
  const out = { vars: [] as string[], fields: [] as string[], effects: [] as string[], now: false };
  const walk = (x: unknown, depth: number) => {
    if (depth > DERIVE_MAX_DEPTH || !isDerived(x)) return;
    for (const a of x[DERIVE_KEY].args ?? []) {
      const k = argKind(a);
      if (k === 'var') out.vars.push(argText(a));
      else if (k === 'field') out.fields.push(argText(a));
      else if (k === 'effect') out.effects.push(argText(a));
      else if (k === 'now') out.now = true;
      else if (k === 'nested') walk(a, depth + 1);
    }
    if (x[DERIVE_KEY].fn === 'date' && !(x[DERIVE_KEY].args ?? []).length) out.now = true;
  };
  walk(v, 0);
  const uniq = (l: string[]) => [...new Set(l)];
  return { vars: uniq(out.vars), fields: uniq(out.fields), effects: uniq(out.effects), now: out.now };
}

/** What an expression reads when it is evaluated. */
export interface DeriveEnv {
  vars?: Record<string, unknown>;
  object?: Record<string, unknown>;
  effects?: Record<string, string>;
  now: Date;
}

export type DeriveResult = { ok: true; value: unknown } | { ok: false; missing: true } | { ok: false; missing?: false; error: string };

class Missing extends Error {}
class EvalError extends Error {}

/** A result rendered as the server renders it: integers without decimals, other numbers with at most 9 decimals. */
export function deriveNumber(f: number): number {
  if (f === Math.trunc(f) && Math.abs(f) < 1e15) return f;
  return Math.round(f * 1e9) / 1e9;
}

function toFloat(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const f = Number(v.trim());
    return Number.isFinite(f) ? f : null;
  }
  return null;
}

function parseTime(s: string): Date | null {
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return new Date(`${s}T00:00:00Z`);
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) {
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3600_000, d: 86_400_000 };

/** "+30d" in milliseconds (0 when it is not an offset). */
export function deriveOffsetMs(s: string): number {
  if (!OFFSET_RE.test(s)) return 0;
  const sign = s.startsWith('-') ? -1 : 1;
  return sign * Number(s.replace(/^[+-]/, '').slice(0, -1)) * UNIT_MS[s.slice(-1)];
}

const rfc3339 = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

function fieldValues(obj: unknown, path: string): unknown[] {
  let cur: unknown[] = [obj];
  for (const seg of path.split('.')) {
    const all = seg.endsWith('[*]');
    const name = all ? seg.slice(0, -3) : seg;
    const next: unknown[] = [];
    for (const c of cur) {
      if (!isObj(c) || !(name in c)) continue;
      const v = c[name];
      if (all) {
        if (Array.isArray(v)) next.push(...v);
      } else next.push(v);
    }
    cur = next;
  }
  return cur;
}

function vals(a: unknown, env: DeriveEnv): unknown[] {
  switch (argKind(a)) {
    case 'number':
    case 'text':
      return [a];
    case 'now':
      return [rfc3339(env.now)];
    case 'var': {
      const n = argText(a);
      if (env.vars && n in env.vars) return [env.vars[n]];
      throw new Missing();
    }
    case 'effect': {
      const n = argText(a);
      if (env.effects && n in env.effects) return [env.effects[n]];
      throw new Missing();
    }
    case 'field': {
      const vs = fieldValues(env.object ?? {}, argText(a));
      if (!vs.length) throw new Missing();
      return vs;
    }
    case 'nested':
      return [evalSpec((a as DerivedValue)[DERIVE_KEY], env)];
  }
  throw new Missing();
}

function evalSpec(e: DeriveSpec, env: DeriveEnv): unknown {
  const args = e.args ?? [];
  switch (e.fn) {
    case 'copy': {
      const vs = vals(args[0], env);
      return vs.length === 1 ? vs[0] : vs;
    }
    case 'count': {
      let vs: unknown[] = [];
      try {
        vs = vals(args[0], env);
      } catch (x) {
        if (!(x instanceof Missing)) throw x;
      }
      return vs.length === 1 && Array.isArray(vs[0]) ? vs[0].length : vs.length;
    }
    case 'date': {
      let base = env.now;
      if (args.length === 1) {
        const vs = vals(args[0], env);
        if (vs.length !== 1) throw new Missing();
        const t = typeof vs[0] === 'string' ? parseTime(vs[0]) : null;
        if (!t) throw new EvalError('the base of a date is not a date');
        base = t;
      }
      const t = new Date(base.getTime() + deriveOffsetMs(e.offset || '+0d'));
      return e.format === 'date' ? t.toISOString().slice(0, 10) : rfc3339(t);
    }
    case 'template':
      // The id is generated by the world and the mock (id formats): the preview shows the template.
      return e.template ?? '';
  }
  const nums: number[] = [];
  for (const a of args) {
    const vs = vals(a, env);
    for (const v of vs) {
      if (Array.isArray(v) && e.fn === 'sum') {
        for (const x of v) {
          const f = toFloat(x);
          if (f === null) throw new EvalError('sum of a value that is not a number');
          nums.push(f);
        }
        continue;
      }
      const f = toFloat(v);
      if (f === null) throw new EvalError(`${e.fn} of a value that is not a number`);
      nums.push(f);
    }
    if (e.fn !== 'sum' && vs.length !== 1) throw new EvalError(`${e.fn} needs one value per argument`);
  }
  let r = 0;
  switch (e.fn) {
    case 'sum':
    case 'add':
      r = nums.reduce((s, f) => s + f, 0);
      break;
    case 'sub':
      r = nums[0] - nums[1];
      break;
    case 'mul':
      r = nums.reduce((s, f) => s * f, 1);
      break;
    case 'div':
      if (nums[1] === 0) throw new EvalError('division by zero');
      r = nums[0] / nums[1];
      break;
    case 'min':
      r = Math.min(...nums);
      break;
    case 'max':
      r = Math.max(...nums);
      break;
    case 'round': {
      const p = 10 ** (e.digits ?? 2);
      r = Math.round(nums[0] * p) / p;
      break;
    }
  }
  if (!Number.isFinite(r)) throw new EvalError('result is not a finite number');
  return deriveNumber(r);
}

/** Computes a derived value on an example (the value is checked first). */
export function evalDerived(v: unknown, env: DeriveEnv): DeriveResult {
  const bad = checkDerived(v);
  if (bad) return { ok: false, error: bad.code };
  try {
    return { ok: true, value: evalSpec((v as DerivedValue)[DERIVE_KEY], env) };
  } catch (x) {
    if (x instanceof Missing) return { ok: false, missing: true };
    return { ok: false, error: x instanceof Error ? x.message : String(x) };
  }
}

/** The derived value in a short formula: sum(items[*].price), date(now +30d). */
export function derivedFormula(v: unknown, depth = 0): string {
  if (!isDerived(v) || depth > DERIVE_MAX_DEPTH) return '?';
  const e = v[DERIVE_KEY];
  const args = (e.args ?? []).map((a) => {
    const k = argKind(a);
    if (k === 'nested') return derivedFormula(a, depth + 1);
    if (k === 'var') return argText(a);
    if (k === 'effect') return `effect:${argText(a)}`;
    if (k === 'now') return 'now';
    if (k === 'text') return JSON.stringify(a);
    return argText(a);
  });
  if (e.fn === 'date') return `date(${args[0] ?? 'now'} ${e.offset || '+0d'})`;
  if (e.fn === 'template') return `template(${e.template ?? ''})`;
  if (e.fn === 'round') return `round(${args[0] ?? ''}, ${e.digits ?? 2})`;
  return `${e.fn}(${args.join(', ')})`;
}

// ---- the example a preview is computed on

/** One input of the example: a field of the entity, a variable of the cause or an earlier effect. */
export interface ExampleInput {
  key: string;
  kind: 'field' | 'var' | 'effect';
  name: string;
  /** What the editor fills in first (a comma-separated list for a [*] field). */
  sample: string;
}

/**
 * The inputs of the example of a derived value: its references, with samples. A field that is a literal value of the
 * same effect starts from that value; a list field ([*]) from three prices.
 */
export function exampleInputs(v: unknown, literals: Record<string, unknown> = {}): ExampleInput[] {
  const r = derivedRefs(v);
  const out: ExampleInput[] = [];
  for (const f of r.fields) {
    const lit = literals[f.replaceAll('[*]', '')];
    const sample = lit !== undefined && !isDerived(lit) && typeof lit !== 'object' ? String(lit) : f.includes('[*]') ? '10.10, 12.20, 8' : '25';
    out.push({ key: `field:${f}`, kind: 'field', name: f, sample });
  }
  for (const n of r.vars) out.push({ key: `var:${n}`, kind: 'var', name: n, sample: 'ORD-SYN-0042' });
  for (const n of r.effects) out.push({ key: `effect:${n}`, kind: 'effect', name: n, sample: 'SHP-SYN-0091' });
  return out;
}

const scalar = (s: string): unknown => {
  const t = s.trim();
  return t !== '' && Number.isFinite(Number(t)) ? Number(t) : t;
};

function put(obj: Record<string, unknown>, segs: string[], values: unknown[]): void {
  const [seg, ...rest] = segs;
  const all = seg.endsWith('[*]');
  const name = all ? seg.slice(0, -3) : seg;
  if (!all) {
    if (!rest.length) {
      obj[name] = values.length === 1 ? values[0] : values;
      return;
    }
    const child = isObj(obj[name]) ? (obj[name] as Record<string, unknown>) : {};
    obj[name] = child;
    put(child, rest, values);
    return;
  }
  if (!rest.length) {
    obj[name] = values;
    return;
  }
  const arr = Array.isArray(obj[name]) ? (obj[name] as unknown[]) : [];
  values.forEach((x, i) => {
    const el = isObj(arr[i]) ? (arr[i] as Record<string, unknown>) : {};
    arr[i] = el;
    put(el, rest, [x]);
  });
  obj[name] = arr;
}

/** The environment of a preview from the example inputs (the person's texts by input key). */
export function exampleEnv(inputs: ExampleInput[], texts: Record<string, string>, now: Date): DeriveEnv {
  const env: DeriveEnv = { vars: {}, object: {}, effects: {}, now };
  for (const i of inputs) {
    const text = texts[i.key] ?? i.sample;
    if (i.kind === 'var') env.vars![i.name] = scalar(text);
    else if (i.kind === 'effect') env.effects![i.name] = text.trim();
    else {
      const list = i.name.includes('[*]') ? text.split(',').map(scalar).filter((x) => x !== '') : [scalar(text)];
      put(env.object!, i.name.split('.'), list);
    }
  }
  return env;
}

/** Parses a value typed as text in a field row: a derived value written as JSON stays an object. */
export function typedValue(s: string): unknown {
  const t = s.trim();
  if (t.startsWith('{') && t.includes(DERIVE_KEY)) {
    try {
      const v = JSON.parse(t) as unknown;
      if (isDerived(v)) return v;
    } catch {
      /* not JSON: kept as a text */
    }
  }
  return /^-?[0-9]+(\.[0-9]+)?$/.test(s) ? Number(s) : s === 'true' ? true : s === 'false' ? false : s;
}

/**
 * The derived value with another function: the arguments that still fit are kept (texts only for copy), the missing
 * ones are filled in, the options of the old function are dropped and those of the new one get their default.
 */
export function switchFn(v: DerivedValue, fn: string): DerivedValue {
  const old = v[DERIVE_KEY];
  const fresh = newDerived(fn)[DERIVE_KEY];
  const [lo, hi] = arity(fn);
  // The base of a date is a date: the arguments of another function are not.
  let args = fn === 'date' && old.fn !== 'date' ? [] : (old.args ?? []).filter((a) => fn === 'copy' || argKind(a) !== 'text').slice(0, hi);
  while (args.length < lo) args = [...args, fresh.args?.[args.length] ?? 1];
  const spec: DeriveSpec = { fn };
  if (args.length) spec.args = args;
  if (fn === 'date') {
    spec.offset = old.offset || fresh.offset;
    spec.format = old.format || fresh.format;
  }
  if (fn === 'template') spec.template = old.template || fresh.template;
  if (fn === 'round') spec.digits = old.digits ?? 2;
  return { [DERIVE_KEY]: spec };
}

/** The derived value with some properties of its body changed (an empty or undefined one is removed). */
export function withSpec(v: DerivedValue, patch: Partial<DeriveSpec>): DerivedValue {
  const spec: Record<string, unknown> = { ...v[DERIVE_KEY], ...patch };
  for (const k of Object.keys(spec)) if (spec[k] === undefined || spec[k] === '') delete spec[k];
  if (Array.isArray(spec.args) && spec.args.length === 0) delete spec.args;
  return { [DERIVE_KEY]: spec as unknown as DeriveSpec };
}
