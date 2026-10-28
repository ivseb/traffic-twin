// Logic of the rule editor: definitions in the rules.v1 form (sent to the server as they are), the choices the form
// offers from the catalog, the plain-language preview and the checks the form can do before asking the server.

import type { CatalogField, CatalogOp, RuleCatalog, RuleDefinition, RuleEffectDef, RuleProblem, RuleRefDef } from './api';
import { t, tk } from './i18n/index.svelte';
import { checkDerived, derivedFormula, derivedRefs, isDerived, typedValue } from './derive';
import { matchesText } from './rule-templates';

export type EffectKind = 'state' | 'create' | 'next' | 'error';

const DURATION = /^[0-9]{1,6}(s|m|h|d)$/;

export const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

export function newDefinition(kind: 'causal' | 'batch' = 'causal'): RuleDefinition {
  if (kind === 'batch') return { kind: 'batch', title: '', schedule: '0 2 * * *', entity: '', where: {}, set: {}, fraction: 1 };
  return { kind: 'causal', title: '', cause: { service: '', op: '', when: { status: [] }, bind: {} }, effects: [], outcomes: [{ name: 'always', p: 1, effects: [] }] };
}

export function effectKind(e: RuleEffectDef): EffectKind {
  if (e.respond) return e.respond.times && e.respond.times > 0 ? 'next' : 'error';
  return e.create ? 'create' : 'state';
}

/** The delay as the form writes it: "5m" or "2m-10m". */
export function delayText(a: RuleEffectDef['after']): string {
  return typeof a === 'string' ? a : `${a.min}-${a.max}`;
}

/** Parses "5m" or "2m-10m" (null when invalid). */
export function parseDelay(s: string): RuleEffectDef['after'] | null {
  const v = s.trim().replace(/\s+/g, '');
  if (DURATION.test(v)) return v;
  const m = v.split(/[-–]/);
  if (m.length === 2 && DURATION.test(m[0]) && DURATION.test(m[1])) return { min: m[0], max: m[1] };
  return null;
}

export function findOp(cat: RuleCatalog | undefined, service: string, op: string): CatalogOp | undefined {
  return cat?.services.find((s) => s.name === service)?.ops.find((o) => o.op === op);
}

/** A key for a reference into the cause: "req.path|id", "resp.body|$.id". */
export const refKey = (r: RuleRefDef): string => `${r.from}|${r.path ?? r.name ?? ''}`;

export function refOfKey(key: string): RuleRefDef {
  const [from, rest] = key.split('|');
  return from.endsWith('.body') ? { from, path: rest } : { from, name: rest };
}

export const refLabel = (r: RuleRefDef): string => (r.path ? `${r.from === 'req.body' ? 'req' : 'resp'} ${r.path}` : `${r.from.replace('req.', '')} ${r.name}`);

/** The fields of the cause that can identify an entity: parameters and body fields, identifiers of its domain first. */
export function causeFields(op: CatalogOp | undefined, domain?: string): CatalogField[] {
  if (!op) return [];
  const all = [...(op.params ?? []), ...(op.request ?? []), ...(op.response ?? [])].filter((f) => f.kind === 'id' || f.kind === undefined || f.kind === 'shape');
  const rank = (f: CatalogField) => (f.kind === 'id' && f.domain === domain ? 0 : f.kind === 'id' ? 1 : 2);
  return [...all].sort((a, b) => rank(a) - rank(b));
}

const fieldRef = (f: CatalogField): RuleRefDef => (f.path ? { from: f.from, path: f.path } : { from: f.from, name: f.name ?? '' });

/** The bind variable that holds `ref`, created when missing (named after the entity). */
export function bindFor(def: RuleDefinition, ref: RuleRefDef, hint: string): string {
  const c = def.cause!;
  c.bind ??= {};
  for (const [k, v] of Object.entries(c.bind)) if (refKey(v) === refKey(ref)) return k;
  let base = hint.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '') || 'ref';
  base = base.slice(0, 24);
  let name = base;
  for (let i = 2; c.bind[name]; i++) name = `${base}${i}`;
  c.bind[name] = ref;
  return name;
}

export { fieldRef };

/** "which entity" of a set effect: "eff:<id>" (an earlier effect) or "ref:<refKey>" (an id in the cause). */
export function whichOf(def: RuleDefinition, e: RuleEffectDef): string {
  if (e.target) return `eff:${e.target}`;
  const m = /^\$\{([a-z][a-z0-9_]*)\}$/.exec(e.target_id ?? '');
  const ref = m ? def.cause?.bind?.[m[1]] : undefined;
  return ref ? `ref:${refKey(ref)}` : '';
}

export function setWhich(def: RuleDefinition, e: RuleEffectDef, which: string): void {
  delete e.target;
  delete e.target_id;
  if (which.startsWith('eff:')) e.target = which.slice(4);
  else if (which.startsWith('ref:')) e.target_id = '${' + bindFor(def, refOfKey(which.slice(4)), e.entity ?? 'ref') + '}';
}

export function nextEffectId(def: RuleDefinition): string {
  const ids = new Set((def.effects ?? []).map((e) => e.id));
  for (let i = 1; ; i++) if (!ids.has(`effect-${i}`)) return `effect-${i}`;
}

export function newEffect(def: RuleDefinition, kind: EffectKind, cat?: RuleCatalog): RuleEffectDef {
  const id = nextEffectId(def);
  switch (kind) {
    case 'next':
      return { id, respond: { service: def.cause?.service ?? '', op: '', status: 404, times: 1 }, after: '0s' };
    case 'error':
      return { id, respond: { service: def.cause?.service ?? '', op: '', status: 503, p: 0.2 }, after: '0s' };
    case 'create':
      return { id, entity: cat?.entities[0]?.name ?? '', create: {}, after: '0s' };
    default:
      return { id, entity: cat?.entities[0]?.name ?? '', set: {}, after: '1h' };
  }
}

/** Whether the outcomes are the editor's simple form: one branch with every effect, plus optionally an empty one. */
export function simpleOutcomes(def: RuleDefinition): boolean {
  const o = def.outcomes ?? [];
  const all = (def.effects ?? []).map((e) => e.id).sort().join(',');
  if (o.length === 0 || o.length > 2) return false;
  if (o.some((x) => x.when?.length)) return false; // rules v1.9: conditional branches are edited one by one
  if ([...o[0].effects].sort().join(',') !== all) return false;
  return o.length === 1 || o[1].effects.length === 0;
}

/** Sets the probability that the rule fires (simple form): "always" and, below 1, "never". */
export function setChance(def: RuleDefinition, p: number): void {
  const effects = (def.effects ?? []).map((e) => e.id);
  const name = def.outcomes?.[0]?.name ?? 'always';
  def.outcomes = p >= 1 ? [{ name, p: 1, effects }] : [{ name, p: round(p), effects }, { name: def.outcomes?.[1]?.name ?? 'never', p: round(1 - p), effects: [] }];
}

const round = (p: number) => Math.round(p * 10000) / 10000;

export function addEffect(def: RuleDefinition, e: RuleEffectDef): void {
  const simple = simpleOutcomes(def);
  def.effects = [...(def.effects ?? []), e];
  if (simple) {
    def.outcomes![0].effects = [...def.outcomes![0].effects, e.id];
    return;
  }
  const withEffects = (def.outcomes ?? []).filter((o) => o.effects.length > 0);
  for (const o of withEffects.length ? withEffects : (def.outcomes ?? [])) o.effects = [...o.effects, e.id];
}

export function removeEffect(def: RuleDefinition, id: string): void {
  def.effects = (def.effects ?? []).filter((e) => e.id !== id);
  for (const e of def.effects) {
    if (e.after_effect === id) delete e.after_effect;
    if (e.target === id) delete e.target;
  }
  for (const o of def.outcomes ?? []) o.effects = o.effects.filter((x) => x !== id);
}

/** The definition sent to the server: unused bind variables dropped, every effect's prerequisites in its branches. */
export function finalize(src: RuleDefinition): RuleDefinition {
  const def = clone(src);
  def.title = def.title.trim();
  if (def.kind === 'batch') {
    delete def.cause;
    delete def.effects;
    delete def.outcomes;
    return def;
  }
  const effects = def.effects ?? [];
  const used = new Set<string>();
  for (const e of effects) {
    // rules v1.8: a keyed target and the key of a counter use binds too
    const v18 = [...Object.values(e.target_key ?? {}), e.respond?.limit?.key];
    for (const v of [e.target_id, ...Object.values(e.create ?? {}), ...Object.values(e.set ?? {}), ...v18]) {
      const m = typeof v === 'string' ? /^\$\{([a-z][a-z0-9_]*)\}$/.exec(v) : null;
      if (m) used.add(m[1]);
      // A variable read by a derived value is used too (it would be dropped otherwise).
      if (isDerived(v)) for (const n of derivedRefs(v).vars) used.add(n);
    }
    if (e.respond) {
      if (e.respond.body === undefined || e.respond.body === '') delete e.respond.body;
      if (!e.respond.example) delete e.respond.example;
      if (!e.respond.times) delete e.respond.times;
      if (e.respond.p === undefined || e.respond.p >= 1) delete e.respond.p;
    }
  }
  if (def.cause?.bind) for (const k of Object.keys(def.cause.bind)) if (!used.has(k)) delete def.cause.bind[k];
  const byId = new Map(effects.map((e) => [e.id, e]));
  for (const o of def.outcomes ?? []) {
    const set = new Set(o.effects);
    let grew = true;
    while (grew) {
      grew = false;
      for (const id of [...set]) {
        const e = byId.get(id);
        for (const need of [e?.after_effect, e?.target]) if (need && !set.has(need)) (set.add(need), (grew = true));
      }
    }
    o.effects = effects.map((e) => e.id).filter((id) => set.has(id));
  }
  return def;
}

const pct = (p: number) => `${Math.round(p * 1000) / 10}%`;

function changesText(vals: Record<string, unknown> | undefined, def: RuleDefinition): string {
  const bindName = (s: string) => {
    const m = /^\$\{(effect:)?([a-z][a-z0-9_-]*)\}$/.exec(s);
    return m ? t('re.value.ref', { name: m[1] ? m[2] : refLabel(def.cause?.bind?.[m[2]] ?? { from: '', name: m[2] }) }) : null;
  };
  const parts = Object.entries(vals ?? {}).map(([k, v]) => `${k} = ${typeof v === 'string' ? (bindName(v) ?? v) : isDerived(v) ? t('drv.pv', { formula: derivedFormula(v) }) : JSON.stringify(v)}`);
  return parts.join(', ') || '—';
}

function afterText(def: RuleDefinition, e: RuleEffectDef): string {
  const d = delayText(e.after);
  if (e.after_effect) return t('re.pv.afterEffect', { d, id: e.after_effect });
  return d === '0s' ? t('re.pv.now') : t('re.pv.after', { d });
}

/** The rule in plain language: one sentence for the cause, one per effect. */
export function preview(def: RuleDefinition): string[] {
  if (def.kind === 'batch') {
    if (!def.entity || !Object.keys(def.set ?? {}).length) return [t('re.pv.empty')];
    const where = Object.keys(def.where ?? {}).length ? t('re.pv.where', { where: changesText(def.where, def) }) : '';
    return [t('re.pv.batch', { schedule: def.schedule ?? '', p: pct(def.fraction ?? 1), entity: def.entity, where, changes: changesText(def.set, def) })];
  }
  const c = def.cause;
  const effects = def.effects ?? [];
  if (!c?.service || !c.op || !effects.length) return [t('re.pv.empty')];
  const fires = def.outcomes?.find((o) => o.effects.length > 0);
  const chance = fires && fires.p < 1 && simpleOutcomes(def) ? t('re.pv.chance', { p: pct(fires.p) }) : '';
  // rules v1.9: the conditions of the cause, all of which must hold
  const cond = c.when.match?.length ? t('w4.pv.if', { cond: matchesText(c.when.match) }) : '';
  const head = t('re.pv.when', { service: c.service, status: c.when.status.join('/') || t('re.pv.choose'), op: c.op }) + cond + chance + t('re.pv.then');
  const lines = effects.map((e) => {
    const after = afterText(def, e);
    if (e.respond?.until) {
      return t('w4.pv.until', { op: e.respond.op || t('re.pv.choose'), service: e.respond.service || t('re.pv.choose'), status: e.respond.status });
    }
    if (e.respond?.limit) {
      return t('w4.pv.limit', { n: e.respond.limit.n, window: e.respond.limit.window ?? t('w4.pv.session'), op: e.respond.op || t('re.pv.choose'), status: e.respond.status });
    }
    if (e.target_all) {
      const where = Object.keys(e.where ?? {}).length ? t('re.pv.where', { where: changesText(e.where, def) }) : '';
      return e.remove ? t('w4.pv.allRemove', { after, entity: e.entity ?? t('re.pv.choose'), where }) : t('w4.pv.all', { after, entity: e.entity ?? t('re.pv.choose'), where, changes: changesText(e.set, def) });
    }
    if (e.respond) {
      const n = e.respond.times ?? 0;
      const calls = n === 1 ? t('re.pv.calls.one') : n > 1 ? t('re.pv.calls.n', { n }) : t('re.pv.calls.all');
      const freq = e.respond.p !== undefined && e.respond.p < 1 ? t('re.pv.freq', { p: pct(e.respond.p) }) : '';
      return t('re.pv.next', { after, calls, op: e.respond.op || t('re.pv.choose'), service: e.respond.service || t('re.pv.choose'), freq, verb: n === 1 ? t('re.pv.verb.one') : t('re.pv.verb.many'), status: e.respond.status });
    }
    if (e.create) return t('re.pv.create', { after, entity: e.entity ?? t('re.pv.choose'), changes: changesText(e.create, def) });
    const w = whichOf(def, e);
    const which = w.startsWith('eff:') ? t('re.which.effect', { id: w.slice(4) }) : w ? t('re.which.field', { field: refLabel(refOfKey(w.slice(4))) }) : '?';
    return t('re.pv.state', { after, entity: e.entity ?? t('re.pv.choose'), which, changes: changesText(e.set, def) });
  });
  // rules v1.9: the branches that apply only under conditions
  const conditional = (def.outcomes ?? []).filter((o) => o.when?.length).map((o) => t('w4.pv.outcome', { name: o.name, cond: matchesText(o.when), p: pct(o.p) }));
  return [head, ...lines, ...conditional];
}

/** What the form can tell before asking the server (texts for a person). */
export function localProblems(def: RuleDefinition): string[] {
  const out: string[] = [];
  if (!def.title.trim()) out.push(t('re.local.noTitle'));
  if (def.kind === 'batch') {
    if (!def.entity || !(def.schedule ?? '').trim() || !Object.keys(def.set ?? {}).length) out.push(t('re.local.batch'));
    if (!(def.fraction! > 0 && def.fraction! <= 1)) out.push(t('re.local.badP'));
    return out;
  }
  if (!def.cause?.service || !def.cause.op) out.push(t('re.local.noCause'));
  else if (!def.cause.when.status.length) out.push(t('re.local.noStatus'));
  const effects = def.effects ?? [];
  if (!effects.length) out.push(t('re.local.noEffects'));
  effects.forEach((e, i) => {
    const n = i + 1;
    if (parseDelay(delayText(e.after)) === null) out.push(t('re.local.badAfter', { n }));
    if (e.respond) {
      if (!e.respond.service || !e.respond.op || !e.respond.status) out.push(t('re.local.noCall', { n }));
      if (e.respond.p !== undefined && !(e.respond.p > 0 && e.respond.p <= 1)) out.push(t('re.local.badP'));
      const bodyProblem = errorBodyProblem(e.respond.body);
      if (bodyProblem) out.push(t('ebody.local', { n, msg: tk(`ebody.err.${bodyProblem}`) }));
      return;
    }
    if (!e.create && !e.target && !e.target_id && !e.target_key && !e.target_all) out.push(t('re.local.noWhich', { n }));
    if (e.remove) return;
    const vals = e.create ?? e.set ?? {};
    if (!Object.keys(vals).length || Object.entries(vals).some(([k]) => !k.trim())) out.push(t('re.local.noFields', { n }));
    for (const [k, v] of Object.entries(vals)) {
      if (!isDerived(v)) continue;
      const bad = checkDerived(v);
      if (bad) out.push(t('drv.local', { n, field: k, msg: tk(`drv.err.${bad.code}`, bad.params) }));
    }
  });
  const sum = (def.outcomes ?? []).reduce((a, o) => a + o.p, 0);
  if (Math.abs(sum - 1) > 0.001) out.push(t('re.local.sum'));
  return out;
}

/** Example commands to try the rule in the mock (session, cause, clock, journal). */
export function tryCommands(def: RuleDefinition): string {
  const c = def.cause;
  const after = (def.effects ?? []).map((e) => delayText(e.after)).find((d) => d !== '0s') ?? '1h';
  const [method, path] = (c?.op ?? 'GET /').split(' ');
  return [
    'S=$(curl -s -X POST 127.0.0.1:8480/__tt/sessions -d \'{"seed":42}\' | jq -r .id)',
    `curl -s -X ${method} -H "X-TT-Session: $S" 127.0.0.1:8480/__svc/${c?.service ?? 'service'}${path}`,
    `curl -s -X POST 127.0.0.1:8480/__tt/sessions/$S/clock/advance -d '{"by":"${after.split('-').pop()}"}'`,
    'curl -s 127.0.0.1:8480/__tt/sessions/$S/journal',
  ].join('\n');
}

// ---- field rows of create/set/where values (edited as [field, value] pairs)

type Vals = Record<string, unknown>;

/** Renames a field of a values map, keeping its value (a derived value stays an object) and the order of the keys. */
export function renameRow(v: Vals, oldKey: string, key: string): Vals {
  const out: Vals = {};
  for (const [k, x] of Object.entries(v)) out[k === oldKey ? key : k] = x;
  if (!(oldKey in v)) out[key] = '';
  return out;
}

/** Sets the value of a field from what the person typed (numbers, true/false, a derived value written as JSON). */
export function setRowText(v: Vals, key: string, text: string): Vals {
  return setRowValue(v, key, typedValue(text));
}

/** Sets the value of a field as it is (a derived value object). */
export function setRowValue(v: Vals, key: string, value: unknown): Vals {
  const out: Vals = {};
  for (const [k, x] of Object.entries(v)) out[k] = k === key ? value : x;
  if (!(key in v)) out[key] = value;
  return out;
}

/** The problems of the server about one field of an effect's values (effects[i].create.<field>), shown on the row. */
export function rowProblems(problems: RuleProblem[], effectIndex: number, kind: 'create' | 'set', field: string): RuleProblem[] {
  const base = `effects[${effectIndex}].${kind}`;
  return problems.filter((p) => p.path === `${base}.${field}` || (p.path === base && p.code === 'bad_derived' && p.message.includes(`"${field}"`)));
}

/** The largest error body a respond effect may carry (pack.MaxErrorBody). */
export const MAX_ERROR_BODY = 16 << 10;

/** Why an error body is refused: not an object/array/text, or larger than 16 KiB once written as JSON. */
export function errorBodyProblem(body: unknown): 'type' | 'size' | null {
  if (body === undefined) return null;
  if (typeof body !== 'string' && (typeof body !== 'object' || body === null)) return 'type';
  return new TextEncoder().encode(JSON.stringify(body)).length > MAX_ERROR_BODY ? 'size' : null;
}

/** Reads the error body textarea: JSON (object, array or text in quotes) or, when it is not JSON, a plain text. */
export function parseErrorBody(text: string): { body?: unknown; error?: 'json' } {
  const t = text.trim();
  if (!t) return {};
  if (t.startsWith('{') || t.startsWith('[') || t.startsWith('"')) {
    try {
      return { body: JSON.parse(t) as unknown };
    } catch {
      return { error: 'json' };
    }
  }
  return { body: text };
}

/** The error body as the textarea shows it. */
export function errorBodyText(body: unknown): string {
  if (body === undefined) return '';
  return typeof body === 'string' ? body : JSON.stringify(body, null, 2);
}
