// Rules v1.9 in the console: conditions in plain words (cause.when.match, outcomes[].when), the candidates below k
// (C0) and the templates of the rule editor (C18): «una scrittura cambia un campo», «scade dopo», «al massimo n»,
// «finché non». The builders produce rules.v1 definitions the server checks as any other rule written by hand.

import type { MinerCandidate, RuleDefinition, RuleEffectDef, RuleMatch, RuleRefDef } from './api/types';
import { t } from './i18n/index.svelte';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

export type TemplateId = 'write_changes_field' | 'expires_after' | 'at_most_n' | 'until';
export const TEMPLATES: TemplateId[] = ['write_changes_field', 'expires_after', 'at_most_n', 'until'];

export const isTemplate = (s: string | undefined): s is TemplateId => !!s && (TEMPLATES as string[]).includes(s);

/** The name a person reads for a request point: the last member of a body path, or the parameter name. */
export function pointName(r: RuleRefDef | undefined): string {
  if (!r) return '?';
  if (r.path) return r.path.replace(/^\$\.?/, '').split('.').pop() || r.path;
  return r.name ?? '?';
}

const valueText = (v: string | number | boolean) => (typeof v === 'string' ? v : String(v));

/** One condition in plain words: «se il canale è WEB», «se il cliente ha segmento GOLD», «se l'importo è tra 100 e 500». */
export function matchText(m: RuleMatch): string {
  const subject = m.customer ? t('w4.cond.customer', { attr: m.customer }) : t('w4.cond.request', { field: pointName(m.at) });
  if (m.in?.length) {
    const values = m.in.map(valueText).join(', ');
    return m.in.length === 1 ? t('w4.cond.is', { subject, values }) : t('w4.cond.oneOf', { subject, values });
  }
  if (m.min !== undefined && m.max !== undefined) return t('w4.cond.between', { subject, min: m.min, max: m.max });
  if (m.min !== undefined) return t('w4.cond.atLeast', { subject, min: m.min });
  return t('w4.cond.below', { subject, max: m.max ?? '?' });
}

/** All the conditions, joined: they must all hold. */
export function matchesText(ms: RuleMatch[] | undefined): string {
  return (ms ?? []).map(matchText).join(t('w4.cond.and'));
}

/** Parses the values of a condition as a person types them: "WEB, APP" → ["WEB", "APP"]; numbers and booleans typed. */
export function parseValues(s: string): (string | number | boolean)[] {
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map(typed);
}

/** A typed value: a number, a boolean or a string. */
export function typed(s: string): string | number | boolean {
  const v = s.trim();
  if (/^-?[0-9]+(\.[0-9]+)?$/.test(v)) return Number(v);
  if (v === 'true') return true;
  if (v === 'false') return false;
  return v;
}

/**
 * The definition «Crea bozza» opens for a candidate below k: its skeleton (structure only, never an example) or, when
 * the server sent none, the cause alone.
 */
export function candidateDraft(c: MinerCandidate): RuleDefinition {
  if (c.draft) {
    const d = clone(c.draft);
    if (!d.title.trim()) d.title = t('w4.cand.title', { op: c.op });
    return d;
  }
  return {
    kind: 'causal',
    title: t('w4.cand.title', { op: c.op }),
    cause: { service: c.service, op: c.op, when: { status: [] }, bind: {} },
    effects: [],
    outcomes: [{ name: 'always', p: 1, effects: [] }],
  };
}

/** What a template asks for. The cause is the operation that triggers the rule. */
export interface TemplateParams {
  template: TemplateId;
  service: string;
  op: string;
  status: number;
  entity?: string;
  /** Where the request carries the id of the object that changes (target_id). */
  which?: RuleRefDef;
  /** Every object of the customer instead of one (target_all, rules v1.9). */
  all?: boolean;
  field?: string;
  /** The new value: a literal as typed... */
  value?: string;
  /** ...or a copy of a request member (write_changes_field only). */
  copy?: RuleRefDef;
  /** expires_after: the value it goes back to and after how long. */
  revertTo?: string;
  expiresAfter?: string;
  /** at_most_n: how many calls, in which window, per which request member (absent: per customer), answer status. */
  n?: number;
  window?: string;
  key?: RuleRefDef;
  answer?: number;
  /** until: the call that answers `answer` until the cause is seen. */
  targetService?: string;
  targetOp?: string;
  /** Delay of the change (figurative). */
  after?: string;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '').slice(0, 24) || 'ref';
const effSlug = (s: string) => s.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^[^a-z]+/, '').slice(0, 40) || 'effect';

function bind(def: RuleDefinition, ref: RuleRefDef, hint: string): string {
  const b = (def.cause!.bind ??= {});
  for (const [k, v] of Object.entries(b)) if (v.from === ref.from && (v.path ?? v.name) === (ref.path ?? ref.name)) return k;
  const base = slug(hint);
  let name = base;
  for (let i = 2; b[name]; i++) name = `${base}${i}`;
  b[name] = ref.path ? { from: ref.from, path: ref.path } : { from: ref.from, name: ref.name };
  return name;
}

/** The rules.v1 definition of a template (title from the template when the person gave none). */
export function buildTemplate(p: TemplateParams, title = ''): RuleDefinition {
  const def: RuleDefinition = {
    kind: 'causal',
    title,
    cause: { service: p.service, op: p.op, when: { status: p.status ? [p.status] : [] }, bind: {} },
    effects: [],
    outcomes: [],
  };
  const effects: RuleEffectDef[] = [];
  switch (p.template) {
    case 'write_changes_field':
    case 'expires_after': {
      const entity = p.entity ?? '';
      const field = (p.field ?? '').trim();
      const target: Partial<RuleEffectDef> = p.all ? { target_all: true } : p.which ? { target_id: '${' + bind(def, p.which, entity || 'target') + '}' } : {};
      const copied = p.template === 'write_changes_field' && p.copy;
      const value = copied ? '${' + bind(def, p.copy!, field || 'value') + '}' : typed(p.value ?? '');
      const first: RuleEffectDef = { id: `${effSlug(entity)}-updated`, entity, ...target, set: { [field]: value }, after: p.after?.trim() || '0s' };
      effects.push(first);
      if (p.template === 'expires_after') {
        effects.push({
          id: `${effSlug(entity)}-${effSlug(field)}-reverted`.slice(0, 60),
          entity,
          ...target,
          set: { [field]: typed(p.revertTo ?? '') },
          where: { [field]: value },
          after_effect: first.id,
          after: p.expiresAfter?.trim() || '1h',
        });
      }
      def.title ||= p.template === 'expires_after' ? t('w4.tpl.title.expires', { op: p.op, field, after: p.expiresAfter ?? '1h' }) : t('w4.tpl.title.write', { op: p.op, field, entity });
      break;
    }
    case 'at_most_n': {
      const answer = p.answer || 429;
      const key = p.key ? '${' + bind(def, p.key, pointName(p.key)) + '}' : undefined;
      const limit = { n: Math.max(1, Math.round(p.n ?? 1)), ...(p.window?.trim() ? { window: p.window.trim() } : {}), ...(key ? { key } : {}) };
      effects.push({ id: `limit-${answer}`, respond: { service: p.service, op: p.op, status: answer, limit }, after: '0s' });
      def.title ||= t('w4.tpl.title.limit', { n: limit.n, op: p.op });
      break;
    }
    case 'until': {
      const answer = p.answer || 409;
      effects.push({ id: `until-${answer}`, respond: { service: p.targetService || p.service, op: p.targetOp ?? '', status: answer, until: true }, after: '0s' });
      def.title ||= t('w4.tpl.title.until', { target: p.targetOp ?? '?', op: p.op });
      break;
    }
  }
  def.effects = effects;
  def.outcomes = [{ name: 'always', p: 1, effects: effects.map((e) => e.id) }];
  return def;
}

const asText = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v : JSON.stringify(v));

/** The template a definition follows (a C2/C7 draft of the miner, a candidate's skeleton), or null. */
export function templateOf(def: RuleDefinition): TemplateId | null {
  const es = def.effects ?? [];
  if (es.some((e) => e.respond?.until)) return 'until';
  if (es.some((e) => e.respond?.limit)) return 'at_most_n';
  const sets = es.filter((e) => e.set && (e.target_id || e.target_all || e.target_key));
  if (sets.length >= 2 && sets.some((e) => e.where && e.after_effect)) return 'expires_after';
  if (sets.length >= 1) return 'write_changes_field';
  return null;
}

/** The parameters of a template read back from a definition, to prefill the form (null when it follows none). */
export function templateParams(def: RuleDefinition, want?: string): TemplateParams | null {
  const template = isTemplate(want) ? want : templateOf(def);
  const c = def.cause;
  if (!template || !c) return null;
  const refOf = (v: unknown): RuleRefDef | undefined => {
    const m = typeof v === 'string' ? /^\$\{([a-z][a-z0-9_]*)\}$/.exec(v) : null;
    return m ? c.bind?.[m[1]] : undefined;
  };
  const base: TemplateParams = { template, service: c.service, op: c.op, status: c.when.status[0] ?? 0 };
  const es = def.effects ?? [];
  if (template === 'until' || template === 'at_most_n') {
    const e = es.find((x) => (template === 'until' ? x.respond?.until : x.respond?.limit)) ?? es.find((x) => x.respond);
    if (!e?.respond) return base;
    const r = e.respond;
    return template === 'until'
      ? { ...base, answer: r.status, targetService: r.service, targetOp: r.op }
      : { ...base, answer: r.status, n: r.limit?.n ?? 1, window: r.limit?.window ?? '', key: refOf(r.limit?.key) };
  }
  const first = es.find((x) => x.set && !x.where) ?? es.find((x) => x.set);
  if (!first?.set) return { ...base };
  const [field, value] = Object.entries(first.set)[0] ?? ['', ''];
  const copy = refOf(value);
  const out: TemplateParams = {
    ...base,
    entity: first.entity,
    ...(first.target_all ? { all: true } : refOf(first.target_id) ? { which: refOf(first.target_id) } : {}),
    field,
    ...(copy?.from.startsWith('req.') ? { copy } : { value: asText(value) }),
    after: typeof first.after === 'string' ? first.after : `${first.after.min}-${first.after.max}`,
  };
  const back = es.find((x) => x !== first && x.where && x.set);
  if (template === 'expires_after' && back?.set) {
    out.revertTo = asText(back.set[field]);
    out.expiresAfter = typeof back.after === 'string' ? back.after : back.after.max;
  }
  return out;
}

/** What a template still misses (keys of w4.tpl.miss.*), empty when it can be applied. */
export function templateMissing(p: TemplateParams): string[] {
  const out: string[] = [];
  if (!p.service || !p.op) out.push('cause');
  if (p.template === 'write_changes_field' || p.template === 'expires_after') {
    if (!p.entity) out.push('entity');
    if (!p.all && !p.which) out.push('which');
    if (!p.field?.trim()) out.push('field');
    if (!p.copy && !(p.value ?? '').trim()) out.push('value');
    if (p.template === 'expires_after' && !(p.revertTo ?? '').trim()) out.push('revert');
    if (p.template === 'expires_after' && !/^[0-9]{1,6}(s|m|h|d)$/.test((p.expiresAfter ?? '').trim())) out.push('delay');
  }
  if (p.template === 'at_most_n' && !(Number(p.n) >= 1)) out.push('n');
  if (p.template === 'at_most_n' && p.window?.trim() && !/^[0-9]{1,6}(s|m|h|d)$/.test(p.window.trim())) out.push('delay');
  if (p.template === 'until' && !p.targetOp) out.push('target');
  if ((p.template === 'at_most_n' || p.template === 'until') && !(Number(p.answer) >= 100 && Number(p.answer) <= 599)) out.push('answer');
  return out;
}
