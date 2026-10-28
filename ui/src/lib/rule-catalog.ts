// The rule editor's catalog without repeats (usability test #4, M1). The editor's lists are keyed (service names,
// operations, entities, field names, values): a name twice (the same service of two groups, an entity of another team
// with the same name, a status listed twice) stopped the rendering on a duplicate key and the editor stayed on its
// loading skeleton for ever, with no request pending and no message. The catalog is made unique here.
import type { CatalogField, CatalogOp, OperationSummary, RuleCatalog } from './api';

const uniq = <T>(xs: readonly T[] | undefined): T[] => [...new Set(xs ?? [])];
const fieldId = (f: CatalogField) => `${f.from}|${f.path ?? f.name ?? ''}`;

function mergeFields(a: readonly CatalogField[] | undefined, b: readonly CatalogField[] | undefined, key: (f: CatalogField) => string = fieldId): CatalogField[] {
  const out: CatalogField[] = [];
  for (const f of [...(a ?? []), ...(b ?? [])]) {
    const have = out.find((x) => key(x) === key(f));
    if (have) have.values = uniq([...(have.values ?? []), ...(f.values ?? [])]);
    else out.push({ ...f, ...(f.values ? { values: uniq(f.values) } : {}) });
  }
  return out;
}

function mergeOp(a: CatalogOp, b?: CatalogOp): CatalogOp {
  const examples: Record<string, string[]> = {};
  for (const [st, xs] of [...Object.entries(a.examples ?? {}), ...Object.entries(b?.examples ?? {})]) examples[st] = uniq([...(examples[st] ?? []), ...xs]);
  return {
    op: a.op,
    statuses: uniq([...(a.statuses ?? []), ...(b?.statuses ?? [])]).sort((x, y) => x - y),
    ...(Object.keys(examples).length ? { examples } : {}),
    params: mergeFields(a.params, b?.params),
    request: mergeFields(a.request, b?.request),
    response: mergeFields(a.response, b?.response),
  };
}

/**
 * The catalog with every name once: services by name (operations merged), operations by template, statuses, examples
 * and fields once, and the entities of the listed services only (the server lists every team's), one per name.
 */
export function normalizeCatalog(cat: RuleCatalog | undefined): RuleCatalog | undefined {
  if (!cat) return undefined;
  const services: RuleCatalog['services'] = [];
  for (const s of cat.services ?? []) {
    let have = services.find((x) => x.name === s.name);
    if (!have) services.push((have = { name: s.name, ops: [] }));
    for (const o of s.ops ?? []) {
      const i = have.ops.findIndex((x) => x.op === o.op);
      if (i >= 0) have.ops[i] = mergeOp(have.ops[i], o);
      else have.ops.push(mergeOp(o));
    }
  }
  const names = new Set(services.map((s) => s.name));
  const entities: RuleCatalog['entities'] = [];
  for (const e of cat.entities ?? []) {
    if (names.size && !names.has(e.service)) continue;
    const have = entities.find((x) => x.name === e.name);
    if (have) {
      have.ops = uniq([...have.ops, ...(e.ops ?? [])]);
      have.fields = mergeFields(have.fields, e.fields, (f) => f.name ?? '');
    } else entities.push({ ...e, ops: uniq(e.ops), fields: mergeFields([], e.fields, (f) => f.name ?? '') });
  }
  return { services, entities };
}

/** What the editor can offer: no contracts, no entities (no state to set), or entities without values in clear. */
export function catalogNotice(cat: RuleCatalog | undefined): { noServices: boolean; noEntities: boolean; noValues: boolean } {
  const entities = cat?.entities ?? [];
  return {
    noServices: (cat?.services.length ?? 0) === 0,
    noEntities: entities.length === 0,
    noValues: entities.length > 0 && !entities.some((e) => e.fields.some((f) => (f.values?.length ?? 0) > 0)),
  };
}

// ---------------------------------------------------------------- slow catalog (usability test #5, M4)

/**
 * A partial catalog from the operations of the contracts (services, operations and the statuses seen): enough to write
 * a rule on calls, errors and faults while the server is still computing the entities and the state values.
 */
export function catalogFromOperations(ops: readonly OperationSummary[]): RuleCatalog {
  const services = new Map<string, CatalogOp[]>();
  for (const o of ops) {
    const list = services.get(o.service) ?? [];
    list.push({ op: o.op, statuses: o.statuses.map((s) => s.status) });
    services.set(o.service, list);
  }
  return { services: [...services].map(([name, list]) => ({ name, ops: list })), entities: [] };
}

interface Kept {
  catalog: RuleCatalog;
  /** When it was read (epoch ms). */
  at: number;
}
const kept = new Map<string, Kept>();

/** The key of a group selection in the cache (no selection: every group). */
export const catalogKey = (groups: readonly string[] | null | undefined): string => (groups?.length ? [...groups].sort().join(',') : '*');

/** The catalog read earlier in this tab for the groups, if any: the editor opens on it while the server refreshes it. */
export function keptCatalog(groups: readonly string[] | null | undefined): Kept | undefined {
  return kept.get(catalogKey(groups));
}

export function keepCatalog(groups: readonly string[] | null | undefined, catalog: RuleCatalog, at = Date.now()): void {
  kept.set(catalogKey(groups), { catalog, at });
}

/** Forgets what was kept (tests). */
export function forgetCatalogs(): void {
  kept.clear();
}
