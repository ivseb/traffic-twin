// The policy assistant's services without repeats (usability test #4, M2). After «Simula nel mock» a host seen as
// `host:ip:private:9301` is also declared as `catalog-api`: the server may answer both rows, with the same operations and
// fields under the old key and the new name. Shown as they are, the pages listed every field twice and the keyed lists
// of Svelte stopped on a duplicate key (each_key_duplicate: a blank page). Here a service is one block per key, an
// operation one row per template and a field one row per (operation, part, path) of the service as the policy names it.
import type { AssistOp, AssistService, PolicySuggestion } from './api';

const fieldKey = (f: Pick<PolicySuggestion, 'part' | 'path'>) => `${f.part}\u0000${f.path}`;

/** Elements of `list` whose key was not seen before (first one wins). */
export function uniqBy<T>(list: readonly T[], key: (x: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of list) {
    const k = key(x);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(x);
  }
  return out;
}

function mergeOps(into: AssistOp[], more: readonly AssistOp[]): AssistOp[] {
  const out = into.map((o) => ({ ...o, fields: [...o.fields], rawOps: [...o.rawOps] }));
  for (const o of more) {
    const have = out.find((x) => x.op === o.op);
    if (!have) {
      out.push({ ...o, fields: [...o.fields], rawOps: [...o.rawOps] });
      continue;
    }
    have.declared ||= o.declared;
    have.calls = Math.max(have.calls, o.calls);
    have.needCalls = Math.min(have.needCalls, o.needCalls);
    have.rawOps = [...new Set([...have.rawOps, ...o.rawOps])];
    have.fields = [...have.fields, ...o.fields];
  }
  return out.map((o) => ({ ...o, fields: uniqBy(o.fields, fieldKey) }));
}

/** The name the policy gives the service (the identity of its rows). */
const identity = (s: AssistService) => (s.declared && s.name ? s.name : s.service);

/**
 * One block per service key, one row per operation and per field; a service that is the same policy service as
 * another one (the old `host:` key of a service declared since) keeps only what the main block lacks, and goes when
 * nothing is left. The main block is the one whose key is the declared name, else the declared one, else the busiest.
 */
export function dedupeAssist(services: readonly AssistService[]): AssistService[] {
  // 1. the same key twice: one block.
  const byKey: AssistService[] = [];
  for (const s of services) {
    const have = byKey.find((x) => x.service === s.service);
    if (!have) byKey.push({ ...s, ops: mergeOps([], s.ops) });
    else {
      have.ops = mergeOps(have.ops, s.ops);
      have.calls = Math.max(have.calls, s.calls);
      have.declared ||= s.declared;
      if (!have.name) have.name = s.name;
    }
  }
  // 2. two keys, one policy service.
  const groups = new Map<string, AssistService[]>();
  for (const s of byKey) groups.set(identity(s), [...(groups.get(identity(s)) ?? []), s]);
  const drop = new Set<AssistService>();
  for (const [name, list] of groups) {
    if (list.length < 2) continue;
    const rank = (s: AssistService) => (s.service === name ? 0 : s.declared ? 1 : 2);
    const [main, ...rest] = [...list].sort((a, b) => rank(a) - rank(b) || b.calls - a.calls);
    for (const s of rest) {
      s.ops = s.ops
        .map((o) => {
          const twin = main.ops.find((m) => m.op === o.op);
          if (!twin) return o;
          const known = new Set(twin.fields.map(fieldKey));
          return { ...o, fields: o.fields.filter((f) => !known.has(fieldKey(f))) };
        })
        .filter((o) => o.fields.length > 0 || !main.ops.some((m) => m.op === o.op));
      if (s.ops.length === 0) drop.add(s);
    }
  }
  return byKey.filter((s) => !drop.has(s));
}

/** The flat list of field proposals of `services`, in their order (the ids the choices refer to). */
export function suggestionsOf(services: readonly AssistService[]): PolicySuggestion[] {
  return services.flatMap((s) => s.ops.flatMap((o) => o.fields));
}
