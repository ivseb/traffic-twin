/** Splits help markup into text / bold / glossary-link segments (see types.ts). */
export type Seg = { t: 'text'; v: string } | { t: 'b'; v: string } | { t: 'g'; id: string; v: string };

export function parseRich(src: string, termOf: (id: string) => string | undefined = () => undefined): Seg[] {
  const out: Seg[] = [];
  const re = /\[\[([a-z0-9-]+)(?:\|([^\]]+))?\]\]|\*\*([^*]+)\*\*/g;
  let last = 0;
  for (const m of src.matchAll(re)) {
    const i = m.index ?? 0;
    if (i > last) out.push({ t: 'text', v: src.slice(last, i) });
    if (m[3] !== undefined) out.push({ t: 'b', v: m[3] });
    else out.push({ t: 'g', id: m[1], v: m[2] ?? termOf(m[1]) ?? m[1] });
    last = i + m[0].length;
  }
  if (last < src.length) out.push({ t: 'text', v: src.slice(last) });
  return out;
}

/** Every glossary id referenced by a text. */
export function glossaryRefs(src: string): string[] {
  return [...src.matchAll(/\[\[([a-z0-9-]+)(?:\|[^\]]+)?\]\]/g)].map((m) => m[1]);
}
