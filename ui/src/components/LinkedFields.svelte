<script lang="ts">
  // "Campi collegati": the field dependencies of a body (x-tt-dependencies). For each pair, the values of the field
  // with fewer values lead (macro-category), each with the values of the other field seen with it (categories).
  import type { LinkedFields } from '../lib/api';
  import { t } from '../lib/i18n/index.svelte';
  import { fmtNum } from '../lib/format';

  let { deps, label }: { deps: LinkedFields[]; label: string } = $props();

  const MAX = 8;

  function grouped(d: LinkedFields): { lead: string; other: string; rows: { value: string; with: { v: string; n: number }[] }[] } {
    const distinct = (i: number) => new Set(d.combos.map((c) => c.values[i])).size;
    const li = distinct(0) <= distinct(1) ? 0 : 1;
    const oi = 1 - li;
    const by = new Map<string, { v: string; n: number }[]>();
    for (const c of d.combos) {
      const k = c.values[li];
      by.set(k, [...(by.get(k) ?? []), { v: c.values[oi], n: c.atLeast }]);
    }
    const rows = [...by.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([value, w]) => ({ value, with: w.sort((a, b) => b.n - a.n || a.v.localeCompare(b.v)) }));
    return { lead: d.fields[li], other: d.fields[oi], rows };
  }
</script>

{#if deps.length}
  <section class="linked" aria-label={t('lf.title')} data-testid="linked-fields">
    <h3 class="fs-4">{t('lf.title')} <span class="subtle">· {label}</span></h3>
    <p class="subtle">{t('lf.hint')}</p>
    {#each deps as d, i (i)}
      {@const g = grouped(d)}
      <div class="dep">
        <p class="pair"><b>{t('lf.arrow', { a: g.lead, b: g.other })}</b> <span class="subtle">{d.at ? t('lf.at', { at: d.at }) : t('lf.root')}</span></p>
        <ul>
          {#each g.rows as r (r.value)}
            <li>
              <span class="lead">{r.value}</span> →
              {#each r.with.slice(0, MAX) as w, j (w.v)}<span class="val" title={t('lf.atLeast', { n: fmtNum(w.n) })}>{w.v}</span>{#if j < Math.min(MAX, r.with.length) - 1}{', '}{/if}{/each}
              {#if r.with.length > MAX}<span class="subtle"> {t('lf.more', { n: r.with.length - MAX })}</span>{/if}
            </li>
          {/each}
        </ul>
        {#if d.partial}<p class="subtle note">{t('lf.partial')}</p>{/if}
      </div>
    {/each}
  </section>
{/if}

<style>
  .linked { padding: var(--s-3) var(--s-4); border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: var(--s-2); }
  .linked h3 { margin: 0; }
  .dep { border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-2) var(--s-3); }
  .pair { margin: 0 0 var(--s-1); }
  .dep ul { margin: 0; padding-left: 1.1rem; display: flex; flex-direction: column; gap: 2px; }
  .lead { font-weight: 600; }
  .val { font-family: var(--font-mono); font-size: 0.86rem; }
  .note { margin: var(--s-1) 0 0; font-size: 0.82rem; }
</style>
