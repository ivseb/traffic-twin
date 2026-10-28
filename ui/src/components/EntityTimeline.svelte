<script lang="ts">
  // One entity of a synthetic customer (an order, a shipment...) with the states it went through, in order.
  import Badge from './Badge.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { statusPath } from '../lib/world-explorer';
  import type { WorldEntity } from '../lib/api';

  let { entity }: { entity: WorldEntity } = $props();
  const path = $derived(statusPath(entity));
  const when = (iso: string) => (iso ? iso.replace('T', ' ').replace(/(:\d\d)?(\.\d+)?Z$/, '') : '—');
</script>

<section class="ent" aria-label="{entity.entity} {entity.id}">
  <h4 class="fs-4"><span class="kind">{entity.entity}</span> <code>{entity.id}</code></h4>
  {#if path.length}
    <p class="path" aria-label={t('wx.path')}>
      {#each path as s, i (i)}{#if i > 0}<span class="arrow" aria-hidden="true">→</span>{/if}<Badge tone={i === path.length - 1 ? 'accent' : 'neutral'}>{s}</Badge>{/each}
    </p>
  {/if}
  {#if entity.steps.length}
    <ol class="steps">
      {#each entity.steps as s (s.seq + s.at)}
        <li>
          <time datetime={s.at}>{when(s.at)}</time>
          <b>{s.status || t('wx.noStatus')}</b>
          {#if s.rule}<span class="subtle">{t('wx.byRule', { rule: s.rule })}{#if s.outcome} · {s.outcome}{/if}</span>{:else}<span class="subtle">{t('wx.byCall')}</span>{/if}
        </li>
      {/each}
    </ol>
  {:else}
    <p class="subtle">{t('wx.noHistory')}</p>
  {/if}
</section>

<style>
  .ent { border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3); background: var(--surface); }
  h4 { margin: 0 0 var(--s-2); display: flex; gap: var(--s-2); align-items: baseline; flex-wrap: wrap; }
  .kind { text-transform: capitalize; }
  .path { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s-1); margin: 0 0 var(--s-2); }
  .arrow { color: var(--fg-subtle); }
  .steps { list-style: none; margin: 0; padding: 0 0 0 var(--s-3); border-left: 2px solid var(--border-strong); display: flex; flex-direction: column; gap: var(--s-2); }
  .steps li { display: flex; gap: var(--s-2); align-items: baseline; flex-wrap: wrap; }
  time { font-variant-numeric: tabular-nums; color: var(--fg-muted); font-size: 0.85rem; }
</style>
