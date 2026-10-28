<script lang="ts">
  // World explorer: the synthetic customers of one world (search, pages) and, for the chosen customer, its entities
  // with their state timelines. Everything shown is invented by the generator.
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import Badge from './Badge.svelte';
  import Loading from './Loading.svelte';
  import EntityTimeline from './EntityTimeline.svelte';
  import WorldGraph from './WorldGraph.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { World } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { fmtNum } from '../lib/format';
  import { entitiesLabel } from '../lib/world-explorer';

  let { world }: { world: World } = $props();

  const PAGE = 20;
  let q = $state('');
  let applied = $state('');
  let offset = $state(0);
  let picked = $state('');

  // The search is applied a moment after typing stops.
  $effect(() => {
    const v = q.trim();
    const h = setTimeout(() => {
      if (v !== applied) {
        applied = v;
        offset = 0;
      }
    }, 250);
    return () => clearTimeout(h);
  });
  // Another world: back to the first page, nothing chosen.
  $effect(() => {
    void world.id;
    offset = 0;
    picked = '';
    q = '';
    applied = '';
  });

  const page = resource(() => api.worlds.customers(world.id, { q: applied, offset, limit: PAGE }));
  const first = $derived(page.data?.customers[0]?.id ?? '');
  const customerId = $derived(picked || first);
  const detail = resource(async () => (customerId ? await api.worlds.customer(world.id, customerId) : null));
  const index = $derived(Number(/-(\d+)$/.exec(customerId)?.[1] ?? 0) - 1);
  const graph = resource(async () => (index >= 0 && customerId ? await api.worlds.graph(world.id, index) : null));

  const total = $derived(page.data?.total ?? 0);
  const from = $derived(total === 0 ? 0 : offset + 1);
  const to = $derived(Math.min(total, offset + PAGE));
</script>

<Card title={t('wx.title', { id: world.id })} subtitle={t('wx.hint')}>
  <div class="layout">
    <section class="list" aria-label={t('wx.customers')}>
      <div class="search">
        <label for="wx-q">{t('wx.search')}</label>
        <input id="wx-q" type="search" bind:value={q} placeholder={t('wx.searchPh')} autocomplete="off" spellcheck="false" />
      </div>
      {#if page.data}
        {#if page.data.customers.length === 0}
          <p class="muted">{t('wx.none')}</p>
        {:else}
          <table>
            <caption class="sr-only">{t('wx.customers')}</caption>
            <thead><tr><th scope="col">{t('wx.col.customer')}</th><th scope="col" class="hide-sm">{t('wx.col.archetype')}</th><th scope="col" class="hide-sm">{t('wx.col.entities')}</th></tr></thead>
            <tbody>
              {#each page.data.customers as c (c.id)}
                <tr class:sel={c.id === customerId}>
                  <td>
                    <button type="button" class="link-btn" aria-current={c.id === customerId ? 'true' : undefined} onclick={() => (picked = c.id)}>
                      <code>{c.id}</code>
                      <span class="nm">{c.name}</span>
                    </button>
                  </td>
                  <td class="hide-sm">{#if c.archetype}<Badge tone="accent">{c.archetype}</Badge>{/if}</td>
                  <td class="hide-sm subtle">{entitiesLabel(c.entities) || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        <div class="pager">
          <span class="subtle" role="status">{t('wx.range', { from: fmtNum(from), to: fmtNum(to), total: fmtNum(total) })}{#if applied} · {t('wx.filtered', { all: fmtNum(page.data.all) })}{/if}</span>
          <span class="row-tight">
            <Button size="sm" icon="arrowLeft" disabled={offset === 0} onclick={() => (offset = Math.max(0, offset - PAGE))}>{t('world.prev')}</Button>
            <Button size="sm" icon="arrowRight" disabled={offset + PAGE >= total} onclick={() => (offset += PAGE)}>{t('world.next')}</Button>
          </span>
        </div>
      {:else}
        <Loading error={page.error} onretry={page.reload} lines={6} />
      {/if}
    </section>

    <section class="detail" aria-label={t('wx.detail')} aria-live="polite">
      {#if detail.data}
        <header>
          <h3 class="fs-3">{detail.data.name || detail.data.id}</h3>
          <p class="subtle"><code>{detail.data.id}</code>{#if detail.data.email} · {detail.data.email}{/if}</p>
          {#if detail.data.archetype}<p><Badge tone="accent">{detail.data.archetype}</Badge> <span class="subtle">{t('world.fakeNote')}</span></p>{/if}
        </header>
        {#if detail.data.entities.length === 0}
          <p class="muted">{t('wx.noEntities')}</p>
        {:else}
          <div class="ents">
            {#each detail.data.entities as e (e.entity + e.id)}<EntityTimeline entity={e} />{/each}
          </div>
        {/if}
        {#if graph.data && graph.data.nodes.length > 1}
          <h4 class="fs-4 gh">{t('wx.graph')}</h4>
          <WorldGraph graph={graph.data} />
        {/if}
      {:else if customerId}
        <Loading error={detail.error} onretry={detail.reload} lines={5} />
      {:else}
        <p class="muted">{t('wx.pick')}</p>
      {/if}
    </section>
  </div>
</Card>

<style>
  .layout { display: grid; grid-template-columns: minmax(280px, 26rem) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  .search { display: flex; flex-direction: column; gap: var(--s-1); margin-bottom: var(--s-3); }
  .search label { font-weight: 600; font-size: 0.85rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th { text-align: left; font-size: 0.75rem; text-transform: uppercase; color: var(--fg-subtle); padding: var(--s-1) var(--s-2); border-bottom: 1px solid var(--border-strong); }
  td { padding: var(--s-1) var(--s-2); border-bottom: 1px solid var(--border); vertical-align: top; }
  tr.sel td { background: var(--accent-soft); }
  .link-btn { all: unset; cursor: pointer; display: flex; flex-direction: column; gap: 1px; color: var(--accent); }
  .link-btn:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  .nm { color: var(--fg); }
  .pager { display: flex; justify-content: space-between; align-items: center; gap: var(--s-2); flex-wrap: wrap; margin-top: var(--s-3); }
  .ents { display: flex; flex-direction: column; gap: var(--s-3); margin-top: var(--s-3); }
  header h3 { margin: 0; }
  header p { margin: 2px 0 0; }
  .gh { margin: var(--s-4) 0 var(--s-2); }
  @media (max-width: 960px) {
    .layout { grid-template-columns: minmax(0, 1fr); }
    .hide-sm { display: none; }
  }
</style>
