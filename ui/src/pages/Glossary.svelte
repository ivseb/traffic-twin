<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import RichText from '../components/RichText.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { glossaryEntry, helpUi, pack } from '../lib/help/index.svelte';
  import { loc, setQuery } from '../lib/router.svelte';

  let q = $state('');
  const entries = $derived(
    Object.entries(pack().glossary)
      .map(([id, g]) => ({ id, ...g }))
      .sort((a, b) => a.term.localeCompare(b.term, undefined, { sensitivity: 'base' })),
  );
  const shown = $derived.by(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    return words.length ? entries.filter((e) => words.every((w) => `${e.term} ${e.short} ${e.long}`.toLowerCase().includes(w))) : entries;
  });
  const current = $derived(loc.query.term);

  // Scroll the linked term into view.
  $effect(() => {
    const id = current;
    if (!id) return;
    queueMicrotask(() => document.getElementById(`term-${id}`)?.scrollIntoView({ block: 'start', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }));
  });
</script>

<PageHeader title={helpUi('gl.title')} description={helpUi('gl.desc')} help="glossary" />

<div class="stack">
  <input type="search" bind:value={q} placeholder={helpUi('gl.search')} aria-label={helpUi('gl.search')} class="s" />
  <div class="list">
    {#each shown as e (e.id)}
      <article id="term-{e.id}" class:cur={current === e.id}>
        <Card>
          <h2 class="fs-3"><a href="#/glossary?term={e.id}" onclick={() => setQuery({ term: e.id })}>{e.term}</a></h2>
          <p class="lead">{e.short}</p>
          <p class="muted"><RichText text={e.long} /></p>
          {#if e.example}<p class="ex"><b>{helpUi('gl.example')}:</b> {e.example}</p>{/if}
          {#if e.see?.length}
            <p class="subtle">{helpUi('gl.see')}: {#each e.see as s, i (s)}{#if i > 0}, {/if}<a href="#/glossary?term={s}">{glossaryEntry(s)?.term ?? s}</a>{/each}</p>
          {/if}
        </Card>
      </article>
    {:else}
      <p class="muted">{helpUi('gl.none')}</p>
    {/each}
  </div>
</div>

<style>
  .s { max-width: 360px; }
  .list { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fill, minmax(min(100%, 420px), 1fr)); align-items: start; }
  article { scroll-margin-top: calc(var(--header-h) + 16px); }
  article.cur :global(.card) { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  h2 a { color: var(--fg); text-decoration: none; }
  .lead { font-weight: 500; margin: var(--s-1) 0 var(--s-2); }
  .ex { margin-top: var(--s-2); padding: var(--s-2) var(--s-3); background: var(--surface-2); border-radius: var(--r-md); font-size: 0.9rem; }
  p + p { margin-top: var(--s-2); }
</style>
