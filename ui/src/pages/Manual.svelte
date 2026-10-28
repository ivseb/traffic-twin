<script lang="ts">
  // "Manuale utente": docs/USER_GUIDE.md, built into the console so that it is there on any installation.
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { renderMarkdown } from '../lib/markdown';
  import guide from '../../../docs/USER_GUIDE.md?raw';

  const doc = renderMarkdown(guide);
  const toc = doc.headings.filter((h) => h.level === 2);

  function jump(e: MouseEvent, id: string): void {
    // The hash is the router's: scroll instead of navigating.
    e.preventDefault();
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
</script>

<PageHeader title={t('manual.title')} description={t('manual.desc')} breadcrumbs={[{ label: t('manual.title') }]} />

<div class="layout">
  <nav aria-label={t('manual.toc')}>
    <Card>
      <ol class="toc">
        {#each toc as h (h.id)}<li><a href={'#' + h.id} onclick={(e) => jump(e, h.id)}>{h.text}</a></li>{/each}
      </ol>
    </Card>
  </nav>
  <article class="md">
    <Card>
      <!-- eslint-disable-next-line svelte/no-at-html-tags -- produced by lib/markdown.ts, which escapes the source -->
      {@html doc.html}
    </Card>
  </article>
</div>

<style>
  .layout { display: grid; grid-template-columns: minmax(200px, 280px) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  nav { position: sticky; top: calc(var(--header-h) + var(--s-4)); max-height: calc(100dvh - var(--header-h) - 32px); overflow: auto; }
  .toc { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: var(--s-1); font-size: 0.9rem; }
  .md { min-width: 0; line-height: 1.6; }
  .md :global(h1) { font-size: 1.5rem; margin: 0 0 var(--s-3); }
  .md :global(h2) { font-size: 1.25rem; margin: var(--s-6) 0 var(--s-2); padding-top: var(--s-2); border-top: 1px solid var(--border); scroll-margin-top: calc(var(--header-h) + var(--s-4)); }
  .md :global(h3) { font-size: 1.05rem; margin: var(--s-4) 0 var(--s-2); scroll-margin-top: calc(var(--header-h) + var(--s-4)); }
  .md :global(pre.code) { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3); overflow-x: auto; font-size: 0.85rem; }
  .md :global(blockquote) { margin: var(--s-3) 0; padding: var(--s-2) var(--s-3); border-left: 3px solid var(--accent); background: var(--accent-soft); }
  .md :global(table) { margin: var(--s-3) 0; }
  .md :global(p), .md :global(ul), .md :global(ol) { margin: var(--s-2) 0; }
  @media (max-width: 960px) { .layout { grid-template-columns: minmax(0, 1fr); } nav { position: static; max-height: none; } }
</style>
