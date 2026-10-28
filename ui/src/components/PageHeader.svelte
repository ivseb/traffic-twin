<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import Button from './Button.svelte';
  import RichText from './RichText.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { helpUi, pageGuide } from '../lib/help/index.svelte';
  import { fmtAgo } from '../lib/format';
  import { openHelp, seen, markSeen } from '../lib/stores.svelte';

  interface Props {
    title: string;
    description?: string;
    breadcrumbs?: { label: string; href?: string }[];
    actions?: Snippet;
    /** Page guide id: enables the first-visit hint and the contextual guide. */
    help?: string;
    /** Last successful load (ms epoch) and refresh handler. */
    updatedAt?: number;
    onrefresh?: () => void;
    refreshing?: boolean;
  }
  let { title, description, breadcrumbs, actions, help, updatedAt, onrefresh, refreshing = false }: Props = $props();

  const guide = $derived(help ? pageGuide(help) : undefined);
  // Re-evaluate the relative timestamp every 15 s.
  let tick = $state(0);
  $effect(() => {
    if (!updatedAt) return;
    const h = setInterval(() => tick++, 15000);
    return () => clearInterval(h);
  });
  const ago = $derived((void tick, updatedAt ? fmtAgo(new Date(updatedAt).toISOString()) : ''));
  const showHint = $derived(!!guide && !!help && !seen(help));
</script>

<div class="head">
  {#if breadcrumbs?.length}
    <nav class="crumbs" aria-label={t('app.breadcrumbs')}>
      {#each breadcrumbs as c, i (i)}
        {#if c.href}<a href={c.href}>{c.label}</a>{:else}<span aria-current="page">{c.label}</span>{/if}
        {#if i < breadcrumbs.length - 1}<span class="sep" aria-hidden="true">/</span>{/if}
      {/each}
    </nav>
  {/if}
  <div class="main">
    <div class="grow">
      <h1>{title}</h1>
      {#if description}<p class="muted desc">{description}</p>{/if}
    </div>
    <div class="side">
      {#if onrefresh}
        <span class="subtle upd">{#if updatedAt}{t('app.updated', { when: ago })}{/if}</span>
        <Button size="sm" variant="ghost" icon="refresh" loading={refreshing} onclick={onrefresh} aria-label={t('app.refresh')} title={t('app.refresh')}>{''}</Button>
      {/if}
      {#if guide}<Button size="sm" variant="ghost" icon="book" onclick={() => openHelp(help)}>{t('help.guide')}</Button>{/if}
      {#if actions}{@render actions()}{/if}
    </div>
  </div>
  {#if showHint && guide && help}
    <div class="hint" role="note">
      <Icon name="info" size={16} />
      <p class="grow"><b>{helpUi('firstVisitTitle')}</b> <RichText text={guide.firstVisit} /></p>
      <Button size="sm" onclick={() => openHelp(help)}>{t('help.openGuide')}</Button>
      <Button size="sm" variant="ghost" onclick={() => markSeen(help)}>{t('help.dismiss')}</Button>
    </div>
  {/if}
</div>

<style>
  .head { margin-bottom: var(--s-5); display: flex; flex-direction: column; gap: var(--s-2); }
  .crumbs { display: flex; gap: var(--s-2); font-size: 0.86rem; color: var(--fg-subtle); flex-wrap: wrap; }
  .crumbs a { color: var(--fg-muted); text-decoration: none; }
  .crumbs a:hover { color: var(--accent); text-decoration: underline; }
  .sep { color: var(--fg-subtle); }
  .main { display: flex; gap: var(--s-4); align-items: flex-start; flex-wrap: wrap; }
  .main > .grow { flex: 1 1 280px; }
  .side { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; margin-left: auto; }
  .desc { margin-top: var(--s-1); max-width: 72ch; }
  .upd { white-space: nowrap; }
  .hint { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; padding: var(--s-3) var(--s-4); background: var(--accent-soft); border: 1px solid var(--border); border-radius: var(--r-md); color: var(--fg); }
  .hint :global(svg) { color: var(--accent); }
</style>
