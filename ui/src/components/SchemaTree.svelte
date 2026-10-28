<script lang="ts">
  import type { SchemaNode } from '../lib/api';
  import ProgressBar from './ProgressBar.svelte';
  import Badge from './Badge.svelte';
  import { t } from '../lib/i18n/index.svelte';

  let { root }: { root: SchemaNode } = $props();
</script>

{#snippet row(n: SchemaNode, depth: number, isRoot: boolean)}
  <li role="treeitem" aria-selected="false" aria-level={depth + 1}>
    <div class="line">
      <span class="name" style:padding-inline-start="{depth * 1.1}rem">
        <code>{isRoot ? '$' : n.name}{n.type === 'array' ? '[]' : ''}</code>
        <span class="type">{n.type === 'array' ? `array<${n.itemType ?? 'object'}>` : n.type}{n.format ? ` · ${n.format}` : ''}</span>
        {#if n.enumValues}<span class="enum">{n.enumValues.join(' | ')}</span>{/if}
      </span>
      <span class="pres">
        {#if n.presence >= 1}
          <Badge tone="neutral">{t('schema.always')}</Badge>
        {:else}
          <ProgressBar value={n.presence} label={t('schema.presence', { name: n.name })} tone="auto" />
        {/if}
      </span>
    </div>
    {#if n.children?.length}
      <ul role="group">
        {#each n.children as c (c.name)}
          {@render row(c, depth + 1, false)}
        {/each}
      </ul>
    {/if}
  </li>
{/snippet}

<ul role="tree" aria-label={t('schema.tree')} class="tree">
  {@render row(root, 0, true)}
</ul>

<style>
  .tree, ul { list-style: none; margin: 0; padding: 0; }
  .line { display: grid; grid-template-columns: minmax(0, 1fr) 10rem; gap: var(--s-3); align-items: center; padding: 0.35rem var(--s-3); border-bottom: 1px solid var(--border); }
  .name { display: flex; gap: var(--s-2); align-items: baseline; flex-wrap: wrap; min-width: 0; }
  code { font-weight: 650; }
  .type { color: var(--fg-muted); font-size: 0.82rem; }
  .enum { font-size: 0.78rem; color: var(--info); background: var(--info-soft); border-radius: 4px; padding: 0 0.35rem; font-family: var(--font-mono); }
  .pres { display: flex; justify-content: flex-end; }
  @media (max-width: 560px) { .line { grid-template-columns: 1fr; gap: 2px; } .pres { justify-content: flex-start; } }
</style>
