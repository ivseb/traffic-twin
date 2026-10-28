<script lang="ts">
  // A host pattern (docs/spec/sanitizer.md 3.5) with `{*}` drawn as a wildcard chip. The chip says the part was hidden
  // on purpose because it looked like a value (an id, a hash, a person): it is never something to "reveal".
  import InfoTip from './InfoTip.svelte';
  import { patternParts } from '../lib/hosts';
  import { t } from '../lib/i18n/index.svelte';

  let { pattern, strong = false }: { pattern: string; strong?: boolean } = $props();
  const parts = $derived(patternParts(pattern));
</script>

<span class="pat mono" class:strong>
  {#each parts as p, i (i)}
    {#if p.kind === 'star'}
      <InfoTip id="hosts.wildcard" label={t('hosts.star.label')}><span class="star" title={t('hosts.star.tip')}>{'{*}'}</span></InfoTip>
    {:else if p.kind === 'port'}
      <span class="port">{p.value}</span>
    {:else}
      <span>{p.value}</span>
    {/if}
  {/each}
</span>

<style>
  .pat { display: inline-flex; flex-wrap: wrap; align-items: center; overflow-wrap: anywhere; }
  .strong { font-weight: 650; font-size: 0.95em; }
  .star { display: inline-block; padding: 0 0.35em; margin: 0 1px; border-radius: 999px; border: 1px dashed var(--accent); background: var(--accent-soft); color: var(--accent); font-weight: 650; cursor: help; line-height: 1.35; }
  .port { color: var(--fg-subtle); }
</style>
