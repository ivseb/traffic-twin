<script lang="ts">
  // Time-range picker (presets). The value usually lives in the URL via queryParam().
  import { t } from '../lib/i18n/index.svelte';
  import { RANGES, type Range } from '../lib/format';

  let { value = $bindable(), label }: { value: Range; label?: string } = $props();
</script>

<div class="seg" role="group" aria-label={label ?? t('range.label')}>
  {#each RANGES as r (r)}
    <button type="button" aria-pressed={value === r} onclick={() => (value = r)}>{t(`range.${r}` as 'range.1h')}</button>
  {/each}
</div>

<style>
  .seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-md); overflow: hidden; }
  button { font: inherit; font-size: 0.82rem; font-weight: 500; border: 0; border-right: 1px solid var(--border); background: var(--surface); color: var(--fg-muted); padding: 4px 10px; cursor: pointer; }
  button:last-child { border-right: 0; }
  button:hover { background: var(--surface-2); color: var(--fg); }
  button[aria-pressed='true'] { background: var(--accent); color: var(--accent-fg); }
</style>
