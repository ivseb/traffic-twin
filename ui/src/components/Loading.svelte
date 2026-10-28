<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { ApiError } from '../lib/api/types';
  import { errorMessage } from '../lib/stores.svelte';
  // `label`: what is being loaded or computed, shown above the skeleton (a grey skeleton alone looked like a hang:
  // usability test #4, m4). After `slowMs` the page says that the server is still working, with a retry.
  let { error, onretry, lines = 4, label, slowMs = 15000 }: { error?: Error; onretry?: () => void; lines?: number; label?: string; slowMs?: number } = $props();
  const widths = [92, 78, 86, 64, 90, 72];
  const unsupported = $derived(error instanceof ApiError && error.code === 'unsupported');
  const forbidden = $derived(error instanceof ApiError && error.code === 'forbidden');
  let slow = $state(false);
  $effect(() => {
    if (error) return;
    slow = false;
    const h = setTimeout(() => (slow = true), slowMs);
    return () => clearTimeout(h);
  });
</script>

{#if error && unsupported}
  <div class="callout warn" role="status">
    <b>{t('common.unsupportedTitle')}</b> {t('common.unsupportedHint')}
  </div>
{:else if error}
  <div class="callout {forbidden ? 'warn' : 'danger'}" role="alert">
    {#if forbidden}{errorMessage(error)}{:else}<b>{t('common.error')}</b> {errorMessage(error)}{/if}
    {#if onretry && !forbidden}<button type="button" class="link-btn" onclick={onretry}>{t('common.retry')}</button>{/if}
  </div>
{:else}
  <div class="load" role="status" aria-busy="true" aria-label={label ?? t('common.loading')}>
    <span class="txt subtle">{label ?? t('fix4.loading')}</span>
    {#if slow}<span class="txt subtle slow">{t('fix4.slow')}{#if onretry} <button type="button" class="link-btn" onclick={onretry}>{t('common.retry')}</button>{/if}</span>{/if}
    <span class="skeleton head"></span>
    {#each Array.from({ length: lines }, (_, i) => i) as i (i)}
      <span class="skeleton line" style:width="{widths[i % widths.length]}%"></span>
    {/each}
  </div>
{/if}

<style>
  .load { display: flex; flex-direction: column; gap: var(--s-3); padding: var(--s-4) 0; }
  .txt { font-size: 0.88rem; }
  .head { height: 20px; width: 34%; }
  .line { height: 14px; }
</style>
