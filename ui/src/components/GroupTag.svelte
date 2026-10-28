<script lang="ts">
  // The group of a row (group, service) when rows of several groups are listed together ("Tutti i gruppi", or
  // "I miei gruppi" with more than one). `always` shows it whatever the filter.
  import Badge from './Badge.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { showGroupColumn } from '../lib/scope.svelte';

  let { group, always = false }: { group: string | readonly string[] | undefined; always?: boolean } = $props();
  const names = $derived(group === undefined ? [] : typeof group === 'string' ? [group] : [...group]);
</script>

{#if (always || showGroupColumn()) && group !== undefined}
  {#each names.length ? names : [''] as g (g)}
    <Badge tone="neutral" title={t('scope.groupTip')}>{g || t('scope.unknownGroup')}</Badge>
  {/each}
{/if}
