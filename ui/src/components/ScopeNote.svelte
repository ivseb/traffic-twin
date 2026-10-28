<script lang="ts">
  // Says that a list is filtered by the Group/Team filter and offers to show every group. The server filters the
  // lists (`?group=`): `hidden` is given only where the page still knows how many rows it left out.
  import { t } from '../lib/i18n/index.svelte';
  import { ALL, scopeLabel, scopeNoGroups, setScope } from '../lib/scope.svelte';

  let { hidden }: { hidden?: number } = $props();
  const label = $derived(scopeLabel());
</script>

{#if scopeNoGroups()}
  <p class="callout note scope-note" role="status">{t('fix4.scope.noneNote')}</p>
{:else if label}
  <p class="callout note scope-note" role="status">
    {hidden === undefined ? t('scope.noteServer', { groups: label }) : t('scope.note', { groups: label, n: hidden })}
    {#if hidden === undefined || hidden > 0}<button type="button" class="linkish" onclick={() => setScope(ALL)}>{t('scope.showAll')}</button>{/if}
  </p>
{/if}

<style>
  .scope-note { margin: 0 0 var(--s-3); display: flex; flex-wrap: wrap; gap: var(--s-2); align-items: baseline; }
  .linkish { all: unset; cursor: pointer; color: var(--accent); text-decoration: underline; }
  .linkish:focus-visible { outline: 2px solid var(--focus); }
</style>
