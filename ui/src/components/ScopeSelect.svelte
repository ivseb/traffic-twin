<script lang="ts">
  // Group/Team filter of the header (lib/scope.svelte.ts).
  import { t } from '../lib/i18n/index.svelte';
  import { ALL, MINE, loadScope, scope, scopeValue, setScope } from '../lib/scope.svelte';
  import { isAdmin } from '../lib/rbac';
  import { session } from '../lib/stores.svelte';

  $effect(() => {
    if (session.user && !scope.data) void loadScope();
  });
  const value = $derived(scopeValue());
  // For an administrator "my groups" are the groups it acted on (tokens, policies): other teams, not its own.
  const mineLabel = (groups: string) => (isAdmin(session.user) ? t('scope.mineAdmin', { groups }) : t('scope.mine', { groups }));
</script>

{#if session.user && scope.data && scope.data.groups.length > 0}
  <label class="scope">
    <span class="lbl">{t('scope.label')}</span>
    <select value={value} onchange={(e) => setScope((e.currentTarget as HTMLSelectElement).value)} aria-label={t('scope.aria')} title={t('scope.title')}>
      <option value={ALL}>{t('scope.all')}</option>
      {#if scope.data.mine.length > 0}<option value={MINE}>{mineLabel(scope.data.mine.join(', '))}</option>
      {:else if !isAdmin(session.user)}<option value={MINE}>{t('fix4.scope.mineNone')}</option>{/if}
      {#each scope.data.groups as g (g)}<option value={g}>{g}</option>{/each}
    </select>
  </label>
{/if}

<style>
  .scope { display: inline-flex; align-items: center; gap: var(--s-2); font-size: 0.84rem; color: var(--fg-muted); }
  .scope select { max-width: 14rem; height: 30px; font-size: 0.84rem; }
  @media (max-width: 899px) { .lbl { display: none; } .scope select { max-width: 9rem; } }
</style>
