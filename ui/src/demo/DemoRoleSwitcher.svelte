<script lang="ts">
  // Role switcher inside the user menu. Demo build only.
  import { tk } from '../lib/i18n/index.svelte';
  import { session, toastError } from '../lib/stores.svelte';
  import { ALL_ROLES } from '../lib/rbac';
  import { api, type Role } from '../lib/api';
  import { d } from './messages';

  let { onpicked }: { onpicked?: () => void } = $props();

  async function as(role: Role): Promise<void> {
    try {
      session.user = (await api.demo?.loginAs(role)) ?? null;
      onpicked?.();
    } catch (e) {
      toastError(e);
    }
  }
</script>

{#if api.demo}
  <div class="demo">
    <p class="subtle">{d('demo.roles')}</p>
    {#each ALL_ROLES as role (role)}
      <button type="button" class="item" onclick={() => as(role)} aria-current={session.user && session.user.roles.length === 1 && session.user.roles[0] === role ? 'true' : undefined}>
        {tk(`role.${role}`)}
      </button>
    {/each}
  </div>
{/if}

<style>
  .demo { border-bottom: 1px solid var(--border); padding-bottom: var(--s-1); margin-bottom: var(--s-1); }
  .demo p { padding: var(--s-1) var(--s-2); }
  .item { display: flex; align-items: center; gap: var(--s-2); width: 100%; font: inherit; color: var(--fg); background: none; border: 0; border-radius: var(--r-sm); padding: 0.4rem var(--s-2); cursor: pointer; text-align: left; }
  .item:hover { background: var(--surface-2); }
  .item[aria-current='true'] { background: var(--accent-soft); font-weight: 650; }
</style>
