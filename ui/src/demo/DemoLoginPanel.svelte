<script lang="ts">
  // One-click role logins and the demo password hint. Demo build only.
  import Button from '../components/Button.svelte';
  import { tk } from '../lib/i18n/index.svelte';
  import { afterLoginPath, refreshStatus, session, toastError } from '../lib/stores.svelte';
  import { navigate } from '../lib/router.svelte';
  import { api } from '../lib/api';
  import { ALL_ROLES } from '../lib/rbac';
  import type { Role } from '../lib/api';
  import { d } from './messages';

  async function as(role: Role): Promise<void> {
    try {
      session.user = (await api.demo?.loginAs(role)) ?? null;
      navigate(afterLoginPath());
    } catch (e) {
      toastError(e);
    }
  }
  async function firstRun(): Promise<void> {
    api.demo?.resetFirstRun();
    await refreshStatus();
    navigate('/setup');
  }
</script>

{#if api.demo}
  <div class="callout demo">
    <b>{d('demo.login.title')}</b>
    <p>{d('demo.login.text')}</p>
    <div class="row-tight roles">
      {#each ALL_ROLES as role (role)}
        <Button size="sm" onclick={() => as(role)}>{tk(`role.${role}`)}</Button>
      {/each}
    </div>
    <p class="subtle">{d('demo.login.creds')}</p>
    <button type="button" class="link-btn" onclick={firstRun}>{d('demo.login.firstRun')}</button>
  </div>
{/if}

<style>
  .demo p { margin: var(--s-1) 0; }
  .roles { margin: var(--s-2) 0; }
</style>
