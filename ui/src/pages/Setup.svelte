<script lang="ts">
  import Logo from '../components/Logo.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import Card from '../components/Card.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { errorMessage, refreshStatus, session, toast } from '../lib/stores.svelte';
  import { navigate } from '../lib/router.svelte';
  import { api } from '../lib/api';
  import { DemoSetupHint } from 'tt-demo';

  let token = $state('');
  let username = $state('admin');
  let password = $state('');
  let confirm = $state('');
  let error = $state('');
  let busy = $state(false);

  const tooShort = $derived(password.length > 0 && password.length < 12);
  const mismatch = $derived(confirm.length > 0 && confirm !== password);
  const valid = $derived(token.trim() !== '' && username.trim() !== '' && password.length >= 12 && confirm === password);

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.system.setup({ setupToken: token.trim(), username: username.trim(), password });
      await refreshStatus();
      toast(t('setup.done'));
      // The server logs the first administrator in; the demo adapter does not.
      session.user = await api.auth.me().catch(() => null);
      navigate(session.user ? '/onboarding' : '/login');
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="box">
  <div class="brand"><Logo size={40} /><h1>{t('setup.title')}</h1></div>

  {#if session.status?.initialized}
    <Card>
      <EmptyState icon="check" title={t('setup.already')} description={t('setup.alreadyHint')}>
        <Button variant="primary" href="#/login">{t('login.submit')}</Button>
      </EmptyState>
    </Card>
  {:else}
    <p class="muted">{t('setup.intro')}</p>
    <Card>
      <form onsubmit={submit} class="stack" novalidate>
        <Field label={t('setup.token')} hint={t('setup.tokenHint')} help="setup.token">
          {#snippet children({ id, describedby })}
            <input {id} bind:value={token} autocomplete="off" spellcheck="false" placeholder="tts_…" aria-describedby={describedby} />
          {/snippet}
        </Field>
        <Field label={t('setup.username')}>
          {#snippet children({ id })}
            <input {id} bind:value={username} autocomplete="username" />
          {/snippet}
        </Field>
        <Field label={t('setup.password')} help="setup.password" hint={t('setup.passwordHint')} error={tooShort ? t('setup.tooShort') : ''}>
          {#snippet children({ id, describedby })}
            <input {id} type="password" bind:value={password} autocomplete="new-password" aria-describedby={describedby} aria-invalid={tooShort ? 'true' : undefined} />
          {/snippet}
        </Field>
        <Field label={t('setup.confirm')} error={mismatch ? t('setup.mismatch') : error}>
          {#snippet children({ id, describedby })}
            <input {id} type="password" bind:value={confirm} autocomplete="new-password" aria-describedby={describedby} aria-invalid={mismatch ? 'true' : undefined} />
          {/snippet}
        </Field>
        <Button type="submit" variant="primary" full loading={busy} disabled={!valid}>{t('setup.submit')}</Button>
      </form>
    </Card>
    <DemoSetupHint />
  {/if}
</div>

<style>
  .box { width: min(27rem, 100%); display: flex; flex-direction: column; gap: var(--s-4); }
  .brand { display: flex; align-items: center; gap: var(--s-3); }
</style>
