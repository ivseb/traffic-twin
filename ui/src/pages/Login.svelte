<script lang="ts">
  import Logo from '../components/Logo.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import Card from '../components/Card.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { afterLoginPath, doLogin, doSso, errorMessage, session } from '../lib/stores.svelte';
  import { navigate } from '../lib/router.svelte';
  import { DemoLoginPanel } from 'tt-demo';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  // The identity provider sends the browser back to "/?auth_error=<code>" when sign-in fails.
  const authError = (() => {
    try {
      const code = new URLSearchParams(window.location.search).get('auth_error');
      return code ? tk(`err.auth.${code}`, undefined, tk('err.auth.other')) : '';
    } catch {
      return '';
    }
  })();

  const local = $derived(session.status?.localEnabled ?? true);

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await doLogin(username.trim(), password);
      navigate(afterLoginPath());
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
  async function sso(): Promise<void> {
    busy = true;
    error = '';
    try {
      await doSso();
      navigate(afterLoginPath());
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="box">
  <div class="brand"><Logo size={40} /><h1>traffic-twin</h1></div>
  <p class="muted center">{t('login.subtitle')}</p>

  {#if authError}<p class="callout danger" role="alert">{authError}</p>{/if}

  <Card>
    {#if local}
      <form onsubmit={submit} class="stack" novalidate>
        <Field label={t('login.username')}>
          {#snippet children({ id, describedby })}
            <input {id} bind:value={username} autocomplete="username" required aria-describedby={describedby} />
          {/snippet}
        </Field>
        <Field label={t('login.password')} error={error}>
          {#snippet children({ id, describedby })}
            <input {id} type="password" bind:value={password} autocomplete="current-password" required aria-describedby={describedby} aria-invalid={error ? 'true' : undefined} />
          {/snippet}
        </Field>
        <Button type="submit" variant="primary" full loading={busy} disabled={!username || !password}>{t('login.submit')}</Button>
      </form>
    {/if}
    {#if session.status?.ssoEnabled}
      {#if local}<div class="or"><span>{t('login.or')}</span></div>{/if}
      <Button full onclick={sso} disabled={busy} icon="lock">{t('login.sso')}</Button>
      {#if !local && error}<p class="callout danger" role="alert">{error}</p>{/if}
    {/if}
    {#if !local && !session.status?.ssoEnabled}
      <p class="callout warn">{t('login.noMethod')}</p>
    {/if}
  </Card>

  <DemoLoginPanel />
</div>

<style>
  .box { width: min(25rem, 100%); display: flex; flex-direction: column; gap: var(--s-4); }
  .brand { display: flex; align-items: center; justify-content: center; gap: var(--s-3); }
  .center { text-align: center; }
  .or { display: flex; align-items: center; gap: var(--s-3); margin: var(--s-4) 0; color: var(--fg-subtle); font-size: 0.82rem; }
  .or::before, .or::after { content: ''; flex: 1; border-top: 1px solid var(--border); }
</style>
