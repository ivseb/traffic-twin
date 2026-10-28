<script lang="ts">
  import Icon from './Icon.svelte';
  import Badge from './Badge.svelte';
  import { t, tk, i18n, setLang } from '../lib/i18n/index.svelte';
  import { session, doLogout, theme, setTheme } from '../lib/stores.svelte';
  import { DemoRoleSwitcher } from 'tt-demo';

  let open = $state(false);
  const uid = $props.id();
  let root: HTMLDivElement | undefined = $state();

  function onwindow(e: MouseEvent | FocusEvent): void {
    if (open && root && e.target instanceof Node && !root.contains(e.target)) open = false;
  }
  function onkey(e: KeyboardEvent): void {
    if (e.key === 'Escape' && open) {
      open = false;
      root?.querySelector<HTMLButtonElement>('button')?.focus();
    }
  }
</script>

<svelte:window onclick={onwindow} onfocusin={onwindow} onkeydown={onkey} />

{#if session.user}
  <div class="menu" bind:this={root}>
    <button type="button" class="trigger" aria-expanded={open} aria-controls={open ? `${uid}-m` : undefined} onclick={() => (open = !open)}>
      <span class="avatar" aria-hidden="true">{session.user.displayName.slice(0, 1)}</span>
      <span class="who">
        <b>{session.user.displayName}</b>
        <small>{session.user.roles.map((r) => tk(`role.${r}`)).join(', ')}</small>
      </span>
      <Icon name="down" size={14} />
    </button>
    {#if open}
      <div class="pop" id="{uid}-m" role="group" aria-label={t('user.menu')}>
        <div class="info">
          <b>{session.user.username}</b>
          <div class="row-tight">
            {#each session.user.roles as r (r)}<Badge tone="accent">{tk(`role.${r}`)}</Badge>{/each}
          </div>
          <span class="subtle">{session.user.authMethod === 'sso' ? t('user.sso') : t('user.local')}</span>
        </div>
        <div class="prefs" role="group" aria-label={t('set.appearance')}>
          {#each ['it', 'en'] as const as l (l)}<button type="button" class="chip" aria-pressed={i18n.lang === l} onclick={() => setLang(l)}>{l.toUpperCase()}</button>{/each}
          {#each ['auto', 'light', 'dark'] as const as m (m)}<button type="button" class="chip" aria-pressed={theme.choice === m} onclick={() => setTheme(m)}>{t(`theme.${m}` as 'theme.auto')}</button>{/each}
        </div>
        <DemoRoleSwitcher onpicked={() => (open = false)} />
        <button type="button" class="item out" onclick={() => doLogout()}><Icon name="logout" size={16} /> {t('user.logout')}</button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .menu { position: relative; }
  .trigger { display: flex; align-items: center; gap: var(--s-2); font: inherit; color: var(--fg); background: none; border: 1px solid transparent; border-radius: var(--r-sm); padding: 0.25rem 0.5rem; cursor: pointer; text-align: left; }
  .trigger:hover { background: var(--surface-2); }
  .avatar { display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: 50%; background: var(--accent-soft); color: var(--accent); font-weight: 700; }
  .who { display: flex; flex-direction: column; line-height: 1.2; }
  .who small { color: var(--fg-muted); font-size: 0.75rem; }
  .pop { position: absolute; right: 0; top: calc(100% + 0.3rem); z-index: 40; width: 16rem; max-width: calc(100vw - 1.5rem); background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-md); box-shadow: var(--shadow-md); padding: var(--s-2); display: flex; flex-direction: column; gap: var(--s-1); }
  .info { display: flex; flex-direction: column; gap: var(--s-1); padding: var(--s-2); border-bottom: 1px solid var(--border); margin-bottom: var(--s-1); }
  .prefs { display: flex; flex-wrap: wrap; gap: 4px; padding: var(--s-2); border-bottom: 1px solid var(--border); margin-bottom: var(--s-1); }
  .chip { font: inherit; font-size: 0.8rem; border: 1px solid var(--border-strong); background: var(--surface); color: var(--fg-muted); border-radius: 999px; padding: 2px 10px; cursor: pointer; }
  .chip[aria-pressed='true'] { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .item { display: flex; align-items: center; gap: var(--s-2); width: 100%; font: inherit; color: var(--fg); background: none; border: 0; border-radius: var(--r-sm); padding: 0.4rem var(--s-2); cursor: pointer; text-align: left; }
  .item:hover { background: var(--surface-2); }
  /* narrow screens: the name stays in the accessible name of the button, only its box disappears */
  @media (max-width: 720px) { .who { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; } }
</style>
