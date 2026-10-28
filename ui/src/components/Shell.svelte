<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import Logo from './Logo.svelte';
  import Badge from './Badge.svelte';
  import UserMenu from './UserMenu.svelte';
  import HelpDrawer from './HelpDrawer.svelte';
  import ScopeSelect from './ScopeSelect.svelte';
  import { JOURNEY, NAV, navActive } from '../routes';
  import { loc, navigate } from '../lib/router.svelte';
  import { i18n, setLang, t, type Lang } from '../lib/i18n/index.svelte';
  import { helpUi } from '../lib/help/index.svelte';
  import { openHelp, session, setTheme, theme, ui } from '../lib/stores.svelte';
  import { DemoBanner } from 'tt-demo';

  let { children }: { children: Snippet } = $props();
  let navOpen = $state(false);
  let burger: HTMLButtonElement | undefined = $state();
  let sidebar: HTMLElement | undefined = $state();

  const env = $derived(session.status?.environment);
  const envTone = $derived(env === 'production' ? 'danger' : env === 'staging' ? 'warning' : 'info');
  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

  // Off-canvas menu (narrow screens): focus moves into it when it opens and back to the button when Esc closes it.
  function toggleNav(): void {
    navOpen = !navOpen;
    if (navOpen) queueMicrotask(() => sidebar?.querySelector<HTMLElement>('a')?.focus());
  }

  // Close the off-canvas menu when navigating.
  $effect(() => {
    void loc.path;
    navOpen = false;
  });

  function cycleTheme(): void {
    setTheme(theme.choice === 'auto' ? 'light' : theme.choice === 'light' ? 'dark' : 'auto');
  }
  const current = (item: (typeof NAV)[number]) => navActive(item, loc.path, loc.query);
  const inSection = (id: string) => NAV.filter((n) => n.section === id);

  // "Avanzate" is collapsed; it opens by itself when the current page is one of its pages, and the choice is remembered.
  const ADV_KEY = 'tt.nav.advanced';
  function readAdv(): boolean {
    try {
      return localStorage.getItem(ADV_KEY) === '1';
    } catch {
      return false;
    }
  }
  let advOpen = $state(readAdv());
  const advActive = $derived(inSection('advanced').some(current));
  const advShown = $derived(advOpen || advActive);
  function toggleAdv(): void {
    const next = !advShown;
    advOpen = next;
    try {
      localStorage.setItem(ADV_KEY, next ? '1' : '0');
    } catch {
      /* storage unavailable: the choice lasts for this session */
    }
  }

  // Keyboard: Ctrl/Cmd+K palette, ? guide, "g" then a letter to jump.
  const GO: Record<string, string> = { i: '/home', m: '/mock', o: '/onboarding', s: '/sources', v: '/services', h: '/hosts', c: '/contracts', r: '/rules', w: '/worlds', p: '/packs', a: '/alerts', u: '/audit', g: '/glossary' };
  let goPending = false;
  let goTimer: ReturnType<typeof setTimeout> | undefined;

  function typing(e: KeyboardEvent): boolean {
    const el = e.target as HTMLElement | null;
    return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);
  }
  function onkeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape' && navOpen) {
      navOpen = false;
      burger?.focus();
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      ui.paletteOpen = !ui.paletteOpen;
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || typing(e) || document.querySelector('dialog[open]')) {
      if (e.key === '?' && !typing(e) && ui.helpOpen) ui.helpOpen = false;
      return;
    }
    if (e.key === '?') {
      e.preventDefault();
      ui.helpOpen = !ui.helpOpen;
    } else if (goPending && GO[e.key]) {
      e.preventDefault();
      goPending = false;
      navigate(GO[e.key]);
    } else if (e.key === 'g') {
      goPending = true;
      clearTimeout(goTimer);
      goTimer = setTimeout(() => (goPending = false), 1200);
    } else goPending = false;
  }
</script>

<svelte:window {onkeydown} />

<DemoBanner />

<div class="shell">
  <header>
    <button type="button" class="burger" bind:this={burger} aria-label={t('app.menu')} aria-expanded={navOpen} aria-controls="sidebar" onclick={toggleNav}>
      <Icon name={navOpen ? 'close' : 'menu'} size={20} />
    </button>
    <a class="brand" href="#/home"><Logo size={22} /> <span>traffic-twin</span></a>
    {#if env || session.status?.installation}
      <span class="env" title={t('app.env')}>
        {#if env}<Badge tone={envTone}>{t(`env.${env}` as 'env.production')}</Badge>{/if}
        {#if session.status?.installation}<span class="inst mono">{session.status.installation}</span>{/if}
      </span>
    {/if}
    <span class="grow"></span>
    <ScopeSelect />
    <button type="button" class="search" onclick={() => (ui.paletteOpen = true)} aria-label="{helpUi('pal.short').replace('…', '')} {helpUi('pal.title')}" aria-keyshortcuts="Control+K Meta+K">
      <Icon name="search" size={14} />
      <span class="ph">{helpUi('pal.short')}</span>
      <kbd>{isMac ? '⌘' : 'Ctrl'} K</kbd>
    </button>
    <button type="button" class="icon" onclick={() => openHelp()} aria-label={t('help.guide')} title="{t('help.guide')} (?)"><Icon name="help" size={18} /></button>
    <div class="lang" role="group" aria-label={t('app.language')}>
      {#each ['it', 'en'] as const as l (l)}
        <button type="button" aria-pressed={i18n.lang === l} onclick={() => setLang(l as Lang)}>{l.toUpperCase()}</button>
      {/each}
    </div>
    <button type="button" class="icon" onclick={cycleTheme} aria-label={t('app.theme', { mode: t(`theme.${theme.choice}` as 'theme.auto') })} title={t('app.theme', { mode: t(`theme.${theme.choice}` as 'theme.auto') })}>
      <Icon name={theme.choice === 'dark' ? 'moon' : theme.choice === 'light' ? 'sun' : 'monitor'} size={18} />
    </button>
    <UserMenu />
  </header>

  <nav id="sidebar" bind:this={sidebar} class:open={navOpen} aria-label={t('app.nav')}>
    <div class="navin">
    <ul class="home">
      {#each inSection('home') as item (item.path)}
        <li>
          <a href="#{item.path}" aria-current={current(item) ? 'page' : undefined}>
            <Icon name={item.icon} size={16} />
            <span>{t(item.label)}</span>
          </a>
        </li>
      {/each}
    </ul>
    <ol class="steps">
      {#each JOURNEY as step, si (step.id)}
        <li>
          <p class="step" id="nav-step-{step.id}"><span class="num" aria-hidden="true">{si + 1}</span> {t(step.title)}</p>
          <ul aria-labelledby="nav-step-{step.id}">
            {#each inSection(step.id) as item (item.path + (item.query?.tab ?? ''))}
              <li>
                <a href="#{item.path}{item.query ? '?' + new URLSearchParams(item.query).toString() : ''}" aria-current={current(item) ? 'page' : undefined}>
                  <Icon name={item.icon} size={16} />
                  <span>{t(item.label)}</span>
                </a>
              </li>
            {/each}
          </ul>
        </li>
      {/each}
    </ol>
    <hr />
    <button type="button" class="adv" aria-expanded={advShown} aria-controls="nav-advanced" onclick={toggleAdv}>
      <Icon name={advShown ? 'down' : 'right'} size={14} />
      <span>{t('journey.advanced')}</span>
    </button>
    <ul id="nav-advanced" hidden={!advShown} aria-label={t('journey.advanced')}>
      {#each inSection('advanced') as item (item.path + (item.query?.tab ?? ''))}
        <li>
          <a href="#{item.path}{item.query ? '?' + new URLSearchParams(item.query).toString() : ''}" aria-current={current(item) ? 'page' : undefined}>
            <Icon name={item.icon} size={16} />
            <span>{t(item.label)}</span>
          </a>
        </li>
      {/each}
    </ul>
    {#if session.status?.version}<p class="ver subtle mono">v{session.status.version}</p>{/if}
    </div>
  </nav>
  {#if navOpen}
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
    <div class="scrim" onclick={() => (navOpen = false)}></div>
  {/if}

  <div class="content">
    <div class="inner">{@render children()}</div>
  </div>
</div>

<HelpDrawer />
{#if ui.paletteOpen}
  {#await import('./CommandPalette.svelte') then m}
    <m.default />
  {/await}
{/if}

<style>
  .shell { min-height: 100dvh; display: grid; grid-template-columns: var(--sidebar-w) minmax(0, 1fr); grid-template-rows: var(--header-h) 1fr; grid-template-areas: 'head head' 'nav content'; }
  header { grid-area: head; display: flex; align-items: center; gap: var(--s-3); padding: 0 var(--s-4); background: var(--surface); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 30; }
  .brand { display: inline-flex; align-items: center; gap: var(--s-2); font-weight: 600; color: var(--fg); text-decoration: none; letter-spacing: -0.01em; }
  .brand:hover { color: var(--fg); }
  .env { display: inline-flex; align-items: center; gap: var(--s-2); }
  .inst { color: var(--fg-muted); font-size: 0.8rem; }
  .burger { display: none; }
  button.icon, .burger { all: unset; cursor: pointer; display: grid; place-items: center; width: 32px; height: 32px; border-radius: var(--r-md); color: var(--fg-muted); }
  .burger { display: none; }
  button.icon:hover, .burger:hover { background: var(--surface-2); color: var(--fg); }
  button.icon:focus-visible, .burger:focus-visible, .search:focus-visible { outline: 2px solid var(--focus); }
  .search { display: inline-flex; align-items: center; gap: var(--s-2); height: 30px; min-width: 200px; padding: 0 var(--s-2) 0 var(--s-3); background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-md); color: var(--fg-subtle); cursor: pointer; font: inherit; font-size: 0.86rem; }
  .search:hover { border-color: var(--border-strong); }
  .search .ph { flex: 1; text-align: left; }
  .lang { flex: none; display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-md); overflow: hidden; }
  .lang button { white-space: nowrap; font: inherit; font-size: 0.78rem; font-weight: 600; border: 0; background: transparent; color: var(--fg-muted); padding: 3px 8px; cursor: pointer; }
  .lang button[aria-pressed='true'] { background: var(--accent); color: var(--accent-fg); }
  /* The column (and its background) spans the whole page; only its content sticks while scrolling. */
  nav { grid-area: nav; background: var(--surface); border-right: 1px solid var(--border); }
  .navin { padding: var(--s-3) var(--s-2); overflow-y: auto; position: sticky; top: var(--header-h); max-height: calc(100dvh - var(--header-h)); }
  nav ul, nav ol { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
  nav ol.steps { gap: var(--s-3); margin-top: var(--s-3); }
  nav ul[hidden] { display: none; }
  .step { margin: 0 0 2px; padding: 0 var(--s-3); display: flex; align-items: center; gap: var(--s-2); font-size: 0.78rem; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase; color: var(--fg-muted); }
  .step .num { display: grid; place-items: center; width: 1.25rem; height: 1.25rem; border-radius: 50%; background: var(--accent-soft); color: var(--accent); font-size: 0.72rem; letter-spacing: 0; }
  nav ol ul { padding-left: 0; }
  .adv { all: unset; box-sizing: border-box; width: 100%; display: flex; align-items: center; gap: var(--s-2); padding: 6px var(--s-3); border-radius: var(--r-md); cursor: pointer; color: var(--fg-muted); font-weight: 500; font-size: 0.9rem; }
  .adv:hover { background: var(--surface-2); color: var(--fg); }
  .adv:focus-visible { outline: 2px solid var(--focus); }
  nav hr { border: 0; border-top: 1px solid var(--border); margin: var(--s-3) var(--s-2); }
  nav a { display: flex; align-items: center; gap: var(--s-3); padding: 6px var(--s-3); border-radius: var(--r-md); color: var(--fg-muted); text-decoration: none; font-weight: 500; }
  nav a:hover { background: var(--surface-2); color: var(--fg); }
  nav a[aria-current='page'] { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
  .ver { padding: var(--s-3) var(--s-3) 0; }
  .content { grid-area: content; min-width: 0; }
  .inner { max-width: 1600px; margin: 0 auto; padding: var(--s-5) var(--s-5) var(--s-7); }
  .scrim { display: none; }
  @media (max-width: 899px) {
    .shell { grid-template-columns: minmax(0, 1fr); grid-template-areas: 'head' 'content'; }
    .burger { display: grid; }
    nav { position: fixed; z-index: 60; left: 0; top: var(--header-h); bottom: 0; width: min(256px, 85vw); transform: translateX(-100%); visibility: hidden; transition: transform 0.18s ease-out, visibility 0s 0.18s; box-shadow: var(--shadow-md); }
    /* closed: out of the tab order and of the accessibility tree, not just off screen */
    nav.open { transform: none; visibility: visible; transition-delay: 0s; }
    .navin { position: static; max-height: none; height: 100%; }
    .scrim { display: block; position: fixed; inset: var(--header-h) 0 0 0; background: var(--backdrop); z-index: 50; }
    .inner { padding: var(--s-4) var(--s-4) var(--s-6); }
    .search { min-width: 0; padding: 0 var(--s-2); }
    .search .ph, .search kbd { display: none; }
    .inst { display: none; }
  }
  @media (max-width: 520px) { .brand span { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; } .lang { display: none; } }
</style>
