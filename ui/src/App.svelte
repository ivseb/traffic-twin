<script lang="ts">
  import type { Component } from 'svelte';
  import { onMount } from 'svelte';
  import { matchRoute } from './lib/router';
  import { loc, navigate, startRouter } from './lib/router.svelte';
  import { initSession, resumeStepUp, session, ui } from './lib/stores.svelte';
  import { consumeStepUpReturn } from './lib/stepup';
  import { t } from './lib/i18n/index.svelte';
  import { routes } from './routes';
  import Shell from './components/Shell.svelte';
  import ToastHost from './components/ToastHost.svelte';
  import Loading from './components/Loading.svelte';

  const match = $derived(matchRoute(routes, loc.path));
  const info = $derived(match?.route.data);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let Page = $state.raw<Component<any> | null>(null);
  // The route Page was loaded for: while another route loads, the previous page must not receive the new
  // route's parameters (it would fetch with them).
  let pageRoute = $state.raw<unknown>(null);
  let main: HTMLElement | undefined = $state();

  onMount(() => {
    // Back from an approval step-up: restore the page (the hash) before the router reads it.
    const back = consumeStepUpReturn();
    const stop = startRouter();
    void initSession().then(() => {
      if (back) void resumeStepUp(back);
    });
    return stop;
  });

  // Route guard: setup first, then login, then the requested page.
  $effect(() => {
    if (!session.ready) return;
    const path = loc.path;
    const isPublic = info?.public ?? false;
    if (session.status && !session.status.initialized) {
      if (path !== '/setup') navigate('/setup', {}, true);
    } else if (!session.user && !isPublic) {
      navigate('/login', path !== '/' && path !== '/login' ? { next: path } : {}, true);
    } else if (session.user && (path === '/' || path === '/login' || path === '/setup')) {
      navigate('/home', {}, true);
    }
  });

  // Lazy-load the page component of the current route.
  $effect(() => {
    const load = info?.load;
    if (!load) {
      Page = null;
      pageRoute = null;
      return;
    }
    let cancelled = false;
    load().then((m) => {
      if (!cancelled) {
        Page = m.default;
        pageRoute = info;
      }
    });
    return () => {
      cancelled = true;
    };
  });

  const allowed = $derived(session.ready && (info?.public || !!session.user));

  $effect(() => {
    if (info && !info.public) ui.helpPage = info.guide;
  });

  // The page title is also announced: moving between hash routes is not a page load for a screen reader.
  let announced = $state('');
  $effect(() => {
    document.title = (info ? t(info.title) + ' · ' : '') + 'traffic-twin';
    announced = info && !info.public && session.user ? t(info.title) : '';
  });

  // Move focus to the page on navigation so screen readers announce it. Not on the first load: the
  // skip link and the browser chrome must stay the first things Tab reaches.
  let firstPath = true;
  $effect(() => {
    void loc.path;
    if (firstPath) {
      firstPath = false;
      return;
    }
    main?.focus({ preventScroll: true });
  });
</script>

<a class="skip" href="#main" onclick={(e) => { e.preventDefault(); main?.focus(); }}>{t('app.skip')}</a>

<div class="sr-only" role="status" aria-live="polite" aria-atomic="true">{announced}</div>

{#if !session.ready}
  <Loading />
{:else if !allowed}
  <Loading />
{:else if info?.public}
  <main id="main" tabindex="-1" bind:this={main} class="public">
    {#if Page && pageRoute === info}<Page params={match?.params ?? {}} />{/if}
  </main>
{:else}
  <Shell>
    <main id="main" tabindex="-1" bind:this={main}>
      {#if !match}
        <div class="callout warn"><h1 class="fs-3">{t('app.notFound')}</h1> <a href="#/home">{t('app.home')}</a></div>
      {:else if Page && pageRoute === info}
        <Page params={match.params} />
      {:else}
        <Loading />
      {/if}
    </main>
  </Shell>
{/if}

<ToastHost />

<style>
  .skip { position: absolute; left: -999px; top: 0; z-index: 200; background: var(--accent); color: var(--accent-fg); padding: 0.5rem 1rem; border-radius: 0 0 var(--r-sm) 0; }
  .skip:focus { left: 0; }
  main { outline: none; }
  .public { min-height: 100dvh; display: grid; place-items: center; padding: var(--s-4); }
</style>
