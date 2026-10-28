<script lang="ts">
  // Standalone page (viewer.html): renders the OpenAPI document of one service with
  // Swagger UI, Redoc or Scalar. It is a separate HTML document so that the server can
  // serve it with a scoped CSP (the viewers need inline styles); the rest of the app
  // keeps the strict policy.
  import Button from '../components/Button.svelte';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import { t, tk, setLang, i18n } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { saveDoc } from '../lib/download';
  import { isViewer, loadViewer, validMockUrl, VIEWERS, type ViewerHandle, type ViewerId } from '../viewers';

  const q = new URLSearchParams(window.location.search);
  const service = q.get('service') ?? '';
  // The group of the row the viewer was opened from: the contract of that group's traffic only.
  const group = q.get('group') || undefined;
  let viewer = $state<ViewerId>(isViewer(q.get('viewer') ?? undefined) ? (q.get('viewer') as ViewerId) : 'swagger');

  const doc = resource(async () => {
    const me = await api.auth.me();
    if (!me) throw new Error(t('docs.needLogin'));
    return api.contracts.openapi(service, group);
  });

  function pick(v: ViewerId): void {
    viewer = v;
    const next = new URL(window.location.href);
    next.searchParams.set('viewer', v);
    window.history.replaceState(null, '', next);
  }

  let host: HTMLDivElement | undefined = $state();
  let status = $state<'idle' | 'loading' | 'ready' | 'error'>('idle');
  let failure = $state('');
  // "Try it out" is off until the user enters the base URL of a tt mock.
  let draftUrl = $state('');
  let tryUrl = $state('');
  const urlError = $derived(draftUrl !== '' && !validMockUrl(draftUrl));

  $effect(() => {
    const el = host;
    const spec = doc.data;
    const id = viewer;
    const url = tryUrl;
    if (!el || !spec) return;
    let cancelled = false;
    let handle: ViewerHandle | undefined;
    status = 'loading';
    failure = '';
    loadViewer[id]()
      .then((m) => m.mount(el, spec, { tryItUrl: url }))
      .then((h) => {
        if (cancelled) h.destroy();
        else {
          handle = h;
          status = 'ready';
        }
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        failure = e instanceof Error ? e.message : String(e);
        status = 'error';
      });
    return () => {
      cancelled = true;
      handle?.destroy();
      el.replaceChildren();
    };
  });

  const back = `/#/contracts/service/${encodeURIComponent(service)}?tab=openapi${group ? `&group=${encodeURIComponent(group)}` : ''}`;
</script>

<header class="top">
  <a class="brand" href={back}><Logo size={22} /><span>traffic-twin</span></a>
  <nav class="crumbs" aria-label={t('docs.crumbs')}>
    <a href={back}><Icon name="arrowLeft" size={14} /> {t('docs.back')}</a>
    <span aria-hidden="true">/</span>
    <b>{service}</b>
    <span class="subtle">{t('docs.openapi')}</span>
  </nav>
  <span class="grow"></span>
  <div class="seg" role="group" aria-label={t('docs.viewer')}>
    {#each VIEWERS as v (v)}
      <button type="button" aria-pressed={viewer === v} onclick={() => pick(v)}>{tk(`docs.v.${v}`)}</button>
    {/each}
  </div>
  <Button size="sm" icon="download" disabled={!doc.data} onclick={() => doc.data && saveDoc(service, doc.data, 'json')}>JSON</Button>
  <Button size="sm" icon="download" disabled={!doc.data} onclick={() => doc.data && saveDoc(service, doc.data, 'yaml')}>YAML</Button>
  <div class="lang" role="group" aria-label={t('app.language')}>
    {#each ['it', 'en'] as const as l (l)}<button type="button" aria-pressed={i18n.lang === l} onclick={() => setLang(l)}>{l.toUpperCase()}</button>{/each}
  </div>
</header>

<form class="try" onsubmit={(e) => { e.preventDefault(); if (!urlError) tryUrl = draftUrl.trim(); }}>
  <label for="mock-url">{t('docs.tryUrl')}</label>
  <input id="mock-url" type="url" bind:value={draftUrl} placeholder="http://127.0.0.1:8480" spellcheck="false" aria-invalid={urlError ? 'true' : undefined} aria-describedby="mock-url-h" />
  <Button type="submit" size="sm" disabled={urlError || draftUrl.trim() === tryUrl}>{t('docs.tryOn')}</Button>
  <Button size="sm" variant="ghost" disabled={tryUrl === ''} onclick={() => { draftUrl = ''; tryUrl = ''; }}>{t('docs.tryOff')}</Button>
  <span class="subtle" id="mock-url-h">{tryUrl ? t('docs.tryActive', { url: tryUrl }) : t('docs.tryHint')}</span>
</form>

{#if doc.error}
  <p class="callout danger" role="alert">{doc.error.message} <a href={back}>{t('docs.back')}</a></p>
{:else}
  {#if status === 'loading' || !doc.data}<div class="skel" role="status" aria-label={t('common.loading')}></div>{/if}
  {#if status === 'error'}<p class="callout danger" role="alert"><b>{t('docs.failed')}</b> {failure}</p>{/if}
  <div class="host" class:hidden={status === 'loading' || !doc.data} bind:this={host} data-viewer={viewer}></div>
{/if}

<style>
  .top { display: flex; align-items: center; gap: var(--s-3); padding: 0 var(--s-4); height: 3rem; background: var(--surface); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .brand { display: inline-flex; gap: var(--s-2); align-items: center; font-weight: 650; color: var(--fg); text-decoration: none; }
  .crumbs { display: flex; gap: var(--s-2); align-items: center; font-size: 0.9rem; }
  .seg, .lang { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-sm); overflow: hidden; }
  .seg button, .lang button { font: inherit; font-size: 0.82rem; font-weight: 600; border: 0; background: var(--surface); color: var(--fg-muted); padding: 0.3rem 0.8rem; cursor: pointer; }
  .seg button[aria-pressed='true'], .lang button[aria-pressed='true'] { background: var(--accent); color: var(--accent-fg); }
  .try { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; padding: var(--s-2) var(--s-4); background: var(--surface-2); border-bottom: 1px solid var(--border); }
  .try label { font-size: 0.82rem; white-space: nowrap; }
  .try input { max-width: 17rem; min-height: 1.9rem; padding-block: 0.2rem; }
  .callout { margin: var(--s-4); }
  .skel { height: 60vh; margin: var(--s-4); border-radius: var(--r-md); background: linear-gradient(90deg, var(--surface-2), var(--surface-3), var(--surface-2)); background-size: 200% 100%; animation: sk 1.4s linear infinite; }
  @keyframes sk { to { background-position: -200% 0; } }
  /* The viewers are designed for their own canvas and bring their own styles. */
  .host { background: #fff; color: #1b1f27; color-scheme: light; min-height: calc(100dvh - 7rem); overflow: auto; isolation: isolate; }
  /* Redoc's footer logo is a remote image: not loaded, so hide the link entirely. */
  .host :global(a[href*='redocly.com']) { display: none !important; }
  .host.hidden { visibility: hidden; height: 0; min-height: 0; }
</style>
