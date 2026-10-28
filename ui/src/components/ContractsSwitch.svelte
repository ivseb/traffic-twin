<script lang="ts">
  // "Global view | By service" toggle shared by the two contract pages.
  import { t } from '../lib/i18n/index.svelte';
  import { contractHref } from '../lib/scope.svelte';

  let { current, service = '', group }: { current: 'global' | 'service'; service?: string; group?: string } = $props();
  const target = $derived(service ? contractHref(service, group) : '#/services');
</script>

<nav class="seg" aria-label={t('ct.view')}>
  <a href="#/contracts" aria-current={current === 'global' ? 'page' : undefined}>{t('ct.view.global')}</a>
  <a href={target} aria-current={current === 'service' ? 'page' : undefined}>{t('ct.view.service')}</a>
</nav>

<style>
  .seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-md); overflow: hidden; }
  a { padding: 4px 14px; font-weight: 500; font-size: 0.9rem; text-decoration: none; color: var(--fg-muted); background: var(--surface); }
  a:hover { background: var(--surface-2); color: var(--fg); }
  a[aria-current='page'] { background: var(--accent); color: var(--accent-fg); }
</style>
