<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { session, ui } from '../lib/stores.svelte';
  import { d } from './messages';
</script>

{#if session.status?.adapter === 'mock' && !ui.bannerHidden}
  <div class="banner" role="status">
    <Icon name="info" size={14} />
    <span class="grow"><b>{d('demo.banner.title')}</b> {d('demo.banner.hint')}</span>
    <button type="button" aria-label={t('common.close')} onclick={() => (ui.bannerHidden = true)}><Icon name="close" size={14} /></button>
  </div>
{/if}

<style>
  .banner { display: flex; gap: var(--s-2); align-items: center; padding: 6px var(--s-4); background: var(--info-soft); color: var(--info); border-bottom: 1px solid var(--border); font-size: 0.86rem; }
  .banner span { color: var(--fg); }
  .grow { flex: 1; }
  .banner button { all: unset; cursor: pointer; display: grid; place-items: center; width: 22px; height: 22px; border-radius: var(--r-sm); color: var(--fg-muted); }
  .banner button:hover { background: var(--surface-3); }
  .banner button:focus-visible { outline: 2px solid var(--focus); }
</style>
