<script lang="ts">
  // "N nuovi host scoperti": a hint for the start pages. It stays out of the way: nothing is shown without new hosts,
  // for people who cannot see the registry, or when the registry cannot be read.
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { href } from '../lib/router';
  import { dedupeHosts, strictPolicies, summarize } from '../lib/hosts';
  import { scopeGroups } from '../lib/scope.svelte';
  import Icon from './Icon.svelte';

  const reg = resource(async () => {
    if (!can('hosts.twin')) return null;
    try {
      return await api.hosts.list(scopeGroups());
    } catch {
      return null;
    }
  });
  // Only the hosts of the Group/Team filter (the server filters): "a service of yours calls something new".
  const sum = $derived(reg.data ? summarize(dedupeHosts(reg.data), reg.updatedAt ?? Date.now()) : null);
  const hidden = $derived(reg.data && strictPolicies(reg.data).length > 0 ? reg.data.unlisted.calls : 0);
</script>

{#if sum && sum.fresh > 0}
  <p class="callout hint" role="status" data-testid="new-hosts-hint">
    <Icon name="spark" size={16} />
    <span><b>{t('hosts.hint.new', { n: sum.fresh })}</b> {t('hosts.hint.newHelp')}</span>
    <a href={href('/hosts', {}, { range: '24h', decl: 'no' })}>{t('hosts.hint.open')}</a>
  </p>
{/if}
{#if hidden > 0}
  <p class="callout warn hint" role="status" data-testid="strict-hosts-hint">
    <Icon name="lock" size={16} />
    <span>{t('hosts.hint.strict', { n: hidden })}</span>
    <a href={href('/hosts')}>{t('hosts.hint.open')}</a>
  </p>
{/if}

<style>
  .hint { display: flex; align-items: center; gap: var(--s-2); flex-wrap: wrap; }
  .hint span { flex: 1 1 14rem; }
</style>
