<script lang="ts">
  // Why a service has (no) contract yet, how far it is, when the next snapshot runs, and "update now".
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import ProgressBar from './ProgressBar.svelte';
  import EmptyState from './EmptyState.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api, ApiError } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { fmtAgo, fmtDate, fmtNum } from '../lib/format';

  let { service, group, onupdated }: { service: string; group?: string; onupdated?: () => void } = $props();

  const st = resource(() => api.contracts.status(service, group));
  let busy = $state(false);
  let err = $state('');

  async function refresh(): Promise<void> {
    busy = true;
    err = '';
    try {
      await api.contracts.refreshNow(service, group);
      toast(t('cst.updated', { name: service }));
      st.reload();
      onupdated?.();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'not_found') err = t('cst.noRecent');
      else toastError(e);
    } finally {
      busy = false;
    }
  }
  const s = $derived(st.data);
  const notFound = $derived(st.error instanceof ApiError && st.error.code === 'not_found');
</script>

{#if notFound}
  <Card><EmptyState icon="contracts" title={t('cst.noCalls')} description={t('cst.noCallsHint')} level={3} /></Card>
{:else if s}
  <Card title={s.snapshot ? t('cst.titleSnap') : t('cst.titleWaiting')}>
    {#snippet actions()}
      <Button size="sm" icon="refresh" loading={busy} denied={!can('sources.manage')} onclick={refresh}>{t('cst.refresh')}</Button>
    {/snippet}
    <div class="stack-sm">
      {#if s.snapshot}
        <p>{t('cst.snapshot', { when: fmtAgo(s.snapshot.createdAt), next: fmtDate(s.nextSnapshotAt) })}</p>
      {:else}
        <p>{t('cst.when', { hours: s.windowHours, next: fmtDate(s.nextSnapshotAt), min: s.minCalls })}</p>
      {/if}
      <p class="subtle">{t('cst.progress', { calls: fmtNum(s.calls), ops: s.operations, ready: s.readyOperations, min: s.minCalls })}</p>
      <ProgressBar value={s.minCalls ? s.bestOpCalls / s.minCalls : 1} label={t('cst.progressLabel', { calls: fmtNum(Math.min(s.bestOpCalls, s.minCalls)), min: s.minCalls })} tone="auto" />
      {#if s.inferredOperations > 0}<p class="callout note">{t('cst.inferred', { n: s.inferredOperations })}</p>{/if}
      {#if err}<p class="callout warn" role="alert">{err}</p>{/if}
    </div>
  </Card>
{/if}
