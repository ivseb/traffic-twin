<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Tabs from '../components/Tabs.svelte';
  import OperationList from '../components/OperationList.svelte';
  import OperationPanel from '../components/OperationPanel.svelte';
  import SnapshotsPanel from '../components/SnapshotsPanel.svelte';
  import ContractsSwitch from '../components/ContractsSwitch.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { href } from '../lib/router';
  import { loc } from '../lib/router.svelte';
  import { queryTab } from '../lib/tabs.svelte';

  let { params }: { params: Record<string, string> } = $props();

  // Group/Team filter: the server lists the services of the chosen groups; each operation carries its group, and
  // the open operation keeps it in the URL (?group=): the contract of that group's traffic only.
  const ops = resource(() => api.contracts.operations(undefined, scopeGroups()));
  const tabs = queryTab('op', ['op', 'snapshots']);
  const service = $derived(params.service ?? ops.data?.[0]?.service ?? '');
  const group = $derived(params.service ? loc.query.group || undefined : ops.data?.[0]?.group);
  const opHref = (o: { service: string; op: string; group?: string }) => href('/contracts/:service/:op', { service: o.service, op: o.op }, { group: o.group ?? '' });
</script>

<PageHeader title={t('ct.title')} description={t('ct.desc')} help="contracts" breadcrumbs={[{ label: t('nav.contracts') }, { label: t('ct.view.global') }]} updatedAt={ops.updatedAt} onrefresh={ops.reload} refreshing={ops.loading}>
  {#snippet actions()}<ContractsSwitch current="global" {service} {group} />{/snippet}
</PageHeader>

<ScopeNote />
<div class="layout">
  <aside aria-label={t('ct.explorer')}>
    <Card flush>
      {#if ops.data && ops.data.length === 0}
        <EmptyState icon="contracts" title={t('cst.noContracts')} description={t('cst.noContractsHint')} level={3} />
      {:else if ops.data}
        <OperationList ops={ops.data} hrefOf={opHref} isCurrent={(o) => params.service === o.service && params.op === o.op && (o.group ?? '') === (group ?? '')} />
      {:else}
        <Loading error={ops.error} onretry={ops.reload} lines={6} />
      {/if}
    </Card>
  </aside>

  <section class="main">
    <Tabs tabs={[{ id: 'op', label: t('ct.tab.operation') }, { id: 'snapshots', label: t('ct.tab.snapshots') }]} bind:value={tabs.value} label={t('ct.title')}>
      {#if tabs.value === 'snapshots'}
        {#key `${group ?? ''}/${service}`}<SnapshotsPanel {service} {group} />{/key}
      {:else if !params.op}
        <Card><EmptyState icon="contracts" title={t('ct.pick')} description={t('ct.pickHint')} /></Card>
      {:else}
        {#key `${group ?? ''}/${params.service}/${params.op}`}
          <OperationPanel service={params.service} op={params.op} {group} />
        {/key}
      {/if}
    </Tabs>
  </section>
</div>

<style>
  .layout { display: grid; grid-template-columns: minmax(240px, 320px) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  aside { position: sticky; top: calc(var(--header-h) + var(--s-4)); max-height: calc(100dvh - var(--header-h) - 32px); overflow: auto; border-radius: var(--r-md); }
  .main { min-width: 0; }
  @media (max-width: 960px) { .layout { grid-template-columns: minmax(0, 1fr); } aside { position: static; max-height: 288px; } }
</style>
