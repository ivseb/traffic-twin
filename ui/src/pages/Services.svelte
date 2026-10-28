<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Badge from '../components/Badge.svelte';
  import Switch from '../components/Switch.svelte';
  import Loading from '../components/Loading.svelte';
  import NewHostsHint from '../components/NewHostsHint.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { contractHref, scopeGroups, showGroupColumn } from '../lib/scope.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { serviceKey, type ServiceInfo } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { fmtAgo, fmtNum } from '../lib/format';
  import { href } from '../lib/router';

  // Group/Team filter: the server lists the services of the chosen groups, one row per (group, service).
  const services = resource(() => api.services.list(scopeGroups()));
  const rows = $derived(services.data ?? []);
  // host:<pattern> entries not declared by any policy are not twinned yet: they are declared on the Host esterni page.
  const undeclaredHost = (s: ServiceInfo) => s.name.startsWith('host:') && !s.baseUrl;

  const cols: Column<ServiceInfo>[] = $derived([
    { key: 'name', label: t('svc.col.name'), sortable: true },
    ...(showGroupColumn() ? [{ key: 'group', label: t('scope.col.group'), sortable: true, value: (s: ServiceInfo) => s.group ?? '' }] : []),
    { key: 'kind', label: t('svc.col.kind'), sortable: true, hideBelow: 'sm', help: 'svc.kind' },
    { key: 'calls', label: t('svc.col.calls'), sortable: true, align: 'end', hideBelow: 'sm' },
    { key: 'operations', label: t('svc.col.ops'), sortable: true, align: 'end', hideBelow: 'sm' },
    { key: 'lastSeen', label: t('svc.col.lastSeen'), hideBelow: 'md', value: (s) => -new Date(s.lastSeen).getTime(), sortable: true },
    { key: 'twin', label: t('svc.col.inMock'), help: 'svc.twin' },
  ]);

  async function toggle(s: ServiceInfo, twin: boolean): Promise<void> {
    try {
      await api.services.setTwin(s.name, twin, s.group);
      toast(twin ? t('svc.inMockOn', { name: s.name }) : t('svc.inMockOff', { name: s.name }));
    } catch (e) {
      toastError(e);
    } finally {
      services.reload();
    }
  }
</script>

<PageHeader title={t('svc.title')} description={t('svc.desc')} help="services" breadcrumbs={[{ label: t('nav.services') }]} updatedAt={services.updatedAt} onrefresh={services.reload} refreshing={services.loading} />

<NewHostsHint />

{#if services.data}
  {#if !api.capabilities.twinOnServer}<p class="callout">{t('svc.twinLocal')}</p><div class="gap"></div>{/if}
  <ScopeNote />
  <p class="subtle legend">{t('svc.inMockLegend')}</p>
  <Card flush>
    <Table rows={rows} columns={cols} rowKey={(s) => serviceKey(s.group, s.name)} caption={t('svc.title')} urlKey="svc" searchText={(s) => `${s.name} ${s.group ?? ''} ${s.baseUrl ?? ''} ${s.hostPattern ?? ''}`}>
      {#snippet cell(s, col)}
        {#if col.key === 'name'}
          <a href={contractHref(s.name, s.group)}><b>{s.name}</b></a>
          {#if s.baseUrl}<div class="subtle mono">{s.baseUrl}</div>{/if}
          {#if s.nowDeclaredAs}<div class="subtle"><Badge tone="neutral">{t('svc.nowDeclared', { name: s.nowDeclaredAs })}</Badge></div>{/if}
          {#if s.hostPattern && can('hosts.twin')}<div class="subtle"><a href={href('/hosts', {}, { q: s.hostPattern })}>{t('svc.hostGroup')}</a></div>{/if}
          <div class="subtle m-only">{t(s.kind === 'own' ? 'svc.own' : 'svc.external')} · {fmtNum(s.calls)}</div>
        {:else if col.key === 'group'}
          <GroupTag group={s.group ?? ''} always />
        {:else if col.key === 'kind'}
          <Badge tone={s.kind === 'own' ? 'accent' : 'info'}>{t(s.kind === 'own' ? 'svc.own' : 'svc.external')}</Badge>
        {:else if col.key === 'calls'}
          <span class="num">{fmtNum(s.calls)}</span>
        {:else if col.key === 'operations'}
          <span class="num">{s.operations}</span>
        {:else if col.key === 'lastSeen'}
          {fmtAgo(s.lastSeen)}
        {:else if s.nowDeclaredAs}
          <span class="subtle">{t('svc.mergedInto', { name: s.nowDeclaredAs })}</span>
        {:else if undeclaredHost(s)}
          <span class="subtle">{t('svc.undeclared')}</span>
          {#if can('hosts.twin')}<div><a href={href('/hosts', {}, { q: s.name.slice(5) })}>{t('svc.declareInHosts')}</a></div>{/if}
        {:else}
          <Switch checked={s.twin} label={s.twin ? t('svc.inMock') : t('svc.notInMock')} disabled={!can('sources.manage')} onchange={(v) => toggle(s, v)} />
        {/if}
      {/snippet}
    </Table>
  </Card>
{:else}
  <Loading error={services.error} onretry={services.reload} />
{/if}

<style>
  .gap { height: var(--s-3); }
  .legend { margin: 0 0 var(--s-3); }
  @media (min-width: 641px) { .m-only { display: none; } }
</style>
