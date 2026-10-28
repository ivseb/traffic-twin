<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import Icon from '../components/Icon.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { AuditEntry } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';
  import { fmtDate, inRange, RANGES, type Range } from '../lib/format';
  import { queryParam } from '../lib/tabs.svelte';
  import TimeRange from '../components/TimeRange.svelte';
  import InfoTip from '../components/InfoTip.svelte';

  // Only auditors may read the log: do not even ask (the server would count a denied attempt).
  const entries = resource(async () => (can('audit.view') ? await api.audit.list() : []));
  const verify = resource(async () => (can('audit.view') ? await api.audit.verify() : null));

  const cols: Column<AuditEntry>[] = $derived([
    { key: 'seq', label: '#', sortable: true, align: 'end', hideBelow: 'sm' },
    { key: 'at', label: t('audit.col.at'), sortable: true, value: (e) => e.at },
    { key: 'actor', label: t('audit.col.actor'), sortable: true, hideBelow: 'sm' },
    { key: 'action', label: t('audit.col.action'), sortable: true },
    { key: 'result', label: t('audit.col.result'), sortable: true },
    { key: 'hash', label: 'hash', hideBelow: 'md' },
  ]);
  const short = (h: string) => h.slice(0, 10);
  const range = queryParam<Range>('range', 'all', RANGES);
  const rows = $derived((entries.data ?? []).filter((e) => inRange(e.at, range.value)));

  function refresh(): void {
    entries.reload();
    verify.reload();
  }
</script>

<PageHeader title={t('audit.title')} description={t('audit.desc')} help="audit" breadcrumbs={[{ label: t('nav.audit') }]} updatedAt={entries.updatedAt} onrefresh={entries.reload} refreshing={entries.loading}>
  {#snippet actions()}<Button icon="refresh" onclick={refresh}>{t('audit.verifyNow')}</Button>{/snippet}
</PageHeader>

{#if !can('audit.view')}
  <Card><EmptyState icon="lock" title={t('audit.denied')} /></Card>
{:else}
  <div class="stack">
    {#if verify.data}
      <div class="callout {verify.data.ok ? 'ok' : 'danger'} verify" role="status">
        <Icon name={verify.data.ok ? 'audit' : 'alert'} size={22} />
        <div>
          <b>{verify.data.ok ? t('audit.verified') : t('audit.broken', { n: verify.data.brokenAt ?? 0 })}</b>
          <div class="subtle">{t('audit.verifiedDetail', { n: verify.data.entries, when: fmtDate(verify.data.verifiedAt) })} · head <code>{short(verify.data.headHash)}…</code> <InfoTip id="audit.chain" /></div>
          {#if verify.data.error}<div class="subtle">{verify.data.error}</div>{/if}
        </div>
      </div>
    {:else}
      <Loading error={verify.error} />
    {/if}
    <Card flush>
      {#if entries.data}
        <Table rows={rows} columns={cols} urlKey="au" rowKey={(e) => String(e.seq)} caption={t('audit.title')} searchText={(e) => `${e.actor} ${e.action} ${e.target}`} initialSort={{ key: 'seq', dir: 'desc' }}>
          {#snippet toolbar()}<TimeRange bind:value={range.value} />{/snippet}
          {#snippet cell(e, col)}
            {#if col.key === 'seq'}<span class="num">{e.seq}</span>
            {:else if col.key === 'at'}<span class="nowrap">{fmtDate(e.at)}</span>
            {:else if col.key === 'actor'}{e.actor}
            {:else if col.key === 'action'}<code>{e.action}</code><div class="subtle">{e.target}</div><div class="subtle m-only">{e.actor}</div>
            {:else if col.key === 'result'}<StatusPill value={e.result} />
            {:else}<code class="sub" title={e.hash}>{short(e.hash)}</code><div class="subtle">← <code title={e.prevHash}>{short(e.prevHash)}</code></div>{/if}
          {/snippet}
        </Table>
      {:else}
        <Loading error={entries.error} onretry={entries.reload} />
      {/if}
    </Card>
  </div>
{/if}

<style>
  .verify { display: flex; gap: var(--s-3); align-items: center; }
  .sub { color: var(--fg-muted); }
  @media (min-width: 641px) { .m-only { display: none; } }
</style>
