<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Badge from '../components/Badge.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import ApprovalNotice from '../components/ApprovalNotice.svelte';
  import { t, tk, type MsgKey } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { QuarantineItem } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, session, stepUpDone, toast, toastError } from '../lib/stores.svelte';
  import { fmtAgo, fmtNum } from '../lib/format';
  import { href } from '../lib/router';
  import { hostQuarantine } from '../lib/hosts';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { scopeGroups } from '../lib/scope.svelte';

  // Group/Team filter: the server keeps the items of the sources of the chosen groups.
  const items = resource(() => api.quarantine.list(scopeGroups()));
  const settings = resource(() => api.settings.get());
  // A dismissal approved after an OIDC step-up (App resumes the call): show the new state.
  $effect(() => {
    if (stepUpDone.tick) items.reload();
  });
  let target = $state<QuarantineItem | null>(null);
  let dismissOpen = $state(false);

  const mine = (n: string) => n === session.user?.username || n === session.user?.displayName || n === session.user?.id;
  const open = $derived((items.data ?? []).filter((q) => q.state !== 'resolved'));

  const cols: Column<QuarantineItem>[] = $derived([
    { key: 'where', label: t('qu.col.where'), sortable: true, value: (q) => `${q.service} ${q.op ?? ''} ${q.where}` },
    { key: 'kind', label: t('qu.col.kind'), sortable: true, hideBelow: 'sm' },
    { key: 'distinct', label: t('qu.col.distinct'), sortable: true, align: 'end', hideBelow: 'sm', value: (q) => q.distinctEstimate },
    { key: 'state', label: t('qu.col.state'), sortable: true },
    { key: 'since', label: t('qu.col.since'), hideBelow: 'md', value: (q) => -new Date(q.since).getTime(), sortable: true },
    { key: 'act', label: '' },
  ]);

  /** Readable "where" of an item: the host kinds are described, the others show the part and path as the server wrote them. */
  function whereLabel(q: QuarantineItem): string {
    const h = hostQuarantine(q);
    if (h?.kind === 'host-label' && h.domain) return t('qu.hostLabel', { domain: h.domain, pos: h.position });
    if (h?.kind === 'host') return t('qu.hostKind');
    return q.where;
  }
  const hasHost = $derived(open.some((q) => hostQuarantine(q)));

  /** Why the item is here, by kind of element. */
  const whyKey = (q: QuarantineItem): MsgKey =>
    q.kind === 'keep-value' ? 'qj.why.keep' : q.kind === 'name' ? 'qj.why.name' : q.kind === 'path-segment' ? 'qj.why.segment' : 'qj.why.host';

  function block(q: QuarantineItem): string | null {
    if (q.state === 'resolved') return t('qu.resolved');
    if (q.approvals.some((a) => mine(a.by))) return t('qu.alreadyDone');
    return null;
  }

  async function resolve(q: QuarantineItem, resolution: 'close' | 'dismiss'): Promise<void> {
    try {
      const r = await api.quarantine.resolve(q.id, resolution);
      toast(r.state === 'resolved' ? t('qu.done') : t('qu.pending'));
      items.reload();
    } catch (e) {
      toastError(e);
    }
  }
</script>

<PageHeader title={t('qu.title')} description={t('qu.desc')} help="quarantine" breadcrumbs={[{ label: t('nav.quarantine') }]} updatedAt={items.updatedAt} onrefresh={items.reload} refreshing={items.loading} />

{#if items.data}
  <div class="stack">
    <ScopeNote />
    <p class="callout">{t('qu.intro')}</p>
    <ApprovalNotice approvals={settings.data?.approvals} />
    {#if hasHost}<p class="callout">{t('qu.hostHint')}</p>{/if}
    {#if can('override.admin')}<p class="callout warn">{t('qu.adminHint')}</p>{/if}
    <Card flush>
      {#if open.length === 0}
        <EmptyState icon="check" title={t('qu.none')} description={t('qu.noneHint')} />
      {:else}
        <Table rows={open} columns={cols} rowKey={(q) => q.id} caption={t('qu.title')} urlKey="qu" searchText={(q) => `${q.service} ${q.op ?? ''} ${q.where}`}>
          {#snippet cell(q, col)}
            {#if col.key === 'where'}
              {@const hq = hostQuarantine(q)}
              {#if hq}
                <b>{whereLabel(q)}</b>
                <div class="subtle">
                  <GroupTag group={q.group} />
                  {#if q.alert}<Badge tone="warning" title={t('qu.alert.host_cardinality.tip')}>{t('qu.alert.host_cardinality')}</Badge>{/if}
                  {#if hq.kind === 'host-label' && hq.domain}<a href={href('/hosts', {}, { q: hq.domain })}>{t('qu.hostSee')}</a>{/if}
                </div>
              {:else}
                <b class="mono">{q.where}</b>
                <div class="subtle">
                  {q.service}{#if q.op} · {q.op}{/if} <GroupTag group={q.group} />
                  {#if q.alert === 'value_cardinality'}<Badge tone="warning" title={t('qu.alert.value_cardinality.tip')}>{t('qu.alert.value_cardinality')}</Badge>{/if}
                </div>
              {/if}
              <p class="why">{t(whyKey(q))}</p>
            {:else if col.key === 'kind'}
              <Badge>{tk(`qu.kind.${q.kind}`, undefined, q.kind)}</Badge>
            {:else if col.key === 'distinct'}
              <span class="num">{fmtNum(q.distinctEstimate)}</span>
            {:else if col.key === 'state'}
              <Badge tone={q.state === 'dismiss-pending' ? 'warning' : 'danger'}>{t(`qu.state.${q.state}` as 'qu.state.quarantined')}</Badge>
              {#if q.approvals.length}<div class="subtle">{t('qu.approvedBy', { who: q.approvals.map((a) => a.by).join(', ') })}</div>{/if}
              {#if q.state === 'dismiss-pending'}<div class="subtle">{t('qj.pending')}</div>{/if}
            {:else if col.key === 'since'}
              {fmtAgo(q.since)}
            {:else}
              {@const why = block(q)}
              <div class="acts">
                <div class="act">
                  <Button size="sm" variant="primary" denied={!can('quarantine.resolve')} disabled={!!why} title={why ?? undefined} onclick={() => resolve(q, 'close')}>{t('qu.close')}</Button>
                  <p class="eff">{t('qj.closeEffect')}</p>
                </div>
                <div class="act">
                  <Button size="sm" denied={!can('quarantine.resolve')} disabled={!!why} title={why ?? undefined} onclick={() => { target = q; dismissOpen = true; }}>{t('qu.dismiss')}</Button>
                  <p class="eff">{t('qj.dismissEffect')}</p>
                </div>
              </div>
            {/if}
          {/snippet}
        </Table>
      {/if}
    </Card>
  </div>
{:else}
  <Loading error={items.error} onretry={items.reload} />
{/if}

<ConfirmDialog
  bind:open={dismissOpen}
  title={t('qu.dismissTitle')}
  message={t('qu.dismissMsg', { where: target ? whereLabel(target) : '' })}
  confirmLabel={t('qu.dismiss')}
  onconfirm={() => (target ? resolve(target, 'dismiss') : Promise.resolve())}
/>

<style>
  .why { margin: var(--s-1) 0 0; color: var(--fg-muted); font-size: 0.86rem; max-width: 34rem; }
  .acts { display: flex; flex-direction: column; gap: var(--s-2); min-width: 15rem; max-width: 22rem; }
  .act { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
  .eff { margin: 0; font-size: 0.8rem; color: var(--fg-muted); }
</style>
