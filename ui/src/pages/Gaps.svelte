<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Badge from '../components/Badge.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { Gap } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { fmtNum } from '../lib/format';
  import { href } from '../lib/router';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { serverText } from '../lib/server-text';

  // Group/Team filter: the server keeps the gaps of the services of the chosen groups.
  const gaps = resource(() => api.gaps.list(scopeGroups()));
  let kind = $state<'all' | Gap['kind']>('all');
  const kinds: Gap['kind'][] = ['few-samples', 'status-never-seen', 'low-support-rule', 'value-unknown', 'entity-without-creator'];
  const present = $derived(kinds.filter((k) => (gaps.data ?? []).some((g) => g.kind === k) || ['few-samples', 'status-never-seen', 'low-support-rule'].includes(k)));
  const shown = $derived((gaps.data ?? []).filter((g) => kind === 'all' || g.kind === kind));
  const count = (k: Gap['kind']) => (gaps.data ?? []).filter((g) => g.kind === k).length;

  const cols: Column<Gap>[] = $derived([
    { key: 'kind', label: t('gaps.col.kind'), sortable: true },
    { key: 'subject', label: t('gaps.col.subject'), sortable: true, value: (g) => `${g.service ?? ''} ${g.op ?? g.ruleId ?? ''}` },
    { key: 'count', label: t('gaps.col.support'), sortable: true, hideBelow: 'sm' },
    { key: 'detail', label: t('gaps.col.detail'), hideBelow: 'md' },
  ]);
  const tone = (k: Gap['kind']) => (k === 'status-never-seen' ? 'danger' : 'warning');
</script>

<PageHeader title={t('gaps.title')} description={t('gaps.desc')} help="gaps" breadcrumbs={[{ label: t('nav.gaps') }]} updatedAt={gaps.updatedAt} onrefresh={gaps.reload} refreshing={gaps.loading} />

{#if gaps.data}
  <ScopeNote />
  <p class="callout" role="note">{t('gj.intro')}</p>
  <div class="chips" role="group" aria-label={t('gaps.filter')}>
    <button type="button" class="chip" aria-pressed={kind === 'all'} onclick={() => (kind = 'all')}>{t('rules.all')} <small>{gaps.data.length}</small></button>
    {#each present as k (k)}
      <button type="button" class="chip" aria-pressed={kind === k} onclick={() => (kind = k)}>{tk(`gaps.kind.${k}`)} <small>{count(k)}</small></button>
    {/each}
  </div>
  <Card flush>
    {#if gaps.data.length === 0}
      <EmptyState icon="check" title={t('gaps.none')} description={t('gaps.noneHint')} />
    {:else}
      <Table rows={shown} columns={cols} rowKey={(g) => g.id} caption={t('gaps.title')} urlKey="g" searchText={(g) => `${g.service ?? ''} ${g.op ?? ''} ${g.ruleId ?? ''} ${serverText(g.detail)} ${g.detail}`}>
        {#snippet cell(g, col)}
          {#if col.key === 'kind'}
            <Badge tone={tone(g.kind)}>{tk(`gaps.kind.${g.kind}`)}</Badge>
          {:else if col.key === 'subject'}
            {#if g.ruleId}
              <a href={href('/rules/:id', { id: g.ruleId })}><b>{g.ruleId}</b></a>
            {:else if g.service && g.op}
              <a href={href('/contracts/:service/:op', { service: g.service, op: g.op }, { group: g.group ?? '' })}><b class="mono">{g.op}</b></a>
              <div class="subtle">{g.service} <GroupTag group={g.group} /></div>
            {/if}
          {:else if col.key === 'count'}
            {#if g.threshold}
              <div class="sup">
                <span class="num">{fmtNum(g.count)} / {fmtNum(g.threshold)}</span>
                <ProgressBar value={g.count / g.threshold} label={t('gaps.supportOf')} tone="warning" showValue={false} />
              </div>
            {:else}
              <span class="num">{g.count ? fmtNum(g.count) : '—'}</span>
            {/if}
          {:else}
            <span class="muted">{serverText(g.detail)}</span>
            <div class="todo">{tk(`gj.do.${g.kind}`)}</div>
          {/if}
        {/snippet}
      </Table>
    {/if}
  </Card>
{:else}
  <Loading error={gaps.error} onretry={gaps.reload} />
{/if}

<style>
  .todo { margin-top: 2px; font-size: 0.84rem; color: var(--fg-muted); }
  .chips { display: flex; flex-wrap: wrap; gap: var(--s-2); margin-bottom: var(--s-4); }
  .chip { font: inherit; font-size: 0.86rem; font-weight: 600; border: 1px solid var(--border-strong); border-radius: 999px; background: var(--surface); color: var(--fg-muted); padding: 0.25rem 0.8rem; cursor: pointer; }
  .chip[aria-pressed='true'] { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .sup { display: flex; flex-direction: column; gap: 4px; min-width: 7rem; }
</style>
