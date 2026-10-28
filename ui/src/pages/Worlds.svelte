<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import WorldExplorer from '../components/WorldExplorer.svelte';
  import ProgressSteps from '../components/ProgressSteps.svelte';
  import Loading from '../components/Loading.svelte';
  import { buildSteps, type Phase } from '../lib/world-build';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { scope, scopeGroups, showGroupColumn } from '../lib/scope.svelte';
  import type { World } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, errorMessage, toast, toastError } from '../lib/stores.svelte';
  import { fmtDate, fmtNum } from '../lib/format';

  // Group/Team filter: the server lists the worlds of the chosen groups.
  const worlds = resource(() => api.worlds.list(scopeGroups()));
  let seed = $state(42);
  let customers = $state(100);
  let busy = $state(false);
  // Which step of the generation is running: the profiles (archetypes) are built here when there are none.
  let phase = $state<Phase>('idle');
  let failed = $state(false);
  let needArchetypes = $state(false);
  let selectedId = $state<string>('');
  // What the last generation said, kept on the page (a toast goes away): why it failed (no usable rules of the
  // group, with the rules and the services they miss) or which of the group's rules it left out.
  let failNote = $state('');
  let excludedNote = $state('');

  const selected = $derived(worlds.data?.find((w) => w.id === selectedId) ?? worlds.data?.[0] ?? null);

  const seedOk = $derived(Number.isInteger(seed) && seed >= 0);
  const custOk = $derived(Number.isInteger(customers) && customers >= 1 && customers <= 5000);

  // A world holds the contracts, rules and services of one group (the rules of another team would drag their
  // services into the pack and the gate would refuse it). With a filter: one of its groups; "every group" only
  // without a filter.
  const manyGroups = $derived((scope.data?.groups.length ?? 0) > 1);
  const groupChoices = $derived(scopeGroups() ?? scope.data?.groups ?? []);
  let pickedGroup = $state<string | null>(null);
  const genGroup = $derived(
    pickedGroup !== null && (groupChoices.includes(pickedGroup) || (pickedGroup === '' && !scopeGroups())) ? pickedGroup : (scopeGroups()?.[0] ?? ''),
  );

  async function generate(): Promise<void> {
    busy = true;
    failed = false;
    failNote = '';
    excludedNote = '';
    phase = 'check';
    toast(t('world.started'));
    try {
      // Archetypes (the behaviour profiles the customers are drawn from) are built automatically the first time.
      const set = await api.archetypes.get(genGroup || undefined);
      needArchetypes = set.built === false || (set.built === undefined && set.archetypes.length === 0);
      if (needArchetypes) {
        phase = 'archetypes';
        await api.archetypes.build(genGroup || undefined);
      }
      phase = 'world';
      const w = await api.worlds.generate({ seed, customers, ...(genGroup ? { group: genGroup } : {}) });
      phase = 'done';
      toast(t('world.generated', { id: w.id }));
      const ex = w.excludedRules ?? [];
      if (ex.length) {
        excludedNote = t('world.excluded', { id: w.id, n: ex.length, rules: ex.map((x) => x.id).join(', '), services: [...new Set(ex.flatMap((x) => x.services))].join(', ') });
      }
      selectedId = w.id;
      worlds.reload();
    } catch (e) {
      failed = true;
      failNote = errorMessage(e);
      toastError(e);
    } finally {
      busy = false;
    }
  }
  const steps = $derived(buildSteps(phase, needArchetypes, failed));

  const cols: Column<World>[] = $derived([
    { key: 'id', label: t('world.col.id'), sortable: true },
    ...(showGroupColumn() ? [{ key: 'group', label: t('scope.col.group'), sortable: true, value: (w: World) => w.group ?? '' }] : []),
    { key: 'seed', label: 'seed', sortable: true, align: 'end' },
    { key: 'customers', label: t('world.col.customers'), sortable: true, align: 'end' },
    { key: 'entities', label: t('world.col.entities'), align: 'end', hideBelow: 'sm' },
    { key: 'createdAt', label: t('world.col.created'), hideBelow: 'md', sortable: true },
  ]);
</script>

<PageHeader title={t('world.title')} description={t('world.desc')} help="worlds" breadcrumbs={[{ label: t('nav.worlds') }]} updatedAt={worlds.updatedAt} onrefresh={worlds.reload} refreshing={worlds.loading} />

<div class="stack">
  <Card title={t('world.gen')} subtitle={t('world.genHint')}>
    <form class="row form" onsubmit={(e) => { e.preventDefault(); void generate(); }}>
      <Field label={t('world.seed')} help="world.seed" hint={t('world.seedHint')} error={seedOk ? '' : t('world.seedInvalid')}>
        {#snippet children({ id, describedby })}<input {id} type="number" min="0" step="1" bind:value={seed} aria-describedby={describedby} />{/snippet}
      </Field>
      <Field label={t('world.customers')} help="world.customers" hint={t('world.customersHint')} error={custOk ? '' : t('world.customersInvalid')}>
        {#snippet children({ id, describedby })}<input {id} type="number" min="1" max="5000" step="1" bind:value={customers} aria-describedby={describedby} />{/snippet}
      </Field>
      {#if groupChoices.length > 1 || (!scopeGroups() && groupChoices.length > 0)}
        <Field label={t('world.group')} hint={t('world.groupHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} value={genGroup} onchange={(e) => (pickedGroup = e.currentTarget.value)}>
              {#if !scopeGroups()}<option value="">{t('world.groupAll')}</option>{/if}
              {#each groupChoices as g (g)}<option value={g}>{g}</option>{/each}
            </select>
          {/snippet}
        </Field>
      {/if}
      <div class="btn"><Button type="submit" variant="primary" icon="spark" loading={busy} denied={!can('worlds.generate')} disabled={!seedOk || !custOk}>{t('world.generate')}</Button></div>
    </form>
    {#if genGroup}
      <p class="callout" role="status">{t('world.scopeGroup', { group: genGroup })}</p>
    {:else if manyGroups}
      <p class="callout warn" role="status">{t('world.scopeAll')}</p>
    {/if}
    {#if phase !== 'idle'}<ProgressSteps {steps} label={t('world.progress')} />{/if}
    {#if failNote}<div class="callout danger" role="alert"><b>{t('world.failedTitle')}</b> {failNote}</div>{/if}
    {#if excludedNote}<p class="callout warn" role="status">{excludedNote}</p>{/if}
  </Card>

  {#if worlds.data}
    <ScopeNote />
    <Card title={t('world.list')} flush>
      <Table rows={worlds.data} columns={cols} rowKey={(w) => w.id} caption={t('world.list')} onrowclick={(w) => { selectedId = w.id; }} selectedKey={selected?.id}>
        {#snippet cell(w, col)}
          {#if col.key === 'id'}
            <button type="button" class="link-btn" onclick={(e) => { e.stopPropagation(); selectedId = w.id; }}><b>{w.id}</b></button>
          {:else if col.key === 'group'}<GroupTag group={w.group ?? ''} always />
          {:else if col.key === 'seed'}<span class="num">{w.seed}</span>
          {:else if col.key === 'customers'}<span class="num">{fmtNum(w.customers)}</span>
          {:else if col.key === 'entities'}<span class="num">{fmtNum(w.entities)}</span>{#if w.services?.length} <span class="subtle">· {t('world.scopeOf', { n: w.services.length })}</span>{/if}
          {:else}{fmtDate(w.createdAt)} <span class="subtle">· {w.createdBy}</span>{/if}
        {/snippet}
      </Table>
    </Card>

    {#if selected}
      <div class="row spread bar">
        <p class="subtle">{t('wx.of', { id: selected.id, n: fmtNum(selected.customers) })}</p>
        <Button size="sm" href="#/packs?world={selected.id}" variant="primary">{t('world.publish')}</Button>
      </div>
      <WorldExplorer world={selected} />
    {/if}
  {:else}
    <Loading error={worlds.error} onretry={worlds.reload} />
  {/if}
</div>

<style>
  .form { align-items: flex-start; }
  .form :global(.field) { min-width: 11rem; }
  .btn { padding-top: 1.55rem; }
  .bar { align-items: center; }
  .bar p { margin: 0; }
</style>
