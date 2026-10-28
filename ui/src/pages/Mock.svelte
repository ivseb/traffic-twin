<script lang="ts">
  // The Mock page: "connect the service, come back after a day, press a button, get a mock that replaces the real
  // endpoints". One action prepares and starts the mock of a group (the packs stay in Advanced); then the URL of
  // every simulated service, the live journal, the scenarios, the faults and the virtual clock of a session.
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Button from '../components/Button.svelte';
  import PrepareCard from '../components/mock/PrepareCard.svelte';
  import MockStatus from '../components/mock/MockStatus.svelte';
  import InstallCard from '../components/mock/InstallCard.svelte';
  import CallsPanel from '../components/mock/CallsPanel.svelte';
  import SessionPanel from '../components/mock/SessionPanel.svelte';
  import SavedScenarios from '../components/mock/SavedScenarios.svelte';
  import IdentityCard from '../components/mock/IdentityCard.svelte';
  import PagesCard from '../components/mock/PagesCard.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { scope, scopeGroups } from '../lib/scope.svelte';
  import { loc, navigate } from '../lib/router.svelte';
  import { can } from '../lib/stores.svelte';

  let { params = {} }: { params?: Record<string, string | undefined> } = $props();

  const overview = resource(() => api.mocks.overview(scopeGroups()));
  const tokens = resource(() => (can('publish.build') ? api.mocks.tokens(scopeGroups()) : Promise.resolve([])));

  // Refresh the status every few seconds: the mocks report on their own.
  $effect(() => {
    const h = setInterval(() => overview.reload(), 5000);
    return () => clearInterval(h);
  });

  const groups = $derived.by(() => {
    const sel = scopeGroups();
    if (sel?.length) return sel;
    const all = new Set<string>(scope.data?.groups ?? []);
    for (const m of overview.data?.mocks ?? []) all.add(m.group);
    return [...all].sort();
  });
  let group = $state('');
  $effect(() => {
    if (!group || !groups.includes(group)) group = scope.data?.mine.find((g) => groups.includes(g)) ?? groups[0] ?? '';
  });

  const env = $derived(overview.data?.environment);
  const mocks = $derived(overview.data?.mocks ?? []);
  const selectedId = $derived(params.id ?? loc.query.mock ?? '');
  const selected = $derived(mocks.find((m) => m.id === selectedId) ?? mocks.find((m) => m.online && m.group === group) ?? mocks.find((m) => m.online) ?? mocks[0]);
  const managedOf = (g: string) => overview.data?.managed.find((m) => m.group === g);

  const tabFromUrl = $derived(loc.query.tab ?? '');
  let tab = $state('calls');
  $effect(() => {
    if (tabFromUrl && ['calls', 'session', 'saved'].includes(tabFromUrl)) tab = tabFromUrl;
  });

  function select(id: string): void {
    navigate('/mock', { mock: id, ...(tab !== 'calls' ? { tab } : {}) }, true);
  }
</script>

<PageHeader title={t('mk.title')} description={t('mk.desc')} help="mock" breadcrumbs={[{ label: t('nav.mock') }]} updatedAt={overview.updatedAt} onrefresh={overview.reload} refreshing={overview.loading} />

{#if overview.data && env}
  <div class="stack page">
    {#if groups.length}
      <PrepareCard {groups} bind:group kubernetes={env.kubernetes} ondone={() => { overview.reload(); tokens.reload(); }} />
    {:else}
      <EmptyState title={t('mk.noGroups')} description={t('mk.noGroupsHint')} icon="onboarding"><Button variant="primary" href="#/onboarding">{t('mk.connect')}</Button></EmptyState>
    {/if}

    <section aria-labelledby="mk-running">
      <h2 id="mk-running" class="fs-3">{t('mk.running')}</h2>
      {#if mocks.length}
        <div class="list">
          {#each mocks as m (m.id)}
            <MockStatus mock={m} managed={managedOf(m.group)} selected={selected?.id === m.id} onselect={mocks.length > 1 ? () => select(m.id) : undefined} onchanged={overview.reload} />
          {/each}
        </div>
      {:else}
        <p class="subtle">{env.kubernetes ? t('mk.noneK8s', { ns: env.namespace ?? '' }) : t('mk.noneSelf')}</p>
      {/if}
    </section>

    {#if selected}
      <Card title={t('mk.useTitle', { name: `${selected.group} · ${selected.instance}` })} subtitle={t('mk.useSubtitle')}>
        <Tabs label={t('mk.useTitle', { name: selected.instance })} tabs={[{ id: 'calls', label: t('mk.tab.calls') }, { id: 'session', label: t('mk.tab.session') }, { id: 'saved', label: t('mk.tab.saved') }]} bind:value={tab}>
          {#if tab === 'calls'}
            <CallsPanel mockId={selected.id} />
          {:else if tab === 'session'}
            <SessionPanel mock={selected} onchanged={overview.reload} />
          {:else}
            <SavedScenarios baseUrl={selected.publicUrl} />
          {/if}
        </Tabs>
      </Card>
    {:else if tab === 'saved'}
      <Card title={t('mk.tab.saved')}><SavedScenarios /></Card>
    {/if}

    {#if group && (can('publish.build') || can('publish.run') || can('audit.view'))}
      {#key group}<IdentityCard {group} />{/key}
      {#key group}<PagesCard {group} />{/key}
    {/if}

    {#if group && can('publish.build')}
      <InstallCard {group} kubernetes={env.kubernetes} tokens={tokens.data ?? []} onchanged={tokens.reload} />
    {/if}

    <p class="subtle">{t('soap.mockNote')}</p>
    <p class="subtle">{t('mk.advanced')} <a href="#/packs">{t('mk.advancedLink')}</a></p>
  </div>
{:else}
  <Loading error={overview.error} onretry={overview.reload} />
{/if}

<style>
  .page { gap: var(--s-5); }
  .list { display: flex; flex-direction: column; gap: var(--s-3); margin-top: var(--s-2); }
</style>
