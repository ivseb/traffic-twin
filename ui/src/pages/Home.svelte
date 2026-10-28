<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import JourneySteps from '../components/JourneySteps.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { scopeGroups, scopeNoGroups, scopeReady } from '../lib/scope.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import ApprovalNextStep from '../components/ApprovalNextStep.svelte';
  import { journeyOf, type JourneyFacts } from '../lib/journey';
  import { pendingOpeningDrafts } from '../lib/approval';
  import { statesFacts } from '../lib/codes';

  const NOTHING: JourneyFacts = { sources: 0, services: 0, operations: 0, openAlerts: 0, openQuarantine: 0, gaps: 0, packsPublished: 0 };

  // Where the user is in the journey. Every count is optional: a role that cannot read a list simply does not
  // contribute to the picture (null), and a failed call never blocks the page.
  const facts = resource<JourneyFacts>(async () => {
    // A user who is not an administrator sees its own groups («I miei gruppi»): never the counts of other teams, not
    // even before the filter's data arrive or when it works with no group yet (usability test #4, m2).
    if (!scopeReady()) return new Promise<JourneyFacts>(() => {});
    if (scopeNoGroups()) return NOTHING;
    const g = scopeGroups();
    const or = <T,>(p: Promise<T>): Promise<T | null> => p.catch(() => null);
    const [sources, services, alerts, quarantine, gaps, packs] = await Promise.all([
      or(api.sources.list()),
      or(api.services.list(g)),
      or(api.alerts.list(g)),
      or(api.quarantine.list(g)),
      or(api.gaps.list(g)),
      or(api.publications.list(g)),
    ]);
    const own = (services ?? []).filter((s) => !s.nowDeclaredAs);
    return {
      sources: sources ? sources.filter((s) => !s.revoked && (!g || g.includes(s.group))).length : null,
      services: services ? own.length : null,
      operations: services ? own.reduce((n, s) => n + s.operations, 0) : null,
      openAlerts: alerts ? alerts.filter((a) => a.state === 'open').length : null,
      openQuarantine: quarantine ? quarantine.filter((q) => q.state !== 'resolved').length : null,
      gaps: gaps ? gaps.length : null,
      packsPublished: packs ? packs.filter((p) => p.status === 'published').length : null,
    };
  });

  const journey = $derived(facts.data ? journeyOf(facts.data) : null);
  // A draft of the filtered groups that opens values and waits for approvals (B1).
  const settings = resource(() => api.settings.get().catch(() => null));
  const policies = resource(() => (!scopeReady() || scopeNoGroups() ? Promise.resolve([]) : api.policies.list(scopeGroups()).catch(() => [])));
  const drafts = $derived(pendingOpeningDrafts(policies.data ?? [], scopeGroups()));
  // Where the statuses already come out as codes (no approval) and whether rules with states exist: the «Prossimo
  // passo» never asks for an approval the statuses do not need (usability test #5, M3).
  const rules = resource(() => (!scopeReady() || scopeNoGroups() ? Promise.resolve([]) : api.rules.list(scopeGroups()).catch(() => [])));
  const states = $derived(statesFacts(policies.data ?? [], scopeGroups(), rules.data ?? null));
</script>

<PageHeader title={t('home.title')} description={t('home.desc')} help="home" breadcrumbs={[{ label: t('nav.home') }]} updatedAt={facts.updatedAt} onrefresh={facts.reload} refreshing={facts.loading} />

<div class="stack">
  <ScopeNote />
  {#if scopeNoGroups()}<p class="callout" role="status">{t('fix4.home.noGroups')}</p>{/if}
  {#if drafts.length}<ApprovalNextStep {drafts} facts={states} required={settings.data?.approvals.openingRequired ?? 2} onchange={policies.reload} />{/if}
  {#if journey}
    <Card tone="accent" title={t('home.next')}>
      <div class="next">
        <div class="grow">
          <p class="big"><b>{t(journey.next.title, journey.next.params)}</b></p>
          <p class="muted">{t(journey.next.why, journey.next.params)}</p>
        </div>
        <Button variant="primary" icon="arrowRight" href={journey.next.href}>{t(journey.next.cta)}</Button>
      </div>
    </Card>

    <JourneySteps {journey} />
    <p class="subtle">{t('home.advanced')}</p>
  {:else}
    <Card><p class="muted">{facts.error ? t('common.error') : t('fix4.computing')}</p></Card>
  {/if}
</div>

<style>
  .next { display: flex; align-items: center; gap: var(--s-4); flex-wrap: wrap; }
  .big { font-size: 1.15rem; margin: 0 0 var(--s-1); }
</style>
