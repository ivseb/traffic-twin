<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  import InfoTip from '../components/InfoTip.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Badge from '../components/Badge.svelte';
  import Button from '../components/Button.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Icon from '../components/Icon.svelte';
  import Drawer from '../components/Drawer.svelte';
  import RuleEditor from '../components/RuleEditor.svelte';
  import RetireRule from '../components/RetireRule.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { inScope, scopeGroups } from '../lib/scope.svelte';
  import { ApiError, type MineProgress, type MineResult, type MinerExplanation, type Rule, type RuleEffect, type RuleLimit, type ReviewAction, type RuleStatus } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, session, toast, toastError } from '../lib/stores.svelte';
  import { fmtAgo, fmtDate, fmtNum, fmtAfter, fmtPct, fmtTime, parseAfter } from '../lib/format';
  import { href } from '../lib/router';
  import { navigate } from '../lib/router.svelte';
  import { LOW_SUPPORT_MIN } from '../lib/thresholds';
  import { statesFacts } from '../lib/codes';
  import { keepCatalog } from '../lib/rule-catalog';
  import { serverText } from '../lib/server-text';
  import type { MinerCandidate, RuleDefinition } from '../lib/api';
  import { candidateDraft, matchesText } from '../lib/rule-templates';

  let { params }: { params: Record<string, string> } = $props();

  // Group/Team filter: the server keeps the rules whose services belong to the chosen groups; each rule says which
  // groups own the services it touches (`groups`).
  const rules = resource(() => api.rules.list(scopeGroups()));
  // The last run of the filtered groups (`?group=`); the diagnostics (service names only) are also kept by service.
  const mining_status = resource(() => api.rules.status(scopeGroups()));
  // The active policies of the filtered groups: where the statuses already come out as codes, without approval, the
  // messages about states must not ask for a keep to be approved (usability test #5, M3).
  const policies = resource(() => api.policies.list(scopeGroups()).catch(() => []));
  let mining = $state(false);
  // Where the run is (queued behind another heavy job, running, the server briefly away): never «Errore del server»
  // while the job goes on (usability test #4, M3).
  let progress = $state<MineProgress | null>(null);
  let mineError = $state('');
  // What the last search did, and why it proposed nothing (never a silent "0").
  let mineResult = $state<MineResult | null>(null);
  // The policy assistant of the filtered group: where the sampling is raised.
  const assistantLink = $derived(href('/onboarding', {}, { ...(scopeGroups()?.[0] ? { group: scopeGroups()![0] } : {}), step: '4' }));
  // The explanations shown: those of the search just made, else those of the last run (also a scheduled one),
  // for the services of the filtered groups.
  const explanations = $derived(((mineResult?.diagnostics ?? mining_status.data?.diagnostics) ?? []).filter((d) => inScope(d.service)));
  // What keeps a rule from being proposed (proposed rules, references and plain creations are not problems).
  const blocking = $derived(explanations.filter((d) => !['mined', 'reference', 'no_effect'].includes(d.code)));
  // The last run's outcome is shown for the group also when it found nothing to block (no_effect: no lifecycle seen).
  const lastBox = $derived(explanations.filter((d) => d.code !== 'reference'));
  // «Rivedi in blocco › Stati e codici» of the filtered group: where the status gets out in clear (keep).
  const bulkLink = $derived(href('/sources', {}, { tab: 'policy', bulk: '1', ...(scopeGroups()?.length === 1 ? { group: scopeGroups()![0] } : {}) }));
  const facts = $derived(statesFacts(policies.data ?? [], scopeGroups() ?? null, rules.data ?? null));
  const codeFields = $derived(facts.fields.slice(0, 4).join(', '));
  const lastRunAt = $derived(mineResult?.finishedAt ?? mining_status.data?.lastRunAt);
  const needsAssistant = (d: MinerExplanation) => ['few_causes', 'few_subjects', 'outcome_few_subjects', 'few_births', 'entity_not_accepted'].includes(d.code);
  function fmtSpan(sec: number): string {
    if (sec <= 0) return '—';
    if (sec < 120) return `${sec} s`;
    if (sec < 7200) return `${Math.round(sec / 60)} min`;
    return `${Math.round(sec / 3600)} h`;
  }
  function explain(d: MinerExplanation): string {
    const k = mining_status.data?.kMin ?? 20;
    return tk(`rules.why.${d.code}`, { service: d.service || '—', op: d.op || '—', entity: d.entity || '—', causes: fmtNum(d.causes), decided: fmtNum(d.decided), subjects: fmtNum(d.subjects), horizon: fmtSpan(d.horizonS), k }, serverText(d.reason));
  }
  async function mine(): Promise<void> {
    mining = true;
    mineResult = null;
    mineError = '';
    progress = { status: 'running', elapsedS: 0 };
    // The seconds go on between two polls too.
    const started = Date.now();
    const tick = setInterval(() => progress && (progress = { ...progress, elapsedS: Math.round((Date.now() - started) / 1000) }), 1000);
    try {
      const r = await api.rules.mine((p) => (progress = p));
      mineResult = r;
      toast(t('rules.mineDone', { n: r.newRules }));
      rules.reload();
      mining_status.reload();
    } catch (e) {
      // A run that failed on the server says so in words; anything else (no role, offline) as usual.
      if (e instanceof ApiError && e.code === 'server') mineError = t('fix4.rules.failed', { code: e.serverCode ?? e.message });
      else toastError(e);
      mining_status.reload();
    } finally {
      clearInterval(tick);
      mining = false;
      progress = null;
    }
  }
  // The catalog of the rule editor is read ahead, as soon as the page opens: the editor then opens on it at once
  // instead of waiting for the server (usability test #5, M4). A failure here is silent: the editor asks again.
  $effect(() => {
    if (!can('rules.edit')) return;
    const g = scopeGroups();
    let stop = false;
    api.rules
      .catalog(g)
      .then((c) => {
        if (!stop) keepCatalog(g, c);
      })
      .catch(() => undefined);
    return () => {
      stop = true;
    };
  });
  // Rule editor: a new rule written by hand, or the definition of the open rule.
  let editor = $state<{ open: boolean; rule?: Rule; initial?: RuleDefinition; template?: string }>({ open: false });
  // Rules v1.9 (C0): the structures seen by fewer than k users, for the services of the filtered groups.
  const candidates = $derived((mining_status.data?.candidates ?? []).filter((c) => inScope(c.service)));
  const kMinNow = $derived(mining_status.data?.kMin ?? 20);
  function draftFrom(c: MinerCandidate): void {
    editor = { open: true, initial: candidateDraft(c), template: c.template };
  }
  // Groups mined with a lower k (marked as test by an administrator): a badge wherever their rules are shown.
  const testK = $derived(Object.entries(mining_status.data?.testK ?? {}).filter(([g]) => !scopeGroups() || scopeGroups()!.includes(g)));
  const ruleTestK = (r: Rule): number | undefined => {
    const ks = (r.groups ?? []).map((g) => mining_status.data?.testK?.[g]).filter((k): k is number => typeof k === 'number');
    return ks.length ? Math.min(...ks) : undefined;
  };
  const effectAll = (e: RuleEffect): string => t('w4.rules.all', { entity: e.entity, where: e.where ? t('w4.rules.allWhere', { cond: kindLabel('', e.where) }) : '' });
  function edited(r: Rule): void {
    editor = { open: false };
    if (r.status === 'draft' && filter !== 'all') filter = 'draft';
    rules.reload();
    navigate(`/rules/${r.id}`);
  }
  let filter = $state<'all' | RuleStatus>('draft');
  let note = $state('');
  let edits = $state<Record<string, string>>({});

  const order: RuleStatus[] = ['draft', 'stale', 'approved', 'rejected', 'retired'];
  const list = $derived((rules.data ?? []).filter((r) => filter === 'all' || r.status === filter));
  const counts = $derived(Object.fromEntries(order.map((s) => [s, (rules.data ?? []).filter((r) => r.status === s).length])) as Record<RuleStatus, number>);
  const rule = $derived(rules.data?.find((r) => r.id === params.id) ?? null);
  // The chips: «Ritirata» only once a rule was retired.
  const chipList = $derived(['draft', 'stale', 'approved', 'rejected', ...(counts.retired ? ['retired'] : []), 'all']);
  // A newer rule that replaces the open one (the miner's «sostituisce»): when both are approved both are in the packs.
  const replacement = $derived(rule ? ((rules.data ?? []).find((r) => r.supersedes === rule.id && r.status !== 'rejected' && r.status !== 'retired') ?? undefined) : undefined);

  // Reset local edits when another rule is opened.
  $effect(() => {
    void params.id;
    edits = {};
    note = '';
  });

  const editable = $derived(!!rule && (rule.status === 'draft' || rule.status === 'stale'));
  const lowSupport = $derived(!!rule && rule.kind === 'causal' && rule.origin !== 'manual' && rule.counts.causes < LOW_SUPPORT_MIN);
  const pSum = $derived(rule ? rule.outcomes.reduce((a, o) => a + o.p, 0) : 0);

  function parentLabel(e: RuleEffect): string {
    return e.afterEffect ? e.afterEffect : t('rules.fromCause');
  }

  async function saveAfter(e: RuleEffect): Promise<void> {
    const v = (edits[e.id] ?? e.after).trim();
    if (!rule) return;
    try {
      await api.rules.setAfter(rule.id, e.id, v);
      delete edits[e.id];
      toast(t('rules.afterSaved'));
      rules.reload();
    } catch (err) {
      toastError(err);
    }
  }

  async function review(action: ReviewAction): Promise<void> {
    if (!rule) return;
    try {
      await api.rules.review(rule.id, action, note.trim());
      toast(t(`rules.done.${action}` as 'rules.done.approve'));
      note = '';
      rules.reload();
    } catch (err) {
      toastError(err);
    }
  }
  const effectName = (r: Rule, id: string) => r.effects.find((e) => e.id === id)?.id ?? id;
  const kindLabel = (k: string, v: Record<string, string>) => Object.entries(v).map(([a, b]) => `${a} = ${b}`).join(', ');
  // Rules v1.7: how a value comes from the call (a copy of the request) or from the entity (a toggle).
  const valueNotes = (vals: Record<string, string>, bind: Record<string, string>): string[] =>
    Object.entries(vals).flatMap(([field, v]) => {
      if (/^\$\{not:[A-Za-z_][A-Za-z0-9_.]*\}$/.test(v)) return [t('w2.rules.toggle', { field })];
      const ref = /^\$\{([a-z][a-z0-9_]*)\}$/.exec(v);
      const src = ref ? bind[ref[1]] : undefined;
      return src?.startsWith('req.') ? [t('w2.rules.copy', { field, ref: src })] : [];
    });
  // Rules v1.8: the keyed record an effect targets, and the counter of a response effect.
  const keyNote = (entity: string, key: Record<string, string>): string => {
    const fields = Object.entries(key).map(([k, v]) => `${k} = ${v}`).join(', ');
    return t('w3.rules.targetKey', { entity, fields: fields ? t('w3.rules.targetKey.fields', { fields }) : '' });
  };
  const limitNote = (status: number, lm: RuleLimit, bind: Record<string, string>): string => {
    const ref = /^\$\{([a-z][a-z0-9_]*)\}$/.exec(lm.key ?? '');
    const key = ref ? t('w3.rules.limit.keyRef', { ref: bind[ref[1]] ?? ref[1] }) : t('w3.rules.limit.keyUser');
    if (lm.n === 1 && !lm.window) return t('w3.rules.limit.unique', { key, status });
    const window = lm.window ? t('w3.rules.limit.window', { window: lm.window }) : t('w3.rules.limit.session');
    return t('w3.rules.limit.count', { key, n: lm.n, window, status });
  };
</script>

<PageHeader title={t('rules.title')} description={t('rules.desc')} help="rules" breadcrumbs={[{ label: t('nav.rules') }]} updatedAt={rules.updatedAt} onrefresh={rules.reload} refreshing={rules.loading}>
  {#snippet actions()}
    {#if mining_status.data?.state === 'insufficient_data'}
      <Badge tone="warning" dot>{t('rules.insufficient', { n: mining_status.data.minHours })}</Badge>
    {:else if mining_status.data?.state === 'few_subjects'}
      <Badge tone="warning" dot>{t('rules.fewBadge', { n: mining_status.data.subjects ?? 0, k: mining_status.data.kMin ?? 20 })}</Badge>
    {:else if mining_status.data?.warnings.length}
      <Badge tone="warning" dot>{t('rules.warnings', { n: mining_status.data.warnings.length })}</Badge>
    {/if}
    {#each testK as [g, k] (g)}
      <Badge tone="warning" title={t('w4.testk.tip', { group: g, k, kMin: kMinNow })}>{t('w4.testk.badgeGroup', { group: g, k })}</Badge>
    {/each}
    <Button icon="plus" denied={!can('rules.edit')} onclick={() => (editor = { open: true })}>{t('rules.newRule')}</Button>
    <Button icon="refresh" loading={mining} denied={!can('rules.mine')} onclick={mine}>{t('rules.mine')}</Button>
  {/snippet}
</PageHeader>
<p class="subtle lastrun" data-testid="last-run">
  {#if lastRunAt}{t('rules.lastRun', { time: fmtTime(lastRunAt), ago: fmtAgo(lastRunAt), n: fmtNum(mineResult?.events ?? mining_status.data?.events ?? 0) })}{:else if mining_status.data}{t('rules.neverRun')}{/if}
</p>
{#if mining}
  <p class="callout" role="status" aria-live="polite" data-testid="mining">
    {progress?.retrying ? t('fix4.rules.mining.retrying', { s: progress.elapsedS }) : progress?.status === 'queued' ? t('fix4.rules.mining.queued', { s: progress.elapsedS }) : t('fix4.rules.mining.running', { s: progress?.elapsedS ?? 0 })}
  </p>
{:else if mineError}
  <p class="callout warn" role="alert" data-testid="mine-error">{mineError}</p>
{/if}
{#if mining_status.data?.state === 'insufficient_data'}
  <p class="callout warn" role="status">{t('rules.insufficientLong', { n: mining_status.data.minHours, seen: fmtNum(Math.round(mining_status.data.observedHours * 60)) })}</p>
{:else if mining_status.data?.state === 'no_data'}
  <p class="callout warn" role="status">{t('rules.noData')}</p>
{:else if mining_status.data?.state === 'few_subjects'}
  <p class="callout warn" role="status">{t('rules.fewSubjects', { n: mining_status.data.subjects ?? 0, k: mining_status.data.kMin ?? 20 })} <a href={assistantLink}>{t('rules.mine.sampling')}</a></p>
{:else if mining_status.data?.warnings.length}
  <div class="callout warn" role="status">
    <b>{t('rules.warningsTitle')}</b>
    <details>
      <summary>{t('rules.why.tech')}</summary>
      <ul>{#each mining_status.data.warnings as w (w)}<li>{serverText(w)}</li>{/each}</ul>
    </details>
  </div>
{/if}

{#if mineResult}
  <section class="callout" class:ok={mineResult.newRules > 0} class:warn={mineResult.newRules === 0} aria-label={t('rules.mine.title')} role="status">
    <div class="row">
      <b>{t('rules.mine.title')}</b>
      <Button size="sm" variant="ghost" onclick={() => (mineResult = null)}>{t('rules.mine.close')}</Button>
    </div>
    <p>
      {mineResult.newRules > 0 ? t('rules.mine.found', { n: mineResult.newRules }) : t('rules.mine.none')}
      {#if mineResult.updatedRules > 0}{t('rules.mine.updated', { n: mineResult.updatedRules })}{/if}
      {t('rules.mine.events', { n: fmtNum(mineResult.events) })}
    </p>
    {#if mineResult.newRules === 0}
      <p>
        {#if mineResult.state === 'few_subjects'}
          {t('rules.mine.fewSubjects', { n: mineResult.subjects ?? 0, k: mineResult.kMin ?? 20 })} <a href={assistantLink}>{t('rules.mine.sampling')}</a>
        {:else if mineResult.state === 'insufficient_data'}
          {t('rules.insufficientLong', { n: mining_status.data?.minHours ?? 1, seen: fmtNum(Math.round((mining_status.data?.observedHours ?? 0) * 60)) })}
        {:else if mineResult.state === 'no_data' || mineResult.events === 0}
          {t('rules.mine.noData')}
        {:else}
          {t('rules.mine.other')}
        {/if}
      </p>
    {/if}
    {@render why()}
    {#if mineResult.reasons.length}
      <details>
        <summary>{t('rules.mine.reasons')}</summary>
        <ul>{#each mineResult.reasons as w (w)}<li>{serverText(w)}</li>{/each}</ul>
      </details>
    {/if}
  </section>
{:else if !mining && lastBox.length && lastRunAt}
  <section class="callout" class:warn={blocking.length > 0 || lastBox.some((d) => d.code === 'no_effect')} aria-label={t('rules.mine.title')} role="status" data-testid="last-why">
    <b>{t('fix4.rules.lastTitle', { time: fmtTime(lastRunAt) })}</b>
    {@render why()}
  </section>
{/if}

{#snippet why()}
  {#if explanations.length}
    <p class="whyhead">{t('rules.why.title')}</p>
    <ul class="why" data-testid="why">
      {#each explanations as d, i (i)}
        <li class:ok={d.code === 'mined'} class:info={d.code === 'reference'}>
          {#if d.code === 'no_effect' && (d.values === 'in_clear' || (d.values !== 'dropped' && facts.inClear))}
            <!-- the server says the object already has fields in clear (1.17.0), or the policy has code fields: no approval to ask for -->
            <span data-testid="no-effect-code">{t('fix5.rules.noEffectCode', { service: d.service || '—', op: d.op || '—', entity: d.entity || '—', fields: d.clearFields?.slice(0, 4).join(', ') || codeFields || '…' })}</span> <a href={bulkLink}>{t('fix5.rules.noEffectCodeLink')}</a>
          {:else if d.code === 'no_effect'}
            {t('fix4.rules.noEffect', { service: d.service || '—', op: d.op || '—', entity: d.entity || '—' })} <a href={bulkLink}>{t('fix4.rules.noEffectLink')}</a>
          {:else}
            {explain(d)}
          {/if}
          {#if needsAssistant(d)} <a href={assistantLink}>{t('rules.why.assistant')}</a>{/if}
        </li>
      {/each}
    </ul>
  {:else if mining_status.data?.state === 'ok' && scopeGroups()}
    <p>{t('rules.why.none')} <a href={assistantLink}>{t('rules.why.assistant')}</a></p>
  {/if}
{/snippet}

{#if mining_status.data && mining_status.data.state !== 'never_run'}
  <details class="cands" data-testid="candidates" open={candidates.length > 0 && candidates.length <= 3}>
    <summary><b>{t('w4.cand.heading', { n: candidates.length })}</b></summary>
    <p class="subtle">{t('w4.cand.intro', { k: kMinNow })}</p>
    {#if candidates.length}
      <ul class="clist">
        {#each candidates as c (c.signature + (c.group ?? ''))}
          <li>
            <div class="row spread">
              <div class="grow">
                <span class="row-tight"><Badge tone="info">{tk(`w4.cand.kind.${c.kind}`, undefined, c.kind)}</Badge>{#if c.group}<GroupTag group={c.group} always />{/if}<Badge tone="neutral" title={t('w4.cand.usersTip', { k: kMinNow })}>{t('w4.cand.users', { n: c.subjects })}</Badge></span>
                <b class="mono">{c.service} · {c.op}</b>
                <span class="subtle block">
                  {#if c.entity}{t('w4.cand.entity', { entity: c.entity })}{/if}
                  {#if c.fields?.length} · {t('w4.cand.fields', { fields: c.fields.join(', ') })}{/if}
                  {#if c.states?.length} · {t('w4.cand.states', { states: c.states.join(', ') })}{/if}
                  {#if c.status} · {t('w4.cand.status', { status: c.status })}{/if}
                  {#if c.target} · {t('w4.cand.target', { target: c.target })}{/if}
                </span>
                {#if c.template && c.template !== 'custom'}<span class="subtle block">{t('w4.cand.template', { name: tk(`w4.tpl.name.${c.template}`, undefined, c.template) })}</span>{/if}
                {#if c.missingEntities?.length}<span class="subtle block" data-testid="candidate-missing">{t('w4.cand.missing', { entities: c.missingEntities.join(', '), k: kMinNow })}</span>{/if}
              </div>
              <Button size="sm" icon="plus" denied={!can('rules.edit')} disabled={!!c.missingEntities?.length} title={c.missingEntities?.length ? t('w4.cand.missingTip') : undefined} onclick={() => draftFrom(c)} data-testid="candidate-draft">{t('w4.cand.create')}</Button>
            </div>
          </li>
        {/each}
      </ul>
      <p class="subtle">{t('w4.cand.createHint')}</p>
    {:else}
      <p class="subtle" data-testid="candidates-empty">{t('w4.cand.empty', { k: kMinNow })}</p>
    {/if}
  </details>
{/if}

<ScopeNote />
<div class="layout">
  <aside aria-label={t('rules.queue')}>
    <Card flush>
      <div class="chips" role="group" aria-label={t('rules.filter')}>
        {#each chipList as f (f)}
          <button type="button" class="chip" aria-pressed={filter === f} onclick={() => (filter = f as typeof filter)}>
            {f === 'all' ? t('rules.all') : tk(`status.${f}`)}{#if f !== 'all'}{' '}<small>{counts[f as RuleStatus] ?? 0}</small>{/if}
          </button>
        {/each}
      </div>
      {#if rules.data}
        <ul class="queue">
          {#each list as r (r.id)}
            <li>
              <a href={href('/rules/:id', { id: r.id })} aria-current={params.id === r.id ? 'page' : undefined}>
                <span class="row-tight spread"><code>{r.id}</code><StatusPill value={r.status} plain /></span>
                <span class="ttl">{r.title}</span>
                {#if r.groups}<span class="grp"><GroupTag group={r.groups} /></span>{/if}
                <span class="subtle">
                  {r.kind === 'batch' ? t('rules.batch') : t('rules.causal')}{#if r.origin === 'manual'} · {t('rules.origin.manual')}{/if}{#if r.proposedAt} · {fmtAgo(r.proposedAt)}{/if}
                  {#if r.kind === 'causal' && r.origin !== 'manual' && r.counts.causes < LOW_SUPPORT_MIN} · <span class="lowtag">{t('rules.lowSupport')}</span>{/if}
                </span>
              </a>
            </li>
          {:else}
            <li class="subtle pad">{t('rules.emptyQueue')}</li>
          {/each}
        </ul>
      {:else}
        <Loading error={rules.error} onretry={rules.reload} />
      {/if}
    </Card>
  </aside>

  <section class="detail">
    {#if !params.id}
      <Card><EmptyState icon="rules" title={t('rules.pick')} description={t('rules.pickHint')} /></Card>
    {:else if rule}
      <div class="stack">
        <Card>
          <div class="row spread">
            <div class="grow">
              <div class="row-tight"><code>{rule.id}</code><StatusPill value={rule.status} /><Badge tone="accent">{rule.kind === 'batch' ? t('rules.batch') : t('rules.causal')}</Badge>{#if rule.origin === 'manual'}<Badge tone="info" title={t('rules.originHint.manual')}>{t('rules.origin.manual')}</Badge>{/if}{#if rule.groups}<GroupTag group={rule.groups} always />{/if}</div>
              <h2 class="rt">{rule.title}</h2>
              <p class="subtle">{#if rule.proposedAt}{t('rules.proposed', { when: fmtDate(rule.proposedAt) })}{/if}{#if rule.supersedes}{' '}· {t('rules.supersedes', { id: rule.supersedes })}{/if}</p>
            </div>
            {#if rule.status !== 'rejected' && rule.status !== 'retired'}
              <Button icon="rules" denied={!can('rules.edit')} onclick={() => (editor = { open: true, rule })}>{t('rules.editDefinition')}</Button>
            {/if}
          </div>
          {#if rule.status === 'approved' && rule.failedRuns}
            <p class="callout warn stale" role="status"><b>{t('rules.watchTitle', { n: rule.failedRuns })}</b> {serverText(rule.staleReason)}</p>
          {/if}
          {#if rule.status === 'stale'}
            <p class="callout warn stale" role="status"><b>{t('rules.staleTitle')}</b> {serverText(rule.staleReason)}</p>
          {/if}
          {#if lowSupport}
            <p class="callout warn stale">{t('rules.lowSupportLong', { n: rule.counts.causes, min: LOW_SUPPORT_MIN })}</p>
          {/if}
          {#if ruleTestK(rule) !== undefined}
            <p class="callout warn stale" role="status" data-testid="rule-test-k"><b>{t('w4.testk.badge', { k: ruleTestK(rule) ?? 0 })}</b> {t('w4.testk.rule', { k: ruleTestK(rule) ?? 0, kMin: kMinNow })}</p>
          {/if}
        </Card>

        <!-- evidence: counts vs hints -->
        <div class="grid-2">
          <Card title={t('rules.counts')} subtitle={t('rules.countsHint')} tone="accent">
            {#snippet actions()}<InfoTip id="rules.counts" />{/snippet}
            <div class="facts">
              {#if rule.kind === 'causal'}
                <div class="stat"><b>{fmtNum(rule.counts.causes)}</b><span>{t('rules.ev.causes')}</span></div>
                <div class="stat"><b>{fmtNum(rule.counts.distinctSubjects)}</b><span>{t('rules.ev.subjects')}</span></div>
                <div class="stat"><b>{fmtNum(rule.counts.keyMatches)}</b><span>{t('rules.ev.keys')}</span></div>
              {:else if rule.batch}
                <div class="stat"><b>{rule.batch.runs}</b><span>{t('rules.ev.runs')}</span></div>
                <div class="stat"><b>{fmtNum(rule.batch.entitiesChanged)}</b><span>{t('rules.ev.changed')}</span></div>
              {/if}
            </div>
          </Card>
          <section class="hints" aria-label={t('rules.hints')}>
            <h2 class="fs-3">~ {t('rules.hints')} <InfoTip id="rules.hints" /></h2>
            <p class="subtle">{t('rules.hintsHint')}</p>
            <ul>
              {#each Object.entries(rule.hints.magnitude) as [eid, m] (eid)}
                <li><code>{eid}</code> ≈ {tk(`magnitude.${m}`, undefined, m)}</li>
              {/each}
              {#if rule.hints.scheduleConfidence}<li>{t('rules.ev.schedule')}: ≈ {rule.hints.scheduleConfidence}</li>{/if}
            </ul>
          </section>
        </div>

        {#if rule.kind === 'causal' && rule.cause}
          <Card title={t('rules.chain')} subtitle={t('rules.chainHint')}>
            <ol class="chain">
              <li class="node cause">
                <span class="tag">{t('rules.cause')}</span>
                <b>{rule.cause.op}</b>
                <span class="subtle">{rule.cause.service} · {t('rules.whenStatus')} {rule.cause.whenStatus.join(', ')}</span>
                <span class="subtle mono">{Object.entries(rule.cause.bind).map(([k, v]) => `${k} ← ${v}`).join(' · ')}</span>
                {#if rule.cause.match?.length}<span class="cond" data-testid="cause-conditions">{t('w4.rules.if', { cond: matchesText(rule.cause.match) })}</span>{/if}
              </li>
              {#each rule.effects as e (e.id)}
                <li class="link" aria-hidden="true"><Icon name="down" size={18} /></li>
                <li class="node effect">
                  {#if e.kind === 'respond' && e.respond}
                    <span class="tag">{t('rules.effect')} · {e.respond.service}</span>
                    <b>{e.respond.until ? t('w4.rules.untilTitle', { status: e.respond.status, op: e.respond.op }) : t('rules.responds', { status: e.respond.status, op: e.respond.op })}</b>
                    {#if e.respond.until}
                    <span class="subtle" data-testid="effect-until">{t('w4.rules.until', { status: e.respond.status, op: e.respond.op, cause: rule.cause.op })}</span>
                    {:else if e.respond.limit}
                    <span class="subtle">{limitNote(e.respond.status, e.respond.limit, rule.cause.bind)}</span>
                    {:else}
                    <span class="subtle">{t('rules.respondsDetail', { service: e.respond.service, calls: e.respond.times === 1 ? t('re.pv.calls.one') : e.respond.times ? t('re.pv.calls.n', { n: e.respond.times }) : t('re.pv.calls.all'), freq: fmtPct(e.respond.p ?? 1, 0) })}</span>
                    {/if}
                  {:else if e.kind === 'remove'}
                    <span class="tag">{t('rules.effect')} · {e.entity}</span>
                    <b>{t('w1.rules.removes', { entity: e.entity })}</b>
                    {#if e.targetKey}<span class="subtle">{keyNote(e.entity, e.targetKey)}</span>{/if}
                    {#if e.targetAll}<span class="subtle" data-testid="effect-all">{effectAll(e)}</span>{/if}
                  {:else}
                  <span class="tag">{t('rules.effect')} · {e.entity}</span>
                  <b>{e.kind === 'create' ? t('rules.creates') : t('rules.sets')} <code>{kindLabel(e.kind, e.values)}</code></b>
                  {#each valueNotes(e.values, rule.cause.bind) as n (n)}<span class="subtle">{n}</span>{/each}
                  {#if e.targetAll}
                    <span class="subtle" data-testid="effect-all">{effectAll(e)}</span>
                  {:else if e.where}<span class="subtle">{t('w2.rules.where', { entity: e.entity, cond: kindLabel('', e.where) })}</span>{/if}
                  {#if e.targetKey}<span class="subtle">{keyNote(e.entity, e.targetKey)}</span>{/if}
                  {/if}
                  <span class="subtle mono">{e.id}{#if e.target} → {e.target}{/if}</span>
                  <div class="after">
                    <span class="row-tight"><label for="af-{e.id}">{t('rules.after', { from: parentLabel(e) })}</label><InfoTip id="rules.after" /></span>
                    <div class="row-tight">
                      <input
                        id="af-{e.id}"
                        class="afin"
                        value={edits[e.id] ?? e.after}
                        disabled={!editable || !can('rules.edit')}
                        oninput={(ev) => (edits[e.id] = ev.currentTarget.value)}
                        aria-invalid={parseAfter(edits[e.id] ?? e.after) === null ? 'true' : undefined}
                        aria-describedby="afh-{e.id}"
                      />
                      <Button size="sm" denied={!can('rules.edit')} disabled={!editable || edits[e.id] === undefined || parseAfter(edits[e.id]) === null} onclick={() => saveAfter(e)}>{t('common.save')}</Button>
                      <Badge tone="info" title={t('rules.figurative')}>{t('rules.figurativeShort')}</Badge>
                    </div>
                    <span id="afh-{e.id}" class="subtle">{fmtAfter(edits[e.id] ?? e.after) + (e.magnitude ? ' · ≈ ' + tk(`magnitude.${e.magnitude}`, undefined, e.magnitude) : '')}</span>
                  </div>
                </li>
              {/each}
            </ol>
          </Card>

          <Card title={t('rules.outcomes')} subtitle={t('rules.outcomesHint')}>
            {#snippet actions()}<InfoTip id="rules.outcome" />{/snippet}
            <div class="table-wrap" use:scrollable><table class="data">
              <thead><tr><th scope="col">{t('rules.out.name')}</th><th scope="col">{t('rules.out.p')}</th><th scope="col" class="r">{t('rules.out.count')}</th><th scope="col">{t('rules.out.effects')}</th></tr></thead>
              <tbody>
                {#each rule.outcomes as o (o.name)}
                  <tr>
                    <td><b>{o.name}</b>{#if o.when?.length}<span class="subtle block">{t('w4.rules.outWhen', { cond: matchesText(o.when) })}</span>{:else if rule.outcomes.some((x) => x.when?.length)}<span class="subtle block">{t('w4.rules.outOtherwise')}</span>{/if}</td>
                    <td class="bar"><ProgressBar value={o.p} label={t('rules.out.pOf', { name: o.name })} tone={o.name === 'happy' ? 'success' : 'warning'} /></td>
                    <td class="r num">{fmtNum(o.count)}</td>
                    <td>{#each o.effects as ef (ef)}<span class="eff mono">{effectName(rule, ef)}</span>{:else}<span class="subtle">{t('rules.out.none')}</span>{/each}</td>
                  </tr>
                {/each}
              </tbody>
            </table></div>
            <p class="subtle sum" class:bad={Math.abs(pSum - 1) > 0.001}>{t('rules.out.sum', { p: fmtPct(pSum, 1) })}</p>
          </Card>
        {:else if rule.batch}
          <Card title={t('rules.batchTitle')}>
            <dl class="kv">
              <div><dt>{t('rules.b.schedule')}</dt><dd class="mono">{rule.batch.schedule} <span class="subtle">UTC</span></dd></div>
              <div><dt>{t('rules.b.entity')}</dt><dd>{rule.batch.entity}</dd></div>
              <div><dt>{t('rules.b.where')}</dt><dd class="mono">{kindLabel('', rule.batch.where)}</dd></div>
              <div><dt>{t('rules.b.set')}</dt><dd class="mono">{kindLabel('', rule.batch.set)}</dd></div>
              <div><dt>{t('rules.b.fraction')}</dt><dd><ProgressBar value={rule.batch.fraction} label={t('rules.b.fraction')} /></dd></div>
            </dl>
          </Card>
        {/if}

        <Card title={t('rules.review')}>
          <div class="stack">
            {#if rule.review.at}
              <p class="subtle">{t('rules.reviewedBy', { who: rule.review.by.join(', '), when: fmtDate(rule.review.at) })}{#if rule.review.note} — “{rule.review.note}”{/if}</p>
            {/if}
            {#if rule.status === 'draft' || rule.status === 'stale'}
              <div class="stack-sm">
                <label for="rv-note">{t('rules.note')}</label>
                <textarea id="rv-note" bind:value={note} rows="2" disabled={!can('rules.review')}></textarea>
              </div>
              <div class="row">
                {#if rule.status === 'draft'}
                  <Button variant="primary" icon="check" denied={!can('rules.review')} onclick={() => review('approve')}>{t('rules.approve')}</Button>
                  <Button variant="danger" icon="close" denied={!can('rules.review')} onclick={() => review('reject')}>{t('rules.reject')}</Button>
                {:else}
                  <Button variant="primary" icon="check" denied={!can('rules.review')} onclick={() => review('confirm')}>{t('rules.confirm')}</Button>
                  <Button variant="danger" icon="close" denied={!can('rules.review')} onclick={() => review('retire')}>{t('rules.retire')}</Button>
                {/if}
              </div>
              {#if !can('rules.review')}<p class="subtle">{t('rules.needRole', { user: session.user?.username ?? '' })}</p>{/if}
            {:else if rule.status === 'approved'}
              <p class="muted">{t('rules.lockedApproved')}</p>
              <RetireRule {rule} replacedBy={replacement} onchange={() => rules.reload()} />
            {:else if rule.status === 'retired'}
              <p class="muted" data-testid="rule-retired">{rule.supersededBy ? t('fix5.rr.supersededBy', { id: rule.supersededBy }) : t('fix5.rr.retired')}</p>
            {:else}
              <p class="muted">{t('rules.lockedRejected')}</p>
            {/if}
          </div>
        </Card>
      </div>
    {:else if rules.data}
      <Card><EmptyState icon="alert" title={t('rules.notFound')} /></Card>
    {:else}
      <Loading error={rules.error} />
    {/if}
  </section>
</div>

<Drawer bind:open={editor.open} title={editor.rule ? t('re.edit', { id: editor.rule.id }) : t('re.new')} onclose={() => (editor = { open: false })}>
  {#if editor.open}
    {#key editor.rule?.id ?? 'new'}
      <RuleEditor rule={editor.rule} initial={editor.initial} template={editor.template} onsaved={edited} oncancel={() => (editor = { open: false })} />
    {/key}
  {/if}
</Drawer>

<style>
  .lastrun { margin: 0 0 var(--s-2); }
  .cands { border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); margin-bottom: var(--s-3); background: var(--surface); }
  .cands summary { cursor: pointer; }
  .clist { list-style: none; margin: var(--s-2) 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .clist li { border-top: 1px solid var(--border); padding-top: var(--s-2); }
  .block { display: block; }
  .cond { font-weight: 600; color: var(--accent); }
  .whyhead { margin: var(--s-2) 0 var(--s-1); font-weight: 600; }
  .why { margin: 0; padding-left: 1.1rem; display: flex; flex-direction: column; gap: var(--s-1); }
  .why li.ok { color: var(--success); }
  .why li.info { color: var(--fg-muted); }
  .layout { display: grid; grid-template-columns: minmax(15rem, 21rem) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  aside { position: sticky; top: calc(var(--header-h) + var(--s-4)); max-height: calc(100dvh - var(--header-h) - 2rem); overflow: auto; border-radius: var(--r-md); }
  .chips { display: flex; flex-wrap: wrap; gap: var(--s-1); padding: var(--s-3); border-bottom: 1px solid var(--border); }
  .chip { font: inherit; font-size: 0.82rem; font-weight: 600; border: 1px solid var(--border-strong); border-radius: 999px; background: var(--surface); color: var(--fg-muted); padding: 0.15rem 0.6rem; cursor: pointer; }
  .chip small { margin-left: 2px; }
  .chip[aria-pressed='true'] { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .queue { list-style: none; margin: 0; padding: 0; }
  .queue a { display: flex; flex-direction: column; gap: 2px; padding: var(--s-3) var(--s-4); border-bottom: 1px solid var(--border); text-decoration: none; color: var(--fg); }
  .queue a:hover { background: var(--surface-2); }
  .queue a[aria-current='page'] { background: var(--accent-soft); }
  .ttl { font-weight: 560; }
  .lowtag { color: var(--warning); font-weight: 650; }
  .pad { padding: var(--s-4); }
  .rt { margin: var(--s-2) 0 var(--s-1); }
  .stale { margin-top: var(--s-3); }
  .facts { display: flex; gap: var(--s-6); flex-wrap: wrap; }
  .hints { border: 2px dashed var(--border-strong); border-radius: var(--r-md); padding: var(--s-4); background: var(--surface-2); font-style: italic; }
  .hints h2 { font-style: normal; color: var(--fg-muted); }
  .hints ul { margin: var(--s-2) 0 0; padding-left: 1.1rem; }
  .chain { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; align-items: stretch; }
  .link { display: grid; place-items: center; color: var(--fg-subtle); height: 1.6rem; }
  .node { display: flex; flex-direction: column; gap: 3px; border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); background: var(--surface); }
  .cause { border-left: 5px solid var(--accent); }
  .effect { border-left: 5px solid var(--success); }
  .tag { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 700; color: var(--fg-subtle); }
  .after { margin-top: var(--s-2); padding-top: var(--s-2); border-top: 1px dashed var(--border-strong); display: flex; flex-direction: column; gap: 4px; }
  .afin { width: 6rem; min-height: 2rem; padding-block: 0.25rem; font-family: var(--font-mono); }
  .r { text-align: right !important; }
  .bar { min-width: 9rem; }
  .eff { display: inline-block; background: var(--surface-3); border-radius: 4px; padding: 0 0.35rem; margin: 0 4px 2px 0; font-size: 0.78rem; }
  .sum { margin-top: var(--s-2); }
  .sum.bad { color: var(--danger); }
  .kv { margin: 0; display: grid; gap: var(--s-3); }
  .kv dt { font-size: 0.78rem; color: var(--fg-subtle); text-transform: uppercase; font-weight: 600; }
  .kv dd { margin: 0; }
  @media (max-width: 960px) { .layout { grid-template-columns: minmax(0, 1fr); } aside { position: static; max-height: 20rem; } }
</style>
