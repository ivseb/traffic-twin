<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Drawer from '../components/Drawer.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import Badge from '../components/Badge.svelte';
  import Sparkline from '../components/Sparkline.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import DiffView from '../components/DiffView.svelte';
  import Loading from '../components/Loading.svelte';
  import Modal from '../components/Modal.svelte';
  import Field from '../components/Field.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import NewHostsHint from '../components/NewHostsHint.svelte';
  import ApprovalNotice from '../components/ApprovalNotice.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { inGroups, myGroups, scopeGroups, showGroupColumn } from '../lib/scope.svelte';
  import ApproverHelp from '../components/ApproverHelp.svelte';
  import WithdrawDraft from '../components/WithdrawDraft.svelte';
  import BulkReview from '../components/BulkReview.svelte';
  import IdentityControl from '../components/IdentityControl.svelte';
  import GroupDomainsTestK from '../components/GroupDomainsTestK.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { PolicyVersion, Source } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, session, stepUpDone, toast, toastError } from '../lib/stores.svelte';
  import { healthCounts, sourceHealth } from '../lib/health';
  import { fmtAgo, fmtDate, fmtNum, fmtPct, fmtRate } from '../lib/format';
  import { queryTab } from '../lib/tabs.svelte';
  import { href } from '../lib/router';
  import { loc } from '../lib/router.svelte';

  const sources = resource(() => api.sources.list());
  // Group/Team filter: the sources of the chosen groups (each source belongs to one group) and, from the server, only
  // the versions of the policies serving those groups.
  const shownSources = $derived((sources.data ?? []).filter((s) => inGroups(s.group)));
  const hiddenSources = $derived((sources.data?.length ?? 0) - shownSources.length);
  const policies = resource(() => api.policies.list(scopeGroups()));
  // The user's own groups first (tokens created, policies proposed), then the newest version.
  const mineRank = (p: PolicyVersion) => ((p.groups ?? []).some((g) => myGroups().includes(g)) ? 0 : 1);
  const policyRows = $derived([...(policies.data ?? [])].sort((a, b) => mineRank(a) - mineRank(b) || b.version - a.version));
  /** Approving is offered only for the policies inside the filter (a row of another team never gets the button). */
  const approvable = (p: PolicyVersion) => inGroups(p.groups ?? []);
  const settings = resource(() => api.settings.get());
  let selection = $state<string[]>([]);
  // A policy approved after an OIDC step-up (App resumes the call): show the new state.
  $effect(() => {
    if (stepUpDone.tick) policies.reload();
  });
  let overrideTarget = $state<PolicyVersion | null>(null);
  let overrideOpen = $state(false);
  let overrideReason = $state('');
  // An admin (without the approver role) can approve alone, with a mandatory reason.
  // An admin approves as the admin override (alone, with a reason), also
  // when it holds policy-approver: admin implies every role.
  const adminOnly = $derived(can('override.admin'));

  const tabs = queryTab('sources', ['sources', 'policy']);
  // «Rivedi in blocco» (policy.md §7): the groups of the policies in the filter.
  let bulkOpen = $state(false);
  // «Identità dell'utente» (policy.md §7.4): who the user is, per group with an active policy.
  let identityOpen = $state(false);
  // Rules v1.9: HMAC domains to join and the lower k of a test group.
  let domainsOpen = $state(false);
  // A link «Rivedi in blocco» (?bulk=1, from the rule editor or the miner's result): opens the panel once the policies are known.
  let bulkFromLink = false;
  $effect(() => {
    if (bulkFromLink || loc.query.bulk !== '1' || !policies.data) return;
    bulkFromLink = true;
    tabs.value = 'policy';
    bulkOpen = true;
  });
  const bulkGroups = $derived([...new Set((policies.data ?? []).filter((p) => p.status === 'active' && approvable(p)).flatMap((p) => p.groups ?? []))].sort());

  let selectedId = $state<string | null>(null);
  let drawer = $state(false);
  const selected = $derived(sources.data?.find((s) => s.id === selectedId) ?? null);
  let sampling = $state(0);
  let confirmKill = $state(false);
  let confirmRevoke = $state(false);
  let confirmAll = $state(false);
  let policyDrawer = $state(false);
  let policySelKey = $state<string | null>(null);
  const policySel = $derived(policySelKey ? ((policies.data ?? []).find((x) => `${x.policyId}@${x.version}` === policySelKey) ?? null) : null);

  const now = Date.now();
  const counts = $derived(healthCounts(shownSources, now));
  const totalEvents = $derived(shownSources.filter((s) => !s.revoked).reduce((a, s) => a + s.eventsPerMin, 0));

  function open(s: Source): void {
    selectedId = s.id;
    sampling = s.samplingBp;
    drawer = true;
  }

  const cols: Column<Source>[] = $derived([
    { key: 'serviceName', label: t('src.col.source'), sortable: true },
    { key: 'health', label: t('src.col.health'), sortable: true, help: 'src.health', value: (s) => sourceHealth(s, now) },
    { key: 'policy', label: t('src.col.policy'), hideBelow: 'md', help: 'src.policy', value: (s) => (s.policy ? `${s.policy.id}@${s.policy.version}` : '') },
    { key: 'lastSeen', label: t('src.col.lastSeen'), sortable: true, hideBelow: 'sm', help: 'src.lastSeen', value: (s) => -new Date(s.lastSeen).getTime() },
    { key: 'eventsPerMin', label: t('src.col.events'), sortable: true, align: 'end', help: 'src.events' },
    { key: 'dropRatio', label: t('src.col.dropped'), sortable: true, align: 'end', hideBelow: 'md', help: 'src.dropped' },
    { key: 'overhead', label: t('src.col.overhead'), align: 'end', hideBelow: 'md', help: 'src.overhead', value: (s) => s.overheadUs?.p50 ?? 0 },
  ]);

  async function act<T>(fn: () => Promise<T>, okMsg: string): Promise<void> {
    try {
      await fn();
      toast(okMsg);
      sources.reload();
    } catch (e) {
      toastError(e);
    }
  }

  async function saveSampling(): Promise<void> {
    if (selected) await act(() => api.sources.setSampling(selected.id, sampling), t('src.samplingSaved'));
  }
  async function toggleKill(): Promise<void> {
    if (selected) await act(() => api.sources.kill({ sourceId: selected.id }, !selected.killed), selected.killed ? t('src.resumed') : t('src.killed'));
  }
  async function revoke(): Promise<void> {
    if (selected) await act(() => api.sources.revoke(selected.id), t('src.revoked'));
  }
  const killAll = () => act(() => api.sources.kill({ all: true }, true), t('src.killedAll'));

  // ---------- policies
  // A link to a draft («Copia il link alla bozza» of the wizard): #/sources?tab=policy&draft=<policy>@<version> opens its panel.
  let draftOpened = '';
  $effect(() => {
    const d = loc.query.draft;
    if (!d || d === draftOpened || !policies.data?.some((x) => `${x.policyId}@${x.version}` === d)) return;
    draftOpened = d;
    policySelKey = d;
    policyDrawer = true;
  });
  const polCols: Column<PolicyVersion>[] = $derived([
    { key: 'version', label: t('pol.col.version'), sortable: true, value: (p) => p.version },
    ...(showGroupColumn() ? [{ key: 'groups', label: t('scope.col.group'), sortable: true, value: (p: PolicyVersion) => (p.groups ?? []).join(',') }] : []),
    { key: 'status', label: t('pol.col.status'), sortable: true, help: 'pol.status' },
    { key: 'proposedBy', label: t('pol.col.by'), hideBelow: 'sm' },
    { key: 'opens', label: t('pol.col.opens'), hideBelow: 'sm', help: 'pol.opens' },
    { key: 'approvals', label: t('pol.col.approvals'), help: 'pol.approvals' },
    { key: 'act', label: '' },
  ]);

  function approveBlock(p: PolicyVersion): string | null {
    // The server names people by display name (local users: the same as the username).
    const mine = (n?: string) => !!n && (n === session.user?.username || n === session.user?.displayName);
    if (p.status !== 'draft') return t('pol.notDraft');
    // OIDC: an own approval whose ID token expired is renewed (same endpoint), not blocked.
    if (p.approvals.some((a) => mine(a.by) && a.tokenFresh !== false)) return t('pol.alreadyApproved');
    if (!adminOnly && p.approvalsRequired === 2 && mine(p.proposedBy)) return t('pol.selfBlocked');
    return null;
  }
  async function bulkKill(ids: string[]): Promise<void> {
    try {
      for (const id of ids) await api.sources.kill({ sourceId: id }, true);
      toast(t('src.killedN', { n: ids.length }));
      selection = [];
      sources.reload();
    } catch (e) {
      toastError(e);
    }
  }
  /** The current user's own approval must be renewed (its identity check expired). */
  function mustRenew(p: PolicyVersion): boolean {
    const mine = (n?: string) => !!n && (n === session.user?.username || n === session.user?.displayName);
    return p.status === 'draft' && p.approvals.some((a) => mine(a.by) && a.tokenFresh === false);
  }
  async function approve(p: PolicyVersion, reason?: string): Promise<void> {
    try {
      const r = await api.policies.approve(p.policyId, p.version, reason);
      toast(r.status === 'active' ? t('pol.activated', { v: r.version }) : t('pol.approved'));
      policies.reload();
    } catch (e) {
      toastError(e);
    }
  }
</script>

<PageHeader title={t('src.title')} description={t('src.desc')} help="sources" breadcrumbs={[{ label: t('nav.sources') }]} updatedAt={sources.updatedAt} onrefresh={() => { sources.reload(); policies.reload(); }} refreshing={sources.loading}>
  {#snippet actions()}
    <Button href="#/onboarding" variant="primary" icon="plus">{t('src.add')}</Button>
    <Button variant="danger" icon="power" denied={!can('sources.kill')} onclick={() => (confirmAll = true)}>{t('src.killAll')}</Button>
  {/snippet}
</PageHeader>

<NewHostsHint />

<Tabs tabs={[{ id: 'sources', label: t('src.tab.sources'), count: sources.data ? shownSources.length : undefined }, { id: 'policy', label: t('src.tab.policy'), count: policies.data?.filter((p) => p.status === 'draft' && approvable(p)).length, countLabel: t('fix4.src.draftsBadge') }]} bind:value={tabs.value} label={t('src.title')}>
  {#if tabs.value === 'sources'}
    {#if sources.data}
      <ScopeNote hidden={hiddenSources} />
      <div class="grid tiles">
        <Card><div class="stat"><b>{counts.healthy}</b><span><StatusPill value="healthy" /></span></div></Card>
        <Card><div class="stat"><b>{counts.degraded + counts.offline}</b><span>{t('src.tile.attention')}</span>{#if counts.waiting}<span class="subtle">{t('src.tile.waiting', { n: counts.waiting })}</span>{/if}</div></Card>
        <Card><div class="stat"><b>{counts.killed + counts.revoked}</b><span>{t('src.tile.stopped')}</span></div></Card>
        <Card><div class="stat"><b>{fmtRate(totalEvents)}</b><span>{t('src.tile.events')}</span></div></Card>
      </div>
      <div class="gap"></div>
      <Card flush>
        {#if shownSources.length === 0}
          <EmptyState icon="sources" title={t('src.empty')} description={t('src.emptyHint')}>
            <Button variant="primary" href="#/onboarding">{t('src.add')}</Button>
          </EmptyState>
        {:else}
          <Table rows={shownSources} columns={cols} rowKey={(s) => s.id} caption={t('src.title')} searchText={(s) => `${s.serviceName} ${s.group} ${s.kind} ${s.instance}`} onrowclick={open} selectedKey={selectedId ?? undefined} urlKey="src" selectable bind:selection>
            {#snippet bulk(ids)}
              <Button size="sm" variant="danger" icon="power" denied={!can('sources.kill')} onclick={() => bulkKill(ids)}>{t('src.bulkKill')}</Button>
            {/snippet}
            {#snippet cell(s, col)}
              {#if col.key === 'serviceName'}
                <button type="button" class="link-btn name" onclick={(e) => { e.stopPropagation(); open(s); }}>{s.serviceName}</button>
                <div class="subtle">{s.kind} {s.version} · {s.instances > 1 ? t('src.instances', { n: s.instances }) : s.instance}
                  {#if s.updateAvailable} <Badge tone="info">{t('src.update')}</Badge>{/if}</div>
              {:else if col.key === 'health'}
                <StatusPill value={sourceHealth(s, now)} />
              {:else if col.key === 'policy'}
                {#if s.policy}<span class="mono nowrap">{s.policy.id} v{s.policy.version}</span>{:else}—{/if}
              {:else if col.key === 'lastSeen'}
                <span class="nowrap">{fmtAgo(s.lastSeen)}</span>
              {:else if col.key === 'eventsPerMin'}
                <div class="evt"><span class="num">{fmtRate(s.eventsPerMin)}</span>
                  <Sparkline values={s.series} width={72} height={20} label={t('src.sparkLabel', { name: s.serviceName })} tone={sourceHealth(s, now) === 'healthy' ? 'accent' : 'warning'} /></div>
              {:else if col.key === 'dropRatio'}
                <span class="num">{fmtPct(s.dropRatio, 1)}</span>
              {:else}
                <span class="num">{s.overheadUs ? `+${(s.overheadUs.p50 / 1000).toFixed(1)} ms` : '—'}</span>
              {/if}
            {/snippet}
          </Table>
        {/if}
      </Card>
    {:else}
      <Loading error={sources.error} onretry={sources.reload} />
    {/if}
  {:else if policies.data}
    <div class="stack">
      <ScopeNote />
      <p class="callout">{t('pol.intro')} <InfoTip id="set.approvals" /></p>
      <ApprovalNotice approvals={settings.data?.approvals} />
      {#if settings.data?.approvals.openingRequired === 1}
        <p class="callout warn" role="alert"><b>{t('pol.singleTitle')}</b> {t('pol.singleWarn')}</p>
      {/if}
      {#if adminOnly}<p class="callout warn">{t('pol.adminHint')} <InfoTip id="set.adminOverride" /></p>{/if}
      <div class="row bulkbar">
        <Button icon="check" denied={!can('policy.propose')} disabled={bulkGroups.length === 0} onclick={() => (bulkOpen = true)}>{t('obs.bulk.button')}</Button>
        <span class="subtle grow">{t('obs.bulk.intro')} <InfoTip id="obs.classify" /></span>
      </div>
      <div class="row bulkbar">
        <Button icon="user" disabled={bulkGroups.length === 0} onclick={() => (identityOpen = true)}>{t('id.open')}</Button>
        <span class="subtle grow">{t('id.openHint')} <InfoTip id="obs.identity" /></span>
      </div>
      <div class="row bulkbar">
        <Button icon="settings" disabled={bulkGroups.length === 0} onclick={() => (domainsOpen = true)} data-testid="open-group-domains">{t('w4.grp.open')}</Button>
        <span class="subtle grow">{t('w4.grp.openHint')}</span>
      </div>
      <Card flush>
        <Table rows={policyRows} columns={polCols} rowKey={(p) => `${p.policyId}@${p.version}`} caption={t('src.tab.policy')} urlKey="pol">
          {#snippet cell(p, col)}
            {#if col.key === 'version'}
              <button type="button" class="link-btn name" onclick={() => { policySelKey = `${p.policyId}@${p.version}`; policyDrawer = true; }}>{p.policyId} v{p.version}</button>
              {#if p.origin === 'host-twin'}<div><Badge tone="info" title={t('pol.origin.host-twin.tip')}>{t('pol.origin.host-twin')}</Badge></div>{/if}
              {#if p.origin === 'starter'}<div><Badge tone="info" title={t('pol.origin.starter.tip')}>{t('pol.origin.starter')}</Badge></div>{/if}
              {#if p.origin === 'observe-auto'}<div><Badge tone="info" title={t('obs.listen.masked', { at: fmtDate(p.proposedAt ?? ''), v: p.version })}>{t('obs.origin.observe-auto')}</Badge></div>{/if}
              {#if p.status === 'active' && can('policy.propose')}
                {#each p.groups ?? [] as g (g)}<div><a href={href('/onboarding', {}, { group: g, step: '4' })}>{t('pol.assistant', { group: g })}</a></div>{/each}
              {/if}
            {:else if col.key === 'groups'}
              <GroupTag group={p.groups ?? []} always />
            {:else if col.key === 'status'}
              <StatusPill value={p.status} />
            {:else if col.key === 'proposedBy'}
              {p.proposedBy ?? '—'}
            {:else if col.key === 'opens'}
              {#if p.opensValues}<Badge tone="warning" title={p.valueReasons.map((r) => tk(`obs.reason.${r.code}`, undefined, r.code)).join(' · ')}>{t('obs.badge.opens')}</Badge>{:else}<Badge tone="success">{t('obs.badge.safe')}</Badge>{/if}
              {#if p.origin === 'starter'}<div><Badge tone="info" title={t('pol.origin.starter.tip')}>{t('pol.starterDiscovery')}</Badge></div>{/if}
            {:else if col.key === 'approvals' && p.approvalsRequired === 0}
              <span class="subtle">{t('obs.mode.observe')}</span>
              {#if p.status === 'draft' && approvable(p)}{@render approveBtn(p)}{/if}
            {:else if col.key === 'approvals'}
              <span class="num">{p.approvals.length}/{p.approvalsRequired}</span>
              {#each p.approvals as a (a.by)}
                <div class="subtle">{a.by}{#if a.mode === 'admin'} <Badge tone="warning" title={a.reason}>{t('pol.adminBadge')}</Badge>{/if}{#if a.tokenFresh === false} <Badge tone="warning" title={t('pol.tokenExpired')}>{t('pol.tokenExpiredShort')}</Badge>{/if}</div>
              {/each}
            {:else if p.status === 'draft' && !approvable(p)}
              <span class="subtle">{t('pol.otherGroup')}</span>
            {:else if p.status === 'draft'}
              {@render approveBtn(p)}
            {/if}
          {/snippet}
        </Table>
      </Card>
    </div>
  {:else}
    <Loading error={policies.error} onretry={policies.reload} />
  {/if}
</Tabs>

<Drawer bind:open={drawer} title={selected ? selected.serviceName : ''}>
  {#if selected}
    {@const h = sourceHealth(selected, now)}
    <div class="stack">
      <div class="row"><StatusPill value={h} /><span class="subtle mono">{selected.id}</span></div>
      <KeyValue
        cols={2}
        items={[
          { k: t('src.d.kind'), v: `${selected.kind} ${selected.version}` },
          { k: t('src.d.group'), v: selected.group },
          { k: t('src.d.instance'), v: selected.instance },
          { k: t('src.d.policy'), v: selected.policy ? `${selected.policy.id} v${selected.policy.version}` : '—' },
          { k: t('src.d.lastSeen'), v: fmtAgo(selected.lastSeen) },
          { k: t('src.d.state'), v: tk(`state.${selected.state}`, undefined, selected.state) },
        ]}
      />
      <Sparkline values={selected.series} width={420} height={56} label={t('src.sparkLabel', { name: selected.serviceName })} />
      {#each selected.problems as p (p.code)}
        <div class="callout {p.code === 'no_policy' && h === 'waiting' ? 'note' : 'warn'}" role={h === 'waiting' ? 'status' : 'alert'}><b>{p.message}</b>{#if p.hint}<div class="subtle">{p.hint}</div>{/if}
          {#if p.code === 'key_missing' || p.code === 'key_mismatch' || p.code === 'hmac_kid_unknown'}<div><a href="#/help/hmac-keys">{t('hmac.link')}</a></div>{/if}
          {#if p.code === 'no_policy'}<div><button type="button" class="link-btn" onclick={() => { drawer = false; tabs.value = 'policy'; }}>{t('src.d.toPolicy')}</button></div>{/if}
        </div>
      {/each}
      {#if selected.lastErrors.length}
        <div>
          <h3 class="fs-4">{t('src.d.errors')}</h3>
          <ul class="errs">{#each selected.lastErrors as e, i (i)}<li><code>{e.code}</code> <span class="subtle">{#if e.count}×{e.count} · {/if}{#if e.firstSeen && e.count && e.count > 1}{fmtDate(e.firstSeen)} → {/if}{fmtDate(e.at)}{#if e.code.startsWith('intake_rejected:')} · {t('src.d.rejectedByIntake')}{/if}</span></li>{/each}</ul>
        </div>
      {/if}
      <div class="stack-sm">
        <label for="smp">{t('src.d.sampling')}</label>
        <div class="row">
          <input id="smp" type="range" min="0" max={selected.policyRateBp} step="25" bind:value={sampling} disabled={!can('sources.manage')} aria-valuetext={fmtPct(sampling / 10000, 2)} />
          <b class="num">{fmtPct(sampling / 10000, 2)}</b>
        </div>
        <p class="subtle">{t('src.d.samplingHint', { rate: fmtPct(selected.policyRateBp / 10000, 2) })}</p>
        <p class="subtle">{selected.samplingBp < selected.policyRateBp ? t('src.d.samplingOverride', { policy: fmtPct(selected.policyRateBp / 10000, 2), eff: fmtPct(selected.samplingBp / 10000, 2) }) : t('src.d.samplingPolicy', { policy: fmtPct(selected.policyRateBp / 10000, 2) })}</p>
        <div><Button size="sm" denied={!can('sources.manage')} disabled={sampling === selected.samplingBp} onclick={saveSampling}>{t('common.save')}</Button></div>
      </div>
    </div>
  {/if}
  {#snippet footer()}
    {#if selected}
      <Button variant="danger" denied={!can('sources.manage')} disabled={selected.revoked} onclick={() => (confirmRevoke = true)} icon="trash">{t('src.revoke')}</Button>
      <Button denied={!can('sources.kill')} disabled={selected.revoked} onclick={() => (selected.killed ? toggleKill() : (confirmKill = true))} icon={selected.killed ? 'onboarding' : 'power'}>
        {selected.killed ? t('src.resume') : t('src.kill')}
      </Button>
    {/if}
  {/snippet}
</Drawer>

{#snippet approveBtn(p: PolicyVersion)}
  {@const block = approveBlock(p)}
  {#if adminOnly}
    <Button size="sm" variant="danger" disabled={!!block} title={block ?? undefined} onclick={() => { overrideTarget = p; overrideReason = ''; overrideOpen = true; }}>{t('pol.approveAdmin')}</Button>
  {:else}
    <Button size="sm" variant="primary" denied={!can('policy.approve')} disabled={!!block} title={block ?? undefined} onclick={() => approve(p)}>{mustRenew(p) ? t('pol.renew') : t('pol.approve')}</Button>
  {/if}
  <WithdrawDraft version={p} onchange={() => { policies.reload(); policyDrawer = false; }} />
{/snippet}

<Drawer bind:open={policyDrawer} title={policySel ? `${policySel.policyId} v${policySel.version}` : ''}>
  {#if policySel}
    <div class="stack">
      <div class="row"><StatusPill value={policySel.status} />{#if policySel.opensValues}<Badge tone="warning">{t('obs.badge.opens')}</Badge>{:else}<Badge tone="success">{t('obs.badge.safe')}</Badge>{/if}{#if policySel.approvalsRequired > 0}<span class="num">{t('pol.approvalsOf', { n: policySel.approvals.length, total: policySel.approvalsRequired })}</span>{:else}<span class="subtle">{t('obs.mode.observe')}</span>{/if}</div>
      {#if policySel.status === 'draft'}
        <p class="callout {policySel.opensValues ? 'warn' : 'ok'}" role="status" data-testid="draft-class">{policySel.opensValues ? t('obs.class.opens') : t('obs.draft.safe')}</p>
        {#if policySel.opensValues && policySel.valueReasons.length}
          <div class="subtle">{t('obs.class.why')}<ul class="errs">{#each policySel.valueReasons as r, i (i)}<li>{tk(`obs.reason.${r.code}`, undefined, r.code)} <code>{r.where}</code></li>{/each}</ul></div>
        {/if}
      {/if}
      {#if policySel.approvals.length}
        <ul class="errs">{#each policySel.approvals as a (a.by)}<li>{a.by} <span class="subtle">{fmtDate(a.at)}</span>{#if a.tokenFresh === false} <span class="subtle">· {t('pol.tokenExpired')}</span>{/if}{#if a.mode === 'admin'} <Badge tone="warning">{t('pol.adminBadge')}</Badge><div class="callout warn">{t('pol.adminReason')} «{a.reason}»</div>{/if}</li>{/each}</ul>
      {/if}
      {#if policySel.diff.length}
        <ul class="errs">{#each policySel.diff as d, i (i)}<li><Badge tone={d.change === 'removed' ? 'success' : 'warning'}>{tk(`diff.${d.change}`, undefined, d.change)}</Badge> {d.where} <code>{d.from} → {d.to}</code></li>{/each}</ul>
      {/if}
      {#if policySel.status === 'draft' && !can('policy.approve')}<ApproverHelp version={policySel} />{/if}
      <DiffView before={policySel.yamlBefore} after={policySel.yamlAfter} format="yaml" />
    </div>
  {/if}
  {#snippet footer()}
    {#if policySel && policySel.status === 'draft' && !approvable(policySel)}
      <span class="subtle grow">{t('pol.otherGroup')}</span>
      <Button variant="ghost" onclick={() => (policyDrawer = false)}>{t('common.close')}</Button>
    {:else if policySel && policySel.status === 'draft'}
      {@const blk = approveBlock(policySel)}
      {#if blk}<span class="subtle grow">{blk}</span>{/if}
      <Button variant="ghost" onclick={() => (policyDrawer = false)}>{t('common.close')}</Button>
      {@render approveBtn(policySel)}
    {/if}
  {/snippet}
</Drawer>

<BulkReview bind:open={bulkOpen} groups={bulkGroups} initialGroup={loc.query.group} onchange={() => policies.reload()} />
<Drawer bind:open={identityOpen} title={t('id.title')}>
  {#if identityOpen}<IdentityControl groups={bulkGroups} initialGroup={loc.query.group} onchange={() => policies.reload()} />{/if}
</Drawer>
<Drawer bind:open={domainsOpen} title={t('w4.grp.title')}>
  {#if domainsOpen}<GroupDomainsTestK groups={bulkGroups} initialGroup={loc.query.group} onchange={() => policies.reload()} />{/if}
</Drawer>

<Modal bind:open={overrideOpen} title={t('pol.overrideTitle')}>
  <div class="stack">
    <p class="callout warn" role="alert"><b>{t('pol.overrideWarnTitle')}</b> {t('pol.overrideWarn')}</p>
    <ApprovalNotice approvals={settings.data?.approvals} />
    {#if overrideTarget}<p class="muted">{overrideTarget.policyId} v{overrideTarget.version} · {t('pol.approvalsOf', { n: overrideTarget.approvals.length, total: overrideTarget.approvalsRequired })}</p>{/if}
    <Field label={t('pol.reason')} help="pack.reason" hint={t('pol.reasonHint')}>
      {#snippet children({ id, describedby })}<textarea {id} bind:value={overrideReason} rows="3" aria-describedby={describedby}></textarea>{/snippet}
    </Field>
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (overrideOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" disabled={overrideReason.trim() === ''} onclick={async () => { if (overrideTarget) { await approve(overrideTarget, overrideReason.trim()); overrideOpen = false; } }}>{t('pol.approveAdmin')}</Button>
  {/snippet}
</Modal>

<ConfirmDialog bind:open={confirmKill} title={t('src.killTitle')} message={t('src.killMsg')} confirmLabel={t('src.kill')} requireText={t('kill.word')} onconfirm={toggleKill} />
<ConfirmDialog bind:open={confirmRevoke} title={t('src.revokeTitle')} message={t('src.revokeMsg')} confirmLabel={t('src.revoke')} requireText={selected?.serviceName} onconfirm={revoke} />
<ConfirmDialog bind:open={confirmAll} title={t('src.killAllTitle')} message={t('src.killAllMsg')} confirmLabel={t('src.killAll')} requireText={t('kill.word')} onconfirm={killAll} />

<style>
  .tiles { grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); }
  .gap { height: var(--s-4); }
  .name { font-weight: 650; text-decoration: none; font-size: 0.95rem; text-align: left; }
  .name:hover { text-decoration: underline; }
  .evt { display: flex; align-items: center; gap: var(--s-2); justify-content: flex-end; }
  .errs { margin: var(--s-1) 0 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: 4px; }
  .bulkbar { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; }
  .bulkbar .grow { flex: 1 1 18rem; }
</style>
