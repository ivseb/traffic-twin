<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  // Host esterni (spec v1.5): every outbound host the services call, grouped by registrable domain, so that
  // "if my service calls something I do not remember I can see it and intercept it".
  import { untrack } from 'svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Badge from '../components/Badge.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import PatternView from '../components/PatternView.svelte';
  import HostTwinModal from '../components/HostTwinModal.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { contractHref, scopeGroups } from '../lib/scope.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { serviceKey, type HostEntry } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';
  import { fmtAgo, fmtNum, fmtPct } from '../lib/format';
  import { href } from '../lib/router';
  import { loc, setQuery } from '../lib/router.svelte';
  import { queryParam } from '../lib/tabs.svelte';
  import { dedupeHosts, filterDomains, HOST_SORTS, ipDomains, isNewHost, nameDomains, NEW_RANGES, sortDomains, strictPolicies, summarize, type HostFilter } from '../lib/hosts';

  // Group/Team filter: the server lists the hosts called by the sources of the chosen groups. The same pattern
  // called by two groups is two entries (one per group), each with its own callers and declaration.
  const reg = resource(() => api.hosts.list(scopeGroups()));
  // One row per host: once a host is declared the registry lists it twice (the calls before, the declared one).
  const data = $derived(reg.data ? dedupeHosts(reg.data) : undefined);
  const now = $derived(reg.updatedAt ?? Date.now());

  const range = queryParam('range', 'all', NEW_RANGES);
  const sort = queryParam('sort', 'calls', HOST_SORTS);
  const decl = queryParam('decl', 'all', ['all', 'no'] as const);
  // The search box keeps its text in the URL (?q=…), so a link from a service lands on its host.
  let q = $state(untrack(() => loc.query.q ?? ''));
  $effect(() => {
    const next = q;
    if (untrack(() => loc.query.q ?? '') !== next) untrack(() => setQuery({ q: next }));
  });

  const filter = $derived<HostFilter>({ range: range.value, q, undeclaredOnly: decl.value === 'no' });
  const domains = $derived(data ? sortDomains(filterDomains(nameDomains(data), filter, now), sort.value) : []);
  const ips = $derived(data ? sortDomains(filterDomains(ipDomains(data), filter, now), sort.value) : []);
  const sum = $derived(data ? summarize(data, now) : null);
  const strict = $derived(data ? strictPolicies(data) : []);
  const filtering = $derived(range.value !== 'all' || q.trim() !== '' || decl.value === 'no');

  type SysId = 'unlisted' | 'invalid' | 'ip:private' | 'ip:public';
  interface SysRow {
    id: SysId;
    entry: HostEntry;
  }
  const system = $derived.by<SysRow[]>(() => {
    if (!data) return [];
    const rows: SysRow[] = [];
    if (strict.length > 0 || data.unlisted.calls > 0) rows.push({ id: 'unlisted', entry: data.unlisted });
    if (data.invalid.calls > 0) rows.push({ id: 'invalid', entry: data.invalid });
    for (const d of ips) for (const e of d.patterns) rows.push({ id: d.domain === 'ip:private' ? 'ip:private' : 'ip:public', entry: e });
    return rows;
  });

  let twinOpen = $state(false);
  let twinHost = $state<HostEntry | null>(null);
  function twin(h: HostEntry): void {
    twinHost = h;
    twinOpen = true;
  }

  const errTone = (h: HostEntry) => (h.errorRate >= 0.05 ? 'danger' : h.errorRate >= 0.01 ? 'warning' : 'neutral');
  const callers = (h: HostEntry) => h.callers.map((c) => `${c.service} (${fmtNum(c.calls)})`).join(', ');
  const reset = () => {
    q = '';
    setQuery({ q: '', range: '', decl: '' });
  };
</script>

{#snippet metrics(h: HostEntry)}
  <td class="r nw">{fmtNum(h.calls)}</td>
  <td class="callers hide-md" title={callers(h)}>
    {#each h.callers.slice(0, 2) as c (c.service)}<span class="who">{c.service}</span>{/each}
    {#if h.callers.length > 2}<span class="subtle">{t('hosts.moreCallers', { n: h.callers.length - 2 })}</span>{/if}
    {#if h.callers.length === 0}—{/if}
  </td>
  <td class="seen">
    {#if h.firstSeen}
      <div title={h.firstSeen}>{t('hosts.first')} {fmtAgo(h.firstSeen, now)}</div>
      <div class="subtle" title={h.lastSeen ?? ''}>{t('hosts.last')} {h.lastSeen ? fmtAgo(h.lastSeen, now) : '—'}</div>
    {:else}—{/if}
  </td>
  <td class="r nw">
    {#if h.calls > 0}
      <Badge tone={errTone(h)}>{fmtPct(h.errorRate, 1)}</Badge>
      {#if h.clientErrors > 0}<div class="subtle" title={t('hosts.client4xxTip')}>{t('hosts.client4xx', { n: fmtNum(h.clientErrors) })}</div>{/if}
    {:else}—{/if}
  </td>
  <td class="r nw hide-md">{h.latencyP50Ms === null ? '—' : `${fmtNum(h.latencyP50Ms)} ms`}</td>
{/snippet}

{#snippet badges(h: HostEntry)}
  <GroupTag group={h.group} />
  {#if h.declared}<Badge tone="success" title={t('hosts.declaredTip', { policies: h.declaredBy.join(', ') })}>{t('hosts.declared')}</Badge>{/if}
  {#if isNewHost(h, now)}<Badge tone="info" title={t('hosts.newTip')}>{t('hosts.new')}</Badge>{/if}
  {#if h.quarantined}<a class="plain" href={href('/quarantine')} title={t('hosts.quarantinedTip')}><Badge tone="danger">{t('hosts.quarantined')}</Badge></a>{/if}
  {#if h.nowDeclaredAs}<Badge tone="neutral" title={t('hosts.nowDeclaredTip')}>{t('svc.nowDeclared', { name: h.nowDeclaredAs })}</Badge>{/if}
{/snippet}

{#snippet action(h: HostEntry)}
  {#if h.declared}
    <a href={contractHref(h.service, h.group)}>{t('hosts.openService', { name: h.service })}</a>
  {:else if h.nowDeclaredAs}
    <a href={contractHref(h.nowDeclaredAs, h.group)}>{t('hosts.openService', { name: h.nowDeclaredAs })}</a>
  {:else}
    <Button size="sm" variant="primary" icon="plus" denied={!can('hosts.twin')} onclick={() => twin(h)}>{t('hosts.twin.button')}</Button>
  {/if}
{/snippet}

{#snippet sysAction(row: SysRow)}
  {#if row.id === 'unlisted'}
    <a href="#/onboarding">{t('hosts.strict.cta')}</a>
  {:else if row.id !== 'invalid'}
    {@render action(row.entry)}
  {/if}
{/snippet}

<PageHeader title={t('hosts.title')} description={t('hosts.desc')} help="hosts" breadcrumbs={[{ label: t('nav.hosts') }]} updatedAt={reg.updatedAt} onrefresh={reg.reload} refreshing={reg.loading} />

{#if data && sum}
  <div class="stack">
    <ScopeNote />
    {#if strict.length > 0}
      <p class="callout warn" role="status" data-testid="strict-callout">
        <b>{t('hosts.strict.title')}</b> {t('hosts.strict.body', { policies: strict.join(', ') })} <InfoTip id="hosts.strict" />
        <a href="#/onboarding">{t('hosts.strict.cta')}</a>
      </p>
    {/if}

    <div class="grid tiles">
      <Card><div class="stat"><b>{fmtNum(sum.domains)}</b><span>{t('hosts.tile.domains')}</span></div></Card>
      <Card><div class="stat"><b data-testid="tile-hosts">{fmtNum(sum.all)}</b><span>{t('hosts.tile.hosts')} <InfoTip id="hosts.counters" /></span>{#if sum.ips > 0}<span class="subtle">{t('fix5.hosts.tile.ips', { n: sum.ips })}</span>{/if}</div></Card>
      <Card><div class="stat"><b class={sum.undeclared ? 'warning' : ''}>{fmtNum(sum.undeclared)}</b><span>{t('hosts.tile.undeclared')} <InfoTip id="hosts.declared" /></span></div></Card>
      <Card><div class="stat"><b class={sum.fresh ? 'accent' : ''}>{fmtNum(sum.fresh)}</b><span>{t('hosts.tile.new')} <InfoTip id="hosts.new" /></span></div></Card>
      <Card><div class="stat"><b class={sum.quarantined ? 'danger' : ''}>{fmtNum(sum.quarantined)}</b><span>{t('hosts.tile.quarantined')} <InfoTip id="hosts.quarantined" /></span></div></Card>
    </div>

    <Card>
      <div class="filters" role="search" aria-label={t('hosts.filters')}>
        <div class="f grow">
          <label for="hq">{t('hosts.search')}</label>
          <input id="hq" type="search" bind:value={q} placeholder={t('hosts.searchPh')} spellcheck="false" autocomplete="off" />
        </div>
        <div class="f">
          <label for="hr">{t('hosts.show')}</label>
          <select id="hr" value={range.value} onchange={(e) => (range.value = e.currentTarget.value as typeof range.value)}>
            {#each NEW_RANGES as r (r)}<option value={r}>{tk(`hosts.range.${r}`)}</option>{/each}
          </select>
        </div>
        <div class="f">
          <label for="hs">{t('hosts.sort')}</label>
          <select id="hs" value={sort.value} onchange={(e) => (sort.value = e.currentTarget.value as typeof sort.value)}>
            {#each HOST_SORTS as s (s)}<option value={s}>{tk(`hosts.sort.${s}`)}</option>{/each}
          </select>
        </div>
        <label class="chk"><input type="checkbox" checked={decl.value === 'no'} onchange={(e) => (decl.value = e.currentTarget.checked ? 'no' : 'all')} /> {t('hosts.onlyUndeclared')}</label>
        {#if filtering}<Button size="sm" variant="ghost" onclick={reset}>{t('hosts.reset')}</Button>{/if}
      </div>
    </Card>

    {#if data.domains.length === 0 && system.length === 0}
      <Card><EmptyState icon="services" title={t('hosts.none')} description={t('hosts.noneHint')} /></Card>
    {:else if domains.length === 0 && system.length === 0}
      <Card><EmptyState icon="filter" title={t('hosts.noMatch')} description={t('hosts.noMatchHint')}><Button onclick={reset}>{t('hosts.reset')}</Button></EmptyState></Card>
    {/if}

    {#each domains as d (d.domain)}
      <Card flush id={`dom-${d.domain}`} title={d.domain} subtitle={t('hosts.domain.summary', { calls: fmtNum(d.calls), n: d.patterns.length, last: d.lastSeen ? fmtAgo(d.lastSeen, now) : '—' })}>
        <div class="table-wrap" use:scrollable>
          <table class="data">
            <thead>
              <tr>
                <th scope="col">{t('hosts.col.host')} <InfoTip id="hosts.pattern" /></th>
                <th scope="col" class="r">{t('hosts.col.calls')}</th>
                <th scope="col" class="hide-md">{t('hosts.col.callers')}</th>
                <th scope="col">{t('hosts.col.seen')}</th>
                <th scope="col" class="r">{t('hosts.col.errors')} <InfoTip id="hosts.errors" /></th>
                <th scope="col" class="r hide-md">{t('hosts.col.p50')}</th>
                <th scope="col" class="hide-md"><span class="sr-only">{t('hosts.col.action')}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each d.patterns as h (serviceKey(h.group, h.service))}
                <tr data-testid="host-row">
                  <td class="host">
                    <PatternView pattern={h.pattern} strong />
                    <div class="tags">{@render badges(h)}</div>
                    {#if h.declared}<div class="subtle" data-testid="declared-as">{t('fix5.hosts.declaredAs', { name: h.service })}</div>{/if}
                    {#if h.mergedCalls}<div class="subtle">{t('fix5.hosts.history', { n: fmtNum(h.mergedCalls) })}</div>{:else if h.foldedFrom?.length}<div class="subtle">{t('fix5.hosts.folded', { patterns: h.foldedFrom.join(', ') })}</div>{/if}
                    <div class="subtle m-md">{callers(h) || '—'} · {h.latencyP50Ms === null ? '—' : `${fmtNum(h.latencyP50Ms)} ms`}</div>
                    <div class="m-md inl">{@render action(h)}</div>
                  </td>
                  {@render metrics(h)}
                  <td class="act hide-md">{@render action(h)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </Card>
    {/each}

    {#if system.length > 0}
      <Card flush title={t('hosts.sys.title')} subtitle={t('hosts.sys.subtitle')}>
        {#snippet actions()}<InfoTip id="hosts.system" />{/snippet}
        <div class="table-wrap" use:scrollable>
          <table class="data">
            <thead>
              <tr>
                <th scope="col">{t('hosts.col.what')}</th>
                <th scope="col" class="r">{t('hosts.col.calls')}</th>
                <th scope="col" class="hide-md">{t('hosts.col.callers')}</th>
                <th scope="col">{t('hosts.col.seen')}</th>
                <th scope="col" class="r">{t('hosts.col.errors')}</th>
                <th scope="col" class="r hide-md">{t('hosts.col.p50')}</th>
                <th scope="col" class="hide-md"><span class="sr-only">{t('hosts.col.action')}</span></th>
              </tr>
            </thead>
            <tbody>
              {#each system as row (serviceKey(row.entry.group, row.entry.service + row.entry.pattern))}
                <tr data-testid="system-row" data-kind={row.id}>
                  <td class="host">
                    <b class="mono">{row.entry.pattern}</b>
                    <div class="tags">
                      <Badge tone={row.id === 'invalid' ? 'warning' : row.id === 'unlisted' ? 'neutral' : 'info'}>{tk(`hosts.sys.${row.id}`)}</Badge>
                      {#if isNewHost(row.entry, now)}<Badge tone="info" title={t('hosts.newTip')}>{t('hosts.new')}</Badge>{/if}
                    </div>
                    <p class="subtle expl">{tk(`hosts.sys.${row.id}.why`)}</p>
                    <div class="m-md inl">{@render sysAction(row)}</div>
                  </td>
                  {@render metrics(row.entry)}
                  <td class="act hide-md">{@render sysAction(row)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </Card>
    {/if}
  </div>
{:else}
  <Loading error={reg.error} onretry={reg.reload} />
{/if}

<HostTwinModal bind:open={twinOpen} host={twinHost} ondone={reg.reload} />

<style>
  .tiles { grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr)); }
  .warning { color: var(--warning); }
  .accent { color: var(--accent); }
  .danger { color: var(--danger); }
  .filters { display: flex; flex-wrap: wrap; gap: var(--s-3); align-items: flex-end; }
  .f { display: flex; flex-direction: column; gap: 4px; min-width: 9rem; }
  .f.grow { min-width: 14rem; }
  .f label { font-size: 0.82rem; font-weight: 600; color: var(--fg-muted); }
  .chk { display: inline-flex; gap: var(--s-2); align-items: center; font-weight: 500; padding-bottom: 0.4rem; }
  td.host { min-width: 13rem; }
  td.nw { white-space: nowrap; }
  .m-md { display: none; }
  .inl { margin-top: var(--s-2); }
  @media (max-width: 1100px) {
    .hide-md { display: none; }
    .m-md { display: block; }
  }
  .tags { display: flex; gap: var(--s-1); flex-wrap: wrap; margin-top: 4px; }
  .tags:empty { display: none; }
  td.callers { max-width: 14rem; }
  .who { display: inline-block; margin-right: var(--s-2); }
  td.seen { white-space: nowrap; }
  td.act { text-align: right; white-space: nowrap; }
  .plain { text-decoration: none; }
  .expl { margin: 6px 0 0; max-width: 34rem; white-space: normal; }
</style>
