<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Badge from '../components/Badge.svelte';
  import Button from '../components/Button.svelte';
  import OperationList from '../components/OperationList.svelte';
  import OperationPanel from '../components/OperationPanel.svelte';
  import SnapshotsPanel from '../components/SnapshotsPanel.svelte';
  import ContractsSwitch from '../components/ContractsSwitch.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Loading from '../components/Loading.svelte';
  import ContractStatusCard from '../components/ContractStatusCard.svelte';
  import IdFormats from '../components/IdFormats.svelte';
  import DateOffsets from '../components/DateOffsets.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { loc, navigate, setQuery } from '../lib/router.svelte';
  import { queryTab } from '../lib/tabs.svelte';
  import { can, toastError } from '../lib/stores.svelte';
  import { href } from '../lib/router';
  import { saveBlob, saveDoc, serializeDoc, type DocFormat } from '../lib/download';
  import { serviceKey } from '../lib/api';
  import GroupTag from '../components/GroupTag.svelte';
  import { scopeGroups, showGroupColumn } from '../lib/scope.svelte';
  import { viewerUrl } from '../lib/viewer-url';
  import { VIEWERS } from '../viewers';
  import { fmtAgo, fmtNum, fmtPct } from '../lib/format';
  import { capturedSchemas, graphqlOperations, operationsText, sdlOf } from '../lib/graphql';

  let { params }: { params: Record<string, string> } = $props();

  // The contract of one (group, service): the row's group travels in the URL (?group=). Without it, every group.
  const group = $derived(loc.query.group || undefined);
  const summary = resource(() => api.contracts.service(params.name, group));
  const ops = resource(() => api.contracts.operations(params.name, group));
  // The services of the Group/Team filter only, one entry per (group, service).
  const services = resource(() => api.services.list(scopeGroups()));
  const doc = resource(() => api.contracts.openapi(params.name, group));
  const tabs = queryTab('ops', ['ops', 'snapshots', 'openapi', 'ids', 'dates', 'graphql']);
  // GraphQL endpoints (x-tt-graphql): the captured schema as SDL and the observed operations.
  const gqlOps = $derived(doc.data ? graphqlOperations(doc.data) : []);
  const gqlSchemas = $derived(doc.data ? capturedSchemas(doc.data) : []);
  const current = $derived(serviceKey(group ?? summary.data?.service.group, params.name));
  const pickList = $derived.by(() => {
    const list = services.data ?? [];
    // The open service stays in the menu even when the filter would hide it.
    return list.some((sv) => serviceKey(sv.group, sv.name) === current) || !summary.data ? list : [summary.data.service, ...list];
  });
  function pick(key: string): void {
    const sv = pickList.find((x) => serviceKey(x.group, x.name) === key);
    if (sv) navigate(`/contracts/service/${encodeURIComponent(sv.name)}`, sv.group ? { group: sv.group } : {});
  }

  let format = $state<DocFormat>('yaml');
  // The text shown and downloaded is the one the server serializes (JSON or YAML); the object is the fallback.
  const raw = resource(() => api.contracts.rawDocument(params.name, format, group).catch(() => null));
  const text = $derived(raw.data ?? (doc.data ? serializeDoc(doc.data, format) : ''));

  async function download(f: DocFormat): Promise<void> {
    if (!doc.data) return;
    try {
      const body = await api.contracts.rawDocument(params.name, f, group);
      saveBlob(`${params.name}.openapi.${f}`, new Blob([body], { type: f === 'json' ? 'application/json' : 'application/yaml' }));
    } catch {
      saveDoc(params.name, doc.data, f);
    }
  }
  let postmanBusy = $state(false);
  async function downloadPostman(): Promise<void> {
    postmanBusy = true;
    try {
      const { filename, blob } = await api.contracts.postman(params.name, group);
      saveBlob(filename, blob);
    } catch (e) {
      toastError(e);
    } finally {
      postmanBusy = false;
    }
  }
  const op = $derived(loc.query.op);
  const s = $derived(summary.data);
  const cov = $derived(s ? s.coverage.fewSamples + s.coverage.statusesNeverSeen + s.coverage.lowSupportRules : 0);
  const errTone = $derived(!s ? 'neutral' : s.errorRate > 0.05 ? 'danger' : s.errorRate > 0.02 ? 'warning' : 'success');
</script>

<PageHeader
  title={params.name}
  description={t('cs.desc')}
  help="contract-service"
  breadcrumbs={[{ label: t('nav.contracts'), href: '#/contracts' }, { label: t('ct.view.service') }, { label: params.name }]}
  updatedAt={summary.updatedAt}
  onrefresh={() => { summary.reload(); ops.reload(); doc.reload(); raw.reload(); }}
  refreshing={summary.loading}
>
  {#snippet actions()}
    <ContractsSwitch current="service" service={params.name} {group} />
    <Button size="sm" icon="download" disabled={!doc.data} loading={postmanBusy} onclick={downloadPostman}>{t('cs.postman.short')}</Button>
    {#if summary.data?.service.group !== undefined}<GroupTag group={summary.data.service.group} always />{/if}
    {#if services.data}
      <select class="pick" aria-label={t('cs.pickService')} value={current} onchange={(e) => pick(e.currentTarget.value)}>
        {#each pickList as sv (serviceKey(sv.group, sv.name))}<option value={serviceKey(sv.group, sv.name)}>{sv.name}{showGroupColumn() && sv.group !== undefined ? ` · ${sv.group || t('scope.unknownGroup')}` : ''}</option>{/each}
      </select>
    {/if}
  {/snippet}
</PageHeader>

{#if summary.error}
  <Loading error={summary.error} onretry={summary.reload} />
{:else if s}
  <div class="tiles">
    <Card>
      <div class="stat">
        <b class="sm">{t(s.service.kind === 'own' ? 'svc.own' : 'svc.external')}</b>
        <span>{t('cs.kind')} <InfoTip id="svc.kind" /></span>
        {#if s.service.baseUrl}<span class="mono trunc" title={s.service.baseUrl}>{s.alias ? `${s.alias}.example` : s.service.baseUrl}</span>{/if}
        {#if s.service.hostPattern && can('hosts.twin')}<a href={href('/hosts', {}, { q: s.service.hostPattern })}>{t('svc.hostGroup')}</a>{/if}
        {#if s.alias}<span class="subtle">{t('cs.alias', { alias: s.alias })}</span>{/if}
      </div>
    </Card>
    <Card><div class="stat"><b>{s.operations}</b><span>{t('cs.operations')}</span><span class="subtle num">{t('cs.calls', { n: fmtNum(s.calls) })}</span></div></Card>
    <Card>
      <div class="stat"><b class={errTone}>{fmtPct(s.errorRate, 1)}</b><span>{t('cs.errorRate')} <InfoTip id="ct.errorRate" /></span></div>
    </Card>
    <Card><div class="stat"><b class="num">{s.latencyMs.p50} / {s.latencyMs.p95} ms</b><span>{t('cs.latency')} <InfoTip id="ct.latency" /></span></div></Card>
    <Card>
      <div class="stat">
        {#if s.lastDrift}
          <StatusPill value={s.lastDrift.severity} />
          <span>{t('cs.lastDrift', { when: fmtAgo(s.lastDrift.at) })}{s.lastDrift.open ? '' : ' · ' + tk('status.resolved')}</span>
          <a href="#/alerts">{t('cs.openAlerts')}</a>
        {:else}
          <b class="sm">{t('cs.noDrift')}</b><span>{t('cs.driftLabel')}</span>
        {/if}
      </div>
    </Card>
    <Card>
      <div class="stat">
        <b class={cov === 0 ? 'success' : 'warning'}>{cov}</b>
        <span>{t('cs.coverage')} <InfoTip id="ct.coverage" /></span>
        <span class="subtle">{t('cs.coverageDetail', { few: s.coverage.fewSamples, never: s.coverage.statusesNeverSeen, low: s.coverage.lowSupportRules })} · <a href="#/gaps?q={encodeURIComponent(params.name)}">{t('nav.gaps')}</a></span>
      </div>
    </Card>
  </div>
{:else}
  <Loading lines={2} />
{/if}

<div class="gap"></div>
{#key `${group ?? ''}/${params.name}`}<ContractStatusCard service={params.name} {group} onupdated={() => { summary.reload(); ops.reload(); doc.reload(); raw.reload(); }} />{/key}
<div class="gap"></div>

<Tabs
  tabs={[
    { id: 'ops', label: t('cs.tab.ops'), count: ops.data?.length },
    { id: 'snapshots', label: t('ct.tab.snapshots'), count: s?.snapshots },
    { id: 'openapi', label: t('cs.tab.openapi') },
    { id: 'ids', label: t('idf.title') },
    { id: 'dates', label: t('dof.title') },
    ...(gqlOps.length || gqlSchemas.length ? [{ id: 'graphql', label: t('gql.tab'), count: gqlOps.length }] : []),
  ]}
  bind:value={tabs.value}
  label={params.name}
>
  {#if tabs.value === 'ops'}
    <div class="layout">
      <aside aria-label={t('ct.explorer')}>
        <Card flush>
          {#if ops.data}
            <OperationList ops={ops.data} grouped={false} hrefOf={(o) => href('/contracts/service/:name', { name: params.name }, { op: o.op, group: group ?? '' })} isCurrent={(o) => op === o.op} />
          {:else}<Loading error={ops.error} lines={5} />{/if}
        </Card>
      </aside>
      <section class="main">
        {#if ops.data && ops.data.length === 0}
          <Card><EmptyState icon="contracts" title={t('cst.emptyOps')} description={t('cst.emptyOpsHint')} /></Card>
        {:else if !op}
          <Card><EmptyState icon="contracts" title={t('ct.pick')} description={t('ct.pickHint')} /></Card>
        {:else}
          {#key `${group ?? ''}/${params.name}/${op}`}<OperationPanel service={params.name} {op} {group} />{/key}
        {/if}
      </section>
    </div>
  {:else if tabs.value === 'snapshots'}
    {#key `${group ?? ''}/${params.name}`}<SnapshotsPanel service={params.name} {group} />{/key}
  {:else if tabs.value === 'graphql'}
    <div class="stack">
      <Card title={t('gql.schemaTitle')}>
        {#snippet actions()}<InfoTip id="ct.graphqlSchema" />{/snippet}
        {#each gqlSchemas as sc (sc.endpoint)}
          <p class="subtle">{t('gql.schemaCaptured', { endpoint: sc.endpoint, date: sc.capturedAt })}</p>
          <div class="row">
            <Button size="sm" icon="download" onclick={() => saveBlob(`${params.name}.graphql`, new Blob([sdlOf(sc.schema)], { type: 'application/graphql' }))}>{t('gql.download')}</Button>
          </div>
          <CodeBlock code={sdlOf(sc.schema)} title={`${params.name} · ${sc.endpoint}`} language="graphql" maxHeight="26rem" />
        {:else}
          <p class="subtle">{t('gql.schemaMissing')}</p>
        {/each}
      </Card>
      <Card title={t('gql.operationsTitle')} subtitle={t('gql.operationsHint')}>
        {#snippet actions()}<InfoTip id="ct.graphql" />{/snippet}
        <CodeBlock code={operationsText(doc.data)} title={`${params.name}.operations.graphql`} language="graphql" maxHeight="26rem" />
      </Card>
    </div>
  {:else if tabs.value === 'ids'}
    {#key `${group ?? ''}/${params.name}`}<IdFormats doc={doc.data} group={group ?? s?.service.group ?? ''} />{/key}
  {:else if tabs.value === 'dates'}
    {#key `${group ?? ''}/${params.name}`}<DateOffsets doc={doc.data} group={group ?? s?.service.group ?? ''} />{/key}
  {:else}
    <div class="stack">
      <Card title={t('cs.docTitle')} subtitle={t('cs.docHint')}>
        {#snippet actions()}
          <InfoTip id="ct.openapi" />
          <div class="seg" role="group" aria-label={t('cs.format')}>
            {#each ['yaml', 'json'] as const as f (f)}<button type="button" aria-pressed={format === f} onclick={() => (format = f)}>{t('fix4.cs.show', { f: f.toUpperCase() })}</button>{/each}
          </div>
          <Button size="sm" icon="download" disabled={!doc.data} onclick={() => download('json')}>{t('fix4.cs.downloadJson')}</Button>
          <Button size="sm" icon="download" disabled={!doc.data} onclick={() => download('yaml')}>{t('fix4.cs.downloadYaml')}</Button>
        {/snippet}
        {#if doc.data}
          <CodeBlock code={text} title={`${params.name}.openapi.${format}`} language={format} maxHeight="26rem" />
        {:else}<Loading error={doc.error} lines={6} />{/if}
      </Card>
      <Card title={t('cs.postman.title')} subtitle={t('cs.postman.hint')}>
        <div class="stack-sm">
          <div class="row">
            <Button variant="primary" icon="download" loading={postmanBusy} disabled={!doc.data} onclick={downloadPostman}>{t('cs.postman.button')}</Button>
            <InfoTip id="ct.postman" />
          </div>
          <p class="subtle">{t('cs.postman.note')}</p>
        </div>
      </Card>
      <Card title={t('cs.viewers')} subtitle={t('cs.viewersHint')}>
        <div class="grid viewers">
          {#each VIEWERS as v (v)}
            <a class="viewer" href={viewerUrl(params.name, v, group)}>
              <b>{tk(`docs.v.${v}`)}</b>
              <span class="muted">{tk(`cs.v.${v}`)}</span>
              <span class="open">{t('cs.openViewer')} →</span>
            </a>
          {/each}
        </div>
        <p class="subtle note">{t('cs.viewersNote')}</p>
      </Card>
    </div>
  {/if}
</Tabs>

<style>
  .tiles { display: grid; gap: var(--s-3); align-items: start; grid-template-columns: repeat(auto-fit, minmax(min(100%, 160px), 1fr)); }
  .tiles > :global(*) { min-width: 0; }
  .stat b.sm { font-size: 1.05rem; letter-spacing: 0; }
  .stat b.success { color: var(--success); }
  .stat b.warning { color: var(--warning); }
  .stat b.danger { color: var(--danger); }
  .stat .trunc { max-width: 100%; }
  .gap { height: var(--s-5); }
  .pick { width: auto; min-width: 160px; }
  .layout { display: grid; grid-template-columns: minmax(240px, 320px) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  aside { max-height: 560px; overflow: auto; border-radius: var(--r-md); }
  .main { min-width: 0; }
  .seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-md); overflow: hidden; }
  .seg button { font: inherit; font-size: 0.8rem; font-weight: 600; border: 0; background: var(--surface); color: var(--fg-muted); padding: 3px 10px; cursor: pointer; }
  .seg button[aria-pressed='true'] { background: var(--accent); color: var(--accent-fg); }
  .viewers { grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); }
  .viewer { display: flex; flex-direction: column; gap: var(--s-1); padding: var(--s-4); border: 1px solid var(--border-strong); border-radius: var(--r-md); text-decoration: none; color: var(--fg); background: var(--surface); }
  .viewer:hover { border-color: var(--accent); }
  .open { color: var(--accent); font-weight: 500; margin-top: var(--s-1); }
  .note { margin-top: var(--s-3); }
  @media (max-width: 960px) { .layout { grid-template-columns: minmax(0, 1fr); } aside { max-height: 280px; } }
</style>
