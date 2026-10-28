<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  // Detail of one operation: header with key numbers, then schema / statuses / examples.
  import Card from './Card.svelte';
  import Tabs from './Tabs.svelte';
  import Badge from './Badge.svelte';
  import SchemaTree from './SchemaTree.svelte';
  import ProgressBar from './ProgressBar.svelte';
  import CodeBlock from './CodeBlock.svelte';
  import Sparkline from './Sparkline.svelte';
  import KeyValue from './KeyValue.svelte';
  import Loading from './Loading.svelte';
  import InfoTip from './InfoTip.svelte';
  import LinkedFields from './LinkedFields.svelte';
  import OperationKind from './OperationKind.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { fmtDate, fmtNum, fmtPct } from '../lib/format';
  import { graphqlLabel, prettyDocument } from '../lib/graphql';
  import { soapBadge } from '../lib/soap';

  let { service, op, group }: { service: string; op: string; group?: string } = $props();

  const detail = resource(() => api.contracts.operation(service, op, group));
  let tab = $state('schema');
  let respStatus = $state<number | 'request'>(0);
  const d = $derived(detail.data ?? null);

  $effect(() => {
    if (d) respStatus = d.responses[0]?.status ?? 'request';
  });
  const activeResp = $derived(d?.responses.find((r) => r.status === respStatus));
  const statusTone = (s: number) => (s >= 500 ? 'danger' : s >= 400 ? 'warning' : 'success');
  const methodTone = (m: string) => (m === 'GET' ? 'info' : m === 'DELETE' ? 'danger' : 'accent');
</script>

{#if d}
  <div class="stack">
    <Card>
      <div class="row spread top">
        <div class="grow">
          {#if d.graphql}
            <div class="row-tight"><Badge tone="accent">{t('gql.badge')}</Badge><code class="path">{graphqlLabel(d.graphql, t('gql.anonymous'))}</code><InfoTip id="ct.graphql" /></div>
          {:else if d.soap}
            <div class="row-tight"><Badge tone="accent">{soapBadge(d.soap.format)}</Badge><code class="path">{d.soap.name}</code></div>
            <p class="subtle">{t('soap.subtitle', { method: d.soap.method, endpoint: d.soap.endpoint })}</p>
          {:else}
            <div class="row-tight"><Badge tone={methodTone(d.method)}>{d.method}</Badge><code class="path">{d.pathTemplate}</code></div>
          {/if}
          <p class="subtle">{d.service}{#if d.entity}{' '}· {t('ct.entity')} <Badge tone="accent">{d.entity}</Badge><InfoTip id="ct.entity" />{/if}</p>
        </div>
        <div class="row stats">
          <div class="stat"><b>{fmtNum(d.calls)}</b><span>{t('ct.calls')}</span></div>
          <div class="stat"><b>{d.latencyMs.p50}</b><span>p50 ms <InfoTip id="ct.latency" /></span></div>
          <div class="stat"><b>{d.latencyMs.p95}</b><span>p95 ms</span></div>
          <div class="stat"><b>{d.latencyMs.p99}</b><span>p99 ms</span></div>
        </div>
      </div>
      {#if d.fewSamples}
        <p class="callout warn few" role="note">{t('ct.fewSamplesLong', { n: d.calls })} <InfoTip id="ct.fewSamples" /></p>
      {/if}
    </Card>

    {#if d.graphql}
      <Card title={t('gql.title')} subtitle={t('gql.subtitle', { method: d.graphql.method, endpoint: d.graphql.endpoint })}>
        <div class="stack">
          {#if d.graphql.anonymous}<p class="subtle">{t('gql.anonymousNote')}</p>{/if}
          {#if d.graphql.introspection}<p class="callout" role="note">{t('gql.introspection')} <InfoTip id="ct.graphqlSchema" /></p>{/if}
          <CodeBlock code={prettyDocument(d.graphql.document)} title={t('gql.document')} language="graphql" maxHeight="16rem" />
          <p class="subtle">{t('gql.documentNote')}</p>
          {#if d.graphql.variables.length}
            <KeyValue items={d.graphql.variables.map((v) => ({ k: `$${v.name}`, v: v.type }))} cols={2} />
          {:else}<p class="subtle">{t('gql.noVariables')}</p>{/if}
          {#if d.graphql.fields.length}<p class="subtle">{t('gql.fields', { fields: d.graphql.fields.join(', ') })}</p>{/if}
        </div>
      </Card>
    {/if}

    {#if !d.graphql?.introspection}
      <OperationKind {service} {op} method={d.method} group={group ?? d.group ?? ''} graphqlType={d.graphql?.type} />
    {/if}

    <Tabs tabs={[{ id: 'schema', label: t('ct.tab.schema') }, { id: 'status', label: t('ct.tab.status') }, { id: 'examples', label: t('ct.tab.examples') }]} bind:value={tab} label={t('ct.title')}>
      {#if tab === 'schema'}
        <Card title={t('ct.schema')} subtitle={t('ct.schemaHint')} flush>
          <div class="pills" role="group" aria-label={t('ct.pickStatus')}>
            {#if d.request}<button type="button" class="pill" aria-pressed={respStatus === 'request'} onclick={() => (respStatus = 'request')}>{t('ct.request')}</button>{/if}
            {#each d.responses as r (r.status)}
              <button type="button" class="pill" aria-pressed={respStatus === r.status} onclick={() => (respStatus = r.status)}>{r.status} <small>{fmtPct(r.frequency, 1)}</small></button>
            {/each}
          </div>
          {#if respStatus === 'request' && d.request}
            <SchemaTree root={d.request} />
            <LinkedFields deps={d.requestLinked ?? []} label={t('lf.request')} />
          {:else if activeResp}
            <SchemaTree root={activeResp.schema} />
            <LinkedFields deps={activeResp.linked ?? []} label={t('lf.response', { status: activeResp.status })} />
          {/if}
        </Card>
      {:else if tab === 'status'}
        <div class="grid-2">
          <Card title={t('ct.statuses')} flush>
            <div class="table-wrap" use:scrollable>
              <table class="data">
                <thead><tr><th scope="col">{t('ct.col.status')}</th><th scope="col">{t('ct.col.freq')} <InfoTip id="ct.frequency" /></th><th scope="col" class="r">{t('ct.col.calls')}</th></tr></thead>
                <tbody>
                  {#each d.statuses as s (s.status)}
                    <tr>
                      <td><Badge tone={statusTone(s.status)}>{s.status}</Badge>{#if s.example}{' '}<span class="subtle mono">{s.example}</span>{/if}</td>
                      <td class="bar"><ProgressBar value={s.frequency} label={t('ct.freqOf', { status: s.status })} tone={statusTone(s.status) === 'success' ? 'success' : statusTone(s.status)} /></td>
                      <td class="r num">{fmtNum(s.calls)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title={t('ct.latency')}>
            <KeyValue items={[{ k: 'p50', v: `${d.latencyMs.p50} ms` }, { k: 'p95', v: `${d.latencyMs.p95} ms` }, { k: 'p99', v: `${d.latencyMs.p99} ms` }, { k: t('ct.firstSeen'), v: fmtDate(d.firstSeen, false) }, { k: t('ct.lastSeen'), v: fmtDate(d.lastSeen) }]} cols={2} />
            <div class="spark"><Sparkline values={d.latencySeries} width={320} height={56} label={t('ct.latencySpark')} /></div>
          </Card>
        </div>
      {:else}
        <Card title={t('ct.examples')} subtitle={t('ct.examplesHint')}>
          <div class="stack">
            {#each d.responses as r (r.status)}
              {#each r.examples as ex (r.status + ex.name)}
                <CodeBlock code={JSON.stringify(ex.value, null, 2)} title={`${r.status} · ${ex.name}`} language="json" maxHeight="14rem" />
              {/each}
            {/each}
          </div>
        </Card>
      {/if}
    </Tabs>
  </div>
{:else}
  <Loading error={detail.error} onretry={detail.reload} />
{/if}

<style>
  .top { align-items: flex-start; }
  .path { font-size: 0.95rem; }
  .stats { gap: var(--s-5); }
  .few { margin-top: var(--s-3); }
  .pills { display: flex; gap: var(--s-2); flex-wrap: wrap; padding: var(--s-3) var(--s-4); border-bottom: 1px solid var(--border); }
  .pill { font: inherit; font-weight: 600; border: 1px solid var(--border-strong); background: var(--surface); color: var(--fg); border-radius: 999px; padding: 2px 12px; cursor: pointer; }
  .pill small { color: var(--fg-muted); font-weight: 500; margin-left: 4px; }
  .pill[aria-pressed='true'] { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .pill[aria-pressed='true'] small { color: inherit; }
  .bar { min-width: 140px; }
  .spark { margin-top: var(--s-4); max-width: 100%; overflow: hidden; }
</style>
