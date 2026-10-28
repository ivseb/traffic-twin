<script lang="ts">
  // Filterable list of operations, grouped by service (one group in the per-service view).
  import Badge from './Badge.svelte';
  import GroupTag from './GroupTag.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { serviceKey, type OperationSummary } from '../lib/api';
  import { soapBadge } from '../lib/soap';

  interface Props {
    ops: OperationSummary[];
    hrefOf: (o: OperationSummary) => string;
    isCurrent: (o: OperationSummary) => boolean;
    /** Show the service name as a group heading. */
    grouped?: boolean;
  }
  let { ops, hrefOf, isCurrent, grouped = true }: Props = $props();

  let filter = $state('');
  // One heading per (group, service): two teams calling the same host are two services.
  const groups = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const m = new Map<string, OperationSummary[]>();
    for (const o of ops) {
      if (q && !`${o.service} ${o.group ?? ''} ${o.op}`.toLowerCase().includes(q)) continue;
      const k = serviceKey(o.group, o.service);
      m.set(k, [...(m.get(k) ?? []), o]);
    }
    return [...m.entries()];
  });
  const methodTone = (m: string) => (m === 'GET' ? 'info' : m === 'DELETE' ? 'danger' : 'accent');
  // A logical GraphQL operation shows its kind and name, not the shared endpoint path.
  const gqlTone = (kind: string) => (kind === 'mutation' ? 'accent' : kind === 'subscription' ? 'warning' : 'info');
</script>

<div class="search"><input type="search" placeholder={t('ct.filter')} aria-label={t('ct.filter')} bind:value={filter} /></div>
<nav class="tree" aria-label={t('ct.explorer')}>
  {#each groups as [key, list] (key)}
    {#if grouped}<h2 class="fs-4">{list[0].service} <GroupTag group={list[0].group} /> <span class="subtle">· {list.length}</span></h2>{/if}
    <ul>
      {#each list as o (o.op)}
        <li>
          <a href={hrefOf(o)} aria-current={isCurrent(o) ? 'page' : undefined}>
            {#if o.graphql}
              <Badge tone={gqlTone(o.graphql.type)}>{o.graphql.type.toUpperCase()}</Badge>
              <span class="path mono" title={`${t('gql.badge')} · ${o.method} ${o.graphql.endpoint}`}>{o.graphql.anonymous ? t('gql.anonymous') : o.graphql.name}</span>
            {:else if o.soap}
              <!-- a logical SOAP operation: its name, the shared endpoint in the title -->
              <Badge tone="accent">{soapBadge(o.soap.format)}</Badge>
              <span class="path mono" title={`${o.soap.method} ${o.soap.endpoint}#${o.soap.name}`}>{o.soap.name}</span>
            {:else}
              <Badge tone={methodTone(o.method)}>{o.method}</Badge>
              <span class="path mono" title={o.pathTemplate}>{o.pathTemplate}</span>
            {/if}
            {#if o.fewSamples}<span class="flag" title={t('ct.fewSamples')} role="img" aria-label={t('ct.fewSamples')}>!</span>{/if}
          </a>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="subtle empty">{t('table.empty')}</p>
  {/each}
</nav>

<style>
  .search { padding: var(--s-3); border-bottom: 1px solid var(--border); }
  .tree { padding: var(--s-2); }
  .tree h2 { padding: var(--s-2) var(--s-2) var(--s-1); color: var(--fg-muted); }
  ul { list-style: none; margin: 0; padding: 0; }
  a { display: flex; align-items: center; gap: var(--s-2); padding: 5px var(--s-2); border-radius: var(--r-md); text-decoration: none; color: var(--fg); min-width: 0; }
  a:hover { background: var(--surface-2); }
  a[aria-current='page'] { background: var(--accent-soft); }
  .path { flex: 1; min-width: 0; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .flag { flex: none; display: inline-grid; place-items: center; width: 18px; height: 18px; border-radius: 50%; background: var(--warning-soft); color: var(--warning); font-weight: 700; font-size: 0.75rem; }
  .empty { padding: var(--s-3); }
</style>
