<script lang="ts">
  // "Formato degli id": for each id domain of the service's contract (x-tt-value kind id), the shape of the synthetic
  // ids the world and the mock use, per group (admin-api 1.18.0, /api/v1/id-formats).
  import Card from './Card.svelte';
  import Loading from './Loading.svelte';
  import IdFormatRow from './IdFormatRow.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api, idDomains } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';

  let { doc, group }: { doc: Record<string, unknown> | undefined; group: string } = $props();

  const domains = $derived(doc ? idDomains(doc) : []);
  const formats = resource(() => (domains.length ? api.idFormats.list(group) : Promise.resolve([])));
  const canEdit = $derived(can('worlds.generate') || can('rules.edit'));
  const byDomain = $derived(new Map((formats.data ?? []).map((f) => [f.domain, f])));
</script>

<Card title={t('idf.title')} subtitle={t('idf.subtitle')}>
  <div class="stack-sm">
    <p>{t('idf.why')}</p>
    <p class="subtle">{group ? t('idf.scope', { group }) : t('idf.scopeNoGroup')}</p>
    <details>
      <summary>{t('idf.grammar.title')}</summary>
      <ul class="grammar">
        {#each ['idf.grammar.N', 'idf.grammar.A', 'idf.grammar.a', 'idf.grammar.X', 'idf.grammar.lit', 'idf.grammar.quote', 'idf.grammar.ref', 'idf.grammar.seg', 'idf.grammar.fn', 'idf.grammar.b64', 'idf.grammar.min'] as const as k (k)}
          <li>{t(k)}</li>
        {/each}
      </ul>
    </details>
    {#if !doc}
      <Loading lines={2} />
    {:else if !domains.length}
      <p class="subtle">{t('idf.none')}</p>
    {:else if formats.error}
      <Loading error={formats.error} onretry={formats.reload} />
    {:else}
      {#if !canEdit}<p class="subtle">{t('idf.readOnly')}</p>{/if}
      <div>
        {#each domains as d (d.domain)}
          <IdFormatRow item={d} {group} saved={byDomain.get(d.domain)} {canEdit} onchanged={formats.reload} />
        {/each}
      </div>
    {/if}
  </div>
</Card>

<style>
  .grammar { margin: var(--s-2) 0 0; padding-left: var(--s-5); display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  summary { cursor: pointer; font-weight: 600; }
</style>
