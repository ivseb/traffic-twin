<script lang="ts">
  // "Date relative": for each date field of the service's contract, the range of offsets between the date and the
  // moment of the call (learned from the traffic, x-tt-value.date_offset) and the range a person chose for that
  // field name in the group (/api/v1/date-offsets), which wins. The world and the mock generate clock + offset.
  import Card from './Card.svelte';
  import Loading from './Loading.svelte';
  import DateOffsetRow from './DateOffsetRow.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api, dateFields } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';

  let { doc, group }: { doc: Record<string, unknown> | undefined; group: string } = $props();

  const fields = $derived(doc ? dateFields(doc) : []);
  const offsets = resource(() => (fields.length ? api.dateOffsets.list(group) : Promise.resolve([])));
  const canEdit = $derived(can('worlds.generate') || can('rules.edit'));
  const byField = $derived(new Map((offsets.data ?? []).map((o) => [o.field, o])));
</script>

<Card title={t('dof.title')} subtitle={t('dof.subtitle')}>
  <div class="stack-sm">
    <p>{t('dof.why')}</p>
    <p class="subtle">{t('dof.when')}</p>
    <p class="subtle">{group ? t('dof.scope', { group }) : t('dof.scopeNoGroup')}</p>
    <details>
      <summary>{t('dof.how.title')}</summary>
      <ul class="how">
        <li>{t('dof.how.learned')}</li>
        <li>{t('dof.how.syntax')}</li>
        <li>{t('dof.how.past')}</li>
        <li>{t('dof.how.none')}</li>
      </ul>
    </details>
    {#if !doc}
      <Loading lines={2} />
    {:else if !fields.length}
      <p class="subtle">{t('dof.none')}</p>
    {:else if offsets.error}
      <Loading error={offsets.error} onretry={offsets.reload} />
    {:else if !offsets.data}
      <Loading lines={2} />
    {:else}
      {#if !canEdit}<p class="subtle">{t('dof.readOnly')}</p>{/if}
      <div>
        {#each fields as f (f.field)}
          <DateOffsetRow item={f} {group} saved={byField.get(f.field)} {canEdit} onchanged={offsets.reload} />
        {/each}
      </div>
    {/if}
  </div>
</Card>

<style>
  .how { margin: var(--s-2) 0 0; padding-left: var(--s-5); display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  summary { cursor: pointer; font-weight: 600; }
</style>
