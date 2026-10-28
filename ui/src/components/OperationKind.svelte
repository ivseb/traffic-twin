<script lang="ts">
  // "Questa operazione è una lettura" (rules v1.6): how the miner treats one operation, and the choice of a person.
  import Card from './Card.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { fmtDate } from '../lib/format';
  import { opKindState, readByMethod, type OpKindChoice } from '../lib/api/opkinds';

  let { service, op, method, group, graphqlType }: { service: string; op: string; method: string; group: string; graphqlType?: string } = $props();

  const kinds = resource(() => api.opKinds.list(group));
  const st = $derived(opKindState(kinds.data, group, service, op));
  const isRead = $derived(st.choice === 'auto' ? st.autoRead || readByMethod(method, graphqlType) : st.choice === 'read');
  const editable = $derived(can('rules.review'));
  let busy = $state(false);

  async function choose(c: OpKindChoice): Promise<void> {
    if (c === st.choice || busy) return;
    busy = true;
    try {
      await api.opKinds.set(group, service, op, c);
      toast(t('w1.kind.saved'));
      kinds.reload();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  const choices = [
    { c: 'auto', label: () => t('w1.kind.choice.auto') },
    { c: 'read', label: () => t('w1.kind.choice.read') },
    { c: 'write', label: () => t('w1.kind.choice.write') },
  ] as const;
</script>

<Card title={t('w1.kind.title')} subtitle={t('w1.kind.subtitle')}>
  <div class="stack-sm">
    <p>
      <b>{t(isRead ? 'w1.kind.now.read' : 'w1.kind.now.write')}</b>
      {#if st.decision}
        {t('w1.kind.why.person', { by: st.decision.setBy, date: fmtDate(st.decision.setAt, false) })}
      {:else if st.autoRead}
        {t('w1.kind.why.auto')}
      {:else}
        {t('w1.kind.why.method', { method: graphqlType ? graphqlType.toUpperCase() : method })}
      {/if}
    </p>
    <div class="seg" role="radiogroup" aria-label={t('w1.kind.isRead')}>
      {#each choices as ch (ch.c)}
        <button type="button" role="radio" aria-checked={st.choice === ch.c} disabled={!editable || busy || !kinds.data} onclick={() => choose(ch.c)}>{ch.label()}</button>
      {/each}
    </div>
    <p class="subtle">{editable ? t('w1.kind.next') : t('w1.kind.readonly')}</p>
  </div>
</Card>

<style>
  .seg { display: inline-flex; flex-wrap: wrap; border: 1px solid var(--border-strong); border-radius: var(--r-md); overflow: hidden; width: fit-content; }
  .seg button { font: inherit; font-size: 0.85rem; font-weight: 600; border: 0; background: var(--surface); color: var(--fg-muted); padding: 4px 12px; cursor: pointer; }
  .seg button[aria-checked='true'] { background: var(--accent); color: var(--accent-fg); }
  .seg button:disabled { cursor: default; }
</style>
