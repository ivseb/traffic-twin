<script lang="ts">
  // One date field of the "Date relative" card: the learned range, the chosen one, an editor with a preview of the
  // dates it gives today, save and back-to-learned.
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import { t, locale } from '../lib/i18n/index.svelte';
  import { api, rangeDates, rangeProblem, type DateField, type DateOffset } from '../lib/api';
  import { toast, toastError } from '../lib/stores.svelte';
  import { fmtDate } from '../lib/format';

  let { item, group, saved, canEdit, onchanged }: { item: DateField; group: string; saved?: DateOffset; canEdit: boolean; onchanged?: () => void } = $props();

  let min = $state('');
  let max = $state('');
  let synced = $state<string | undefined>(undefined);
  $effect(() => {
    // Follow the saved range (or the learned one) when it changes, keeping what the person is typing otherwise.
    const cur = saved ? `${saved.min}/${saved.max}` : item.learned ? `${item.learned.min}/${item.learned.max}` : '';
    if (synced !== cur) {
      synced = cur;
      min = saved?.min ?? item.learned?.min ?? '';
      max = saved?.max ?? item.learned?.max ?? '';
    }
  });

  const problem = $derived(min.trim() || max.trim() ? rangeProblem(min, max) : null);
  const now = new Date();
  const fmt = (d: Date) =>
    new Intl.DateTimeFormat(locale(), item.format === 'date' ? { day: '2-digit', month: '2-digit', year: 'numeric' } : { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(d);
  const range = $derived(min.trim() && max.trim() && !problem ? rangeDates(now, min.trim(), max.trim()) : null);
  const dirty = $derived(min.trim() !== (saved?.min ?? '') || max.trim() !== (saved?.max ?? ''));

  let busy = $state(false);
  async function save(): Promise<void> {
    busy = true;
    try {
      await api.dateOffsets.set(group, item.field, min.trim(), max.trim());
      toast(t('dof.saved', { field: item.field }));
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  async function remove(): Promise<void> {
    busy = true;
    try {
      await api.dateOffsets.remove(group, item.field);
      toast(t('dof.removed', { field: item.field }));
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="row-item" data-testid="date-offset-row">
  <div class="head">
    <h3 class="fs-4 mono">{item.field}</h3>
    <span class="subtle">{item.format === 'date' ? t('dof.format.date') : t('dof.format.dateTime')}</span>
  </div>
  <p class="subtle">
    {#if item.learned}{t('dof.learned', { min: item.learned.min, max: item.learned.max })}{:else}{t('dof.learnedNone')}{/if}
  </p>
  <p class:subtle={!saved}>
    {#if saved}<b>{t('dof.override', { min: saved.min, max: saved.max, who: saved.updatedBy || '—', when: saved.updatedAt ? fmtDate(saved.updatedAt) : '—' })}</b>{:else}{t('dof.overrideNone')}{/if}
  </p>
  {#if canEdit}
    <div class="grid2">
      <Field label={t('dof.min')} hint={t('dof.minHint')} error={problem === 'min' ? t('dof.err.min') : problem === 'order' ? t('dof.err.order') : undefined}>
        {#snippet children({ id, describedby })}
          <input {id} aria-describedby={describedby} class="mono" bind:value={min} maxlength="8" spellcheck="false" autocomplete="off" placeholder="+30d" />
        {/snippet}
      </Field>
      <Field label={t('dof.max')} hint={t('dof.maxHint')} error={problem === 'max' ? t('dof.err.max') : undefined}>
        {#snippet children({ id, describedby })}
          <input {id} aria-describedby={describedby} class="mono" bind:value={max} maxlength="8" spellcheck="false" autocomplete="off" placeholder="+365d" />
        {/snippet}
      </Field>
    </div>
  {/if}
  {#if range}
    <p class="preview" aria-live="polite" data-testid="date-offset-preview">{t('dof.preview', { today: fmt(now), min: min.trim(), max: max.trim(), from: fmt(range.from), to: fmt(range.to) })}</p>
  {:else if !item.learned && !saved && !min.trim() && !max.trim()}
    <p class="preview subtle">{t('dof.previewClock', { today: fmt(now) })}</p>
  {/if}
  {#if canEdit}
    <div class="actions">
      <Button variant="primary" size="sm" loading={busy} disabled={!min.trim() || !max.trim() || !!problem || !dirty} onclick={save}>{t('dof.save')}</Button>
      {#if saved}<Button size="sm" disabled={busy} onclick={remove}>{t('dof.remove')}</Button>{/if}
    </div>
  {/if}
</div>

<style>
  .row-item { display: flex; flex-direction: column; gap: var(--s-2); padding: var(--s-3) 0; border-top: 1px solid var(--border); }
  .row-item:first-child { border-top: 0; padding-top: 0; }
  .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--s-2); }
  .head h3 { margin: 0; }
  .grid2 { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fit, minmax(min(100%, 200px), 1fr)); }
  .preview { margin: 0; }
  .actions { display: flex; gap: var(--s-2); }
  p { margin: 0; }
</style>
