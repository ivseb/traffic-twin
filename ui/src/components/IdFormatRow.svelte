<script lang="ts">
  // One id domain of the "Formato degli id" card: the saved format, an input with a live preview of the first ids
  // (debounced server check), save and back-to-default.
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api, ApiError, type IdDomain, type IdFormat, type IdFormatError } from '../lib/api';
  import { toast, toastError } from '../lib/stores.svelte';
  import { fmtDate } from '../lib/format';
  import { exampleIdOf, idFormatErrorText } from '../lib/idfmt';

  let { item, group, saved, canEdit, onchanged }: { item: IdDomain; group: string; saved?: IdFormat; canEdit: boolean; onchanged?: () => void } = $props();

  let value = $state('');
  let synced = $state<string | undefined>(undefined);
  $effect(() => {
    // Follow the saved format when it changes (after a save or a reload), keeping what the user is typing otherwise.
    const f = saved?.format ?? '';
    if (synced !== f) {
      synced = f;
      value = f;
    }
  });

  let preview = $state<string[]>([]);
  let capacity = $state('');
  let error = $state<IdFormatError | null>(null);
  let checking = $state(false);
  let seq = 0;
  $effect(() => {
    const v = value.trim();
    const n = ++seq;
    if (!v) {
      preview = [];
      capacity = '';
      error = null;
      checking = false;
      return;
    }
    checking = true;
    const h = setTimeout(async () => {
      try {
        const r = await api.idFormats.preview(v, item.domain);
        if (n !== seq) return;
        if (r.valid) {
          preview = r.preview.slice(0, 3);
          capacity = r.capacityLabel;
          error = null;
        } else {
          preview = [];
          capacity = '';
          error = r.error;
        }
      } catch {
        if (n === seq) preview = [];
      } finally {
        if (n === seq) checking = false;
      }
    }, 300);
    return () => clearTimeout(h);
  });

  let busy = $state(false);
  async function save(): Promise<void> {
    busy = true;
    try {
      await api.idFormats.set(group, item.domain, value.trim());
      toast(t('idf.saved', { domain: item.domain }));
      onchanged?.();
    } catch (e) {
      const d = e instanceof ApiError && e.serverCode === 'invalid_format' ? e.details?.[0] : undefined;
      if (d?.code) error = { code: d.code as IdFormatError['code'], at: d.at ?? 0 };
      else toastError(e);
    } finally {
      busy = false;
    }
  }
  async function remove(): Promise<void> {
    busy = true;
    try {
      await api.idFormats.remove(group, item.domain);
      toast(t('idf.removed', { domain: item.domain }));
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  const errText = $derived(error ? t('idf.errorAt', { msg: idFormatErrorText(error.code, tk), pos: error.at + 1 }) : undefined);
  const dirty = $derived(value.trim() !== (saved?.format ?? ''));
</script>

<div class="row-item">
  <div class="head">
    <h3 class="fs-4">{t('idf.domain', { domain: item.domain })}</h3>
    {#if item.fields.length}<span class="subtle">{t('idf.fields', { fields: item.fields.join(', ') })}</span>{/if}
  </div>
  <p class="subtle">
    {#if saved}{t('idf.current', { format: saved.format, who: saved.updatedBy || '—', when: saved.updatedAt ? fmtDate(saved.updatedAt) : '—' })}{:else}{t('idf.default', { example: exampleIdOf(item.domain) })}{/if}
  </p>
  <Field label={t('idf.input', { domain: item.domain })} hint={t('idf.inputHint')} error={errText}>
    {#snippet children({ id, describedby })}
      <input {id} aria-describedby={describedby} class="mono" bind:value maxlength="64" spellcheck="false" autocomplete="off" disabled={!canEdit} placeholder="NN-NNNNNN-NNNN-NNNNNN" />
    {/snippet}
  </Field>
  {#if value.trim()}
    <div class="preview" aria-live="polite">
      <span class="lbl">{t('idf.preview')}:</span>
      {#if checking && !preview.length}<span class="subtle">{t('idf.checking')}</span>{/if}
      {#each preview as id (id)}<code>{id}</code>{/each}
      {#if capacity}<span class="subtle">{t('idf.capacity', { n: capacity })}</span>{/if}
    </div>
    {#if preview.length}<p class="subtle note">{t('idf.previewNote')}</p>{/if}
  {/if}
  {#if canEdit}
    <div class="actions">
      <Button variant="primary" size="sm" loading={busy} disabled={!value.trim() || !dirty || !!error} onclick={save}>{t('idf.save')}</Button>
      {#if saved}<Button size="sm" disabled={busy} onclick={remove}>{t('idf.remove')}</Button>{/if}
    </div>
  {/if}
</div>

<style>
  .row-item { display: flex; flex-direction: column; gap: var(--s-2); padding: var(--s-3) 0; border-top: 1px solid var(--border); }
  .row-item:first-child { border-top: 0; padding-top: 0; }
  .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--s-2); }
  .head h3 { margin: 0; }
  .preview { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s-2); }
  .preview .lbl { font-weight: 600; }
  .preview code { font-size: 0.86rem; }
  .note { font-size: 0.82rem; }
  .actions { display: flex; gap: var(--s-2); }
</style>
