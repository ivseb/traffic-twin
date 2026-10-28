<script lang="ts">
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { EventsExportJob } from '../lib/api';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { fmtBytes, fmtNum } from '../lib/format';
  import { saveBlob } from '../lib/download';
  import { resource } from '../lib/resource.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import { exportServices, localInput as local, rangeFromNow } from '../lib/export-form';

  const now = new Date();
  let from = $state(local(new Date(now.getTime() - 7 * 86400000)));
  let to = $state(local(now));
  // The services of the Group/Team filter: the export is limited to one of them, or covers every service.
  const services = resource(() => api.services.list(scopeGroups()).catch(() => []));
  const choices = $derived(exportServices(services.data ?? []));
  let service = $state('');
  // A service that left the list (filter changed) is no longer chosen.
  $effect(() => {
    if (service && !choices.includes(service)) service = '';
  });
  function quick(hours: number): void {
    const r = rangeFromNow(hours, new Date());
    from = r.from;
    to = r.to;
  }
  let format = $state<'ocel2-json' | 'jsonl'>('ocel2-json');
  let busy = $state(false);
  let job = $state<EventsExportJob | null>(null);

  const rangeOk = $derived(from !== '' && to !== '' && new Date(from) < new Date(to));

  async function run(): Promise<void> {
    busy = true;
    job = null;
    try {
      job = await api.events.export({ from: new Date(from).toISOString(), to: new Date(to).toISOString(), format, service: service || undefined });
      toast(t('ev.ready'));
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  async function download(): Promise<void> {
    if (!job) return;
    try {
      const { filename, blob } = await api.events.download(job);
      saveBlob(filename, blob);
    } catch (e) {
      toastError(e);
    }
  }
</script>

<PageHeader title={t('ev.title')} description={t('ev.desc')} help="events" breadcrumbs={[{ label: t('nav.events') }]} />

<div class="stack">
  <ScopeNote />
  <p class="callout" role="note">{t('ej.what')}</p>
  <p class="callout warn" role="note"><b>{t('ev.warnTitle')}</b> {t('ev.warn')}</p>
  <Card title={t('ev.form')}>
    <form class="stack form" onsubmit={(e) => { e.preventDefault(); void run(); }}>
      <div class="quick" role="group" aria-label={t('ej.quick')}>
        <Button size="sm" onclick={() => quick(24)}>{t('ej.last24h')}</Button>
        <Button size="sm" onclick={() => quick(24 * 7)}>{t('ej.last7d')}</Button>
        <Button size="sm" onclick={() => quick(24 * 30)}>{t('ej.last30d')}</Button>
      </div>
      <Field label={t('ev.from')}>
        {#snippet children({ id })}<input {id} type="datetime-local" bind:value={from} />{/snippet}
      </Field>
      <Field label={t('ev.to')} error={rangeOk || !from || !to ? '' : t('ev.rangeInvalid')}>
        {#snippet children({ id, describedby })}<input {id} type="datetime-local" bind:value={to} aria-describedby={describedby} />{/snippet}
      </Field>
      <Field label={t('ev.service')} hint={t('ev.serviceHint')}>
        {#snippet children({ id, describedby })}
          <select {id} bind:value={service} aria-describedby={describedby}>
            <option value="">{t('ej.allServices')}</option>
            {#each choices as name (name)}<option value={name}>{name}</option>{/each}
          </select>
        {/snippet}
      </Field>
      <Field label={t('ev.format')} hint={t('ev.formatHint')}>
        {#snippet children({ id, describedby })}
          <select {id} bind:value={format} aria-describedby={describedby}>
            <option value="ocel2-json">OCEL 2.0 (JSON)</option>
            <option value="jsonl">JSON Lines</option>
          </select>
        {/snippet}
      </Field>
      <div><Button type="submit" variant="primary" icon="download" loading={busy} disabled={!rangeOk} denied={!can('events.export')}>{t('ev.run')}</Button></div>
    </form>
  </Card>

  {#if job}
    <Card title={t('ev.result')}>
      <div class="stack-sm">
        <p>{t('ev.resultText', { size: fmtBytes(job.bytes) })}{#if job.events !== undefined} · {t('ev.events', { n: fmtNum(job.events) })}{/if}</p>
        <div><Button variant="primary" icon="download" onclick={download}>{t('ev.download')}</Button></div>
        <p class="subtle">{t('ev.once')}</p>
      </div>
    </Card>
  {/if}
</div>

<style>
  .form { max-width: 30rem; }
  .quick { display: flex; gap: var(--s-2); flex-wrap: wrap; }
</style>
