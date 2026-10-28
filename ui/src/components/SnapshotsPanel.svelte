<script lang="ts">
  import { serverText } from '../lib/server-text';
  // Snapshot timeline of one service and the breaking / non-breaking diff between two dates.
  import Card from './Card.svelte';
  import Badge from './Badge.svelte';
  import StatusPill from './StatusPill.svelte';
  import DiffView from './DiffView.svelte';
  import Loading from './Loading.svelte';
  import InfoTip from './InfoTip.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { fmtDate, fmtNum } from '../lib/format';

  let { service, group }: { service: string; group?: string } = $props();

  const snaps = resource(() => (service ? api.contracts.snapshots(service, group) : Promise.resolve([])));
  let fromId = $state('');
  let toId = $state('');
  $effect(() => {
    const s = snaps.data;
    if (s && s.length >= 2) {
      fromId = s[s.length - 2].id;
      toId = s[s.length - 1].id;
    }
  });
  const diff = resource(async () => (fromId && toId && fromId !== toId ? await api.contracts.diff(service, fromId, toId, group) : null));
</script>

<div class="stack">
  <Card title={t('ct.snap.title', { service })} subtitle={t('ct.snap.subtitle')}>
    {#if snaps.data}
      <ol class="timeline">
        {#each snaps.data as s (s.id)}
          <li>
            <b>{fmtDate(s.date, false)}</b>
            <span class="subtle">{t('ct.snap.calls', { n: fmtNum(s.calls) })}</span>
            {#if s.breaking}<Badge tone="danger">{t('ct.snap.breaking', { n: s.breaking })}</Badge>{/if}
            {#if s.nonBreaking}<Badge tone="success">{t('ct.snap.nonBreaking', { n: s.nonBreaking })}</Badge>{/if}
            {#if !s.breaking && !s.nonBreaking}<Badge>{t('ct.snap.baseline')}</Badge>{/if}
          </li>
        {/each}
      </ol>
      <div class="row pick">
        <label>{t('ct.snap.from')}
          <select bind:value={fromId}>{#each snaps.data as s (s.id)}<option value={s.id}>{fmtDate(s.date, false)}</option>{/each}</select>
        </label>
        <label>{t('ct.snap.to')}
          <select bind:value={toId}>{#each snaps.data as s (s.id)}<option value={s.id}>{fmtDate(s.date, false)}</option>{/each}</select>
        </label>
        <InfoTip id="ct.snapshot" />
      </div>
    {:else}<Loading error={snaps.error} />{/if}
  </Card>
  {#if diff.data}
    <Card title={t('ct.snap.changes')}>
      {#if diff.data.changes.length === 0}
        <p class="muted">{t('ct.snap.noChanges')}</p>
      {:else}
        <ul class="changes">
          {#each diff.data.changes as c (c.path + c.kind)}
            <li>
              <StatusPill value={c.severity} />
              <div class="grow">
                <b>{serverText(c.detail)}</b>
                <div class="subtle mono">{c.op} · {c.path}</div>
                {#if c.from || c.to}<div class="mono">{c.from ?? '—'} → {c.to ?? '—'}</div>{/if}
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    </Card>
    <Card title={t('ct.snap.json')} flush><div class="pad"><DiffView before={diff.data.before} after={diff.data.after} format="json" /></div></Card>
  {/if}
</div>

<style>
  .timeline { list-style: none; margin: 0 0 var(--s-4); padding: 0 0 0 var(--s-4); border-left: 2px solid var(--border-strong); display: flex; flex-direction: column; gap: var(--s-3); }
  .timeline li { position: relative; display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; }
  .timeline li::before { content: ''; position: absolute; left: calc(-1 * var(--s-4) - 6px); width: 10px; height: 10px; border-radius: 50%; background: var(--accent); border: 2px solid var(--surface); }
  .pick { align-items: flex-end; }
  .pick label { display: flex; flex-direction: column; gap: 4px; min-width: 150px; }
  .changes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-3); }
  .changes li { display: flex; gap: var(--s-3); align-items: flex-start; }
  .pad { padding: 0 var(--s-4) var(--s-4); }
</style>
