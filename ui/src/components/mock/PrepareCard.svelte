<script lang="ts">
  // "Prepara e avvia il mock": one button for archetypes, world, pack, publication and the mock, with the steps in
  // plain words as they run. The packs stay hidden (Advanced > Twin packs, for CI downloads).
  import Card from '../Card.svelte';
  import Button from '../Button.svelte';
  import Field from '../Field.svelte';
  import Icon from '../Icon.svelte';
  import InfoTip from '../InfoTip.svelte';
  import { untrack } from 'svelte';
  import { t, tk } from '../../lib/i18n/index.svelte';
  import { api, type PrepareRun, type PrepareStep, PREPARE_STEPS } from '../../lib/api';
  import { can, session, toastError } from '../../lib/stores.svelte';
  import { fmtTime } from '../../lib/format';
  import { lastPreparation, rememberPreparation } from '../../lib/prepare-memory';

  let { groups, group = $bindable(), kubernetes, ondone }: { groups: string[]; group: string; kubernetes: boolean; ondone?: (r: PrepareRun) => void } = $props();

  const isAdmin = $derived(session.user?.roles.includes('admin') ?? false);
  const canPublish = $derived(can('publish.run'));
  let reason = $state('');
  let run = $state<PrepareRun | null>(null);
  let busy = $state(false);
  // The last preparation of the group, kept in this browser by job id: after a reload the steps and the outcome stay
  // on the page, and a run still going is followed again (usability test #4, m4).
  let restoredAt = $state('');
  // A job the page found running when it opened and is following again (the person left during the preparation).
  let resumed = $state(false);
  // Following a job: the button stays off while it runs, whoever started it (this page, or before a reload).
  let following = $state(false);
  $effect(() => {
    const g = group;
    if (!g || untrack(() => busy)) return;
    const last = lastPreparation(g);
    run = last?.run ?? null;
    restoredAt = last?.at ?? '';
    resumed = false;
    following = false;
    if (!last) return;
    let stop = false;
    const wasRunning = last.run.status === 'running';
    resumed = wasRunning;
    following = wasRunning;
    api.mocks
      .preparation(last.jobId, (r) => {
        if (!stop) {
          run = r;
          rememberPreparation(g, r, last.at);
        }
      })
      .then((r) => {
        if (stop) return;
        if (r) {
          run = r;
          rememberPreparation(g, r, last.at);
          if (wasRunning && r.status === 'running') return;
          if (wasRunning) ondone?.(r);
        }
      })
      .catch(() => {
        /* the server no longer has the job: the outcome kept here stays */
      })
      .finally(() => {
        if (!stop) {
          following = false;
          resumed = false;
        }
      });
    return () => {
      stop = true;
    };
  });
  const working = $derived(busy || following);

  $effect(() => {
    if (isAdmin && !reason && group) reason = t('mk.prep.reasonDefault', { group });
  });

  const steps = $derived<PrepareStep[]>(run?.steps.length ? run.steps : PREPARE_STEPS.map((id) => ({ id, status: 'pending' })));

  async function start(): Promise<void> {
    if (!group) return;
    busy = true;
    run = null;
    const g = group;
    const at = new Date().toISOString();
    restoredAt = '';
    try {
      run = await api.mocks.prepare({ group: g, reason: isAdmin ? reason.trim() : undefined }, (r) => {
        run = r;
        rememberPreparation(g, r, at);
      });
      rememberPreparation(g, run, at);
      ondone?.(run);
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  function icon(s: PrepareStep): 'check' | 'close' | 'clock' | 'dot' {
    if (s.status === 'done') return 'check';
    if (s.status === 'failed') return 'close';
    if (s.status === 'running' || s.status === 'waiting') return 'clock';
    return 'dot';
  }

  function detail(s: PrepareStep): string {
    if (s.code) return tk(`mk.step.code.${s.code}`, s.detail ?? {}, s.code);
    if (s.status !== 'done' || !s.detail) return '';
    return tk(`mk.step.done.${s.id}`, s.detail, '');
  }
</script>

<Card title={t('mk.prep.title')} subtitle={t('mk.prep.subtitle')} tone="accent">
  <div class="stack">
    <div class="row">
      <Field label={t('mk.prep.group')} help="mock.group">
        {#snippet children({ id, describedby })}
          <select {id} aria-describedby={describedby} bind:value={group} disabled={working}>
            {#each groups as g (g)}<option value={g}>{g}</option>{/each}
          </select>
        {/snippet}
      </Field>
      {#if isAdmin}
        <Field label={t('mk.prep.reason')} hint={t('mk.prep.reasonHint')} help="mock.reason">
          {#snippet children({ id, describedby })}
            <input {id} aria-describedby={describedby} bind:value={reason} disabled={busy} maxlength="500" />
          {/snippet}
        </Field>
      {/if}
    </div>
    <p class="subtle">{kubernetes ? t('mk.prep.whatK8s') : t('mk.prep.whatSelf')}</p>
    {#if !canPublish}<p class="callout">{t('mk.prep.needsPublisher')}</p>{/if}
    <div>
      <Button variant="primary" icon="power" loading={working} denied={!can('publish.build')} disabled={!group || (isAdmin && !reason.trim())} onclick={start} data-testid="prepare-button">{t('mk.prep.button')}</Button>
      <InfoTip id="mock.prepare.resume" />
    </div>

    {#if run || busy}
      {#if resumed && restoredAt && !busy}
        <p class="callout" role="status" data-testid="prep-resumed">{t('fix5.prep.resumed', { group, time: fmtTime(restoredAt) })}</p>
      {:else if restoredAt && !busy}<p class="subtle" data-testid="prep-last">{t('fix4.prep.last', { group, time: fmtTime(restoredAt) })}</p>{/if}
      {#if working}<p class="subtle">{t('fix5.prep.keepHint')}</p>{/if}
      <ol class="steps" aria-live="polite" aria-label={t('mk.prep.progress')}>
        {#each steps as s (s.id)}
          <li class={s.status}>
            <span class="ico" aria-hidden="true"><Icon name={icon(s)} /></span>
            <span class="txt">
              <b>{t(`mk.step.${s.id}` as 'mk.step.world')}</b>
              <span class="subtle">{tk(`mk.step.status.${s.status}`)}{#if detail(s)}{' · '}{detail(s)}{/if}</span>
            </span>
          </li>
        {/each}
      </ol>
      {#if run?.status === 'done' && !run.waiting}
        <p class="callout ok">{run.url ? t('mk.prep.doneUrl', { url: run.url }) : t('mk.prep.done')}</p>
      {:else if run?.waiting}
        <p class="callout warn">{t('mk.prep.waitingPublisher', { pack: run.packId ?? '' })} <a href="#/packs">{t('mk.prep.openPacks')}</a></p>
      {:else if run?.status === 'failed'}
        <p class="callout danger">{tk(`mk.err.${run.error}`, {}, t('mk.err.generic', { code: run.error ?? '' }))} <a href="#/packs">{t('mk.prep.openPacks')}</a></p>
      {/if}
    {/if}
  </div>
</Card>

<style>
  .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 16rem), 1fr)); gap: var(--s-3); }
  .steps { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .steps li { display: flex; gap: var(--s-2); align-items: flex-start; }
  .steps .txt { display: flex; flex-direction: column; }
  .ico { display: grid; place-items: center; width: 1.5rem; height: 1.5rem; border-radius: 50%; background: var(--surface-3); color: var(--fg-muted); flex: none; }
  .done .ico { background: var(--success-soft); color: var(--success); }
  .failed .ico { background: var(--danger-soft); color: var(--danger); }
  .running .ico, .waiting .ico { background: var(--warning-soft); color: var(--warning); }
</style>
