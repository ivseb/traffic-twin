<script lang="ts">
  // The test session of a running mock: pick or create a session, apply a scenario of the pack, switch the faults,
  // advance the virtual clock, reset. Every action is a control call the console sends to the mock.
  import Button from '../Button.svelte';
  import Field from '../Field.svelte';
  import InfoTip from '../InfoTip.svelte';
  import CodeBlock from '../CodeBlock.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api, clockStep, type RunningMock } from '../../lib/api';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtDate } from '../../lib/format';

  let { mock, onchanged }: { mock: RunningMock; onchanged?: () => void } = $props();

  interface Preset {
    id: string;
    name: string;
    description?: string;
  }
  let sessionId = $state('default');
  let presets = $state<Preset[]>([]);
  let presetsFor = '';
  let newId = $state('');
  let amount = $state(1);
  let unit = $state<'s' | 'm' | 'h' | 'd'>('d');
  let busy = $state('');
  let lastAnswer = $state('');

  const session = $derived(mock.sessions.find((s) => s.id === sessionId) ?? mock.sessions[0]);
  const allowed = $derived(can('scenarios.edit') && mock.online);

  $effect(() => {
    const id = mock.id;
    const pack = mock.packId;
    if (!mock.online || `${id}|${pack}` === presetsFor) return;
    presetsFor = `${id}|${pack}`;
    api.mocks.command(id, 'GET', '/__tt/scenarios').then(
      (r) => (presets = r.status === 200 && Array.isArray(r.body) ? (r.body as Preset[]) : []),
      () => (presets = []),
    );
  });

  async function call(what: string, method: 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, ok?: string): Promise<boolean> {
    busy = what;
    try {
      const r = await api.mocks.command(mock.id, method, path, body);
      lastAnswer = JSON.stringify(r.body, null, 2) ?? '';
      if (r.status >= 400) {
        const b = r.body as { message?: string; code?: string } | null;
        toast(t('mk.ses.refused', { status: r.status, reason: b?.message ?? b?.code ?? '' }), 'danger');
        return false;
      }
      if (ok) toast(ok);
      onchanged?.();
      return true;
    } catch (e) {
      toastError(e);
      return false;
    } finally {
      busy = '';
    }
  }

  const sp = (id: string) => `/__tt/sessions/${encodeURIComponent(id)}`;

  async function create(): Promise<void> {
    const id = newId.trim();
    if (await call('create', 'POST', '/__tt/sessions', id ? { id } : {}, t('mk.ses.created'))) {
      if (id) sessionId = id;
      newId = '';
    }
  }
  async function preset(p: Preset): Promise<void> {
    await call('preset:' + p.id, 'POST', `${sp(session.id)}/scenario`, { preset: p.id }, t('mk.ses.presetApplied', { name: p.name }));
  }
  async function faults(mode: 'observed' | 'off'): Promise<void> {
    await call('faults', 'PUT', `${sp(session.id)}/faults`, { mode }, mode === 'off' ? t('mk.ses.faultsOff') : t('mk.ses.faultsObserved'));
  }
  async function advance(): Promise<void> {
    const by = clockStep(amount, unit);
    if (!by) return;
    await call('clock', 'POST', `${sp(session.id)}/clock/advance`, { by }, t('mk.ses.advanced', { by }));
  }
  async function reset(): Promise<void> {
    await call('reset', 'POST', `${sp(session.id)}/reset`, undefined, t('mk.ses.resetDone'));
  }
  async function remove(): Promise<void> {
    if (await call('delete', 'DELETE', sp(session.id), undefined, t('mk.ses.deleted'))) sessionId = 'default';
  }
</script>

{#if !mock.online}
  <p class="callout warn">{t('mk.ses.offline')}</p>
{:else}
  <div class="stack">
    <div class="row">
      <Field label={t('mk.ses.session')} help="mock.session">
        {#snippet children({ id, describedby })}
          <select {id} aria-describedby={describedby} bind:value={sessionId}>
            {#each mock.sessions as s (s.id)}<option value={s.id}>{s.id}{s.scenario ? ` · ${s.scenario}` : ''}</option>{/each}
          </select>
        {/snippet}
      </Field>
      <Field label={t('mk.ses.newId')} hint={t('mk.ses.newIdHint')}>
        {#snippet children({ id, describedby })}
          <div class="inline">
            <input {id} aria-describedby={describedby} bind:value={newId} maxlength="64" pattern="[A-Za-z0-9_-]*" placeholder="test-checkout-1" />
            <Button icon="plus" loading={busy === 'create'} denied={!allowed} onclick={create}>{t('mk.ses.create')}</Button>
          </div>
        {/snippet}
      </Field>
    </div>
    {#if session}
      <p class="subtle">
        {t('mk.ses.clockNow')} <InfoTip id="mock.clock" />: <b>{fmtDate(session.clock)}</b> · {t('mk.ses.calls', { n: session.calls })} · {t('mk.ses.faultsMode')}: <b>{session.faults}</b>
        {#if session.scenario}· {t('mk.ses.scenario')}: <b>{session.scenario}</b>{/if}
      </p>
      <p class="subtle">{t('mk.ses.header', { id: session.id })}</p>
    {/if}

    <div>
      <h3 class="fs-4">{t('mk.ses.scenarios')} <InfoTip id="mock.scenario" /></h3>
      {#if presets.length}
        <div class="presets">
          {#each presets as p (p.id)}
            <div class="preset">
              <b>{p.name}</b>
              {#if p.description}<span class="subtle">{p.description}</span>{/if}
              <div><Button size="sm" loading={busy === 'preset:' + p.id} denied={!allowed} onclick={() => preset(p)}>{t('mk.ses.apply')}</Button></div>
            </div>
          {/each}
        </div>
      {:else}
        <p class="subtle">{t('mk.ses.noPresets')}</p>
      {/if}
    </div>

    <div class="grid2">
      <div>
        <h3 class="fs-4">{t('mk.ses.faults')} <InfoTip id="mock.faults" /></h3>
        <div class="inline">
          <Button size="sm" loading={busy === 'faults'} denied={!allowed} onclick={() => faults('observed')}>{t('mk.ses.faultsOnBtn')}</Button>
          <Button size="sm" loading={busy === 'faults'} denied={!allowed} onclick={() => faults('off')}>{t('mk.ses.faultsOffBtn')}</Button>
        </div>
      </div>
      <div>
        <h3 class="fs-4">{t('mk.ses.clock')} <InfoTip id="mock.clock" /></h3>
        <div class="inline">
          <input type="number" min="1" max="999999" bind:value={amount} aria-label={t('mk.ses.amount')} class="num" />
          <select bind:value={unit} aria-label={t('mk.ses.unit')}>
            <option value="m">{t('mk.unit.m')}</option>
            <option value="h">{t('mk.unit.h')}</option>
            <option value="d">{t('mk.unit.d')}</option>
            <option value="s">{t('mk.unit.s')}</option>
          </select>
          <Button size="sm" icon="clock" loading={busy === 'clock'} denied={!allowed} disabled={!clockStep(amount, unit)} onclick={advance}>{t('mk.ses.advance')}</Button>
        </div>
      </div>
    </div>
    <div class="inline">
      <Button size="sm" icon="refresh" loading={busy === 'reset'} denied={!allowed} onclick={reset}>{t('mk.ses.reset')}</Button>
      {#if session && session.id !== 'default'}<Button size="sm" variant="danger" icon="trash" loading={busy === 'delete'} denied={!allowed} onclick={remove}>{t('mk.ses.delete')}</Button>{/if}
    </div>
    {#if lastAnswer}<CodeBlock code={lastAnswer} title={t('mk.ses.answer')} language="json" maxHeight="14rem" />{/if}
  </div>
{/if}

<style>
  .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 16rem), 1fr)); gap: var(--s-3); }
  .inline { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; }
  .presets { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 15rem), 1fr)); gap: var(--s-2); margin-top: var(--s-1); }
  .preset { display: flex; flex-direction: column; gap: 4px; border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3); }
  .grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr)); gap: var(--s-4); }
  .num { max-width: 6rem; }
</style>
