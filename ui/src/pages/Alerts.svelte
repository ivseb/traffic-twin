<script lang="ts">
  import InfoTip from '../components/InfoTip.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import Badge from '../components/Badge.svelte';
  import Modal from '../components/Modal.svelte';
  import Switch from '../components/Switch.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { DriftAlert, Webhook } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { fmtAgo, fmtDate, fmtNum, inRange, RANGES, type Range } from '../lib/format';
  import { queryParam, queryTab } from '../lib/tabs.svelte';
  import TimeRange from '../components/TimeRange.svelte';
  import { href } from '../lib/router';
  import ScopeNote from '../components/ScopeNote.svelte';
  import GroupTag from '../components/GroupTag.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { serverText } from '../lib/server-text';

  // Group/Team filter: the server keeps the alerts of the services of the chosen groups.
  const alerts = resource(() => api.alerts.list(scopeGroups()));
  const hooks = resource(() => api.webhooks.list());
  const canResolve = api.capabilities.alertResolve;
  const hookToggle = api.capabilities.webhookToggle;

  const tabs = queryTab('alerts', ['alerts', 'webhooks']);

  let view = $state<'open' | 'all'>('open');
  const range = queryParam<Range>('range', 'all', RANGES);
  let selection = $state<string[]>([]);
  const shown = $derived((alerts.data ?? []).filter((a) => (view === 'all' || a.state !== 'resolved') && inRange(a.firstSeen, range.value)));

  async function bulkSet(ids: string[], state: DriftAlert['state']): Promise<void> {
    try {
      for (const id of ids) await api.alerts.setState(id, state);
      toast(t('al.updated'));
      selection = [];
      alerts.reload();
    } catch (e) {
      toastError(e);
    }
  }

  const cols: Column<DriftAlert>[] = $derived([
    { key: 'severity', label: t('al.col.severity'), sortable: true, help: 'al.severity' },
    { key: 'change', label: t('al.col.change') },
    { key: 'subject', label: t('al.col.subject'), hideBelow: 'sm', value: (a) => `${a.service} ${a.op ?? ''}` },
    { key: 'firstSeen', label: t('al.col.first'), sortable: true, hideBelow: 'md', value: (a) => -new Date(a.firstSeen).getTime() },
    { key: 'state', label: t('al.col.state'), sortable: true },
    { key: 'act', label: '' },
  ]);

  async function setState(a: DriftAlert, s: DriftAlert['state']): Promise<void> {
    try {
      await api.alerts.setState(a.id, s);
      toast(t('al.updated'));
      alerts.reload();
    } catch (e) {
      toastError(e);
    }
  }

  // ---- webhooks
  // Event types of the admin API (Webhook.events).
  const EVENTS: Webhook['events'] = ['contract.drift', 'rule.stale', 'quarantine.opened', 'source.problem', 'kill.changed', 'keyguard.alert', 'pack.published', 'storage.high_watermark'];
  let secret = $state('');
  let secretOpen = $state(false);
  let editOpen = $state(false);
  let wh = $state<Omit<Webhook, 'id'> & { id?: string }>({ name: '', url: 'https://', events: ['contract.drift'], enabled: true });
  let delTarget = $state<Webhook | null>(null);
  let delOpen = $state(false);
  const urlOk = $derived(/^https:\/\/[^\s/]+/.test(wh.url));

  function edit(w?: Webhook): void {
    wh = w ? { ...w, events: [...w.events] } : { name: '', url: 'https://', events: ['contract.drift'], enabled: true };
    editOpen = true;
  }
  function toggleEvent(e: Webhook['events'][number], on: boolean): void {
    wh.events = on ? [...new Set([...wh.events, e])] : wh.events.filter((x) => x !== e);
  }
  async function save(): Promise<void> {
    try {
      const saved = await api.webhooks.save($state.snapshot(wh));
      editOpen = false;
      toast(t('al.hookSaved'));
      if (saved.secret) {
        secret = saved.secret;
        secretOpen = true;
      }
      hooks.reload();
    } catch (e) {
      toastError(e);
    }
  }
  async function test(w: Webhook): Promise<void> {
    try {
      const r = await api.webhooks.test(w.id);
      toast(r.lastDelivery?.ok ? t('al.testOk', { code: r.lastDelivery.httpStatus }) : t('al.testFail', { code: r.lastDelivery?.httpStatus ?? 0 }), r.lastDelivery?.ok ? 'success' : 'danger');
      hooks.reload();
    } catch (e) {
      toastError(e);
    }
  }
  async function remove(): Promise<void> {
    if (!delTarget) return;
    await api.webhooks.remove(delTarget.id);
    toast(t('al.hookDeleted'));
    hooks.reload();
  }
  const SAMPLE = JSON.stringify(
    { type: 'contract.drift', severity: 'breaking', service: 'shipping-ext', op: 'GET /v1/shipments', change: "field 'eta' type changed: string(date-time) -> integer(epoch)", first_seen: '2026-10-22T03:10:00Z', evidence: { calls_after_change: 1840 } },
    null,
    2,
  );
</script>

<PageHeader title={t('al.title')} description={t('al.desc')} help="alerts" breadcrumbs={[{ label: t('nav.alerts') }]} updatedAt={alerts.updatedAt} onrefresh={alerts.reload} refreshing={alerts.loading}>
  {#snippet actions()}
    {#if tabs.value === 'webhooks'}<Button variant="primary" icon="plus" denied={!can('webhooks.manage')} onclick={() => edit()}>{t('al.newHook')}</Button>{/if}
  {/snippet}
</PageHeader>

<Tabs tabs={[{ id: 'alerts', label: t('al.tab.alerts'), count: alerts.data?.filter((a) => a.state === 'open').length }, { id: 'webhooks', label: t('al.tab.webhooks'), count: hooks.data?.length }]} bind:value={tabs.value} label={t('al.title')}>
  {#if tabs.value === 'alerts'}
    {#if alerts.data}
      <ScopeNote />
      <div class="legend" role="note">
        <p><b>{t('al.ack')}</b>: {t('aj.ackEffect')}</p>
        {#if canResolve}<p><b>{t('al.resolve')}</b>: {t('aj.resolveEffect')}</p>{/if}
        <p><b>{tk('status.breaking')}</b>: {t('aj.breaking')} <b>{tk('status.non-breaking')}</b>: {t('aj.nonBreaking')}</p>
        <p data-testid="drift-note">{t('fix5.msg.driftNote')}</p>
      </div>
      <Card flush>
        <Table rows={shown} columns={cols} rowKey={(a) => a.id} caption={t('al.title')} urlKey="al" selectable bind:selection searchText={(a) => `${a.service} ${a.op ?? ''} ${serverText(a.change)} ${a.change}`} empty={t('al.none')}>
          {#snippet bulk(ids)}
            <Button size="sm" title={t('aj.ackEffect')} denied={!can('alerts.manage')} onclick={() => bulkSet(ids, 'acknowledged')}>{t('al.ack')}</Button>
            {#if canResolve}<Button size="sm" title={t('aj.resolveEffect')} denied={!can('alerts.manage')} onclick={() => bulkSet(ids, 'resolved')}>{t('al.resolve')}</Button>{/if}
          {/snippet}
          {#snippet toolbar()}
            <div class="seg" role="group" aria-label={t('al.filter')}>
              <button type="button" aria-pressed={view === 'open'} onclick={() => (view = 'open')}>{t('al.f.open')}</button>
              <button type="button" aria-pressed={view === 'all'} onclick={() => (view = 'all')}>{t('al.f.all')}</button>
            </div>
            <TimeRange bind:value={range.value} />
          {/snippet}
          {#snippet cell(a, col)}
            {#if col.key === 'severity'}
              <StatusPill value={a.severity} />
              <div class="subtle">{tk(`al.type.${a.type}`)}</div>
            {:else if col.key === 'change'}
              <span>{serverText(a.change)}</span>
              {#if a.type === 'contract.drift' && a.severity === 'non-breaking'}<div class="subtle" title={t('fix5.msg.driftNote')}>{t('fix5.msg.driftNote')}</div>{/if}
              {#if a.callsAfterChange}<div class="subtle">{t('al.evidence', { n: fmtNum(a.callsAfterChange) })}</div>{/if}
            {:else if col.key === 'subject'}
              {#if a.op}<a href={href('/contracts/:service/:op', { service: a.service, op: a.op }, { group: a.group ?? '' })}>{a.op}</a><div class="subtle">{a.service} <GroupTag group={a.group} /></div>{:else}{a.service} <GroupTag group={a.group} />{/if}
            {:else if col.key === 'firstSeen'}
              <span title={fmtDate(a.firstSeen)}>{fmtAgo(a.firstSeen)}</span>
            {:else if col.key === 'state'}
              <StatusPill value={a.state} />
            {:else}
              <div class="row-tight">
                {#if a.state === 'open'}<Button size="sm" title={t('aj.ackEffect')} denied={!can('alerts.manage')} onclick={() => setState(a, 'acknowledged')}>{t('al.ack')}</Button>{/if}
                {#if canResolve && a.state !== 'resolved'}<Button size="sm" variant="ghost" title={t('aj.resolveEffect')} denied={!can('alerts.manage')} onclick={() => setState(a, 'resolved')}>{t('al.resolve')}</Button>{/if}
              </div>
            {/if}
          {/snippet}
        </Table>
      </Card>
    {:else}<Loading error={alerts.error} onretry={alerts.reload} />{/if}
  {:else}
    <div class="stack">
      <p class="callout">{t('al.hookIntro')}</p>
      {#if hooks.data}
        {#if hooks.data.length === 0}
          <Card><EmptyState icon="alerts" title={t('al.noHooks')} /></Card>
        {:else}
          <div class="grid-2">
            {#each hooks.data as w (w.id)}
              <Card>
                <div class="stack-sm">
                  <div class="row spread"><b>{w.name}</b>{#if hookToggle}<StatusPill value={w.enabled ? 'active' : 'offline'} />{/if}</div>
                  <code class="url">{w.url}</code>
                  <div class="row-tight">{#each w.events as e (e)}<Badge tone="accent">{e}</Badge>{/each}</div>
                  {#if w.lastDelivery}
                    <p class="subtle">{t('al.lastDelivery', { when: fmtAgo(w.lastDelivery.at), code: w.lastDelivery.httpStatus })} <StatusPill value={w.lastDelivery.ok ? 'ok' : 'error'} /></p>
                  {/if}
                  <div class="row-tight">
                    <Button size="sm" denied={!can('webhooks.manage')} onclick={() => test(w)}>{t('al.test')}</Button>
                    <Button size="sm" denied={!can('webhooks.manage')} onclick={() => edit(w)}>{t('common.edit')}</Button>
                    <Button size="sm" variant="ghost" denied={!can('webhooks.manage')} onclick={() => { delTarget = w; delOpen = true; }}>{t('common.delete')}</Button>
                  </div>
                </div>
              </Card>
            {/each}
          </div>
        {/if}
      {:else}<Loading error={hooks.error} onretry={hooks.reload} />{/if}
      <Card title={t('al.payload')} subtitle={t('al.payloadHint')}><CodeBlock code={SAMPLE} language="json" maxHeight="14rem" /></Card>
    </div>
  {/if}
</Tabs>

<Modal bind:open={editOpen} title={wh.id ? t('al.editHook') : t('al.newHook')}>
  <div class="stack">
    <div class="stack-sm"><label for="wh-n">{t('al.hookName')}</label><input id="wh-n" bind:value={wh.name} /></div>
    <div class="stack-sm">
      <span class="row-tight"><label for="wh-u">URL</label><InfoTip id="al.url" /></span>
      <input id="wh-u" bind:value={wh.url} type="url" spellcheck="false" aria-invalid={urlOk ? undefined : 'true'} />
      <p class="subtle">{t('al.urlHint')}</p>
    </div>
    <fieldset>
      <legend>{t('al.events')} <InfoTip id="al.events" /></legend>
      {#each EVENTS as e (e)}
        <label class="chk"><input type="checkbox" checked={wh.events.includes(e)} onchange={(ev) => toggleEvent(e, ev.currentTarget.checked)} /> {tk(`al.type.${e}`)}</label>
      {/each}
    </fieldset>
    {#if hookToggle}<Switch bind:checked={wh.enabled} label={t('al.enabled')} />{/if}
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (editOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" disabled={!wh.name.trim() || !urlOk || wh.events.length === 0} onclick={save}>{t('common.save')}</Button>
  {/snippet}
</Modal>

<Modal bind:open={secretOpen} title={t('al.secretTitle')}>
  <div class="stack">
    <p class="callout warn">{t('al.secretHint')}</p>
    <CodeBlock code={secret} language="text" />
  </div>
  {#snippet footer()}<Button variant="primary" onclick={() => { secretOpen = false; secret = ''; }}>{t('common.close')}</Button>{/snippet}
</Modal>

<ConfirmDialog bind:open={delOpen} title={t('al.deleteTitle')} message={t('al.deleteMsg', { name: delTarget?.name ?? '' })} confirmLabel={t('common.delete')} onconfirm={remove} />

<style>
  .legend { margin: 0 0 var(--s-3); padding: var(--s-3); border: 1px solid var(--border); border-radius: var(--r-md); background: var(--surface-2); font-size: 0.88rem; }
  .legend p { margin: 0; }
  .legend p + p { margin-top: var(--s-1); }
  .seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--r-sm); overflow: hidden; }
  .seg button { font: inherit; font-size: 0.85rem; font-weight: 600; border: 0; background: var(--surface); color: var(--fg-muted); padding: 0.35rem 0.8rem; cursor: pointer; }
  .seg button[aria-pressed='true'] { background: var(--accent); color: var(--accent-fg); }
  .url { word-break: break-all; }
  fieldset { border: 1px solid var(--border-strong); border-radius: var(--r-sm); display: flex; flex-direction: column; gap: var(--s-2); padding: var(--s-3); margin: 0; }
  legend { font-weight: 600; font-size: 0.9rem; padding: 0 var(--s-1); }
  .chk { display: flex; align-items: center; gap: var(--s-2); font-weight: 500; }
</style>
