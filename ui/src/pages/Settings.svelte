<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Field from '../components/Field.svelte';
  import Switch from '../components/Switch.svelte';
  import Loading from '../components/Loading.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import Badge from '../components/Badge.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { i18n, setLang, type Lang } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { Settings, EnvName } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, refreshStatus, setTheme, theme, toast, toastError, type ThemeChoice } from '../lib/stores.svelte';
  import { fmtBytes, fmtDate, fmtNum, fmtPct } from '../lib/format';
  import type { StorageLevel } from '../lib/api';
  import { queryTab } from '../lib/tabs.svelte';

  const loaded = resource(() => api.settings.get());
  let form = $state<Settings | null>(null);
  let saving = $state(false);
  const tabs = queryTab('approvals', ['general', 'privacy', 'approvals', 'access', 'keys', 'keyguard', 'data', 'appearance']);

  $effect(() => {
    if (loaded.data && !form) form = structuredClone($state.snapshot(loaded.data));
  });

  // tt-core serves only the approval settings through the API; the rest lives in its configuration file.
  const hasGeneral = $derived(!!loaded.data?.general);
  const hasServer = $derived(!!loaded.data?.server);
  const editable = $derived(can('settings.edit') && api.capabilities.settingsEdit);
  const configTabs = ['general', 'privacy', 'access'];
  const keys = resource(() => api.fleet.signingKeys());
  // Loaded only when their tab is open (a role may not read all of them).
  const retention = resource(async () => (tabs.value === 'data' ? await api.store.retention() : null));
  const usage = resource(async () => (tabs.value === 'data' && (can('store.manage') || can('audit.view')) ? await api.store.usage() : null));
  const kg = resource(async () => (tabs.value === 'keyguard' ? await api.keyguard.status() : null));
  const levelTone = (l: StorageLevel) => (l === 'ok' ? 'success' : l === 'high' ? 'warning' : 'danger');
  let maintaining = $state(false);
  async function runMaintenance(): Promise<void> {
    maintaining = true;
    try {
      const r = await api.store.maintenance();
      toast(t('set.data.maintDone', { deleted: fmtNum(r.deleted), reclaimed: fmtBytes(r.reclaimedBytes) }));
      usage.reload();
    } catch (e) {
      toastError(e);
    } finally {
      maintaining = false;
    }
  }
  const kgAudit = resource(async () => (tabs.value === 'keyguard' && can('audit.view') ? await api.keyguard.audit() : []));

  let days = $state('');
  $effect(() => {
    if (retention.data && days === '') days = String(retention.data.eventsDays);
  });
  const daysOk = $derived(/^[0-9]+$/.test(days) && Number(days) >= 1 && Number(days) <= 365);
  let purgeBefore = $state('');
  let purgeOpen = $state(false);
  async function saveRetention(): Promise<void> {
    try {
      await api.store.setRetention(Number(days));
      toast(t('set.data.saved'));
      retention.reload();
    } catch (e) {
      toastError(e);
    }
  }
  let revokeKid = $state<string | null>(null);
  let revokeOpen = $state(false);
  async function revokeKey(): Promise<void> {
    if (!revokeKid) return;
    try {
      await api.fleet.revokeSigningKey(revokeKid);
      toast(t('set.keysRevokedToast', { kid: revokeKid }));
    } catch (e) {
      toastError(e);
    } finally {
      revokeKid = null;
      keys.reload();
    }
  }
  async function purge(): Promise<void> {
    const r = await api.store.purge(new Date(purgeBefore).toISOString());
    toast(t('set.data.purged', { events: r.events, tokens: r.tokens }));
  }
  const dirty = $derived(!!form && !!loaded.data && JSON.stringify($state.snapshot(form)) !== JSON.stringify(loaded.data));

  async function save(): Promise<void> {
    if (!form) return;
    saving = true;
    try {
      const saved = await api.settings.save($state.snapshot(form) as Settings);
      toast(t('set.saved'));
      form = structuredClone(saved);
      loaded.reload();
      await refreshStatus();
    } catch (e) {
      toastError(e);
    } finally {
      saving = false;
    }
  }
  const envs: EnvName[] = ['production', 'staging', 'development'];
  const minutes = (s: number) => Math.round(s / 60);
  const hours = (s: number) => Math.round(s / 3600);
  const themes: ThemeChoice[] = ['auto', 'light', 'dark'];
</script>

<PageHeader title={t('set.title')} description={t('set.desc')} help="settings" breadcrumbs={[{ label: t('nav.settings') }]} updatedAt={loaded.updatedAt} onrefresh={loaded.reload} refreshing={loaded.loading}>
  {#snippet actions()}
    {#if hasGeneral && tabs.value !== 'appearance' && tabs.value !== 'approvals' && tabs.value !== 'keys' && tabs.value !== 'keyguard' && tabs.value !== 'data'}<Button variant="primary" loading={saving} denied={!editable} disabled={!dirty} onclick={save}>{t('common.save')}</Button>{/if}
    {#if hasServer && !hasGeneral && tabs.value === 'general'}<Button variant="primary" loading={saving} denied={!editable} disabled={!dirty} onclick={save}>{t('common.save')}</Button>{/if}
  {/snippet}
</PageHeader>

{#if hasGeneral && !editable && tabs.value !== 'appearance' && tabs.value !== 'approvals' && tabs.value !== 'keys' && tabs.value !== 'keyguard' && tabs.value !== 'data'}<p class="callout warn ro">{t('set.readonly')}</p>{/if}

<Tabs tabs={[{ id: 'general', label: t('set.tab.general') }, { id: 'privacy', label: t('set.tab.privacy') }, { id: 'approvals', label: t('set.tab.approvals') }, { id: 'access', label: t('set.tab.access') }, { id: 'keys', label: t('set.tab.keys') }, { id: 'keyguard', label: t('set.tab.keyguard') }, { id: 'data', label: t('set.tab.data') }, { id: 'appearance', label: t('set.tab.appearance') }]} bind:value={tabs.value} label={t('set.title')}>
  {#if tabs.value === 'appearance'}
    <Card title={t('set.appearance')} subtitle={t('set.appearanceHint')}>
      <div class="stack">
        <fieldset>
          <legend>{t('set.theme')}</legend>
          {#each themes as th (th)}
            <label class="chk"><input type="radio" name="theme" value={th} checked={theme.choice === th} onchange={() => setTheme(th)} /> {t(`theme.${th}` as 'theme.auto')}</label>
          {/each}
        </fieldset>
        <fieldset>
          <legend>{t('set.language')}</legend>
          {#each ['it', 'en'] as const as l (l)}
            <label class="chk"><input type="radio" name="lang" value={l} checked={i18n.lang === l} onchange={() => setLang(l as Lang)} /> {l === 'it' ? 'Italiano' : 'English'}</label>
          {/each}
        </fieldset>
      </div>
    </Card>
  {:else if tabs.value === 'keys'}
    <Card title={t('set.tab.keys')} subtitle={t('set.keysHint')} flush>
      {#if keys.data}
        {#if keys.data.length === 0}
          <p class="pad subtle">{t('set.keysNone')}</p>
        {:else}
          <div class="table-wrap" use:scrollable>
            <table class="data">
              <thead><tr><th scope="col">kid</th><th scope="col">{t('set.keysAlg')}</th><th scope="col">{t('set.keysEndorsed')}</th><th scope="col">{t('set.keysState')}</th><th scope="col">{t('set.keysTrusted')}</th><th scope="col">{t('set.keysRevoke')}</th></tr></thead>
              <tbody>
                {#each keys.data as k (k.kid)}
                  <tr>
                    <td class="mono">{k.kid}</td>
                    <td>{k.alg}</td>
                    <td>{k.endorsedBy ?? '—'}</td>
                    <td>
                      {#if k.revoked}<Badge tone="danger">{t('set.keysRevoked')}</Badge>
                      {:else if k.active}<Badge tone="success">{t('set.keysSigning')}</Badge>
                      {:else}<Badge tone="neutral">{t('set.keysValid')}</Badge>{/if}
                    </td>
                    <td>{k.revoked ? '—' : String(k.trustedBy ?? 0)}</td>
                    <td>
                      {#if k.revoke}
                        {#if k.revoke.ok}
                          <Button variant="danger" size="sm" denied={!can('settings.edit')} onclick={() => ((revokeKid = k.kid), (revokeOpen = true))}>{t('set.keysRevokeBtn')}</Button>
                          <span class="subtle">{t('set.keysConfirmed', { n: k.revoke.confirmed, of: k.revoke.seen })}</span>
                        {:else if k.revoke.blocker === 'rotation_unconfirmed'}
                          <span class="subtle">{t('set.keysWaiting', { n: k.revoke.confirmed, of: k.revoke.seen, pct: fmtPct(k.revoke.required) })}</span>
                        {:else}
                          <span class="subtle">{tk(`set.keysBlocked.${k.revoke.blocker ?? 'other'}`, undefined, t('set.keysBlocked.other'))}</span>
                        {/if}
                      {:else}—{/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {:else}
        <div class="pad"><Loading error={keys.error} onretry={keys.reload} /></div>
      {/if}
    </Card>
  {:else if tabs.value === 'keyguard'}
    <div class="stack">
      {#if kg.data}
        {#if !kg.data.reachable}<p class="callout danger" role="alert">{t('set.kg.unreachable')}</p>{/if}
        <Card title={t('set.kg.title')}>
          <dl class="ro">
            <div><dt>{t('set.kg.reachable')}</dt><dd><Badge tone={kg.data.reachable ? 'success' : 'danger'}>{kg.data.reachable ? t('set.on') : t('set.off')}</Badge>{#if kg.data.transport} <span class="subtle">{t('set.kg.transport')}: {kg.data.transport}</span>{/if}</dd></div>
            {#if kg.data.reachable}
              <div><dt>{t('set.kg.kids')}</dt><dd class="mono">{kg.data.hmacKids.join(', ') || t('set.kg.none')} <span class="subtle">· {t('set.kg.epochs')}: {kg.data.epochs.join(', ') || t('set.kg.none')}</span></dd></div>
              <div><dt>{t('set.kg.policyKid')}</dt><dd class="mono">{kg.data.policyKid ?? '—'}</dd></div>
              <div><dt>{t('set.kg.packKid')}</dt><dd class="mono">{kg.data.packKid ?? '—'}</dd></div>
              <div><dt>{t('set.kg.revoked')}</dt><dd class="mono">{kg.data.revokedKids.join(', ') || t('set.kg.none')}</dd></div>
              {#if kg.data.matchBudgetLeft !== undefined}<div><dt>{t('set.kg.budget')}</dt><dd class="num">{kg.data.matchBudgetLeft}</dd></div>{/if}
            {/if}
          </dl>
        </Card>
        {#if can('audit.view')}
          <Card title={t('set.kg.audit')} subtitle={t('set.kg.auditHint')} flush>
            {#if kgAudit.data && kgAudit.data.length}
              <div class="table-wrap" use:scrollable>
                <table class="data">
                  <thead><tr><th scope="col">#</th><th scope="col">{t('audit.col.at')}</th><th scope="col">{t('audit.col.action')}</th><th scope="col">{t('audit.col.result')}</th></tr></thead>
                  <tbody>
                    {#each kgAudit.data as e (e.seq)}
                      <tr><td class="num">{e.seq}</td><td class="nowrap">{fmtDate(e.at)}</td><td><code>{e.op}</code></td><td>{e.outcome}</td></tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else if kgAudit.data}<p class="pad subtle">{t('set.kg.auditNone')}</p>
            {:else}<div class="pad"><Loading error={kgAudit.error} onretry={kgAudit.reload} /></div>{/if}
          </Card>
        {/if}
      {:else}<Loading error={kg.error} onretry={kg.reload} />{/if}
    </div>
  {:else if tabs.value === 'data'}
    <div class="stack">
      {#if can('store.manage') || can('audit.view')}
        <Card title={t('set.data.usage')} subtitle={t('set.data.usageHint')} flush>
          {#snippet actions()}<Button size="sm" icon="refresh" loading={maintaining} denied={!can('store.manage')} disabled={usage.data?.running} onclick={runMaintenance}>{t('set.data.maintRun')}</Button>{/snippet}
          {#if usage.data}
            {@const u = usage.data}
            <div class="pad stack">
              {#if u.db.level === 'over'}<p class="callout danger" role="alert">{t('set.data.levelOver')}</p>
              {:else if u.db.level === 'critical'}<p class="callout danger" role="alert">{t('set.data.levelCritical', { pct: u.db.criticalPct })}</p>
              {:else if u.db.level === 'high'}<p class="callout warn">{t('set.data.levelHigh', { pct: u.db.highPct })}</p>{/if}
              {#if u.db.autoVacuum === 'none'}<p class="callout warn">{t('set.data.legacy')}</p>{/if}
              <dl class="ro">
                <div>
                  <dt>{t('set.data.db')} <Badge tone={levelTone(u.db.level)}>{tk(`set.data.level.${u.db.level}`, undefined, u.db.level)}</Badge></dt>
                  {#if u.db.maxBytes > 0}
                    <dd><ProgressBar value={u.db.usedBytes / u.db.maxBytes} label={t('set.data.db')} tone={u.db.level === 'ok' ? 'accent' : u.db.level === 'high' ? 'warning' : 'danger'} /></dd>
                    <dd class="subtle">{t('set.data.dbBudget', { used: fmtBytes(u.db.usedBytes), max: fmtBytes(u.db.maxBytes), high: u.db.highPct, critical: u.db.criticalPct })}</dd>
                  {:else}
                    <dd>{fmtBytes(u.db.usedBytes)} <span class="subtle">· {t('set.data.noBudget')}</span></dd>
                  {/if}
                  <dd class="subtle">{t('set.data.dbFile', { file: fmtBytes(u.db.fileBytes), wal: fmtBytes(u.db.walBytes), free: fmtBytes(u.db.freeBytes) })}</dd>
                </div>
                <div>
                  <dt>{t('set.data.lastRun')}</dt>
                  {#if u.lastRun}
                    <dd>{fmtDate(u.lastRun.finishedAt)} · {t('set.data.lastRunValue', { deleted: fmtNum(u.lastRun.deleted), reclaimed: fmtBytes(u.lastRun.reclaimedBytes) })}{#if u.lastRun.errors > 0} <Badge tone="danger">{t('set.data.errors', { n: u.lastRun.errors })}</Badge>{/if}</dd>
                    {#if u.lastRun.shed.length}<dd class="subtle">{t('set.data.shed', { steps: u.lastRun.shed.join(', ') })}</dd>{/if}
                    {#if u.lastRun.reclaimNote}<dd class="subtle">{u.lastRun.reclaimNote}</dd>{/if}
                  {:else}<dd class="subtle">{t('set.data.never')}</dd>{/if}
                  <dd class="subtle">{u.running ? t('set.data.running') : u.nextRun ? t('set.data.nextRun', { when: fmtDate(u.nextRun) }) : t('set.data.nextSoon')}</dd>
                </div>
                {#if u.auditArchive}
                  <div>
                    <dt>{t('set.data.auditArchive')}</dt>
                    <dd>{u.auditArchive.enabled ? t('set.data.auditArchiveValue', { segments: u.auditArchive.segments, entries: fmtNum(u.auditArchive.entries), dir: u.auditArchive.dir }) : t('set.data.auditArchiveOff')}</dd>
                  </div>
                {/if}
              </dl>
            </div>
            <div class="table-wrap" use:scrollable>
              <table class="data">
                <thead><tr><th scope="col">{t('set.data.col.dataset')}</th><th scope="col" class="num">{t('set.data.col.size')}</th><th scope="col">{t('set.data.col.retention')}</th><th scope="col" class="num">{t('set.data.col.removed')}</th></tr></thead>
                <tbody>
                  {#each u.datasets as d (d.name)}
                    <tr>
                      <td>{tk(`set.data.ds.${d.name}`, undefined, d.name)}</td>
                      <td class="num nowrap">{fmtBytes(d.bytes)}{#if d.fileBytes} <span class="subtle">+ {fmtBytes(d.fileBytes)} {t('set.data.files')}</span>{/if}{#if d.quotaBytes} <span class="subtle">/ {fmtBytes(d.quotaBytes)}</span>{/if}{#if d.overQuota} <Badge tone="danger">{t('set.data.overQuota')}</Badge>{/if}</td>
                      <td>{tk(`set.data.pol.${d.policy.code}`, d.policy.params, d.policy.code)}</td>
                      <td class="num">{#if d.lastRun?.error}<Badge tone="danger" title={d.lastRun.error}>{t('set.data.stepError')}</Badge>{:else if d.lastRun}{fmtNum(d.lastRun.deleted)}{:else}—{/if}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
            {#if u.measuredAt}<p class="pad subtle">{t('set.data.measuredAt', { when: fmtDate(u.measuredAt) })}</p>{/if}
          {:else}<div class="pad"><Loading error={usage.error} onretry={usage.reload} /></div>{/if}
        </Card>
      {/if}
      <Card title={t('set.data.retention')} subtitle={t('set.data.retentionHint', { aggregates: retention.data?.aggregatesDays ?? '…' })}>
        {#if retention.data}
          <div class="stack form">
            <Field label={t('set.data.days')} error={daysOk ? '' : t('set.data.daysInvalid')}>
              {#snippet children({ id, describedby })}<input {id} inputmode="numeric" bind:value={days} aria-describedby={describedby} disabled={!can('store.manage')} />{/snippet}
            </Field>
            <div><Button variant="primary" denied={!can('store.manage')} disabled={!daysOk || Number(days) === retention.data.eventsDays} onclick={saveRetention}>{t('common.save')}</Button></div>
          </div>
        {:else}<Loading error={retention.error} onretry={retention.reload} />{/if}
      </Card>
      <Card title={t('set.data.purge')} subtitle={t('set.data.purgeHint')}>
        <div class="stack form">
          <Field label={t('set.data.before')}>
            {#snippet children({ id })}<input {id} type="date" bind:value={purgeBefore} disabled={!can('store.manage')} />{/snippet}
          </Field>
          <div><Button variant="danger" icon="trash" denied={!can('store.manage')} disabled={!purgeBefore} onclick={() => (purgeOpen = true)}>{t('set.data.purge')}</Button></div>
        </div>
      </Card>
    </div>
  {:else if form && form.server && configTabs.includes(tabs.value)}
    {#if tabs.value === 'general'}
      <fieldset class="plain" disabled={!editable}>
        <Card title={t('set.tab.general')} subtitle={t('set.srv.labelsOnly')}>
          <div class="stack form">
            <Field label={t('set.srv.name')} hint={t('set.srv.nameHint')}>
              {#snippet children({ id, describedby })}<input {id} maxlength="64" bind:value={form!.server!.installation} spellcheck="false" aria-describedby={describedby} />{/snippet}
            </Field>
            <Field label={t('set.env')} hint={t('set.envHint')} help="set.env">
              {#snippet children({ id, describedby })}
                <select {id} value={form!.server!.environment ?? ''} onchange={(ev) => (form!.server!.environment = (ev.currentTarget.value || undefined) as EnvName | undefined)} aria-describedby={describedby}>
                  <option value="">{t('set.srv.envNone')}</option>
                  {#each envs as e (e)}<option value={e}>{t(`env.${e}` as 'env.production')}</option>{/each}
                </select>
              {/snippet}
            </Field>
          </div>
        </Card>
      </fieldset>
      {#if !editable}<p class="callout warn ro">{t('set.readonly')}</p>{/if}
    {:else if tabs.value === 'privacy'}
      <div class="stack">
        <p class="callout">{t('set.srv.configOnly')}</p>
        <Card title={t('set.tab.privacy')}>
          <dl class="ro">
            <div>
              <dt>{t('set.srv.retention')}</dt>
              <dd>{t('set.srv.retentionValue', { events: form.server.privacy.eventsRetentionDays, aggregates: form.server.privacy.aggregatesDays })}</dd>
              <dd class="subtle">{t('set.srv.retentionHint')}</dd>
            </div>
            <div>
              <dt>{t('set.srv.kmin')} <InfoTip id="set.kmin" /></dt>
              <dd class="num">{t('set.srv.kminValue', form.server.privacy.kMin)}</dd>
              <dd class="subtle">{t('set.kminHint')}</dd>
            </div>
            <div>
              <dt>{t('set.srv.minSamples')} <InfoTip id="set.minSamples" /></dt>
              <dd class="num">{form.server.privacy.minSamples}</dd>
            </div>
          </dl>
        </Card>
      </div>
    {:else}
      <div class="stack">
        <p class="callout">{t('set.srv.configOnly')}</p>
        <Card title={t('set.tab.access')} subtitle={t('set.accessHint')}>
          <dl class="ro">
            <div>
              <dt>{t('set.ssoEnabled')} <InfoTip id="set.sso" /></dt>
              <dd><Badge tone={form.server.access.sso.enabled ? 'success' : 'neutral'}>{form.server.access.sso.enabled ? t('set.on') : t('set.off')}</Badge></dd>
            </div>
            {#if form.server.access.sso.enabled}
              <div><dt>{t('set.issuer')}</dt><dd class="mono">{form.server.access.sso.issuer}</dd></div>
              <div><dt>Client ID</dt><dd class="mono">{form.server.access.sso.clientId}</dd></div>
              <div><dt>{t('set.roleClaim')} <InfoTip id="set.roleClaim" /></dt><dd class="mono">{form.server.access.sso.roleClaim || '—'}</dd><dd class="subtle">{t('set.roleClaimHint')}</dd></div>
            {/if}
            <div>
              <dt>{t('set.srv.local')}</dt>
              <dd><Badge tone={form.server.access.localEnabled ? 'success' : 'neutral'}>{form.server.access.localEnabled ? t('set.on') : t('set.off')}</Badge></dd>
            </div>
            <div>
              <dt>{t('set.srv.sessions')}</dt>
              <dd>{t('set.srv.sessionsValue', { idle: minutes(form.server.access.sessionIdleSeconds), abs: hours(form.server.access.sessionAbsoluteSeconds) })}</dd>
            </div>
          </dl>
          <p class="subtle">{t('set.noSecret')}</p>
        </Card>
      </div>
    {/if}
  {:else if form && !form.general && tabs.value !== 'approvals'}
    <Card title={t('set.serverConfigTitle')}><p class="callout">{t('set.serverConfig')}</p></Card>
  {:else if form}
    <fieldset class="plain" disabled={!editable}>
      {#if tabs.value === 'general'}
        <Card title={t('set.tab.general')}>
          <div class="stack form">
            <Field label={t('set.env')} hint={t('set.envHint')} help="set.env">
              {#snippet children({ id, describedby })}
                <select {id} bind:value={form!.general!.environment} aria-describedby={describedby}>{#each envs as e (e)}<option value={e}>{t(`env.${e}` as 'env.production')}</option>{/each}</select>
              {/snippet}
            </Field>
            <Field label={t('set.sampling')} help="set.sampling" hint={t('set.samplingHint', { rate: fmtPct(form.general!.defaultSamplingBp / 10000, 2) })}>
              {#snippet children({ id, describedby })}
                <input {id} type="range" min="0" max="10000" step="25" bind:value={form!.general!.defaultSamplingBp} aria-describedby={describedby} />
              {/snippet}
            </Field>
            <Field label={t('set.minSamples')} hint={t('set.minSamplesHint')} help="set.minSamples">
              {#snippet children({ id, describedby })}<input {id} type="number" min="1" bind:value={form!.general!.minSamples} aria-describedby={describedby} />{/snippet}
            </Field>
          </div>
        </Card>
      {:else if tabs.value === 'approvals'}
        <Card title={t('set.tab.approvals')} subtitle={t('set.approvalsHint')}>
          <dl class="ro">
            <div>
              <dt>{t('set.approvals')} <InfoTip id="set.approvals" /></dt>
              <dd><b class="big">{form.approvals.openingRequired}</b> <Badge tone={form.approvals.openingRequired === 2 ? 'success' : 'warning'}>{form.approvals.openingRequired === 2 ? t('set.approvals.safe') : t('set.approvals.single')}</Badge></dd>
              <dd class="subtle">{t('set.approvals.explain')}</dd>
            </div>
            <div>
              <dt>{t('set.adminOverride')} <InfoTip id="set.adminOverride" /></dt>
              <dd><Badge tone={form.approvals.adminOverride ? 'warning' : 'success'}>{form.approvals.adminOverride ? t('set.on') : t('set.off')}</Badge></dd>
              <dd class="subtle">{t('set.adminOverride.explain')}</dd>
            </div>
            <div>
              <dt>{t('set.identities')}</dt>
              <dd><Badge tone={form.approvals.identitiesVerified ? 'success' : 'warning'}>{form.approvals.identitiesVerified ? t('set.verified') : t('set.unverified')}</Badge></dd>
              <dd class="subtle">{t('set.identities.explain')}</dd>
            </div>
          </dl>
          <p class="callout">{t('set.approvals.how')}</p>
          <pre class="env" use:scrollable><code>TT_KEYGUARD_OPENING_APPROVALS=2   # 1 | 2
TT_KEYGUARD_ADMIN_OVERRIDE=true   # true | false</code></pre>
        </Card>
      {:else if tabs.value === 'privacy'}
        <Card title={t('set.tab.privacy')}>
          <div class="stack form">
            <Field label={t('set.retention')} hint={t('set.retentionHint')} help="set.retention">
              {#snippet children({ id, describedby })}<input {id} type="number" min="1" max="365" bind:value={form!.general!.retentionDays} aria-describedby={describedby} />{/snippet}
            </Field>
            <Field label={t('set.kmin')} hint={t('set.kminHint')} help="set.kmin">
              {#snippet children({ id, describedby })}<input {id} type="number" min="5" max="1000" bind:value={form!.general!.kMin} aria-describedby={describedby} />{/snippet}
            </Field>
            <div class="row-tight"><Switch bind:checked={form.general!.anonymizeHosts} label={t('set.anonHosts')} /><InfoTip id="set.anonHosts" /></div>
            <p class="subtle">{t('set.anonHostsHint')}</p>
          </div>
        </Card>
      {:else}
        <Card title={t('set.tab.access')} subtitle={t('set.accessHint')}>
          <div class="stack form">
            <div class="row-tight"><Switch bind:checked={form.general!.sso.enabled} label={t('set.ssoEnabled')} /><InfoTip id="set.sso" /></div>
            <Field label={t('set.issuer')}>
              {#snippet children({ id })}<input {id} type="url" bind:value={form!.general!.sso.issuer} spellcheck="false" />{/snippet}
            </Field>
            <Field label="Client ID">
              {#snippet children({ id })}<input {id} bind:value={form!.general!.sso.clientId} spellcheck="false" />{/snippet}
            </Field>
            <Field label={t('set.roleClaim')} hint={t('set.roleClaimHint')} help="set.roleClaim">
              {#snippet children({ id, describedby })}<input {id} bind:value={form!.general!.sso.roleClaim} spellcheck="false" aria-describedby={describedby} />{/snippet}
            </Field>
            <p class="subtle">{t('set.noSecret')}</p>
          </div>
        </Card>
      {/if}
    </fieldset>
  {:else}
    <Loading error={loaded.error} onretry={loaded.reload} />
  {/if}
</Tabs>

<ConfirmDialog bind:open={revokeOpen} title={t('set.keysRevokeBtn')} message={t('set.keysRevokeConfirm', { kid: revokeKid ?? '' })} confirmLabel={t('set.keysRevokeBtn')} onconfirm={revokeKey} />
<ConfirmDialog bind:open={purgeOpen} title={t('set.data.purge')} message={t('set.data.purgeConfirm', { when: purgeBefore })} confirmLabel={t('set.data.purge')} requireText={t('set.data.word')} onconfirm={purge} />

<style>
  .ro { margin-bottom: var(--s-4); }
  fieldset.plain { border: 0; padding: 0; margin: 0; min-width: 0; }
  .form { max-width: 34rem; }
  .ro { margin: 0 0 var(--s-4); display: grid; gap: var(--s-4); }
  .ro dt { font-weight: 600; }
  .ro dd { margin: 4px 0 0; }
  .pad { padding: var(--s-3) var(--s-4); }
  .big { font-size: 1.6rem; margin-right: var(--s-2); }
  .env { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3); margin: var(--s-3) 0 0; overflow-x: auto; }
  fieldset:not(.plain) { border: 1px solid var(--border-strong); border-radius: var(--r-sm); padding: var(--s-3); display: flex; flex-direction: column; gap: var(--s-2); margin: 0; }
  legend { font-weight: 600; padding: 0 var(--s-1); }
  .chk { display: flex; align-items: center; gap: var(--s-2); font-weight: 500; }
</style>
