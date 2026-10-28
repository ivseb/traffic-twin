<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import Badge from '../components/Badge.svelte';
  import Icon from '../components/Icon.svelte';
  import Modal from '../components/Modal.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import Field from '../components/Field.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import RichText from '../components/RichText.svelte';
  import Loading from '../components/Loading.svelte';
  import ApprovalNotice from '../components/ApprovalNotice.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { serviceKey, type ExportReport, type ExportTarget, type Publication, type ServiceInfo } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, stepUpDone, toast, toastError } from '../lib/stores.svelte';
  import { fmtBytes, fmtDate, fmtNum, fmtPct } from '../lib/format';
  import { href } from '../lib/router';
  import { loc, navigate } from '../lib/router.svelte';
  import { saveBlob } from '../lib/download';
  import ProgressBar from '../components/ProgressBar.svelte';
  import ScopeNote from '../components/ScopeNote.svelte';
  import { ApiError } from '../lib/api';
  import GroupTag from '../components/GroupTag.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { errorMessage } from '../lib/stores.svelte';

  let { params }: { params: Record<string, string> } = $props();

  // Group/Team filter: the server lists the packs of the chosen groups (their residual risk is computed on the
  // archetypes of the pack's group), and the worlds a pack can be built from.
  const list = resource(() => api.publications.list(scopeGroups()));
  const gateKeys = resource(() => api.gate.keys());
  const worlds = resource(() => api.worlds.list(scopeGroups()));
  const detail = resource(async () => (params.id ? await api.publications.get(params.id) : null));
  const settings = resource(() => api.settings.get());
  // The installation k of the gate: a pack built with a lower k is of a group marked as test (rules v1.9).
  const installK = $derived(settings.data?.server?.privacy.kMin.gate ?? settings.data?.general?.kMin ?? 0);
  // A pack released after an OIDC step-up (App resumes the call): show the new state.
  $effect(() => {
    if (stepUpDone.tick) {
      list.reload();
      detail.reload();
    }
  });

  let newOpen = $state(false);
  let worldId = $state(loc.query.world ?? '');
  let validDays = $state('');
  let busy = $state(false);
  let releaseOpen = $state(false);
  let reason = $state('');
  let started = false;
  let exportOpen = $state(false);
  let report = $state<ExportReport | null>(null);

  // Building (operator) and releasing (publisher) are two steps by two roles. An administrator
  // without the publisher role can still release, alone, with a reason.
  const canBuild = $derived(can('publish.build'));
  // An admin releases as the admin override (reason, alert), also with publisher.
  const override = $derived(can('override.admin'));
  const canRelease = $derived(can('publish.run') || can('override.admin'));
  const canGet = $derived(can('publish.download'));
  const daysOk = $derived(validDays === '' || (/^[0-9]+$/.test(validDays) && Number(validDays) >= 1 && Number(validDays) <= 3650));

  $effect(() => {
    if (loc.query.world) {
      worldId = loc.query.world;
      newOpen = true;
    }
  });
  // The newest world by default: an older one is often "stale" (rules or contracts changed since).
  const newestWorld = $derived(worlds.data?.length ? [...worlds.data].sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] : undefined);
  $effect(() => {
    if (!worldId && newestWorld) worldId = newestWorld.id;
  });
  const worldsByDate = $derived([...(worlds.data ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt)));

  // A pack holds the services of one group: the world's group (else the filter's). The dialog lists that group's
  // services with an explicit include/exclude checkbox (default: the service's "in the mock" choice). Services of
  // several groups in one pack only for an administrator who asks for it (multi_group).
  const selectedWorld = $derived(worlds.data?.find((w) => w.id === worldId));
  const packGroup = $derived(selectedWorld?.group || scopeGroups()?.[0] || '');
  const canMulti = $derived(can('override.admin'));
  let multiGroup = $state(false);
  const svcGroups = $derived(multiGroup && canMulti ? scopeGroups() : packGroup ? [packGroup] : scopeGroups());
  const packServices = resource(() => (newOpen ? api.services.list(svcGroups) : Promise.resolve([] as ServiceInfo[])));
  // Explicit choices of this dialog (group, service) -> in the pack; the rest follows the service's default.
  let picked = $state<Record<string, boolean>>({});
  const inPack = (s: ServiceInfo) => picked[serviceKey(s.group, s.name)] ?? s.twin;
  const includedNames = $derived([...new Set((packServices.data ?? []).filter(inPack).map((s) => s.name))]);
  const excludedNames = $derived([...new Set((packServices.data ?? []).filter((s) => !inPack(s)).map((s) => s.name))].filter((n) => !includedNames.includes(n)));
  // The gate runs synchronously (tens of seconds on a big store): show where it is and what went wrong in the dialog.
  let runError = $state('');
  let runStale = $state(false);
  let runMixed = $state(false);
  let runStarted = $state(0);
  let runElapsed = $state(0);
  $effect(() => {
    if (!busy || !runStarted) return;
    const h = setInterval(() => (runElapsed = Math.round((Date.now() - runStarted) / 1000)), 500);
    return () => clearInterval(h);
  });
  async function copyCommand(): Promise<void> {
    if (!gateKeys.data) return;
    try {
      await navigator.clipboard.writeText(gateKeys.data.command);
      toast(t('code.copied'));
    } catch {
      toast(t('code.copyFailed'), 'warning');
    }
  }
  async function downloadKeys(): Promise<void> {
    try {
      const { filename, blob } = await api.gate.keyFile();
      saveBlob(filename, blob);
    } catch (e) {
      toastError(e);
    }
  }

  // Poll the pack while its gate runs: the next request starts a second
  // after the previous answer (never two at once, whatever the latency),
  // nothing while the tab is hidden; the list is reloaded once, when the
  // verdict is known.
  $effect(() => {
    void detail.updatedAt;
    void detail.error;
    if (detail.data?.verdict !== 'running') return;
    let h = setTimeout(function poll() {
      if (document.hidden || detail.loading) {
        h = setTimeout(poll, 1000);
        return;
      }
      detail.reload();
    }, 1000);
    return () => clearTimeout(h);
  });
  let lastVerdict: string | undefined;
  $effect(() => {
    const v = detail.data?.verdict;
    if (lastVerdict === 'running' && v !== 'running') list.reload();
    lastVerdict = v;
  });

  async function run(): Promise<void> {
    busy = true;
    runError = '';
    runStale = false;
    runStarted = Date.now();
    runElapsed = 0;
    try {
      const listed = !!packServices.data?.length;
      const p = await api.publications.run(worldId, {
        validDays: validDays ? Number(validDays) : undefined,
        ...(listed ? { services: includedNames, excludeServices: excludedNames } : {}),
        ...(packGroup ? { group: packGroup } : {}),
        ...(multiGroup && canMulti ? { multiGroup: true } : {}),
      });
      started = true;
      newOpen = false;
      list.reload();
      toast(p.verdict === 'fail' ? t('pub.builtBlocked', { name: p.packId }) : t('pub.built', { name: p.packId }), p.verdict === 'fail' ? 'warning' : 'success');
      navigate('/packs/' + encodeURIComponent(p.id));
    } catch (e) {
      // The dialog stays open with the reason (a toast would sit behind the modal).
      runStale = e instanceof ApiError && (e.serverCode === 'world_stale' || e.serverCode === 'missing_service');
      runMixed = e instanceof ApiError && e.serverCode === 'mixed_groups';
      runError = errorMessage(e);
    } finally {
      busy = false;
      runStarted = 0;
    }
  }

  async function release(p: Publication): Promise<void> {
    busy = true;
    try {
      await api.publications.publish(p.id, { reason: override ? reason.trim() : undefined });
      toast(t('pub.released', { name: p.packId }));
      releaseOpen = false;
      reason = '';
      list.reload();
      detail.reload();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  async function download(p: Publication): Promise<void> {
    try {
      const { filename, blob } = await api.publications.download(p.id);
      saveBlob(filename, blob);
      toast(t('pub.downloaded', { name: filename }));
    } catch (e) {
      toastError(e);
    }
  }

  async function downloadExportZip(): Promise<void> {
    if (!report?.exportId) return;
    try {
      const { filename, blob } = await api.publications.downloadExport(report.exportId);
      saveBlob(filename, blob);
    } catch (e) {
      toastError(e);
    }
  }

  async function doExport(p: Publication, target: ExportTarget): Promise<void> {
    try {
      report = await api.publications.export(p.id, target);
      exportOpen = true;
    } catch (e) {
      toastError(e);
    }
  }

  const cols: Column<Publication>[] = $derived([
    { key: 'packId', label: t('pub.col.pack'), sortable: true },
    { key: 'verdict', label: t('pub.col.verdict'), sortable: true, help: 'pack.verdict' },
    { key: 'createdAt', label: t('pub.col.created'), sortable: true, hideBelow: 'md', value: (p) => -new Date(p.createdAt).getTime() },
  ]);

  const checkIcon = (s: string) => (s === 'pass' ? 'check' : s === 'warn' ? 'alert' : s === 'fail' ? 'close' : s === 'running' ? 'refresh' : s === 'skipped' ? 'pause' : 'clock');

  function gateReport(p: Publication): string {
    return JSON.stringify(
      {
        format: 'tt.gate-report/v1',
        pack_id: p.packId,
        verdict: p.verdict,
        k_min: p.kMin,
        checks: p.checks.map((c) => ({ id: c.id, status: c.status, findings: c.findings, ...(c.stringsChecked ? { strings_checked: c.stringsChecked } : {}) })),
      },
      null,
      2,
    );
  }
  const d = $derived(detail.data ?? null);
  const targets: ExportTarget[] = ['wiremock', 'microcks', 'prism'];
</script>

<PageHeader title={t('pub.title')} description={t('pub.subtitle')} help="packs" breadcrumbs={[{ label: t('pub.crumb') }, { label: t('pub.title') }]} updatedAt={list.updatedAt} onrefresh={list.reload} refreshing={list.loading}>
  {#snippet actions()}
    <Button variant="primary" icon="publications" denied={!canBuild} onclick={() => (newOpen = true)}>{t('pub.new')}</Button>
  {/snippet}
</PageHeader>

<p class="callout">{t('mk.packsHint')} <a href="#/mock">{t('mk.packsHintLink')}</a></p>

<Card title={t('pub.what')} subtitle={t('pub.whatSub')}>
  <ol class="flow" aria-label={t('pub.flowLabel')}>
    <li><b>{t('pub.flow.prod')}</b><span class="muted">{t('pub.flow.prodD')}</span></li>
    <li class="arrow" aria-hidden="true"><Icon name="arrowRight" size={18} /></li>
    <li class="gate"><b>{t('pub.flow.gate')}</b><span class="muted">{t('pub.flow.gateD')}</span></li>
    <li class="arrow" aria-hidden="true"><Icon name="arrowRight" size={18} /></li>
    <li><b>{t('pub.flow.reg')}</b><span class="muted">{t('pub.flow.regD')}</span></li>
    <li class="arrow" aria-hidden="true"><Icon name="arrowRight" size={18} /></li>
    <li><b>{t('pub.flow.ci')}</b><span class="muted">{t('pub.flow.ciD')}</span></li>
  </ol>
  <p class="callout note"><RichText text={t('pub.never')} /></p>
</Card>
<div class="gap"></div>

{#if gateKeys.data}
  <Card title={t('pub.use.title')} subtitle={t('pub.use.sub')}>
    {#snippet actions()}
      <Button size="sm" icon="download" onclick={downloadKeys}>{t('pub.use.file')}</Button>
    {/snippet}
    <div class="stack-sm">
      <p class="muted">{t('pub.use.hint')}</p>
      <CodeBlock code={gateKeys.data.command} language="bash" title={t('pub.use.cmdTitle')} />
      <div class="row-tight">
        <Button size="sm" icon="copy" onclick={copyCommand}>{t('pub.use.copy')}</Button>
        <CopyButton value={gateKeys.data.value} label={t('pub.use.copyValue')} />
        <span class="subtle">{t('pub.use.kids', { kids: gateKeys.data.keys.map((k) => k.kid).join(', ') })}</span>
      </div>
      <p class="subtle">{t('pub.use.ci')}</p>
    </div>
  </Card>
  <div class="gap"></div>
{/if}

<ScopeNote />
<div class="layout">
  <aside>
    <Card flush>
      {#if list.data}
        <Table rows={list.data} columns={cols} rowKey={(p) => p.id} caption={t('pub.title')} selectedKey={params.id} urlKey="pk" onrowclick={(p) => navigate('/packs/' + encodeURIComponent(p.id))} maxHeight="440px">
          {#snippet cell(p, col)}
            {#if col.key === 'packId'}
              <a href={href('/packs/:id', { id: p.id })}><b class="mono">{p.packId}</b></a>
              <div class="subtle">{p.createdBy || '—'}{#if p.adminOverride} · <Badge tone="warning">{t('pub.adminBadge')}</Badge>{/if} <GroupTag group={p.groups?.length ? p.groups : p.group} /></div>
            {:else if col.key === 'verdict'}<StatusPill value={p.status} />
            {:else}<span class="nowrap">{fmtDate(p.createdAt)}</span>{/if}
          {/snippet}
        </Table>
      {:else}
        <Loading error={list.error} onretry={list.reload} />
      {/if}
    </Card>
  </aside>

  <section class="main">
    {#if !params.id}
      <Card><div class="callout">{t('pub.pick')}</div></Card>
    {:else if d}
      <div class="stack">
        <Card>
          <div class="row spread">
            <div class="grow">
              <h2 class="mono">{d.packId}</h2>
              <p class="subtle">{t('pub.meta', { who: d.createdBy || '—', when: fmtDate(d.createdAt), world: d.worldId, seed: d.seed })}</p>
              {#if d.group || d.groups?.length}<p class="subtle">{t('pub.groupOf', { groups: (d.groups?.length ? d.groups : [d.group]).join(', ') })}{#if (d.groups?.length ?? 0) > 1} <Badge tone="warning">{t('pub.multiBadge')}</Badge>{/if}</p>{/if}
              {#if d.services?.length}<p class="subtle">{t('pub.servicesIn', { services: d.services.join(', ') })}</p>{/if}
              {#if d.kMin > 0 && installK && d.kMin < installK}
                <!-- rules v1.9: a pack of a group marked as test, built and gated with its lower k -->
                <p class="callout warn" role="status" data-testid="pack-test-k"><Badge tone="warning">{t('w4.testk.badge', { k: d.kMin })}</Badge> {t('w4.pack.testk', { k: d.kMin, kMin: installK })}</p>
              {/if}
              <p class="subtle">{d.notAfter ? t('pub.validUntil', { when: fmtDate(d.notAfter, false) }) : t('pub.noExpiry')} <InfoTip id="pack.notAfter" /></p>
            </div>
            <div class="row-tight">
              <StatusPill value={d.status} />
              {#if d.signedBy}<Badge tone="success">{t('pub.signed', { kid: d.signedBy })}</Badge>{/if}
            </div>
          </div>
          {#if d.publishedAt}<p class="subtle">{t('pub.publishedAt', { when: fmtDate(d.publishedAt) })}</p>{/if}
          {#if d.adminOverride}
            <p class="callout warn ovr" role="alert"><b>{t('pub.adminTitle', { who: d.adminOverride.by || '—' })}</b> {t('pub.adminWarn')}{#if d.adminOverride.reason} <span class="reason">«{d.adminOverride.reason}»</span>{/if}</p>
          {/if}
        </Card>

        <Card title={t('pub.pipeline')} subtitle={t('pub.pipelineHint')}>
          {#snippet actions()}<InfoTip id="pack.gate" />{/snippet}
          <ol class="pipe" aria-label={t('pub.pipeline')}>
            {#each d.checks as c, i (c.id)}
              <li class="step {c.status}">
                <span class="ico"><Icon name={checkIcon(c.status)} size={16} /></span>
                <div class="grow">
                  <b>{i + 1} · {tk(`gate.${c.id}.name`)}</b>
                  <div class="subtle">{tk(`gate.${c.id}.desc`)}</div>
                  <StatusPill value={c.status} />
                  {#if c.stringsChecked}<span class="subtle"> · {t('pub.strings', { n: fmtNum(c.stringsChecked) })}</span>{/if}
                </div>
              </li>
            {/each}
          </ol>
          {#each d.checks.filter((c) => c.status === 'warn') as c (c.id)}
            <p class="callout warn" role="status"><b>{tk(`gate.${c.id}.name`)}</b> {tk(`gate.${c.id}.warn`)}</p>
          {/each}
          {#if d.verdict === 'fail'}
            <div class="stack-sm blocked">
              <p class="callout danger" role="alert"><b>{t('pub.blocked')}</b> {t('pub.blockedHint')}</p>
              {#each d.checks.filter((c) => c.findings.length) as c (c.id)}
                <h3 class="fs-4">{tk(`gate.${c.id}.name`)}</h3>
                <ul class="finds">
                  {#each c.findings as f, i (i)}
                    <li><code>{f.file}</code> <code class="ptr">{f.pointer}</code><div class="muted">{f.reason}</div></li>
                  {/each}
                </ul>
              {/each}
              <p class="subtle">{t('pub.neverValues')}</p>
            </div>
          {/if}
        </Card>

        <Card title={t('pub.actions')}>
          <div class="stack">
            <div class="row">
              {#if d.status === 'signed'}
                <Button variant="primary" icon="publications" denied={!canRelease} onclick={() => (releaseOpen = true)}>{t('pub.publish')}</Button>
              {/if}
              <Button variant={d.status === 'published' ? 'primary' : 'secondary'} icon="download" denied={!canGet} disabled={d.status !== 'published'} onclick={() => download(d)}>{t('pub.download')}</Button>
              {#each targets as tg (tg)}
                <Button denied={!canGet} disabled={d.status !== 'published'} onclick={() => doExport(d, tg)} icon="external">{t('pub.export', { target: tk(`export.${tg}`) })}</Button>
              {/each}
              <InfoTip id="pack.export" />
            </div>
            {#if d.status === 'signed'}<p class="subtle">{t('pub.onlyReleased')}</p>{:else if d.verdict !== 'pass'}<p class="subtle">{t('pub.onlySigned')}</p>{/if}
          </div>
        </Card>

        {#if d.residualRisk}
          <Card title={t('pub.risk.title')} subtitle={t('pub.risk.sub')}>
            <dl class="risk">
              <div><dt>{t('pub.risk.profiles')}</dt><dd class="num">{fmtNum(d.residualRisk.profiles)} → {fmtNum(d.residualRisk.archetypes)}</dd></div>
              <div><dt>{t('pub.risk.minSize')}</dt><dd class="num">{fmtNum(d.residualRisk.minArchetypeSize)}</dd></div>
              <div><dt>{t('pub.risk.suppressed')}</dt><dd class="num">{fmtNum(d.residualRisk.suppressedSubjects)}</dd></div>
              <div><dt>{t('pub.risk.uniqueness')}</dt><dd class="num">{fmtPct(d.residualRisk.uniquenessRate, 1)}</dd></div>
              <div><dt>{t('pub.risk.singling')}</dt><dd class="num">{fmtPct(d.residualRisk.singlingOutRate, 1)}</dd></div>
              <div><dt>{t('pub.risk.exact')}</dt><dd class="num">{fmtPct(d.residualRisk.exactMatchShare, 1)}</dd></div>
              <div><dt>{t('pub.risk.homogeneity')}</dt><dd class="num">{fmtPct(d.residualRisk.maxHomogeneity, 1)}</dd></div>
            </dl>
            <p class="subtle">{d.residualRisk.note}</p>
            <details class="riskhelp">
              <summary>{t('fix4.pub.risk.how')}</summary>
              <p class="subtle">{t('fix4.pub.risk.explain')}</p>
              <ul class="subtle">
                <li><b>{t('pub.risk.exact')}</b>: {t('fix4.pub.risk.exactHint')}</li>
                <li><b>{t('pub.risk.homogeneity')}</b>: {t('fix4.pub.risk.homogeneityHint')}</li>
                <li><b>{t('pub.risk.uniqueness')}</b> / <b>{t('pub.risk.singling')}</b>: {t('fix4.pub.risk.uniqueHint')}</li>
              </ul>
            </details>
          </Card>
        {/if}

        <div class="grid-2">
          <Card title={t('pub.report')} subtitle="gate-report.json"><CodeBlock code={gateReport(d)} language="json" maxHeight="20rem" /></Card>
          <Card title={t('pub.files')} flush>
            {#snippet actions()}<InfoTip id="pack.files" />{/snippet}
            <div class="table-wrap" use:scrollable>
              <table class="data">
                <thead><tr><th scope="col">{t('pub.file')}</th><th scope="col" class="r">{t('pub.size')}</th><th scope="col">sha256</th></tr></thead>
                <tbody>
                  {#each d.files as f (f.path)}
                    <tr>
                      <td class="mono trunc-cell" title={f.path}>{f.path}</td>
                      <td class="r num">{fmtBytes(f.bytes)}</td>
                      <td class="nowrap"><code class="hash" title={f.sha256}>{f.sha256.slice(0, 12)}…</code> <CopyButton value={f.sha256} label={t('pub.copyHash')} /></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
            <p class="subtle pad">{t('pub.rulesIncluded', { rules: d.rulesApproved.join(', ') || '—' })}</p>
          </Card>
        </div>
      </div>
    {:else}
      <Loading error={detail.error} onretry={detail.reload} />
    {/if}
  </section>
</div>

<Modal bind:open={newOpen} title={t('pub.new')} onclose={() => { if (loc.query.world && !started) navigate('/packs'); started = false; runError = ''; runStale = false; runMixed = false; picked = {}; multiGroup = false; }}>
  <div class="stack">
    <p class="muted">{t('pub.newHint')}</p>
    <Field label={t('pub.world')} hint={t('pub.worldNewest')}>
      {#snippet children({ id })}
        <select {id} bind:value={worldId} disabled={busy}>
          {#each worldsByDate as w (w.id)}<option value={w.id}>{w.id} · seed {w.seed} · {t('pub.customers', { n: w.customers })} · {fmtDate(w.createdAt)}{w.id === newestWorld?.id ? ' · ' + t('pub.newest') : ''}</option>{/each}
        </select>
      {/snippet}
    </Field>
    {#if packGroup}<p class="subtle">{t('pub.packGroup', { group: packGroup })}</p>{/if}
    {#if canMulti}
      <label class="chk"><input type="checkbox" bind:checked={multiGroup} disabled={busy} /> {t('pub.multiGroup')}</label>
      {#if multiGroup}<p class="callout warn" role="status">{t('pub.multiGroupWarn')}</p>{/if}
    {/if}
    <fieldset class="svcs">
      <legend>{t('pub.svc.title')}</legend>
      <p class="subtle">{t('pub.svc.hint')}</p>
      {#if packServices.data}
        {#if packServices.data.length === 0}
          <p class="subtle">{t('pub.svc.none')}</p>
        {:else}
          <ul class="svc-list">
            {#each packServices.data as s (serviceKey(s.group, s.name))}
              <li>
                <label class="chk">
                  <input type="checkbox" checked={inPack(s)} disabled={busy} onchange={(e) => (picked[serviceKey(s.group, s.name)] = e.currentTarget.checked)} />
                  <span class="mono">{s.name}</span>
                  {#if multiGroup}<GroupTag group={s.group ?? ''} always />{/if}
                  {#if s.name.startsWith('host:') && !s.baseUrl}<span class="subtle">{t('pub.svc.undeclared')}</span>{/if}
                </label>
              </li>
            {/each}
          </ul>
          <p class="subtle">{t('pub.svc.count', { n: includedNames.length, out: excludedNames.length })}</p>
        {/if}
      {:else}
        <Loading error={packServices.error} lines={2} />
      {/if}
    </fieldset>
    {#if busy}
      <div role="status" aria-live="polite" class="stack-sm">
        <ProgressBar value={Math.min(0.95, runElapsed / 30)} label={t('pub.running')} showValue={false} />
        <p class="subtle">{t('pub.runningHint', { s: runElapsed })}</p>
      </div>
    {/if}
    {#if runError}
      <div class="callout danger" role="alert">
        <p>{runError}</p>
        {#if runMixed && canMulti && !multiGroup}<p><Button size="sm" onclick={() => (multiGroup = true)}>{t('pub.multiGroup')}</Button></p>{/if}
        {#if runStale}<p><Button size="sm" variant="primary" icon="worlds" onclick={() => { newOpen = false; navigate('/worlds'); }}>{t('pub.regenerate')}</Button></p>{/if}
      </div>
    {/if}
    <Field label={t('pub.validDays')} help="pack.validDays" hint={t('pub.validDaysHint')} error={daysOk ? '' : t('pub.validDaysInvalid')}>
      {#snippet children({ id, describedby })}<input {id} inputmode="numeric" bind:value={validDays} aria-describedby={describedby} placeholder="90" />{/snippet}
    </Field>
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (newOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" loading={busy} disabled={!worldId || !daysOk} onclick={run}>{t('pub.run')}</Button>
  {/snippet}
</Modal>

<Modal bind:open={releaseOpen} title={t('pub.publish')}>
  <div class="stack">
    <p class="muted">{t('pub.publishHint')}</p>
    <ApprovalNotice approvals={settings.data?.approvals} />
    {#each d?.checks.filter((c) => c.status === 'warn') ?? [] as c (c.id)}
      <p class="callout warn" role="alert"><b>{t('pub.warnBeforePublish')}</b> {tk(`gate.${c.id}.warn`)}</p>
    {/each}
    {#if override}
      <div class="callout warn" role="alert">
        <b>{t('pub.overrideTitle')}</b> {t('pub.overrideWarn')}
      </div>
      <Field label={t('pub.reason')} help="pack.reason" hint={t('pub.reasonHint')}>
        {#snippet children({ id, describedby })}<textarea {id} bind:value={reason} rows="3" aria-describedby={describedby}></textarea>{/snippet}
      </Field>
    {/if}
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (releaseOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" loading={busy} disabled={!d || (override && reason.trim() === '')} onclick={() => d && release(d)}>{override ? t('pub.runOverride') : t('pub.publish')}</Button>
  {/snippet}
</Modal>

<Modal bind:open={exportOpen} title={report ? t('pub.exportTitle', { target: tk(`export.${report.target}`) }) : ''}>
  {#if report}
    <div class="stack">
      <div>
        <h3 class="fs-4">{t('pub.exp.produced')}</h3>
        <ul class="list">{#each report.produced as f, i (i)}<li><code>{f.path}</code><div class="subtle">{f.description}</div></li>{/each}</ul>
      </div>
      <div>
        <h3 class="fs-4">{t('pub.exp.preserved')}</h3>
        <ul class="list ok">{#each report.preserved as x, i (i)}<li>{x}</li>{/each}</ul>
      </div>
      <div class="callout warn">
        <h3 class="fs-4">{t('pub.exp.lost')}</h3>
        <ul class="list">{#each report.lost as l, i (i)}<li><b>{l.item}</b><div class="subtle">{l.reason}</div></li>{/each}</ul>
      </div>
      <p class="subtle">{t('pub.exp.reportNote')} <code>export-report.json</code></p>
    </div>
  {/if}
  {#snippet footer()}
    {#if report?.exportId}<Button variant="primary" icon="download" onclick={downloadExportZip}>{t('pub.exp.download')}</Button>{/if}
    <Button onclick={() => (exportOpen = false)}>{t('common.close')}</Button>
  {/snippet}
</Modal>

<style>
  .gap { height: var(--s-4); }
  .chk { display: flex; gap: var(--s-2); align-items: center; min-height: 28px; }
  .svcs { border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3); margin: 0; min-width: 0; }
  .svcs legend { font-weight: 600; padding: 0 var(--s-1); }
  .svc-list { list-style: none; margin: var(--s-2) 0; padding: 0; display: flex; flex-direction: column; max-height: 14rem; overflow: auto; }
  .flow { list-style: none; margin: 0 0 var(--s-3); padding: 0; display: flex; gap: var(--s-2); align-items: stretch; flex-wrap: wrap; }
  .flow li:not(.arrow) { flex: 1 1 160px; display: flex; flex-direction: column; gap: 2px; padding: var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-md); background: var(--surface-2); font-size: 0.9rem; }
  .flow li.gate { border-color: var(--accent); background: var(--accent-soft); }
  .flow .arrow { display: grid; place-items: center; color: var(--fg-subtle); }
  .note { margin-top: var(--s-2); }
  .layout { display: grid; grid-template-columns: minmax(280px, 400px) minmax(0, 1fr); gap: var(--s-5); align-items: start; }
  .main { min-width: 0; }
  .ovr { margin-top: var(--s-3); }
  .reason { font-style: italic; }
  .pipe { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 200px), 1fr)); gap: var(--s-3); }
  .step { display: flex; gap: var(--s-3); align-items: flex-start; padding: var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-md); background: var(--surface); min-width: 0; }
  .ico { flex: none; display: grid; place-items: center; width: 28px; height: 28px; border-radius: 50%; background: var(--surface-3); color: var(--fg-muted); }
  .pass { border-color: var(--success); }
  .pass .ico { background: var(--success); color: var(--surface); }
  .fail { border-color: var(--danger); background: var(--danger-soft); }
  .fail .ico { background: var(--danger); color: var(--surface); }
  .running { border-color: var(--info); }
  .skipped { border-style: dashed; }
  .blocked { margin-top: var(--s-4); }
  .finds { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: var(--s-2); }
  .ptr { word-break: break-all; color: var(--fg-muted); }
  .hash { color: var(--fg-muted); }
  .risk { display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr)); gap: var(--s-3); margin: 0 0 var(--s-3); }
  .risk dt { color: var(--fg-muted); font-size: 0.82rem; }
  .risk dd { margin: 2px 0 0; font-weight: 650; }
  .pad { padding: var(--s-3) var(--s-4); }
  .list { margin: var(--s-1) 0 0; padding-left: 18px; display: flex; flex-direction: column; gap: var(--s-2); }
  .list.ok li::marker { color: var(--success); content: '✓ '; }
  @media (max-width: 1100px) { .layout { grid-template-columns: minmax(0, 1fr); } .flow .arrow { display: none; } }
</style>
