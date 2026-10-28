<script lang="ts">
  // «Simula questo host nel mock» for a host of the registry: confirm the base URL (the exact host for a pattern with
  // `{*}` or an IP class, checked against the pattern), the name of the service and the policy; it creates a new policy
  // version. Before confirming, the server's classification of that change (dry run): a change that opens no values
  // applies at once, one that opens values is a draft waiting for approvals. After, what really happened (applied at
  // HH:MM, or the draft waiting): never «2 approvals» for a change that needs none (usability test #4, M5).
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import PatternView from './PatternView.svelte';
  import Badge from './Badge.svelte';
  import ApprovalNotice from './ApprovalNotice.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { ChangeClass, HostEntry, PolicyVersion } from '../lib/api';
  import ApproverHelp from './ApproverHelp.svelte';
  import { href } from '../lib/router';
  import { fmtTime } from '../lib/format';
  import { can, errorMessage, toast } from '../lib/stores.svelte';
  import { resource } from '../lib/resource.svelte';
  import { ApiError } from '../lib/api/types';
  import { scopeGroups } from '../lib/scope.svelte';
  import { baseHint, checkBase, defaultServiceName, exactBaseUrl, isIpClass, splitPort, validServiceName } from '../lib/hosts';

  interface Props {
    open: boolean;
    host: HostEntry | null;
    /** Called after the draft exists (the registry should be reloaded). */
    ondone?: () => void;
  }
  let { open = $bindable(), host, ondone }: Props = $props();

  const settings = resource(() => api.settings.get());
  // Only the policies of the host's group: the same pattern called by another team is that team's entry.
  const known = resource(() => api.policies.list(host?.group ? [host.group] : scopeGroups()));

  let base = $state('');
  // The scheme of an exact host: the events do not carry it (the default port of http and https is left out), so the
  // person chooses it; there is no default.
  let scheme = $state<'' | 'http' | 'https'>('');
  let service = $state('');
  let policyId = $state('');
  let busy = $state(false);
  let error = $state('');
  let errorCode = $state('');
  let created = $state<PolicyVersion | null>(null);
  let reason = $state('');
  let approving = $state(false);
  let approveError = $state('');
  let activated = $state(false);
  // The server's classification of the change, asked before creating it (undefined: not asked yet; null: unknown).
  let klass = $state<ChangeClass | null | undefined>(undefined);
  let checking = $state(false);
  let appliedAt = $state('');

  // A fresh form every time the dialog opens for a host.
  $effect(() => {
    if (!open || !host) return;
    base = '';
    scheme = '';
    service = '';
    policyId = host.policies.length === 1 ? host.policies[0] : '';
    error = errorCode = reason = approveError = '';
    created = null;
    activated = false;
    busy = approving = false;
    klass = undefined;
    appliedAt = '';
  });
  // A change of the form asks the server again.
  $effect(() => {
    void base;
    void scheme;
    void service;
    void policyId;
    klass = undefined;
  });

  const pattern = $derived(host?.pattern ?? '');
  const ipClass = $derived(isIpClass(splitPort(pattern).host));
  const needsBase = $derived(!!host && !host.exact);
  const required = $derived(settings.data?.approvals.openingRequired ?? 2);
  const policyOptions = $derived(host && host.policies.length > 1 ? host.policies : [...new Set((known.data ?? []).map((p) => p.policyId))].sort());
  const askPolicy = $derived(!!host && host.policies.length !== 1 && policyOptions.length > 1);
  const effectivePolicy = $derived(policyId || (policyOptions.length === 1 && host?.policies.length !== 1 ? policyOptions[0] : ''));

  const baseTyped = $derived(base.trim());
  const check = $derived(baseTyped ? checkBase(pattern, baseTyped) : null);
  const baseError = $derived(check && !check.ok ? t(`err.${check.code}` as 'err.invalid_base') : errorCode === 'base_required' || errorCode === 'base_mismatch' || errorCode === 'invalid_base' ? error : '');
  const nameDefault = $derived(defaultServiceName(baseTyped || (host?.exact ? (exactBaseUrl(pattern, 'https') ?? '') : '')) ?? '');
  const nameTyped = $derived(service.trim());
  const serviceError = $derived(nameTyped && !validServiceName(nameTyped) ? t('err.invalid_service') : errorCode === 'service_exists' ? error : '');
  const canSubmit = $derived(
    !!host && (needsBase ? baseTyped !== '' && !!check?.ok : scheme !== '') && (!baseTyped || !!check?.ok) && !serviceError && (!askPolicy || !!effectivePolicy) && !busy,
  );

  function input() {
    return {
      pattern: host!.pattern,
      ...(host!.group ? { group: host!.group } : {}),
      ...(effectivePolicy ? { policyId: effectivePolicy } : {}),
      ...(nameTyped ? { service: nameTyped } : {}),
      ...(needsBase && baseTyped ? { base: baseTyped } : {}),
      ...(!needsBase && scheme ? { scheme } : {}),
    };
  }

  /** Asks the server how the change would apply; the form shows it before the confirmation. */
  async function classify(): Promise<void> {
    if (!host) return;
    checking = true;
    try {
      klass = await api.hosts.twinPreview(input());
    } catch {
      klass = null;
    } finally {
      checking = false;
    }
  }

  async function submit(): Promise<void> {
    if (!host) return;
    if (klass === undefined) return classify();
    busy = true;
    error = errorCode = '';
    try {
      created = await api.hosts.twin({
        pattern: host.pattern,
        ...(host.group ? { group: host.group } : {}),
        ...(effectivePolicy ? { policyId: effectivePolicy } : {}),
        ...(nameTyped ? { service: nameTyped } : {}),
        ...(needsBase && baseTyped ? { base: baseTyped } : {}),
        ...(!needsBase && scheme ? { scheme } : {}),
      });
      activated = created.status === 'active';
      appliedAt = fmtTime(created.proposedAt ?? new Date().toISOString());
      toast(activated ? t('fix4.twin.applied', { time: appliedAt, v: created.version }) : t('hosts.twin.created', { policy: created.policyId, v: created.version }));
      ondone?.();
    } catch (e) {
      error = errorMessage(e);
      errorCode = e instanceof ApiError ? (e.serverCode ?? '') : '';
    } finally {
      busy = false;
    }
  }

  async function approveAsAdmin(): Promise<void> {
    if (!created) return;
    approving = true;
    approveError = '';
    try {
      const r = await api.policies.approve(created.policyId, created.version, reason.trim());
      created = r;
      activated = r.status === 'active';
      toast(activated ? t('pol.activated', { v: r.version }) : t('pol.approved'));
      ondone?.();
    } catch (e) {
      approveError = errorMessage(e);
    } finally {
      approving = false;
    }
  }
</script>

<Modal bind:open title={t('hosts.twin.title')}>
  {#if host}
    <div class="stack">
      <div class="who">
        <PatternView {pattern} strong />
        {#if ipClass}<Badge tone="info">{t('hosts.ip.badge')}</Badge>{/if}
      </div>

      {#if !created}
        <p class="callout">{t('fix4.twin.note')}</p>

        {#if needsBase}
          <p class="callout warn">{ipClass ? t('hosts.twin.needBaseIp') : t('hosts.twin.needBase')}</p>
        {/if}

        {#if needsBase}
          <Field label={t('hosts.twin.base')} help="hosts.base" hint={t('hosts.twin.baseHintExact', { example: baseHint(pattern) })} error={baseError}>
            {#snippet children({ id, describedby })}
              <input {id} bind:value={base} placeholder={baseHint(pattern)} aria-describedby={describedby} aria-invalid={baseError ? 'true' : undefined} spellcheck="false" autocomplete="off" inputmode="url" />
            {/snippet}
          </Field>
        {:else}
          <fieldset class="scheme">
            <legend>{t('hosts.twin.scheme')}</legend>
            <div class="row">
              {#each ['http', 'https'] as const as sc (sc)}
                <label class="chk"><input type="radio" name="twin-scheme" value={sc} bind:group={scheme} /> <span class="mono">{sc}://{pattern}</span></label>
              {/each}
            </div>
            <p class="subtle">{t('hosts.twin.schemeHint')}</p>
            {#if errorCode === 'scheme_required' || errorCode === 'base_mismatch'}<p class="callout danger" role="alert">{error}</p>{/if}
          </fieldset>
        {/if}

        <Field label={t('hosts.twin.service')} hint={t('hosts.twin.serviceHint')} error={serviceError}>
          {#snippet children({ id, describedby })}
            <input {id} bind:value={service} placeholder={nameDefault} aria-describedby={describedby} aria-invalid={serviceError ? 'true' : undefined} spellcheck="false" autocomplete="off" />
          {/snippet}
        </Field>

        {#if askPolicy}
          <Field label={t('hosts.twin.policy')} hint={t('hosts.twin.policyHint')}>
            {#snippet children({ id, describedby })}
              <select {id} bind:value={policyId} aria-describedby={describedby}>
                <option value="">{t('hosts.twin.policyPick')}</option>
                {#each policyOptions as p (p)}<option value={p}>{p}</option>{/each}
              </select>
            {/snippet}
          </Field>
        {/if}

        {#if checking}
          <p class="callout" role="status">{t('fix4.twin.checking')}</p>
        {:else if klass}
          <p class="callout {klass.opensValues ? 'warn' : 'ok'}" role="status" data-testid="twin-class">{klass.opensValues ? t('fix4.twin.opens', { n: klass.approvalsRequired || required }) : t('fix4.twin.safe')}</p>
          {#if klass.opensValues}<ApprovalNotice approvals={settings.data?.approvals} />{/if}
        {:else if klass === null}
          <p class="callout" role="status" data-testid="twin-class">{t('fix4.twin.unknown')}</p>
        {/if}

        {#if error && !baseError && !serviceError}<p class="callout danger" role="alert">{error}</p>{/if}
      {:else}
        <div class="callout ok" role="status" data-testid="twin-done">
          <b>{activated ? t('fix4.twin.applied', { time: appliedAt, v: created.version }) : t('fix4.twin.waiting', { v: created.version, n: created.approvals.length, total: created.approvalsRequired })}</b>
        </div>
        <p class="subtle">{t('fix4.twin.ids')} <a href={href('/sources', {}, { tab: 'policy', bulk: '1', ...(host.group ? { group: host.group } : {}) })}>{t('fix4.twin.idsLink')}</a></p>
        {#if !activated}
          {#if !can('override.admin')}<ApproverHelp version={created} {required} />{/if}
          {#if can('override.admin')}
            <div class="stack-sm override">
              <p class="callout warn" role="alert"><b>{t('pol.overrideWarnTitle')}</b> {t('pol.overrideWarn')}</p>
              <Field label={t('pol.reason')} help="pack.reason" hint={t('pol.reasonHint')} error={approveError}>
                {#snippet children({ id, describedby })}<textarea {id} bind:value={reason} rows="2" aria-describedby={describedby}></textarea>{/snippet}
              </Field>
            </div>
          {/if}
        {/if}
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    {#if !created}
      <Button variant="ghost" onclick={() => (open = false)}>{t('common.cancel')}</Button>
      <Button variant="primary" icon={klass === undefined ? 'check' : 'plus'} denied={!can('hosts.twin')} disabled={!canSubmit || checking} loading={busy || checking} onclick={submit}>{klass === undefined ? t('fix4.twin.check') : t('fix4.twin.confirm')}</Button>
    {:else}
      <Button variant="ghost" onclick={() => (open = false)}>{t('common.close')}</Button>
      {#if !activated}
        {#if can('override.admin')}
          <Button variant="danger" disabled={reason.trim() === ''} loading={approving} onclick={approveAsAdmin}>{t('pol.approveAdmin')}</Button>
        {/if}
        <Button variant="primary" href="#/sources?tab=policy">{t('hosts.twin.goApprove')}</Button>
      {/if}
    {/if}
  {/snippet}
</Modal>

<style>
  .who { display: flex; align-items: center; gap: var(--s-3); flex-wrap: wrap; font-size: 1.05rem; padding: var(--s-2) var(--s-3); background: var(--surface-2); border-radius: var(--r-sm); }
  .override { padding-top: var(--s-2); }
  .scheme { border: 0; padding: 0; margin: 0; display: grid; gap: var(--s-2); }
  .scheme legend { font-weight: 600; margin-bottom: var(--s-1); }
  .scheme .row { display: flex; gap: var(--s-4); flex-wrap: wrap; }
  .chk { display: inline-flex; gap: var(--s-2); align-items: center; }
</style>
