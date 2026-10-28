<script lang="ts">
  // Approval of one policy version from the page that created it (onboarding wizard): an approver approves, an admin
  // approves alone with a reason (the override, audited and alerted). Never a value on screen: only the version.
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import StatusPill from './StatusPill.svelte';
  import ApproverHelp from './ApproverHelp.svelte';
  import WithdrawDraft from './WithdrawDraft.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { PolicyVersion } from '../lib/api';
  import { can, session, toast, toastError } from '../lib/stores.svelte';

  interface Props {
    version: PolicyVersion;
    /** Label of the admin approval button (e.g. "Approva e avvia la cattura"). */
    adminLabel?: string;
    onchange?: (v: PolicyVersion) => void;
  }
  let { version, adminLabel, onchange }: Props = $props();

  let reason = $state('');
  let busy = $state(false);
  const admin = $derived(can('override.admin'));
  const mine = (n?: string) => !!n && (n === session.user?.username || n === session.user?.displayName);
  const selfBlocked = $derived(!admin && version.approvalsRequired === 2 && mine(version.proposedBy));
  const already = $derived(version.approvals.some((a) => mine(a.by) && a.tokenFresh !== false));

  async function approve(): Promise<void> {
    busy = true;
    try {
      const r = await api.policies.approve(version.policyId, version.version, admin ? reason.trim() : undefined);
      toast(r.status === 'active' ? t('pol.activated', { v: r.version }) : t('pol.approved'));
      reason = '';
      onchange?.(r);
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="stack-sm">
  <div class="row head">
    <b class="mono">{version.policyId} v{version.version}</b>
    <StatusPill value={version.status} />
    <span class="subtle">{t('wiz.review.approvals', { n: version.approvals.length, total: version.approvalsRequired })}</span>
  </div>
  {#if version.status === 'draft'}
    {#if admin}
      <p class="callout warn" role="alert"><b>{t('pol.overrideWarnTitle')}</b> {t('pol.overrideWarn')}</p>
      <Field label={t('pol.reason')} help="pack.reason" hint={t('pol.reasonHint')}>
        {#snippet children({ id, describedby })}<textarea {id} bind:value={reason} rows="2" aria-describedby={describedby}></textarea>{/snippet}
      </Field>
      <div><Button variant="danger" icon="lock" disabled={reason.trim() === '' || already} loading={busy} onclick={approve}>{adminLabel ?? t('pol.approveAdmin')}</Button></div>
    {:else if can('policy.approve')}
      {#if selfBlocked}<p class="subtle">{t('wiz.review.cannotSelf')}</p>{/if}
      <div><Button variant="primary" icon="check" disabled={selfBlocked || already} loading={busy} onclick={approve}>{t('pol.approve')}</Button></div>
    {:else}
      <p class="subtle">{t('wiz.appr.other')}</p>
    {/if}
    <ApproverHelp {version} />
    {#if version.origin !== 'starter'}<div><WithdrawDraft {version} size="md" explain onchange={(v) => onchange?.(v)} /></div>{/if}
  {/if}
</div>

<style>
  .head { gap: var(--s-3); align-items: center; flex-wrap: wrap; }
</style>
