<script lang="ts">
  // «Ritira bozza»: the proposer (or an admin) takes a pending policy draft back (usability test #5, major 2). A
  // confirmation says what is lost and what stays. The route is POST /fleet/policies/{id}/versions/{v}/withdraw: a
  // server without it answers `unsupported` and the button explains instead of failing (the REST adapter turns the 404/405).
  import Button from './Button.svelte';
  import Modal from './Modal.svelte';
  import Field from './Field.svelte';
  import InfoTip from './InfoTip.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { PolicyVersion } from '../lib/api';
  import { can, session, toast, toastError } from '../lib/stores.svelte';
  import { canWithdraw } from '../lib/approval';
  import { features, isUnsupported } from '../lib/features.svelte';

  interface Props {
    version: PolicyVersion;
    size?: 'sm' | 'md';
    /** Show the sentence «la ritira chi l’ha proposta o un amministratore» when the person cannot. */
    explain?: boolean;
    onchange?: (v: PolicyVersion) => void;
  }
  let { version, size = 'sm', explain = false, onchange }: Props = $props();

  let open = $state(false);
  let reason = $state('');
  let busy = $state(false);
  let notice = $state('');
  const allowed = $derived(canWithdraw(version, session.user, can('override.admin')));

  async function go(): Promise<void> {
    busy = true;
    notice = '';
    try {
      const r = await api.policies.withdraw(version.policyId, version.version, reason.trim() || undefined);
      toast(t('fix5.wd.done', { v: version.version }));
      open = false;
      reason = '';
      onchange?.(r);
    } catch (e) {
      if (isUnsupported(e)) {
        features.withdraw = false;
        open = false;
        notice = t('fix5.wd.unsupported');
      } else toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if version.status === 'draft'}
  {#if allowed && features.withdraw}
    <span class="wd">
      <Button {size} variant="ghost" icon="close" data-testid="withdraw-draft" onclick={() => { notice = ''; open = true; }}>{t('fix5.wd.button')}</Button>
      <InfoTip id="policy.withdraw" />
    </span>
  {:else if allowed && !features.withdraw}
    <span class="subtle" role="status" data-testid="withdraw-unsupported">{t('fix5.wd.unsupported')}</span>
  {:else if explain}
    <span class="subtle">{t('fix5.wd.only')}</span>
  {/if}
  {#if notice}<p class="callout warn" role="status">{notice}</p>{/if}

  <Modal bind:open title={t('fix5.wd.title', { policy: version.policyId, v: version.version })}>
    <div class="stack">
      <p>{t('fix5.wd.message', { have: version.approvals.length, total: version.approvalsRequired })}</p>
      <Field label={t('fix5.wd.reason')} help="policy.withdraw">
        {#snippet children({ id, describedby })}<textarea {id} bind:value={reason} rows="2" maxlength="500" aria-describedby={describedby}></textarea>{/snippet}
      </Field>
    </div>
    {#snippet footer()}
      <Button variant="ghost" onclick={() => (open = false)}>{t('common.cancel')}</Button>
      <Button variant="danger" loading={busy} onclick={go}>{t('fix5.wd.confirm')}</Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .wd { display: inline-flex; align-items: center; gap: var(--s-1); }
</style>
