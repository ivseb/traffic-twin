<script lang="ts">
  // «Ritira regola»: a rule-reviewer (or an admin) takes an approved rule out of the packs (usability test #5, major 1:
  // a rule replaced by the miner stayed approved and active, with its effects added to the new one's). POST
  // /rules/{id}/retire; a server without the route answers `unsupported` and the button explains instead of failing.
  import Button from './Button.svelte';
  import Modal from './Modal.svelte';
  import Field from './Field.svelte';
  import InfoTip from './InfoTip.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { Rule } from '../lib/api';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { features, isUnsupported } from '../lib/features.svelte';

  interface Props {
    rule: Rule;
    /** A newer rule that replaces this one and is approved too: both are in the packs. */
    replacedBy?: Rule;
    onchange?: (r: Rule) => void;
  }
  let { rule, replacedBy, onchange }: Props = $props();

  let open = $state(false);
  let note = $state('');
  let busy = $state(false);
  let notice = $state('');

  async function go(): Promise<void> {
    busy = true;
    try {
      const r = await api.rules.retire(rule.id, note.trim() || undefined);
      toast(t('fix5.rr.done', { id: rule.id }));
      open = false;
      note = '';
      onchange?.(r);
    } catch (e) {
      if (isUnsupported(e)) {
        features.retire = false;
        open = false;
        notice = t('fix5.rr.unsupported');
      } else toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="stack-sm" data-testid="retire-rule">
  {#if replacedBy?.status === 'approved'}
    <p class="callout warn" role="status" data-testid="replaced-by">{t('fix5.rr.replacedBy', { id: replacedBy.id })}</p>
  {:else if replacedBy?.status === 'draft'}
    <p class="callout" role="status">{t('fix5.rr.replacedByDraft', { id: replacedBy.id })}</p>
  {/if}
  {#if features.retire}
    <div class="row-tight">
      <Button variant="danger" icon="close" denied={!can('rules.review')} data-testid="retire-rule-button" onclick={() => { notice = ''; open = true; }}>{t('fix5.rr.button')}</Button>
      <InfoTip id="rule.retire" />
    </div>
  {:else}
    <p class="callout warn" role="status" data-testid="retire-unsupported">{notice || t('fix5.rr.unsupported')}</p>
  {/if}
  {#if notice && features.retire}<p class="callout warn" role="status">{notice}</p>{/if}
</div>

<Modal bind:open title={t('fix5.rr.title', { id: rule.id })}>
  <div class="stack">
    <p>{t('fix5.rr.message')}</p>
    <Field label={t('fix5.rr.note')} help="rule.retire">
      {#snippet children({ id, describedby })}<textarea {id} bind:value={note} rows="2" maxlength="500" aria-describedby={describedby}></textarea>{/snippet}
    </Field>
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (open = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" loading={busy} onclick={go}>{t('fix5.rr.confirm')}</Button>
  {/snippet}
</Modal>
