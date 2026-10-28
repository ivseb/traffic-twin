<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { toastError } from '../lib/stores.svelte';

  interface Props {
    open: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    tone?: 'primary' | 'danger';
    /** The user must type this word to enable the confirm button. */
    requireText?: string;
    onconfirm: () => void | Promise<void>;
  }
  let { open = $bindable(), title, message, confirmLabel, tone = 'danger', requireText, onconfirm }: Props = $props();

  let typed = $state('');
  let busy = $state(false);
  const ok = $derived(!requireText || typed.trim().toUpperCase() === requireText.toUpperCase());
  const uid = $props.id();

  $effect(() => {
    if (!open) typed = '';
  });

  async function go(): Promise<void> {
    busy = true;
    try {
      await onconfirm();
      open = false;
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open {title}>
  <div class="stack">
    <p>{message}</p>
    {#if requireText}
      <div class="stack-sm">
        <label for="{uid}-in">{t('confirm.type', { word: requireText })}</label>
        <input id="{uid}-in" bind:value={typed} autocomplete="off" />
      </div>
    {/if}
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (open = false)}>{t('common.cancel')}</Button>
    <Button variant={tone} disabled={!ok} loading={busy} onclick={go}>{confirmLabel}</Button>
  {/snippet}
</Modal>
