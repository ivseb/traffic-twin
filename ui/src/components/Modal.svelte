<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import ToastHost from './ToastHost.svelte';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    open: boolean;
    title: string;
    children: Snippet;
    footer?: Snippet;
    variant?: 'center' | 'drawer';
    onclose?: () => void;
  }
  let { open = $bindable(), title, children, footer, variant = 'center', onclose }: Props = $props();

  let el: HTMLDialogElement | undefined = $state();
  const uid = $props.id();

  // The native <dialog> gives us focus trapping, Esc handling and inertness.
  $effect(() => {
    if (!el) return;
    if (open && !el.open) el.showModal();
    else if (!open && el.open) el.close();
  });

  function handleClose(): void {
    open = false;
    onclose?.();
  }
  function backdrop(e: MouseEvent): void {
    if (e.target === el) el?.close();
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<dialog bind:this={el} class={variant} aria-labelledby="{uid}-t" onclose={handleClose} onclick={backdrop}>
  {#if open}
    <div class="panel">
      <header>
        <h2 id="{uid}-t">{title}</h2>
        <button type="button" class="x" aria-label={t('common.close')} onclick={() => el?.close()}><Icon name="close" /></button>
      </header>
      <div class="content">{@render children()}</div>
      {#if footer}<footer>{@render footer()}</footer>{/if}
      <ToastHost inDialog />
    </div>
  {/if}
</dialog>

<style>
  dialog {
    border: 0;
    padding: 0;
    color: var(--fg);
    background: var(--surface);
    box-shadow: var(--shadow-md);
    max-width: 100vw;
    max-height: 100dvh;
  }
  dialog::backdrop { background: var(--backdrop); }
  .center { border-radius: var(--r-lg); width: min(36rem, calc(100vw - 2rem)); max-height: calc(100dvh - 2rem); }
  .drawer { margin: 0 0 0 auto; height: 100dvh; max-height: 100dvh; width: min(34rem, 100vw); border-radius: 0; animation: slide 0.18s ease-out; }
  @keyframes slide { from { transform: translateX(2rem); opacity: 0; } }
  .panel { display: flex; flex-direction: column; max-height: inherit; height: 100%; }
  header { display: flex; align-items: center; gap: var(--s-3); padding: var(--s-4); border-bottom: 1px solid var(--border); }
  header h2 { flex: 1; font-size: 1.1rem; }
  .x { all: unset; cursor: pointer; display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: var(--r-sm); color: var(--fg-muted); }
  .x:hover { background: var(--surface-2); color: var(--fg); }
  .x:focus-visible { outline: 2px solid var(--focus); }
  .content { padding: var(--s-4); overflow-y: auto; flex: 1; }
  footer { display: flex; justify-content: flex-end; gap: var(--s-2); flex-wrap: wrap; padding: var(--s-3) var(--s-4); border-top: 1px solid var(--border); background: var(--surface-2); }
</style>
