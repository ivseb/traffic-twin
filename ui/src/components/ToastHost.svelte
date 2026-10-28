<script lang="ts">
  // Status messages. Two live regions that exist before the first toast is added: errors are
  // announced at once (role=alert), the rest politely (role=status). A toast stays while the pointer
  // or the keyboard focus is on it. While a modal dialog is open everything outside it is inert, so
  // the dialog renders its own host (`inDialog`) and the page-level one is hidden meanwhile.
  import Icon from './Icon.svelte';
  import { toasts, dismissToast } from '../lib/stores.svelte';
  import { t } from '../lib/i18n/index.svelte';

  let { inDialog = false }: { inDialog?: boolean } = $props();
  const urgent = $derived(toasts.items.filter((x) => x.tone === 'danger'));
  const calm = $derived(toasts.items.filter((x) => x.tone !== 'danger'));
</script>

{#snippet item(it: (typeof toasts.items)[number])}
  <div class="toast {it.tone}">
    <Icon name={it.tone === 'danger' || it.tone === 'warning' ? 'alert' : it.tone === 'info' ? 'info' : 'check'} />
    <span class="grow">{it.text}</span>
    <button type="button" aria-label={t('common.close')} onclick={() => dismissToast(it.id)}><Icon name="close" size={14} /></button>
  </div>
{/snippet}

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<section
  class="host"
  class:outer={!inDialog}
  aria-label={t('toast.region')}
  onmouseenter={() => (toasts.hold = true)}
  onmouseleave={() => (toasts.hold = false)}
  onfocusin={() => (toasts.hold = true)}
  onfocusout={() => (toasts.hold = false)}
>
  <div role="alert" class="list">{#each urgent as it (it.id)}{@render item(it)}{/each}</div>
  <div role="status" class="list">{#each calm as it (it.id)}{@render item(it)}{/each}</div>
</section>

<style>
  .host { position: fixed; z-index: 100; right: var(--s-4); bottom: var(--s-4); display: flex; flex-direction: column; gap: var(--s-2); width: min(24rem, calc(100vw - 2rem)); pointer-events: none; }
  .list { display: flex; flex-direction: column; gap: var(--s-2); }
  /* a modal dialog makes the page inert: its own copy takes over */
  :global(body:has(dialog[open])) .outer { visibility: hidden; }
  .toast { pointer-events: auto; display: flex; gap: var(--s-3); align-items: flex-start; background: var(--surface); color: var(--fg); border: 1px solid var(--border-strong); border-left: 4px solid var(--success); border-radius: var(--r-sm); box-shadow: var(--shadow-md); padding: var(--s-3); animation: in 0.15s ease-out; }
  .toast :global(svg) { margin-top: 2px; flex: none; }
  .danger { border-left-color: var(--danger); }
  .warning { border-left-color: var(--warning); }
  .info { border-left-color: var(--info); }
  button { all: unset; cursor: pointer; color: var(--fg-muted); padding: 2px; border-radius: 4px; }
  button:focus-visible { outline: 2px solid var(--focus); }
  @keyframes in { from { transform: translateY(0.5rem); opacity: 0; } }
</style>
