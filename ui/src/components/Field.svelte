<script lang="ts">
  import type { Snippet } from 'svelte';
  import InfoTip from './InfoTip.svelte';

  // Label + help + hint + error wrapper. The control receives `id` and `describedby`.
  interface Props {
    label: string;
    hint?: string;
    error?: string;
    /** Key in the help content: adds the (i) popover next to the label. */
    help?: string;
    children: Snippet<[{ id: string; describedby: string }]>;
  }
  let { label, hint, error, help, children }: Props = $props();
  const uid = $props.id();
  const describedby = $derived([hint ? `${uid}-h` : '', error ? `${uid}-e` : ''].filter(Boolean).join(' '));

  // The control is rendered by the caller: mark it invalid while the error shows (unless the caller already did).
  $effect(() => {
    const el = document.getElementById(uid);
    if (!el || !error || el.hasAttribute('aria-invalid')) return;
    el.setAttribute('aria-invalid', 'true');
    return () => el.removeAttribute('aria-invalid');
  });
</script>

<div class="field">
  <div class="lbl"><label for={uid}>{label}</label>{#if help}<InfoTip id={help} />{/if}</div>
  {@render children({ id: uid, describedby })}
  {#if hint}<p class="subtle" id="{uid}-h">{hint}</p>{/if}
  {#if error}<p class="err" id="{uid}-e" role="alert">{error}</p>{/if}
</div>

<style>
  .field { display: flex; flex-direction: column; gap: 4px; }
  .lbl { display: flex; align-items: center; gap: 2px; }
  .err { color: var(--danger); font-size: 0.86rem; }
</style>
