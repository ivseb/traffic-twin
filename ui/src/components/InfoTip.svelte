<script lang="ts">
  // Help affordance: an (i) button that opens a small popover with the meaning, the
  // practical effect, the default and when to change it. Keyboard accessible
  // (Enter/Space toggles, Esc closes, focus stays on the trigger).
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import RichText from './RichText.svelte';
  import { fieldHelp, helpUi } from '../lib/help/index.svelte';

  interface Props {
    /** Key in the help `fields` content. */
    id: string;
    /** Custom trigger (e.g. a status pill); defaults to the (i) icon. */
    children?: Snippet;
    /** Accessible name of the default trigger. */
    label?: string;
  }
  let { id, children, label }: Props = $props();

  const help = $derived(fieldHelp(id));
  const uid = $props.id();
  let open = $state(false);
  let trigger: HTMLButtonElement | undefined = $state();
  let pop: HTMLDivElement | undefined = $state();
  let pos = $state({ top: 0, left: 0 });

  function place(): void {
    if (!trigger) return;
    const r = trigger.getBoundingClientRect();
    const w = Math.min(340, window.innerWidth - 16);
    const left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8));
    const below = r.bottom + 6;
    const h = pop?.offsetHeight ?? 160;
    const top = below + h > window.innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : below;
    pos = { top, left };
  }

  async function toggle(): Promise<void> {
    open = !open;
    if (open) {
      place();
      queueMicrotask(place);
    }
  }
  function onkey(e: KeyboardEvent): void {
    if (e.key === 'Escape' && open) {
      open = false;
      trigger?.focus();
      e.stopPropagation();
    }
  }
  function onwindow(e: Event): void {
    if (open && e.target instanceof Node && !trigger?.contains(e.target) && !pop?.contains(e.target)) open = false;
  }
</script>

<svelte:window onclick={onwindow} onfocusin={onwindow} onresize={() => open && place()} onscroll={() => open && place()} />

{#if help}
  <span class="tip">
    <button
      bind:this={trigger}
      type="button"
      class:icon={!children}
      class:custom={!!children}
      aria-expanded={open}
      aria-controls={open ? `${uid}-p` : undefined}
      aria-haspopup="dialog"
      aria-label={children ? undefined : (label ?? `${helpUi('about')}: ${help.title}`)}
      onclick={toggle}
      onkeydown={onkey}
    >
      {#if children}{@render children()}{:else}<Icon name="help" size={14} />{/if}
    </button>
    {#if open}
      <div bind:this={pop} class="pop" id="{uid}-p" role="dialog" aria-label={help.title} tabindex="-1" onkeydown={onkey} style:top="{pos.top}px" style:left="{pos.left}px">
        <strong class="ttl">{help.title}</strong>
        <p><RichText text={help.meaning} /></p>
        {#if help.effect}<p><span class="k">{helpUi('effect')}</span> <RichText text={help.effect} /></p>{/if}
        {#if help.default}<p><span class="k">{helpUi('default')}</span> <RichText text={help.default} /></p>{/if}
        {#if help.when}<p><span class="k">{helpUi('when')}</span> <RichText text={help.when} /></p>{/if}
        {#if help.example}<p><span class="k">{helpUi('example')}</span> <RichText text={help.example} /></p>{/if}
        {#if help.term}<p class="more"><a href="#/glossary?term={help.term}">{helpUi('moreGlossary')}</a></p>{/if}
      </div>
    {/if}
  </span>
{/if}

<style>
  .tip { display: inline-flex; vertical-align: middle; }
  button { font: inherit; border: 0; cursor: pointer; }
  .icon { display: inline-grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; background: transparent; color: var(--fg-subtle); padding: 0; }
  .icon:hover, .icon[aria-expanded='true'] { color: var(--accent); background: var(--accent-soft); }
  .custom { background: none; padding: 0; color: inherit; border-radius: 999px; text-align: inherit; }
  .pop { position: fixed; z-index: 90; width: min(340px, calc(100vw - 16px)); background: var(--surface); color: var(--fg); border: 1px solid var(--border-strong); border-radius: var(--r-lg); box-shadow: var(--shadow-md); padding: var(--s-3) var(--s-4); display: flex; flex-direction: column; gap: var(--s-2); font-size: 0.88rem; font-weight: 400; text-transform: none; letter-spacing: 0; text-align: left; white-space: normal; }
  .ttl { font-size: 0.9rem; font-weight: 600; }
  .k { font-weight: 600; color: var(--fg-muted); }
  .more { margin-top: 2px; }
</style>
