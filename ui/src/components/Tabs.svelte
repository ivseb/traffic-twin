<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Tab {
    id: string;
    label: string;
    count?: number;
    /** What the count counts, said next to it («bozze in attesa»). */
    countLabel?: string;
  }
  let { tabs, value = $bindable(), children, label }: { tabs: Tab[]; value: string; children: Snippet; label: string } = $props();

  const uid = $props.id();

  function onkey(e: KeyboardEvent): void {
    // The tab that has the focus, not `value`: when the selection lives in the URL it follows with a delay.
    const focused = tabs.findIndex((x) => `${uid}-tab-${x.id}` === document.activeElement?.id);
    const i = focused >= 0 ? focused : tabs.findIndex((x) => x.id === value);
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    value = tabs[next].id;
    document.getElementById(`${uid}-tab-${tabs[next].id}`)?.focus();
  }
</script>

<div class="tabs" role="tablist" aria-label={label} tabindex="-1" onkeydown={onkey}>
  {#each tabs as tab (tab.id)}
    <button
      type="button"
      role="tab"
      id="{uid}-tab-{tab.id}"
      aria-selected={value === tab.id}
      aria-controls="{uid}-panel"
      tabindex={value === tab.id ? 0 : -1}
      class:active={value === tab.id}
      onclick={() => (value = tab.id)}
    >
      {tab.label}
      {#if tab.count !== undefined}<span class="n" title={tab.countLabel}>{tab.count}{#if tab.countLabel}<span class="nl"> {tab.countLabel}</span>{/if}</span>{/if}
    </button>
  {/each}
</div>
<div role="tabpanel" id="{uid}-panel" aria-labelledby="{uid}-tab-{value}" class="panel">
  {@render children()}
</div>

<style>
  .tabs { display: flex; gap: var(--s-1); border-bottom: 1px solid var(--border); overflow-x: auto; margin-bottom: var(--s-4); }
  button {
    font: inherit;
    font-weight: 560;
    color: var(--fg-muted);
    background: none;
    border: 0;
    border-bottom: 2px solid transparent;
    padding: 0.6rem 0.9rem;
    cursor: pointer;
    white-space: nowrap;
    margin-bottom: -1px;
  }
  button:hover { color: var(--fg); }
  button.active { color: var(--accent); border-bottom-color: var(--accent); }
  .n { background: var(--surface-3); color: var(--fg-muted); border-radius: 999px; padding: 0 0.45rem; font-size: 0.75rem; margin-left: 0.25rem; }
  .panel { min-width: 0; }
</style>
