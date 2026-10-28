<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon, { type IconName } from './Icon.svelte';
  let { title, description, icon = 'info', children, level = 2 }: { title: string; description?: string; icon?: IconName; children?: Snippet; level?: 2 | 3 } = $props();
</script>

<div class="empty">
  <span class="ico"><Icon name={icon} size={26} /></span>
  <svelte:element this={`h${level}`} class="fs-3">{title}</svelte:element>
  {#if description}<p class="muted">{description}</p>{/if}
  {#if children}<div class="act">{@render children()}</div>{/if}
</div>

<style>
  .empty { display: flex; flex-direction: column; align-items: center; text-align: center; gap: var(--s-2); padding: var(--s-6) var(--s-4); max-width: 34rem; margin: 0 auto; }
  .ico { display: grid; place-items: center; width: 3.2rem; height: 3.2rem; border-radius: 50%; background: var(--accent-soft); color: var(--accent); }
  .act { margin-top: var(--s-2); }
</style>
