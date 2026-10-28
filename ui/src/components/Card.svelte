<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title?: string;
    subtitle?: string;
    actions?: Snippet;
    children: Snippet;
    flush?: boolean;
    tone?: 'default' | 'accent' | 'danger';
    id?: string;
    /** Heading level of the title: the page title is the h1, so cards default to h2. */
    level?: 2 | 3 | 4;
  }
  let { title, subtitle, actions, children, flush = false, tone = 'default', id, level = 2 }: Props = $props();
  const uid = $props.id();
  const hid = $derived(`${id ?? uid}-h`);
</script>

<section class="card {tone}" aria-labelledby={title ? hid : undefined} {id}>
  {#if title || actions}
    <header>
      <div class="grow">
        {#if title}<svelte:element this={`h${level}`} id={hid} class="fs-3">{title}</svelte:element>{/if}
        {#if subtitle}<p class="subtle">{subtitle}</p>{/if}
      </div>
      {#if actions}<div class="row-tight">{@render actions()}</div>{/if}
    </header>
  {/if}
  <div class="body" class:flush>{@render children()}</div>
</section>

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-sm);
    min-width: 0;
  }
  .accent { border-color: var(--accent); }
  .danger { border-color: var(--danger); }
  header {
    display: flex;
    gap: var(--s-3);
    align-items: flex-start;
    padding: var(--s-4) var(--s-4) 0;
    flex-wrap: wrap;
  }
  .body { padding: var(--s-4); }
  .body.flush { padding: 0; }
  header + .body.flush { margin-top: var(--s-3); }
</style>
