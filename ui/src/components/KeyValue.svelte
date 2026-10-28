<script lang="ts">
  interface Item {
    k: string;
    v: string | number | undefined | null;
    mono?: boolean;
  }
  let { items, cols = 1 }: { items: Item[]; cols?: 1 | 2 } = $props();
</script>

<dl class:two={cols === 2}>
  {#each items as it (it.k)}
    <div>
      <dt>{it.k}</dt>
      <dd class:mono={it.mono}>{it.v ?? '—'}</dd>
    </div>
  {/each}
</dl>

<style>
  dl { margin: 0; display: grid; gap: var(--s-2) var(--s-5); grid-template-columns: 1fr; }
  dl.two { grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); }
  div { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  dt { font-size: 0.78rem; color: var(--fg-subtle); text-transform: uppercase; letter-spacing: 0.03em; font-weight: 600; }
  dd { margin: 0; }
</style>
