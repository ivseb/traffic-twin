<script lang="ts">
  import type { WorldGraph, WorldNode } from '../lib/api';
  import { t } from '../lib/i18n/index.svelte';

  let { graph }: { graph: WorldGraph } = $props();

  const W = 150;
  const H = 40;
  const COLX: Record<WorldNode['type'], number> = { customer: 12, order: 236, shipment: 460 };

  const layout = $derived.by(() => {
    const orders = graph.nodes.filter((n) => n.type === 'order');
    const ships = graph.nodes.filter((n) => n.type === 'shipment');
    const rowH = 64;
    const height = Math.max(orders.length, 1) * rowH + 16;
    const pos = new Map<string, { x: number; y: number }>();
    graph.nodes.forEach((n) => {
      if (n.type === 'customer') pos.set(n.id, { x: COLX.customer, y: height / 2 - H / 2 });
    });
    orders.forEach((n, i) => pos.set(n.id, { x: COLX.order, y: 8 + i * rowH + (rowH - H) / 2 }));
    // a shipment sits on the row of the order it belongs to
    for (const s of ships) {
      const e = graph.edges.find((x) => x.to === s.id);
      const o = e ? pos.get(e.from) : undefined;
      pos.set(s.id, { x: COLX.shipment, y: o?.y ?? 8 });
    }
    return { pos, height };
  });

  const edgePath = (from: string, to: string): string => {
    const a = layout.pos.get(from);
    const b = layout.pos.get(to);
    if (!a || !b) return '';
    const x1 = a.x + W;
    const y1 = a.y + H / 2;
    const x2 = b.x;
    const y2 = b.y + H / 2;
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  };
  const stateTone = (s?: string) => (s === 'CANCELLED' ? 'bad' : s === 'DELIVERED' || s === 'PAID' ? 'ok' : 'mid');
</script>

<svg viewBox="0 0 620 {layout.height}" role="img" aria-label={t('world.graphLabel', { id: graph.customerId, n: graph.nodes.length })}>
  <defs>
    <marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="head" /></marker>
  </defs>
  {#each graph.edges as e (e.from + e.to)}
    <path d={edgePath(e.from, e.to)} class="edge" marker-end="url(#arr)" fill="none" />
    {#if e.rule}
      {@const a = layout.pos.get(e.from)}
      {#if a}<text x={a.x + W + 12} y={a.y + H / 2 - 5} class="rule">{e.rule}</text>{/if}
    {/if}
  {/each}
  {#each graph.nodes as n (n.id)}
    {@const p = layout.pos.get(n.id)}
    {#if p}
      <g transform="translate({p.x},{p.y})" class="node {n.type}">
        <rect width={W} height={H} rx="8" />
        <text x="10" y="17" class="lbl">{n.label}</text>
        <text x="10" y="32" class="st {stateTone(n.state)}">{n.state ?? ''}</text>
      </g>
    {/if}
  {/each}
</svg>

<style>
  svg { width: 100%; height: auto; max-width: 44rem; display: block; }
  .edge { stroke: var(--border-strong); stroke-width: 1.6; }
  .head { fill: var(--border-strong); }
  .node rect { fill: var(--surface-2); stroke: var(--border-strong); stroke-width: 1.2; }
  .customer rect { stroke: var(--accent); fill: var(--accent-soft); }
  .shipment rect { stroke: var(--success); }
  .lbl { font-family: var(--font-mono); font-size: 11.5px; fill: var(--fg); font-weight: 650; }
  .st { font-size: 10px; fill: var(--fg-muted); letter-spacing: 0.03em; }
  .st.ok { fill: var(--success); }
  .st.bad { fill: var(--danger); }
  .rule { font-size: 9.5px; fill: var(--fg-subtle); font-family: var(--font-mono); }
</style>
