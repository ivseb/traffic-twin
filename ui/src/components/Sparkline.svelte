<script lang="ts">
  interface Props {
    values: number[];
    width?: number;
    height?: number;
    tone?: 'accent' | 'success' | 'warning' | 'danger';
    label: string;
  }
  let { values, width = 120, height = 28, tone = 'accent', label }: Props = $props();

  const pts = $derived.by(() => {
    if (values.length === 0) return { line: '', area: '' };
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const span = max - min || 1;
    const step = values.length > 1 ? width / (values.length - 1) : 0;
    const xy = values.map((v, i) => [i * step, height - 2 - ((v - min) / span) * (height - 4)] as const);
    const line = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
    return { line, area: `0,${height} ${line} ${width},${height}` };
  });
</script>

<svg {width} height={height} viewBox="0 0 {width} {height}" role="img" aria-label={label} class={tone}>
  <polygon points={pts.area} class="area" />
  <polyline points={pts.line} class="line" fill="none" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" />
</svg>

<style>
  svg { display: block; max-width: 100%; }
  .line { stroke: var(--c); }
  .area { fill: var(--c); opacity: 0.14; }
  .accent { --c: var(--accent); }
  .success { --c: var(--success); }
  .warning { --c: var(--warning); }
  .danger { --c: var(--danger); }
</style>
