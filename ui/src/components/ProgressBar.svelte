<script lang="ts">
  import { fmtPct } from '../lib/format';

  interface Props {
    value: number; // 0..1
    label: string;
    tone?: 'accent' | 'success' | 'warning' | 'danger' | 'auto';
    showValue?: boolean;
  }
  let { value, label, tone = 'accent', showValue = true }: Props = $props();
  const v = $derived(Math.min(1, Math.max(0, value)));
  const eff = $derived(tone === 'auto' ? (v >= 0.95 ? 'success' : v >= 0.3 ? 'accent' : 'warning') : tone);
</script>

<div class="pb">
  <div class="track" role="progressbar" aria-label={label} aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(v * 100)}>
    <div class="fill {eff}" style:width="{v * 100}%"></div>
  </div>
  {#if showValue}<span class="val num">{fmtPct(v, v < 0.1 ? 1 : 0)}</span>{/if}
</div>

<style>
  .pb { display: flex; align-items: center; gap: var(--s-2); min-width: 5rem; }
  .track { flex: 1; height: 0.5rem; background: var(--surface-3); border-radius: 999px; overflow: hidden; }
  .fill { height: 100%; border-radius: 999px; background: var(--accent); min-width: 2px; }
  .success { background: var(--success); }
  .warning { background: var(--warning); }
  .danger { background: var(--danger); }
  .val { font-size: 0.8rem; width: 3rem; text-align: right; color: var(--fg-muted); }
</style>
