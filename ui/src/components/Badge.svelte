<script lang="ts">
  import type { Snippet } from 'svelte';

  type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';
  let { tone = 'neutral', dot = false, children, title }: { tone?: Tone; dot?: boolean; children: Snippet; title?: string } = $props();
</script>

<span class="badge {tone}" {title}>
  {#if dot}<i class="dot" aria-hidden="true"></i>{/if}
  {@render children()}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.78rem;
    font-weight: 600;
    line-height: 1.1;
    padding: 0.2rem 0.5rem;
    border-radius: 999px;
    white-space: nowrap;
    background: var(--surface-3);
    color: var(--fg-muted);
  }
  .dot { width: 0.5rem; height: 0.5rem; border-radius: 50%; background: currentColor; }
  .success { background: var(--success-soft); color: var(--success); }
  .warning { background: var(--warning-soft); color: var(--warning); }
  .danger { background: var(--danger-soft); color: var(--danger); }
  .info { background: var(--info-soft); color: var(--info); }
  .accent { background: var(--accent-soft); color: var(--accent); }
</style>
