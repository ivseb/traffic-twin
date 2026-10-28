<script lang="ts">
  // A short list of steps with their state (waiting, running, done, skipped, failed): the progress of a job that
  // chains several calls. It is a live region, so a screen reader hears the step change.
  import Icon from './Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import type { BuildStep } from '../lib/world-build';

  let { steps, label }: { steps: BuildStep[]; label: string } = $props();
</script>

<ol class="ps" aria-label={label} role="status">
  {#each steps as s (s.id)}
    <li class={s.state}>
      <span class="ico" aria-hidden="true">
        {#if s.state === 'done' || s.state === 'skipped'}<Icon name="check" size={14} />
        {:else if s.state === 'failed'}<Icon name="close" size={14} />
        {:else if s.state === 'running'}<Icon name="refresh" size={14} />
        {:else}<i></i>{/if}
      </span>
      <span>{t(s.label)}</span>
      <span class="sr-only">{t(`ps.${s.state}` as 'ps.done')}</span>
    </li>
  {/each}
</ol>

<style>
  .ps { list-style: none; margin: var(--s-3) 0 0; padding: var(--s-3); display: flex; flex-direction: column; gap: var(--s-2); border: 1px solid var(--border); border-radius: var(--r-md); background: var(--surface-2); }
  li { display: flex; align-items: center; gap: var(--s-2); color: var(--fg-muted); }
  .ico { display: grid; place-items: center; width: 1.4rem; height: 1.4rem; border-radius: 50%; border: 2px solid var(--border-strong); }
  .ico i { width: 0.4rem; height: 0.4rem; border-radius: 50%; background: var(--border-strong); }
  .running { color: var(--fg); font-weight: 600; }
  .running .ico { border-color: var(--accent); color: var(--accent); }
  .running .ico :global(svg) { animation: spin 1.2s linear infinite; }
  .done .ico, .skipped .ico { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .failed { color: var(--danger); }
  .failed .ico { border-color: var(--danger); color: var(--danger); }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .running .ico :global(svg) { animation: none; } }
</style>
