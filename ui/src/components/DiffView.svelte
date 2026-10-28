<script lang="ts">
  import { collapseContext, diffLines, diffStats } from '../lib/diff';
  import { t } from '../lib/i18n/index.svelte';

  let { before, after, format = 'text', context = 3 }: { before: string; after: string; format?: 'json' | 'yaml' | 'text'; context?: number } = $props();

  let full = $state(false);
  const lines = $derived(diffLines(before, after));
  const stats = $derived(diffStats(lines));
  const shown = $derived(full ? lines : collapseContext(lines, context));
</script>

<figure>
  <figcaption>
    <span class="fmt">{format.toUpperCase()}</span>
    <span class="s-add">+{stats.added}</span>
    <span class="s-del">−{stats.removed}</span>
    <button type="button" class="link-btn" onclick={() => (full = !full)}>{full ? t('diff.collapse') : t('diff.expand')}</button>
  </figcaption>
  {#if stats.added === 0 && stats.removed === 0}
    <p class="none">{t('diff.none')}</p>
  {:else}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div class="scroll" role="group" aria-label={t('diff.label')} tabindex="0">
      {#each shown as l, i (i)}
        {#if l.kind === 'gap'}
          <div class="line gap"><span class="no"></span><span class="sign">⋯</span><span class="txt">{t('diff.hidden', { n: l.hidden })}</span></div>
        {:else}
          <div class="line {l.kind}">
            <span class="no" aria-hidden="true">{l.oldNo ?? ''}</span>
            <span class="no" aria-hidden="true">{l.newNo ?? ''}</span>
            <span class="sign" aria-hidden="true">{l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ' '}</span>
            <span class="txt"><span class="sr-only">{l.kind === 'add' ? t('diff.added') : l.kind === 'del' ? t('diff.removed') : ''}</span>{l.text}</span>
          </div>
        {/if}
      {/each}
    </div>
  {/if}
</figure>

<style>
  figure { margin: 0; border: 1px solid var(--border-strong); border-radius: var(--r-sm); overflow: hidden; background: var(--surface); }
  figcaption { display: flex; gap: var(--s-3); align-items: center; padding: 0.3rem 0.75rem; background: var(--surface-2); border-bottom: 1px solid var(--border); font-size: 0.82rem; font-weight: 600; }
  .fmt { color: var(--fg-subtle); }
  .s-add { color: var(--success); }
  .s-del { color: var(--danger); }
  figcaption button { margin-left: auto; font-size: 0.8rem; }
  .scroll { overflow: auto; max-height: 28rem; font-family: var(--font-mono); font-size: 0.82rem; line-height: 1.55; }
  .line { display: flex; min-width: max-content; }
  .no { flex: none; width: 2.6rem; text-align: right; padding-right: 0.5rem; color: var(--fg-subtle); user-select: none; }
  .sign { flex: none; width: 1.2rem; text-align: center; user-select: none; }
  .txt { white-space: pre; padding-right: var(--s-4); }
  .line.add { background: var(--diff-add); }
  .line.add .sign { color: var(--success); }
  .line.del { background: var(--diff-del); }
  .line.del .sign { color: var(--danger); }
  .gap { color: var(--fg-subtle); background: var(--surface-2); }
  .none { padding: var(--s-4); color: var(--fg-muted); margin: 0; }
</style>
