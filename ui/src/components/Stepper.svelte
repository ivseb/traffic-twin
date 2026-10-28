<script lang="ts">
  import Icon from './Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';

  interface Step {
    id: string;
    label: string;
  }
  let { steps, current, onselect }: { steps: Step[]; current: number; onselect?: (index: number) => void } = $props();
</script>

<nav aria-label={t('stepper.label')}>
  <p class="compact" aria-hidden="true">{t('stepper.of', { n: current + 1, total: steps.length })} · <b>{steps[current]?.label}</b></p>
  <ol>
    {#each steps as step, i (step.id)}
      <li class:done={i < current} class:current={i === current}>
        {#if i < current && onselect}
          <button type="button" onclick={() => onselect(i)} aria-label={t('stepper.back', { label: step.label })}>
            <span class="dot"><Icon name="check" size={14} /></span>
            <span class="lbl">{step.label}</span>
          </button>
        {:else}
          <span class="item" aria-current={i === current ? 'step' : undefined}>
            <span class="dot">{#if i < current}<Icon name="check" size={14} />{:else}{i + 1}{/if}</span>
            <span class="lbl">{step.label}</span>
          </span>
        {/if}
      </li>
    {/each}
  </ol>
</nav>

<style>
  ol { list-style: none; display: flex; gap: var(--s-2); margin: 0; padding: 0; counter-reset: s; }
  li { flex: 1 1 0; min-width: 0; position: relative; }
  li::after { content: ''; position: absolute; top: 0.95rem; left: calc(50% + 1.1rem); right: calc(-50% + 1.1rem); height: 2px; background: var(--border-strong); }
  li:last-child::after { display: none; }
  li.done::after { background: var(--accent); }
  .item, button { display: flex; flex-direction: column; align-items: center; gap: var(--s-1); text-align: center; width: 100%; }
  button { all: unset; box-sizing: border-box; display: flex; flex-direction: column; align-items: center; gap: var(--s-1); width: 100%; cursor: pointer; text-align: center; }
  .dot { display: grid; place-items: center; width: 1.9rem; height: 1.9rem; border-radius: 50%; border: 2px solid var(--border-strong); background: var(--surface); font-weight: 650; font-size: 0.85rem; color: var(--fg-muted); position: relative; z-index: 1; }
  .done .dot { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .current .dot { border-color: var(--accent); color: var(--accent); }
  .lbl { font-size: 0.8rem; color: var(--fg-muted); line-height: 1.2; }
  .current .lbl { color: var(--fg); font-weight: 650; }
  .compact { display: none; margin-bottom: var(--s-2); }
  button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: var(--r-sm); }
  @media (max-width: 720px) {
    .compact { display: block; }
    .lbl { display: none; }
    li::after { top: 0.95rem; }
  }
</style>
