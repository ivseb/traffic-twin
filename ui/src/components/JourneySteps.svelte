<script lang="ts">
  // The four steps of the journey as cards: number, state, what the step is, where the user stands, a button.
  import Card from './Card.svelte';
  import Badge from './Badge.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { t, type MsgKey } from '../lib/i18n/index.svelte';
  import type { Journey } from '../lib/journey';

  let { journey }: { journey: Journey } = $props();
  const tone = { done: 'success', current: 'accent', todo: 'neutral' } as const;
</script>

<ol class="steps" aria-label={t('home.journey')}>
  {#each journey.steps as step, i (step.id)}
    <li class="step {step.status}">
      <Card>
        <div class="stack-sm">
          <div class="row spread">
            <span class="num" aria-hidden="true">{#if step.status === 'done'}<Icon name="check" size={16} />{:else}{i + 1}{/if}</span>
            <Badge tone={tone[step.status]} dot>{t(`journey.status.${step.status}` as MsgKey)}</Badge>
          </div>
          <h2 class="fs-3"><span class="sr-only">{i + 1}. </span>{t(`journey.step.${step.id}` as MsgKey)}</h2>
          <p class="muted lead">{t(`journey.lead.${step.id}` as MsgKey)}</p>
          <p class="sum">{t(step.summary.key, step.summary.params)}</p>
          <div><Button size="sm" variant={step.status === 'current' ? 'primary' : 'secondary'} href={step.href}>{t(`journey.open.${step.id}` as MsgKey)}</Button></div>
        </div>
      </Card>
    </li>
  {/each}
</ol>

<style>
  .steps { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--s-4); grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr)); }
  .steps > li { display: flex; }
  .steps > li > :global(*) { flex: 1; }
  .num { display: grid; place-items: center; width: 1.9rem; height: 1.9rem; border-radius: 50%; border: 2px solid var(--border-strong); font-weight: 650; font-size: 0.9rem; color: var(--fg-muted); background: var(--surface); }
  .done .num { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
  .current .num { border-color: var(--accent); color: var(--accent); }
  .lead { margin: 0; min-height: 2.6em; }
  .sum { margin: 0; font-weight: 500; }
</style>
