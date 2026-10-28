<script lang="ts">
  import Badge from './Badge.svelte';
  import InfoTip from './InfoTip.svelte';
  import { tk } from '../lib/i18n/index.svelte';
  import { fieldHelp } from '../lib/help/index.svelte';

  // Maps domain states to a tone + label (status.<value> in the dictionaries). When help
  // exists for `status.<value>` the pill itself is the (keyboard-accessible) trigger of the explanation.
  const TONES: Record<string, 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent'> = {
    healthy: 'success',
    capturing: 'success',
    approved: 'success',
    active: 'success',
    pass: 'success',
    warn: 'warning',
    signed: 'info',
    published: 'success',
    'gate-failed': 'danger',
    building: 'info',
    ok: 'success',
    resolved: 'success',
    degraded: 'warning',
    waiting: 'neutral',
    stale: 'warning',
    warning: 'warning',
    draft: 'info',
    running: 'info',
    pending: 'neutral',
    skipped: 'neutral',
    acknowledged: 'info',
    offline: 'neutral',
    superseded: 'neutral',
    killed: 'warning',
    revoked: 'danger',
    rejected: 'danger',
    fail: 'danger',
    denied: 'danger',
    error: 'danger',
    open: 'danger',
    breaking: 'danger',
    'non-breaking': 'success',
    info: 'info',
  };
  /** `plain`: no explanation popover (the pill sits inside a link or a button, which cannot contain another control). */
  let { value, plain = false }: { value: string; plain?: boolean } = $props();
  const hasHelp = $derived(!plain && !!fieldHelp(`status.${value}`));
</script>

{#snippet pill()}
  <Badge tone={TONES[value] ?? 'neutral'} dot>{tk(`status.${value}`, undefined, value)}</Badge>
{/snippet}

{#if hasHelp}
  <InfoTip id={`status.${value}`}>{@render pill()}</InfoTip>
{:else}
  {@render pill()}
{/if}
