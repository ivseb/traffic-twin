<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon, { type IconName } from './Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';

  interface Props {
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 'sm' | 'md';
    type?: 'button' | 'submit';
    disabled?: boolean;
    /** The user's role does not allow this action: shown disabled with an explanation. */
    denied?: boolean;
    loading?: boolean;
    href?: string;
    title?: string;
    icon?: IconName;
    full?: boolean;
    onclick?: (e: MouseEvent) => void;
    children: Snippet;
    [key: string]: unknown;
  }

  let { variant = 'secondary', size = 'md', type = 'button', disabled = false, denied = false, loading = false, href, title, icon, full = false, onclick, children, ...rest }: Props = $props();

  const off = $derived(disabled || denied || loading);
  const tip = $derived(denied ? t('rbac.denied') : title);
</script>

{#if href && !off}
  <a class="btn {variant} {size}" class:full {href} title={tip} {...rest}>
    {#if icon}<Icon name={icon} size={16} />{/if}
    {@render children()}
  </a>
{:else}
  <button class="btn {variant} {size}" class:full {type} disabled={off} aria-disabled={off} aria-busy={loading || undefined} title={tip} {onclick} {...rest}>
    {#if icon}<Icon name={icon} size={16} />{/if}
    {@render children()}
  </button>
{/if}

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font: inherit;
    font-weight: 500;
    line-height: 1.2;
    border: 1px solid transparent;
    border-radius: var(--r-md);
    padding: 5px 12px;
    min-height: 32px;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
    transition: background-color 0.12s, border-color 0.12s;
  }
  .sm { padding: 2px 8px; min-height: 26px; font-size: 0.86rem; }
  .full { width: 100%; }
  .primary { background: var(--accent); color: var(--accent-fg); }
  .primary:hover:not(:disabled) { background: var(--accent-strong); color: var(--accent-fg); }
  .secondary { background: var(--surface); color: var(--fg); border-color: var(--border-strong); }
  .secondary:hover:not(:disabled) { background: var(--surface-2); color: var(--fg); }
  .ghost { background: transparent; color: var(--fg-muted); }
  .ghost:hover:not(:disabled) { background: var(--surface-2); color: var(--fg); }
  .danger { background: var(--danger); color: var(--surface); }
  .danger:hover:not(:disabled) { filter: brightness(0.92); color: var(--surface); }
  /* Disabled is flat grey whatever the variant, so an enabled primary button is never mistaken for it. */
  .btn:disabled { background: var(--surface-3); color: var(--fg-subtle); border-color: var(--border); cursor: not-allowed; }
  .ghost:disabled { background: transparent; border-color: transparent; }
  /* Busy keeps the look of its variant, dimmed. */
  .btn[aria-busy='true']:disabled { cursor: progress; opacity: 0.7; }
  .primary[aria-busy='true']:disabled { background: var(--accent); color: var(--accent-fg); border-color: transparent; }
  .danger[aria-busy='true']:disabled { background: var(--danger); color: var(--surface); border-color: transparent; }
  .secondary[aria-busy='true']:disabled { background: var(--surface); color: var(--fg); border-color: var(--border-strong); }
</style>
