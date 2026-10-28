<script lang="ts">
  import Icon from './Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { toast } from '../lib/stores.svelte';

  let { value, label }: { value: string; label?: string } = $props();
  let done = $state(false);

  async function copy(): Promise<void> {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        if (!ok) throw new Error('copy failed');
      }
      done = true;
      toast(t('code.copied'), 'success', 1500);
      setTimeout(() => (done = false), 1500);
    } catch {
      toast(t('code.copyFailed'), 'danger');
    }
  }
</script>

<button type="button" onclick={copy} aria-label={label ?? t('code.copy')} title={label ?? t('code.copy')}><Icon name={done ? 'check' : 'copy'} size={13} /></button>

<style>
  button { display: inline-grid; place-items: center; width: 22px; height: 22px; border: 0; border-radius: var(--r-sm); background: transparent; color: var(--fg-subtle); cursor: pointer; vertical-align: middle; }
  button:hover { background: var(--surface-3); color: var(--fg); }
</style>
