<script lang="ts">
  import Icon from './Icon.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { toast } from '../lib/stores.svelte';

  let { code, title, language, maxHeight = '22rem' }: { code: string; title?: string; language?: string; maxHeight?: string } = $props();
  let copied = $state(false);

  async function copy(): Promise<void> {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(code);
      else legacyCopy(code);
      copied = true;
      toast(t('code.copied'), 'success', 1800);
      setTimeout(() => (copied = false), 2000);
    } catch {
      toast(t('code.copyFailed'), 'danger');
    }
  }

  function legacyCopy(text: string): void {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    if (!ok) throw new Error('copy failed');
  }
</script>

<figure>
  <figcaption>
    <span class="grow">{title ?? ''}{#if language}<span class="lang">{language}</span>{/if}</span>
    <button type="button" class="copy" onclick={copy} aria-label={t('code.copy')}>
      <Icon name={copied ? 'check' : 'copy'} size={15} />
      {copied ? t('code.copied') : t('code.copy')}
    </button>
  </figcaption>
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <pre style:max-height={maxHeight} tabindex="0"><code>{code}</code></pre>
</figure>

<style>
  figure { margin: 0; border: 1px solid var(--border-strong); border-radius: var(--r-sm); overflow: hidden; background: var(--surface-2); }
  figcaption { display: flex; align-items: center; gap: var(--s-2); padding: 0.3rem 0.4rem 0.3rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.82rem; font-weight: 600; color: var(--fg-muted); }
  .lang { margin-left: 0.5rem; font-weight: 500; color: var(--fg-subtle); text-transform: uppercase; font-size: 0.72rem; }
  pre { margin: 0; padding: var(--s-3) var(--s-4); overflow: auto; white-space: pre; font-size: 0.85rem; line-height: 1.55; }
  code { font-size: inherit; }
  .copy { display: inline-flex; align-items: center; gap: 0.3rem; font: inherit; font-size: 0.8rem; font-weight: 600; background: var(--surface); color: var(--fg); border: 1px solid var(--border-strong); border-radius: var(--r-sm); padding: 0.2rem 0.55rem; cursor: pointer; }
  .copy:hover { background: var(--surface-3); }
</style>
