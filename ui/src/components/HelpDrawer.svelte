<script lang="ts">
  // Page guide: what the page is for, how to use it, what the concepts mean and what the
  // actions change in practice. Opens with "?" or the Guide button; content lives in lib/help/.
  import Drawer from './Drawer.svelte';
  import RichText from './RichText.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { helpUi, pageGuide } from '../lib/help/index.svelte';
  import { ui } from '../lib/stores.svelte';

  const guide = $derived(pageGuide(ui.helpPage));
  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);
  const mod = isMac ? '⌘' : 'Ctrl';
  const shortcuts = $derived([
    { keys: [mod, 'K'], text: helpUi('sc.palette') },
    { keys: ['?'], text: helpUi('sc.help') },
    { keys: ['g', 'o'], text: helpUi('sc.go') },
    { keys: ['Esc'], text: helpUi('sc.close') },
  ]);
</script>

<Drawer bind:open={ui.helpOpen} title={guide ? `${t('help.guide')}: ${guide.title}` : t('help.guide')}>
  {#if guide}
    <div class="guide stack">
      <section>
        <h3>{helpUi('purpose')}</h3>
        <p><RichText text={guide.purpose} /></p>
      </section>
      <section>
        <h3>{helpUi('steps')}</h3>
        <ol>{#each guide.steps as s, i (i)}<li><RichText text={s} /></li>{/each}</ol>
      </section>
      <section>
        <h3>{helpUi('concepts')}</h3>
        <dl>{#each guide.concepts as c (c.term)}<dt>{c.term}</dt><dd><RichText text={c.text} /></dd>{/each}</dl>
      </section>
      <section class="effects">
        <h3>{helpUi('effects')}</h3>
        <ul>{#each guide.effects as e, i (i)}<li><RichText text={e} /></li>{/each}</ul>
      </section>
      <section>
        <h3>{helpUi('shortcuts')}</h3>
        <ul class="sc">{#each shortcuts as s (s.text)}<li>{#each s.keys as k, i (i)}<kbd>{k}</kbd>{' '}{/each} <span class="muted">{s.text}</span></li>{/each}</ul>
      </section>
      <p><a href="#/glossary">{helpUi('openGlossary')}</a> · <a href="#/manual">{t('manual.title')}</a></p>
    </div>
  {:else}
    <p class="muted">{helpUi('noGuide')} <a href="#/glossary">{helpUi('openGlossary')}</a> · <a href="#/manual">{t('manual.title')}</a></p>
  {/if}
</Drawer>

<style>
  .guide section { display: flex; flex-direction: column; gap: var(--s-2); }
  h3 { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--fg-muted); }
  ol, ul { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: var(--s-2); }
  dl { margin: 0; display: grid; gap: var(--s-1) 0; }
  dt { font-weight: 600; margin-top: var(--s-2); }
  dd { margin: 0; color: var(--fg-muted); }
  .effects { background: var(--warning-soft); border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); }
  .effects h3 { color: var(--warning); }
  .sc { list-style: none; padding: 0; }
</style>
