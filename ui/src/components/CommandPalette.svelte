<script lang="ts">
  // Ctrl/Cmd+K: jump to pages, services, rules and glossary terms; run a few actions.
  import Icon, { type IconName } from './Icon.svelte';
  import { NAV } from '../routes';
  import { t, tk, setLang, i18n } from '../lib/i18n/index.svelte';
  import { helpUi, pack } from '../lib/help/index.svelte';
  import { api } from '../lib/api';
  import { untrack } from 'svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { navigate } from '../lib/router.svelte';
  import { href } from '../lib/router';
  import { openHelp, setTheme, theme, ui } from '../lib/stores.svelte';

  interface Item {
    id: string;
    group: string;
    label: string;
    hint?: string;
    icon: IconName;
    run: () => void;
  }

  let el: HTMLDialogElement | undefined = $state();
  let query = $state('');
  let active = $state(0);
  let dynamic = $state<Item[]>([]);

  const go = (path: string, q: Record<string, string> = {}) => () => navigate(path, q);

  // Services and rules are loaded when the palette opens.
  $effect(() => {
    if (!el) return;
    el.showModal();
    // A role may read one of the two and not the other: each list is optional.
    // The services and rules of the Group/Team filter; a service is one per (group, service).
    const gs = untrack(() => scopeGroups());
    Promise.all([api.services.list(gs).catch(() => []), api.rules.list(gs).catch(() => [])])
      .then(([svcs, rules]) => {
        dynamic = [
          ...svcs.map((s): Item => ({
            id: `svc-${s.group ?? ''}-${s.name}`,
            group: helpUi('pal.services'),
            label: s.name,
            hint: [s.group, s.baseUrl ?? t('svc.own')].filter(Boolean).join(' · '),
            icon: 'services',
            run: go(`/contracts/service/${encodeURIComponent(s.name)}`, s.group ? { group: s.group } : {}),
          })),
          ...rules.map((r): Item => ({ id: `rule-${r.id}`, group: helpUi('pal.rules'), label: `${r.id} · ${r.title}`, hint: tk(`status.${r.status}`), icon: 'rules', run: go(`/rules/${r.id}`) })),
        ];
      })
      .catch(() => (dynamic = []));
  });

  const items = $derived<Item[]>([
    ...NAV.map((n): Item => ({ id: `nav-${n.path}${n.query ? '?' + new URLSearchParams(n.query).toString() : ''}`, group: helpUi('pal.pages'), label: t(n.label), icon: n.icon, run: go(n.path, n.query) })),
    ...dynamic,
    ...Object.entries(pack().glossary).map(([id, g]): Item => ({ id: `gl-${id}`, group: helpUi('pal.glossary'), label: g.term, hint: g.short, icon: 'book', run: go('/glossary', { term: id }) })),
    { id: 'act-help', group: helpUi('pal.actions'), label: t('help.guide'), icon: 'help', run: () => openHelp() },
    { id: 'act-theme', group: helpUi('pal.actions'), label: t('app.theme', { mode: t(`theme.${theme.choice === 'auto' ? 'light' : theme.choice === 'light' ? 'dark' : 'auto'}` as 'theme.auto') }), icon: 'monitor', run: () => setTheme(theme.choice === 'auto' ? 'light' : theme.choice === 'light' ? 'dark' : 'auto') },
    { id: 'act-lang', group: helpUi('pal.actions'), label: i18n.lang === 'it' ? 'English' : 'Italiano', icon: 'worlds', run: () => setLang(i18n.lang === 'it' ? 'en' : 'it') },
  ]);

  const shown = $derived.by(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    const list = words.length ? items.filter((i) => words.every((w) => `${i.label} ${i.hint ?? ''}`.toLowerCase().includes(w))) : items.filter((i) => i.group === helpUi('pal.pages') || i.group === helpUi('pal.actions'));
    return list.slice(0, 40);
  });
  $effect(() => {
    void query;
    active = 0;
  });

  function choose(i: Item | undefined): void {
    if (!i) return;
    el?.close();
    i.run();
  }
  function onkey(e: KeyboardEvent): void {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      active = Math.min(shown.length - 1, active + 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      active = Math.max(0, active - 1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(shown[active]);
    }
    document.getElementById(`pal-${active}`)?.scrollIntoView({ block: 'nearest' });
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<dialog bind:this={el} aria-label={helpUi('pal.title')} onclose={() => (ui.paletteOpen = false)} onclick={(e) => e.target === el && el?.close()}>
  <div class="box">
    <div class="in">
      <Icon name="search" size={16} />
      <!-- svelte-ignore a11y_autofocus -->
      <input
        autofocus
        role="combobox"
        aria-expanded="true"
        aria-controls="pal-list"
        aria-activedescendant={shown.length ? `pal-${active}` : undefined}
        bind:value={query}
        onkeydown={onkey}
        placeholder={helpUi('pal.placeholder')}
        aria-label={helpUi('pal.title')}
        autocomplete="off"
        spellcheck="false"
      />
      <kbd>Esc</kbd>
    </div>
    <ul id="pal-list" role="listbox" aria-label={helpUi('pal.title')}>
      {#each shown as it, i (it.id)}
        {#if i === 0 || shown[i - 1].group !== it.group}<li class="grp" role="presentation">{it.group}</li>{/if}
        <li id="pal-{i}" role="option" aria-selected={i === active} class:active={i === active} onmouseenter={() => (active = i)} onclick={() => choose(it)}>
          <Icon name={it.icon} size={16} />
          <span class="l">{it.label}</span>
          {#if it.hint}<span class="subtle h">{it.hint}</span>{/if}
        </li>
      {:else}
        <li class="none subtle" role="presentation">{helpUi('pal.none')}</li>
      {/each}
    </ul>
  </div>
</dialog>

<style>
  dialog { border: 0; padding: 0; background: transparent; width: min(560px, calc(100vw - 24px)); max-height: 80dvh; margin: 12vh auto 0; color: var(--fg); overflow: visible; }
  dialog::backdrop { background: var(--backdrop); }
  .box { background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-lg); box-shadow: var(--shadow-md); overflow: hidden; display: flex; flex-direction: column; max-height: 70dvh; }
  .in { display: flex; align-items: center; gap: var(--s-3); padding: var(--s-3) var(--s-4); border-bottom: 1px solid var(--border); color: var(--fg-subtle); }
  .in input { border: 0; background: transparent; padding: 4px 0; min-height: 28px; font-size: 1rem; outline: none; }
  .in input:focus-visible { outline: none; }
  ul { list-style: none; margin: 0; padding: var(--s-2); overflow-y: auto; }
  .grp { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--fg-subtle); padding: var(--s-2) var(--s-3) var(--s-1); }
  [role='option'] { display: flex; align-items: center; gap: var(--s-3); padding: 7px var(--s-3); border-radius: var(--r-md); cursor: pointer; }
  [role='option'].active { background: var(--accent-soft); }
  .l { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .h { margin-left: auto; max-width: 45%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .none { padding: var(--s-4); text-align: center; }
</style>
