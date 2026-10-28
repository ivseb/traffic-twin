<script lang="ts" module>
  export interface Column<T> {
    key: string;
    label: string;
    sortable?: boolean;
    /** Value used for sorting; defaults to row[key]. */
    value?: (row: T) => string | number;
    align?: 'end';
    width?: string;
    /** Hide below this viewport width to keep the table readable on phones. */
    hideBelow?: 'sm' | 'md';
    /** Key in the help content: adds an (i) popover to the header. */
    help?: string;
  }
</script>

<script lang="ts" generics="T">
  import { untrack, type Snippet } from 'svelte';
  import { scrollable } from '../lib/scrollable';
  import Icon from './Icon.svelte';
  import InfoTip from './InfoTip.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { loc, setQuery } from '../lib/router.svelte';

  interface Props {
    rows: T[];
    columns: Column<T>[];
    rowKey: (row: T) => string;
    cell: Snippet<[T, Column<T>]>;
    caption: string;
    searchText?: (row: T) => string;
    toolbar?: Snippet;
    onrowclick?: (row: T) => void;
    empty?: string;
    initialSort?: { key: string; dir: 'asc' | 'desc' };
    selectedKey?: string;
    /** Persist search, sort and page in the URL under this prefix (saved/shareable filters). */
    urlKey?: string;
    pageSize?: number;
    /** Row checkboxes + a bulk-actions bar. */
    selectable?: boolean;
    selection?: string[];
    bulk?: Snippet<[string[]]>;
    maxHeight?: string;
  }
  let {
    rows,
    columns,
    rowKey,
    cell,
    caption,
    searchText,
    toolbar,
    onrowclick,
    empty,
    initialSort,
    selectedKey,
    urlKey,
    pageSize: pageSizeProp = 25,
    selectable = false,
    selection = $bindable([]),
    bulk,
    maxHeight = 'min(72vh, 720px)',
  }: Props = $props();

  const k = (name: string) => `${urlKey}.${name}`;
  const fromUrl = (name: string) => (urlKey ? loc.query[k(name)] : undefined);

  let query = $state(untrack(() => fromUrl('q') ?? ''));
  let sort = $state<{ key: string; dir: 'asc' | 'desc' } | null>(
    untrack(() => {
      const s = fromUrl('sort');
      if (s) {
        const [key, dir] = s.split(':');
        if (key) return { key, dir: dir === 'desc' ? 'desc' : 'asc' };
      }
      return initialSort ?? null;
    }),
  );
  let page = $state(untrack(() => Math.max(1, Number(fromUrl('page') ?? 1) || 1)));
  let size = $state(untrack(() => pageSizeProp));

  // Keep the URL in sync (replace, no history spam).
  $effect(() => {
    if (!urlKey) return;
    const next = { [k('q')]: query, [k('sort')]: sort ? `${sort.key}:${sort.dir}` : '', [k('page')]: page > 1 ? String(page) : '' };
    const cur = loc.query;
    if (Object.entries(next).some(([key, v]) => (cur[key] ?? '') !== v)) untrack(() => setQuery(next));
  });

  function val(row: T, col: Column<T>): string | number {
    if (col.value) return col.value(row);
    const v = (row as Record<string, unknown>)[col.key];
    return typeof v === 'number' ? v : String(v ?? '');
  }

  const collator = new Intl.Collator(undefined, { numeric: true });
  // Sorted once per change of rows or sort (each key computed once per row),
  // so that typing in the search box only filters.
  const sorted = $derived.by(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort!.key);
    if (!col) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    const keyed = rows.map((r) => ({ r, k: val(r, col) }));
    keyed.sort((a, b) => {
      const x = a.k;
      const y = b.k;
      return (typeof x === 'number' && typeof y === 'number' ? x - y : collator.compare(String(x), String(y))) * dir;
    });
    return keyed.map((e) => e.r);
  });
  // Lowercase search text, computed once per row.
  const haystack = $derived(searchText ? new Map(rows.map((r) => [r, searchText(r).toLowerCase()])) : undefined);
  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q || !haystack) return sorted;
    return sorted.filter((r) => (haystack.get(r) ?? '').includes(q));
  });
  const pages = $derived(Math.max(1, Math.ceil(filtered.length / size)));
  const cur = $derived(Math.min(page, pages));
  const shown = $derived(filtered.slice((cur - 1) * size, cur * size));

  // A new search or sort goes back to the first page.
  function setQ(v: string): void {
    query = v;
    page = 1;
  }
  function toggleSort(col: Column<T>): void {
    if (!col.sortable) return;
    if (sort?.key !== col.key) sort = { key: col.key, dir: 'asc' };
    else if (sort.dir === 'asc') sort = { key: col.key, dir: 'desc' };
    else sort = null;
    page = 1;
  }
  const ariaSort = (col: Column<T>) => (sort?.key === col.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : col.sortable ? 'none' : undefined);

  const allOnPage = $derived(shown.length > 0 && shown.every((r) => selection.includes(rowKey(r))));
  function toggleAll(on: boolean): void {
    const keys = shown.map(rowKey);
    selection = on ? [...new Set([...selection, ...keys])] : selection.filter((x) => !keys.includes(x));
  }
  function toggleOne(key: string, on: boolean): void {
    selection = on ? [...selection, key] : selection.filter((x) => x !== key);
  }
  const colspan = $derived(columns.length + (selectable ? 1 : 0));
</script>

<div class="wrap">
  {#if searchText || toolbar || (selectable && selection.length > 0)}
    <div class="bar">
      {#if selectable && selection.length > 0}
        <div class="bulk" role="region" aria-label={t('table.bulk')}>
          <b>{t('table.selected', { n: selection.length })}</b>
          {#if bulk}{@render bulk(selection)}{/if}
          <button type="button" class="link-btn" onclick={() => (selection = [])}>{t('table.clear')}</button>
        </div>
      {:else}
        {#if searchText}
          <div class="search">
            <Icon name="search" size={15} />
            <input type="search" value={query} oninput={(e) => setQ(e.currentTarget.value)} placeholder={t('table.search')} aria-label={t('table.search')} />
          </div>
        {/if}
        {#if toolbar}{@render toolbar()}{/if}
        <span class="subtle count" aria-live="polite">{t('table.count', { shown: filtered.length, total: rows.length })}</span>
      {/if}
    </div>
  {/if}
  <div class="scroll" style:max-height={maxHeight} use:scrollable={caption}>
    <table>
      <caption class="sr-only">{caption}</caption>
      <thead>
        <tr>
          {#if selectable}
            <th scope="col" class="chk"><input type="checkbox" checked={allOnPage} onchange={(e) => toggleAll(e.currentTarget.checked)} aria-label={t('table.selectAll')} /></th>
          {/if}
          {#each columns as col (col.key)}
            <th scope="col" class:end={col.align === 'end'} class:hide-sm={col.hideBelow === 'sm'} class:hide-md={col.hideBelow === 'md'} aria-sort={ariaSort(col)} style:width={col.width}>
              <span class="h">
                {#if col.sortable}
                  <button type="button" class="sort" onclick={() => toggleSort(col)}>
                    {col.label}
                    <Icon name={sort?.key === col.key ? (sort.dir === 'asc' ? 'sortAsc' : 'sortDesc') : 'sort'} size={12} />
                  </button>
                {:else}
                  {col.label}
                {/if}
                {#if col.help}<InfoTip id={col.help} />{/if}
              </span>
            </th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each shown as row (rowKey(row))}
          <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
          <tr class:clickable={!!onrowclick} class:selected={selectedKey === rowKey(row) || selection.includes(rowKey(row))} onclick={onrowclick ? () => onrowclick(row) : undefined}>
            {#if selectable}
              <td class="chk"><input type="checkbox" checked={selection.includes(rowKey(row))} onclick={(e) => e.stopPropagation()} onchange={(e) => toggleOne(rowKey(row), e.currentTarget.checked)} aria-label={t('table.selectRow')} /></td>
            {/if}
            {#each columns as col (col.key)}
              <td class:end={col.align === 'end'} class:hide-sm={col.hideBelow === 'sm'} class:hide-md={col.hideBelow === 'md'}>{@render cell(row, col)}</td>
            {/each}
          </tr>
        {:else}
          <tr><td colspan={colspan} class="none">{empty ?? t('table.empty')}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if filtered.length > Math.min(size, 25) || pages > 1}
    <div class="pager">
      <span class="subtle num">{t('table.range', { from: (cur - 1) * size + 1, to: Math.min(cur * size, filtered.length), total: filtered.length })}</span>
      <span class="grow"></span>
      <label class="subtle">{t('table.perPage')}
        <select value={size} onchange={(e) => { size = Number(e.currentTarget.value); page = 1; }}>
          {#each [25, 50, 100] as n (n)}<option value={n}>{n}</option>{/each}
        </select>
      </label>
      <button type="button" class="pg" disabled={cur <= 1} onclick={() => (page = cur - 1)} aria-label={t('table.prev')}><Icon name="left" size={14} /></button>
      <span class="num subtle">{cur} / {pages}</span>
      <button type="button" class="pg" disabled={cur >= pages} onclick={() => (page = cur + 1)} aria-label={t('table.next')}><Icon name="right" size={14} /></button>
    </div>
  {/if}
</div>

<style>
  .wrap { min-width: 0; }
  .bar { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; padding: var(--s-3) var(--s-4); border-bottom: 1px solid var(--border); min-height: 52px; }
  .search { position: relative; flex: 1 1 224px; max-width: 320px; }
  .search :global(svg) { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--fg-subtle); pointer-events: none; }
  .search input { padding-left: 30px; }
  .count { margin-left: auto; }
  .bulk { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; }
  .scroll { overflow: auto; max-width: 100%; }
  table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.93rem; }
  th, td { text-align: start; padding: 8px var(--s-4); border-top: 1px solid var(--border); vertical-align: middle; }
  thead th { position: sticky; top: 0; z-index: 2; border-top: 0; border-bottom: 1px solid var(--border-strong); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--fg-muted); font-weight: 600; background: var(--surface-2); white-space: nowrap; }
  tbody tr:first-child td { border-top: 0; }
  th.end, td.end { text-align: end; font-variant-numeric: tabular-nums; }
  th.end .h { justify-content: flex-end; }
  .chk { width: 36px; padding-right: 0; }
  /* Links and link-buttons stacked in a cell are targets of their own: at least 24px tall (WCAG 2.5.8). */
  td :global(a), td :global(.link-btn) { display: inline-flex; align-items: center; min-height: 24px; }
  .h { display: inline-flex; align-items: center; gap: 2px; }
  .sort { all: unset; cursor: pointer; display: inline-flex; gap: 4px; align-items: center; }
  .sort:hover { color: var(--fg); }
  .sort:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  tbody tr:hover { background: var(--surface-2); }
  tr.clickable { cursor: pointer; }
  tr.selected { background: var(--accent-soft); }
  .none { text-align: center; color: var(--fg-muted); padding: var(--s-6) var(--s-4); }
  .pager { display: flex; align-items: center; gap: var(--s-3); padding: var(--s-2) var(--s-4); border-top: 1px solid var(--border); flex-wrap: wrap; }
  .pager select { width: auto; min-height: 26px; padding: 0 6px; margin-left: 6px; }
  .pg { display: grid; place-items: center; width: 26px; height: 26px; border: 1px solid var(--border-strong); background: var(--surface); color: var(--fg); border-radius: var(--r-sm); cursor: pointer; }
  .pg:disabled { opacity: 0.4; cursor: not-allowed; }
  @media (max-width: 640px) { .hide-sm { display: none; } th, td { padding-inline: var(--s-3); } }
  @media (max-width: 900px) { .hide-md { display: none; } }
</style>
