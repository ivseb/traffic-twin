<script lang="ts">
  // Live journal of a mock: the last calls the tests made (method, path, status, scenario, fault). The mock reports
  // only these summaries, never headers or bodies.
  import { untrack } from 'svelte';
  import Badge from '../Badge.svelte';
  import Switch from '../Switch.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api, type MockCall } from '../../lib/api';
  import { fmtTime } from '../../lib/format';
  import { scrollable } from '../../lib/scrollable';

  let { mockId }: { mockId: string } = $props();

  let calls = $state<MockCall[]>([]);
  let last = $state(0);
  let live = $state(true);
  let error = $state('');
  let filter = $state('');
  let shownFor = '';

  $effect(() => {
    const id = mockId;
    const on = live;
    untrack(() => {
      if (id !== shownFor) {
        calls = [];
        last = 0;
        shownFor = id;
      }
    });
    if (!on) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      if (stop) return;
      try {
        const r = await api.mocks.calls(id, untrack(() => last));
        if (stop) return;
        if (r.lastSeq < last) calls = []; // the console restarted
        calls = [...untrack(() => calls), ...r.calls].slice(-300);
        last = r.lastSeq;
        error = '';
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
      if (!stop) timer = setTimeout(poll, 2000);
    };
    untrack(() => void poll());
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  });

  const shown = $derived.by(() => {
    const f = filter.trim().toLowerCase();
    const list = f ? calls.filter((c) => `${c.method} ${c.path} ${c.status} ${c.session} ${c.scenario ?? ''} ${c.fault ?? ''}`.toLowerCase().includes(f)) : calls;
    return [...list].reverse();
  });

  function tone(c: MockCall): 'success' | 'warning' | 'danger' | 'neutral' {
    if (c.status === 0 || c.status >= 500) return 'danger';
    if (c.status >= 400) return 'warning';
    return c.status ? 'success' : 'neutral';
  }
</script>

<div class="stack">
  <div class="bar">
    <input type="search" bind:value={filter} placeholder={t('mk.calls.filter')} aria-label={t('mk.calls.filter')} />
    <Switch bind:checked={live} label={t('mk.calls.live')} />
  </div>
  {#if error}<p class="callout warn">{error}</p>{/if}
  {#if shown.length}
    <div class="scroll" use:scrollable={t('mk.calls.caption')}>
      <table class="tbl">
        <caption class="sr-only">{t('mk.calls.caption')}</caption>
        <thead>
          <tr><th scope="col">{t('mk.calls.when')}</th><th scope="col">{t('mk.calls.session')}</th><th scope="col">{t('mk.calls.request')}</th><th scope="col">{t('mk.calls.status')}</th><th scope="col">{t('mk.calls.scenario')}</th><th scope="col">{t('mk.calls.fault')}</th></tr>
        </thead>
        <tbody>
          {#each shown as c (c.seq)}
            <tr>
              <td class="nowrap">{fmtTime(c.wall)}</td>
              <td><code>{c.session}</code></td>
              <td class="req"><b>{c.method}</b> <code>{c.path}</code>{#if !c.matched && c.reason}<span class="subtle"> · {c.reason}</span>{/if}</td>
              <td><Badge tone={tone(c)}>{c.status || t('mk.calls.noResponse')}</Badge></td>
              <td>{c.scenario ?? '—'}</td>
              <td>{c.fault ?? '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <p class="subtle">{t('mk.calls.empty')}</p>
  {/if}
</div>

<style>
  .bar { display: flex; gap: var(--s-3); align-items: center; flex-wrap: wrap; }
  .bar input { flex: 1 1 16rem; }
  .scroll { max-height: 28rem; overflow: auto; }
  .tbl { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  .tbl th, .tbl td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  .req { overflow-wrap: anywhere; }
  .nowrap { white-space: nowrap; }
</style>
