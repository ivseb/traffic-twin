<script lang="ts">
  // "Pagine di terzi": the payment / e-signature pages the mocks of a group serve at /__pages/<id>
  // (/api/v1/mocks/pages). The application under test sends the browser there; a button calls the application back
  // server to server and sends the browser to the return URL. Tests without a browser use the control API.
  import Card from '../Card.svelte';
  import Button from '../Button.svelte';
  import Badge from '../Badge.svelte';
  import Loading from '../Loading.svelte';
  import CodeBlock from '../CodeBlock.svelte';
  import PageForm from './PageForm.svelte';
  import { t, tk } from '../../lib/i18n/index.svelte';
  import { api, ApiError, newPage, PAGE_PLACEHOLDERS, pageControlCommands, type ThirdPartyPage } from '../../lib/api';
  import { resource } from '../../lib/resource.svelte';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtDate } from '../../lib/format';

  let { group }: { group: string } = $props();

  const pages = resource(() => api.mocks.pages(group));
  const canEdit = $derived(can('publish.build'));
  const list = $derived(pages.data?.pages ?? []);

  /** The page being edited: its index in the list, or -1 for a new one. */
  let editing = $state<{ index: number; page: ThirdPartyPage } | null>(null);
  let busy = $state(false);
  let error = $state('');

  async function saveList(next: ThirdPartyPage[], done: string): Promise<boolean> {
    busy = true;
    error = '';
    try {
      await api.mocks.setPages(group, next);
      toast(done);
      pages.reload();
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.serverCode === 'invalid_pages') error = t('pg.refused', { msg: e.message });
      else toastError(e);
      return false;
    } finally {
      busy = false;
    }
  }
  async function save(p: ThirdPartyPage): Promise<void> {
    if (!editing) return;
    const next = editing.index < 0 ? [...list, p] : list.map((x, i) => (i === editing!.index ? p : x));
    if (await saveList(next, t('pg.saved', { id: p.id }))) editing = null;
  }
  async function remove(i: number): Promise<void> {
    const id = list[i].id;
    await saveList(list.filter((_, j) => j !== i), t('pg.removed', { id }));
  }
  const keyStoredOf = (i: number) => i >= 0 && !!list[i]?.callback?.hmac;
  const example = $derived(list[0] ? pageControlCommands(list[0].id, list[0].buttons[0]?.action ?? 'approve') : pageControlCommands('pay', 'approve'));
</script>

<Card title={t('pg.title')} subtitle={t('pg.subtitle')}>
  <div class="stack-sm" data-testid="pages-card">
    <p>{t('pg.why')}</p>
    <p class="subtle">{t('pg.how')}</p>
    <p class="subtle">{t('pg.reach')} {t('pg.noCrypto')}</p>
    <details>
      <summary>{t('pg.placeholders')}</summary>
      <p class="subtle">{t('pg.placeholdersHint')}</p>
      <ul class="ph">
        {#each PAGE_PLACEHOLDERS as x (x)}<li><code>{`{${x}}`}</code> — {tk(`pg.ph.${x.replace('.<name>', '')}`, undefined, x)}</li>{/each}
      </ul>
    </details>
    <details>
      <summary>{t('pg.tests')}</summary>
      <p class="subtle">{t('pg.testsHint')}</p>
      <CodeBlock code={example} title={t('pg.testsCmd')} language="bash" />
    </details>

    {#if pages.data}
      {@const d = pages.data}
      {#if d.updatedAt}<p class="subtle">{t('pg.updated', { who: d.updatedBy ?? '—', when: fmtDate(d.updatedAt) })}</p>{/if}
      {#if !canEdit}<p class="subtle">{t('pg.readOnly')}</p>{/if}
      {#if list.length}
        <ul class="pages">
          {#each list as p, i (p.id)}
            <li class="page" data-testid="page-item">
              {#if editing && editing.index === i}
                <PageForm page={editing.page} others={list.filter((_, j) => j !== i)} keyStored={keyStoredOf(i)} {busy} {error} onsave={save} oncancel={() => ((editing = null), (error = ''))} />
              {:else}
                <div class="head">
                  <h3 class="fs-4">{p.title}</h3>
                  <code>/__pages/{p.id}</code>
                </div>
                {#if p.description}<p class="subtle">{p.description}</p>{/if}
                <p class="badges">
                  {#each p.buttons as b (b.action)}<Badge tone={b.no_callback ? 'neutral' : 'info'}>{b.label} · {b.action}</Badge>{/each}
                </p>
                <dl class="kv">
                  {#if p.return_url}<dt>{t('pg.l.return')}</dt><dd class="mono">{p.return_url}</dd>{/if}
                  <dt>{t('pg.l.callback')}</dt>
                  <dd>
                    {#if p.callback}<span class="mono">{p.callback.method} {p.callback.url}</span>{#if p.callback.hmac} · {t('pg.l.signed', { header: p.callback.hmac.header })}{/if}{:else}{t('pg.l.noCallback')}{/if}
                  </dd>
                  {#if p.links?.length}<dt>{t('pg.l.links')}</dt><dd>{p.links.map((l) => `${l.service} ${l.op} → ${l.path}`).join('; ')}</dd>{/if}
                  {#if p.auto && Object.keys(p.auto).length}<dt>{t('pg.l.auto')}</dt><dd>{Object.entries(p.auto).map(([k, a]) => `${k === '*' ? t('pg.l.autoAll') : k} → ${a}`).join('; ')}</dd>{/if}
                </dl>
                {#if canEdit}
                  <div class="actions">
                    <Button size="sm" disabled={busy || !!editing} onclick={() => ((editing = { index: i, page: structuredClone($state.snapshot(p)) as ThirdPartyPage }), (error = ''))}>{t('pg.edit', { id: p.id })}</Button>
                    <Button size="sm" variant="ghost" disabled={busy || !!editing} onclick={() => remove(i)}>{t('pg.remove', { id: p.id })}</Button>
                  </div>
                {/if}
              {/if}
            </li>
          {/each}
        </ul>
      {:else}
        <p class="subtle">{t('pg.empty')}</p>
      {/if}
      {#if canEdit}
        {#if editing && editing.index < 0}
          <PageForm page={editing.page} others={list} keyStored={false} {busy} {error} onsave={save} oncancel={() => ((editing = null), (error = ''))} />
        {:else}
          <div class="actions">
            <Button size="sm" icon="plus" disabled={busy || !!editing || list.length >= 32} onclick={() => ((editing = { index: -1, page: newPage(list.map((x) => x.id)) }), (error = ''))}>{t('pg.add')}</Button>
          </div>
        {/if}
      {/if}
    {:else}
      <Loading error={pages.error} onretry={pages.reload} lines={2} />
    {/if}
  </div>
</Card>

<style>
  .ph { margin: var(--s-2) 0 0; padding-left: var(--s-5); display: flex; flex-direction: column; gap: 2px; font-size: 0.9rem; }
  summary { cursor: pointer; font-weight: 600; }
  .pages { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-3); }
  .page { border-top: 1px solid var(--border); padding-top: var(--s-3); display: flex; flex-direction: column; gap: var(--s-2); }
  .page:first-child { border-top: 0; padding-top: 0; }
  .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--s-2); }
  .head h3 { margin: 0; }
  .page p { margin: 0; }
  .badges { display: flex; flex-wrap: wrap; gap: var(--s-1); }
  .kv { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 2px var(--s-3); margin: 0; font-size: 0.9rem; }
  .kv dt { font-weight: 600; }
  .kv dd { margin: 0; overflow-wrap: anywhere; }
  .actions { display: flex; gap: var(--s-2); }
  .mono { font-family: var(--font-mono); }
</style>
