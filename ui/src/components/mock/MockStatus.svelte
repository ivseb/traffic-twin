<script lang="ts">
  // One mock connected to the console: is it up, which pack, and the URL of every simulated service that replaces
  // the real one in the tests.
  import Card from '../Card.svelte';
  import Badge from '../Badge.svelte';
  import Button from '../Button.svelte';
  import CopyButton from '../CopyButton.svelte';
  import InfoTip from '../InfoTip.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api, replacementOf, type ManagedMock, type RunningMock } from '../../lib/api';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtAgo } from '../../lib/format';
  import { saveBlob } from '../../lib/download';

  let { mock, managed, selected = false, onselect, onchanged }: { mock: RunningMock; managed?: ManagedMock; selected?: boolean; onselect?: () => void; onchanged?: () => void } = $props();

  let busy = $state(false);
  let postmanBusy = $state('');

  // The contract of the service as a Postman/Insomnia collection whose {{baseUrl}} is this mock.
  async function postman(service: string, mockUrl: string): Promise<void> {
    postmanBusy = service;
    try {
      const { filename, blob } = await api.contracts.postman(service, mock.group, mockUrl);
      saveBlob(filename, blob);
    } catch (e) {
      toastError(e);
    } finally {
      postmanBusy = '';
    }
  }
  let stopOpen = $state(false);

  const tone = $derived(!mock.online ? 'danger' : mock.status === 'serving' && mock.upToDate ? 'success' : 'warning');
  const label = $derived(
    mock.status === 'revoked' ? t('mk.st.revoked') : !mock.online ? t('mk.st.offline') : mock.status === 'waiting' ? t('mk.st.waiting') : mock.upToDate ? t('mk.st.ready') : t('mk.st.old'),
  );

  async function restart(): Promise<void> {
    busy = true;
    try {
      await api.mocks.restartManaged(mock.group);
      toast(t('mk.restarted'));
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  async function stop(): Promise<void> {
    busy = true;
    try {
      await api.mocks.stopManaged(mock.group);
      toast(t('mk.stopped'));
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<Card title={`${mock.group} · ${mock.instance}`} subtitle={mock.managed ? t('mk.kind.managed') : t('mk.kind.self')} tone={selected ? 'accent' : 'default'} level={3}>
  {#snippet actions()}
    <Badge {tone} dot>{label}</Badge>
    {#if onselect && !selected}<Button size="sm" onclick={onselect}>{t('mk.select')}</Button>{/if}
    {#if mock.managed && managed}
      <Button size="sm" icon="refresh" loading={busy} denied={!can('publish.build')} onclick={restart}>{t('mk.restart')}</Button>
      <Button size="sm" variant="danger" icon="power" disabled={busy} denied={!can('publish.build')} onclick={() => (stopOpen = true)}>{t('mk.stop')}</Button>
    {/if}
  {/snippet}
  <div class="stack">
    <p class="subtle">
      {t('mk.pack')} <InfoTip id="mock.pack" />: <code>{mock.packId || '—'}</code>
      {#if mock.latestPackId && !mock.upToDate}· {t('mk.latest', { pack: mock.latestPackId })}{/if}
      · {t('mk.seen', { ago: fmtAgo(mock.lastSeen) })}
      {#if mock.version}· tt {mock.version}{/if}
    </p>
    {#if mock.packError}<p class="callout danger">{t('mk.packRefused', { reason: mock.packError })}</p>{/if}
    {#if !mock.online}<p class="callout warn">{mock.status === 'revoked' ? t('mk.revokedHint') : t('mk.offlineHint')}</p>{/if}
    <div>
      <h3 class="fs-4">{t('mk.urls')} <InfoTip id="mock.url" /></h3>
      <ul class="urls">
        {#each mock.services as s (s.name)}
          {@const r = replacementOf(s)}
          <li>
            <span class="svc"><b>{s.name}</b>{#if s.alias}<span class="subtle"> ({s.alias})</span>{/if}</span>
            {#if r}
              <span class="repl">{t('mk.replace')} <code>{r.from}</code> {t('mk.with')} <code>{r.to}</code></span>
            {:else}
              <span class="repl">{t('mk.use')} <code>{s.mockUrl}</code></span>
            {/if}
            <span class="acts">
              <CopyButton value={s.mockUrl} label={t('mk.copyUrl', { service: s.name })} />
              <Button size="sm" variant="ghost" icon="download" loading={postmanBusy === s.name} title={t('mk.postmanHint')} onclick={() => postman(s.name, s.mockUrl)}>{t('mk.postman')}</Button>
            </span>
          </li>
        {/each}
      </ul>
      {#if !mock.services.length}<p class="subtle">{t('mk.noServices')}</p>{/if}
    </div>
  </div>
</Card>

<ConfirmDialog bind:open={stopOpen} title={t('mk.stopTitle')} message={t('mk.stopMsg', { group: mock.group })} confirmLabel={t('mk.stop')} onconfirm={stop} />

<style>
  .urls { list-style: none; margin: var(--s-1) 0 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .urls li { display: grid; grid-template-columns: minmax(8rem, 12rem) minmax(0, 1fr) auto; gap: var(--s-2); align-items: center; }
  .repl { overflow-wrap: anywhere; }
  .acts { display: inline-flex; gap: var(--s-1); align-items: center; }
  @media (max-width: 40rem) { .urls li { grid-template-columns: 1fr auto; } .svc { grid-column: 1 / -1; } }
</style>
