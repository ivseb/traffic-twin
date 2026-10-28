<script lang="ts">
  // "Sessione per utente": the header (or JWT claim) whose value picks the mock session and the synthetic customer of a
  // call, for the mocks of a group (admin-api 1.18.0, /api/v1/mocks/identity). The console keeps only keyed hashes of
  // the test users.
  import Card from '../Card.svelte';
  import Button from '../Button.svelte';
  import Field from '../Field.svelte';
  import Loading from '../Loading.svelte';
  import Badge from '../Badge.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api, CUSTOMER_RE, fingerprint } from '../../lib/api';
  import { resource } from '../../lib/resource.svelte';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtDate } from '../../lib/format';

  let { group }: { group: string } = $props();

  const ident = resource(() => api.mocks.identity(group));
  const canEdit = $derived(can('publish.build'));

  let header = $state('');
  let claim = $state('');
  let loadedFor = $state('');
  $effect(() => {
    const d = ident.data;
    const key = d ? `${d.group}/${d.header}/${d.claim}/${d.updatedAt ?? ''}` : '';
    if (d && key !== loadedFor) {
      loadedFor = key;
      header = d.header;
      claim = d.claim;
    }
  });

  let busy = $state(false);
  async function save(off = false): Promise<void> {
    busy = true;
    try {
      await api.mocks.setIdentity(group, off ? '' : header.trim(), off ? '' : claim.trim());
      toast(t(off || !header.trim() ? 'mid.off' : 'mid.saved'));
      ident.reload();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  let user = $state('');
  let customer = $state('');
  const customerBad = $derived(!!customer.trim() && !CUSTOMER_RE.test(customer.trim()));
  async function add(): Promise<void> {
    busy = true;
    try {
      await api.mocks.addIdentityUser(group, user.trim(), customer.trim());
      user = '';
      customer = '';
      toast(t('mid.map.added'));
      ident.reload();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  async function remove(hash: string): Promise<void> {
    busy = true;
    try {
      await api.mocks.removeIdentityUser(group, hash);
      toast(t('mid.map.removed'));
      ident.reload();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<Card title={t('mid.title')} subtitle={t('mid.subtitle')}>
  <div class="stack-sm">
    <p>{t('mid.why')}</p>
    <p class="subtle">{t('mid.how')}</p>
    <p class="subtle">{t('mid.privacy')} {t('mid.reach')}</p>
    {#if ident.data}
      {@const d = ident.data}
      <p>
        {#if d.enabled}
          <Badge tone="success">{d.claim ? t('mid.state.onClaim', { claim: d.claim, header: d.header }) : t('mid.state.on', { header: d.header })}</Badge>
        {:else}
          <Badge>{t('mid.state.off')}</Badge>
        {/if}
        {#if d.updatedAt}<span class="subtle">{d.updatedBy ?? ''} · {fmtDate(d.updatedAt)}</span>{/if}
      </p>
      {#if !canEdit}<p class="subtle">{t('mid.readOnly')}</p>{/if}
      <div class="grid2">
        <Field label={t('mid.header')} hint={t('mid.headerHint')}>
          {#snippet children({ id, describedby })}
            <input {id} aria-describedby={describedby} class="mono" bind:value={header} maxlength="64" spellcheck="false" autocomplete="off" placeholder="x-user-id" disabled={!canEdit} />
          {/snippet}
        </Field>
        <Field label={t('mid.claim')} hint={t('mid.claimHint')}>
          {#snippet children({ id, describedby })}
            <input {id} aria-describedby={describedby} class="mono" bind:value={claim} maxlength="64" spellcheck="false" autocomplete="off" placeholder="sub" disabled={!canEdit} />
          {/snippet}
        </Field>
      </div>
      {#if canEdit}
        <div class="actions">
          <Button variant="primary" size="sm" loading={busy} onclick={() => save()}>{t('mid.save')}</Button>
          {#if d.enabled}<Button size="sm" disabled={busy} onclick={() => save(true)}>{t('mid.turnOff')}</Button>{/if}
        </div>
      {/if}

      <h3 class="fs-4">{t('mid.map.title')}</h3>
      <p class="subtle">{t('mid.map.hint')}</p>
      {#if d.map.length}
        <table class="map">
          <thead><tr><th scope="col">{t('mid.map.fingerprint')}</th><th scope="col">{t('mid.map.customer')}</th>{#if canEdit}<th scope="col"><span class="sr-only">{t('mid.map.remove', { hash: '' })}</span></th>{/if}</tr></thead>
          <tbody>
            {#each d.map as m (m.hash)}
              <tr>
                <td class="mono" title={m.hash}>{fingerprint(m.hash)}</td>
                <td class="mono">{m.customer}</td>
                {#if canEdit}<td><Button size="sm" variant="ghost" disabled={busy} aria-label={t('mid.map.remove', { hash: fingerprint(m.hash) })} onclick={() => remove(m.hash)}>×</Button></td>{/if}
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="subtle">{t('mid.map.empty')}</p>
      {/if}
      {#if canEdit}
        <div class="grid2">
          <Field label={t('mid.map.user')} hint={t('mid.map.userHint')}>
            {#snippet children({ id, describedby })}
              <input {id} aria-describedby={describedby} bind:value={user} maxlength="256" spellcheck="false" autocomplete="off" />
            {/snippet}
          </Field>
          <Field label={t('mid.map.customer')} hint={t('mid.map.customerHint')} error={customerBad ? t('mid.map.badCustomer') : undefined}>
            {#snippet children({ id, describedby })}
              <input {id} aria-describedby={describedby} class="mono" bind:value={customer} maxlength="32" spellcheck="false" autocomplete="off" placeholder="CUS-SYN-0007" />
            {/snippet}
          </Field>
        </div>
        <div class="actions">
          <Button size="sm" loading={busy} disabled={!user.trim() || !customer.trim() || customerBad} onclick={add}>{t('mid.map.add')}</Button>
        </div>
      {/if}
    {:else}
      <Loading error={ident.error} onretry={ident.reload} lines={2} />
    {/if}
  </div>
</Card>

<style>
  .grid2 { display: grid; gap: var(--s-3); grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); }
  .actions { display: flex; gap: var(--s-2); }
  h3 { margin: var(--s-3) 0 0; }
  .map { border-collapse: collapse; width: auto; }
  .map th, .map td { text-align: left; padding: 4px var(--s-3) 4px 0; }
</style>
