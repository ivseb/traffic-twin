<script lang="ts">
  // Run the mock yourself (container or Helm chart) connected to the console: a mock token for the group, shown
  // once, with the commands already filled in. Also the list of tokens, to revoke one.
  import Card from '../Card.svelte';
  import Button from '../Button.svelte';
  import Field from '../Field.svelte';
  import Tabs from '../Tabs.svelte';
  import CodeBlock from '../CodeBlock.svelte';
  import Badge from '../Badge.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api, cliCommand, type MockToken, type NewMockToken } from '../../lib/api';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtDate } from '../../lib/format';

  let { group, kubernetes, tokens, onchanged }: { group: string; kubernetes: boolean; tokens: MockToken[]; onchanged?: () => void } = $props();

  let label = $state('');
  let busy = $state(false);
  let created = $state<NewMockToken | null>(null);
  // The tt binary of the kit first: no container needed, the command the guide describes (usability test #4, m1).
  let tab = $state('cli');
  let revokeId = $state<string | null>(null);
  let revokeOpen = $state(false);

  const code = $derived.by(() => {
    const s = created?.setup;
    if (!s) return '';
    switch (tab) {
      case 'helm':
        return `# values-mock.yaml\n${s.helmValues}\n# ${t('mk.inst.commands')}\n${s.helm}`;
      case 'openshift':
        return `# values-mock.yaml\n${s.helmValues}\n# ${t('mk.inst.commands')}\n${s.openshift}`;
      case 'env':
        return s.env;
      case 'cli':
        return cliCommand(s, created?.token ?? '');
      default:
        return s.docker;
    }
  });

  async function create(): Promise<void> {
    busy = true;
    try {
      created = await api.mocks.createToken(group, label.trim() || undefined);
      label = '';
      onchanged?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  async function revoke(): Promise<void> {
    if (!revokeId) return;
    try {
      await api.mocks.revokeToken(revokeId);
      toast(t('mk.inst.revoked'));
      if (created?.id === revokeId) created = null;
      onchanged?.();
    } catch (e) {
      toastError(e);
    }
  }
  const mine = $derived(tokens.filter((x) => x.group === group && !x.managed));
</script>

<Card title={t('mk.inst.title')} subtitle={kubernetes ? t('mk.inst.subtitleK8s') : t('mk.inst.subtitle')}>
  <div class="stack">
    <ol class="how">
      <li>{t('mk.inst.step1')}</li>
      <li>{t('mk.inst.step2')}</li>
      <li>{t('mk.inst.step3')}</li>
    </ol>
    <div class="row">
      <Field label={t('mk.inst.label')} hint={t('mk.inst.labelHint')} help="mock.token">
        {#snippet children({ id, describedby })}
          <input {id} aria-describedby={describedby} bind:value={label} maxlength="64" placeholder={t('mk.inst.labelPlaceholder')} />
        {/snippet}
      </Field>
      <div class="go"><Button variant="primary" icon="lock" loading={busy} disabled={!group} denied={!can('publish.build')} onclick={create}>{t('mk.inst.create', { group })}</Button></div>
    </div>
    {#if created}
      <div class="callout warn">
        <p><b>{t('mk.inst.once')}</b></p>
        <p class="subtle">{t('fix4.mk.tokenPrefix')}</p>
        <CodeBlock code={created.token} title={t('mk.inst.token')} />
      </div>
      <Tabs label={t('mk.inst.how')} tabs={[{ id: 'cli', label: t('fix4.mk.cli') }, { id: 'docker', label: 'Docker' }, { id: 'helm', label: 'Helm' }, { id: 'openshift', label: 'OpenShift' }, { id: 'env', label: t('mk.inst.env') }]} bind:value={tab}>
        {#if tab === 'cli' || tab === 'docker'}<p class="subtle" data-testid="mock-cli-note">{tab === 'cli' ? t('fix4.mk.cliNote', { version: created.setup.version ?? created.setup.image.split(':')[1] ?? '' }) : t('fix4.mk.dockerNote', { version: created.setup.version ?? created.setup.image.split(':')[1] ?? '' })}</p>{/if}
        <CodeBlock {code} language={tab === 'env' || tab === 'docker' || tab === 'cli' ? 'bash' : 'yaml'} maxHeight="24rem" />
      </Tabs>
      <p class="subtle">{t('mk.inst.after')}</p>
    {/if}
    {#if mine.length}
      <div>
        <h3 class="fs-4">{t('mk.inst.tokens')}</h3>
        <ul class="toks">
          {#each mine as tok (tok.id)}
            <li>
              <code>{tok.id}</code>
              {#if tok.label}<span>{tok.label}</span>{/if}
              <span class="subtle">{t('mk.inst.tokenMeta', { by: tok.createdBy, until: fmtDate(tok.expiresAt, false) })}</span>
              {#if tok.revoked}<Badge tone="danger">{t('mk.inst.isRevoked')}</Badge>{:else}
                <Button size="sm" variant="ghost" icon="trash" denied={!can('publish.build')} onclick={() => { revokeId = tok.id; revokeOpen = true; }}>{t('mk.inst.revoke')}</Button>
              {/if}
            </li>
          {/each}
        </ul>
      </div>
    {/if}
  </div>
</Card>

<ConfirmDialog bind:open={revokeOpen} title={t('mk.inst.revokeTitle')} message={t('mk.inst.revokeMsg')} confirmLabel={t('mk.inst.revoke')} onconfirm={revoke} />

<style>
  .how { margin: 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: 4px; }
  .row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: var(--s-3); align-items: end; }
  .go { padding-bottom: 2px; }
  .toks { list-style: none; margin: var(--s-1) 0 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-1); }
  .toks li { display: flex; flex-wrap: wrap; gap: var(--s-2); align-items: center; }
  @media (max-width: 40rem) { .row { grid-template-columns: 1fr; } }
</style>
