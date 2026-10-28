<script lang="ts">
  // "Chiavi HMAC": where the HMAC key of the sources comes from and how the platform team distributes it.
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import RichText from '../components/RichText.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can } from '../lib/stores.svelte';

  // keyguard status lists the kids it holds (never the keys); not every role may read it.
  const kg = resource(async () => (can('audit.view') || can('sources.manage') || can('policy.approve') ? await api.keyguard.status().catch(() => null) : null));
  const kids = $derived(kg.data?.reachable ? kg.data.hmacKids : []);

  const genCmd = $derived(`# ${t('hmac.c.gen')}
tt keyguard genkey -type hmac -kid k1 -out /etc/traffic-twin/hmac.keys
# ${t('hmac.c.kg')}
TT_KEYGUARD_HMAC_KEYS_FILE=/etc/traffic-twin/hmac.keys`);
  const vmCmd = $derived(`# ${t('hmac.c.vm')}
sudo install -d -m 0755 /etc/traffic-twin
sudo install -m 0640 -o root -g <app-group> hmac.keys /etc/traffic-twin/hmac.key
export TT_HMAC_KEY_FILE=/etc/traffic-twin/hmac.key`);
  const k8sCmd = $derived(`# ${t('hmac.c.k8s')}
kubectl -n <namespace> create secret generic tt-hmac --from-file=hmac-key=/etc/traffic-twin/hmac.keys
# ${t('hmac.c.annot')}
#   traffic-twin.io/hmac-secret: tt-hmac
# ${t('hmac.c.noWebhook')}
#   TT_HMAC_KEY_FILE=/var/run/secrets/traffic-twin/hmac-key`);
  const rotateCmd = $derived(`# ${t('hmac.c.rotate1')}
tt keyguard genkey -type hmac -kid k2 -out k2.key && cat k2.key >> /etc/traffic-twin/hmac.keys && rm k2.key
# ${t('hmac.c.rotate2')}`);
</script>

<PageHeader title={t('hmac.title')} description={t('hmac.desc')} help="hmac-keys" breadcrumbs={[{ label: t('nav.glossary'), href: '#/glossary' }, { label: t('hmac.title') }]} />

<div class="stack">
  <Card title={t('hmac.what.title')}>
    <div class="stack-sm">
      <p><RichText text={t('hmac.what.p1')} /></p>
      <p><RichText text={t('hmac.what.p2')} /></p>
      <p class="callout warn"><RichText text={t('hmac.what.warn')} /></p>
      {#if kids.length}<p class="subtle">{t('hmac.kids', { kids: kids.join(', ') })}</p>{/if}
    </div>
  </Card>

  <Card title={t('hmac.dev.title')}>
    <ol class="steps">
      <li><RichText text={t('hmac.dev.s1')} /></li>
      <li><RichText text={t('hmac.dev.s2')} /></li>
      <li><RichText text={t('hmac.dev.s3')} /></li>
      <li><RichText text={t('hmac.dev.s4')} /></li>
    </ol>
  </Card>

  <Card title={t('hmac.admin.title')} subtitle={t('hmac.admin.sub')}>
    <div class="stack-sm">
      <h3 class="fs-4">{t('hmac.admin.gen')}</h3>
      <CodeBlock code={genCmd} language="bash" />
      <h3 class="fs-4">{t('hmac.admin.vm')}</h3>
      <CodeBlock code={vmCmd} language="bash" />
      <h3 class="fs-4">{t('hmac.admin.k8s')}</h3>
      <CodeBlock code={k8sCmd} language="bash" />
      <h3 class="fs-4">{t('hmac.admin.rotate')}</h3>
      <CodeBlock code={rotateCmd} language="bash" />
      <p class="subtle"><RichText text={t('hmac.admin.note')} /></p>
    </div>
  </Card>

  <Card title={t('hmac.trouble.title')}>
    <ul class="steps">
      <li><RichText text={t('hmac.trouble.missing')} /></li>
      <li><RichText text={t('hmac.trouble.mismatch')} /></li>
      <li><RichText text={t('hmac.trouble.unknown')} /></li>
    </ul>
  </Card>
</div>

<style>
  .steps { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: var(--s-2); }
</style>
