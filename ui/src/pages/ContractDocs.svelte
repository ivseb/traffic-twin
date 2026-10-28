<script lang="ts">
  // Deep link #/contracts/service/:name/docs?viewer=swagger|redoc|scalar.
  // The viewers live in their own HTML document (/viewer.html), which the server serves
  // with a scoped CSP; this route just hands over to it.
  import Loading from '../components/Loading.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { loc } from '../lib/router.svelte';
  import { isViewer } from '../viewers';
  import { viewerUrl } from '../lib/viewer-url';

  let { params }: { params: Record<string, string> } = $props();
  const target = $derived(viewerUrl(params.name, isViewer(loc.query.viewer) ? loc.query.viewer : 'swagger', loc.query.group || undefined));

  $effect(() => {
    window.location.replace(target);
  });
</script>

<Loading />
<p class="muted">{t('docs.opening')} <a href={target}>{t('docs.openManual')}</a></p>
