<script lang="ts">
  // How keyguard checks the approval about to be given (keyguard.md 3.2): without OIDC it trusts tt-core
  // (a reduced guarantee, shown as a warning); with OIDC every approval asks a step-up at the identity provider.
  import { t } from '../lib/i18n/index.svelte';

  import type { Settings } from '../lib/api';

  /** Nothing is shown while the settings load or when this role cannot read them (known: false). */
  let { approvals }: { approvals: Settings['approvals'] | undefined } = $props();
  const verified = $derived(approvals && approvals.known !== false ? approvals.identitiesVerified : undefined);
</script>

{#if verified === false}
  <p class="callout warn" role="note" data-testid="approvals-unverified"><b>{t('appr.unverifiedTitle')}</b> {t('appr.unverified')}</p>
{:else if verified === true}
  <p class="callout" role="note" data-testid="approvals-stepup">{t('appr.stepupNote')}</p>
{/if}
