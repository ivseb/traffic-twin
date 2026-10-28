<script lang="ts">
  // «Identità dell'utente» (docs/spec/policy.md §7.1, §7.4): who the user is, as the console detected it from the data,
  // and the person's choice. Any request header that is not a credential applies at once (the value leaves only as a
  // token); a cookie or a credential waits for approvals. The server decides; the verdict shown here only anticipates it.
  import Badge from './Badge.svelte';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import InfoTip from './InfoTip.svelte';
  import Loading from './Loading.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { IdentityCandidate, IdentitySource, ObserveStatus, PolicyVersion } from '../lib/api';
  import { can, errorMessage, toast, toastError } from '../lib/stores.svelte';
  import { fmtNum, fmtPct } from '../lib/format';
  import { candidateSource, identityVerdict, normalizeSource, sameSource, sourceText, splitCandidates } from '../lib/identity';

  interface Props {
    /** The groups whose policy may be set; with more than one the person picks. */
    groups: string[];
    initialGroup?: string;
    /** The observe state already loaded by the page (the wizard polls it); otherwise the control loads it. */
    status?: ObserveStatus | null;
    /** Called after a version was applied or proposed. */
    onchange?: (v: PolicyVersion) => void;
  }
  let { groups, initialGroup, status = undefined, onchange }: Props = $props();

  let group = $state('');
  $effect(() => {
    if (!group || !groups.includes(group)) group = initialGroup && groups.includes(initialGroup) ? initialGroup : (groups[0] ?? '');
  });

  let loaded = $state<ObserveStatus | null>(null);
  let loading = $state(false);
  let loadError = $state<Error | undefined>();
  async function load(): Promise<void> {
    if (!group) return;
    loading = true;
    loadError = undefined;
    try {
      loaded = await api.onboarding.observe(group);
    } catch (e) {
      loadError = e instanceof Error ? e : new Error(String(e));
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    if (status === undefined && group) void load();
  });
  const st = $derived(status === undefined ? loaded : status);

  const current = $derived(st?.identity);
  const best = $derived(st?.identityBest);
  const bestCand = $derived((st?.identityCandidates ?? []).find((c) => c.best) ?? (best ? (st?.identityCandidates ?? []).find((c) => sameSource(candidateSource(c), best)) : undefined));
  const split = $derived(splitCandidates(st?.identityCandidates ?? []));

  // The choice: a candidate (by index in the server list) or a name typed by the person.
  let mode = $state<'cand' | 'custom'>('cand');
  let pickedKey = $state('');
  let customFrom = $state<'header' | 'cookie'>('header');
  let customName = $state('');
  let customClaim = $state('');
  // Spec v1.18: the user as a member of a header whose value is JSON (dotted path), header only.
  let customJson = $state('');
  const keyOf = (c: IdentityCandidate) => `${c.from}\u0000${c.name}\u0000${c.claim ?? ''}`;
  const all = $derived([...split.usable, ...split.excluded]);
  // Preselect what is in use, else what the detection picks.
  $effect(() => {
    if (pickedKey || mode === 'custom' || all.length === 0) return;
    const cur = all.find((c) => sameSource(candidateSource(c), current));
    const pick = cur ?? all.find((c) => c.best) ?? split.usable[0];
    if (pick) pickedKey = keyOf(pick);
  });
  const chosen = $derived.by((): IdentitySource | undefined => {
    if (mode === 'custom') return customName.trim() ? normalizeSource({ from: customFrom, name: customName, claim: customClaim, jsonPath: customFrom === 'header' ? customJson : '' }) : undefined;
    const c = all.find((x) => keyOf(x) === pickedKey);
    return c ? candidateSource(c) : undefined;
  });
  const verdict = $derived(chosen ? identityVerdict(chosen) : undefined);
  const isCurrent = $derived(!!chosen && sameSource(chosen, current));

  const srcText = (s: { from: string; name: string; claim?: string }) => {
    const x = sourceText(s);
    return t(x.key, x.params);
  };
  const reasonsOf = (c: IdentityCandidate) => (c.signals ?? []).map((s) => tk(`id.sig.${s}`, undefined, s)).join(' · ');

  let busy = $state(false);
  async function apply(): Promise<void> {
    if (!chosen || !group || verdict === 'invalid' || isCurrent) return;
    busy = true;
    try {
      const v = await api.onboarding.setIdentity(group, chosen);
      toast(v.status === 'active' ? t('id.applied', { source: srcText(chosen), v: v.version }) : t('id.draft', { v: v.version }));
      if (status === undefined) await load();
      onchange?.(v);
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="stack-sm idc" data-testid="identity-control">
  {#if groups.length > 1}
    <Field label={t('id.group')}>
      {#snippet children({ id })}
        <select {id} bind:value={group} onchange={() => { pickedKey = ''; mode = 'cand'; }}>
          {#each groups as g (g)}<option value={g}>{g}</option>{/each}
        </select>
      {/snippet}
    </Field>
  {/if}

  {#if status === undefined && loading && !loaded}
    <Loading />
  {:else if loadError}
    <p class="callout warn" role="alert">{t('id.loadError', { error: errorMessage(loadError) })}</p>
  {:else if st && !st.policyId && st.phase === 'no_policy'}
    <p class="callout" role="status">{t('id.noPolicy')}</p>
  {:else if st}
    <p class="subtle">{t('id.subtitle')} <InfoTip id="obs.identity" /></p>
    <p class={current ? 'callout ok' : 'callout warn'} role="status" data-testid="identity-current">
      {current ? t('id.current', { source: srcText(current) }) : t('id.currentNone')}
    </p>
    {#if best}
      <p class="callout" role="status" data-testid="identity-detected">
        {t('id.detected', { source: srcText(best), score: bestCand?.score ?? 100 })}
        {#if bestCand?.signals?.length}<span class="block subtle">{reasonsOf(bestCand)}</span>{/if}
        {#if sameSource(best, current)}<span class="block subtle">{t('id.detectedIsCurrent')}</span>{/if}
      </p>
    {:else if all.length}
      <p class="callout" role="status" data-testid="identity-detected">{t('id.detectedNone')}</p>
    {:else}
      <p class="subtle" role="status">{t('id.noData')}</p>
    {/if}

    <fieldset class="cands">
      <legend>{t('id.candidates')}</legend>
      {#each split.usable as c (keyOf(c))}
        {@render option(c)}
      {/each}
      {#if split.excluded.length}
        <details class="excl">
          <summary>{t('id.excluded', { n: split.excluded.length })}</summary>
          <p class="subtle">{t('id.excludedHint')}</p>
          {#each split.excluded as c (keyOf(c))}
            {@render option(c)}
          {/each}
        </details>
      {/if}
      <label class="mode" class:sel={mode === 'custom'}>
        <input type="radio" name="idc-{group}" checked={mode === 'custom'} onchange={() => (mode = 'custom')} />
        <span>{t('id.custom')}</span>
      </label>
      {#if mode === 'custom'}
        <div class="row idrow">
          <Field label={t('id.from')}>
            {#snippet children({ id })}<select {id} bind:value={customFrom}><option value="header">header</option><option value="cookie">cookie</option></select>{/snippet}
          </Field>
          <Field label={t('id.name')} hint={t('id.nameHint')}>
            {#snippet children({ id, describedby })}<input {id} bind:value={customName} aria-describedby={describedby} spellcheck="false" autocomplete="off" data-testid="identity-name" />{/snippet}
          </Field>
          <Field label={t('id.claim')} hint={t('id.claimHint')}>
            {#snippet children({ id, describedby })}<input {id} bind:value={customClaim} aria-describedby={describedby} spellcheck="false" autocomplete="off" placeholder="sub" disabled={!!customJson.trim()} />{/snippet}
          </Field>
          {#if customFrom === 'header'}
            <Field label={t('w4.id.json')} hint={t('w4.id.jsonHint')}>
              {#snippet children({ id, describedby })}<input {id} bind:value={customJson} aria-describedby={describedby} spellcheck="false" autocomplete="off" placeholder="user.id" data-testid="identity-json-path" />{/snippet}
            </Field>
          {/if}
        </div>
      {/if}
    </fieldset>

    {#if chosen && verdict}
      {#if verdict === 'invalid'}
        <p class="callout warn" role="status">{t('id.invalidName')}</p>
      {:else if isCurrent}
        <p class="subtle" role="status">{t('id.same')}</p>
      {:else if verdict === 'safe'}
        <p class="callout ok" role="status" data-testid="identity-verdict">{t('id.safe')}</p>
      {:else}
        <p class="callout warn" role="status" data-testid="identity-verdict">{tk(`id.opens.${verdict}`)}</p>
      {/if}
    {/if}
    <div>
      <Button variant="primary" icon="check" loading={busy} denied={!can('policy.propose')} disabled={!chosen || verdict === 'invalid' || isCurrent || !group} onclick={apply}>{t('id.apply')}</Button>
    </div>
  {/if}
</div>

{#snippet option(c: IdentityCandidate)}
  {@const src = candidateSource(c)}
  <label class="mode" class:sel={mode === 'cand' && pickedKey === keyOf(c)}>
    <input type="radio" name="idc-{group}" checked={mode === 'cand' && pickedKey === keyOf(c)} onchange={() => { mode = 'cand'; pickedKey = keyOf(c); }} />
    <span>
      <b class="mono">{c.from} {c.name}</b>
      {#if src.claim}<Badge tone="accent">JWT → {src.claim}</Badge>{/if}
      {#if c.best}<Badge tone="success">{t('id.best')}</Badge>{/if}
      {#if sameSource(src, current)}<Badge tone="info">{t('id.inUse')}</Badge>{/if}
      <Badge tone={identityVerdict(src) === 'safe' ? 'neutral' : 'warning'}>{identityVerdict(src) === 'safe' ? t('id.immediate') : t('id.needsApproval')}</Badge>
      {#if typeof c.score === 'number'}<span class="subtle"> {t('id.score', { score: c.score })}</span>{/if}
      <span class="subtle block">{t('id.stats', { calls: fmtNum(c.calls), distinct: fmtNum(c.distinct), presence: typeof c.presence === 'number' ? fmtPct(c.presence, 0) : '—' })}</span>
      {#if c.excluded}<span class="block warnText">{tk(`id.excl.${c.excluded}`, undefined, c.excluded)}</span>{/if}
      {#if c.signals?.length}<span class="subtle block">{reasonsOf(c)}</span>{/if}
    </span>
  </label>
{/snippet}

<style>
  .cands { border: 0; padding: 0; margin: 0; display: grid; gap: var(--s-2); }
  .cands legend { font-weight: 600; margin-bottom: var(--s-1); }
  .mode { display: flex; gap: var(--s-3); align-items: flex-start; padding: var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-sm); cursor: pointer; }
  .mode.sel { border-color: var(--accent); background: var(--accent-soft); }
  .block { display: block; }
  .excl { display: grid; gap: var(--s-2); }
  .excl summary { cursor: pointer; }
  .idrow { gap: var(--s-3); flex-wrap: wrap; align-items: flex-start; }
  .warnText { color: var(--warning); }
</style>
