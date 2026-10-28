<script lang="ts">
  // Two settings of a group that come with rules v1.9 (admin-api 1.21.0):
  //  - «Domini da unire» (C15): HMAC domains that look like one identifier under two names, proposed by the miner from
  //    structure only; joining them writes hmac.families in the policy (observe-safe: no value leaves, applies at once).
  //  - «Gruppo di test: k ridotto» (C0): an administrator lowers k for a group of testers (never below 2, with a reason,
  //    audited); rules come from few users and the packs of the group carry a warning.
  import Badge from './Badge.svelte';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import Loading from './Loading.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { FamilyCandidate, ObserveStatus } from '../lib/api';
  import { can, errorMessage, session, toast, toastError } from '../lib/stores.svelte';
  import { isAdmin } from '../lib/rbac';
  import { fmtNum, fmtPct } from '../lib/format';

  let { groups, initialGroup, onchange }: { groups: string[]; initialGroup?: string; onchange?: () => void } = $props();

  let group = $state('');
  $effect(() => {
    if (!group || !groups.includes(group)) group = initialGroup && groups.includes(initialGroup) ? initialGroup : (groups[0] ?? '');
  });

  let st = $state<ObserveStatus | null>(null);
  let cands = $state<FamilyCandidate[]>([]);
  let loading = $state(false);
  let loadError = $state('');
  async function load(): Promise<void> {
    if (!group) return;
    loading = true;
    loadError = '';
    try {
      const [o, s] = await Promise.all([api.onboarding.observe(group), api.rules.status([group]).catch(() => null)]);
      st = o;
      cands = (s?.families ?? []).filter((f) => !f.group || f.group === group);
      kInput = String(o.testKMin ?? 0);
    } catch (e) {
      loadError = errorMessage(e);
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    if (group) void load();
  });

  const families = $derived(Object.entries(st?.families ?? {}));
  const kMin = $derived(st?.kMin ?? 20);
  const admin = $derived(isAdmin(session.user));

  // The name of a new family: the shortest domain (the person may change it).
  let names = $state<Record<string, string>>({});
  const keyOf = (f: FamilyCandidate) => f.domains.join('+');
  const nameOf = (f: FamilyCandidate) => names[keyOf(f)] ?? [...f.domains].sort((a, b) => a.length - b.length || a.localeCompare(b))[0];
  const validName = (n: string) => /^[a-z][a-z0-9_-]{0,31}$/.test(n) && n !== 'subject';

  let busy = $state('');
  async function join(f: FamilyCandidate): Promise<void> {
    busy = keyOf(f);
    try {
      const v = await api.onboarding.setFamily(group, nameOf(f), f.domains);
      toast(t('w4.fam.joined', { family: nameOf(f), v: v.version }));
      await load();
      onchange?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = '';
    }
  }
  async function split(family: string): Promise<void> {
    busy = family;
    try {
      const v = await api.onboarding.removeFamily(group, family);
      toast(t('w4.fam.splitDone', { family, v: v.version }));
      await load();
      onchange?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = '';
    }
  }

  let kInput = $state('0');
  let reason = $state('');
  const kValue = $derived(Number(kInput));
  const kValid = $derived(Number.isInteger(kValue) && (kValue === 0 || (kValue >= 2 && kValue < kMin)));
  const kChanged = $derived(kValue !== (st?.testKMin ?? 0));
  async function saveK(): Promise<void> {
    if (!kValid || (kValue > 0 && !reason.trim())) return;
    busy = 'k';
    try {
      st = await api.onboarding.setTestK(group, kValue, reason);
      toast(kValue > 0 ? t('w4.tk.saved', { group, k: kValue }) : t('w4.tk.off', { group }));
      reason = '';
      onchange?.();
    } catch (e) {
      toastError(e);
    } finally {
      busy = '';
    }
  }
</script>

<div class="stack" data-testid="group-domains-testk">
  {#if groups.length > 1}
    <Field label={t('w4.grp.group')}>
      {#snippet children({ id })}
        <select {id} bind:value={group}>{#each groups as g (g)}<option value={g}>{g}</option>{/each}</select>
      {/snippet}
    </Field>
  {/if}
  {#if loading && !st}
    <Loading />
  {:else if loadError}
    <p class="callout warn" role="alert">{loadError}</p>
  {:else if st}
    <section class="stack-sm" aria-labelledby="fam-h" data-testid="families">
      <h3 id="fam-h" class="fs-3">{t('w4.fam.heading')}</h3>
      <p class="subtle">{t('w4.fam.intro')}</p>
      <p class="callout" role="note">{t('w4.fam.consequence')}</p>
      {#if cands.length}
        <ul class="list">
          {#each cands as f (keyOf(f))}
            <li class="item">
              <div class="row-tight"><b class="mono">{f.domains.join(' + ')}</b><Badge tone="neutral">{t('w4.fam.subjects', { n: fmtNum(f.subjects) })}</Badge><Badge tone="info">{t('w4.fam.score', { score: fmtPct(f.score, 0) })}</Badge></div>
              <span class="subtle">{t('w4.fam.signals', { signals: f.signals.map((s) => tk(`w4.fam.sig.${s}`, undefined, s)).join(' · ') || '—' })}</span>
              <div class="row-tight">
                <Field label={t('w4.fam.name')} hint={t('w4.fam.nameHint')} error={validName(nameOf(f)) ? undefined : t('w4.fam.badName')}>
                  {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} value={nameOf(f)} oninput={(ev) => (names[keyOf(f)] = ev.currentTarget.value.trim())} spellcheck="false" />{/snippet}
                </Field>
                <Button size="sm" variant="primary" loading={busy === keyOf(f)} denied={!can('policy.propose')} disabled={!validName(nameOf(f))} onclick={() => join(f)}>{t('w4.fam.join')}</Button>
              </div>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="subtle" data-testid="families-empty">{t('w4.fam.empty')}</p>
      {/if}
      <h4 class="fs-4">{t('w4.fam.current')}</h4>
      {#if families.length}
        <ul class="list">
          {#each families as [name, ds] (name)}
            <li class="item row spread">
              <span><b class="mono">{name}</b> = <span class="mono">{ds.join(', ')}</span></span>
              <Button size="sm" variant="ghost" loading={busy === name} denied={!can('policy.propose')} onclick={() => split(name)}>{t('w4.fam.split')}</Button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="subtle">{t('w4.fam.none')}</p>
      {/if}
    </section>

    <section class="stack-sm" aria-labelledby="tk-h" data-testid="test-k">
      <h3 id="tk-h" class="fs-3">{t('w4.tk.heading')}</h3>
      <p class="subtle">{t('w4.tk.intro', { k: kMin })}</p>
      <p class={st.testKMin ? 'callout warn' : 'callout'} role="status" data-testid="test-k-current">
        {st.testKMin ? t('w4.tk.current', { k: st.testKMin, kMin }) : t('w4.tk.currentOff', { kMin })}
      </p>
      {#if admin}
        <div class="grid-2">
          <Field label={t('w4.tk.k')} hint={t('w4.tk.kHint', { max: kMin - 1 })} error={kValid ? undefined : t('w4.tk.invalid', { max: kMin - 1 })}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="0" max={kMin - 1} step="1" bind:value={kInput} data-testid="test-k-input" />{/snippet}
          </Field>
          <Field label={t('w4.tk.reason')} hint={t('w4.tk.reasonHint')}>
            {#snippet children({ id, describedby })}<textarea {id} aria-describedby={describedby} rows="2" maxlength="500" bind:value={reason}></textarea>{/snippet}
          </Field>
        </div>
        <p class="subtle">{t('w4.tk.consequences')}</p>
        <div>
          <Button variant="primary" loading={busy === 'k'} disabled={!kValid || !kChanged || (kValue > 0 && !reason.trim())} onclick={saveK}>{t('w4.tk.save')}</Button>
        </div>
      {:else}
        <p class="subtle">{t('w4.tk.adminOnly')}</p>
      {/if}
    </section>
  {/if}
</div>

<style>
  .list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .item { border: 1px solid var(--border-strong); border-radius: var(--r-sm); padding: var(--s-2) var(--s-3); display: flex; flex-direction: column; gap: var(--s-1); }
  .item.row { flex-direction: row; align-items: center; }
  .mono { font-family: var(--font-mono); }
  h3, h4 { margin: 0; }
</style>
