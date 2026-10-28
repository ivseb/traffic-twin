<script lang="ts">
  // Conditions of a rule (rules v1.9, cause.when.match): the rule fires only when a member of the request has one of
  // the values (or a number in a range), or when the customer has an attribute. All conditions must hold. The values
  // are typed by the person; the server checks the members against the contracts.
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import type { CatalogOp, RuleMatch, RuleRefDef } from '../lib/api';
  import { matchText, parseValues } from '../lib/rule-templates';
  import { refKey, refLabel, refOfKey } from '../lib/rule-editor';

  let { matches, op, onchange }: { matches: RuleMatch[] | undefined; op: CatalogOp | undefined; onchange: (ms: RuleMatch[] | undefined) => void } = $props();
  const uid = $props.id();

  // The request members a condition can read: parameters, query, headers and body members outside arrays.
  const members = $derived(
    [...(op?.params ?? []), ...(op?.request ?? [])]
      .filter((f) => f.from.startsWith('req.') && f.from !== 'req.cookies' && !(f.path ?? '').includes('[*]'))
      .map((f): RuleRefDef => (f.path ? { from: f.from, path: f.path } : { from: f.from, name: f.name ?? '' })),
  );

  let adding = $state(false);
  let source = $state<'request' | 'customer'>('request');
  let member = $state('');
  let customMember = $state('');
  let attr = $state('');
  let mode = $state<'in' | 'range'>('in');
  let values = $state('');
  let min = $state('');
  let max = $state('');

  const atRef = $derived.by((): RuleRefDef | undefined => {
    if (member === '__custom') {
      const n = customMember.trim();
      if (!n) return undefined;
      return n.startsWith('$') ? { from: 'req.body', path: n } : { from: 'req.query', name: n };
    }
    return member ? refOfKey(member) : undefined;
  });
  const draft = $derived.by((): RuleMatch | undefined => {
    const who: Partial<RuleMatch> | undefined = source === 'customer' ? (/^[a-z][a-z0-9_]{0,31}$/.test(attr.trim()) ? { customer: attr.trim() } : undefined) : atRef ? { at: atRef } : undefined;
    if (!who) return undefined;
    if (mode === 'in') {
      const vs = parseValues(values);
      return vs.length ? { ...who, in: vs } : undefined;
    }
    const lo = min.trim() === '' ? undefined : Number(min);
    const hi = max.trim() === '' ? undefined : Number(max);
    if ((lo === undefined && hi === undefined) || (lo !== undefined && Number.isNaN(lo)) || (hi !== undefined && Number.isNaN(hi))) return undefined;
    if (lo !== undefined && hi !== undefined && !(lo < hi)) return undefined;
    return { ...who, ...(lo !== undefined ? { min: lo } : {}), ...(hi !== undefined ? { max: hi } : {}) };
  });

  function add(): void {
    if (!draft) return;
    onchange([...(matches ?? []), draft]);
    adding = false;
    values = min = max = customMember = attr = '';
  }
  function drop(i: number): void {
    const next = (matches ?? []).filter((_, j) => j !== i);
    onchange(next.length ? next : undefined);
  }
</script>

<fieldset class="conds" data-testid="conditions">
  <legend>{t('w4.cond.heading')}</legend>
  {#if matches?.length}
    <ul>
      {#each matches as m, i (i)}
        <li class="row-tight"><span class="grow">{matchText(m)}</span><Button size="sm" variant="ghost" icon="close" onclick={() => drop(i)}>{t('w4.cond.remove')}</Button></li>
      {/each}
    </ul>
  {:else}
    <p class="subtle">{t('w4.cond.none')}</p>
  {/if}
  {#if adding}
    <div class="grid-2">
      <Field label={t('w4.cond.source')}>
        {#snippet children({ id })}
          <select {id} bind:value={source}>
            <option value="request">{t('w4.cond.src.request')}</option>
            <option value="customer">{t('w4.cond.src.customer')}</option>
          </select>
        {/snippet}
      </Field>
      {#if source === 'request'}
        <Field label={t('w4.cond.member')} hint={t('w4.cond.memberHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} bind:value={member}>
              <option value="">—</option>
              {#each members as r (refKey(r))}<option value={refKey(r)}>{refLabel(r)}</option>{/each}
              <option value="__custom">{t('w4.cond.memberOther')}</option>
            </select>
            {#if member === '__custom'}<input aria-label={t('w4.cond.memberOther')} bind:value={customMember} placeholder="$.channel" spellcheck="false" />{/if}
          {/snippet}
        </Field>
      {:else}
        <Field label={t('w4.cond.attr')} hint={t('w4.cond.attrHint')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} bind:value={attr} spellcheck="false" placeholder="segment" />{/snippet}
        </Field>
      {/if}
    </div>
    <div class="row-tight" role="radiogroup" aria-label={t('w4.cond.kind')}>
      <label><input type="radio" name="{uid}-mode" checked={mode === 'in'} onchange={() => (mode = 'in')} /> {t('w4.cond.kind.in')}</label>
      <label><input type="radio" name="{uid}-mode" checked={mode === 'range'} onchange={() => (mode = 'range')} /> {t('w4.cond.kind.range')}</label>
    </div>
    {#if mode === 'in'}
      <Field label={t('w4.cond.values')} hint={t('w4.cond.valuesHint')}>
        {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} bind:value={values} spellcheck="false" placeholder="WEB, APP" />{/snippet}
      </Field>
    {:else}
      <div class="grid-2">
        <Field label={t('w4.cond.min')}>{#snippet children({ id })}<input {id} type="number" bind:value={min} />{/snippet}</Field>
        <Field label={t('w4.cond.max')} hint={t('w4.cond.maxHint')}>{#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" bind:value={max} />{/snippet}</Field>
      </div>
    {/if}
    {#if draft}<p class="subtle" role="status">{matchText(draft)}</p>{/if}
    <div class="row-tight">
      <Button size="sm" variant="primary" disabled={!draft} onclick={add}>{t('w4.cond.addThis')}</Button>
      <Button size="sm" variant="ghost" onclick={() => (adding = false)}>{t('common.cancel')}</Button>
    </div>
  {:else}
    <div><Button size="sm" icon="plus" onclick={() => (adding = true)}>{t('w4.cond.add')}</Button></div>
  {/if}
  <p class="subtle">{t('w4.cond.help')}</p>
</fieldset>

<style>
  .conds { border: 0; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--s-2); }
  .conds legend { font-weight: 600; margin-bottom: var(--s-1); }
  ul { margin: 0; padding-left: 1.1rem; }
  .grow { flex: 1; }
</style>
