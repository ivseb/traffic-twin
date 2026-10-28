<script lang="ts">
  // Templates of the rule editor (rules v1.9, C18): the four behaviours people write most by hand, as a short form
  // instead of effects and branches. The cause is the operation chosen in the editor; applying a template replaces the
  // effects and the branches of the rule (the title is kept). Prefilled from a candidate below k or from the draft the
  // editor was opened on.
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import type { RuleCatalog, RuleDefinition, RuleRefDef } from '../lib/api';
  import { causeFields, fieldRef, findOp, refKey, refLabel, refOfKey } from '../lib/rule-editor';
  import { TEMPLATES, buildTemplate, templateMissing, type TemplateId, type TemplateParams } from '../lib/rule-templates';

  interface Props {
    def: RuleDefinition;
    cat: RuleCatalog;
    /** Values to start from (a candidate's template, a draft's effects). */
    preset?: TemplateParams | null;
    /** Where the preset comes from: a candidate below k or the draft the editor edits. */
    origin?: 'candidate' | 'draft';
    onapply: (def: RuleDefinition) => void;
  }
  let { def, cat, preset = null, origin, onapply }: Props = $props();
  const uid = $props.id();

  // svelte-ignore state_referenced_locally
  let p = $state<TemplateParams>(preset ? { ...preset } : { template: 'write_changes_field', service: '', op: '', status: 0, after: '0s' });
  // svelte-ignore state_referenced_locally
  let open = $state(!!preset);

  const cause = $derived(def.cause);
  const causeOp = $derived(findOp(cat, cause?.service ?? '', cause?.op ?? ''));
  const entity = $derived(cat.entities.find((e) => e.name === p.entity));
  const requestRefs = $derived(
    [...(causeOp?.params ?? []), ...(causeOp?.request ?? [])].filter((f) => f.from.startsWith('req.')).map(fieldRef),
  );
  const full = $derived<TemplateParams>({ ...p, service: cause?.service ?? p.service, op: cause?.op ?? p.op, status: cause?.when.status[0] ?? p.status });
  const missing = $derived(templateMissing(full));
  const ops = (svc: string) => cat.services.find((s) => s.name === svc)?.ops ?? [];
  const keyOf = (r: RuleRefDef | undefined) => (r ? refKey(r) : '');
  const refFrom = (k: string): RuleRefDef | undefined => (k ? refOfKey(k) : undefined);

  function apply(): void {
    if (missing.length) return;
    onapply(buildTemplate(full, def.title.trim()));
  }
</script>

<details class="tpl" bind:open data-testid="rule-templates">
  <summary>{t('w4.tpl.heading')}</summary>
  <div class="stack-sm">
    <p class="subtle">{t('w4.tpl.intro')}</p>
    {#if origin}<p class="callout" role="status">{origin === 'candidate' ? t('w4.tpl.from.candidate') : t('w4.tpl.from.draft')}</p>{/if}
    <fieldset class="seg">
      <legend>{t('w4.tpl.pick')}</legend>
      {#each TEMPLATES as id (id)}
        <label class="opt" class:sel={p.template === id}>
          <input type="radio" name="{uid}-kind" checked={p.template === id} onchange={() => (p.template = id as TemplateId)} />
          <span><b>{tk(`w4.tpl.name.${id}`)}</b><span class="block subtle">{tk(`w4.tpl.desc.${id}`)}</span></span>
        </label>
      {/each}
    </fieldset>
    <p class="subtle">{cause?.op ? t('w4.tpl.causeNote', { op: cause.op, service: cause.service }) : t('w4.tpl.causeFirst')}</p>

    {#if p.template === 'write_changes_field' || p.template === 'expires_after'}
      <div class="grid-2">
        <Field label={t('w4.tpl.entity')} hint={t('w4.tpl.entityHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} bind:value={p.entity}>
              <option value={undefined}>—</option>
              {#each cat.entities as en (en.name)}<option value={en.name}>{en.name}</option>{/each}
              {#if p.entity && !entity}<option value={p.entity}>{p.entity}</option>{/if}
            </select>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.which')} hint={t('w4.tpl.whichHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} value={p.all ? '__all' : keyOf(p.which)} onchange={(ev) => { const v = ev.currentTarget.value; p.all = v === '__all'; p.which = v && v !== '__all' ? refFrom(v) : undefined; }}>
              <option value="">—</option>
              {#each causeFields(causeOp, entity?.idDomain) as f (refKey(fieldRef(f)))}<option value={refKey(fieldRef(f))}>{t('re.which.field', { field: refLabel(fieldRef(f)) })}</option>{/each}
              {#if p.which && !causeFields(causeOp, entity?.idDomain).some((f) => refKey(fieldRef(f)) === keyOf(p.which))}<option value={keyOf(p.which)}>{refLabel(p.which)}</option>{/if}
              <option value="__all">{t('w4.tpl.which.all')}</option>
            </select>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.field')} hint={t('w4.tpl.fieldHint')}>
          {#snippet children({ id, describedby })}
            <input {id} aria-describedby={describedby} list="{uid}-fields" bind:value={p.field} spellcheck="false" />
            <datalist id="{uid}-fields">{#each entity?.fields ?? [] as f, i (i)}<option value={f.name ?? ''}></option>{/each}</datalist>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.value')} hint={p.template === 'write_changes_field' ? t('w4.tpl.valueHint') : t('w4.tpl.valueHintExpires')}>
          {#snippet children({ id, describedby })}
            <input {id} aria-describedby={describedby} list="{uid}-values" bind:value={p.value} disabled={!!p.copy && p.template === 'write_changes_field'} spellcheck="false" />
            <datalist id="{uid}-values">{#each entity?.fields.find((f) => f.name === p.field)?.values ?? [] as v (v)}<option value={v}></option>{/each}</datalist>
          {/snippet}
        </Field>
        {#if p.template === 'write_changes_field'}
          <Field label={t('w4.tpl.copy')} hint={t('w4.tpl.copyHint')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={keyOf(p.copy)} onchange={(ev) => (p.copy = refFrom(ev.currentTarget.value))}>
                <option value="">{t('w4.tpl.copy.none')}</option>
                {#each requestRefs as r (refKey(r))}<option value={refKey(r)}>{refLabel(r)}</option>{/each}
                {#if p.copy && !requestRefs.some((r) => refKey(r) === keyOf(p.copy))}<option value={keyOf(p.copy)}>{refLabel(p.copy)}</option>{/if}
              </select>
            {/snippet}
          </Field>
        {:else}
          <Field label={t('w4.tpl.revert')} hint={t('w4.tpl.revertHint')}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} list="{uid}-values" bind:value={p.revertTo} spellcheck="false" />{/snippet}
          </Field>
          <Field label={t('w4.tpl.expires')} hint={t('w4.tpl.expiresHint')}>
            {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" bind:value={p.expiresAfter} placeholder="1h" />{/snippet}
          </Field>
        {/if}
      </div>
    {:else if p.template === 'at_most_n'}
      <div class="grid-2">
        <Field label={t('w4.tpl.n')} hint={t('w4.tpl.nHint')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="1" step="1" bind:value={p.n} />{/snippet}
        </Field>
        <Field label={t('w4.tpl.window')} hint={t('w4.tpl.windowHint')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" bind:value={p.window} placeholder="15m" />{/snippet}
        </Field>
        <Field label={t('w4.tpl.key')} hint={t('w4.tpl.keyHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} value={keyOf(p.key)} onchange={(ev) => (p.key = refFrom(ev.currentTarget.value))}>
              <option value="">{t('w4.tpl.key.user')}</option>
              {#each requestRefs as r (refKey(r))}<option value={refKey(r)}>{refLabel(r)}</option>{/each}
              {#if p.key && !requestRefs.some((r) => refKey(r) === keyOf(p.key))}<option value={keyOf(p.key)}>{refLabel(p.key)}</option>{/if}
            </select>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.answer')} hint={t('w4.tpl.answerHintLimit')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="100" max="599" bind:value={p.answer} placeholder="429" />{/snippet}
        </Field>
      </div>
    {:else}
      <div class="grid-2">
        <Field label={t('w4.tpl.targetService')}>
          {#snippet children({ id })}
            <select {id} value={p.targetService ?? cause?.service ?? ''} onchange={(ev) => ((p.targetService = ev.currentTarget.value), (p.targetOp = undefined))}>
              <option value="">—</option>
              {#each cat.services as s (s.name)}<option value={s.name}>{s.name}</option>{/each}
            </select>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.target')} hint={t('w4.tpl.targetHint')}>
          {#snippet children({ id, describedby })}
            <select {id} aria-describedby={describedby} bind:value={p.targetOp}>
              <option value={undefined}>—</option>
              {#each ops(p.targetService ?? cause?.service ?? '') as o (o.op)}<option value={o.op}>{o.op}</option>{/each}
              {#if p.targetOp && !ops(p.targetService ?? cause?.service ?? '').some((o) => o.op === p.targetOp)}<option value={p.targetOp}>{p.targetOp}</option>{/if}
            </select>
          {/snippet}
        </Field>
        <Field label={t('w4.tpl.answer')} hint={t('w4.tpl.answerHintUntil')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="100" max="599" bind:value={p.answer} placeholder="409" />{/snippet}
        </Field>
      </div>
    {/if}

    {#if missing.length}<p class="subtle" role="status">{t('w4.tpl.miss', { what: missing.map((m) => tk(`w4.tpl.miss.${m}`)).join(', ') })}</p>{/if}
    <div class="row-tight">
      <Button size="sm" variant="primary" disabled={missing.length > 0} onclick={apply} data-testid="template-apply">{t('w4.tpl.apply')}</Button>
      <span class="subtle">{t('w4.tpl.applyHint')}</span>
    </div>
  </div>
</details>

<style>
  .tpl { border: 1px dashed var(--border-strong); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); }
  .tpl summary { cursor: pointer; font-weight: 600; }
  .seg { border: 0; padding: 0; margin: 0; display: grid; gap: var(--s-2); }
  .seg legend { font-weight: 600; margin-bottom: var(--s-1); }
  .opt { display: flex; gap: var(--s-3); align-items: flex-start; padding: var(--s-2) var(--s-3); border: 1px solid var(--border-strong); border-radius: var(--r-sm); cursor: pointer; }
  .opt.sel { border-color: var(--accent); background: var(--accent-soft); }
  .block { display: block; }
  .mono { font-family: var(--font-mono); }
</style>
