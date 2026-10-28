<script lang="ts">
  // "Valore calcolato" of a create/set field of a rule (rules 1.10): a function, its arguments (numbers, variables of
  // the cause, fields of the entity, earlier effects, the clock, nested values), the options of date / round /
  // template and, at the top level, a preview computed on an example the person can change.
  import Button from './Button.svelte';
  import Self from './DerivedValue.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import {
    arity, argKind, argText, checkDerived, DERIVE_FNS, DERIVE_KEY, DERIVE_MAX_DEPTH, derivedFormula, evalDerived, exampleEnv, exampleInputs, makeArg, switchFn,
    withSpec, type ArgKind, type DerivedValue,
  } from '../lib/derive';

  interface Props {
    value: DerivedValue;
    onchange: (v: DerivedValue) => void;
    /** The literal values of the same effect (samples of the example). */
    literals?: Record<string, unknown>;
    /** Variables bound by the cause, earlier effects, fields of the entity: suggestions. */
    vars?: string[];
    effects?: string[];
    fields?: string[];
    depth?: number;
    /** Prefix of the suggestion lists (the top level's, for the nested values). */
    lists?: string;
  }
  let { value, onchange, literals = {}, vars = [], effects = [], fields = [], depth = 0, lists }: Props = $props();
  const uid = $props.id();
  const listPrefix = $derived(lists ?? uid);

  const spec = $derived(value[DERIVE_KEY]);
  const fn = $derived(spec.fn);
  const args = $derived(spec.args ?? []);
  const lo = $derived(arity(fn)[0]);
  const hi = $derived(arity(fn)[1]);
  const bad = $derived(checkDerived(value, depth));
  const kinds = $derived<ArgKind[]>(['number', 'var', 'field', 'effect', 'now', ...(fn === 'copy' ? (['text'] as ArgKind[]) : []), ...(depth < DERIVE_MAX_DEPTH ? (['nested'] as ArgKind[]) : [])]);

  function setArg(i: number, a: unknown): void {
    const next = [...args];
    next[i] = a;
    onchange(withSpec(value, { args: next }));
  }
  function dropArg(i: number): void {
    onchange(withSpec(value, { args: args.filter((_, j) => j !== i) }));
  }
  function addArg(): void {
    onchange(withSpec(value, { args: [...args, fn === 'date' ? '${now}' : 1] }));
  }

  // The example of the preview (top level only): texts typed by the person, by input key.
  let texts = $state<Record<string, string>>({});
  const inputs = $derived(depth === 0 ? exampleInputs(value, literals) : []);
  const now = new Date();
  const result = $derived(depth === 0 ? evalDerived(value, exampleEnv(inputs, texts, now)) : null);
  const shown = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));

  // The first ids of a template, checked by the server (the grammar of the id formats).
  let tplPreview = $state<string[]>([]);
  let tplError = $state('');
  let seq = 0;
  $effect(() => {
    const tpl = fn === 'template' ? (spec.template ?? '').trim() : '';
    const n = ++seq;
    if (!tpl) {
      tplPreview = [];
      tplError = '';
      return;
    }
    const h = setTimeout(async () => {
      try {
        const r = await api.idFormats.preview(tpl);
        if (n !== seq) return;
        tplPreview = r.valid ? r.preview.slice(0, 3) : [];
        tplError = r.valid ? '' : t('idf.errorAt', { msg: tk(`idf.err.${r.error.code}`, undefined, r.error.code), pos: r.error.at + 1 });
      } catch {
        if (n === seq) tplPreview = [];
      }
    }, 300);
    return () => clearTimeout(h);
  });
</script>

<div class="dv" class:nested={depth > 0} data-testid={depth === 0 ? 'derived-value' : undefined}>
  <div class="line">
    <label class="lbl" for="{uid}-fn">{t('drv.fn')}</label>
    <select id="{uid}-fn" value={fn} onchange={(ev) => onchange(switchFn(value, ev.currentTarget.value))}>
      {#each DERIVE_FNS as f (f)}<option value={f}>{tk(`drv.fn.${f}`, undefined, f)}</option>{/each}
      {#if !(DERIVE_FNS as readonly string[]).includes(fn)}<option value={fn}>{fn}</option>{/if}
    </select>
  </div>
  <p class="subtle hint">{tk(`drv.fn.${fn}.help`, undefined, '')}</p>

  {#if hi > 0}
    <ol class="args" aria-label={t('drv.args')}>
      {#each args as a, i (i)}
        {@const k = argKind(a) ?? 'text'}
        <li>
          <div class="line">
            <select aria-label={t('drv.argKind', { n: i + 1 })} value={k} onchange={(ev) => setArg(i, makeArg(ev.currentTarget.value as ArgKind, k === 'nested' ? '' : argText(a)))}>
              {#each kinds as x (x)}<option value={x}>{tk(`drv.kind.${x}`, undefined, x)}</option>{/each}
              {#if !kinds.includes(k)}<option value={k}>{tk(`drv.kind.${k}`, undefined, k)}</option>{/if}
            </select>
            {#if k === 'number' || k === 'text'}
              <input aria-label={t('drv.argValue', { n: i + 1 })} class="mono" value={argText(a)} inputmode={k === 'number' ? 'decimal' : undefined} oninput={(ev) => setArg(i, makeArg(k, ev.currentTarget.value))} />
            {:else if k === 'var' || k === 'field' || k === 'effect'}
              <input aria-label={t('drv.argValue', { n: i + 1 })} class="mono" list="{listPrefix}-{k}" value={argText(a)} spellcheck="false" placeholder={k === 'field' ? 'items[*].price' : k === 'var' ? 'order' : 'effect-1'} oninput={(ev) => setArg(i, makeArg(k, ev.currentTarget.value))} />
            {:else if k === 'now'}
              <span class="subtle">{t('drv.kind.now.note')}</span>
            {/if}
            {#if args.length > lo}<Button size="sm" variant="ghost" icon="close" title={t('drv.argRemove', { n: i + 1 })} onclick={() => dropArg(i)}>{t('drv.argRemove', { n: i + 1 })}</Button>{/if}
          </div>
          {#if k === 'nested'}
            <Self value={a as DerivedValue} onchange={(v) => setArg(i, v)} {literals} {vars} {effects} {fields} depth={depth + 1} lists={listPrefix} />
          {/if}
        </li>
      {/each}
    </ol>
    {#if args.length < hi}<Button size="sm" icon="plus" onclick={addArg}>{fn === 'date' ? t('drv.dateBase') : t('drv.argAdd')}</Button>{/if}
    <p class="subtle hint">{t('drv.args.help')}</p>
  {/if}

  {#if fn === 'date'}
    <div class="line">
      <label class="lbl" for="{uid}-off">{t('drv.offset')}</label>
      <input id="{uid}-off" class="mono short" value={spec.offset ?? ''} placeholder="+0d" aria-describedby="{uid}-offh" oninput={(ev) => onchange(withSpec(value, { offset: ev.currentTarget.value.trim() }))} />
      <label class="lbl" for="{uid}-fmt">{t('drv.format')}</label>
      <select id="{uid}-fmt" value={spec.format ?? ''} onchange={(ev) => onchange(withSpec(value, { format: ev.currentTarget.value }))}>
        <option value="">{t('drv.format.default')}</option>
        <option value="date">{t('drv.format.date')}</option>
        <option value="date-time">{t('drv.format.dateTime')}</option>
      </select>
    </div>
    <p class="subtle hint" id="{uid}-offh">{t('drv.offset.help')}</p>
  {:else if fn === 'round'}
    <div class="line">
      <label class="lbl" for="{uid}-dg">{t('drv.digits')}</label>
      <input id="{uid}-dg" class="short" type="number" min="0" max="6" step="1" value={spec.digits ?? 2} oninput={(ev) => onchange(withSpec(value, { digits: Math.round(Number(ev.currentTarget.value)) }))} />
    </div>
  {:else if fn === 'template'}
    <div class="line">
      <label class="lbl" for="{uid}-tpl">{t('drv.template')}</label>
      <input id="{uid}-tpl" class="mono" value={spec.template ?? ''} maxlength="64" spellcheck="false" placeholder="'INV'-NNNN" aria-describedby="{uid}-tplh" oninput={(ev) => onchange(withSpec(value, { template: ev.currentTarget.value }))} />
    </div>
    <p class="subtle hint" id="{uid}-tplh">{t('drv.template.help')}</p>
    {#if tplError}<p class="err">{tplError}</p>{:else if tplPreview.length}<p class="subtle hint">{t('idf.preview')}: {#each tplPreview as x (x)}<code>{x}</code> {/each}</p>{/if}
  {/if}

  {#if bad}<p class="err" role="alert">{tk(`drv.err.${bad.code}`, bad.params, bad.code)}</p>{/if}

  {#if depth === 0}
    <div class="example" data-testid="derived-preview">
      <b>{t('drv.example')}</b>
      {#if inputs.length}
        <p class="subtle hint">{t('drv.example.help')}</p>
        <div class="inputs">
          {#each inputs as x (x.key)}
            <label class="ex"><span class="mono">{x.kind === 'var' ? t('drv.ex.var', { name: x.name }) : x.kind === 'effect' ? t('drv.ex.effect', { name: x.name }) : x.name}</span>
              <input class="mono" value={texts[x.key] ?? x.sample} oninput={(ev) => (texts[x.key] = ev.currentTarget.value)} />
            </label>
          {/each}
        </div>
      {/if}
      <p aria-live="polite">
        {#if result?.ok}
          {fn === 'template' ? t('drv.result.template', { formula: derivedFormula(value) }) : t('drv.result', { formula: derivedFormula(value), value: shown(result.value) })}
        {:else if result && result.missing}
          {t('drv.result.missing')}
        {:else if result && !bad}
          {t('drv.result.error', { error: result.error })}
        {/if}
      </p>
      {#if fn === 'date' || derivedFormula(value).includes('now')}<p class="subtle hint">{t('drv.example.clock')}</p>{/if}
    </div>
    <datalist id="{uid}-var">{#each vars as x (x)}<option value={x}></option>{/each}</datalist>
    <datalist id="{uid}-field">{#each fields as x (x)}<option value={x}></option>{/each}</datalist>
    <datalist id="{uid}-effect">{#each effects as x (x)}<option value={x}></option>{/each}</datalist>
  {/if}
</div>

<style>
  .dv { display: flex; flex-direction: column; gap: var(--s-2); width: 100%; border: 1px dashed var(--border-strong); border-radius: var(--r-md); padding: var(--s-2) var(--s-3); }
  .dv.nested { margin: var(--s-2) 0 0 var(--s-3); }
  .line { display: flex; flex-wrap: wrap; gap: var(--s-2); align-items: center; }
  .line input { flex: 1; min-width: 6rem; }
  .line input.short { flex: 0 0 7rem; min-width: 0; }
  .lbl { font-weight: 600; font-size: 0.9rem; }
  .hint { margin: 0; font-size: 0.84rem; }
  .args { margin: 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: var(--s-2); }
  .example { background: var(--surface-2); border-radius: var(--r-md); padding: var(--s-2) var(--s-3); display: flex; flex-direction: column; gap: var(--s-1); }
  .example p { margin: 0; }
  .inputs { display: flex; flex-wrap: wrap; gap: var(--s-2); }
  .ex { display: flex; flex-direction: column; gap: 2px; font-size: 0.85rem; min-width: 10rem; flex: 1; }
  .err { color: var(--danger); font-size: 0.86rem; margin: 0; }
  .mono { font-family: var(--font-mono); }
</style>
