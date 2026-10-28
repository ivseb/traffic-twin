<script lang="ts">
  // Guided editor of a rule written by hand (or of the definition of a draft): "When <call> then <effects>", with
  // dropdowns from the contracts and the entities (GET /api/v1/rules/catalog), a preview in plain words, the checks
  // of the server and a "try it in the mock" hint. The definition is the rules.v1 object the server stores.
  import Field from './Field.svelte';
  import Button from './Button.svelte';
  import Loading from './Loading.svelte';
  import CodeBlock from './CodeBlock.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api, ApiError } from '../lib/api';
  import type { Rule, RuleCheck, RuleDefinition, RuleEffectDef, RuleProblem } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { scopeGroups } from '../lib/scope.svelte';
  import { toast, toastError } from '../lib/stores.svelte';
  import {
    addEffect, causeFields, clone, delayText, effectKind, finalize, findOp, localProblems, newDefinition, newEffect, parseDelay,
    preview, refKey, refLabel, removeEffect, setChance, setWhich, simpleOutcomes, tryCommands, whichOf, fieldRef, type EffectKind,
    renameRow, setRowText, setRowValue, rowProblems, errorBodyProblem, errorBodyText, parseErrorBody,
  } from '../lib/rule-editor';
  import { isDerived, newDerived, type DerivedValue as Derived } from '../lib/derive';
  import { catalogFromOperations, catalogNotice, keepCatalog, keptCatalog, normalizeCatalog } from '../lib/rule-catalog';
  import { statesFacts } from '../lib/codes';
  import { serverText } from '../lib/server-text';
  import InfoTip from './InfoTip.svelte';
  import DerivedValue from './DerivedValue.svelte';
  import { fmtTime } from '../lib/format';
  import { href } from '../lib/router';
  import ConditionsEditor from './ConditionsEditor.svelte';
  import RuleTemplate from './RuleTemplate.svelte';
  import { matchesText, templateParams } from '../lib/rule-templates';

  let {
    rule,
    initial,
    template,
    onsaved,
    oncancel,
  }: {
    rule?: Rule;
    /** Rules v1.9 (C0): a definition to start a new rule from (the skeleton of a candidate below k). */
    initial?: RuleDefinition;
    /** The editor template the start fills (C18). */
    template?: string;
    onsaved: (r: Rule) => void;
    oncancel: () => void;
  } = $props();

  const uid = $props.id();
  const catalog = resource(() => api.rules.catalog(scopeGroups()));
  // The editor opens at once on the catalog read earlier in this tab (the Rules page reads it ahead) while the server
  // refreshes it; when the server is slow and there is none, the person can start with the contracts already read
  // (usability test #5, M4: ~100 s of waiting on every opening).
  const kept = keptCatalog(scopeGroups());
  let partialRaw = $state<ReturnType<typeof catalogFromOperations> | undefined>();
  let partialBusy = $state(false);
  let waited = $state(0);
  $effect(() => {
    if (catalog.data) keepCatalog(scopeGroups(), catalog.data);
  });
  // Every name once (a repeated key stopped the rendering: usability test #4, M1).
  const fresh = $derived(normalizeCatalog(catalog.data));
  const cat = $derived(fresh ?? normalizeCatalog(kept?.catalog) ?? normalizeCatalog(partialRaw));
  const onKept = $derived(!fresh && !!kept);
  const onPartial = $derived(!fresh && !kept && !!partialRaw);
  const notice = $derived(catalogNotice(cat));
  // Seconds of waiting, shown while there is nothing to edit on yet.
  $effect(() => {
    if (cat) return;
    waited = 0;
    const h = setInterval(() => (waited += 1), 1000);
    return () => clearInterval(h);
  });
  async function startPartial(): Promise<void> {
    partialBusy = true;
    try {
      partialRaw = catalogFromOperations(await api.contracts.operations(undefined, scopeGroups()));
    } catch (e) {
      toastError(e);
    } finally {
      partialBusy = false;
    }
  }
  // Where the statuses already come out as codes, the editor must not ask for a keep to be approved (usability #5, M3).
  const policies = resource(() => api.policies.list(scopeGroups()).catch(() => []));
  const states = $derived(statesFacts(policies.data ?? [], scopeGroups() ?? null, null));
  // «Rivedi in blocco › Stati e codici» of the filtered group: where the status gets out in clear (keep).
  const statesLink = $derived(href('/sources', {}, { tab: 'policy', bulk: '1', ...(scopeGroups()?.length === 1 ? { group: scopeGroups()![0] } : {}) }));
  // svelte-ignore state_referenced_locally
  let def = $state<RuleDefinition>(rule ? clone(rule.definition) : initial ? clone(initial) : newDefinition());
  // Rules v1.9 (C18): the template form starts from the candidate or from the draft the editor is open on.
  // svelte-ignore state_referenced_locally
  const preset = def.kind === 'causal' ? templateParams(def, template) : null;
  // svelte-ignore state_referenced_locally
  const presetOrigin: 'candidate' | 'draft' | undefined = preset ? (initial ? 'candidate' : rule ? 'draft' : undefined) : undefined;
  function applyTemplate(next: RuleDefinition): void {
    const match = def.cause?.when.match;
    def = { ...next, title: def.title.trim() || next.title };
    if (match?.length && def.cause) def.cause.when.match = match;
    delays = {};
    invalidate();
    toast(t('w4.tpl.applied'));
  }
  let checking = $state(false);
  let saving = $state(false);
  let checked = $state<RuleCheck | null>(null);
  let serverProblems = $state<RuleProblem[]>([]);
  let delays = $state<Record<string, string>>({});

  const causeOp = $derived(findOp(cat, def.cause?.service ?? '', def.cause?.op ?? ''));
  const local = $derived(localProblems(def));
  const lines = $derived(preview(def));
  const simple = $derived(def.kind === 'causal' && simpleOutcomes(def));
  const chance = $derived(def.outcomes?.find((o) => o.effects.length > 0)?.p ?? def.outcomes?.[0]?.p ?? 1);
  const ops = (svc: string) => cat?.services.find((s) => s.name === svc)?.ops ?? [];
  const entity = (name?: string) => cat?.entities.find((e) => e.name === name);
  const kinds: EffectKind[] = ['state', 'create', 'next', 'error'];

  function invalidate(): void {
    checked = null;
    serverProblems = [];
  }

  function setKind(i: number, kind: EffectKind): void {
    const old = def.effects![i];
    const e = newEffect(def, kind, cat);
    e.id = old.id;
    e.after = old.after;
    if (old.after_effect) e.after_effect = old.after_effect;
    if (e.respond && old.respond) e.respond = { ...old.respond, ...(kind === 'next' ? { times: old.respond.times || 1, p: undefined } : { times: undefined, p: old.respond.p ?? 0.2 }) };
    if (!e.respond && old.entity) e.entity = old.entity;
    def.effects![i] = e;
    invalidate();
  }

  function setCause(service: string, op: string): void {
    def.cause = { service, op, when: { status: [] }, bind: {} };
    const o = findOp(cat, service, op);
    def.cause.when.status = (o?.statuses ?? []).filter((s) => s >= 200 && s < 300).slice(0, 1);
    for (const e of def.effects ?? []) if (e.target_id) delete e.target_id;
    invalidate();
  }

  function toggleStatus(s: number): void {
    const l = def.cause!.when.status;
    def.cause!.when.status = l.includes(s) ? l.filter((x) => x !== s) : [...l, s].sort();
    invalidate();
  }

  // Field rows of create/set/where values: edited as [field, value] pairs.
  type Vals = Record<string, unknown>;
  const rows = (v: Vals | undefined) => Object.entries(v ?? {});
  // A renamed field keeps its value as it is (a derived value stays an object); a typed value is read as a text,
  // a number, true/false or a derived value written as JSON.
  const setRow = (v: Vals, oldKey: string, key: string, value: string): Vals => (oldKey === key ? setRowText(v, key, value) : renameRow(v, oldKey, key));
  const shown = (x: unknown) => (typeof x === 'string' ? x : JSON.stringify(x));
  function setVals(e: RuleEffectDef, kind: EffectKind, nv: Vals): void {
    if (kind === 'create') e.create = nv;
    else e.set = nv;
    invalidate();
  }
  // The error body textarea of each respond effect: the text as typed, until it is valid JSON (or a plain text).
  let bodies = $state<Record<string, string>>({});
  let bodyErrors = $state<Record<string, string>>({});
  function setBody(e: RuleEffectDef, text: string): void {
    bodies[e.id] = text;
    const r = parseErrorBody(text);
    if (r.error) {
      bodyErrors[e.id] = t('ebody.err.json');
      return;
    }
    delete bodyErrors[e.id];
    e.respond = { ...e.respond!, body: r.body };
    if (r.body === undefined) delete e.respond.body;
    invalidate();
  }
  function addRow(v: Vals | undefined, fields: string[]): Vals {
    const used = new Set(Object.keys(v ?? {}));
    const next = fields.find((f) => !used.has(f)) ?? `field${used.size + 1}`;
    return { ...(v ?? {}), [next]: '' };
  }
  function dropRow(v: Vals, key: string): Vals {
    const out = { ...v };
    delete out[key];
    return out;
  }
  const bindRefs = $derived(Object.keys(def.cause?.bind ?? {}).map((k) => '${' + k + '}'));

  function setDelay(e: RuleEffectDef, text: string): void {
    delays[e.id] = text;
    const d = parseDelay(text);
    if (d !== null) e.after = d;
    invalidate();
  }

  function problemText(p: RuleProblem): string {
    return `${tk(`re.code.${p.code}`, undefined, p.code)}${p.path ? ` (${p.path})` : ''}: ${serverText(p.message)}`;
  }

  async function check(): Promise<void> {
    checking = true;
    try {
      checked = await api.rules.check(finalize(def), scopeGroups());
      serverProblems = checked.problems;
    } catch (e) {
      toastError(e);
    } finally {
      checking = false;
    }
  }

  async function save(): Promise<void> {
    if (local.length) return;
    saving = true;
    try {
      const out = finalize(def);
      const r = rule ? await api.rules.update(rule.id, out, scopeGroups()) : await api.rules.create(out, scopeGroups());
      toast(rule && r.id !== rule.id ? t('re.savedNew', { id: r.id, old: rule.id }) : t('re.saved', { id: r.id }));
      onsaved(r);
    } catch (e) {
      if (e instanceof ApiError && e.details?.some((d) => d.code)) {
        serverProblems = e.details.filter((d) => d.code).map((d) => ({ path: d.path ?? '', code: d.code ?? 'invalid', message: d.message ?? '' }));
      } else toastError(e);
    } finally {
      saving = false;
    }
  }
</script>

<div class="editor stack">
  <p class="subtle">{rule ? (rule.status === 'draft' ? t('re.editDraft') : t('re.editApproved')) : t('re.newHint')}</p>
  {#if !cat}
    <div class="stack-sm" data-testid="editor-loading">
      <Loading error={catalog.error} onretry={catalog.reload} lines={4} label={t('fix4.re.loading')} slowMs={600000} />
      {#if !catalog.error}
        <p class="subtle" role="status" data-testid="editor-waited">{t('fix5.re.waiting', { s: waited })}</p>
        <p class="subtle">{t('fix5.re.waitingHow')}</p>
        {#if waited >= 8}
          <div class="callout" role="status" data-testid="editor-slow">
            <b>{t('fix5.re.slowTitle', { s: waited })}</b> {t('fix5.re.partialWhy')}
            <div class="row-tight">
              <Button size="sm" variant="primary" loading={partialBusy} data-testid="editor-partial" onclick={startPartial}>{t('fix5.re.partial')}</Button>
              <InfoTip id="re.partial" />
              <Button size="sm" variant="ghost" onclick={catalog.reload}>{t('fix5.re.retry')}</Button>
            </div>
          </div>
        {/if}
      {/if}
    </div>
  {:else}
  <svelte:boundary onerror={(e) => console.error('rule editor', e)}>
    {#snippet failed(error, retry)}
      <div class="callout danger" role="alert" data-testid="editor-failed">
        {t('fix4.renderFailed', { error: error instanceof Error ? error.message : String(error) })}
        <button type="button" class="link-btn" onclick={() => { def = rule ? clone(rule.definition) : newDefinition(); retry(); }}>{t('fix4.renderRetry')}</button>
      </div>
    {/snippet}
    {#if onKept && kept}<p class="callout" role="status" data-testid="editor-kept">{t('fix5.re.cachedNote', { time: fmtTime(new Date(kept.at).toISOString()) })}</p>{/if}
    {#if onPartial}<p class="callout" role="status" data-testid="editor-partial-note">{t('fix5.re.partialNote')}</p>{/if}
    {#if notice.noServices}<p class="callout warn" role="status">{t('re.noCatalog')}</p>{/if}
    {#if notice.noEntities && onPartial}
      <!-- the entities are still being computed: the partial note above says it -->
    {:else if notice.noEntities}
      <p class="callout" role="status" data-testid="no-states">{states.inClear ? t('fix5.re.noStatesCode', { fields: states.fields.slice(0, 4).join(', ') }) : t('fix4.re.noStates')} <a href={statesLink}>{t('fix4.re.noStatesLink')}</a></p>
    {:else if notice.noValues}
      <p class="callout" role="status">{t('fix4.re.noValues')} <a href={statesLink}>{t('fix4.re.noStatesLink')}</a></p>
    {/if}

    <Field label={t('re.title')} hint={t('re.title.help')}>
      {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} bind:value={def.title} maxlength="200" oninput={invalidate} />{/snippet}
    </Field>

    {#if !rule}
      <fieldset class="seg">
        <legend>{t('re.trigger')}</legend>
        <label><input type="radio" name="{uid}-kind" checked={def.kind === 'causal'} onchange={() => ((def = { ...newDefinition('causal'), title: def.title }), invalidate())} /> {t('re.trigger.op')}</label>
        <label><input type="radio" name="{uid}-kind" checked={def.kind === 'batch'} disabled={notice.noEntities} onchange={() => ((def = { ...newDefinition('batch'), title: def.title }), invalidate())} /> {t('re.trigger.schedule')}</label>
        <p class="subtle">{t('re.trigger.help')}{#if notice.noEntities} {t('fix4.re.batchNeedsEntity')}{/if}</p>
      </fieldset>
    {/if}

    {#if def.kind === 'causal' && def.cause}
      <section class="block cause" aria-label={t('re.trigger')}>
        <h3 class="tag">{t('re.trigger')}</h3>
        <div class="grid-2">
          <Field label={t('re.service')} hint={t('re.service.help')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={def.cause!.service} onchange={(ev) => setCause(ev.currentTarget.value, '')}>
                <option value="">—</option>
                {#each cat.services as s, i (i)}<option value={s.name}>{s.name}</option>{/each}
              </select>
            {/snippet}
          </Field>
          <Field label={t('re.op')} hint={t('re.op.help')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={def.cause!.op} disabled={!def.cause!.service} onchange={(ev) => setCause(def.cause!.service, ev.currentTarget.value)}>
                <option value="">—</option>
                {#each ops(def.cause!.service) as o, i (i)}<option value={o.op}>{o.op}</option>{/each}
              </select>
            {/snippet}
          </Field>
        </div>
        {#if causeOp}
          <fieldset class="chips-row">
            <legend>{t('re.status')}</legend>
            {#each [...new Set([...causeOp.statuses, ...def.cause.when.status])].sort((a, b) => a - b) as s (s)}
              <label class="chip"><input type="checkbox" checked={def.cause.when.status.includes(s)} onchange={() => toggleStatus(s)} /> {s}{#if !causeOp.statuses.includes(s)} <small>({t('re.status.unseen')})</small>{/if}</label>
            {/each}
            <p class="subtle">{t('re.status.help')}</p>
          </fieldset>
        {/if}
        {#if def.cause.op}
          <ConditionsEditor matches={def.cause.when.match} op={causeOp} onchange={(ms) => { if (ms) def.cause!.when.match = ms; else delete def.cause!.when.match; invalidate(); }} />
        {/if}
      </section>

      <RuleTemplate {def} {cat} {preset} origin={presetOrigin} onapply={applyTemplate} />

      <section class="block" aria-label={t('re.effects')}>
        <h3 class="tag">{t('re.effects')}</h3>
        <p class="subtle">{t('re.effects.help')}</p>
        {#each def.effects ?? [] as e, i (e.id)}
          {@const kind = effectKind(e)}
          {@const ent = entity(e.entity)}
          {@const fieldNames = (ent?.fields ?? []).map((f) => f.name ?? '')}
          <div class="effect stack-sm">
            <div class="row spread">
              <b>{t('re.effect.n', { n: i + 1 })} <code class="subtle">{e.id}</code></b>
              <Button size="sm" variant="ghost" icon="trash" onclick={() => (removeEffect(def, e.id), invalidate())}>{t('re.effect.remove')}</Button>
            </div>
            <Field label={t('re.kind')} hint={i === 0 ? t('re.kind.help') : undefined}>
              {#snippet children({ id, describedby })}
                <select {id} aria-describedby={describedby} value={kind} onchange={(ev) => setKind(i, ev.currentTarget.value as EffectKind)}>
                  {#each kinds as k (k)}<option value={k} disabled={(k === 'state' || k === 'create') && cat.entities.length === 0}>{tk(`re.kind.${k}`)}</option>{/each}
                </select>
              {/snippet}
            </Field>

            {#if e.respond}
              {@const rop = findOp(cat, e.respond.service, e.respond.op)}
              <div class="grid-2">
                <Field label={t('re.callService')} hint={t('re.callService.help')}>
                  {#snippet children({ id, describedby })}
                    <select {id} aria-describedby={describedby} value={e.respond!.service} onchange={(ev) => ((e.respond = { ...e.respond!, service: ev.currentTarget.value, op: '', example: undefined }), invalidate())}>
                      <option value="">—</option>
                      {#each cat.services as s, i (i)}<option value={s.name}>{s.name}</option>{/each}
                    </select>
                  {/snippet}
                </Field>
                <Field label={t('re.callOp')} hint={t('re.callOp.help')}>
                  {#snippet children({ id, describedby })}
                    <select {id} aria-describedby={describedby} value={e.respond!.op} onchange={(ev) => ((e.respond = { ...e.respond!, op: ev.currentTarget.value, example: undefined }), invalidate())}>
                      <option value="">—</option>
                      {#each ops(e.respond!.service) as o, i (i)}<option value={o.op}>{o.op}</option>{/each}
                    </select>
                  {/snippet}
                </Field>
                <Field label={t('re.respStatus')} hint={t('re.respStatus.help')}>
                  {#snippet children({ id, describedby })}
                    <input {id} aria-describedby={describedby} type="number" min="100" max="599" list="{uid}-st-{e.id}" value={e.respond!.status} oninput={(ev) => ((e.respond!.status = Number(ev.currentTarget.value)), invalidate())} />
                    <datalist id="{uid}-st-{e.id}">{#each rop?.statuses ?? [] as s, i (i)}<option value={s}></option>{/each}</datalist>
                  {/snippet}
                </Field>
                <Field label={t('re.example')} hint={t('re.example.help')}>
                  {#snippet children({ id, describedby })}
                    <select {id} aria-describedby={describedby} value={e.respond!.example ?? ''} onchange={(ev) => ((e.respond!.example = ev.currentTarget.value || undefined), invalidate())}>
                      <option value="">{t('re.example.first')}</option>
                      {#each rop?.examples?.[String(e.respond!.status)] ?? [] as x, i (i)}<option value={x}>{x}</option>{/each}
                    </select>
                  {/snippet}
                </Field>
                {#if kind === 'next'}
                  <Field label={t('re.times')} hint={t('re.times.help')}>
                    {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="0" step="1" value={e.respond!.times ?? 1} oninput={(ev) => ((e.respond!.times = Math.max(0, Math.round(Number(ev.currentTarget.value)))), invalidate())} />{/snippet}
                  </Field>
                {:else if !e.respond!.until && !e.respond!.limit}
                  <Field label={t('re.p')} hint={t('re.p.help')}>
                    {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="0.01" max="1" step="0.01" value={e.respond!.p ?? 1} oninput={(ev) => ((e.respond!.p = Number(ev.currentTarget.value)), invalidate())} />{/snippet}
                  </Field>
                {/if}
              </div>
              {#if e.respond.until}
                <p class="callout" role="note">{t('w4.re.until', { op: e.respond.op || '…', status: e.respond.status })}</p>
              {:else if e.respond.limit}
                <p class="callout" role="note">{t('w4.re.limit', { n: e.respond.limit.n, window: e.respond.limit.window ?? t('w4.pv.session'), status: e.respond.status })}</p>
              {/if}
              {@const bodyProblem = errorBodyProblem(e.respond.body)}
              {@const bodyProbs = serverProblems.filter((p) => p.path.startsWith(`effects[${i}].respond.body`))}
              <Field
                label={t('ebody.label')}
                hint={t('ebody.help')}
                error={bodyErrors[e.id] ?? (bodyProblem ? tk(`ebody.err.${bodyProblem}`) : bodyProbs.length ? bodyProbs.map(problemText).join(' ') : undefined)}
              >
                {#snippet children({ id, describedby })}
                  <textarea {id} aria-describedby={describedby} class="mono body" rows="4" spellcheck="false" placeholder={t('ebody.placeholder')} value={bodies[e.id] ?? errorBodyText(e.respond!.body)} oninput={(ev) => setBody(e, ev.currentTarget.value)}></textarea>
                {/snippet}
              </Field>
              <p class="subtle">{t('ebody.privacy')}</p>
            {:else}
              <div class="grid-2">
                <Field label={t('re.entity')} hint={t('re.entity.help')}>
                  {#snippet children({ id, describedby })}
                    <select {id} aria-describedby={describedby} value={e.entity ?? ''} onchange={(ev) => ((e.entity = ev.currentTarget.value), invalidate())}>
                      {#each cat.entities as en, i (i)}<option value={en.name}>{en.name}</option>{/each}
                      {#if e.entity && !entity(e.entity)}<option value={e.entity}>{e.entity}</option>{/if}
                    </select>
                  {/snippet}
                </Field>
                {#if kind === 'state' && e.target_all}
                  <p class="callout" role="note">{t('w4.re.all', { entity: e.entity ?? '…' })} <button type="button" class="link-btn" onclick={() => { delete e.target_all; invalidate(); }}>{t('w4.re.allOff')}</button></p>
                {:else if kind === 'state'}
                  <Field label={t('re.which')} hint={t('re.which.help')}>
                    {#snippet children({ id, describedby })}
                      <select {id} aria-describedby={describedby} value={whichOf(def, e)} onchange={(ev) => (setWhich(def, e, ev.currentTarget.value), invalidate())}>
                        <option value="">{t('re.which.none')}</option>
                        {#each causeFields(causeOp, ent?.idDomain) as f, i (i)}<option value={`ref:${refKey(fieldRef(f))}`}>{t('re.which.field', { field: refLabel(fieldRef(f)) })}</option>{/each}
                        {#each (def.effects ?? []).slice(0, i).filter((x) => x.entity === e.entity && !x.respond) as x (x.id)}<option value={`eff:${x.id}`}>{t('re.which.effect', { id: x.id })}</option>{/each}
                        {#if whichOf(def, e).startsWith('ref:') && !causeFields(causeOp, ent?.idDomain).some((f) => `ref:${refKey(fieldRef(f))}` === whichOf(def, e))}<option value={whichOf(def, e)}>{whichOf(def, e).slice(4)}</option>{/if}
                      </select>
                    {/snippet}
                  </Field>
                {/if}
              </div>
              {@const vals = (kind === 'create' ? e.create : e.set) ?? {}}
              <div class="rows">
                {#each rows(vals) as [k, v], j (j)}
                  {@const fld = ent?.fields.find((f) => f.name === k)}
                  {@const derived = isDerived(v)}
                  {@const probs = rowProblems(serverProblems, i, kind === 'create' ? 'create' : 'set', k)}
                  <div class="row-tight vrow">
                    <input aria-label={t('re.field')} list="{uid}-f-{e.id}" value={k} onchange={(ev) => setVals(e, kind, setRow(vals, k, ev.currentTarget.value.trim(), shown(v)))} />
                    <span aria-hidden="true">=</span>
                    <select class="mode" aria-label={t('drv.mode', { field: k })} value={derived ? 'derived' : 'plain'} onchange={(ev) => setVals(e, kind, setRowValue(vals, k, ev.currentTarget.value === 'derived' ? newDerived(fld?.type === 'string' ? 'template' : 'sum') : ''))}>
                      <option value="plain">{t('drv.mode.plain')}</option>
                      <option value="derived">{t('drv.mode.derived')}</option>
                    </select>
                    {#if !derived}
                      <input aria-label={t('re.value')} list="{uid}-v-{e.id}-{j}" value={shown(v)} oninput={(ev) => setVals(e, kind, setRow(vals, k, k, ev.currentTarget.value))} />
                      <datalist id="{uid}-v-{e.id}-{j}">{#each [...new Set([...(fld?.values ?? []), ...bindRefs])] as x (x)}<option value={x}></option>{/each}</datalist>
                    {/if}
                    <Button size="sm" variant="ghost" icon="close" title={t('re.field.remove')} onclick={() => setVals(e, kind, dropRow(vals, k))}>{t('re.field.remove')}</Button>
                  </div>
                  {#if derived}
                    <DerivedValue
                      value={v as Derived}
                      onchange={(nv) => setVals(e, kind, setRowValue(vals, k, nv))}
                      literals={vals}
                      vars={Object.keys(def.cause?.bind ?? {})}
                      effects={(def.effects ?? []).slice(0, i).map((x) => x.id)}
                      fields={[...new Set([...fieldNames, ...Object.keys(vals).filter((x) => x !== k)])]}
                    />
                  {/if}
                  {#each probs as p, pi (pi)}<p class="row-err" role="alert">{problemText(p)}</p>{/each}
                {/each}
                <datalist id="{uid}-f-{e.id}">{#each [...new Set(fieldNames)] as f (f)}<option value={f}></option>{/each}</datalist>
                <Button size="sm" icon="plus" onclick={() => setVals(e, kind, addRow(vals, fieldNames))}>{t('re.field.add')}</Button>
                <p class="subtle">{t('re.field.help')} {t('re.value.help')}</p>
                <p class="subtle">{t('drv.help')}</p>
              </div>
            {/if}

            <div class="grid-2">
              <Field label={t('re.after')} hint={t('re.after.help')} error={parseDelay(delays[e.id] ?? delayText(e.after)) === null ? t('re.local.badAfter', { n: i + 1 }) : undefined}>
                {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} class="mono" value={delays[e.id] ?? delayText(e.after)} oninput={(ev) => setDelay(e, ev.currentTarget.value)} />{/snippet}
              </Field>
              <Field label={t('re.afterFrom')} hint={t('re.afterFrom.help')}>
                {#snippet children({ id, describedby })}
                  <select {id} aria-describedby={describedby} value={e.after_effect ?? ''} onchange={(ev) => { if (ev.currentTarget.value) e.after_effect = ev.currentTarget.value; else delete e.after_effect; invalidate(); }}>
                    <option value="">{t('re.afterFrom.cause')}</option>
                    {#each (def.effects ?? []).slice(0, i) as x (x.id)}<option value={x.id}>{t('re.afterFrom.effect', { id: x.id })}</option>{/each}
                  </select>
                {/snippet}
              </Field>
            </div>
          </div>
        {/each}
        <div class="row">
          <Button icon="plus" onclick={() => (addEffect(def, newEffect(def, cat && cat.entities.length ? 'state' : 'next', cat)), invalidate())}>{t('re.effect.add')}</Button>
        </div>
      </section>

      <section class="block" aria-label={simple ? t('re.chance') : t('re.outcomes')}>
        {#if simple}
          <Field label={t('re.chance')} hint={t('re.chance.help')}>
            {#snippet children({ id, describedby })}<span class="row-tight"><input class="pct" {id} aria-describedby={describedby} type="number" min="1" max="100" step="1" value={Math.round(chance * 100)} oninput={(ev) => (setChance(def, Math.min(100, Math.max(1, Number(ev.currentTarget.value))) / 100), invalidate())} /><span class="subtle">%</span></span>{/snippet}
          </Field>
        {:else}
          <h3 class="tag">{t('re.outcomes')}</h3>
          <p class="subtle">{t('re.outcomes.help')}</p>
          <div class="table-wrap">
            <table class="data">
              <tbody>
                {#each def.outcomes ?? [] as o (o.name)}
                  <tr>
                    <th scope="row">{o.name}{#if o.when?.length}<span class="block subtle cond">{matchesText(o.when)}</span>{/if}</th>
                    <td><input aria-label={t('re.outcome.p', { name: o.name })} type="number" min="0" max="1" step="0.01" value={o.p} oninput={(ev) => ((o.p = Number(ev.currentTarget.value)), invalidate())} /></td>
                    <td>
                      {#each def.effects ?? [] as x (x.id)}
                        <label class="chip"><input type="checkbox" checked={o.effects.includes(x.id)} onchange={() => ((o.effects = o.effects.includes(x.id) ? o.effects.filter((y) => y !== x.id) : [...o.effects, x.id]), invalidate())} /> {x.id}</label>
                      {/each}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <p class="subtle">{t('re.outcome.sum', { p: `${Math.round((def.outcomes ?? []).reduce((a, o) => a + o.p, 0) * 1000) / 10}%` })}</p>
        {/if}
      </section>
    {:else if def.kind === 'batch'}
      {@const ent = entity(def.entity)}
      {@const fieldNames = (ent?.fields ?? []).map((f) => f.name ?? '')}
      <section class="block" aria-label={t('re.trigger.schedule')}>
        <div class="grid-2">
          <Field label={t('re.batch.entity')} hint={t('re.batch.entity.help')}>
            {#snippet children({ id, describedby })}
              <select {id} aria-describedby={describedby} value={def.entity ?? ''} onchange={(ev) => ((def.entity = ev.currentTarget.value), invalidate())}>
                <option value="">—</option>
                {#each cat.entities as en, i (i)}<option value={en.name}>{en.name}</option>{/each}
              </select>
            {/snippet}
          </Field>
          <Field label={t('re.batch.schedule')} hint={t('re.batch.schedule.help')}>
            {#snippet children({ id, describedby })}
              <input {id} aria-describedby={describedby} class="mono" bind:value={def.schedule} oninput={invalidate} />
              <span class="row-tight presets">
                <Button size="sm" variant="ghost" onclick={() => ((def.schedule = '0 2 * * *'), invalidate())}>{t('re.batch.preset.night')}</Button>
                <Button size="sm" variant="ghost" onclick={() => ((def.schedule = '0 * * * *'), invalidate())}>{t('re.batch.preset.hour')}</Button>
                <Button size="sm" variant="ghost" onclick={() => ((def.schedule = '0 6 * * 1'), invalidate())}>{t('re.batch.preset.monday')}</Button>
              </span>
            {/snippet}
          </Field>
        </div>
        {#each [['where', t('re.batch.where'), t('re.batch.where.help')], ['set', t('re.batch.set'), t('re.batch.set.help')]] as [key, label, help] (key)}
          {@const vals = ((key === 'where' ? def.where : def.set) ?? {}) as Record<string, unknown>}
          <fieldset class="rows">
            <legend>{label}</legend>
            {#each rows(vals) as [k, v], j (j)}
              <div class="row-tight vrow">
                <input aria-label={t('re.field')} list="{uid}-bf" value={k} onchange={(ev) => { const nv = setRow(vals, k, ev.currentTarget.value.trim(), shown(v)); if (key === 'where') def.where = nv; else def.set = nv; invalidate(); }} />
                <span aria-hidden="true">=</span>
                <input aria-label={t('re.value')} list="{uid}-bv-{key}-{j}" value={shown(v)} oninput={(ev) => { const nv = setRow(vals, k, k, ev.currentTarget.value); if (key === 'where') def.where = nv; else def.set = nv; invalidate(); }} />
                <datalist id="{uid}-bv-{key}-{j}">{#each [...new Set(ent?.fields.find((f) => f.name === k)?.values ?? [])] as x (x)}<option value={x}></option>{/each}</datalist>
                <Button size="sm" variant="ghost" icon="close" title={t('re.field.remove')} onclick={() => { const nv = dropRow(vals, k); if (key === 'where') def.where = nv; else def.set = nv; invalidate(); }}>{t('re.field.remove')}</Button>
              </div>
            {/each}
            <Button size="sm" icon="plus" onclick={() => { const nv = addRow(vals, fieldNames); if (key === 'where') def.where = nv; else def.set = nv; invalidate(); }}>{t('re.field.add')}</Button>
            <p class="subtle">{help}</p>
          </fieldset>
        {/each}
        <datalist id="{uid}-bf">{#each [...new Set(fieldNames)] as f (f)}<option value={f}></option>{/each}</datalist>
        <Field label={t('re.batch.fraction')} hint={t('re.batch.fraction.help')}>
          {#snippet children({ id, describedby })}<input {id} aria-describedby={describedby} type="number" min="0.01" max="1" step="0.01" bind:value={def.fraction} oninput={invalidate} />{/snippet}
        </Field>
      </section>
    {/if}

    <section class="preview" aria-label={t('re.preview')} data-testid="rule-preview">
      <h3 class="tag">{t('re.preview')}</h3>
      <p class="head">{lines[0]}</p>
      {#if lines.length > 1}<ol>{#each lines.slice(1) as l, i (i)}<li>{l}</li>{/each}</ol>{/if}
      <p class="subtle">{t('re.preview.help')}</p>
    </section>

    {#if local.length || serverProblems.length}
      <div class="callout warn" role="alert">
        <b>{t('re.problems')}</b>
        <ul>
          {#each local as p, i (i)}<li>{p}</li>{/each}
          {#each serverProblems as p, i (i)}<li>{problemText(p)}</li>{/each}
        </ul>
      </div>
    {/if}
    {#if checked?.warnings.length}
      <div class="callout" role="status">
        <b>{t('re.warnings')}</b>
        <ul>{#each checked.warnings as p, i (i)}<li>{problemText(p)}</li>{/each}</ul>
      </div>
    {/if}
    {#if checked?.valid}<p class="callout ok" role="status">{t('re.checkOk')}</p>{/if}

    {#if def.kind === 'causal' && def.cause?.op}
      <details class="try">
        <summary>{t('re.try')}</summary>
        <p>{t('re.try.body', { op: def.cause.op, service: def.cause.service, after: (def.effects ?? []).map((e) => delayText(e.after)).find((d) => d !== '0s') ?? '1h' })}</p>
        <CodeBlock code={tryCommands(def)} title={t('re.try.cmd')} language="bash" />
      </details>
    {/if}

    <div class="row actions">
      <Button onclick={oncancel}>{t('common.cancel')}</Button>
      <Button icon="check" loading={checking} disabled={local.length > 0} onclick={check}>{t('re.check')}</Button>
      <Button variant="primary" loading={saving} disabled={local.length > 0} onclick={save}>{t('re.save')}</Button>
    </div>
  </svelte:boundary>
  {/if}
</div>

<style>
  .editor { max-width: 52rem; }
  .block { border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); display: flex; flex-direction: column; gap: var(--s-3); }
  .cause { border-left: 5px solid var(--accent); }
  .effect { border-left: 4px solid var(--success); padding-left: var(--s-3); }
  .tag { margin: 0; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 700; color: var(--fg-subtle); }
  .seg, .chips-row, .rows { border: 0; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: var(--s-2); align-items: center; }
  .seg legend, .chips-row legend, .rows legend { font-weight: 600; margin-bottom: var(--s-1); width: 100%; }
  .seg p, .chips-row p, .rows p { width: 100%; margin: 0; }
  .chip { display: inline-flex; align-items: center; gap: 4px; border: 1px solid var(--border-strong); border-radius: 999px; padding: 0.1rem 0.6rem; font-size: 0.85rem; margin: 0 4px 4px 0; }
  .vrow { width: 100%; }
  .vrow input { flex: 1; min-width: 6rem; }
  .vrow .mode { width: auto; flex: 0 0 auto; }
  .row-err { color: var(--danger); font-size: 0.86rem; margin: 0; width: 100%; }
  .body { width: 100%; }
  .presets { margin-top: 4px; flex-wrap: wrap; }
  .preview { background: var(--surface-2); border-radius: var(--r-md); padding: var(--s-3) var(--s-4); }
  .preview ol { margin: var(--s-2) 0; padding-left: 1.2rem; }
  .preview .head { margin: var(--s-2) 0 0; font-weight: 600; }
  .try summary { cursor: pointer; font-weight: 600; }
  .actions { justify-content: flex-end; flex-wrap: wrap; }
  .mono { font-family: var(--font-mono); }
  .pct { max-width: 7rem; }
  .block { display: block; }
  .cond { font-weight: 400; font-size: 0.82rem; }
</style>
