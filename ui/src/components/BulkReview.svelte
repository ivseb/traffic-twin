<script lang="ts">
  // «Rivedi in blocco» (spec v1.6, policy.md §7): the fields the assistant saw, grouped by kind, one action per group.
  // The result is one policy version: applied at once when it opens no values, a draft to approve otherwise.
  import Drawer from './Drawer.svelte';
  import Button from './Button.svelte';
  import Badge from './Badge.svelte';
  import Field from './Field.svelte';
  import InfoTip from './InfoTip.svelte';
  import Loading from './Loading.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { GroupApprover, PolicyAssist, PolicySuggestion, ProposePolicyInput, ValueReason } from '../lib/api';
  import { can, toast, toastError } from '../lib/stores.svelte';
  import { formatChoice } from '../lib/policy';
  import { FIELD_GROUPS, fieldGroup, groupActions, type FieldGroup, type GroupAction } from '../lib/observe';
  import { approvalPlan, bulkRow, summarizeRows, type ApprovalPlan, type BulkRow } from '../lib/bulk';

  interface Props {
    open: boolean;
    /** Groups that have a policy (the person picks one). */
    groups: string[];
    /** Called after a version was proposed or applied. */
    onchange?: () => void;
    /** The group to open on (a link «Rivedi in blocco» of a group), when it is one of `groups`. */
    initialGroup?: string;
  }
  let { open = $bindable(), groups, onchange, initialGroup }: Props = $props();

  let group = $state('');
  let assist = $state<PolicyAssist | null>(null);
  let loadError = $state<Error | undefined>();
  let loading = $state(false);
  let busy = $state(false);
  let actions = $state<Record<FieldGroup, GroupAction>>({ ids: 'keep-current', states: 'keep-current', numbers: 'keep-current', dates: 'keep-current', personal: 'keep-current', other: 'keep-current' });
  let check = $state<{ opensValues: boolean; valueReasons: ValueReason[]; approvalsRequired: number } | null>(null);
  // The box of every field as the person left it (absent: the default of the group action). Never the code -> keep step.
  let picked = $state<Record<string, boolean>>({});
  // Who can approve a draft of the group (names only); null while unknown or when the server does not say.
  let approvers = $state<GroupApprover[] | null>(null);

  $effect(() => {
    if (open && !group && groups.length) group = initialGroup && groups.includes(initialGroup) ? initialGroup : groups[0];
  });
  $effect(() => {
    if (!open || !group) return;
    const g = group;
    loading = true;
    loadError = undefined;
    assist = null;
    check = null;
    picked = {};
    approvers = null;
    api.policies
      .approvers(g)
      .then((l) => {
        if (g === group) approvers = l;
      })
      .catch(() => {
        /* an older server, or not a member of the group: the drawer says it cannot tell */
      });
    api.onboarding
      .assist(g)
      .then((a) => {
        if (g === group) assist = a;
      })
      .catch((e) => (loadError = e instanceof Error ? e : new Error(String(e))))
      .finally(() => (loading = false));
  });

  /** Services the policy can declare without a person: own ones and external ones already declared (no scheme to guess). */
  const eligible = $derived(new Set((assist?.services ?? []).filter((s) => s.kind === 'own' || s.declared).map((s) => s.service)));
  const skipped = $derived((assist?.services ?? []).some((s) => s.kind === 'external' && !s.declared));
  const fields = $derived((assist?.suggestions ?? []).filter((s) => eligible.has(s.service)));
  const byGroup = $derived(Object.fromEntries(FIELD_GROUPS.map((g) => [g, fields.filter((f) => fieldGroup(f) === g)])) as Record<FieldGroup, PolicySuggestion[]>);
  // One row per field: the group action is the default, the checkbox of the field decides.
  const rowsOf = $derived(Object.fromEntries(fields.map((f) => [f.id, bulkRow(f, actions[fieldGroup(f)], picked[f.id])])) as Record<string, BulkRow>);
  const choices = $derived(Object.fromEntries((assist?.suggestions ?? []).map((s) => [s.id, rowsOf[s.id]?.choice ?? { ...s.current }])));
  const changed = $derived(fields.filter((f) => rowsOf[f.id]?.changes));
  const summary = $derived(summarizeRows(fields.map((f) => rowsOf[f.id])));
  const groupSummary = (g: FieldGroup) => summarizeRows(byGroup[g].map((f) => rowsOf[f.id]));
  const openingFields = $derived(fields.filter((f) => rowsOf[f.id]?.opens));
  // The approvals of the draft: how many (the server's number once checked), who, and whether an admin must step in.
  const plan = $derived<ApprovalPlan>(approvalPlan(check ? (check.opensValues ? 1 : 0) : summary.opening, check?.approvalsRequired || 2, approvers, can('override.admin')));

  function input(): ProposePolicyInput {
    const ops = new Map<string, Set<string>>();
    for (const f of changed) {
      if (!ops.has(f.service)) ops.set(f.service, new Set());
      ops.get(f.service)!.add(f.op);
    }
    const services = (assist?.services ?? [])
      .filter((s) => ops.has(s.service))
      .map((s) => ({ service: s.service, name: s.name, ...(s.base ? { base: s.base } : {}), ops: [...(ops.get(s.service) ?? [])] }));
    return { group, choices: (assist?.suggestions ?? []).map((s) => ({ suggestionId: s.id, choice: choices[s.id] })), services };
  }

  function setAction(g: FieldGroup, a: GroupAction): void {
    actions[g] = a;
    // A new action starts from its own default: the boxes of this group are forgotten.
    for (const f of byGroup[g]) delete picked[f.id];
    check = null;
  }
  function pick(f: PolicySuggestion, on: boolean): void {
    picked[f.id] = on;
    check = null;
  }
  function pickAll(g: FieldGroup, on: boolean): void {
    for (const f of byGroup[g]) picked[f.id] = on;
    check = null;
  }

  async function runCheck(): Promise<void> {
    busy = true;
    try {
      const p = await api.policies.preview(input());
      check = { opensValues: p.opensValues ?? false, valueReasons: p.valueReasons ?? [], approvalsRequired: p.approvalsRequired ?? 0 };
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }

  async function submit(): Promise<void> {
    busy = true;
    try {
      const v = await api.policies.propose(input());
      toast(v.status === 'active' ? t('obs.bulk.done', { v: v.version }) : t('obs.bulk.draft', { v: v.version }));
      onchange?.();
      open = false;
    } catch (e) {
      toastError(e);
    } finally {
      busy = false;
    }
  }
  const fieldLabel = (f: PolicySuggestion) => `${f.op} · ${tk(`wiz.part.${f.part}`, undefined, f.part)} · ${f.path}`;
</script>

<Drawer bind:open title={t('obs.bulk.title')}>
  <div class="stack" data-testid="bulk-review">
    <p class="subtle">{t('obs.bulk.subtitle')} <InfoTip id="obs.bulk" /></p>
    <Field label={t('obs.bulk.group')} help="obs.group" hint={t('obs.bulk.groupHint')}>
      {#snippet children({ id, describedby })}
        <select {id} bind:value={group} aria-describedby={describedby}>
          {#each groups as g (g)}<option value={g}>{g}</option>{/each}
        </select>
      {/snippet}
    </Field>
    {#if !groups.length}
      <p class="callout warn" role="status">{t('obs.bulk.noGroup')}</p>
    {:else if loading || loadError}
      <Loading error={loadError} label={t('fix4.bulk.loading')} />
    {:else if assist && fields.length === 0}
      <p class="callout" role="status">{t('obs.bulk.empty')}</p>
    {:else if assist}
      <p class="subtle" data-testid="bulk-how">{t('fix5.bulk.how')}</p>
      {#each FIELD_GROUPS as g (g)}
        {#if byGroup[g].length}
          {@const gs = groupSummary(g)}
          <section class="grp" data-testid={`bulk-${g}`} aria-label={tk(`obs.bulk.g.${g}`)}>
            <div class="head">
              <div>
                <b>{tk(`obs.bulk.g.${g}`)}</b> <Badge>{t('fix5.bulk.groupCount', { n: byGroup[g].length, changed: gs.changed, opening: gs.opening })}</Badge>
                <div class="subtle">{tk(`obs.bulk.g.${g}.desc`)}</div>
              </div>
              <label class="act">
                <select value={actions[g]} onchange={(e) => setAction(g, e.currentTarget.value as GroupAction)} aria-label={`${t('obs.bulk.action')}: ${tk(`obs.bulk.g.${g}`)}`}>
                  {#each groupActions(g) as a (a)}<option value={a}>{tk(`obs.bulk.a.${a}`)}</option>{/each}
                </select>
              </label>
            </div>
            {#if actions[g] !== 'keep-current'}
              <div class="bulkbtns">
                <Button size="sm" variant="ghost" onclick={() => pickAll(g, true)}>{t('fix5.bulk.all')}</Button>
                <Button size="sm" variant="ghost" onclick={() => pickAll(g, false)}>{t('fix5.bulk.none')}</Button>
              </div>
            {/if}
            <ul class="fields" aria-label={t('fix5.bulk.fieldsOf', { name: tk(`obs.bulk.g.${g}`) })}>
              {#each byGroup[g] as f (f.id)}
                {@const r = rowsOf[f.id]}
                <li class="frow" class:off={!r.selected} data-testid="bulk-field">
                  <input type="checkbox" class="pick" checked={r.selected} disabled={actions[g] === 'keep-current'} aria-label={t('fix5.bulk.pick', { field: f.path })} onchange={(e) => pick(f, e.currentTarget.checked)} />
                  <span class="what"><span class="mono svc">{f.service}</span> <span class="subtle">{fieldLabel(f)}</span></span>
                  <span class="acts">
                    <span class="lbl subtle">{t('fix5.bulk.now')}</span> <code>{formatChoice(f.current)}</code>
                    {#if r.protectedCode}
                      <span class="subtle">· {t('fix5.bulk.stays')}</span>
                    {:else if f.suggestion.action !== f.current.action || formatChoice(f.suggestion) !== formatChoice(f.current)}
                      <span class="lbl subtle">· {t('fix5.bulk.proposal')}</span> <code>{formatChoice(f.suggestion)}</code>
                    {/if}
                    {#if r.changes}<span aria-hidden="true">→</span><span class="sr-only">{t('fix5.bulk.becomes')}</span> <code>{formatChoice(r.choice)}</code>{/if}
                  </span>
                  <span class="tag">
                    {#if r.opens}<Badge tone="warning">{t('fix5.bulk.opens')}</Badge>{:else if r.changes}<Badge tone="success">{t('fix5.bulk.quiet')}</Badge>{/if}
                  </span>
                  {#if r.protectedCode}<span class="note subtle">{t('fix5.bulk.codeKept')}</span>{/if}
                </li>
              {/each}
            </ul>
          </section>
        {/if}
      {/each}
      {#if skipped}<p class="subtle">{t('obs.bulk.skipped')}</p>{/if}
      <p class="callout" role="status" data-testid="bulk-summary">
        {#if summary.changed === 0}{t('fix5.bulk.summaryNone')}{:else}{t('fix5.bulk.summary', { changed: summary.changed, opening: summary.opening, quiet: summary.quiet })}{/if}
      </p>
      {#if changed.length === 0}
        <p class="callout" role="status">{t('obs.bulk.noChange')}</p>
      {:else}
        {#if summary.opening > 0}
          <div class="subtle">{t('fix5.bulk.openingList')}<ul class="fields">{#each openingFields as f (f.id)}<li><span class="mono">{f.service}</span> <code>{f.path}</code></li>{/each}</ul></div>
        {:else}
          <p class="callout ok" role="status" data-testid="bulk-noopen">{t('fix5.bulk.noOpening')}</p>
        {/if}
        {#if summary.opening > 0}
          <section class="callout warn who" role="status" aria-label={t('fix5.bulk.needTitle')} data-testid="bulk-approvals">
            <b>{t('fix5.bulk.needTitle')}</b>
            <p>{t('fix5.bulk.need', { n: plan.need })}</p>
            {#if plan.unknown}
              <p>{t('fix5.bulk.unknown')}</p>
            {:else if plan.adminOnly}
              <p>{t('fix5.bulk.adminOnly', { names: plan.names.join(', ') })}</p>
            {:else if plan.names.length}
              <p>{t('fix5.bulk.who', { names: plan.names.join(', ') })}</p>
              {#if plan.short}<p data-testid="bulk-fewer">{t('fix5.bulk.fewer', { need: plan.need, have: plan.names.length })}</p>{/if}
            {:else}
              <p data-testid="bulk-fewer">{t('fix5.bulk.noOne')}</p>
            {/if}
            {#if plan.selfAdmin}<p>{t('fix5.bulk.selfAdmin')}</p>{/if}
            <p class="subtle">{t('fix5.bulk.withdrawHint')}</p>
          </section>
        {/if}
        {#if check}
          <p class="callout {check.opensValues ? 'warn' : 'ok'}" role="status" data-testid="bulk-class">{check.opensValues ? t('obs.class.opens') : t('obs.class.safe')}</p>
          {#if check.opensValues}
            <div class="subtle">{t('obs.class.why')}<ul class="fields">{#each check.valueReasons as r, i (i)}<li>{tk(`obs.reason.${r.code}`, undefined, r.code)} <code>{r.where}</code></li>{/each}</ul></div>
          {/if}
        {/if}
      {/if}
    {/if}
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (open = false)}>{t('common.close')}</Button>
    {#if !check}
      <Button variant="primary" loading={busy} disabled={changed.length === 0} onclick={runCheck}>{t('obs.bulk.check')}</Button>
    {:else}
      <Button variant="primary" icon={check.opensValues ? 'lock' : 'check'} loading={busy} denied={!can('policy.propose')} disabled={changed.length === 0} onclick={submit}>{check.opensValues ? t('obs.bulk.request') : t('obs.apply')}</Button>
    {/if}
  {/snippet}
</Drawer>

<style>
  .grp { border: 1px solid var(--border); border-radius: var(--r-sm); padding: var(--s-3); display: grid; gap: var(--s-2); container-type: inline-size; }
  .head { display: flex; justify-content: space-between; gap: var(--s-3); align-items: flex-start; flex-wrap: wrap; }
  .act select { min-width: 12rem; }
  .bulkbtns { display: flex; gap: var(--s-2); flex-wrap: wrap; }
  .fields { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--s-2); font-size: 0.86rem; }
  /* One grid for every row: the box, the field, what it does today and what it becomes, the badge. The columns line up
     at any width; when the drawer is narrow the actions and the badge move under the field name. */
  .frow { display: grid; grid-template-columns: 1.4rem minmax(0, 1fr) auto auto; gap: var(--s-1) var(--s-3); align-items: baseline; padding-bottom: var(--s-2); border-bottom: 1px solid var(--border); }
  .frow:last-child { border-bottom: 0; padding-bottom: 0; }
  .pick { margin: 0; align-self: center; }
  .what { min-width: 0; overflow-wrap: anywhere; }
  .acts { display: inline-flex; gap: var(--s-1); align-items: baseline; flex-wrap: wrap; }
  .acts code { white-space: nowrap; }
  .tag { justify-self: end; }
  .note { grid-column: 2 / -1; }
  @container (max-width: 34rem) {
    .frow { grid-template-columns: 1.4rem minmax(0, 1fr); }
    .acts { grid-column: 2; }
    .tag { grid-column: 2; justify-self: start; }
    .tag:empty { display: none; }
  }
  .who p { margin: var(--s-1) 0 0; }
</style>
