<script lang="ts">
  // Scenario presets saved in the console (formerly the "Scenari mock" page): they go into the next pack that
  // "Prepara e avvia il mock" builds, and from there into the mock (Session tab). The commands below drive a mock
  // by hand (curl), for tests that set up their session themselves.
  import InfoTip from '../InfoTip.svelte';
  import Card from '../Card.svelte';
  import Button from '../Button.svelte';
  import Badge from '../Badge.svelte';
  import Modal from '../Modal.svelte';
  import Switch from '../Switch.svelte';
  import CodeBlock from '../CodeBlock.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import Loading from '../Loading.svelte';
  import { t } from '../../lib/i18n/index.svelte';
  import { api } from '../../lib/api';
  import type { FaultSetting, ScenarioPreset } from '../../lib/api';
  import { resource } from '../../lib/resource.svelte';
  import { can, toast, toastError } from '../../lib/stores.svelte';
  import { fmtPct } from '../../lib/format';
  import { scopeGroups } from '../../lib/scope.svelte';

  let { baseUrl = 'http://localhost:8480' }: { baseUrl?: string } = $props();
  const uid = $props.id();

  const presets = resource(() => api.scenarios.list());
  // The operations of the Group/Team filter. A preset names a service and an operation (no group): the same
  // operation of two groups is offered once.
  const opsAll = resource(() => api.contracts.operations(undefined, scopeGroups()));
  const ops = {
    get data() {
      return opsAll.data?.filter((o, i, all) => all.findIndex((x) => x.service === o.service && x.op === o.op) === i);
    },
  };

  let selectedId = $state('sc-observed');
  const selected = $derived(presets.data?.find((p) => p.id === selectedId) ?? presets.data?.[0] ?? null);
  let seed = $state(42);

  let editOpen = $state(false);
  let draft = $state<ScenarioPreset | null>(null);
  let delOpen = $state(false);

  // The control API by hand (api/control-api.v1.openapi.yaml), as a test would do it: TT_CONTROL_TOKEN is the
  // control token of the mock, the session header selects the session.
  const commands = $derived.by(() => {
    const p = selected;
    if (!p) return '';
    const base = baseUrl;
    const c = `curl -s -H "Authorization: Bearer $TT_CONTROL_TOKEN" -H 'Content-Type: application/json'`;
    const lines = [`# ${t('mk.cmd.session')}`, `SESSION=$(${c} -X POST ${base}/__tt/sessions -d '{"seed": ${seed}}' | jq -r .id)`];
    if (p.deterministic && !p.faults.length) lines.push('', `# ${t('mk.cmd.faultsOff')}`, `${c} -X PUT ${base}/__tt/sessions/$SESSION/faults -d '{"mode": "off"}'`);
    if (p.faults.length) {
      const body = { mode: 'custom', rules: p.faults.map((f) => ({ service: f.service, op: f.op, status: f.status, p: f.p })) };
      lines.push('', `# ${t('mk.cmd.faults')}`, `${c} -X PUT ${base}/__tt/sessions/$SESSION/faults -d '${JSON.stringify(body)}'`);
    }
    for (const o of p.forcedOutcomes) lines.push('', `# ${t('mk.cmd.outcome', { rule: o.rule })}`, `${c} -X POST ${base}/__tt/sessions/$SESSION/scenario -d '{"rule": "${o.rule}", "outcome": "${o.outcome}"}'`);
    if (p.clockAdvance) lines.push('', `# ${t('mk.cmd.clock')}`, `${c} -X POST ${base}/__tt/sessions/$SESSION/clock/advance -d '{"by": "${p.clockAdvance}"}'`);
    lines.push('', `# ${t('mk.cmd.then')}`, '#   X-TT-Session: $SESSION');
    return lines.join('\n');
  });

  function startEdit(base?: ScenarioPreset): void {
    draft = base
      ? { ...structuredClone($state.snapshot(base)), id: base.builtin ? '' : base.id, builtin: false, name: base.builtin ? `${base.name} (copia)` : base.name }
      : { id: '', name: '', description: '', builtin: false, faults: [], forcedOutcomes: [], deterministic: true };
    editOpen = true;
  }
  function addFault(): void {
    const first = ops.data?.[0];
    draft?.faults.push({ service: first?.service ?? '', op: first?.op ?? '', status: 503, p: 0.5 } satisfies FaultSetting);
  }
  async function save(): Promise<void> {
    if (!draft) return;
    try {
      const saved = await api.scenarios.save($state.snapshot(draft) as ScenarioPreset);
      toast(t('sc.saved'));
      editOpen = false;
      selectedId = saved.id;
      presets.reload();
    } catch (e) {
      toastError(e);
    }
  }
  async function remove(): Promise<void> {
    if (!selected) return;
    await api.scenarios.remove(selected.id);
    toast(t('sc.deleted'));
    selectedId = 'sc-observed';
    presets.reload();
  }
</script>

<div class="head">
  <p class="subtle">{t('mk.saved.intro')}</p>
  <Button variant="primary" icon="plus" denied={!can('scenarios.edit')} onclick={() => startEdit()}>{t('sc.new')}</Button>
</div>

{#if presets.data}
  <div class="grid presets" role="radiogroup" aria-label={t('sc.title')}>
    {#each presets.data as p (p.id)}
      <button type="button" role="radio" aria-checked={selected?.id === p.id} class="card" class:sel={selected?.id === p.id} onclick={() => (selectedId = p.id)}>
        <span class="row-tight spread"><b>{p.name}</b>{#if p.builtin}<Badge>{t('sc.builtin')}</Badge>{:else}<Badge tone="accent">{t('sc.custom')}</Badge>{/if}</span>
        <span class="muted">{p.description}</span>
        <span class="tags">
          {#if p.deterministic}<Badge tone="info">{t('sc.deterministic')}</Badge>{/if}
          {#if p.faults.length}<Badge tone="warning">{t('sc.nFaults', { n: p.faults.length })}</Badge>{/if}
          {#if p.forcedOutcomes.length}<Badge tone="accent">{t('sc.nOutcomes', { n: p.forcedOutcomes.length })}</Badge>{/if}
        </span>
      </button>
    {/each}
  </div>

  {#if selected}
    <div class="gap"></div>
    <div class="grid-2">
      <Card title={selected.name}>
        {#snippet actions()}
          <Button size="sm" denied={!can('scenarios.edit')} onclick={() => startEdit(selected)}>{selected.builtin ? t('sc.duplicate') : t('common.edit')}</Button>
          {#if !selected.builtin}<Button size="sm" variant="danger" denied={!can('scenarios.edit')} onclick={() => (delOpen = true)}>{t('common.delete')}</Button>{/if}
        {/snippet}
        <div class="stack">
          <p class="muted">{selected.description}</p>
          <div>
            <h3 class="fs-4">{t('sc.faults')} <InfoTip id="sc.faults" /></h3>
            {#if selected.faultsIgnored}<p class="callout warn" role="status">{t('fix4.sc.legacyOff')}</p>{/if}
            {#if selected.faults.length}
              <ul class="list">{#each selected.faults as f, i (i)}<li><code>{f.op}</code> <span class="subtle">({f.service})</span> → <Badge tone="danger">{f.status}</Badge> {fmtPct(f.p, 0)}</li>{/each}</ul>
            {:else}<p class="subtle">{selected.deterministic ? t('sc.noFaultsOff') : t('sc.noFaultsObserved')}</p>{/if}
          </div>
          <div>
            <h3 class="fs-4">{t('sc.outcomes')} <InfoTip id="sc.forced" /></h3>
            {#if selected.forcedOutcomes.length}
              <ul class="list">{#each selected.forcedOutcomes as o (o.rule)}<li><code>{o.rule}</code> → <b>{o.outcome}</b></li>{/each}</ul>
            {:else}<p class="subtle">{t('sc.noOutcomes')}</p>{/if}
          </div>
          {#if selected.clockAdvance}<p><b>{t('sc.clock')}:</b> <InfoTip id="sc.clock" /> +{selected.clockAdvance}</p>{/if}
        </div>
      </Card>
      <Card title={t('sc.apply')} subtitle={t('sc.applyHint')}>
        <div class="stack">
          <div class="stack-sm">
            <label for="sc-seed">{t('sc.seed')}</label>
            <input id="sc-seed" type="number" min="0" bind:value={seed} class="narrow" />
          </div>
          <CodeBlock code={commands} title={t('sc.commands')} language="bash" maxHeight="20rem" />
        </div>
      </Card>
    </div>
  {/if}
{:else}
  <Loading error={presets.error} onretry={presets.reload} />
{/if}

<Modal bind:open={editOpen} title={draft?.id ? t('sc.editTitle') : t('sc.new')}>
  {#if draft}
    <div class="stack">
      <div class="stack-sm"><label for="sc-n">{t('sc.name')}</label><input id="sc-n" bind:value={draft.name} /></div>
      <div class="stack-sm"><label for="sc-d">{t('sc.descr')}</label><textarea id="sc-d" bind:value={draft.description} rows="2"></textarea></div>
      <div class="stack-sm">
        <div class="row-tight"><Switch bind:checked={draft.deterministic} label={t('sc.deterministicLong')} /><InfoTip id="sc.deterministic" /></div>
        <p class="subtle">{t('fix4.sc.deterministicHint')}</p>
      </div>
      <div class="stack-sm">
        <h3 class="fs-4">{t('sc.faults')} <InfoTip id="sc.faults" /></h3>
        {#if draft.faults.length}
          <div class="fault head" aria-hidden="true"><span>{t('sc.operation')}</span><span>{t('fix4.sc.status')}</span><span>{t('fix4.sc.p')}</span><span></span></div>
        {/if}
        {#each draft.faults as f, i (i)}
          <div class="fault">
            <select id="{uid}-op-{i}" aria-label={t('sc.operation')} value={`${f.service}|${f.op}`} onchange={(e) => { const [s, o] = e.currentTarget.value.split('|'); f.service = s; f.op = o; }}>
              {#each ops.data ?? [] as o, j (j)}<option value={`${o.service}|${o.op}`}>{o.service} · {o.op}</option>{/each}
            </select>
            <label class="num-f"><span class="sr-only">{t('fix4.sc.status')}</span><input type="number" min="100" max="599" bind:value={f.status} class="st" /></label>
            <label class="num-f"><span class="sr-only">{t('fix4.sc.p')}</span><input type="number" min="0" max="1" step="0.05" bind:value={f.p} class="st" /></label>
            <Button size="sm" variant="ghost" icon="trash" onclick={() => draft?.faults.splice(i, 1)} aria-label={t('common.delete')}>{''}</Button>
          </div>
        {/each}
        <div><Button size="sm" icon="plus" onclick={addFault}>{t('sc.addFault')}</Button></div>
      </div>
    </div>
  {/if}
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (editOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" disabled={!draft?.name.trim()} onclick={save}>{t('common.save')}</Button>
  {/snippet}
</Modal>

<ConfirmDialog bind:open={delOpen} title={t('sc.deleteTitle')} message={t('sc.deleteMsg')} confirmLabel={t('common.delete')} onconfirm={remove} />

<style>
  .head { display: flex; gap: var(--s-3); align-items: center; justify-content: space-between; flex-wrap: wrap; margin-bottom: var(--s-3); }
  .presets { grid-template-columns: repeat(auto-fill, minmax(min(100%, 17rem), 1fr)); }
  .card { text-align: left; display: flex; flex-direction: column; gap: var(--s-2); font: inherit; color: var(--fg); background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-md); padding: var(--s-4); cursor: pointer; }
  .card:hover { border-color: var(--accent); }
  .card.sel { border-color: var(--accent); background: var(--accent-soft); box-shadow: 0 0 0 1px var(--accent); }
  .tags { display: flex; gap: var(--s-1); flex-wrap: wrap; }
  .gap { height: var(--s-5); }
  .list { margin: var(--s-1) 0 0; padding-left: 1.1rem; display: flex; flex-direction: column; gap: 4px; }
  .narrow { max-width: 9rem; }
  .fault { display: grid; grid-template-columns: minmax(0, 1fr) 6rem 7rem auto; gap: var(--s-2); align-items: center; }
  .fault.head { font-size: 0.78rem; font-weight: 600; color: var(--fg-subtle); }
  .num-f { display: block; }
  .num-f input { width: 100%; }
  .st { padding-inline: 0.4rem; }
</style>
