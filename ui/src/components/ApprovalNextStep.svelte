<script lang="ts">
  // «Prossimo passo: fai approvare i valori in chiaro» (usability test #4, B1). A draft of the group opens values
  // (status and categories in clear, amounts in buckets) and waits for approvals: without it there are no rules with
  // states, no linked fields and the mock answers static values. Who can approve, a message to send them with the
  // link to the draft, and what is lost meanwhile. Shown by the wizard («In ascolto») and the Panoramica.
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import ApproverHelp from './ApproverHelp.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import type { PolicyVersion } from '../lib/api';
  import { href } from '../lib/router';
  import WithdrawDraft from './WithdrawDraft.svelte';
  import { session } from '../lib/stores.svelte';
  import { openedFieldsOf, type StatesFacts } from '../lib/codes';

  // `facts`: where the statuses already come out as codes (no approval) and whether rules with states exist. The card
  // must not say «fai approvare i valori in chiaro, senza non ci sono regole con stati» then (usability test #5, M3).
  let { drafts, required = 2, capturing, facts, onchange }: { drafts: PolicyVersion[]; required?: number; capturing?: number; facts?: StatesFacts; onchange?: () => void } = $props();
  const inClear = $derived(!!facts?.inClear);
  const fieldList = (f: string[]) => f.slice(0, 5).join(', ') + (f.length > 5 ? '…' : '');

  const mine = (n?: string) => !!n && (n === session.user?.username || n === session.user?.displayName);
</script>

{#if drafts.length}
  <Card title={inClear ? t('fix5.next.titleOther') : t('fix4.next.title')} tone="accent">
    <div class="stack" data-testid="approval-next-step">
      {#if capturing}<p class="callout ok" role="status">{t('fix4.wiz.capturing', { v: capturing })}</p>{/if}
      {#each drafts as d (`${d.policyId}@${d.version}`)}
        <div class="stack-sm draft">
          <p>
            <b>{t('fix4.next.draft', { policy: d.policyId, v: d.version, group: (d.groups ?? []).join(', ') || '—', n: d.approvalsRequired || required, have: d.approvals.length })}</b>
          </p>
          {#if mine(d.proposedBy)}<p class="subtle">{t('fix4.next.self')}</p>{/if}
          {#if inClear}
            {@const opened = openedFieldsOf(d)}
            <p class="callout ok" role="status" data-testid="states-in-clear">{facts!.lifecycle ? t('fix5.next.statesOk', { fields: fieldList(facts!.fields) }) : t('fix5.next.statesOkNoRules', { fields: fieldList(facts!.fields) })}</p>
            <p data-testid="draft-opens">{opened.length ? t('fix5.next.opens', { fields: fieldList(opened) }) : t('fix5.next.opensN', { n: d.valueReasons.length || 1 })}</p>
          {/if}
          <ApproverHelp version={d} {required} fields={inClear ? openedFieldsOf(d) : undefined} />
          <div><WithdrawDraft version={d} size="md" onchange={() => onchange?.()} /></div>
          <div><Button size="sm" icon="arrowRight" href={href('/sources', {}, { tab: 'policy', draft: `${d.policyId}@${d.version}` })}>{t('fix4.next.open')}</Button></div>
        </div>
      {/each}
      {#if !inClear}
        <div>
          <p class="lose"><b>{t('fix4.next.lose')}</b></p>
          <ul class="lose">
            <li>{t('fix4.next.lose1')}</li>
            <li>{t('fix4.next.lose2')}</li>
            <li>{t('fix4.next.lose3')}</li>
          </ul>
        </div>
      {/if}
    </div>
  </Card>
{/if}

<style>
  .draft { border-left: 4px solid var(--warning); padding-left: var(--s-3); }
  .draft p { margin: 0; }
  .lose { margin: 0; }
  ul.lose { padding-left: 1.2rem; }
</style>
