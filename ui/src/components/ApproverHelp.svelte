<script lang="ts">
  // Who can approve a draft, a link to it and a message to send. A person who cannot approve (or who proposed it and so
  // cannot approve it alone) otherwise sees only «serve un approvatore». The names come from
  // GET /fleet/groups/{group}/approvers (members of the group, admin-api 1.15.0); on an older server only
  // administrators and auditors could read the user list, and everyone else is told «chiedi a un amministratore».
  import CopyButton from './CopyButton.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import type { GroupApprover, PolicyVersion } from '../lib/api';
  import { can, session } from '../lib/stores.svelte';
  import { approverNames, consoleOrigin, draftLink } from '../lib/approval';

  // `fields`: the fields the draft opens, when the statuses already come out as codes (the message then names only those).
  let { version, required = 2, group: groupProp, fields }: { version?: PolicyVersion; required?: number; group?: string; fields?: string[] } = $props();

  let names = $state<string[] | null>(null);
  let adminOnly = $state(false);
  let loaded = $state('');

  const group = $derived(groupProp ?? version?.groups?.[0] ?? '');
  /** The link a colleague opens to see the draft (and approve it): Sorgenti > Policy with its panel open. */
  const link = $derived(version ? draftLink(version, consoleOrigin()) : '');
  const show = $derived(!version || version.status === 'draft');
  const need = $derived(version?.approvalsRequired ?? required);
  const message = $derived(
    version
      ? fields?.length
        ? t('fix5.next.msgTextFields', { policy: version.policyId, v: version.version, group: group || '—', fields: fields.slice(0, 8).join(', '), link })
        : t('fix4.next.msgText', { policy: version.policyId, v: version.version, group: group || '—', link })
      : '',
  );

  async function load(g: string): Promise<void> {
    if (g) {
      try {
        const list: GroupApprover[] = await api.policies.approvers(g);
        const r = approverNames(list);
        names = r.names;
        adminOnly = r.adminOnly;
        return;
      } catch {
        /* an older server, or not a member of the group: the user list below, when readable */
      }
    }
    if (!can('users.manage') && !can('audit.view')) {
      names = null;
      return;
    }
    try {
      const us = await api.users.list();
      names = us.filter((u) => !u.disabled && u.username !== session.user?.username && u.roles.includes('policy-approver')).map((u) => u.displayName || u.username);
      adminOnly = false;
    } catch {
      names = null;
    }
  }

  $effect(() => {
    const key = `${group}`;
    if (!show || loaded === key + '|done') return;
    loaded = key + '|done';
    void load(group);
  });
</script>

{#if show}
  <div class="stack-sm help" data-testid="approver-help">
    <p class="subtle"><b>{t('appr.who')}</b>
      {#if names && names.length}
        {names.join(', ')}{adminOnly ? ` ${t('fix4.appr.adminTag')}` : ''}.
        {t('appr.whoNote', { n: need })}
        {#if !adminOnly && names.length < need}<span data-testid="approvers-fewer">{t('fix5.bulk.fewer', { need, have: names.length })}</span>{/if}
      {:else if names}
        {t('fix4.appr.none')}
      {:else}
        {t('appr.askAdmin')}
      {/if}
    </p>
    {#if version}
      <p class="row subtle">
        <span>{t('appr.link')}</span>
        <code class="link">{link}</code>
        <CopyButton value={link} label={t('appr.copyLink')} />
      </p>
      <details class="msg">
        <summary>{t('fix4.next.message')}</summary>
        <p class="subtle" data-testid="approver-message">{message}</p>
        <CopyButton value={message} label={t('fix4.next.copy')} />
      </details>
    {/if}
  </div>
{/if}

<style>
  .help { border-top: 1px solid var(--border); padding-top: var(--s-2); }
  .row { display: flex; gap: var(--s-2); align-items: center; flex-wrap: wrap; }
  .link { word-break: break-all; font-size: 0.8rem; }
  .msg summary { cursor: pointer; font-weight: 600; font-size: 0.88rem; }
</style>
