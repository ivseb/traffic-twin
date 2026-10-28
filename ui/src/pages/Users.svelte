<script lang="ts">
  import { scrollable } from '../lib/scrollable';
  import PageHeader from '../components/PageHeader.svelte';
  import Card from '../components/Card.svelte';
  import Button from '../components/Button.svelte';
  import Tabs from '../components/Tabs.svelte';
  import Table, { type Column } from '../components/Table.svelte';
  import Badge from '../components/Badge.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon from '../components/Icon.svelte';
  import Loading from '../components/Loading.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t, tk } from '../lib/i18n/index.svelte';
  import { api } from '../lib/api';
  import { ApiError, type Role, type User } from '../lib/api';
  import { resource } from '../lib/resource.svelte';
  import { can, session, toast, toastError } from '../lib/stores.svelte';
  import { ALL_ROLES } from '../lib/rbac';
  import { fmtAgo } from '../lib/format';
  import { queryTab } from '../lib/tabs.svelte';

  const roles = resource(() => api.users.roles());
  const users = resource(async () => (can('users.manage') ? await api.users.list() : []));

  const tabs = queryTab('users', ['users', 'roles']);

  let editOpen = $state(false);
  let target = $state<User | null>(null);
  let selRoles = $state<Role[]>([]);
  let newOpen = $state(false);
  let nu = $state({ username: '', displayName: '', password: '', authMethod: 'local' as 'local' | 'sso', roles: ['auditor'] as Role[] });
  const unsupported = $derived(users.error instanceof ApiError && users.error.code === 'unsupported');

  const cols: Column<User>[] = $derived([
    { key: 'displayName', label: t('users.col.name'), sortable: true },
    { key: 'roles', label: t('users.col.roles'), help: 'users.roles', value: (u) => u.roles.join(',') },
    { key: 'authMethod', label: t('users.col.auth'), sortable: true, hideBelow: 'sm', help: 'users.auth' },
    { key: 'lastLogin', label: t('users.col.last'), hideBelow: 'md', value: (u) => -new Date(u.lastLogin ?? 0).getTime(), sortable: true },
    { key: 'act', label: '' },
  ]);

  function toggle(list: Role[], r: Role, on: boolean): Role[] {
    return on ? [...new Set([...list, r])] : list.filter((x) => x !== r);
  }
  // admin is the superuser (docs/spec/policy.md §5): any combination of roles
  // is allowed and an admin may grant roles to itself; the server traces it
  // (audit, alert for sensitive roles). Only removing your own admin role is
  // refused (409 self_lockout), so the box stays ticked for yourself.
  function roleBlocked(list: readonly Role[], r: Role, self: User | null): boolean {
    return r === 'admin' && list.includes('admin') && !!self && !!session.user && self.id === session.user.id;
  }
  const editSelf = $derived(!!target && !!session.user && target.id === session.user.id);
  function openEdit(u: User): void {
    target = u;
    selRoles = [...u.roles];
    editOpen = true;
  }
  async function saveRoles(): Promise<void> {
    if (!target) return;
    try {
      await api.users.update(target.id, { roles: selRoles });
      toast(t('users.saved'));
      editOpen = false;
      users.reload();
    } catch (e) {
      toastError(e);
    }
  }
  async function setDisabled(u: User, disabled: boolean): Promise<void> {
    try {
      await api.users.update(u.id, { disabled });
      toast(t('users.saved'));
      users.reload();
    } catch (e) {
      toastError(e);
    }
  }
  async function revokeSessions(u: User): Promise<void> {
    try {
      await api.users.update(u.id, { revokeSessions: true });
      toast(t('users.revoked'));
    } catch (e) {
      toastError(e);
    }
  }
  async function create(): Promise<void> {
    try {
      await api.users.create({ username: nu.username.trim(), displayName: nu.displayName.trim(), authMethod: nu.authMethod, roles: [...nu.roles], password: nu.authMethod === 'local' ? nu.password : undefined });
      toast(t('users.created'));
      newOpen = false;
      nu = { username: '', displayName: '', password: '', authMethod: 'local', roles: ['auditor'] };
      users.reload();
    } catch (e) {
      toastError(e);
    }
  }
  const PERMS = $derived(roles.data ? [...new Set(roles.data.flatMap((r) => r.permissions))].sort() : []);
</script>

<PageHeader title={t('users.title')} description={t('users.desc')} help="users" breadcrumbs={[{ label: t('nav.users') }]} updatedAt={users.updatedAt} onrefresh={users.reload} refreshing={users.loading}>
  {#snippet actions()}
    <Button variant="primary" icon="plus" denied={!can('users.manage')} onclick={() => (newOpen = true)}>{t('users.new')}</Button>
  {/snippet}
</PageHeader>

<Tabs tabs={[{ id: 'users', label: t('users.tab.users'), count: users.data?.length }, { id: 'roles', label: t('users.tab.roles') }]} bind:value={tabs.value} label={t('users.title')}>
  {#if tabs.value === 'users'}
    {#if !can('users.manage')}
      <Card><EmptyState icon="lock" title={t('users.denied')} description={t('users.deniedHint')} /></Card>
    {:else if users.data}
      <Card flush>
        <Table rows={users.data} columns={cols} rowKey={(u) => u.id} caption={t('users.title')} searchText={(u) => `${u.username} ${u.displayName} ${u.roles.join(' ')}`}>
          {#snippet cell(u, col)}
            {#if col.key === 'displayName'}
              <b>{u.displayName}</b> {#if u.disabled}<StatusPill value="revoked" />{/if}
              <div class="subtle mono">{u.username}</div>
            {:else if col.key === 'roles'}
              <div class="row-tight">{#each u.roles as r (r)}<Badge tone="accent">{tk(`role.${r}`)}</Badge>{/each}</div>
            {:else if col.key === 'authMethod'}
              <Badge>{u.authMethod === 'sso' ? 'SSO' : t('users.local')}</Badge>
            {:else if col.key === 'lastLogin'}
              {u.lastLogin ? fmtAgo(u.lastLogin) : '—'}
            {:else}
              <div class="row-tight">
                <Button size="sm" onclick={() => openEdit(u)}>{t('users.editRoles')}</Button>
                <Button size="sm" variant="ghost" onclick={() => setDisabled(u, !u.disabled)}>{u.disabled ? t('users.enable') : t('users.disable')}</Button>
                <Button size="sm" variant="ghost" onclick={() => revokeSessions(u)}>{t('users.revoke')}</Button>
              </div>
            {/if}
          {/snippet}
        </Table>
      </Card>
    {:else if unsupported}
      <Card><EmptyState icon="lock" title={t('common.unsupportedTitle')} description={t('common.unsupportedHint')} /></Card>
    {:else}<Loading error={users.error} onretry={users.reload} />{/if}
  {:else if roles.data}
    <Card flush>
      <div class="scroll" use:scrollable>
        <table class="matrix">
          <caption class="sr-only">{t('users.tab.roles')}</caption>
          <thead>
            <tr><th scope="col">{t('users.permission')}</th>{#each roles.data as r (r.role)}<th scope="col" class="c">{tk(`role.${r.role}`)}</th>{/each}</tr>
          </thead>
          <tbody>
            {#each PERMS as p (p)}
              <tr>
                <th scope="row"><code>{p}</code><div class="subtle">{tk(`perm.${p}`)}</div></th>
                {#each roles.data as r (r.role)}
                  <td class="c">{#if r.permissions.includes(p)}<span class="yes"><Icon name="check" size={16} label={t('users.granted')} /></span>{:else}<span class="no" aria-label={t('users.notGranted')}>·</span>{/if}</td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </Card>
    <p class="subtle sep">{t('users.separation')}</p>
  {:else}<Loading error={roles.error} />{/if}
</Tabs>

<Modal bind:open={editOpen} title={t('users.editRolesFor', { name: target?.displayName ?? '' })}>
  <fieldset>
    <legend class="sr-only">{t('users.col.roles')}</legend>
    {#each ALL_ROLES as r (r)}
      <label class="chk"><input type="checkbox" checked={selRoles.includes(r)} disabled={roleBlocked(selRoles, r, target)} onchange={(e) => (selRoles = toggle(selRoles, r, e.currentTarget.checked))} /> <span><b>{tk(`role.${r}`)}</b><span class="subtle"> — {tk(`role.${r}.desc`)}</span></span></label>
    {/each}
  </fieldset>
  <p class="subtle">{t('users.sodHint')}</p>
  {#if editSelf}<p class="subtle">{t('users.selfGrantHint')}</p>{/if}
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (editOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" disabled={selRoles.length === 0} onclick={saveRoles}>{t('common.save')}</Button>
  {/snippet}
</Modal>

<Modal bind:open={newOpen} title={t('users.new')}>
  <div class="stack">
    <div class="stack-sm"><label for="nu-u">{t('users.username')}</label><input id="nu-u" bind:value={nu.username} spellcheck="false" autocomplete="off" /></div>
    <div class="stack-sm"><label for="nu-n">{t('users.displayName')}</label><input id="nu-n" bind:value={nu.displayName} /></div>
    <div class="stack-sm">
      <label for="nu-a">{t('users.col.auth')}</label>
      <select id="nu-a" bind:value={nu.authMethod}><option value="local">{t('users.local')}</option><option value="sso">SSO</option></select>
    </div>
    {#if nu.authMethod === 'local'}
      <div class="stack-sm"><label for="nu-p">{t('users.password')}</label><input id="nu-p" type="password" bind:value={nu.password} autocomplete="new-password" /><p class="subtle">{t('users.passwordHint')}</p></div>
    {/if}
    <fieldset>
      <legend>{t('users.col.roles')}</legend>
      {#each ALL_ROLES as r (r)}
        <label class="chk"><input type="checkbox" checked={nu.roles.includes(r)} disabled={roleBlocked(nu.roles, r, null)} onchange={(e) => (nu.roles = toggle(nu.roles, r, e.currentTarget.checked))} /> {tk(`role.${r}`)}</label>
      {/each}
    </fieldset>
    <p class="subtle">{t('users.sodHint')}</p>
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (newOpen = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" disabled={!nu.username.trim() || !nu.displayName.trim() || nu.roles.length === 0 || (nu.authMethod === 'local' && nu.password.length < 12)} onclick={create}>{t('common.create')}</Button>
  {/snippet}
</Modal>

<style>
  .scroll { overflow-x: auto; }
  .matrix { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  .matrix th, .matrix td { padding: 0.55rem var(--s-3); border-top: 1px solid var(--border); text-align: left; }
  .matrix thead th { background: var(--surface-2); font-size: 0.75rem; text-transform: uppercase; color: var(--fg-muted); border-top: 0; }
  .matrix tbody th { font-weight: 500; min-width: 14rem; }
  .c { text-align: center !important; }
  .yes { color: var(--success); }
  .no { color: var(--fg-subtle); }
  .sep { margin-top: var(--s-3); }
  fieldset { border: 1px solid var(--border-strong); border-radius: var(--r-sm); display: flex; flex-direction: column; gap: var(--s-3); padding: var(--s-3); margin: 0; }
  legend { font-weight: 600; font-size: 0.9rem; padding: 0 var(--s-1); }
  .chk { display: flex; align-items: flex-start; gap: var(--s-2); font-weight: 500; }
</style>
