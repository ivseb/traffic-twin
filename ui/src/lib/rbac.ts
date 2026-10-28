import type { Permission, Role, User } from './api/types';

// Display-only copy of the role model of tt-core (internal/auth/roles.go and the
// x-tt-roles of the admin API). The roles other than admin are flat and none
// implies another. admin is the superuser: it implies every role, so it holds
// every permission and sees every page and action. What an admin does in place
// of another role is not refused but traced by the server (audit
// authz.admin_override, alerts; docs/spec/policy.md §5). The server is
// authoritative: this just decides what to show or disable.
const ADMIN_OWN: Permission[] = ['users.manage', 'settings.edit', 'webhooks.manage', 'override.admin', 'store.manage'];
const OTHER_ROLES: Record<Exclude<Role, 'admin'>, Permission[]> = {
  operator: ['sources.manage', 'sources.kill', 'policy.propose', 'worlds.generate', 'publish.build', 'scenarios.edit', 'alerts.manage', 'rules.mine', 'hosts.twin'],
  'rule-reviewer': ['rules.edit', 'rules.review', 'alerts.manage'],
  'policy-approver': ['policy.propose', 'policy.approve', 'quarantine.resolve'],
  publisher: ['publish.run', 'publish.download'],
  auditor: ['audit.view'],
  'event-exporter': ['events.export'],
};

/** Every permission of the UI (what an admin holds). */
export const ALL_PERMISSIONS: Permission[] = [...new Set([...ADMIN_OWN, ...Object.values(OTHER_ROLES).flat()])];

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = { admin: ALL_PERMISSIONS, ...OTHER_ROLES };

export const ALL_ROLES = Object.keys(ROLE_PERMISSIONS) as Role[];

export function permissionsOf(roles: readonly Role[]): Set<Permission> {
  const out = new Set<Permission>();
  for (const r of roles) for (const p of ROLE_PERMISSIONS[r] ?? []) out.add(p);
  return out;
}

export function userCan(user: Pick<User, 'roles'> | null | undefined, perm: Permission): boolean {
  if (!user) return false;
  return permissionsOf(user.roles).has(perm);
}

/** Whether user holds admin: its approvals and releases are the admin override (reason, alert). */
export function isAdmin(user: Pick<User, 'roles'> | null | undefined): boolean {
  return !!user && user.roles.includes('admin');
}
