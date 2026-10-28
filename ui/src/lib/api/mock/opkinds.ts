// In-memory operation kinds for the demo build and the tests (rules v1.6): one POST of the demo shop is a search the
// miner classified as a read from the traffic.

import { ApiError, type Permission, type User } from '../types';
import type { OpKindDecision, OpKinds, OpKindsApi } from '../opkinds';
import { permissionsOf } from '../../rbac';

export interface DemoOpKindDeps {
  authed(): User;
  audit(actor: string, action: string, target: string): void;
  now(): number;
  wait(): Promise<void>;
}

function need(d: DemoOpKindDeps, perms: Permission[]): User {
  const u = d.authed();
  const have = permissionsOf(u.roles);
  if (!perms.some((p) => have.has(p))) throw new ApiError('forbidden', `Permesso mancante: ${perms.join(' / ')}`, 403);
  return u;
}

export function createDemoOpKinds(d: DemoOpKindDeps): OpKindsApi {
  const decisions = new Map<string, OpKindDecision>();
  const key = (g: string, s: string, o: string) => `${g}\u0000${s}\u0000${o}`;
  const auto: OpKinds['auto'] = [{ group: 'demo', service: 'shop-api', op: 'POST /carts/{id}/items' }];
  return {
    async list(group) {
      await d.wait();
      need(d, ['rules.review', 'rules.edit', 'audit.view', 'rules.mine']);
      const keep = (g: string) => !group || g === group;
      return { decisions: [...decisions.values()].filter((x) => keep(x.group)).map((x) => ({ ...x })), auto: auto.filter((a) => keep(a.group)) };
    },
    async set(group, service, op, choice) {
      await d.wait();
      const u = need(d, ['rules.review']);
      const k = key(group, service, op);
      if (choice === 'auto') decisions.delete(k);
      else decisions.set(k, { group, service, op, read: choice === 'read', setBy: u.username, setAt: new Date(d.now()).toISOString() });
      d.audit(u.username, 'rule.op_kind_set', `${service} ${op}`);
    },
  };
}
