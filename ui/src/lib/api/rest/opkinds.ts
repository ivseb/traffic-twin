// REST implementation of the operation kinds (admin-api 1.20.0, /api/v1/rules/op-kinds).

import type { OpKinds, OpKindsApi } from '../opkinds';
import type { Http } from './http';

export interface WireOpKinds {
  decisions?: { group?: string; service: string; op: string; read: boolean; set_by?: string; set_at?: string }[];
  auto?: { group?: string; service: string; op: string; read?: boolean }[];
}

export function mapOpKinds(w: WireOpKinds | null | undefined): OpKinds {
  return {
    decisions: (w?.decisions ?? []).map((d) => ({ group: d.group ?? '', service: d.service, op: d.op, read: !!d.read, setBy: d.set_by ?? '', setAt: d.set_at ?? '' })),
    auto: (w?.auto ?? []).filter((a) => a.read !== false).map((a) => ({ group: a.group ?? '', service: a.service, op: a.op })),
  };
}

export function createOpKindsRest(http: Http): OpKindsApi {
  return {
    async list(group) {
      return mapOpKinds(await http.get<WireOpKinds>('/api/v1/rules/op-kinds', { query: { group: group || undefined } }));
    },
    async set(group, service, op, choice) {
      const read = choice === 'auto' ? null : choice === 'read';
      await http.put<unknown>('/api/v1/rules/op-kinds', { ...(group ? { group } : {}), service, op, read });
    },
  };
}
