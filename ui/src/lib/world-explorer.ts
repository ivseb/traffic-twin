// World explorer: turns the lines of world.jsonl about one customer (GET /worlds/{id}/customers/{cid}) into the
// entities and state timelines the page shows. Pure, so it is unit-tested.
import type { WorldCustomerDetail, WorldEntity, WorldStep } from './api/types';

type Line = Record<string, unknown>;

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function customerDetailOf(customerId: string, lines: Line[]): WorldCustomerDetail {
  const customer = lines.find((l) => l.type === 'customer');
  const profile = (customer?.profile ?? {}) as Line;
  const entities = new Map<string, WorldEntity>();
  for (const l of lines) {
    if (l.type !== 'entity' || typeof l.id !== 'string') continue;
    entities.set(`${str(l.entity)}\u0000${l.id}`, { id: l.id, entity: str(l.entity), state: (l.state ?? {}) as Record<string, unknown>, steps: [] });
  }
  for (const l of lines) {
    if (l.type !== 'history' || typeof l.id !== 'string') continue;
    const e = entities.get(`${str(l.entity)}\u0000${l.id}`);
    if (!e) continue;
    const state = (l.state ?? {}) as Record<string, unknown>;
    const step: WorldStep = { at: str(l.at), seq: typeof l.seq === 'number' ? l.seq : 0, status: str(state.status) };
    if (typeof l.rule_id === 'string') step.rule = l.rule_id;
    if (typeof l.outcome === 'string') step.outcome = l.outcome;
    e.steps.push(step);
  }
  const list = [...entities.values()];
  for (const e of list) e.steps.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.seq - b.seq));
  // Order first, then what the rules created from it, then the rest by id.
  const rank = (e: WorldEntity) => (e.steps[0]?.rule ? 1 : 0);
  list.sort((a, b) => rank(a) - rank(b) || a.entity.localeCompare(b.entity) || a.id.localeCompare(b.id));
  return { id: customerId, name: str(profile.name), email: str(profile.email), archetype: str(customer?.archetype), entities: list };
}

/** Distinct statuses an entity went through, in order, with consecutive repeats folded ("CREATED → PAID → SHIPPED"). */
export function statusPath(e: WorldEntity): string[] {
  const out: string[] = [];
  for (const s of e.steps) if (s.status && out[out.length - 1] !== s.status) out.push(s.status);
  return out;
}

/** "order 2 · shipment 2" for a customer row. */
export function entitiesLabel(entities: Record<string, number>): string {
  return Object.entries(entities)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${k} ${n}`)
    .join(' · ');
}
