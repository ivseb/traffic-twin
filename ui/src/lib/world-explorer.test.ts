import { describe, expect, it } from 'vitest';
import { customerDetailOf, entitiesLabel, statusPath } from './world-explorer';

describe('world explorer parsing', () => {
  it('joins entities with their history and orders operations before rule-created entities', () => {
    const d = customerDetailOf('CUS-SYN-0003', [
      { type: 'customer', id: 'CUS-SYN-0003', archetype: 'arch-01', profile: { name: 'Elena Galli', email: 'elena@example.com' } },
      { type: 'entity', entity: 'shipment', id: 'SHP-SYN-0003', state: { status: 'IN_TRANSIT' } },
      { type: 'entity', entity: 'order', id: 'ORD-SYN-0003', state: { status: 'PAID' } },
      { type: 'history', entity: 'shipment', id: 'SHP-SYN-0003', seq: 1, at: '2026-10-19T10:00:00Z', state: { status: 'CREATED' }, rule_id: 'r-0007' },
      { type: 'history', entity: 'shipment', id: 'SHP-SYN-0003', seq: 2, at: '2026-10-19T12:00:00Z', state: { status: 'IN_TRANSIT' }, rule_id: 'r-0007' },
      { type: 'history', entity: 'order', id: 'ORD-SYN-0003', seq: 1, at: '2026-10-19T09:00:00Z', state: { status: 'PAID' } },
      { type: 'history', entity: 'order', id: 'ORD-OTHER', seq: 1, at: '2026-10-19T09:00:00Z', state: { status: 'X' } },
    ]);
    expect(d).toMatchObject({ id: 'CUS-SYN-0003', name: 'Elena Galli', email: 'elena@example.com', archetype: 'arch-01' });
    expect(d.entities.map((e) => e.id)).toEqual(['ORD-SYN-0003', 'SHP-SYN-0003']);
    expect(d.entities[1].steps.map((s) => s.status)).toEqual(['CREATED', 'IN_TRANSIT']);
  });

  it('tolerates a customer line that is missing and history without an entity', () => {
    const d = customerDetailOf('CUS-SYN-0009', [{ type: 'history', entity: 'order', id: 'ORD-1', seq: 1, at: 'x', state: {} }]);
    expect(d).toEqual({ id: 'CUS-SYN-0009', name: '', email: '', archetype: '', entities: [] });
  });

  it('folds repeated statuses in the path', () => {
    const e = { id: 'A', entity: 'order', state: {}, steps: ['CREATED', 'CREATED', 'PAID', 'PAID', 'SHIPPED'].map((status, i) => ({ at: `2026-10-19T0${i}:00:00Z`, seq: i, status })) };
    expect(statusPath(e)).toEqual(['CREATED', 'PAID', 'SHIPPED']);
    expect(statusPath({ ...e, steps: [] })).toEqual([]);
  });

  it('writes the entities of a customer row', () => {
    expect(entitiesLabel({ shipment: 2, order: 3 })).toBe('order 3 · shipment 2');
    expect(entitiesLabel({})).toBe('');
  });
});
