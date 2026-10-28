import { describe, expect, it } from 'vitest';
import { exportServices, localInput, rangeFromNow } from './export-form';

describe('export form', () => {
  it('offers each service name once, sorted, also when two groups call the same host', () => {
    expect(exportServices([{ name: 'shop-api' }, { name: 'shipping-ext' }, { name: 'shop-api' }, { name: 'billing-ext' }])).toEqual(['billing-ext', 'shipping-ext', 'shop-api']);
    expect(exportServices([])).toEqual([]);
  });
  it('writes datetime-local values with minutes and no timezone suffix', () => {
    expect(localInput(new Date(2026, 9, 25, 9, 5, 59))).toBe('2026-10-25T09:05');
  });
  it('computes "the last N hours" ending at the given moment', () => {
    const now = new Date(2026, 5, 15, 12, 0, 0);
    expect(rangeFromNow(24, now)).toEqual({ from: '2026-06-14T12:00', to: '2026-06-15T12:00' });
    expect(rangeFromNow(1, now).from).toBe('2026-06-15T11:00');
  });
});
