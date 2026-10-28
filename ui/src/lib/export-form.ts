// Helpers of the event-export form (Export page): the services to choose from and the quick date ranges.
import type { ServiceInfo } from './api/types';

/** Names of the services to offer in the dropdown: one per name (the same service in two groups is one choice), sorted. */
export function exportServices(list: readonly Pick<ServiceInfo, 'name'>[]): string[] {
  return [...new Set(list.map((s) => s.name))].sort((a, b) => a.localeCompare(b));
}

/** A Date as the value of an `<input type="datetime-local">` (local time, minutes). */
export function localInput(d: Date): string {
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

/** The range "the last `hours` hours" ending now, as datetime-local values. */
export function rangeFromNow(hours: number, now: Date): { from: string; to: string } {
  return { from: localInput(new Date(now.getTime() - hours * 3600_000)), to: localInput(now) };
}
