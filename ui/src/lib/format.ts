import { locale, t } from './i18n/index.svelte';

export function fmtNum(n: number, opts?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(locale(), opts).format(n);
}

/** A rate (events per minute): at most one decimal, so "584,9" never reads as a thousands separator. */
export function fmtRate(n: number): string {
  return fmtNum(n, { maximumFractionDigits: n >= 100 ? 0 : 1 });
}

export function fmtPct(x: number, digits = 1): string {
  return new Intl.NumberFormat(locale(), { style: 'percent', maximumFractionDigits: digits }).format(x);
}

export function fmtDate(iso: string, withTime = true): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale(), withTime ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' }).format(d);
}

/** "14:05": the time of day only (the date when it is not today). */
export function fmtTime(iso: string, now: number = Date.now()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const today = new Date(now).toDateString() === d.toDateString();
  return new Intl.DateTimeFormat(locale(), today ? { hour: '2-digit', minute: '2-digit' } : { dateStyle: 'medium', timeStyle: 'short' }).format(d);
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${fmtNum(n / 1024, { maximumFractionDigits: 1 })} KB`;
  return `${fmtNum(n / 1024 / 1024, { maximumFractionDigits: 1 })} MB`;
}

/** "12 s fa" / "3 min fa" / "2 h fa". */
export function fmtAgo(iso: string, now: number = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return t('time.ago.s', { n: s });
  if (s < 3600) return t('time.ago.m', { n: Math.round(s / 60) });
  if (s < 86400) return t('time.ago.h', { n: Math.round(s / 3600) });
  return t('time.ago.d', { n: Math.round(s / 86400) });
}

export function ageSeconds(iso: string, now: number = Date.now()): number {
  return Math.max(0, (now - new Date(iso).getTime()) / 1000);
}

/** Parses figurative delays like "5m", "4h", "2d" into seconds; null when invalid. */
export function parseAfter(s: string): number | null {
  const m = /^([0-9]+)(s|m|h|d)$/.exec(s.trim());
  if (!m) return null;
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as 's' | 'm' | 'h' | 'd'];
  return Number(m[1]) * mult;
}

export type Range = '1h' | '24h' | '7d' | '30d' | 'all';
export const RANGES: readonly Range[] = ['1h', '24h', '7d', '30d', 'all'];

/** Window length of a time-range preset in ms (Infinity for "all"). */
export function rangeMs(r: Range): number {
  return { '1h': 3600_000, '24h': 86400_000, '7d': 7 * 86400_000, '30d': 30 * 86400_000, all: Infinity }[r];
}

export function inRange(iso: string, r: Range, now: number = Date.now()): boolean {
  return now - new Date(iso).getTime() <= rangeMs(r);
}

export function fmtAfter(s: string): string {
  const m = /^([0-9]+)(s|m|h|d)$/.exec(s.trim());
  if (!m) return s;
  return t(`time.unit.${m[2]}` as 'time.unit.s', { n: Number(m[1]) });
}
