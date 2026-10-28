import type { Source, SourceHealth } from './api/types';

/** Seconds without a heartbeat after which a source counts as offline. */
export const OFFLINE_AFTER_S = 300;

export function sourceHealth(s: Pick<Source, 'revoked' | 'killed' | 'lastSeen' | 'problems' | 'dropRatio' | 'state'>, now: number = Date.now()): SourceHealth {
  if (s.revoked) return 'revoked';
  if (s.killed) return 'killed';
  const age = (now - new Date(s.lastSeen).getTime()) / 1000;
  if (age > OFFLINE_AFTER_S) return 'offline';
  // Enrolled, waiting for its first approved policy: nothing is wrong yet.
  if (s.state === 'no_policy' && s.problems.every((p) => p.code === 'no_policy') && s.dropRatio <= 0.05) return 'waiting';
  if (s.problems.length > 0 || s.dropRatio > 0.05 || s.state !== 'capturing') return 'degraded';
  return 'healthy';
}

export function healthCounts(list: Source[], now: number = Date.now()): Record<SourceHealth, number> {
  const out: Record<SourceHealth, number> = { healthy: 0, waiting: 0, degraded: 0, offline: 0, killed: 0, revoked: 0 };
  for (const s of list) out[sourceHealth(s, now)]++;
  return out;
}
