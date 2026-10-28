// The last «Prepara e avvia il mock» of each group, kept in this browser (usability test #4, m4): after a reload the
// Mock page still says how the last preparation went, and follows it again by its job id while it runs. Only the job
// id, the time and the steps (codes, pack id, mock URL) are kept: never a token or a value of the traffic.
import type { PrepareRun } from './api';

const KEY = 'tt.mock.prepare.v1';

export interface KeptPreparation {
  jobId: string;
  /** When the person started it (ISO). */
  at: string;
  run: PrepareRun;
}

// What this tab knows even when the browser storage is unavailable (private window, blocked site data): leaving the Mock
// page and coming back inside the same tab still finds the running job (usability test #5, m7).
const mem = new Map<string, KeptPreparation>();

function readAll(): Record<string, KeptPreparation> {
  try {
    const raw = localStorage.getItem(KEY);
    const v = raw ? (JSON.parse(raw) as unknown) : null;
    return v && typeof v === 'object' ? (v as Record<string, KeptPreparation>) : {};
  } catch {
    return {};
  }
}

const valid = (p: KeptPreparation | undefined): p is KeptPreparation => !!p && typeof p.jobId === 'string' && !!p.jobId && !!p.run && Array.isArray(p.run.steps);

/** The last preparation of `group` started in this browser, if any. */
export function lastPreparation(group: string): KeptPreparation | null {
  const stored = readAll()[group];
  const live = mem.get(group);
  // The newest of the two: the tab's own memory holds the latest steps even when the storage write failed.
  const best = valid(stored) && valid(live) ? (live.at >= stored.at ? live : stored) : valid(live) ? live : valid(stored) ? stored : null;
  return best;
}

/** Forgets what the tab remembers (tests). */
export function forgetPreparations(): void {
  mem.clear();
}

export function rememberPreparation(group: string, run: PrepareRun, at: string): void {
  if (!run.jobId) return;
  const all = readAll();
  all[group] = { jobId: run.jobId, at, run: { ...run, steps: run.steps.map((s) => ({ ...s })) } };
  mem.set(group, all[group]);
  // A few groups at most: the newest twenty.
  const kept = Object.entries(all)
    .sort((a, b) => b[1].at.localeCompare(a[1].at))
    .slice(0, 20);
  try {
    localStorage.setItem(KEY, JSON.stringify(Object.fromEntries(kept)));
  } catch {
    /* storage unavailable: the outcome lasts for this page only */
  }
}
