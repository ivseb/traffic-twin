// The 4-step journey of the console: Collega -> Osserva -> Rivedi -> Usa il mock.
// Pure: given a few counts it says where the user is and what to do next (Home page, tested).
import type { MsgKey } from './i18n/index.svelte';

export type StepId = 'connect' | 'observe' | 'review' | 'mock';
export const STEP_IDS: readonly StepId[] = ['connect', 'observe', 'review', 'mock'];

/** Counts the home page collects. `null`: not known (the role cannot read it, or the call failed). */
export interface JourneyFacts {
  sources: number | null;
  services: number | null;
  /** Operations seen across the services: the contracts exist from the first one. */
  operations: number | null;
  openAlerts: number | null;
  openQuarantine: number | null;
  gaps: number | null;
  packsPublished: number | null;
}

export type StepStatus = 'done' | 'current' | 'todo';

export interface JourneyStep {
  id: StepId;
  status: StepStatus;
  /** Where the step starts. */
  href: string;
  /** One line about the state of the step. */
  summary: { key: MsgKey; params?: Record<string, number> };
}

export interface NextAction {
  step: StepId;
  /** Title of the suggestion (what to do) and why. */
  title: MsgKey;
  why: MsgKey;
  params?: Record<string, number>;
  href: string;
  /** Label of the button. */
  cta: MsgKey;
}

export interface Journey {
  steps: JourneyStep[];
  current: StepId | null;
  next: NextAction;
}

const n = (v: number | null): number => v ?? 0;

export function journeyOf(f: JourneyFacts): Journey {
  const connected = n(f.sources) > 0;
  const observed = connected && n(f.services) > 0 && n(f.operations) > 0;
  const toReview = n(f.openAlerts) + n(f.openQuarantine) + n(f.gaps);
  const reviewed = observed && toReview === 0;
  const mockReady = n(f.packsPublished) > 0;

  const done: Record<StepId, boolean> = { connect: connected, observe: observed, review: reviewed, mock: mockReady };
  // The current step is the first one not done; the later ones are "todo" (even if their data exist: the mock can be
  // started before the review is over, the home page only says what comes first).
  const current = STEP_IDS.find((s) => !done[s]) ?? null;
  const status = (s: StepId): StepStatus => (done[s] ? 'done' : s === current ? 'current' : 'todo');

  const summary = (s: StepId): JourneyStep['summary'] => {
    switch (s) {
      case 'connect':
        return connected ? { key: 'journey.sum.connect.done', params: { n: n(f.sources) } } : { key: 'journey.sum.connect.todo' };
      case 'observe':
        if (!connected) return { key: 'journey.sum.observe.wait' };
        return observed ? { key: 'journey.sum.observe.done', params: { services: n(f.services), ops: n(f.operations) } } : { key: 'journey.sum.observe.empty' };
      case 'review':
        if (!observed) return { key: 'journey.sum.review.wait' };
        return toReview === 0
          ? { key: 'journey.sum.review.clean' }
          : { key: 'journey.sum.review.items', params: { alerts: n(f.openAlerts), quarantine: n(f.openQuarantine), gaps: n(f.gaps) } };
      case 'mock':
        return mockReady ? { key: 'journey.sum.mock.done', params: { n: n(f.packsPublished) } } : { key: 'journey.sum.mock.todo' };
    }
  };

  const steps: JourneyStep[] = STEP_IDS.map((id) => ({ id, status: status(id), href: STEP_HREF[id], summary: summary(id) }));
  return { steps, current, next: nextAction(current, f, toReview) };
}

export const STEP_HREF: Record<StepId, string> = { connect: '#/onboarding', observe: '#/services', review: '#/contracts', mock: '#/mock' };

function nextAction(current: StepId | null, f: JourneyFacts, toReview: number): NextAction {
  switch (current) {
    case 'connect':
      return { step: 'connect', title: 'journey.next.connect.title', why: 'journey.next.connect.why', href: '#/onboarding', cta: 'journey.next.connect.cta' };
    case 'observe':
      return { step: 'observe', title: 'journey.next.observe.title', why: 'journey.next.observe.why', href: '#/sources', cta: 'journey.next.observe.cta' };
    case 'review': {
      // The most urgent thing first: an incompatible change reaches the alerts, then the quarantine, then the gaps.
      const href = n(f.openAlerts) > 0 ? '#/alerts' : n(f.openQuarantine) > 0 ? '#/quarantine' : '#/gaps';
      return { step: 'review', title: 'journey.next.review.title', why: 'journey.next.review.why', params: { count: toReview }, href, cta: 'journey.next.review.cta' };
    }
    case 'mock':
      return { step: 'mock', title: 'journey.next.mock.title', why: 'journey.next.mock.why', href: '#/mock', cta: 'journey.next.mock.cta' };
    default:
      return { step: 'mock', title: 'journey.next.done.title', why: 'journey.next.done.why', href: '#/mock', cta: 'journey.next.done.cta' };
  }
}
