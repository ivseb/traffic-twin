import { describe, expect, it } from 'vitest';
import { journeyOf, STEP_IDS, type JourneyFacts } from './journey';

const none: JourneyFacts = { sources: 0, services: 0, operations: 0, openAlerts: 0, openQuarantine: 0, gaps: 0, packsPublished: 0 };
const statuses = (f: Partial<JourneyFacts>) => journeyOf({ ...none, ...f }).steps.map((s) => s.status);

describe('journey', () => {
  it('lists the four steps in order, each with an entry page', () => {
    const j = journeyOf(none);
    expect(j.steps.map((s) => s.id)).toEqual([...STEP_IDS]);
    expect(j.steps.map((s) => s.href)).toEqual(['#/onboarding', '#/services', '#/contracts', '#/mock']);
  });

  it('starts at Collega on an empty installation', () => {
    expect(statuses({})).toEqual(['current', 'todo', 'todo', 'todo']);
    const j = journeyOf(none);
    expect(j.current).toBe('connect');
    expect(j.next).toMatchObject({ step: 'connect', href: '#/onboarding' });
  });

  it('waits for traffic once a source is connected', () => {
    expect(statuses({ sources: 1 })).toEqual(['done', 'current', 'todo', 'todo']);
    const j = journeyOf({ ...none, sources: 1 });
    expect(j.next).toMatchObject({ step: 'observe', href: '#/sources' });
    expect(j.steps[1].summary.key).toBe('journey.sum.observe.empty');
  });

  it('moves to Rivedi when services and operations have been seen, and points at the most urgent item', () => {
    const base = { sources: 2, services: 3, operations: 12 };
    expect(statuses(base)).toEqual(['done', 'done', 'done', 'current']);
    expect(journeyOf({ ...none, ...base, gaps: 4 }).next).toMatchObject({ step: 'review', href: '#/gaps', params: { count: 4 } });
    expect(journeyOf({ ...none, ...base, gaps: 4, openQuarantine: 1 }).next.href).toBe('#/quarantine');
    expect(journeyOf({ ...none, ...base, gaps: 4, openQuarantine: 1, openAlerts: 2 }).next).toMatchObject({ href: '#/alerts', params: { count: 7 } });
    expect(statuses({ ...base, openAlerts: 2 })).toEqual(['done', 'done', 'current', 'todo']);
  });

  it('suggests the mock when nothing is left to review and ends when a pack is out', () => {
    const base = { sources: 1, services: 2, operations: 8 };
    expect(journeyOf({ ...none, ...base }).next).toMatchObject({ step: 'mock', href: '#/mock', cta: 'journey.next.mock.cta' });
    const all = journeyOf({ ...none, ...base, packsPublished: 1 });
    expect(all.current).toBeNull();
    expect(all.steps.every((s) => s.status === 'done')).toBe(true);
    expect(all.next.title).toBe('journey.next.done.title');
  });

  it('treats unknown counts (a role without access) as zero without failing', () => {
    const j = journeyOf({ sources: null, services: null, operations: null, openAlerts: null, openQuarantine: null, gaps: null, packsPublished: null });
    expect(j.current).toBe('connect');
  });

  it('does not call the review done while the observation is empty', () => {
    expect(statuses({ sources: 1, services: 1, operations: 0 })).toEqual(['done', 'current', 'todo', 'todo']);
  });
});
