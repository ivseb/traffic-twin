import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import JourneySteps from './JourneySteps.svelte';
import EntityTimeline from './EntityTimeline.svelte';
import ProgressSteps from './ProgressSteps.svelte';
import { journeyOf } from '../lib/journey';
import { buildSteps } from '../lib/world-build';
import { customerDetailOf } from '../lib/world-explorer';
import { setLang } from '../lib/i18n/index.svelte';

// The components are rendered on the server (no browser needed): the markup is what a screen reader sees.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const html = (c: any, props: Record<string, unknown>): string => render(c, { props }).body;

describe('JourneySteps', () => {
  const j = journeyOf({ sources: 1, services: 2, operations: 9, openAlerts: 2, openQuarantine: 0, gaps: 1, packsPublished: 0 });

  it('lists the four steps in order, numbered, with a link each', () => {
    setLang('it');
    const out = html(JourneySteps, { journey: j });
    expect((out.match(/<li class="step /g) ?? []).length).toBe(4);
    const order = ['Collega', 'Osserva', 'Rivedi', 'Usa il mock'].map((s) => out.indexOf(s));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    for (const href of ['#/onboarding', '#/services', '#/contracts', '#/mock']) expect(out).toContain(`href="${href}"`);
  });

  it('marks done, current and todo steps and says where the user stands', () => {
    setLang('it');
    const out = html(JourneySteps, { journey: j });
    expect(out).toMatch(/class="step done /);
    expect(out).toMatch(/class="step current /);
    expect(out).toMatch(/class="step todo /);
    expect(out).toContain('Fatto');
    expect(out).toContain('2 allarmi · 0 in quarantena · 1 buco da guardare.');
  });

  it('follows the language', () => {
    setLang('en');
    const out = html(JourneySteps, { journey: j });
    expect(out).toContain('Use the mock');
    expect(out).toContain('2 alerts · 0 in quarantine · 1 gap to look at.');
    setLang('it');
  });
});

describe('EntityTimeline', () => {
  const lines = [
    { type: 'customer', id: 'CUS-SYN-0001', archetype: 'arch-01', profile: { name: 'Giulia Rossi', email: 'giulia@example.com' } },
    { type: 'entity', entity: 'order', id: 'ORD-SYN-0001', customer_id: 'CUS-SYN-0001', state: { status: 'PAID' } },
    { type: 'history', entity: 'order', id: 'ORD-SYN-0001', seq: 1, at: '2026-10-19T08:00:00Z', state: { status: 'CREATED' } },
    { type: 'history', entity: 'order', id: 'ORD-SYN-0001', seq: 2, at: '2026-10-19T09:30:00Z', state: { status: 'PAID' }, rule_id: 'r-0012', outcome: 'happy' },
  ];
  const detail = customerDetailOf('CUS-SYN-0001', lines);

  it('shows the path of states and each step with its cause', () => {
    setLang('it');
    const out = html(EntityTimeline, { entity: detail.entities[0] });
    expect(out).toContain('ORD-SYN-0001');
    expect(out.indexOf('CREATED')).toBeLessThan(out.indexOf('PAID'));
    expect(out).toContain('<ol class="steps');
    expect(out).toContain('dalla regola r-0012');
    expect(out).toContain('da una chiamata');
    expect(out).toContain('2026-10-19 08:00');
  });

  it('does not fail on an entity without history', () => {
    const out = html(EntityTimeline, { entity: { id: 'SHP-SYN-0001', entity: 'shipment', state: {}, steps: [] } });
    expect(out).toContain('Nessun passaggio registrato.');
  });
});

describe('ProgressSteps', () => {
  it('announces each step with its state in words, not only by colour', () => {
    setLang('it');
    const out = html(ProgressSteps, { steps: buildSteps('world', true), label: 'Avanzamento' });
    expect(out).toContain('role="status"');
    expect(out).toContain('Costruzione dei profili di comportamento (archetipi)');
    expect(out).toContain('fatto');
    expect(out).toContain('in corso');
  });
  it('says when the profiles were already there', () => {
    setLang('it');
    const out = html(ProgressSteps, { steps: buildSteps('done', false), label: 'x' });
    expect(out).toContain('Profili di comportamento già pronti');
    expect(out).toContain('già pronto');
  });
});
