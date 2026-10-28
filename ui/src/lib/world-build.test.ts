import { describe, expect, it } from 'vitest';
import { buildSteps, type Phase } from './world-build';

const states = (phase: Phase, need: boolean, failed = false) => buildSteps(phase, need, failed).map((s) => s.state);

describe('world build progress', () => {
  it('is pending before anything starts', () => {
    expect(states('idle', false)).toEqual(['pending', 'pending']);
  });
  it('builds the archetypes first when there are none, then the world', () => {
    expect(states('archetypes', true)).toEqual(['running', 'pending']);
    expect(states('world', true)).toEqual(['done', 'running']);
    expect(states('done', true)).toEqual(['done', 'done']);
  });
  it('skips the archetypes step when the profiles already exist', () => {
    const steps = buildSteps('world', false);
    expect(steps.map((s) => s.state)).toEqual(['skipped', 'running']);
    expect(steps[0].label).toBe('world.step.archetypesSkipped');
    expect(states('done', false)).toEqual(['skipped', 'done']);
    expect(states('check', false)).toEqual(['running', 'pending']);
  });
  it('marks the step that failed and leaves the next one pending', () => {
    expect(states('archetypes', true, true)).toEqual(['failed', 'pending']);
    expect(states('world', true, true)).toEqual(['done', 'failed']);
  });
});
