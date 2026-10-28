// Steps shown while a world is generated: the Worlds page builds the archetypes (behaviour profiles) itself when
// there are none, then generates the world. Pure, so the progress logic is tested.
import type { MsgKey } from './i18n/index.svelte';

/** check: looking whether the profiles exist; archetypes: building them; world: generating; done: finished. */
export type Phase = 'idle' | 'check' | 'archetypes' | 'world' | 'done';
export type StepState = 'pending' | 'running' | 'done' | 'failed' | 'skipped';

export interface BuildStep {
  id: 'archetypes' | 'world';
  label: MsgKey;
  state: StepState;
}

/**
 * The two steps with their state. `phase` is the step being run (or the one that was running when it failed, with
 * `failed`). `needArchetypes` tells whether the profiles had to be built: when they already existed the first step
 * is shown as skipped.
 */
export function buildSteps(phase: Phase, needArchetypes: boolean, failed = false): BuildStep[] {
  let arch: StepState;
  if (phase === 'idle') arch = 'pending';
  else if (phase === 'check' || phase === 'archetypes') arch = failed ? 'failed' : 'running';
  else arch = needArchetypes ? 'done' : 'skipped';
  let world: StepState = 'pending';
  if (phase === 'world') world = failed ? 'failed' : 'running';
  else if (phase === 'done') world = 'done';
  return [
    { id: 'archetypes', label: arch === 'skipped' ? 'world.step.archetypesSkipped' : 'world.step.archetypes', state: arch },
    { id: 'world', label: 'world.step.world', state: world },
  ];
}
