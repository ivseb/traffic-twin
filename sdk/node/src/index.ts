// Public API of @traffic-twin/sdk.
//
//   import { start } from '@traffic-twin/sdk';
//   await start({ enrollUrl, enrollToken, serviceName, hmacKeyFile });
//
// or zero-config: node --import @traffic-twin/sdk/register app.js

import { Agent, optionsFromEnv, type AgentOptions, type SourceState } from './agent.js';

export type { AgentOptions, SourceState };
export { Agent, optionsFromEnv };
export { SDK_VERSION } from './version.js';

// Sanitizer and conformance test function (sanitizer.md 16).
export { Sanitizer, type Exchange, type Result, type Decision } from './sanitizer/sanitizer.js';
export { Policy, Refused, parseKeyRing, selectKey, verifyEnvelope, validateBodySchema } from './sanitizer/policy.js';
export { runVector, parseVector, vectorExchange, type VectorResult } from './sanitizer/vectors.js';
export { parseJson, writeCanonical, canonicalNumber } from './sanitizer/json.js';

// One agent per process, shared by the ESM and CommonJS builds.
const KEY = Symbol.for('traffic-twin.sdk.agent');
type G = typeof globalThis & { [KEY]?: { agent: Agent; ready: Promise<void> } };

/** Starts the agent once per process (later calls return the same one). Never throws. */
export function start(options: AgentOptions = {}): Promise<Agent> {
  const g = globalThis as G;
  const existing = g[KEY];
  if (existing) return existing.ready.then(() => existing.agent);
  const merged: AgentOptions = { ...optionsFromEnv(), ...stripUndefined(options) };
  const agent = new Agent(merged);
  const ready = agent.start();
  g[KEY] = { agent, ready };
  return ready.then(() => agent);
}

/** The running agent, if any. */
export function current(): Agent | undefined {
  return (globalThis as G)[KEY]?.agent;
}

/** Stops capture and timers; the process keeps working untouched. */
export async function stop(): Promise<void> {
  const g = globalThis as G;
  const e = g[KEY];
  if (!e) return;
  delete g[KEY];
  await e.agent.stop();
}

function stripUndefined<T extends object>(o: T): Partial<T> {
  const out: Partial<T> = {};
  for (const k of Object.keys(o) as Array<keyof T>) if (o[k] !== undefined) out[k] = o[k];
  return out;
}
