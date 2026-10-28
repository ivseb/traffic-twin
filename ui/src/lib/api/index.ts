import type { Api } from './types';
import { createRestApi } from './rest/adapter';
import { createDemoApi } from 'tt-demo';

export * from './types';

// What to do when the server answers 401 to a call (the session expired or was
// revoked). The app registers it at start-up (stores.svelte.ts).
const hooks: { unauthorized: () => void } = { unauthorized: () => {} };
export function onUnauthorized(cb: () => void): void {
  hooks.unauthorized = cb;
}

// The production build talks to tt-core. `createDemoApi` is null there: the in-memory
// mock only exists in the demo build (`npm run build:demo`), see vite.config.ts.
export const api: Api = createDemoApi ? createDemoApi() : createRestApi({ onUnauthorized: () => hooks.unauthorized() });
