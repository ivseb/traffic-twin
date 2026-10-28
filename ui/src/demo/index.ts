// The demo flavour of the app (`npm run build:demo`, `npm run dev:demo`): in-memory mock
// adapter with invented data, one-click role logins, banner and demo texts.
// The production build resolves `tt-demo` to ./stub.ts instead (see vite.config.ts), so
// nothing imported here reaches the bundle that is embedded in the tt binary.

import type { Api } from '../lib/api/types';
import { createMockApi } from '../lib/api/mock/adapter';
import { registerDemoMessages } from './messages';
import DemoBanner from './DemoBanner.svelte';
import DemoLoginPanel from './DemoLoginPanel.svelte';
import DemoRoleSwitcher from './DemoRoleSwitcher.svelte';
import DemoSetupHint from './DemoSetupHint.svelte';

registerDemoMessages();

export const demoEnabled = true;
export const createDemoApi: (() => Api) | null = () => createMockApi();
export { DemoBanner, DemoLoginPanel, DemoRoleSwitcher, DemoSetupHint };
