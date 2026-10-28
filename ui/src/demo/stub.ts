// Production flavour of `tt-demo`: nothing. Keep this file free of imports from the mock,
// the fixtures and the demo components (a test greps the production bundle for them).

import type { Api } from '../lib/api/types';
import Empty from './Empty.svelte';

export const demoEnabled = false;
export const createDemoApi: (() => Api) | null = null;
export const DemoBanner = Empty;
export const DemoLoginPanel = Empty;
export const DemoRoleSwitcher = Empty;
export const DemoSetupHint = Empty;
