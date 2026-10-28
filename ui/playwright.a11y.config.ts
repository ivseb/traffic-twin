import { defineConfig, devices } from '@playwright/test';

// Accessibility suite (axe-core + keyboard checks) against the DEMO build: mock adapter, no server needed.
//
//   npm run test:a11y           builds dist-demo, serves it with `vite preview` and runs a11y/*.spec.ts
//
// axe-core is a devDependency used only here: it is never imported by src/, so it cannot reach the
// production bundle (scripts/ui-build-check.sh checks that too).
// The tests run on the installed Google Chrome; TT_E2E_CHANNEL= (empty) uses the Playwright download.
export const A11Y_PORT = 4187;

const channel = process.env.TT_E2E_CHANNEL ?? 'chrome';

export default defineConfig({
  testDir: './a11y',
  testMatch: '**/*.spec.ts',
  fullyParallel: true,
  workers: process.env.CI ? 2 : 4,
  timeout: 60_000,
  expect: { timeout: 8_000 },
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${A11Y_PORT}`,
    locale: 'en-GB',
    trace: 'retain-on-failure',
    actionTimeout: 8_000,
    channel: channel || undefined,
  },
  projects: [{ name: 'a11y', use: { ...devices['Desktop Chrome'], channel: channel || undefined } }],
  webServer: {
    command: `npx vite preview --mode demo --outDir dist-demo --host 127.0.0.1 --port ${A11Y_PORT} --strictPort`,
    url: `http://127.0.0.1:${A11Y_PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
