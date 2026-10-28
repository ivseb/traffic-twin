import { defineConfig, devices } from '@playwright/test';

// Tests of the production UI against the real composed tt-core (internal/core):
//
//   seeded  e2e/core/serve_test.go: the same core `tt dev up` runs, in process, with a simulated week of
//           the demo shop (source, contracts, rules, world, packs, quarantine) created through the API.
//   fresh   the real `tt dev up` binary on an empty data directory, for the first-run setup. Its
//           one-time setup token is read from the output it prints.
//
// `npm run test:e2e` builds the UI, `tt` and the seeded server first.
// TT_E2E_CHANNEL=chrome runs on the installed Google Chrome instead of the Playwright download
// (`npx playwright install chromium`).
export const SEEDED = 17180;
export const FRESH = 17181;
export const FRESH_LOG = 'e2e/.bin/fresh.log';

const channel = process.env.TT_E2E_CHANNEL || undefined;

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: {
    baseURL: `https://127.0.0.1:${SEEDED}`,
    ignoreHTTPSErrors: true, // the dev certificate is self-signed
    locale: 'en-GB',
    trace: 'retain-on-failure',
    channel,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel } }],
  webServer: [
    {
      command: `TT_E2E_ADDR=127.0.0.1:${SEEDED} ./e2e/.bin/core.test -test.run TestServe -test.timeout 0`,
      // /readyz answers while the week is still being created: wait for the line printed at the end.
      wait: { stdout: /READY https/ },
      reuseExistingServer: false,
      timeout: 240_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
    {
      command: `rm -rf e2e/.bin/fresh-data && ./e2e/.bin/tt dev up -dir e2e/.bin/fresh-data -admin 127.0.0.1:${FRESH} -intake 127.0.0.1:${FRESH + 1} > ${FRESH_LOG} 2>&1`,
      url: `https://127.0.0.1:${FRESH}/readyz`,
      ignoreHTTPSErrors: true,
      reuseExistingServer: false,
      timeout: 120_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
  ],
});
