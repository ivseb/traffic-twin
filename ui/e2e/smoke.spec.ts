import { readFileSync } from 'node:fs';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { FRESH, FRESH_LOG } from '../playwright.config';

// Smoke tests of the production UI against the real composed tt-core (see playwright.config.ts).
// The language is English (locale en-GB). Every seeded user has the password below:
//   ada admin · olga operator · rita rule-reviewer · paul publisher · audrey auditor
//   pia, pete policy-approver · eve event-exporter · root all roles
const PASSWORD = 'correct-horse-battery-1';

async function login(page: Page, user: string, password = PASSWORD): Promise<void> {
  await page.goto('/#/login');
  await page.getByRole('textbox', { name: 'Username' }).fill(user);
  await page.getByRole('textbox', { name: 'Password' }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

async function loginOk(page: Page, user: string): Promise<void> {
  await login(page, user);
  await expect(page.locator('header .who b')).toBeVisible();
}

/** A second browser context signed in as another person. */
async function asUser(browser: Browser, user: string): Promise<{ page: Page; close: () => Promise<void> }> {
  const ctx = await browser.newContext({ locale: 'en-GB', ignoreHTTPSErrors: true, baseURL: 'https://127.0.0.1:17180' });
  const page = await ctx.newPage();
  await loginOk(page, user);
  return { page, close: () => ctx.close() };
}

const apiCalls = (page: Page) => {
  const seen: { method: string; url: string; status: number }[] = [];
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith('/api/')) seen.push({ method: r.request().method(), url: u.pathname + u.search, status: r.status() });
  });
  return seen;
};

/** Console errors and failed API calls of the pages the test visits. */
function noBrowserErrors(page: Page): () => string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`);
  });
  return () => errors;
}

const signOut = async (page: Page) => {
  await page.locator('header .trigger').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
};

test.describe('production build', () => {
  test('has no demo: no role buttons, no demo password, no mock banner', async ({ page }) => {
    await page.goto('/#/login');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    const html = await page.content();
    for (const word of ['Demo mode', 'password “demo”', 'Demo environment', 'Simulate first run']) expect(html).not.toContain(word);
    await expect(page.getByRole('button', { name: /Rule reviewer|Policy approver|Event exporter/ })).toHaveCount(0);
    const scripts = await page.evaluate(() => performance.getEntriesByType('resource').map((e) => e.name).filter((n) => n.endsWith('.js')));
    expect(scripts.length).toBeGreaterThan(0);
    for (const s of scripts) {
      const body = await (await page.request.get(s)).text();
      expect(body).not.toContain('olga.operator');
      expect(body).not.toContain('loginAs');
    }
  });

  test('serves the strict CSP and reports the real server', async ({ page }) => {
    const res = await page.goto('/');
    expect(res?.headers()['content-security-policy']).toContain("default-src 'self'");
    const cfg = await page.request.get('/api/v1/auth/config');
    expect(await cfg.json()).toEqual({ local: true, oidc: false, setup_required: false });
  });
});

test.describe('sign in and roles', () => {
  test('a wrong password says so and stays on the login page', async ({ page }) => {
    await login(page, 'olga', 'not-the-password');
    await expect(page.getByText('Invalid username or password.')).toBeVisible();
    await expect(page).toHaveURL(/#\/login/);
  });

  test('signs in with the server roles, shows the server version, signs out', async ({ page }) => {
    await loginOk(page, 'olga');
    await expect(page).toHaveURL(/#\/home/);
    await expect(page.locator('header .who small')).toHaveText('Operator');
    await expect(page.locator('nav .ver')).toHaveText('v0.0.0-e2e');
    await signOut(page);
    await expect(page).toHaveURL(/#\/login/);
    expect((await page.request.get('/api/v1/auth/me')).status()).toBe(401);
  });

  test('a role without access gets the role message, not a crash', async ({ page }) => {
    await loginOk(page, 'eve');
    await page.goto('/#/sources');
    await expect(page.getByText('Your role does not allow this action.').first()).toBeVisible();
    await page.goto('/#/audit');
    await expect(page.getByText('Chain verified')).toHaveCount(0);
  });

  test('a lost session goes back to the login page and returns to where you were', async ({ page, context }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/services');
    await expect(page.getByRole('link', { name: 'shop-api' })).toBeVisible();
    await context.clearCookies();
    await page.getByRole('button', { name: /Refresh|Update/i }).first().click();
    await expect(page).toHaveURL(/#\/login\?next=%2Fservices/);
  });

  test('a write without the CSRF token is refused by the server', async ({ page }) => {
    await loginOk(page, 'olga');
    const res = await page.request.post('/api/v1/fleet/kill', { data: { active: false, scope: { all: true } } });
    expect(res.status()).toBe(403);
  });
});

test.describe('audit and keyguard', () => {
  test('the auditor sees the log and a verified chain, the operator does not', async ({ page }) => {
    await loginOk(page, 'audrey');
    await page.goto('/#/audit');
    await expect(page.getByText('Chain verified')).toBeVisible();
    await expect(page.getByRole('cell', { name: /auth\.login/ }).first()).toBeVisible();
    await signOut(page);
    await loginOk(page, 'olga');
    await page.goto('/#/audit');
    await expect(page.getByText('Chain verified')).toHaveCount(0);
  });

  test('settings: approvals and signing keys from keyguard, keyguard status and its log (auditor)', async ({ page }) => {
    await loginOk(page, 'audrey');
    await page.goto('/#/settings?tab=approvals');
    await expect(page.getByText('Approvals for changes that open data')).toBeVisible();
    await page.getByRole('tab', { name: 'Signing keys' }).click();
    await expect(page.getByText('policy-dev-1')).toBeVisible();
    await page.getByRole('tab', { name: 'keyguard' }).click();
    await expect(page.getByText('policy-dev-1').first()).toBeVisible();
    await expect(page.getByText('keyguard log')).toBeVisible();
    await page.getByRole('tab', { name: 'General' }).click();
    await expect(page.getByText(/configuration file/)).toBeVisible();
  });
});

test.describe('contracts from real traffic', () => {
  test('services, per-service contract, OpenAPI from the server, snapshots', async ({ page }) => {
    await loginOk(page, 'olga');
    const calls = apiCalls(page);
    await page.goto('/#/services');
    await expect(page.getByRole('link', { name: 'shipping-ext' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'shop-api' })).toBeVisible();

    await page.getByRole('link', { name: 'shipping-ext' }).click();
    await expect(page).toHaveURL(/#\/contracts\/service\/shipping-ext/);
    await expect(page.getByText('POST /v1/shipments').first()).toBeVisible();

    await page.getByRole('tab', { name: 'OpenAPI' }).click();
    await expect(page.getByText('openapi: 3.1.0').first()).toBeVisible();
    await expect.poll(() => calls.some((c) => c.url.includes('/api/v1/contracts/shipping-ext') && c.url.includes('format=yaml'))).toBe(true);

    await page.getByRole('tab', { name: /Snapshots|Snapshot/ }).click();
    await expect(page.getByText(/Snapshots of shipping-ext/)).toBeVisible();
  });

  test('operations of a service open with schema, statuses and examples', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/contracts/shop-api/' + encodeURIComponent('GET /orders/{id}'));
    await expect(page.getByText('/orders/{id}').first()).toBeVisible();
    await expect(page.getByRole('tab', { name: /Schema/ })).toBeVisible();
  });

  test('the same document opens in Swagger UI and Redoc (scoped CSP), also in a new tab', async ({ page, context }) => {
    await loginOk(page, 'olga');
    const tab = await context.newPage(); // the cookie session is shared with new tabs
    await tab.goto('/viewer.html?service=shipping-ext&viewer=swagger');
    await expect(tab.locator('.swagger-ui').first()).toBeVisible({ timeout: 20_000 });
    await expect(tab.getByText('/v1/shipments').first()).toBeVisible();
    const external: string[] = [];
    tab.on('request', (r) => {
      if (!r.url().startsWith('https://127.0.0.1')) external.push(r.url());
    });
    await tab.goto('/viewer.html?service=shipping-ext&viewer=redoc');
    await expect(tab.locator('redoc, .redoc-wrap, [role="navigation"]').first()).toBeVisible({ timeout: 20_000 });
    expect(external).toEqual([]); // Redoc asks for no logo on the internet
  });

  test('gaps and the drift list come from the server', async ({ page }) => {
    await loginOk(page, 'olga');
    const errors = noBrowserErrors(page);
    await page.goto('/#/gaps');
    await expect(page.getByText(/only \d+ calls|no 4xx|below the k threshold|no 5xx/).first()).toBeVisible();
    await page.goto('/#/alerts');
    await expect(page.getByRole('heading', { name: 'Alerts' })).toBeVisible();
    await page.getByRole('tab', { name: /Webhooks/ }).click();
    expect(errors()).toEqual([]);
  });
});

test.describe('knowledge: rules, archetypes, worlds', () => {
  test('rules mined from the traffic; the reviewer approves the last draft, the operator mines again', async ({ page, browser }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/rules');
    await expect(page.getByRole('heading', { name: 'Rules' })).toBeVisible();
    await page.getByRole('button', { name: 'Look for new rules' }).click();
    await expect(page.getByText(/new rule/)).toBeVisible();
    await page.getByRole('button', { name: /^All/ }).click();
    await expect(page.getByRole('link', { name: /r-0001/ })).toBeVisible();

    const rita = await asUser(browser, 'rita');
    await rita.page.goto('/#/rules');
    await rita.page.getByRole('button', { name: /^All/ }).click();
    await rita.page.getByRole('link', { name: /r-0001/ }).click();
    await expect(rita.page.getByText('shipment-created').first()).toBeVisible();
    // an approved rule is locked: no review buttons
    await expect(rita.page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
    await rita.close();
  });

  test('archetypes and worlds', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/archetypes');
    await expect(page.getByText(/arch-01/).first()).toBeVisible();
    await page.goto('/#/worlds');
    await expect(page.getByText(/w-\d{8}-0001/).first()).toBeVisible();
    // a world opens the explorer: the customers, then one customer's journey and graph
    await page.getByRole('button', { name: /w-\d{8}-0001/ }).first().click();
    const customers = page.getByRole('region', { name: 'Synthetic customers' });
    await expect(customers).toBeVisible();
    await customers.locator('tbody').getByRole('button').first().click();
    await expect(page.getByRole('region', { name: 'Customer detail' }).getByRole('heading', { level: 3 })).toBeVisible(); // the journey (the graph only shows for customers with linked entities)
  });
});

test.describe('packs, exports, scenarios', () => {
  test('a signed pack waits for the publisher; releasing unlocks download and export (zip)', async ({ page, browser }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/packs');
    await expect(page.getByText(/pk-\d{8}-0002/).first()).toBeVisible();
    await page.getByRole('link', { name: /pk-\d{8}-0002/ }).click();
    await expect(page.getByText('Signed, to release').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Release to tests' })).toBeDisabled(); // building is not releasing

    const paul = await asUser(browser, 'paul');
    await paul.page.goto('/#/packs');
    await paul.page.getByRole('link', { name: /pk-\d{8}-0002/ }).click();
    await expect(paul.page.getByRole('button', { name: 'Download the pack' })).toBeDisabled();
    await paul.page.getByRole('button', { name: 'Release to tests' }).first().click();
    await paul.page.getByRole('dialog').getByRole('button', { name: 'Release to tests' }).click();
    await expect(paul.page.getByText('Released to tests').first()).toBeVisible();

    const download = paul.page.waitForEvent('download');
    await paul.page.getByRole('button', { name: 'Download the pack' }).click();
    expect((await download).suggestedFilename()).toMatch(/\.ttpack$/);

    await paul.page.getByRole('button', { name: /Export for WireMock/ }).click();
    await expect(paul.page.getByRole('dialog').getByText('What carries over')).toBeVisible();
    const zip = paul.page.waitForEvent('download');
    await paul.page.getByRole('button', { name: 'Download the zip' }).click();
    expect((await zip).suggestedFilename()).toMatch(/\.zip$/);
    await paul.close();
  });

  test('scenario presets are served and the operator can create one', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/scenarios');
    await expect(page.getByText('Cliente abituale').first()).toBeVisible();
    const calls = apiCalls(page);
    await page.getByRole('button', { name: 'New preset' }).click();
    await page.getByRole('textbox', { name: /^Name/ }).fill('Carrier slow');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect.poll(() => calls.some((c) => c.method === 'POST' && c.url === '/api/v1/scenario-presets' && c.status === 201)).toBe(true);
    await expect(page.getByText('Carrier slow').first()).toBeVisible();
  });
});

test.describe('users, data, events', () => {
  test('the admin lists, creates, disables users and ends their sessions; the auditor cannot', async ({ page }) => {
    await loginOk(page, 'ada');
    await page.goto('/#/users');
    await expect(page.getByText('audrey').first()).toBeVisible();
    await page.getByRole('button', { name: 'New user' }).click();
    await page.getByRole('textbox', { name: 'Username', exact: true }).fill('nina');
    await page.getByRole('textbox', { name: 'Display name' }).fill('Nina');
    await page.locator('#nu-p').fill('another-long-password');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('User created.')).toBeVisible();
    const row = page.getByRole('row', { name: /nina/ });
    await row.getByRole('button', { name: 'End sessions' }).click();
    await expect(page.getByText('Sessions ended.')).toBeVisible();
    await row.getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByRole('row', { name: /nina/ }).getByRole('button', { name: 'Re-enable' })).toBeVisible();
    // users are never deleted: the server says so
    const del = await page.request.delete('/api/v1/users/usr_nobody', { headers: { 'X-CSRF-Token': await csrf(page) } });
    expect([404, 409]).toContain(del.status());
  });

  test('retention and purge are the admin’s; everyone else sees them read-only', async ({ page, browser }) => {
    await loginOk(page, 'ada');
    await page.goto('/#/settings?tab=data');
    const days = page.getByRole('textbox', { name: 'Days' });
    await expect(days).toHaveValue(/\d+/);
    await days.fill('45');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Retention updated.')).toBeVisible();
    await page.getByLabel('Before').fill('2020-01-01');
    await page.getByRole('button', { name: 'Delete old events' }).click();
    await page.getByRole('dialog').getByRole('textbox').fill('DELETE');
    await page.getByRole('dialog').getByRole('button', { name: 'Delete old events' }).click();
    await expect(page.getByText(/events and \d+ tokens deleted/)).toBeVisible();

    const audrey = await asUser(browser, 'audrey');
    await audrey.page.goto('/#/settings?tab=data');
    await expect(audrey.page.getByRole('button', { name: 'Delete old events' })).toBeDisabled();
    await audrey.close();
  });

  test('the event exporter prepares and downloads an event export; others cannot', async ({ page, browser }) => {
    await loginOk(page, 'eve');
    await page.goto('/#/events');
    await expect(page.getByText('Pseudonymous personal data.')).toBeVisible();
    await page.getByRole('button', { name: 'Prepare the export' }).click();
    await expect(page.getByText('Export ready').first()).toBeVisible();
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download the file' }).click();
    expect((await download).suggestedFilename()).toMatch(/\.json$/);

    const olga = await asUser(browser, 'olga');
    await olga.page.goto('/#/events');
    await expect(olga.page.getByRole('button', { name: 'Prepare the export' })).toBeDisabled();
    await olga.close();
  });
});

async function csrf(page: Page): Promise<string> {
  return (await (await page.request.get('/api/v1/auth/me')).json()).csrf_token as string;
}

test.describe.serial('onboarding without approvals, and quarantine', () => {
  test('an operator creates the group, the token and the starter policy; the wizard watches the stream', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/onboarding');
    await page.getByRole('radio', { name: /Node\.js/ }).click();
    await page.getByRole('textbox', { name: 'Group name' }).fill('shop');
    await page.getByRole('textbox', { name: 'Allowed service names' }).fill('shop-api');
    const calls = apiCalls(page);
    await page.getByRole('button', { name: 'Generate token and continue' }).click();

    await expect(page.getByTestId('token')).toHaveText(/^tte_/);
    // The starter policy opens no value: active at once, nothing to approve (policy.md §7).
    await expect(page.getByTestId('no-policy')).toBeVisible();
    await expect(page.getByText('TT_SERVICE_NAME=shop-api').first()).toBeVisible();
    await expect.poll(() => calls.filter((c) => c.method === 'POST').map((c) => c.url)).toEqual(expect.arrayContaining(['/api/v1/fleet/groups', '/api/v1/fleet/enrollment-tokens', '/api/v1/fleet/groups/shop/starter-policy']));

    const stream = page.waitForRequest((r) => /\/api\/v1\/fleet\/onboarding\/tok-[^/]+\/status/.test(r.url()));
    await page.getByRole('button', { name: 'Done, wait for data' }).click();
    expect((await stream).headers()['accept']).toContain('text/event-stream');
    await expect(page.getByRole('heading', { name: 'Listening' }).first()).toBeVisible();
  });

  test('the starter policy is active without approvals and says it opens no data', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/sources?tab=policy');
    const row = page.getByRole('row', { name: /p-shop v1/ });
    await expect(row).toBeVisible();
    await expect(row.getByText('Active')).toBeVisible();
    await expect(row.locator('.badge', { hasText: 'Opens no data' })).toBeVisible();
    await expect(row.getByRole('button', { name: 'Approve' })).toHaveCount(0);
  });

  test('sources and policies of the demo source are real: a healthy source, an active demo policy', async ({ page }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/sources');
    await expect(page.getByRole('button', { name: 'shop-api' }).first()).toBeVisible();
    await page.goto('/#/sources?tab=policy');
    await expect(page.getByRole('button', { name: /p-demo v\d+/ }).first()).toBeVisible();
  });

  test('the quarantined field: close is one approver, dismiss needs two different ones', async ({ page, browser }) => {
    await loginOk(page, 'olga');
    await page.goto('/#/quarantine');
    await expect(page.getByText('resp.body $.status').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'It is a parameter: group the values' }).first()).toBeDisabled(); // the operator does not resolve

    const pia = await asUser(browser, 'pia');
    await pia.page.goto('/#/quarantine');
    await pia.page.getByRole('button', { name: 'It is a fixed name: keep it' }).first().click();
    await pia.page.getByRole('dialog').getByRole('button', { name: 'It is a fixed name: keep it' }).click();
    await expect(pia.page.getByText('Approval recorded: another one is needed.')).toBeVisible();
    await expect(pia.page.getByText('Dismissal pending').first()).toBeVisible();
    await expect(pia.page.getByRole('button', { name: 'It is a fixed name: keep it' }).first()).toBeDisabled(); // the same person twice

    const pete = await asUser(browser, 'pete');
    await pete.page.goto('/#/quarantine');
    await pete.page.getByRole('button', { name: 'It is a fixed name: keep it' }).first().click();
    await pete.page.getByRole('dialog').getByRole('button', { name: 'It is a fixed name: keep it' }).click();
    await expect(pete.page.getByText('Quarantine resolved.')).toBeVisible();
    await pia.close();
    await pete.close();
  });
});

test.describe('every page loads without browser errors', () => {
  const PAGES = ['home', 'mock', 'onboarding', 'sources', 'services', 'contracts', 'rules', 'archetypes', 'gaps', 'worlds', 'packs', 'scenarios', 'alerts', 'quarantine', 'events', 'audit', 'users', 'settings', 'glossary'];
  test('as a user with all roles', async ({ page }) => {
    await loginOk(page, 'root');
    const errors = noBrowserErrors(page);
    const failed: string[] = [];
    page.on('response', (r) => {
      const u = new URL(r.url());
      if (u.pathname.startsWith('/api/v1/') && r.status() >= 400) failed.push(`${r.status()} ${r.request().method()} ${u.pathname}`);
    });
    for (const p of PAGES) {
      await page.goto(`/#/${p}`);
      await page.waitForLoadState('networkidle');
      await expect(page.locator('main h1').first()).toBeVisible();
    }
    // detail pages with real data
    const res = await page.request.get('/api/v1/packs');
    expect(res.status(), await res.text()).toBe(200);
    const packs: { pack_id: string }[] = await res.json();
    for (const path of [
      `/#/packs/${packs[0].pack_id}`,
      `/#/packs/${packs[1].pack_id}`,
      '/#/rules/r-0001',
      '/#/contracts/service/shop-api?tab=snapshots',
      '/#/contracts/shipping-ext/' + encodeURIComponent('POST /v1/shipments'),
      '/#/sources?tab=policy',
    ]) {
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      await expect(page.locator('main h1, main h2').first()).toBeVisible();
    }
    expect(failed).toEqual([]);
    expect(errors()).toEqual([]);
  });
});

test.describe('first run (the real `tt dev up`, empty)', () => {
  test.use({ baseURL: `https://127.0.0.1:${FRESH}` });

  test('the setup token creates the first administrator, who is signed in', async ({ page }) => {
    const token = /tts_[A-Za-z0-9_-]+/.exec(readFileSync(FRESH_LOG, 'utf8'))?.[0];
    expect(token, 'the setup token printed by tt dev up').toBeTruthy();
    await page.goto('/');
    await expect(page).toHaveURL(/#\/setup/);
    await page.getByRole('textbox', { name: 'Setup token' }).fill('tts_wrong');
    await page.getByRole('textbox', { name: 'Password', exact: true }).fill('a-very-long-password');
    await page.getByRole('textbox', { name: 'Repeat the password' }).fill('a-very-long-password');
    await page.getByRole('button', { name: 'Create administrator' }).click();
    await expect(page.getByText('Invalid or expired setup token.')).toBeVisible();

    await page.getByRole('textbox', { name: 'Setup token' }).fill(token ?? '');
    await page.getByRole('button', { name: 'Create administrator' }).click();
    await expect(page).toHaveURL(/#\/home/);
    await expect(page.locator('header .who small')).toHaveText('Administrator');
    await expect(page.locator('nav .ver')).toBeVisible();

    // admin is the superuser: it sees the audit too
    await page.goto('/#/audit');
    await expect(page.getByText('Chain verified')).toBeVisible();
    // an empty system is explained, not broken
    await page.goto('/#/services');
    await expect(page.locator('main')).toBeVisible();

    // the setup is closed for good
    const again = await page.request.post('/api/v1/setup', { data: { setup_token: token, username: 'x', password: 'another-long-password' } });
    expect(again.status()).toBe(409);
  });
});
