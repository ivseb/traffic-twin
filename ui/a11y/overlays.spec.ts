import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare, THEMES, WIDTHS } from './axe';

// axe-core on the overlays and the states reached by interaction: command palette, Guide drawer,
// (i) popovers, user menu, side drawers, modals and confirmation dialogs, the onboarding wizard steps,
// selected details. Each check also verifies that Esc closes the overlay and gives focus back.

type Failures = string[];

async function audit(page: Page, failures: Failures, name: string): Promise<void> {
  const bad = await axeViolations(page);
  if (bad.length) failures.push(`== ${name}\n${bad.join('\n')}`);
}

/** Runs a scenario; an exception in one step is a failure like the others and does not hide them. */
async function collect(body: (failures: Failures) => Promise<void>): Promise<void> {
  const failures: Failures = [];
  try {
    await body(failures);
  } catch (e) {
    failures.push(`== scenario aborted\n${(e as Error).message.split('\n').slice(0, 8).join('\n')}`);
  }
  if (failures.length) throw new Error(failures.join('\n\n'));
}

/** Opens a dialog with `open`, audits it, closes it with Esc and checks that focus returns to the opener. */
async function dialog(page: Page, failures: Failures, name: string, open: () => Promise<void>, opener?: () => ReturnType<Page['locator']>): Promise<void> {
  await open();
  const dlg = page.locator('dialog[open]').last();
  try {
    await expect(dlg).toBeVisible();
    // the dialog is named and the focus is inside it
    expect(
      await dlg.evaluate((d) => !!(d.getAttribute('aria-label') || document.getElementById(d.getAttribute('aria-labelledby') ?? '')?.textContent?.trim())),
    ).toBe(true);
    expect(await page.evaluate(() => !!document.activeElement?.closest('dialog[open]'))).toBe(true);
    await page.waitForTimeout(250); // the drawer slides in
    await audit(page, failures, name);
    await page.keyboard.press('Escape');
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    if (opener) await expect(opener()).toBeFocused();
  } catch (e) {
    failures.push(`== ${name}\n${(e as Error).message.split('\n').slice(0, 6).join('\n')}`);
    await page.keyboard.press('Escape').catch(() => {});
    await page.evaluate(() => document.querySelectorAll<HTMLDialogElement>('dialog[open]').forEach((d) => d.close()));
  }
}

for (const theme of THEMES) {
  for (const width of WIDTHS) {
    test.describe(`${theme} ${width}px`, () => {
      test.use({ viewport: { width, height: 900 } });
      test.beforeEach(async ({ page }) => {
        await prepare(page, theme);
        await loginAs(page);
      });

      test('shell overlays: palette, guide, user menu, tooltips', async ({ page }) => {
        await collect(async (failures) => {
          await go(page, '#/onboarding');
          const search = page.getByRole('button', { name: 'Command palette' });
          await dialog(
            page,
            failures,
            'command palette',
            () => search.click(),
            () => search,
          );
          await dialog(page, failures, 'command palette with query', async () => {
            await search.click();
            await page.getByRole('dialog', { name: 'Command palette' }).getByRole('combobox').fill('sou');
          });
          const guide = page.getByRole('button', { name: 'Guide', exact: true }).first();
          await dialog(
            page,
            failures,
            'guide drawer',
            () => guide.click(),
            () => guide,
          );

          // user menu
          const menu = page.locator('header .trigger');
          await menu.click();
          await expect(page.getByRole('group', { name: 'User menu' })).toBeVisible();
          await audit(page, failures, 'user menu');
          await page.keyboard.press('Escape');
          await expect(menu).toBeFocused();

          // (i) popover: open with the keyboard, audit, Esc closes and keeps the focus on the trigger
          await go(page, '#/settings?tab=approvals');
          const tip = page.locator('button[aria-haspopup="dialog"]').first();
          await tip.focus();
          await page.keyboard.press('Enter');
          await expect(page.locator('[role="dialog"][aria-label]:not(dialog)').first()).toBeVisible();
          await audit(page, failures, 'info popover');
          await page.keyboard.press('Escape');
          await expect(page.locator('[role="dialog"]:not(dialog)')).toHaveCount(0);
          await expect(tip).toBeFocused();

          // mobile navigation drawer
          if (width < 900) {
            await page.getByRole('button', { name: 'Menu' }).click();
            await audit(page, failures, 'mobile navigation open');
          }
        });
      });

      test('modals and confirmations', async ({ page }) => {
        await collect(async (failures) => {
          const open = (hash: string, name: string | RegExp, label: string, opts: { exact?: boolean; nth?: number; optional?: boolean } = {}) =>
            page
              .evaluate((h) => {
                location.hash = h;
              }, hash)
              .then(async () => {
                await go(page, hash);
                const btn = page.getByRole('button', { name, exact: opts.exact }).nth(opts.nth ?? 0);
                if ((await btn.count()) === 0 && opts.optional) {
                  test.info().annotations.push({ type: 'not covered', description: `${label}: no opener in the demo data` });
                  return;
                }
                if ((await btn.count()) === 0) {
                  failures.push(`== ${label}\nthe opener button ${String(name)} is not on the page`);
                  return;
                }
                await dialog(
                  page,
                  failures,
                  label,
                  () => btn.click(),
                  () => btn,
                );
              });

          await open('#/alerts?tab=webhooks', 'New webhook', 'alerts: new webhook');
          await open('#/users', 'New user', 'users: new user');
          await open('#/users', 'Roles', 'users: edit roles', { exact: true });
          await open('#/scenarios', 'New preset', 'scenarios: new preset');
          await open('#/packs', 'New pack', 'packs: new pack');
          await open('#/settings?tab=keys', 'Revoke key', 'settings: revoke key', { optional: true });
          await open('#/sources', 'Suspend all', 'sources: suspend all (typed confirmation)');
          await open('#/hosts', 'Simulate in the mock', 'hosts: simulate in the mock', { exact: true });
          await open('#/quarantine', 'It is a fixed name: keep it', 'quarantine: keep it visible');

          // settings data purge needs a date first
          await go(page, '#/settings?tab=data');
          const date = page.locator('input[type="date"], input[type="datetime-local"]').first();
          if (await date.count()) {
            await date.fill((await date.getAttribute('type')) === 'date' ? '2020-01-01' : '2020-01-01T00:00');
            const purge = page.getByRole('button', { name: 'Delete old events', exact: true });
            await dialog(
              page,
              failures,
              'settings: purge',
              () => purge.click(),
              () => purge,
            );
          }
        });
      });

      test('drawers and details', async ({ page }) => {
        await collect(async (failures) => {
          await go(page, '#/sources');
          const svc = page.locator('table .link-btn').first();
          await dialog(
            page,
            failures,
            'sources: service drawer',
            () => svc.click(),
            () => svc,
          );
          await go(page, '#/sources?tab=policy');
          const pol = page.locator('table .link-btn').first();
          if (await pol.count())
            await dialog(
              page,
              failures,
              'sources: policy drawer',
              () => pol.click(),
              () => pol,
            );

          await go(page, '#/rules/r-0007');
          await audit(page, failures, 'rule detail');
          await go(page, '#/packs');
          await page.locator('table a').first().click();
          await go(page, page.url().split('/#')[1] ? '#' + page.url().split('/#')[1] : '#/packs');
          await audit(page, failures, 'pack detail');

          await go(page, '#/worlds');
          await page.locator('table .link-btn').first().click();
          await page.waitForTimeout(300);
          await audit(page, failures, 'world selected');

          await go(page, '#/scenarios');
          await page
            .locator('main [role="listbox"] [role="option"], main table tbody tr, main ul button')
            .first()
            .click()
            .catch(() => {});
          await audit(page, failures, 'scenario selected');

          await go(page, '#/contracts');
          await page.locator('nav.tree a').first().click();
          await page.waitForTimeout(400);
          await audit(page, failures, 'contract operation');

          await go(page, '#/rules');
          await page.getByRole('button', { name: 'Look for new rules' }).first().click();
          await expect(page.getByRole('status').filter({ hasText: /./ }).first()).toBeVisible();
          await page.waitForTimeout(500); // the toast fades in: axe would measure the colours mid-animation
          await audit(page, failures, 'rules after toast');
        });
      });

      test('journey pages: rule editor, bulk review, world explorer, linked fields', async ({ page }) => {
        await collect(async (failures) => {
          // rule editor (drawer): new rule, and the definition of an existing one
          await go(page, '#/rules');
          const newRule = page.getByRole('button', { name: 'New rule', exact: true });
          await dialog(page, failures, 'rules: editor (new rule)', () => newRule.click(), () => newRule);
          await go(page, '#/rules/r-0007');
          const edit = page.getByRole('button', { name: 'Edit conditions and effects' });
          await dialog(page, failures, 'rules: editor (existing rule)', () => edit.click(), () => edit);

          // bulk review of the policies (drawer)
          await go(page, '#/sources?tab=policy');
          const bulk = page.getByRole('button', { name: 'Bulk review', exact: true });
          await dialog(page, failures, 'sources: bulk review', () => bulk.click(), () => bulk);

          // world explorer: the selected world, a customer found with the search, its journey
          await go(page, '#/worlds');
          await page.locator('table .link-btn').first().click();
          const search = page.getByRole('searchbox', { name: 'Search a customer' });
          await expect(search).toBeVisible();
          await audit(page, failures, 'world explorer');
          await search.fill('CUS-SYN-0002');
          await page.getByRole('region', { name: 'Synthetic customers' }).locator('tbody').getByRole('button').first().click();
          await expect(page.getByRole('region', { name: 'Customer detail' }).getByRole('heading', { level: 3 })).toBeVisible();
          // the detail scrolls into view under the sticky header: measure from the top of the page, as for the other pages
          await page.evaluate(() => {
            window.scrollTo(0, 0);
            document.querySelectorAll('main, #app, body').forEach((e) => ((e as HTMLElement).scrollTop = 0));
          });
          await page.waitForTimeout(300);
          await audit(page, failures, 'world explorer: customer detail');

          // linked fields in the schema of an operation
          await go(page, '#/contracts');
          await page.locator('nav.tree a', { hasText: '/products' }).first().click();
          await expect(page.getByTestId('linked-fields').first()).toBeVisible();
          await page.waitForTimeout(300);
          await audit(page, failures, 'contract operation: linked fields');
        });
      });

      test('mock page: prepare, running mock and its tabs', async ({ page }) => {
        test.setTimeout(120_000);
        await collect(async (failures) => {
          await go(page, '#/mock');
          await audit(page, failures, 'mock: nothing running');
          await page.getByRole('combobox', { name: 'Group (team)' }).selectOption('shop-api');
          const reason = page.getByRole('textbox', { name: 'Reason' });
          if (!(await reason.inputValue())) await reason.fill('a11y check');
          await page.getByRole('button', { name: 'Prepare and start the mock' }).click();
          const tabs = page.getByRole('tablist');
          await expect(tabs).toBeVisible({ timeout: 45_000 });
          await expect(page.locator('main .callout.ok').first()).toBeVisible();
          await page.waitForTimeout(500);
          await audit(page, failures, 'mock: running, last calls');
          for (const name of ['Session and scenarios', 'Saved scenarios']) {
            await tabs.getByRole('tab', { name }).click();
            await expect(page.getByRole('tabpanel')).toBeVisible();
            await page.waitForTimeout(300);
            await audit(page, failures, `mock: ${name}`);
          }
        });
      });

      test('onboarding wizard steps', async ({ page }) => {
        test.setTimeout(120_000);
        await collect(async (failures) => {
          await go(page, '#/onboarding');
          await audit(page, failures, 'wizard 1 connect');
          await page.getByRole('radio').first().click();
          await page.getByRole('textbox', { name: 'Group name' }).fill('shop');
          await page.getByRole('button', { name: 'Generate token and continue' }).click();
          await expect(page.getByTestId('token')).toBeVisible();
          await audit(page, failures, 'wizard 2 start');
          await page.getByRole('button', { name: 'Done, wait for data' }).click();
          await expect(page.getByRole('heading', { name: 'Listening' }).first()).toBeVisible();
          await audit(page, failures, 'wizard 3 listening');
          // the policy steps are "Advanced": they open only on request
          await page.getByRole('button', { name: 'Advanced: edit the policy' }).click();
          await expect(page.getByRole('button', { name: 'Next, policy assistant' })).toBeVisible({ timeout: 45_000 });
          await audit(page, failures, 'wizard 4 discovered');
          await page.getByRole('button', { name: 'Next, policy assistant' }).click();
          await expect(page.getByRole('button', { name: /Review the changes/ })).toBeVisible();
          await audit(page, failures, 'wizard 5 policy');
          await page.getByRole('button', { name: /Review the changes/ }).click();
          await expect(page.getByRole('button', { name: /Request/ }).first()).toBeVisible();
          await audit(page, failures, 'wizard 6 review');
        });
      });
    });
  }
}
