import { expect, test, type Page } from '@playwright/test';
import { axeViolations, go, loginAs, prepare } from './axe';

// Usability round 4 (non-admin developer, orders-api): the pages that used to stay blank or stuck, on the demo build.
// Each scenario is checked for what the person sees and, where a page is new or changed, for axe.

async function clean(page: Page, name: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${name}\n${bad.join('\n')}`).toEqual([]);
}

const pageErrors = (page: Page): (() => string[]) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  return () => errors;
};

for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test.describe(`usability 4, ${theme} ${width}px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test.beforeEach(async ({ page }) => {
      await prepare(page, theme);
    });

    test('M1: the new rule editor of a group without states opens with a message, not a skeleton', async ({ page }) => {
      const errors = pageErrors(page);
      await page.addInitScript(() => localStorage.setItem('tt.group', 'reports'));
      await loginAs(page);
      await go(page, '#/rules');
      await page.getByRole('button', { name: 'New rule', exact: true }).click();
      const dlg = page.locator('dialog[open]').last();
      await expect(dlg.getByTestId('no-states')).toBeVisible();
      await expect(dlg.getByRole('textbox', { name: /title/i }).first()).toBeVisible();
      await expect(dlg.locator('[aria-busy="true"]')).toHaveCount(0);
      await page.waitForTimeout(300);
      await clean(page, 'rule editor without states');
      expect(errors()).toEqual([]);
    });

    test('M2: the policy assistant and the bulk review render once per row', async ({ page }) => {
      const errors = pageErrors(page);
      await loginAs(page);
      await go(page, '#/onboarding?group=shop-api&step=3');
      await expect(page.getByRole('button', { name: 'Next, policy assistant' })).toBeVisible({ timeout: 45_000 });
      await clean(page, 'policy assistant');
      await go(page, '#/sources?tab=policy&bulk=1');
      await expect(page.locator('dialog[open]')).toBeVisible();
      await expect(page.locator('dialog[open] [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
      expect(errors().filter((e) => /each_key_duplicate/.test(e))).toEqual([]);
    });

    test('m6: a link to an advanced step without a group says what is needed', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/onboarding?step=4');
      await expect(page.getByTestId('needs-group')).toBeVisible();
      await clean(page, 'wizard ?step=4 without group');
    });

    test('m2: a non-admin starts on «My groups»', async ({ page }) => {
      await page.goto('/#/login');
      await page.getByRole('button', { name: 'Operator', exact: true }).click();
      await expect(page.locator('header').first()).toBeVisible();
      await go(page, '#/sources');
      await expect(page.getByRole('combobox', { name: 'Group/team filter' })).toHaveValue('@mine');
    });

    test('B1: the Panoramica shows the next step for a draft waiting for approval, with a message to copy', async ({ page }) => {
      await loginAs(page);
      await go(page, '#/home');
      const card = page.getByTestId('approval-next-step');
      await expect(card).toBeVisible();
      await expect(card.getByTestId('approver-help').first()).toBeVisible();
      await card.getByText('Message for the approver').first().click();
      await expect(card.getByTestId('approver-message').first()).toContainText('#/sources?tab=policy&draft=');
      await clean(page, 'home with next step');
    });
  });
}
