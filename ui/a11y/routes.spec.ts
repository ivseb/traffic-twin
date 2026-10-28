import { expect, test } from '@playwright/test';
import { axeViolations, go, loginAs, prepare, runAxe, THEMES, WIDTHS } from './axe';

// axe-core on every route (and every tab / wizard step) of the demo build, logged in as administrator,
// in both themes and at three widths. Fails on serious/critical violations (and the structural rules
// listed in axe.ts).
export const ROUTES: [string, string][] = [
  ['home', '#/home'],
  ['onboarding', '#/onboarding'],
  ['sources', '#/sources'],
  ['sources policy', '#/sources?tab=policy'],
  ['services', '#/services'],
  ['hosts', '#/hosts'],
  ['contracts', '#/contracts'],
  ['contracts per service', '#/contracts/service/shipping-ext'],
  ['contracts per service snapshots', '#/contracts/service/shipping-ext?tab=snapshots'],
  ['contracts per service openapi', '#/contracts/service/shipping-ext?tab=openapi'],
  ['contracts per service id formats', '#/contracts/service/shipping-ext?tab=ids'],
  ['contracts per service relative dates', '#/contracts/service/shipping-ext?tab=dates'],
  ['mock', '#/mock'],
  ['mock saved scenarios', '#/mock?tab=saved'],
  ['rules detail', '#/rules/r-0007'],
  ['rules', '#/rules'],
  ['archetypes', '#/archetypes'],
  ['gaps', '#/gaps'],
  ['worlds', '#/worlds'],
  ['packs', '#/packs'],
  ['scenarios', '#/scenarios'],
  ['alerts', '#/alerts'],
  ['alerts webhooks', '#/alerts?tab=webhooks'],
  ['quarantine', '#/quarantine'],
  ['events', '#/events'],
  ['audit', '#/audit'],
  ['users', '#/users'],
  ['users roles', '#/users?tab=roles'],
  ['settings general', '#/settings?tab=general'],
  ['settings privacy', '#/settings?tab=privacy'],
  ['settings approvals', '#/settings?tab=approvals'],
  ['settings access', '#/settings?tab=access'],
  ['settings keys', '#/settings?tab=keys'],
  ['settings keyguard', '#/settings?tab=keyguard'],
  ['settings data', '#/settings?tab=data'],
  ['settings appearance', '#/settings?tab=appearance'],
  ['glossary', '#/glossary'],
  ['not found', '#/does-not-exist'],
];

for (const theme of THEMES) {
  for (const width of WIDTHS) {
    test.describe(`${theme} ${width}px`, () => {
      test.use({ viewport: { width, height: 900 } });
      test.beforeEach(async ({ page }) => {
        await prepare(page, theme);
      });

      test('login', async ({ page }) => {
        await page.goto('/#/login');
        await page.locator('main').waitFor();
        await runAxe(page, `login ${theme} ${width}`);
      });

      test('setup (first run)', async ({ page }) => {
        await page.goto('/#/login');
        await page.getByRole('button', { name: /first run/i }).click();
        await page.waitForURL(/#\/setup/);
        await page.locator('main h1').waitFor();
        await runAxe(page, `setup ${theme} ${width}`);
      });

      test('every route', async ({ page }) => {
        test.setTimeout(240_000);
        await loginAs(page);
        const failures: string[] = [];
        for (const [name, hash] of ROUTES) {
          await go(page, hash);
          const bad = await axeViolations(page);
          if (bad.length) failures.push(`== ${name} (${hash}) ${theme} ${width}\n${bad.join('\n')}`);
        }
        if (failures.length) throw new Error(failures.join('\n\n'));
      });
    });
  }
}

// The same sweep in Italian (the default language of the product): <html lang="it"> and the longer texts.
for (const [theme, width] of [['light', 1280], ['dark', 390]] as const) {
  test(`italian: every route, ${theme} ${width}px`, async ({ page }) => {
    test.setTimeout(240_000);
    await page.setViewportSize({ width, height: 900 });
    await prepare(page, theme, 'it');
    await page.goto('/#/login');
    await page.getByRole('button', { name: 'Amministratore', exact: true }).click();
    await page.locator('header').first().waitFor();
    await expect(page.locator('html')).toHaveAttribute('lang', 'it');
    const failures: string[] = [];
    for (const [name, hash] of ROUTES) {
      await go(page, hash);
      const bad = await axeViolations(page);
      if (bad.length) failures.push(`== ${name} (${hash}) it ${theme} ${width}\n${bad.join('\n')}`);
    }
    if (failures.length) throw new Error(failures.join('\n\n'));
  });
}
