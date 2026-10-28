import { createRequire } from 'node:module';
import { expect, type Page } from '@playwright/test';

const require = createRequire(import.meta.url);
const AXE_PATH = require.resolve('axe-core/axe.min.js');

export const WIDTHS = [390, 1280, 1440] as const;
export const THEMES = ['light', 'dark'] as const;
export type Theme = (typeof THEMES)[number];

interface AxeNode {
  target: unknown[];
  html: string;
  failureSummary?: string;
}
interface AxeViolation {
  id: string;
  impact?: string | null;
  help: string;
  helpUrl: string;
  nodes: AxeNode[];
}

// Fail on every violation of impact serious or critical. The structural rules below are only
// "moderate" in axe but we promised to keep them green (landmarks, heading order, language, ...).
const ALWAYS_FAIL = new Set([
  'heading-order',
  'landmark-one-main',
  'landmark-unique',
  'landmark-no-duplicate-main',
  'landmark-main-is-top-level',
  'landmark-banner-is-top-level',
  'landmark-contentinfo-is-top-level',
  'landmark-complementary-is-top-level',
  'landmark-no-duplicate-banner',
  'landmark-no-duplicate-contentinfo',
  'page-has-heading-one',
  'region',
  'bypass',
  'html-has-lang',
  'html-lang-valid',
  'tabindex',
  'duplicate-id-aria',
  'aria-allowed-role',
  'scope-attr-valid',
]);

/** Runs axe on the current page and returns the failing violations as readable text (empty when clean). */
export async function axeViolations(page: Page): Promise<string[]> {
  await page.addScriptTag({ path: AXE_PATH });
  const result = await page.evaluate(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axe = (window as any).axe;
    return axe.run(document, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] },
      resultTypes: ['violations'],
    });
  });
  const bad = (result.violations as AxeViolation[]).filter((v) => v.impact === 'serious' || v.impact === 'critical' || ALWAYS_FAIL.has(v.id));
  return bad.map(
    (v) =>
      `[${v.impact}] ${v.id}: ${v.help}\n` +
      v.nodes
        .slice(0, 6)
        .map((n) => `    ${JSON.stringify(n.target)}\n      ${n.html.slice(0, 160)}\n      ${(n.failureSummary ?? '').replace(/\n/g, ' | ').slice(0, 300)}`)
        .join('\n'),
  );
}

export async function runAxe(page: Page, label: string): Promise<void> {
  const bad = await axeViolations(page);
  expect(bad, `axe violations on ${label}\n${bad.join('\n')}`).toEqual([]);
}

/** Demo login through the one-click role buttons of the login page. */
export async function loginAs(page: Page, role = 'Administrator'): Promise<void> {
  await page.goto('/#/login');
  await page.getByRole('button', { name: role, exact: true }).click();
  await expect(page.locator('header').first()).toBeVisible();
}

/** Sets theme and language before the app boots (it reads them from localStorage). */
export async function prepare(page: Page, theme: Theme, lang: 'en' | 'it' = 'en'): Promise<void> {
  await page.addInitScript(
    ([th, lg]) => {
      localStorage.setItem('tt.theme', th);
      localStorage.setItem('tt.lang', lg);
    },
    [theme, lang],
  );
  await page.emulateMedia({ colorScheme: theme });
}

/** Navigates the hash router and waits for the lazy page to render. */
export async function go(page: Page, hash: string): Promise<void> {
  await page.evaluate((h) => {
    location.hash = h;
  }, hash);
  await page.locator('main').first().waitFor();
  await page.waitForFunction(() => !document.querySelector('main .skeleton, main [aria-busy="true"]'));
  await page.waitForTimeout(300);
}
