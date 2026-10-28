import { describe, expect, it } from 'vitest';
const files = import.meta.glob('../app.css', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const css = Object.values(files)[0] ?? '';

// WCAG AA (4.5:1) for every text/background pair the design system uses, in both themes.
function tokens(): Record<'light' | 'dark', Record<string, string>> {
  const out = { light: {} as Record<string, string>, dark: {} as Record<string, string> };
  for (const m of css.matchAll(/--([a-z0-9-]+):\s*light-dark\(\s*(#[0-9a-f]{6})\s*,\s*(#[0-9a-f]{6})\s*\)/gi)) {
    out.light[m[1]] = m[2];
    out.dark[m[1]] = m[3];
  }
  return out;
}

function lum(hex: string): number {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
export function ratio(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const PAIRS: [string, string][] = [
  ['fg', 'bg'], ['fg', 'surface'], ['fg', 'surface-2'], ['fg', 'surface-3'],
  ['fg-muted', 'bg'], ['fg-muted', 'surface'], ['fg-muted', 'surface-2'], ['fg-muted', 'surface-3'],
  ['fg-subtle', 'bg'], ['fg-subtle', 'surface'], ['fg-subtle', 'surface-2'],
  ['accent', 'bg'], ['accent', 'surface'], ['accent', 'surface-2'], ['accent', 'accent-soft'], ['accent-strong', 'surface'],
  ['accent-fg', 'accent'],
  ['success', 'success-soft'], ['success', 'surface'],
  ['warning', 'warning-soft'], ['warning', 'surface'],
  ['danger', 'danger-soft'], ['danger', 'surface'],
  ['info', 'info-soft'], ['info', 'surface'],
  ['fg', 'diff-add'], ['fg', 'diff-del'],
];

// Non-text contrast (1.4.11): the edge of a control and the focus ring need 3:1 against the surfaces they sit on.
const NON_TEXT: [string, string][] = [
  ['control-border', 'bg'], ['control-border', 'surface'], ['control-border', 'surface-2'], ['control-border', 'surface-3'],
  ['focus', 'bg'], ['focus', 'surface'], ['focus', 'surface-2'], ['focus', 'surface-3'], ['focus', 'accent-soft'],
];

describe('WCAG AA contrast', () => {
  const t = tokens();
  it('parses the tokens', () => {
    expect(Object.keys(t.light).length).toBeGreaterThan(20);
  });
  for (const theme of ['light', 'dark'] as const) {
    for (const [fg, bg] of PAIRS) {
      it(`${theme}: ${fg} on ${bg}`, () => {
        expect(ratio(t[theme][fg], t[theme][bg])).toBeGreaterThanOrEqual(4.5);
      });
    }
  }
  for (const theme of ['light', 'dark'] as const) {
    for (const [fg, bg] of NON_TEXT) {
      it(`${theme}: ${fg} on ${bg} (non-text, 3:1)`, () => {
        expect(ratio(t[theme][fg], t[theme][bg])).toBeGreaterThanOrEqual(3);
      });
    }
  }
});
