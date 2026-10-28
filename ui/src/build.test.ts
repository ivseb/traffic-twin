// Builds the app twice (as `npm run build` and `npm run build:demo` do) and checks that the
// production bundle, the one embedded in the tt binary, contains nothing of the demo:
// no mock adapter, no fixtures, no demo role buttons, no demo password hint.

import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build } from 'vite';

const root = fileURLToPath(new URL('..', import.meta.url));

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

/** Everything that is text in the output, as one string per file. */
function bundle(dir: string): Map<string, string> {
  return new Map(files(dir).filter((f) => /\.(js|css|html|svg|json)$/.test(f)).map((f) => [f, readFileSync(f, 'utf8')]));
}

// Strings that only exist in the mock adapter, its fixtures and the demo components.
// (Identifiers are minified; literals and property names are not.)
const DEMO_MARKERS = [
  'olga.operator',
  'elena.admin',
  'rita.reviewer',
  'paolo.approver',
  'pia.publisher',
  'pk-20261019-0001',
  'shipping.example',
  'tt.mock.user',
  'loginAs',
  'resetFirstRun',
  'Modalità dimostrativa',
  'Ambiente dimostrativo',
  'Demo mode',
  'Demo environment',
  'password “demo”',
  'password «demo»',
  'Simula il primo avvio',
  'Simulate first run',
  'demo.login',
];

let prod: Map<string, string>;
let demo: Map<string, string>;
const dirs: string[] = [];

async function run(mode: string): Promise<Map<string, string>> {
  const out = mkdtempSync(join(tmpdir(), `tt-ui-${mode}-`));
  dirs.push(out);
  delete process.env.VITE_TT_MOCK;
  await build({ root, mode, logLevel: 'silent', build: { outDir: out, emptyOutDir: true, write: true } });
  return bundle(out);
}

beforeAll(async () => {
  prod = await run('production');
  demo = await run('demo');
}, 240_000);

afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

describe('production bundle (embedded in the tt binary)', () => {
  it('has the two documents and scripts', () => {
    const names = [...prod.keys()].map((f) => f.split('/').pop());
    expect(names).toContain('index.html');
    expect(names).toContain('viewer.html');
    expect([...prod.keys()].some((f) => f.endsWith('.js'))).toBe(true);
  });
  it.each(DEMO_MARKERS)('does not contain %j', (marker) => {
    const hits = [...prod].filter(([, text]) => text.includes(marker)).map(([f]) => f);
    expect(hits).toEqual([]);
  });
  it('does not contain the mock adapter module or the demo components by name', () => {
    // By file name: the "Usa il mock" page is a real page of the product (Mock-<hash>.js), the adapter and the demo are not.
    for (const f of prod.keys()) expect(f.split('/').pop()).not.toMatch(/^(mock-?adapter|fixture|demo)/i);
  });
  it('talks to tt-core: the REST paths are in the bundle', () => {
    const all = [...prod.values()].join('\n');
    for (const p of ['/api/v1/auth/login', '/api/v1/fleet', '/api/v1/audit/export', '/api/v1/contracts/']) expect(all.includes(p), p).toBe(true);
  });
});

describe('test tooling', () => {
  // axe-core (MPL-2.0) is a devDependency of the a11y suite only: it is injected by Playwright, never imported by src/.
  it.each(['axe-core', 'axe.run', 'Deque Systems'])('no bundle, production or demo, contains %j', (marker) => {
    const hits = [...prod, ...demo].filter(([, text]) => text.includes(marker)).map(([f]) => f);
    expect(hits).toEqual([]);
  });
});

describe('no third party', () => {
  it('the bundle (Redoc included) never names a CDN to load anything from', () => {
    const hits = [...prod].filter(([, text]) => text.includes('cdn.redoc.ly')).map(([f]) => f);
    expect(hits).toEqual([]);
  });
});

describe('demo bundle (previews)', () => {
  it('does contain the mock adapter and the demo texts, so the check above can fail', () => {
    const all = [...demo.values()].join('\n');
    for (const marker of ['olga.operator', 'loginAs', 'Modalità dimostrativa', 'Demo mode', 'tt.mock.user']) expect(all.includes(marker), marker).toBe(true);
  });
});
