/// <reference types="vitest/config" />
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// The prebuilt Redoc bundle draws a "powered by" footer image from https://cdn.redoc.ly. The CSP forbids
// it, and no request to a third party should even be attempted from a page that shows our contracts:
// the address is replaced in the copied asset by an empty data URL.
const redocOffline = (): Plugin => ({
  name: 'tt-redoc-offline',
  generateBundle(_o, bundle) {
    for (const f of Object.values(bundle)) {
      if (f.type !== 'asset' || !f.fileName.includes('redoc.standalone')) continue;
      const text = typeof f.source === 'string' ? f.source : new TextDecoder().decode(f.source);
      f.source = text.replaceAll('https://cdn.redoc.ly/redoc/logo-mini.svg', 'data:,');
    }
  },
});

// Two flavours of the same app:
//
//   npm run build        production: written into internal/ui/dist and embedded in
//                        the tt binary. Talks to tt-core only. The `tt-demo` module
//                        resolves to an empty stub, so the mock adapter, its fixtures,
//                        the demo role buttons and the demo texts are not part of the bundle.
//   npm run build:demo   (mode "demo", or VITE_TT_MOCK=1) in-memory mock adapter with
//                        invented data and one-click role logins, written into dist-demo/.
//                        Used for previews, never embedded.
export default defineConfig(({ mode }) => {
  const demo = mode === 'demo' || process.env.VITE_TT_MOCK === '1';
  return {
    plugins: [svelte(), redocOffline()],
    resolve: {
      alias: [{ find: /^tt-demo$/, replacement: here(demo ? './src/demo/index.ts' : './src/demo/stub.ts') }],
    },
    build: {
      // The production output is embedded into the tt binary by internal/ui (go:embed),
      // so it is written straight into that package. emptyOutDir wipes the tracked
      // dist/.gitkeep, so public/.gitkeep is copied back on every build.
      outDir: demo ? 'dist-demo' : '../internal/ui/dist',
      emptyOutDir: true,
      sourcemap: false,
      // Two documents: the app (strict CSP) and the OpenAPI viewer page (scoped CSP).
      rollupOptions: { input: { main: 'index.html', viewer: 'viewer.html' } },
    },
    test: {
      environment: 'node',
      css: true,
      include: ['src/**/*.test.ts'],
    },
  };
});
