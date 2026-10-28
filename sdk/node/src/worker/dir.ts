// Directory of the compiled worker files. This source is the CommonJS flavour; scripts/build.mjs
// replaces dist/esm/worker/dir.js with an import.meta.url based one (tsc cannot emit both).

export function workerDir(): string {
  return __dirname;
}
