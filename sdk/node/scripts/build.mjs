// Builds dist/esm (ES modules) and dist/cjs (CommonJS) with the pinned TypeScript compiler.
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
rmSync(join(root, 'dist'), { recursive: true, force: true });
for (const cfg of ['tsconfig.json', 'tsconfig.cjs.json']) {
  execFileSync(process.execPath, [tsc, '-p', join(root, cfg)], { stdio: 'inherit', cwd: root });
}
mkdirSync(join(root, 'dist', 'cjs'), { recursive: true });
writeFileSync(join(root, 'dist', 'cjs', 'package.json'), '{"type":"commonjs"}\n');
writeFileSync(join(root, 'dist', 'esm', 'package.json'), '{"type":"module"}\n');
// tsc emits one source for both module formats: the ESM flavour of worker/dir needs import.meta.
writeFileSync(join(root, 'dist', 'esm', 'worker', 'dir.js'), "import { dirname } from 'node:path';\nimport { fileURLToPath } from 'node:url';\nexport function workerDir() {\n    return dirname(fileURLToPath(import.meta.url));\n}\n");
