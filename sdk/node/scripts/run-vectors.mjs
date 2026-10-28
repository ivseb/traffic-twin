// Runs every conformance vector against the built SDK sanitizer and compares byte for byte.
//
//   node scripts/run-vectors.mjs [--dir <conformance dir>] [--verbose] [id-prefix ...]
//
// Exit code 0 only if every selected vector passes. Mismatches print the vector id and both
// byte strings (conformance/README.md, "Writing a runner").

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseVector, runVector } from '../dist/esm/sanitizer/vectors.js';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let dir = resolve(here, '..', '..', '..', 'conformance');
let verbose = false;
const prefixes = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--dir') dir = resolve(args[++i]);
  else if (args[i] === '--verbose' || args[i] === '-v') verbose = true;
  else prefixes.push(args[i]);
}

const files = readdirSync(join(dir, 'vectors')).filter((f) => f.endsWith('.json')).sort();
let pass = 0;
let fail = 0;
const failed = [];
for (const f of files) {
  const id = f.slice(0, -5);
  if (prefixes.length && !prefixes.some((p) => id.startsWith(p))) continue;
  const vec = parseVector(readFileSync(join(dir, 'vectors', f)));
  const exp = vec.expected;
  let got;
  try {
    got = runVector(vec, dir);
  } catch (e) {
    got = { outcome: 'error', error: String(e && e.stack || e) };
  }
  let ok = got.outcome === exp.outcome;
  if (ok && exp.outcome === 'event') ok = Buffer.from(got.canonical, 'utf8').equals(Buffer.from(exp.canonical, 'utf8'));
  if (ok && exp.outcome === 'not_sampled') ok = got.sampled_by === exp.sampled_by;
  if (ok && exp.outcome === 'refused') ok = got.code === exp.code;
  if (ok) {
    pass++;
    if (verbose) console.log('PASS', id);
    continue;
  }
  fail++;
  failed.push(id);
  console.log('FAIL', id);
  const e = exp.outcome === 'event' ? exp.canonical : JSON.stringify(exp);
  const g = got.outcome === 'event' ? got.canonical : JSON.stringify(got);
  if (verbose || (e.length <= 2000 && g.length <= 2000)) {
    console.log('  expected:', e);
    console.log('  got:     ', g);
  } else {
    let d = 0;
    while (d < e.length && e[d] === g[d]) d++;
    const from = Math.max(0, d - 150);
    console.log(`  first difference at byte ${d} (expected ${e.length} bytes, got ${g.length} bytes)`);
    console.log('  expected: …' + e.slice(from, d + 250));
    console.log('  got:      …' + g.slice(from, d + 250));
  }
}
console.log(`\nvectors: ${pass} passed, ${fail} failed, ${pass + fail} total`);
if (fail) console.log('failed:', failed.join(' '));
process.exit(fail ? 1 : 0);
