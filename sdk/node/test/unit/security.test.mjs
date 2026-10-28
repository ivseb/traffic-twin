// Red team round 2 regressions at unit level: kill switch vs held batches, state file trust.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Exporter } from '../../dist/esm/export/exporter.js';
import { StateStore } from '../../dist/esm/fleet/store.js';
import { generateCsr } from '../../dist/esm/fleet/asn1.js';
import { startFakeCore } from '../helpers/fake-core.mjs';

test('clear() (kill switch) drops a batch that is waiting to be retried', async () => {
  const core = await startFakeCore();
  try {
    const { csrPem, keyPem } = generateCsr('src-k');
    const agent = new https.Agent({ cert: core.pki.issueFromCsr(csrPem, 'src-k'), key: keyPem, ca: core.pki.caPem });
    const c = { events_sent: 0, events_dropped_queue: 0, events_rejected: 0, send_errors: 0 };
    const ex = new Exporter({ url: core.url + '/v1/logs', agent, resource: { serviceName: 's', sourceId: 'src-k' }, counters: c, onError: () => {}, baseBackoffMs: 400, flushMs: 60_000 });
    core.state.failLogs = 1;
    ex.enqueue({ json: '{"a":1}', tsMs: Date.now(), policyHash: 'sha256:x' });
    const flushing = ex.flush();
    await new Promise((r) => setTimeout(r, 150)); // first attempt failed, backing off
    ex.clear();
    await flushing;
    await new Promise((r) => setTimeout(r, 700));
    assert.equal(c.events_sent, 0);
    assert.equal(core.state.eventStrings.length, 0, 'nothing delivered after clear()');
    assert.equal(c.events_dropped_queue, 1);
    ex.stop();
    agent.destroy();
  } finally {
    await core.close();
  }
});

function scratch() {
  const d = mkdtempSync(join(tmpdir(), 'tt-store-'));
  return { d, done: () => rmSync(d, { recursive: true, force: true }) };
}

test('state files: a file open to others, owned by someone else or a symlink is not trusted', { skip: process.platform === 'win32' }, () => {
  const t = scratch();
  try {
    chmodSync(t.d, 0o700);
    const seen = [];
    const store = new StateStore(t.d);
    store.onUntrusted = (w) => seen.push(w);
    store.writeText('a.json', '{"ok":1}');
    assert.equal(store.readText('a.json'), '{"ok":1}');
    // group/other readable: refused
    chmodSync(join(t.d, 'a.json'), 0o644);
    assert.equal(store.readText('a.json'), null);
    assert.deepEqual(seen, ['a.json']);
    // symlink in place of a state file: not followed
    writeFileSync(join(t.d, 'real'), 'x', { mode: 0o600 });
    symlinkSync(join(t.d, 'real'), join(t.d, 'link'));
    assert.equal(store.readText('link'), null);
    // a pre-existing directory open to others and owned by us is tightened, then trusted
    chmodSync(t.d, 0o755);
    store.writeText('b.json', '{"b":2}');
    assert.equal(store.readText('b.json'), '{"b":2}');
  } finally {
    t.done();
  }
});
