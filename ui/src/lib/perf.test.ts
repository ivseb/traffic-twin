// Regression tests of the performance guard rails of the UI (docs/PERFORMANCE.md).
import { describe, expect, it } from 'vitest';
import { diffLines, diffStats, MAX_DIFF_CELLS } from './diff';
import { Http } from './api/rest/http';
import { err, json, noSleep, on, scripted } from './api/rest/testkit';
import { followJob, JOB_POLL_MS } from './api/rest/adapter';

describe('followJob', () => {
  it('polls a running job until it is done', async () => {
    let n = 0;
    const s = scripted(
      on('GET', '/api/v1/jobs/job_1', () =>
        json(++n < 3 ? { job_id: 'job_1', kind: 'rules.mine', status: 'running' } : { job_id: 'job_1', kind: 'rules.mine', status: 'done', result: { new: 4 } }),
      ),
    );
    const http = new Http({ fetch: s.fetch, sleep: noSleep });
    const waits: number[] = [];
    const done = await followJob(http, { job_id: 'job_1', kind: 'rules.mine', status: 'running' }, async (ms) => void waits.push(ms));
    expect(done.status).toBe('done');
    expect(done.result).toEqual({ new: 4 });
    expect(s.calls).toHaveLength(3);
    expect(waits).toEqual([JOB_POLL_MS[0], JOB_POLL_MS[1], JOB_POLL_MS[2]]);
  });
  it('returns a finished job without polling', async () => {
    const s = scripted();
    const http = new Http({ fetch: s.fetch, sleep: noSleep });
    expect((await followJob(http, { job_id: 'j', kind: 'k', status: 'done' })).status).toBe('done');
    expect(s.calls).toHaveLength(0);
  });
});

describe('diffLines on large documents', () => {
  it('keeps exact line numbers around a change in the middle of a long text', () => {
    const before = Array.from({ length: 50_000 }, (_, i) => `line ${i}`);
    const after = [...before];
    after[25_000] = 'changed';
    const t0 = performance.now();
    const lines = diffLines(before.join('\n'), after.join('\n'));
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(diffStats(lines)).toEqual({ added: 1, removed: 1 });
    const del = lines.find((l) => l.kind === 'del')!;
    const add = lines.find((l) => l.kind === 'add')!;
    expect([del.oldNo, add.newNo]).toEqual([25_001, 25_001]);
    expect(lines.at(-1)).toEqual({ kind: 'same', text: 'line 49999', oldNo: 50_000, newNo: 50_000 });
  });
  it('degrades to a replacement instead of allocating a huge table', () => {
    const side = Math.ceil(Math.sqrt(MAX_DIFF_CELLS)) + 10;
    const a = Array.from({ length: side }, (_, i) => `a${i}`).join('\n');
    const b = Array.from({ length: side }, (_, i) => `b${i}`).join('\n');
    const lines = diffLines(a, b);
    expect(diffStats(lines)).toEqual({ added: side, removed: side });
  });
  it('still finds a minimal diff in a small middle', () => {
    const lines = diffLines('h\na\nb\nc\nt', 'h\na\nc\nd\nt');
    expect(lines.map((l) => `${l.kind}:${l.text}:${l.oldNo ?? ''}:${l.newNo ?? ''}`)).toEqual([
      'same:h:1:1',
      'same:a:2:2',
      'del:b:3:',
      'same:c:4:3',
      'add:d::4',
      'same:t:5:5',
    ]);
  });
});

describe('Http GET sharing', () => {
  it('sends one request for identical concurrent GETs, each caller gets its own copy', async () => {
    const s = scripted(on('GET', '/api/v1/hosts', json({ items: [1, 2] })));
    const http = new Http({ fetch: s.fetch, sleep: noSleep });
    const [a, b] = await Promise.all([http.get<{ items: number[] }>('/api/v1/hosts'), http.get<{ items: number[] }>('/api/v1/hosts')]);
    expect(s.calls).toHaveLength(1);
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    a.items.push(3);
    expect(b.items).toEqual([1, 2]);
    await http.get('/api/v1/hosts'); // finished requests are not cached
    expect(s.calls).toHaveLength(2);
  });
  it('does not retry a 504 (a slow request is not repeated)', async () => {
    const s = scripted(on('GET', '/a', err(504, 'timeout')));
    const http = new Http({ fetch: s.fetch, sleep: noSleep });
    await expect(http.get('/a')).rejects.toThrow();
    expect(s.calls).toHaveLength(1);
  });
});
