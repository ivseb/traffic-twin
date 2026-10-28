// REST adapter: the endpoints for the users of an installed console (gate keys, scope, contract status, key check)
// and the localization of the server texts.
import { describe, expect, it, vi } from 'vitest';
import { createRestApi } from './adapter';
import { json, noSleep, on, scripted, text, type Recorded } from './testkit';
import { localizeSnippet, snippetTitle, SNIPPET_COMMENTS } from './snippets';
import { mapToken } from './map';
import { setLang, tk } from '../../i18n/index.svelte';

function make(...h: Parameters<typeof scripted>) {
  const s = scripted(...h);
  const api = createRestApi({ fetch: s.fetch, sleep: noSleep, onUnauthorized: vi.fn(), eventSource: null, pollMs: 5, now: () => new Date('2026-10-24T09:30:00Z'), docTtlMs: 0 });
  return { api, ...s };
}
const body = (r: Recorded) => JSON.parse(r.body ?? 'null') as Record<string, unknown>;

const SRC = {
  source_id: 'src-1',
  kind: 'sdk-node',
  version: '0.1.0',
  service_name: 'bookings-api',
  group: 'bookings',
  state: 'no_policy',
  killed: false,
  revoked: false,
  last_seen: '2026-10-24T09:29:00Z',
  events_per_min: 0,
  drop_ratio: 0,
  sanitizer_errors: 0,
  sampling_override_bp: null,
  last_errors: [],
  problems: [{ code: 'no_policy', message: 'the source has no policy and does not capture', hint: 'assign a policy to the group and approve it' }],
};

describe('installed console', () => {
  it('reads the gate keys and the gate-keys.txt file', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/gate/keys', (r) =>
        r.query.get('format') === 'txt' ? text('# x\npack-1:abc\n') : json({ tt_gate_pubkeys: 'pack-1:abc', command: "TT_GATE_PUBKEYS='pack-1:abc' tt mock --pack <file.ttpack>", keys: [{ kid: 'pack-1', public_key: 'abc' }] }),
      ),
    );
    expect(await api.gate.keys()).toEqual({ value: 'pack-1:abc', command: "TT_GATE_PUBKEYS='pack-1:abc' tt mock --pack <file.ttpack>", keys: [{ kid: 'pack-1', publicKey: 'abc' }] });
    const f = await api.gate.keyFile();
    expect(f.filename).toBe('gate-keys.txt');
    expect(await f.blob.text()).toContain('pack-1:abc');
    expect(calls.at(-1)?.query.get('format')).toBe('txt');
  });

  it('maps the contract status and asks for a snapshot of the recent window', async () => {
    const { api, calls } = make(
      on('GET', '/api/v1/contracts/bookings-api/status', json({ service: 'bookings-api', calls: 40000, operations: 4, ready_operations: 3, best_op_calls: 21000, min_calls: 20, k_min: 20, inferred_operations: 3, snapshot: null, next_snapshot_at: '2026-10-25T00:05:00Z', window_hours: 24 })),
      on('POST', '/api/v1/contracts/bookings-api/snapshots', json({}, 201)),
    );
    const st = await api.contracts.status('bookings-api');
    expect(st).toMatchObject({ calls: 40000, readyOperations: 3, minCalls: 20, inferredOperations: 3, snapshot: undefined, windowHours: 24 });
    await api.contracts.refreshNow('bookings-api');
    expect(body(calls.at(-1)!)).toEqual({ recent: true });
  });

  it('sends the services of the group filter with a pack build', async () => {
    const { api, calls } = make(on('POST', '/api/v1/packs', json({ status: 'done', result: { pack_id: 'pk-1', status: 'signed', created_at: '2026-10-24T09:00:00Z', published_at: null } })));
    await api.publications.run('w-1', { services: ['bookings-api', 'payments-ext'] });
    expect(body(calls.find((c) => c.method === 'POST' && c.path === '/api/v1/packs')!)).toEqual({ world_id: 'w-1', services: ['bookings-api', 'payments-ext'] });
  });

  it('translates source problems and adds the HMAC key check', async () => {
    setLang('it');
    try {
      const { api } = make(
        on('GET', '/api/v1/fleet/sources', json([SRC])),
        on('GET', '/api/v1/fleet/policies', json([])),
        on('GET', '/api/v1/sources/key-check', json({ reachable: true, keyguard_kids: ['k1'], sources: [{ source_id: 'src-1', unknown_kids: ['k9'] }] })),
      );
      const [s] = await api.sources.list();
      expect(s.problems.map((p) => p.code)).toEqual(['no_policy', 'hmac_kid_unknown']);
      expect(s.problems[0].message).toBe('Nessuna policy ricevuta');
      expect(s.problems[0].hint).not.toMatch(/assign a policy/);
      expect(s.problems[1].message).toContain('k9');
      expect(s.problems[1].message).toContain('sconosciuta a keyguard');
    } finally {
      setLang('en');
    }
  });

  it('marks the host patterns that a policy has declared since', async () => {
    const { api } = make(
      on('GET', '/api/v1/services', json([{ service: 'host:ip:private:9101', kind: 'outbound-host', calls: 10, ops: 1, in_policy: false, first_seen: '2026-10-24T08:00:00Z', last_seen: '2026-10-24T08:10:00Z', twin: true }])),
      on('GET', '/api/v1/fleet/sources', json([])),
      on('GET', '/api/v1/hosts', json({ domains: [{ domain: 'ip:private', calls: 10, first_seen: null, last_seen: null, patterns: [{ pattern: 'ip:private:9101', service: 'host:ip:private:9101', declared: false, exact: false, quarantined: false, calls: 10, server_errors: 0, client_errors: 0, error_rate: 0, latency_p50_ms: null, first_seen: null, last_seen: null, now_declared_as: 'payments-ext' }] }] })),
    );
    const [s] = await api.services.list();
    expect(s.nowDeclaredAs).toBe('payments-ext');
  });

  it('localizes the install snippets', () => {
    setLang('it');
    try {
      const key = Object.keys(SNIPPET_COMMENTS)[0];
      const out = localizeSnippet(`${key}\nnpm install @traffic-twin/sdk\n          # node | python | java | dotnet | go | php: one token serves all of them`);
      expect(out).not.toContain(key);
      expect(out).toContain('Chiave HMAC');
      expect(out).toContain('un solo token vale per tutti');
      expect(out).toContain('npm install @traffic-twin/sdk');
      expect(snippetTitle('node', 'Node.js (20+; full fetch body capture on 24+)')).toBe(tk('snip.t.node'));
      expect(snippetTitle('future', 'Something new')).toBe('Something new');
      const tok = mapToken({ token_id: 't', token: 'tte_x', expires_at: '2026-10-24T10:30:00Z', snippets: [{ id: 'node', title: 'Node.js', language: 'bash', text: key }] }, 'sdk-node', 'bookings');
      expect(tok.snippets[0].title).toContain('Node.js (20+');
      expect(tok.snippets[0].text).toContain('Chiave HMAC');
    } finally {
      setLang('en');
    }
  });
});
