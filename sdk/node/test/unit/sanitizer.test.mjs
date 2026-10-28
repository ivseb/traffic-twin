import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, deflateSync } from 'node:zlib';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Sanitizer, decodeBody, normalizeFrameworkRoute, normalizeUrlBase, MAX_EVENT_BYTES } from '../../dist/esm/sanitizer/sanitizer.js';
import { hostLabelSafe, hostPattern, parseIpv6 } from '../../dist/esm/sanitizer/hostpat.js';
import { Policy, Refused, parseKeyRing, selectKey, validateBodySchema } from '../../dist/esm/sanitizer/policy.js';
import { parseVector, runVector } from '../../dist/esm/sanitizer/vectors.js';
import { Lex, nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';
const L = (n) => new Lex(String(n));
import { ROOT } from '../helpers/procs.mjs';

const CONF = join(ROOT, '..', '..', 'conformance');
const KEY = 'k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

test('all conformance vectors pass byte for byte', () => {
  const files = readdirSync(join(CONF, 'vectors')).filter((f) => f.endsWith('.json'));
  assert.ok(files.length > 0);
  const failed = [];
  for (const f of files) {
    const vec = parseVector(readFileSync(join(CONF, 'vectors', f)));
    const got = runVector(vec, CONF);
    const exp = vec.expected;
    const same = got.outcome === exp.outcome &&
      (exp.outcome === 'event' ? got.canonical === exp.canonical : exp.outcome === 'refused' ? got.code === exp.code : got.sampled_by === exp.sampled_by);
    if (!same) failed.push(f);
  }
  assert.deepEqual(failed, []);
});

function emptyPolicy(extra = {}) {
  return new Policy({ ...parseVector(readFileSync(join(CONF, 'policies', 'empty.json'))), ...extra });
}

function sanitizer(policy = emptyPolicy()) {
  return new Sanitizer(policy, selectKey(parseKeyRing(KEY), policy));
}

// --- G1: with the empty policy no input value appears in the output -------------------

function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

test('G1 generative: empty policy never emits an input value', () => {
  const r = rng(20261023);
  const pick = (a) => a[Math.floor(r() * a.length)];
  const words = ['giulia', 'neri', 'ORD-2026-000184', 'mario.rossi@example.com', '3912345678', 'Roma', 'via-roma-12',
    'tok_9f8e7d6c5b4a3f2e', '550e8400-e29b-41d4-a716-446655440000', 'carrier', 'CREATED', 'zx', 'Q7'];
  const value = () => {
    const w = pick(words) + (r() < 0.5 ? String(Math.floor(r() * 1e6)) : '');
    return w;
  };
  const s = sanitizer();
  for (let i = 0; i < 400; i++) {
    // Every value carries a unique marker, so a name built from the same word list (names
    // may leave, section 13) can never contain it.
    const secrets = new Set();
    const v = () => {
      const x = value() + 'Q' + secrets.size + 'q';
      secrets.add(x);
      return x;
    };
    const json = (d) => {
      const k = r();
      if (d > 3 || k < 0.4) return r() < 0.7 ? JSON.stringify(v()) : String(1e6 + Math.floor(r() * 1e9));
      if (k < 0.7) return '[' + Array.from({ length: 1 + Math.floor(r() * 3) }, () => json(d + 1)).join(',') + ']';
      return '{' + Array.from({ length: 1 + Math.floor(r() * 3) }, () => JSON.stringify(r() < 0.5 ? 'k' + Math.floor(r() * 9) : value()) + ':' + json(d + 1)).join(',') + '}';
    };
    const body = Buffer.from(json(0));
    const ex = {
      dir: r() < 0.5 ? 'inbound' : 'outbound',
      service_name: 'shop-api',
      url_base: 'https://' + pick(['api.carrier.example', 'giulia.example', 'x']) + ':8443',
      method: pick(['GET', 'POST', 'put', 'BREW']),
      raw_path: Buffer.from('/' + v() + '/' + encodeURIComponent(v())),
      raw_query: Buffer.from(`a=${encodeURIComponent(v())}&${encodeURIComponent(v())}&b=${encodeURIComponent(v())}`),
      req_headers: [['X-Customer', Buffer.from(v())], ['Cookie', Buffer.from(`sid=${v()}; ${value()}=1`)], ['Content-Type', Buffer.from('application/json')]],
      req_body: body,
      status: pick([200, 404, 500]),
      resp_headers: [['Set-Cookie', Buffer.from(`t=${v()}; Path=/`)], ['Content-Type', Buffer.from(pick(['application/json', 'application/x-www-form-urlencoded', 'text/plain']))]],
      resp_body: r() < 0.5 ? body : Buffer.from(`a=${encodeURIComponent(v())}&${v()}`),
    };
    const res = s.run(ex, Date.now());
    assert.equal(res.outcome, 'event');
    for (const sec of secrets) {
      if (sec.length < 4) continue;
      assert.ok(!res.canonical.includes(sec), `value leaked in exchange ${i}: ${sec} -> ${res.canonical}`);
    }
    for (const n of String(body).match(/[0-9]{7,}/g) ?? []) assert.ok(!res.canonical.includes(n), `number leaked: ${n}`);
  }
});

test('gzip and deflate decoding is strict and capped (9.0, A-GZIP-STRICT)', () => {
  const data = Buffer.from(JSON.stringify({ a: 'x'.repeat(5000) }));
  const gz = gzipSync(data);
  assert.deepEqual(decodeBody(gz, false, 1 << 20), data);
  assert.deepEqual(decodeBody(deflateSync(data), true, 1 << 20), data);
  assert.equal(decodeBody(gz, false, 100), 'cap');
  assert.equal(decodeBody(gz.subarray(0, gz.length - 4), false, 1 << 20), null, 'truncated');
  assert.equal(decodeBody(Buffer.concat([gz, Buffer.from('junk')]), false, 1 << 20), null, 'trailing bytes');
  assert.equal(decodeBody(Buffer.from('not gzip'), false, 1 << 20), null);
});

test('framework routes are normalized with the table of their framework (3.4)', () => {
  const t = (r, fw) => {
    const n = normalizeFrameworkRoute(r, fw);
    return n && '/' + n.map((s) => (s.lit ?? '{' + s.param + '}')).join('/');
  };
  assert.equal(t('/api/orders/:id(\\d+)', 'express'), '/api/orders/{id}');
  assert.equal(t('/api/orders/:id?', 'express'), null);
  assert.equal(t('/orders/{id:int:min(1)}', 'aspnetcore'), '/orders/{id}');
  assert.equal(t('/files/*path', 'gin'), null);
  assert.equal(t('/api/orders/{id}/{$}', 'nethttp'), '/api/orders/{id}');
  assert.equal(t('/api/orders/{id:path}', 'fastapi'), null);
  assert.equal(t('/api/orders/{id:path}', 'spring'), '/api/orders/{id}');
  assert.equal(t('/api/orders/:id', 'unknown'), null);
});

test('url_base normalization (3.1)', () => {
  const n = normalizeUrlBase('HTTPS://API.Carrier.Example:0443');
  assert.equal(n.invalid, false);
  assert.equal(n.origin, 'https://api.carrier.example');
  assert.equal(n.hostport, 'api.carrier.example');
  assert.equal(n.port, null);
  assert.equal(normalizeUrlBase('https://user:pw@api.carrier.example').invalid, true);
  assert.equal(normalizeUrlBase('http://api.carrier.example:70000').invalid, true);
  assert.equal(normalizeUrlBase('http://api.carrier.example:8080').hostport, 'api.carrier.example:8080');
  // v1.5: IPv6 literals in brackets are valid hosts; the origin keeps the brackets.
  const v6 = normalizeUrlBase('https://[2001:DB8::1]:8443');
  assert.equal(v6.invalid, false);
  assert.equal(v6.hostport, '[2001:db8::1]:8443');
  assert.equal(v6.port, '8443');
  assert.ok(v6.ip6 instanceof Uint8Array && v6.ip6.length === 16);
  assert.equal(normalizeUrlBase('https://[::1]').port, null);
  assert.equal(normalizeUrlBase('http://[::1]:80').port, null);
  for (const bad of ['https://[::1', 'https://[::1]x', 'https://[::1]:', 'https://[::1]:0', 'https://[::1%eth0]', 'https://[]', 'https://[::1]/x', 'https://::1']) {
    assert.equal(normalizeUrlBase(bad).invalid, true, bad);
  }
});

test('IPv6 parser follows RFC 4291 2.2 as written in the spec, not a library (3.1 point 5)', () => {
  const ok = ['::', '::1', '1::', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8', '1::8', '::ffff:1.2.3.4', '64:ff9b::10.0.0.1',
    '1:2:3:4:5:6:1.2.3.4', 'ABCD::EF'.toLowerCase(), '0:0:0:0:0:0:0:0'];
  for (const a of ok) assert.ok(parseIpv6(a), a);
  const bad = ['', ':', ':::', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7:8::', '::1:2:3:4:5:6:7:8', '1::2::3', '12345::', 'g::', '::1.2.3', '::1.2.3.04',
    '::1.2.3.256', '1.2.3.4::', '::1.2.3.4:1', '1.2.3.4', 'fe80::1%eth0', ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7:', ' ::1', '::1 ', '::ffff:1.2.3.4.5'];
  for (const a of bad) assert.equal(parseIpv6(a), null, JSON.stringify(a));
  assert.deepEqual([...parseIpv6('::ffff:1.2.3.4')], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
});

test('host pattern (3.5) and IP classes (3.6)', () => {
  const pat = (u, ...r) => {
    const b = normalizeUrlBase(u);
    return b.invalid ? 'invalid' : hostPattern(b.host, b.port, b.ip6) ?? 'invalid';
  };
  const cases = {
    'https://api.carrier.example': 'api.carrier.example',
    'HTTPS://API.Carrier.example:443': 'api.carrier.example',
    'https://api.carrier.example.:8443': 'api.carrier.example:8443',
    'https://t-3912345678.tenant.example': '{*}.tenant.example',
    'https://cdn-9f8e7d6c5b4a.assets.example': '{*}.assets.example',
    'https://deadbeefcafe.example': '{*}.example',
    'https://1password.example': '{*}.example',
    'https://xn--bcher-kva.example': 'xn--bcher-kva.example',
    'https://ab12cd34ef56.0012345678.cdn.example': '{*}.{*}.cdn.example',
    'https://a_b.example': 'invalid',
    'http://10.0.0.5:8080': 'ip:private:8080',
    'https://8.8.8.8': 'ip:public',
    'https://8.8.8.8.': 'ip:public',
    'https://010.0.0.1': '{*}.{*}.{*}.{*}',
    'https://127.1': '{*}.{*}',
    'https://172.15.255.255': 'ip:public',
    'https://172.16.0.1': 'ip:private',
    'https://169.254.169.254': 'ip:private',
    'https://100.64.0.1': 'ip:private',
    'https://[2606:4700::1111]': 'ip:public',
    'https://[::1]:8080': 'ip:private:8080',
    'https://[::ffff:10.0.0.1]': 'ip:private',
    'https://[::ffff:8.8.8.8]': 'ip:public',
    'https://[64:ff9b::808:808]': 'ip:public',
    'https://[64:ff9b::a00:1]': 'ip:private',
    'https://[64:ff9b:1::1]': 'ip:private',
    'https://[2001:db8::1]': 'ip:private',
    'https://[2001:200::1]': 'ip:public',
    'https://[fd12::1]': 'ip:private',
    'https://[fe80::1]': 'ip:private',
    'https://[ff02::1]': 'ip:private',
    'https://[::2:0:0]': 'ip:public',
    'https://api..carrier.example': 'invalid',
    'https://.example': 'invalid',
    'https://.': 'invalid',
    'https://example..': 'invalid',
    'https://localhost': 'localhost',
  };
  for (const [u, want] of Object.entries(cases)) assert.equal(pat(u), want, u);
  assert.equal(hostLabelSafe('g'.repeat(63)), true);
  assert.equal(hostLabelSafe('g'.repeat(64)), false);
  assert.equal(hostLabelSafe('a-1'), true);
  assert.equal(hostLabelSafe('-a'), false);
});

function hostSvc(policy, urlBase, now = Date.now()) {
  const res = sanitizer(policy).run({ dir: 'outbound', method: 'GET', raw_path: Buffer.from('/x'), url_base: urlBase, req_headers: [], status: 200, resp_headers: [] }, now);
  assert.equal(res.outcome, 'event');
  return JSON.parse(res.canonical).service;
}

test('service selection: base, hosts_allow, pattern, unlisted (3.1)', () => {
  const auto = emptyPolicy();
  const off = emptyPolicy({ hosts: { discovery: 'off' } });
  assert.equal(hostSvc(auto, 'https://t-3912345678.tenant.example'), 'host:{*}.tenant.example');
  assert.equal(hostSvc(off, 'https://t-3912345678.tenant.example'), 'host:unlisted');
  assert.equal(hostSvc(off, 'https://[::1]'), 'host:unlisted');
  assert.equal(hostSvc(off, 'https://api..x.example'), 'host:unlisted');
  assert.equal(hostSvc(auto, 'https://[::1'), 'host:invalid');
  // hosts_allow wins over the pattern and is used exactly as listed.
  const allow = (hosts) => emptyPolicy({ hosts, segments: { auto_words: false, allow: [], hosts_allow: ['t-3912345678.tenant.example'] } });
  assert.equal(hostSvc(allow({ discovery: 'off' }), 'https://T-3912345678.tenant.example'), 'host:t-3912345678.tenant.example');
  assert.equal(hostSvc(allow({ discovery: 'auto' }), 'https://T-3912345678.tenant.example'), 'host:t-3912345678.tenant.example');
  assert.equal(hostSvc(allow({ discovery: 'auto' }), 'https://other.tenant.example'), 'host:other.tenant.example');
});

test('outputs over 512 KiB are reduced, then refused (10.3)', () => {
  const policy = emptyPolicy({
    limits: { max_body_bytes: L(4194304), max_depth: L(32), max_array: L(1024), max_keys: L(4096), keep_max_bytes: L(1024) },
    global: { request: { body: [{ path: '$.*[*]', action: { action: 'keep' } }] } },
  });
  // keep with keep_max_bytes 1024 on ~1 KiB strings: 600 values of ~1 KiB > 512 KiB.
  const body = Buffer.from(JSON.stringify({ a: Array.from({ length: 600 }, (_, i) => 'y'.repeat(1000) + i) }));
  const res = sanitizer(policy).run({
    dir: 'inbound', service_name: 'shop-api', method: 'POST', raw_path: Buffer.from('/x'),
    req_headers: [['content-type', Buffer.from('application/json')]], req_body: body, status: 200,
  }, Date.now());
  assert.equal(res.outcome, 'event');
  assert.ok(res.canonical.length <= MAX_EVENT_BYTES);
  assert.ok(res.canonical.includes('"body":"trunc:size"'));
});

test('policy body: the hosts object takes only discovery auto|off (v1.5)', () => {
  const base = JSON.parse(readFileSync(join(CONF, 'policies', 'empty.json'), 'utf8'));
  const check = (hosts) => {
    const b = { ...base };
    if (hosts !== undefined) b.hosts = hosts;
    return validateBodySchema(nodeToPlain(parseJson(Buffer.from(JSON.stringify(b))), true));
  };
  assert.doesNotThrow(() => check(undefined));
  assert.doesNotThrow(() => check({ discovery: 'auto' }));
  assert.doesNotThrow(() => check({ discovery: 'off' }));
  for (const bad of [{ discovery: 'on' }, {}, { discovery: 'off', extra: 1 }, { discovery: null }, { discovery: 'AUTO' }, 'off', null, []]) {
    assert.throws(() => check(bad), (e) => e instanceof Refused && e.code === 'policy_rejected', JSON.stringify(bad));
  }
  assert.equal(new Policy(check(undefined)).hostsAuto, true);
  assert.equal(new Policy(check({ discovery: 'off' })).hostsAuto, false);
});

// Independent statement of the safe-label rule (3.5 a-c), used to check what leaves.
const SAFE = (l) => /^[a-z][a-z0-9-]{0,62}$/.test(l) && !/[0-9]{6}/.test(l) && !/[0-9a-f]{12}/.test(l);

test('G1 hosts: only safe labels, {*} or an IP class leave; strict mode gives host:unlisted (v1.5)', () => {
  const r = rng(20261024);
  const pick = (a) => a[Math.floor(r() * a.length)];
  const atoms = ['giulia', 'mario-rossi', 't-3912345678', 'cdn-9f8e7d6c5b4a', '9f8e7d6c5b4a3f2e', '550e8400-e29b-41d4-a716-446655440000',
    'user_42', 'x', 'Q7', 'ORD-2026-000184', 'tok_abc', 'api', 'xn--bcher-kva', 'xn--9f8e7d6c5b4a', '', '123', 'g'.repeat(63), 'g'.repeat(64), 'ünï'];
  const auto = sanitizer();
  const off = sanitizer(emptyPolicy({ hosts: { discovery: 'off' } }));
  for (let i = 0; i < 600; i++) {
    const labels = Array.from({ length: 1 + Math.floor(r() * 5) }, () => pick(atoms));
    const kind = r();
    const host = kind < 0.1 ? '[' + pick(['::1', '2606:4700::1111', 'fe80::1', '::ffff:10.0.0.1', 'zz::1']) + ']'
      : kind < 0.2 ? [1, 2, 3, 4].map(() => Math.floor(r() * 300)).join('.')
      : labels.join('.') + (r() < 0.2 ? '.' : '');
    const urlBase = pick(['http', 'https']) + '://' + host + (r() < 0.3 ? ':' + (1 + Math.floor(r() * 70000)) : '');
    const ex = { dir: 'outbound', method: 'GET', raw_path: Buffer.from('/'), url_base: urlBase, req_headers: [], status: 200, resp_headers: [] };
    const svc = JSON.parse(auto.run(ex, Date.now()).canonical).service;
    assert.match(svc, /^host:/);
    assert.ok(Buffer.byteLength(svc) <= 518, svc);
    if (svc !== 'host:invalid') {
      const m = /^host:(.*?)(?::([0-9]{1,5}))?$/.exec(svc);
      const pattern = m[1];
      if (pattern !== 'ip:private' && pattern !== 'ip:public') {
        for (const l of pattern.split('.')) assert.ok(l === '{*}' || SAFE(l), `unsafe label ${JSON.stringify(l)} in ${svc} from ${urlBase}`);
      }
    }
    const strict = JSON.parse(off.run(ex, Date.now()).canonical).service;
    assert.ok(strict === 'host:unlisted' || strict === 'host:invalid', strict);
  }
});
