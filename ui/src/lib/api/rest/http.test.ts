import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../types';
import { Http } from './http';
import { err, json, noSleep, on, scripted } from './testkit';

const make = (...h: Parameters<typeof scripted>) => {
  const s = scripted(...h);
  const unauthorized = vi.fn();
  const http = new Http({ fetch: s.fetch, sleep: noSleep, onUnauthorized: unauthorized });
  return { http, unauthorized, ...s };
};

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof ApiError ? `${e.code}/${e.status}/${e.serverCode ?? ''}` : 'other';
  }
};

describe('CSRF', () => {
  it('sends the token on unsafe methods only', async () => {
    const { http, calls } = make(on('GET', '/a', json({})), on('POST', '/a', json({})), on('PUT', '/a', json({})), on('PATCH', '/a', json({})), on('DELETE', '/a', json({})));
    http.setCsrf('tok-1', 'X-CSRF-Token');
    await http.get('/a');
    await http.post('/a', {});
    await http.put('/a', {});
    await http.patch('/a', {});
    await http.del('/a');
    expect(calls.map((c) => [c.method, c.headers['x-csrf-token']])).toEqual([
      ['GET', undefined],
      ['POST', 'tok-1'],
      ['PUT', 'tok-1'],
      ['PATCH', 'tok-1'],
      ['DELETE', 'tok-1'],
    ]);
  });
  it('uses the header name the server announces', async () => {
    const { http, calls } = make(on('POST', '/a', json({})));
    http.setCsrf('t', 'X-Other');
    await http.post('/a', {});
    expect(calls[0].headers['x-other']).toBe('t');
  });
  it('fetches the token once when an unsafe call comes first', async () => {
    const { http, calls } = make(on('POST', '/a', json({})));
    http.refreshCsrf = async () => http.setCsrf('late', 'X-CSRF-Token');
    await http.post('/a', {});
    expect(calls[0].headers['x-csrf-token']).toBe('late');
  });
  it('sends JSON with the right content type, and cookies of the same origin', async () => {
    let seen: RequestInit | undefined;
    const f = (async (_u: RequestInfo | URL, init?: RequestInit) => {
      seen = init;
      return json({});
    }) as typeof fetch;
    await new Http({ fetch: f }).post('/a', { x: 1 });
    expect(seen?.credentials).toBe('same-origin');
    expect(new Headers(seen?.headers).get('content-type')).toBe('application/json');
    expect(seen?.body).toBe('{"x":1}');
  });
});

describe('error mapping', () => {
  it.each([
    [400, 'invalid'],
    [401, 'unauthenticated'],
    [403, 'forbidden'],
    [404, 'not_found'],
    [409, 'conflict'],
    [422, 'invalid'],
    [429, 'rate_limited'],
    [503, 'unavailable'],
    [500, 'server'],
  ])('maps HTTP %i to %s and keeps the server code and message', async (status, want) => {
    const { http } = make(on('POST', '/a', err(status, 'some_code', 'Readable message')));
    const e = await http.post('/a', {}).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).toMatchObject({ code: want, status, serverCode: 'some_code', message: 'Readable message' });
  });
  it('maps setup_done to already_initialized', async () => {
    const { http } = make(on('POST', '/setup', err(409, 'setup_done')));
    expect(await code(http.post('/setup', {}))).toBe('already_initialized/409/setup_done');
  });
  it('maps a CSRF refusal to a session error, not to a missing role', async () => {
    // Another login in the same browser replaced the cookie: this tab's token no longer matches.
    const { http } = make(on('POST', '/a', err(403, 'csrf')), on('POST', '/b', err(403, 'forbidden')));
    expect(await code(http.post('/a', {}))).toBe('session/403/csrf');
    expect(await code(http.post('/b', {}))).toBe('forbidden/403/forbidden');
  });
  it('survives a body that is not JSON', async () => {
    const { http } = make(on('GET', '/a', new Response('<html>bad gateway</html>', { status: 502 })));
    expect(await code(http.get('/a', { retries: 0 }))).toBe('unavailable/502/');
  });
  it('maps a network failure', async () => {
    const http = new Http({ fetch: (async () => Promise.reject(new TypeError('failed'))) as typeof fetch, sleep: noSleep });
    expect(await code(http.post('/a', {}))).toBe('network/undefined/');
  });
});

describe('401 handling', () => {
  it('calls the hook so the app can go back to the login page', async () => {
    const { http, unauthorized } = make(on('GET', '/a', err(401, 'unauthenticated')));
    await code(http.get('/a'));
    expect(unauthorized).toHaveBeenCalledTimes(1);
  });
  it('does not call it for requests that expect a 401 (login, me)', async () => {
    const { http, unauthorized } = make(on('POST', '/login', err(401, 'invalid_credentials')));
    expect(await code(http.post('/login', {}, { quiet401: true }))).toBe('unauthenticated/401/invalid_credentials');
    expect(unauthorized).not.toHaveBeenCalled();
  });
  it('does not call it on 403 (wrong role is not a lost session)', async () => {
    const { http, unauthorized } = make(on('GET', '/a', err(403, 'forbidden')));
    await code(http.get('/a'));
    expect(unauthorized).not.toHaveBeenCalled();
  });
});

describe('retries', () => {
  it('retries an idempotent GET on 503 and succeeds', async () => {
    let n = 0;
    const { http, calls } = make(on('GET', '/a', () => (++n < 3 ? err(503, 'busy') : json({ ok: true }))));
    expect(await http.get('/a')).toEqual({ ok: true });
    expect(calls).toHaveLength(3);
  });
  it('retries a GET after a network error', async () => {
    let n = 0;
    const f = (async () => {
      if (++n === 1) throw new TypeError('reset');
      return json({ ok: 1 });
    }) as typeof fetch;
    expect(await new Http({ fetch: f, sleep: noSleep }).get('/a')).toEqual({ ok: 1 });
    expect(n).toBe(2);
  });
  it('gives up after the configured attempts', async () => {
    const { http, calls } = make(on('GET', '/a', err(503, 'busy')));
    expect(await code(http.get('/a'))).toBe('unavailable/503/busy');
    expect(calls).toHaveLength(3); // 1 + 2 retries
  });
  it('never retries a write', async () => {
    const { http, calls } = make(on('POST', '/a', err(503, 'busy')));
    await code(http.post('/a', {}));
    expect(calls).toHaveLength(1);
  });
  it('does not retry a 4xx', async () => {
    const { http, calls } = make(on('GET', '/a', err(404, 'not_found')));
    await code(http.get('/a'));
    expect(calls).toHaveLength(1);
  });
  it('backs off exponentially', async () => {
    const waits: number[] = [];
    const s = scripted(on('GET', '/a', err(503, 'busy')));
    const http = new Http({ fetch: s.fetch, retryDelayMs: 100, sleep: async (ms) => void waits.push(ms) });
    await code(http.get('/a'));
    expect(waits).toEqual([100, 200]);
  });
});

describe('responses', () => {
  it('returns undefined for 204', async () => {
    const { http } = make(on('POST', '/a', json(null, 204)));
    expect(await http.post('/a')).toBeUndefined();
  });
  it('builds the query string and skips undefined values', () => {
    const http = new Http({ base: '/x' });
    expect(http.url('/a', { a: 1, b: undefined, c: 'x y' })).toBe('/x/a?a=1&c=x+y');
  });
});
