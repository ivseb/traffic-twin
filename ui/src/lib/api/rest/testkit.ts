// Test helper: a scripted fetch that records requests (used by the REST adapter tests).

export interface Recorded {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Record<string, string>;
  body: string | undefined;
}

export type Handler = (req: Recorded) => Response | Promise<Response> | undefined;

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

export const text = (body: string, status = 200, contentType = 'text/plain'): Response => new Response(body, { status, headers: { 'Content-Type': contentType } });

export const err = (status: number, code: string, message = code): Response => json({ code, message }, status);

/** Routes are tried in order; the first handler returning a Response wins. Unmatched requests answer 599 (test bug). */
export function scripted(...handlers: Handler[]): { fetch: typeof fetch; calls: Recorded[]; add: (h: Handler) => void } {
  const calls: Recorded[] = [];
  const all = [...handlers];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = new URL(String(input), 'http://tt.test');
    const h: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (h[k.toLowerCase()] = v));
    const rec: Recorded = { method: init?.method ?? 'GET', path: u.pathname, query: u.searchParams, headers: h, body: typeof init?.body === 'string' ? init.body : undefined };
    calls.push(rec);
    for (const handler of all) {
      const r = await handler(rec);
      if (r) return r;
    }
    return new Response(`unhandled ${rec.method} ${rec.path}`, { status: 599 });
  }) as typeof fetch;
  return { fetch: f, calls, add: (h) => all.unshift(h) };
}

export const on =
  (method: string, path: string | RegExp, reply: Response | ((r: Recorded) => Response | Promise<Response>)): Handler =>
  (r) => {
    if (r.method !== method) return undefined;
    if (typeof path === 'string' ? r.path !== path : !path.test(r.path)) return undefined;
    return typeof reply === 'function' ? reply(r) : reply.clone();
  };

export const noSleep = (): Promise<void> => Promise.resolve();
