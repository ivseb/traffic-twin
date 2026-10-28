// Thin HTTP layer for the tt-core admin API: session cookie (sent by the
// browser), X-CSRF-Token on unsafe methods, JSON error bodies mapped to
// ApiError, retries for idempotent GETs, a hook for 401.

import { ApiError, type ApiErrorCode, type ApiErrorDetail } from '../types';

export interface HttpOptions {
  /** Defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Prefix of every path, "" = same origin. */
  base?: string;
  /** Extra attempts for GET on network errors, 429 and 502/503/504. */
  retries?: number;
  /** First backoff, doubled at every attempt. */
  retryDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /** Called when a request is answered 401 (the session is gone). */
  onUnauthorized?: () => void;
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  /** JSON body. */
  json?: unknown;
  /** Raw body (with its own contentType). */
  body?: string;
  contentType?: string;
  accept?: string;
  /** Do not call onUnauthorized on 401 (login, me). */
  quiet401?: boolean;
  /** The request needs no CSRF token (login and setup: there is no session yet). */
  noCsrf?: boolean;
  /** Override the retry count for this call. */
  retries?: number;
  signal?: AbortSignal;
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export const CSRF_HEADER = 'X-CSRF-Token';

export function codeForStatus(status: number): ApiErrorCode {
  switch (status) {
    case 400:
    case 413:
    case 415:
    case 422:
      return 'invalid';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 429:
      return 'rate_limited';
    case 502:
    case 503:
    case 504:
      return 'unavailable';
    default:
      return status >= 500 ? 'server' : 'invalid';
  }
}

export class Http {
  private csrf: string | null = null;
  private csrfHeader = CSRF_HEADER;
  /** Fetches the CSRF token when none is known (set by the adapter: GET /auth/me). */
  refreshCsrf: (() => Promise<void>) | null = null;
  private readonly f: typeof fetch;
  private readonly base: string;
  private readonly retries: number;
  private readonly retryDelay: number;
  private readonly sleep: (ms: number) => Promise<void>;
  onUnauthorized: (() => void) | undefined;

  constructor(o: HttpOptions = {}) {
    this.f = o.fetch ?? ((...a) => globalThis.fetch(...a));
    this.base = o.base ?? '';
    this.retries = o.retries ?? 2;
    this.retryDelay = o.retryDelayMs ?? 250;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.onUnauthorized = o.onUnauthorized;
  }

  setCsrf(token: string | null, header?: string): void {
    this.csrf = token;
    if (header) this.csrfHeader = header;
  }
  get hasCsrf(): boolean {
    return this.csrf !== null;
  }

  url(path: string, query?: RequestOptions['query']): string {
    let u = this.base + path;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v !== undefined) q.set(k, String(v));
      const s = q.toString();
      if (s) u += (u.includes('?') ? '&' : '?') + s;
    }
    return u;
  }

  /** Performs the request and returns the Response (status already checked). */
  async raw(method: string, path: string, o: RequestOptions = {}): Promise<Response> {
    const unsafe = UNSAFE.has(method);
    if (unsafe && !o.noCsrf && this.csrf === null && this.refreshCsrf) {
      try {
        await this.refreshCsrf();
      } catch {
        /* the request below will be answered 401/403 and mapped */
      }
    }
    const headers: Record<string, string> = { Accept: o.accept ?? 'application/json' };
    let body: string | undefined;
    if (o.json !== undefined) {
      body = JSON.stringify(o.json);
      headers['Content-Type'] = 'application/json';
    } else if (o.body !== undefined) {
      body = o.body;
      headers['Content-Type'] = o.contentType ?? 'application/json';
    }
    if (unsafe && !o.noCsrf && this.csrf) headers[this.csrfHeader] = this.csrf;

    const attempts = method === 'GET' || method === 'HEAD' ? (o.retries ?? this.retries) : 0;
    let lastErr: unknown;
    for (let i = 0; i <= attempts; i++) {
      if (i > 0) await this.sleep(this.retryDelay * 2 ** (i - 1));
      let res: Response;
      try {
        res = await this.f(this.url(path, o.query), { method, headers, body, credentials: 'same-origin', cache: 'no-store', signal: o.signal });
      } catch (e) {
        if (o.signal?.aborted) throw e;
        lastErr = new ApiError('network', 'Cannot reach the server');
        continue;
      }
      if (res.ok) return res;
      if (i < attempts && (res.status === 429 || res.status === 502 || res.status === 503)) {
        lastErr = await this.toError(res, o);
        continue;
      }
      throw await this.toError(res, o);
    }
    throw lastErr instanceof Error ? lastErr : new ApiError('network', 'Cannot reach the server');
  }

  private async toError(res: Response, o: RequestOptions): Promise<ApiError> {
    let serverCode: string | undefined;
    let details: ApiErrorDetail[] | undefined;
    let message = res.statusText || `HTTP ${res.status}`;
    try {
      const text = await res.text();
      if (text) {
        const j = JSON.parse(text) as { code?: unknown; message?: unknown; details?: unknown };
        if (typeof j.code === 'string') serverCode = j.code;
        if (typeof j.message === 'string') message = j.message;
        if (Array.isArray(j.details)) details = j.details.filter((d): d is ApiErrorDetail => !!d && typeof d === 'object');
      }
    } catch {
      /* not JSON: keep the status text */
    }
    let code = codeForStatus(res.status);
    if (serverCode === 'setup_done') code = 'already_initialized';
    // A CSRF refusal is about the session of this tab, never about the role.
    if (res.status === 403 && serverCode === 'csrf') code = 'session';
    if (res.status === 401 && !o.quiet401) this.onUnauthorized?.();
    return new ApiError(code, message, res.status, serverCode, details);
  }

  private readonly inflight = new Map<string, Promise<{ status: number; text: string }>>();

  private async fetchText(method: string, path: string, o: RequestOptions): Promise<{ status: number; text: string }> {
    const res = await this.raw(method, path, o);
    return { status: res.status, text: res.status === 204 ? '' : await res.text() };
  }

  async json<T>(method: string, path: string, o: RequestOptions = {}): Promise<T> {
    let r: { status: number; text: string };
    if (method === 'GET' && !o.signal) {
      // The pages of the UI ask for the same collections from several
      // components at once (services, hosts, gaps): one request each.
      const key = `${this.url(path, o.query)}\n${o.accept ?? ''}\n${o.quiet401 ? 1 : 0}\n${o.retries ?? ''}`;
      let p = this.inflight.get(key);
      if (!p) {
        const q = this.fetchText(method, path, o);
        p = q;
        this.inflight.set(key, q);
        const drop = (): void => {
          if (this.inflight.get(key) === q) this.inflight.delete(key);
        };
        q.then(drop, drop);
      }
      r = await p;
    } else {
      r = await this.fetchText(method, path, o);
    }
    if (r.status === 204 || !r.text) return undefined as T;
    try {
      return JSON.parse(r.text) as T;
    } catch {
      throw new ApiError('server', 'The server sent an unreadable response', r.status);
    }
  }

  async text(method: string, path: string, o: RequestOptions = {}): Promise<string> {
    const res = await this.raw(method, path, o);
    return res.text();
  }

  get<T>(path: string, o?: RequestOptions): Promise<T> {
    return this.json<T>('GET', path, o);
  }
  post<T>(path: string, json?: unknown, o: RequestOptions = {}): Promise<T> {
    return this.json<T>('POST', path, { ...o, json });
  }
  put<T>(path: string, json?: unknown, o: RequestOptions = {}): Promise<T> {
    return this.json<T>('PUT', path, { ...o, json });
  }
  patch<T>(path: string, json?: unknown, o: RequestOptions = {}): Promise<T> {
    return this.json<T>('PATCH', path, { ...o, json });
  }
  del<T>(path: string, o?: RequestOptions): Promise<T> {
    return this.json<T>('DELETE', path, o);
  }
}
