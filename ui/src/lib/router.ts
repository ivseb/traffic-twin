// Tiny hash router, pure part. The Go file server has no SPA fallback, so the
// routes live after "#": "#/contracts/shop-api/GET%20%2Forders?tab=diff".

export interface RouteDef<T = unknown> {
  pattern: string; // "/contracts/:service/:op?"
  data: T;
}

export interface Location {
  path: string;
  query: Record<string, string>;
}

export interface Match<T> {
  route: RouteDef<T>;
  params: Record<string, string>;
}

export function parseLocation(hash: string): Location {
  let h = hash.startsWith('#') ? hash.slice(1) : hash;
  if (!h.startsWith('/')) h = '/' + h;
  const q = h.indexOf('?');
  const path = q === -1 ? h : h.slice(0, q);
  const query: Record<string, string> = {};
  if (q !== -1) {
    for (const part of h.slice(q + 1).split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const k = safeDecode(eq === -1 ? part : part.slice(0, eq));
      query[k] = eq === -1 ? '' : safeDecode(part.slice(eq + 1));
    }
  }
  return { path: path.length > 1 ? path.replace(/\/+$/, '') : path, query };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

export function matchRoute<T>(routes: readonly RouteDef<T>[], path: string): Match<T> | null {
  const segs = path.split('/').filter(Boolean);
  for (const route of routes) {
    const pat = route.pattern.split('/').filter(Boolean);
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < pat.length; i++) {
      const p = pat[i];
      const optional = p.endsWith('?');
      const name = p.startsWith(':') ? p.slice(1).replace(/\?$/, '') : null;
      const seg = segs[i];
      if (seg === undefined) {
        if (!optional) ok = false;
        break;
      }
      if (name) params[name] = safeDecode(seg);
      else if (p !== seg) {
        ok = false;
        break;
      }
    }
    if (ok && segs.length <= pat.length) return { route, params };
  }
  return null;
}

/** Builds a hash href ("#/x/y?a=b"), encoding each path segment. */
export function href(path: string, params: Record<string, string> = {}, query: Record<string, string> = {}): string {
  const p = path
    .split('/')
    .map((seg) => (seg.startsWith(':') ? encodeURIComponent(params[seg.slice(1).replace(/\?$/, '')] ?? '') : seg))
    .join('/')
    .replace(/\/+$/, '');
  const qs = Object.entries(query)
    .filter(([, v]) => v !== '' && v !== undefined)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  return '#' + (p || '/') + (qs ? '?' + qs : '');
}
