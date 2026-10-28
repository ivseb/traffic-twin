import { parseLocation, href, type Location } from './router';

// Reactive location: components read `loc.path` / `loc.query`.
export const loc: Location = $state(parseLocation(typeof window === 'undefined' ? '' : window.location.hash));

function sync(): void {
  const next = parseLocation(window.location.hash);
  loc.path = next.path;
  loc.query = next.query;
}

export function startRouter(): () => void {
  sync();
  window.addEventListener('hashchange', sync);
  return () => window.removeEventListener('hashchange', sync);
}

export function navigate(path: string, query: Record<string, string> = {}, replace = false): void {
  const target = href(path, {}, query);
  if (replace) window.location.replace(target);
  else window.location.hash = target.slice(1);
}

/** Updates only the query string of the current page (e.g. the selected tab). */
export function setQuery(patch: Record<string, string>): void {
  const merged = { ...loc.query, ...patch };
  for (const k of Object.keys(merged)) if (merged[k] === '') delete merged[k];
  navigate(loc.path, merged, true);
}
