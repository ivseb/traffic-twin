// OpenAPI viewers. Each one is a separate lazy chunk, loaded only when the
// viewer page opens, so the main bundle does not grow.

export type ViewerId = 'swagger' | 'redoc' | 'scalar';
export const VIEWERS: readonly ViewerId[] = ['swagger', 'redoc', 'scalar'];

export interface ViewerOptions {
  /** Base URL of a `tt mock` to enable "Try it out" against. Empty = disabled. */
  tryItUrl: string;
}

export interface ViewerHandle {
  destroy(): void;
}

export interface ViewerModule {
  mount(el: HTMLElement, spec: object, opts: ViewerOptions): Promise<ViewerHandle>;
}

export const loadViewer: Record<ViewerId, () => Promise<ViewerModule>> = {
  swagger: () => import('./swagger'),
  redoc: () => import('./redoc'),
  scalar: () => import('./scalar'),
};

export function isViewer(v: string | undefined): v is ViewerId {
  return v === 'swagger' || v === 'redoc' || v === 'scalar';
}

/** Points the document at the mock (servers[0]) when the user entered a URL. */
export function withServer(spec: object, url: string): object {
  const clone = JSON.parse(JSON.stringify(spec)) as { servers?: { url: string }[] };
  if (url) clone.servers = [{ url }];
  return clone;
}

/** Only http(s) URLs are accepted as mock targets. */
export function validMockUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}
