import type { ViewerId } from '../viewers';

/** Page that hosts the OpenAPI viewers (a separate HTML document with its own CSP). */
export const VIEWER_PAGE = '/viewer.html';

/** `group`: the contract of that group's traffic only (the group of the row the viewer was opened from). */
export function viewerUrl(service: string, viewer: ViewerId, group?: string): string {
  return `${VIEWER_PAGE}?service=${encodeURIComponent(service)}&viewer=${viewer}${group ? `&group=${encodeURIComponent(group)}` : ''}`;
}
