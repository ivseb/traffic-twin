import { createApiReference } from '@scalar/api-reference';
import '@scalar/api-reference/style.css';
import { withServer, type ViewerHandle, type ViewerOptions } from './index';

export async function mount(el: HTMLElement, spec: object, opts: ViewerOptions): Promise<ViewerHandle> {
  const app = createApiReference(el, {
    content: withServer(spec, opts.tryItUrl) as Record<string, unknown>,
    // No outbound calls: no hosted proxy, no CDN fonts, no telemetry, no external fetch.
    proxyUrl: '',
    withDefaultFonts: false,
    hideClientButton: opts.tryItUrl === '',
    hideTestRequestButton: opts.tryItUrl === '',
    telemetry: false,
    showDeveloperTools: 'never',
    agent: { disabled: true },
    mcp: { disabled: true },
    hideDownloadButton: true,
    layout: 'modern',
  } as never) as unknown as { unmount?: () => void; destroy?: () => void };
  return {
    destroy() {
      try {
        app?.unmount?.();
        app?.destroy?.();
      } catch {
        /* ignore */
      }
      el.replaceChildren();
    },
  };
}
