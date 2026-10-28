// The Redoc standalone bundle is a prebuilt UMD file that Rolldown cannot bundle
// (it contains an optional require(null)). It is emitted as a static asset and
// loaded with a <script src> from the same origin, only when this viewer opens.
import redocUrl from 'redoc/bundles/redoc.standalone.js?url';
import { withServer, type ViewerHandle, type ViewerOptions } from './index';

interface RedocGlobal {
  init(spec: object, options: Record<string, unknown>, el: HTMLElement): void;
  destroy(el?: HTMLElement): void;
}

let loading: Promise<RedocGlobal> | undefined;

function load(): Promise<RedocGlobal> {
  const w = window as unknown as { Redoc?: RedocGlobal };
  if (w.Redoc) return Promise.resolve(w.Redoc);
  loading ??= new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = redocUrl;
    s.onload = () => (w.Redoc ? resolve(w.Redoc) : reject(new Error('Redoc did not initialize')));
    s.onerror = () => {
      loading = undefined;
      reject(new Error('Could not load the Redoc bundle'));
    };
    document.head.appendChild(s);
  });
  return loading;
}

export async function mount(el: HTMLElement, spec: object, opts: ViewerOptions): Promise<ViewerHandle> {
  const Redoc = await load();
  Redoc.init(
    withServer(spec, opts.tryItUrl),
    { hideDownloadButton: true, hideLogo: true, nativeScrollbars: true, scrollYOffset: 56, disableSearch: true, expandResponses: '200,201' },
    el,
  );
  return {
    destroy() {
      try {
        Redoc.destroy(el);
      } catch {
        /* already gone */
      }
      el.replaceChildren();
    },
  };
}
