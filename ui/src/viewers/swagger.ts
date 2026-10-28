import SwaggerUIBundle from 'swagger-ui-dist/swagger-ui-es-bundle.js';
import 'swagger-ui-dist/swagger-ui.css';
import { withServer, type ViewerHandle, type ViewerOptions } from './index';

export async function mount(el: HTMLElement, spec: object, opts: ViewerOptions): Promise<ViewerHandle> {
  const tryIt = opts.tryItUrl !== '';
  SwaggerUIBundle({
    spec: withServer(spec, opts.tryItUrl),
    domNode: el,
    deepLinking: false,
    docExpansion: 'list',
    defaultModelsExpandDepth: 0,
    // "Try it out" stays off unless the user entered a mock URL.
    supportedSubmitMethods: tryIt ? ['get', 'put', 'post', 'delete', 'patch'] : [],
    validatorUrl: null,
    syntaxHighlight: { activated: false },
  });
  return {
    destroy() {
      el.replaceChildren();
    },
  };
}
