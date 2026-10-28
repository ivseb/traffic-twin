/// <reference types="svelte" />
/// <reference types="vite/client" />

// Third-party viewer bundles without type declarations.
declare module 'swagger-ui-dist/swagger-ui-es-bundle.js' {
  const SwaggerUIBundle: (config: Record<string, unknown>) => { getSystem?: () => unknown };
  export default SwaggerUIBundle;
}
declare module 'swagger-ui-dist/swagger-ui.css';
declare module 'redoc/bundles/redoc.standalone.js?url' {
  const url: string;
  export default url;
}
