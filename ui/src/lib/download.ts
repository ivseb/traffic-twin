import { toYaml } from './yaml';

export function saveBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export type DocFormat = 'json' | 'yaml';

export function serializeDoc(doc: object, format: DocFormat): string {
  return format === 'json' ? JSON.stringify(doc, null, 2) + '\n' : toYaml(doc) + '\n';
}

export function saveDoc(name: string, doc: object, format: DocFormat): void {
  const mime = format === 'json' ? 'application/json' : 'application/yaml';
  saveBlob(`${name}.openapi.${format}`, new Blob([serializeDoc(doc, format)], { type: mime }));
}
