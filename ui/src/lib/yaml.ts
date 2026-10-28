// Minimal YAML writer for plain objects/arrays/scalars. Only used to render
// author policies in the review diff; it is not a general serializer.

const PLAIN = /^[A-Za-z0-9_./$*\[\]-][A-Za-z0-9_ ./$*\[\]():,-]*$/;
const RESERVED = /^(true|false|null|yes|no|on|off|~|[0-9.+-]+)$/i;

function scalar(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  const s = String(v);
  if (s === '') return '""';
  if (PLAIN.test(s) && !RESERVED.test(s) && !s.endsWith(' ') && !s.includes(': ')) return s;
  return JSON.stringify(s);
}

export function toYaml(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`;
    return value
      .map((item) => {
        if (item !== null && typeof item === 'object') {
          const inner = toYaml(item, indent + 1).split('\n');
          inner[0] = inner[0].trimStart();
          return `${pad}- ${inner.join('\n')}`;
        }
        return `${pad}- ${scalar(item)}`;
      })
      .join('\n');
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return `${pad}{}`;
    return entries
      .map(([k, v]) => {
        const key = scalar(k);
        if (v !== null && typeof v === 'object') {
          const empty = Array.isArray(v) ? v.length === 0 : Object.keys(v).length === 0;
          if (empty) return `${pad}${key}: ${Array.isArray(v) ? '[]' : '{}'}`;
          return `${pad}${key}:\n${toYaml(v, indent + 1)}`;
        }
        return `${pad}${key}: ${scalar(v)}`;
      })
      .join('\n');
  }
  return `${pad}${scalar(value)}`;
}
