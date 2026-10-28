import { describe, expect, it } from 'vitest';
import { inline, renderMarkdown, slug } from './markdown';
import guide from '../../../docs/USER_GUIDE.md?raw';

describe('markdown', () => {
  it('escapes everything it does not produce', () => {
    const { html } = renderMarkdown('Ciao <script>alert(1)</script> **forte** `<b>`\n\n[x](javascript:alert(1)) [y](#/hosts) [z](https://example.org)');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('<strong>forte</strong>');
    expect(html).toContain('<code>&lt;b&gt;</code>');
    expect(html).not.toContain('javascript:');
    expect(html).toContain('<a href="#/hosts">y</a>');
    expect(html).toContain('rel="noopener noreferrer"');
  });
  it('renders headings with anchors, lists, tables and code', () => {
    const { html, headings } = renderMarkdown('# Titolo\n\n## La chiave HMAC\n\n- uno\n- due\n\n1. a\n2. b\n\n| A | B |\n|---|---|\n| `x` | y |\n\n```sh\nnpm install ./a.tgz\n```\n');
    expect(headings.map((h) => h.id)).toEqual(['titolo', 'la-chiave-hmac']);
    expect(html).toContain('<ul><li>uno</li><li>due</li></ul>');
    expect(html).toContain('<ol><li>a</li><li>b</li></ol>');
    expect(html).toContain('<td><code>x</code></td>');
    expect(html).toContain('<pre class="code" data-lang="sh"><code>npm install ./a.tgz</code></pre>');
  });
  it('slugs Italian headings', () => {
    expect(slug('Perché il contratto è vuoto?')).toBe('perche-il-contratto-e-vuoto');
    expect(inline('a *b* c')).toBe('a <em>b</em> c');
  });
  it('renders the user guide shipped in the console', () => {
    const { html, headings } = renderMarkdown(guide);
    expect(headings.length).toBeGreaterThan(10);
    expect(html).not.toContain('<script');
    for (const must of ['TT_HMAC_KEY_FILE', 'TT_GATE_PUBKEYS', 'traffic-twin-sdk-', 'gate-keys.txt']) expect(guide).toContain(must);
    // No leftover note for the maintainers of the product.
    expect(guide).not.toMatch(/nota per i manutentori/i);
  });
});
