// A small, safe Markdown renderer for the user guide shipped in the console (docs/USER_GUIDE.md): headings,
// paragraphs, lists, fenced code, tables, block quotes, inline code, bold, italic and links. Everything is
// escaped first; only the tags produced here end up in the HTML. Links are kept only for http(s), in-page
// anchors and the console's own routes (#/...).

export interface MdHeading {
  level: number;
  text: string;
  id: string;
}

const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Anchor id of a heading: lower case, accents removed, words joined by '-'. */
export function slug(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function safeHref(h: string): string | null {
  if (/^https?:\/\//i.test(h) || h.startsWith('#')) return h;
  return null;
}

/** Inline markup of one line of (unescaped) text. */
export function inline(src: string): string {
  const codes: string[] = [];
  let s = src.replace(/`([^`]+)`/g, (_m, c: string) => {
    codes.push(`<code>${esc(c)}</code>`);
    return `\u0000${codes.length - 1}\u0000`;
  });
  s = esc(s);
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label: string, href: string) => {
    const h = safeHref(href.replace(/&amp;/g, '&'));
    return h ? `<a href="${esc(h)}"${h.startsWith('http') ? ' rel="noopener noreferrer" target="_blank"' : ''}>${label}</a>` : label;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
  return s.replace(/\u0000(\d+)\u0000/g, (_m, i: string) => codes[Number(i)]);
}

/** Renders Markdown to HTML and lists the headings (for the table of contents). */
export function renderMarkdown(md: string): { html: string; headings: MdHeading[] } {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out: string[] = [];
  const headings: MdHeading[] = [];
  const used = new Map<string, number>();
  let i = 0;
  const isBlockStart = (l: string) => /^(#{1,6} |```|> |\s*[-*] |\s*\d+\. |\|)/.test(l) || l.trim() === '' || /^---+\s*$/.test(l);
  while (i < lines.length) {
    const l = lines[i];
    if (l.trim() === '') {
      i++;
      continue;
    }
    const h = /^(#{1,6}) (.*)$/.exec(l);
    if (h) {
      const level = h[1].length;
      const text = h[2].trim();
      let id = slug(text) || 'sezione';
      const n = used.get(id) ?? 0;
      used.set(id, n + 1);
      if (n) id += '-' + n;
      headings.push({ level, text: text.replace(/`/g, ''), id });
      out.push(`<h${level} id="${id}">${inline(text)}</h${level}>`);
      i++;
      continue;
    }
    if (l.startsWith('```')) {
      const lang = l.slice(3).trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) body.push(lines[i++]);
      i++;
      out.push(`<pre class="code"${lang ? ` data-lang="${esc(lang)}"` : ''}><code>${esc(body.join('\n'))}</code></pre>`);
      continue;
    }
    if (/^---+\s*$/.test(l)) {
      out.push('<hr />');
      i++;
      continue;
    }
    if (l.startsWith('|')) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith('|')) {
        const cells = lines[i].trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
        if (!cells.every((c) => /^:?-+:?$/.test(c))) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      out.push(
        '<div class="table-wrap"><table class="data"><thead><tr>' +
          (head ?? []).map((c) => `<th scope="col">${inline(c)}</th>`).join('') +
          '</tr></thead><tbody>' +
          body.map((r) => '<tr>' + r.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
          '</tbody></table></div>',
      );
      continue;
    }
    if (l.startsWith('> ')) {
      const body: string[] = [];
      while (i < lines.length && lines[i].startsWith('> ')) body.push(lines[i++].slice(2));
      out.push(`<blockquote>${inline(body.join(' '))}</blockquote>`);
      continue;
    }
    const li = /^(\s*)([-*]|\d+\.) (.*)$/.exec(l);
    if (li) {
      const ordered = /\d/.test(li[2]);
      const items: string[] = [];
      while (i < lines.length) {
        const m = /^(\s*)([-*]|\d+\.) (.*)$/.exec(lines[i]);
        if (m) {
          items.push(m[3]);
          i++;
        } else if (lines[i].startsWith('   ') && lines[i].trim() !== '' && items.length) {
          items[items.length - 1] += ' ' + lines[i].trim();
          i++;
        } else break;
      }
      const tag = ordered ? 'ol' : 'ul';
      out.push(`<${tag}>${items.map((x) => `<li>${inline(x)}</li>`).join('')}</${tag}>`);
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && (para.length === 0 || !isBlockStart(lines[i]))) para.push(lines[i++].trim());
    out.push(`<p>${inline(para.join(' '))}</p>`);
  }
  return { html: out.join('\n'), headings };
}
