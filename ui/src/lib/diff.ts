// Line diff (LCS) used by DiffView for JSON / YAML text.

export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
  /** 1-based line number in the old / new text (undefined when absent). */
  oldNo?: number;
  newNo?: number;
}

/** Largest LCS table (cells) built for the changed middle: 4M cells = 16 MB. */
export const MAX_DIFF_CELLS = 4_000_000;

export function diffLines(before: string, after: string): DiffLine[] {
  const a = before === '' ? [] : before.split('\n');
  const b = after === '' ? [] : after.split('\n');
  // Unchanged head and tail are copied as they are: a contract or policy
  // diff usually changes a few lines in a long document.
  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head++;
  let tail = 0;
  while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++;
  const out: DiffLine[] = [];
  for (let k = 0; k < head; k++) out.push({ kind: 'same', text: a[k], oldNo: k + 1, newNo: k + 1 });
  const mid = middleDiff(a.slice(head, a.length - tail), b.slice(head, b.length - tail), head);
  for (const l of mid) out.push(l);
  for (let k = tail; k > 0; k--) {
    const i = a.length - k;
    const j = b.length - k;
    out.push({ kind: 'same', text: a[i], oldNo: i + 1, newNo: j + 1 });
  }
  return out;
}

function middleDiff(a: string[], b: string[], offset: number): DiffLine[] {
  const n = a.length;
  const m = b.length;
  if ((n + 1) * (m + 1) > MAX_DIFF_CELLS) {
    // Too large for an exact LCS in the browser: shown as a replacement.
    return [
      ...a.map((text, k): DiffLine => ({ kind: 'del', text, oldNo: offset + k + 1 })),
      ...b.map((text, k): DiffLine => ({ kind: 'add', text, newNo: offset + k + 1 })),
    ];
  }
  // LCS table over the changed middle only.
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: 'same', text: a[i], oldNo: offset + i + 1, newNo: offset + j + 1 });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: 'del', text: a[i], oldNo: offset + i + 1 });
      i++;
    } else {
      out.push({ kind: 'add', text: b[j], newNo: offset + j + 1 });
      j++;
    }
  }
  for (; i < n; i++) out.push({ kind: 'del', text: a[i], oldNo: offset + i + 1 });
  for (; j < m; j++) out.push({ kind: 'add', text: b[j], newNo: offset + j + 1 });
  return out;
}

export function diffStats(lines: DiffLine[]): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of lines) {
    if (l.kind === 'add') added++;
    else if (l.kind === 'del') removed++;
  }
  return { added, removed };
}

/** Collapses long runs of unchanged lines, keeping `context` lines around changes. */
export function collapseContext(lines: DiffLine[], context = 3): (DiffLine | { kind: 'gap'; hidden: number })[] {
  const keep = new Array<boolean>(lines.length).fill(false);
  lines.forEach((l, idx) => {
    if (l.kind !== 'same') {
      for (let k = Math.max(0, idx - context); k <= Math.min(lines.length - 1, idx + context); k++) keep[k] = true;
    }
  });
  const out: (DiffLine | { kind: 'gap'; hidden: number })[] = [];
  let hidden = 0;
  lines.forEach((l, idx) => {
    if (keep[idx]) {
      if (hidden > 0) out.push({ kind: 'gap', hidden });
      hidden = 0;
      out.push(l);
    } else hidden++;
  });
  if (hidden > 0 && out.length > 0) out.push({ kind: 'gap', hidden });
  return out.length === 0 && lines.length > 0 ? lines : out;
}
