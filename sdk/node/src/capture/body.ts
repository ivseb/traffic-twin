// Body tee (sanitizer.md 9.0): keeps a copy of the first `limit` bytes and counts the rest.
// Never alters the chunks it sees; copies only what it keeps, once.
//
// Every kept chunk is a standalone allocation (its own ArrayBuffer, never a slice of the
// Buffer pool): the final bytes can then be handed to a worker thread without cloning a
// whole pool slab. The chunk list is bounded by `limit` bytes; a body made of one chunk
// (the common case) is returned without any further copy.

export class BodyTap {
  private chunks: Buffer[] = [];
  private kept = 0;
  total = 0;
  ended = false;

  constructor(private readonly limit: number) {}

  /** Records a chunk (Buffer, Uint8Array or string with encoding). Never throws. */
  add(chunk: unknown, encoding?: unknown): void {
    try {
      if (chunk === null || chunk === undefined) return;
      if (typeof chunk === 'string') {
        const enc = (typeof encoding === 'string' && Buffer.isEncoding(encoding) ? encoding : 'utf8') as BufferEncoding;
        const len = Buffer.byteLength(chunk, enc);
        this.total += len;
        if (this.kept < this.limit && len > 0) {
          const room = this.limit - this.kept;
          const b = Buffer.allocUnsafeSlow(len);
          b.write(chunk, 0, len, enc);
          const take = len > room ? b.subarray(0, room) : b;
          this.chunks.push(take);
          this.kept += take.length;
        }
        return;
      }
      if (chunk instanceof Uint8Array) {
        const len = chunk.byteLength;
        this.total += len;
        if (this.kept < this.limit && len > 0) {
          const take = Math.min(len, this.limit - this.kept);
          // Copy: the app (or Node) may reuse the underlying memory.
          const b = Buffer.allocUnsafeSlow(take);
          b.set(take === len ? chunk : chunk.subarray(0, take));
          this.chunks.push(b);
          this.kept += take;
        }
      }
    } catch {
      // Capturing must never affect the app.
    }
  }

  bytes(): Buffer {
    const n = this.chunks.length;
    if (n === 0) return Buffer.alloc(0);
    if (n === 1) return this.chunks[0]!;
    const b = Buffer.allocUnsafeSlow(this.kept);
    let o = 0;
    for (let i = 0; i < n; i++) {
      const c = this.chunks[i]!;
      b.set(c, o);
      o += c.length;
    }
    this.chunks = [b];
    return b;
  }
}
