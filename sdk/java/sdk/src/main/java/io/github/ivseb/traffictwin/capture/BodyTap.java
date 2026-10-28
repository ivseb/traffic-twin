package io.github.ivseb.traffictwin.capture;

import java.nio.ByteBuffer;

/**
 * Body tee (sanitizer.md 9.0): keeps a copy of the first {@code limit} bytes and counts the rest.
 * Never alters the bytes it sees and never throws. Not thread safe by design: one tap belongs
 * to one direction of one exchange (callers synchronize when a runtime may call from two
 * threads).
 */
public final class BodyTap {
    private final int limit;
    private byte[] buf = new byte[0];
    private int kept = 0;
    private long total = 0;
    private volatile boolean ended = false;

    public BodyTap(int limit) {
        this.limit = limit;
    }

    public synchronized void add(byte[] b, int off, int len) {
        try {
            if (b == null || len <= 0) return;
            total += len;
            if (kept < limit) {
                int take = Math.min(len, limit - kept);
                ensure(kept + take);
                System.arraycopy(b, off, buf, kept, take);
                kept += take;
            }
        } catch (RuntimeException e) {
            // Capturing must never affect the application.
        }
    }

    public void add(int oneByte) {
        add(new byte[] {(byte) oneByte}, 0, 1);
    }

    /** Copies from a buffer without consuming it. */
    public synchronized void add(ByteBuffer src) {
        try {
            int len = src.remaining();
            if (len <= 0) return;
            total += len;
            if (kept < limit) {
                int take = Math.min(len, limit - kept);
                ensure(kept + take);
                ByteBuffer d = src.duplicate();
                d.get(buf, kept, take);
                kept += take;
            }
        } catch (RuntimeException e) {
            // ignore
        }
    }

    private void ensure(int cap) {
        if (buf.length >= cap) return;
        int n = Math.max(cap, Math.min(limit, Math.max(256, buf.length * 2)));
        buf = java.util.Arrays.copyOf(buf, n);
    }

    public synchronized byte[] bytes() {
        return java.util.Arrays.copyOf(buf, kept);
    }

    public synchronized long total() {
        return total;
    }

    public synchronized int kept() {
        return kept;
    }

    /** Counts bytes that were not copied (their content does not matter, only their number). */
    public synchronized void addCount(long n) {
        if (n > 0) total += n;
    }

    public int limit() {
        return limit;
    }

    /** Forgets everything seen so far (a request body published again after a redirect or retry). */
    public synchronized void reset() {
        kept = 0;
        total = 0;
        ended = false;
    }

    public void markEnded() {
        ended = true;
    }

    public boolean ended() {
        return ended;
    }
}
