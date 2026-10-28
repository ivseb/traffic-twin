package io.github.ivseb.traffictwin.sanitizer;

import java.io.ByteArrayOutputStream;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * 9.0 decoding, one level, with an output cap (A-GZIP-STRICT). A stream that does not end
 * (truncated) or has bytes after its end is an error; reaching the cap is not (it gives
 * {@code trunc:size}).
 */
public final class BodyDecoder {
    private BodyDecoder() {}

    /** Either decoded bytes, the cap flag, or an error (both null/false). */
    public static final class Result {
        public final byte[] data;
        public final boolean cap;

        Result(byte[] data, boolean cap) {
            this.data = data;
            this.cap = cap;
        }
    }

    private static final Result ERROR = new Result(null, false);
    private static final Result CAP = new Result(null, true);

    /** {@code zlibFormat} true for {@code deflate} (RFC 1950), false for gzip. */
    public static Result decode(byte[] in, boolean zlibFormat, int cap) {
        int start = 0;
        int trailer = 0;
        if (!zlibFormat) {
            start = gzipHeaderLength(in);
            if (start < 0) return ERROR;
            trailer = 8;
        }
        Inflater inf = new Inflater(!zlibFormat);
        try {
            inf.setInput(in, start, in.length - start);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(cap, Math.max(64, in.length * 4)));
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n > 0) {
                    out.write(buf, 0, n);
                    if (out.size() >= cap) return CAP;
                } else if (inf.needsInput() || inf.needsDictionary()) {
                    return ERROR; // truncated stream
                }
            }
            if (inf.getRemaining() != trailer) return ERROR; // bytes after the end (or missing trailer)
            byte[] data = out.toByteArray();
            if (!zlibFormat) {
                int t = in.length - 8;
                long crc = (in[t] & 0xffL) | (in[t + 1] & 0xffL) << 8 | (in[t + 2] & 0xffL) << 16 | (in[t + 3] & 0xffL) << 24;
                long isize = (in[t + 4] & 0xffL) | (in[t + 5] & 0xffL) << 8 | (in[t + 6] & 0xffL) << 16 | (in[t + 7] & 0xffL) << 24;
                CRC32 c = new CRC32();
                c.update(data);
                if (c.getValue() != crc || (data.length & 0xffffffffL) != isize) return ERROR;
            }
            return new Result(data, false);
        } catch (DataFormatException e) {
            return ERROR;
        } finally {
            inf.end();
        }
    }

    /** Length of the gzip header (RFC 1952), or -1 if malformed. */
    private static int gzipHeaderLength(byte[] b) {
        if (b.length < 18 || (b[0] & 0xff) != 0x1f || (b[1] & 0xff) != 0x8b || b[2] != 8) return -1;
        int flg = b[3] & 0xff;
        int p = 10;
        if ((flg & 4) != 0) {
            if (p + 2 > b.length) return -1;
            int xlen = (b[p] & 0xff) | (b[p + 1] & 0xff) << 8;
            p += 2 + xlen;
        }
        if ((flg & 8) != 0) {
            while (p < b.length && b[p] != 0) p++;
            p++;
        }
        if ((flg & 16) != 0) {
            while (p < b.length && b[p] != 0) p++;
            p++;
        }
        if ((flg & 2) != 0) p += 2;
        return p > b.length ? -1 : p;
    }
}
