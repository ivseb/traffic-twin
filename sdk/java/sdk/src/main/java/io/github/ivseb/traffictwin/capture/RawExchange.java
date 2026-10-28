package io.github.ivseb.traffictwin.capture;

import io.github.ivseb.traffictwin.sanitizer.Exchange;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import java.util.function.Supplier;

/** A finished exchange, converted to sanitizer input lazily (off the request path). */
public final class RawExchange {
    public Sanitizer sanitizer;
    public Sanitizer.Decision decision;
    public Supplier<Exchange> build;
    public boolean inbound;
    public long tsMs;
    public long latencyMs;
    public String traceId;
    public String spanId;
    public String parentSpanId;
    /** -1 when absent (only with netError). */
    public int status = -1;
    public String netError;
    /** Bytes held by this exchange (queue accounting). */
    public long heldBytes;
}
