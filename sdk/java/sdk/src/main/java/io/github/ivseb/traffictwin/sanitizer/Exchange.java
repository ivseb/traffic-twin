package io.github.ivseb.traffictwin.sanitizer;

import java.util.ArrayList;
import java.util.List;

/** Normalized exchange, the sanitizer input (sanitizer.md 1). Bodies are byte arrays; nothing here is a copy-on-read view. */
public final class Exchange {
    /** Marks a body whose total length is unknown at the end of the exchange. */
    public static final long UNKNOWN = -2;
    /** Marks an absent total: the length of the kept bytes. */
    public static final long ABSENT = -1;

    /** A header as the source sees it; the value is raw bytes. */
    public record Header(String name, byte[] value) {}

    public boolean inbound = true;
    /** Inbound only: the name assigned at enrollment. */
    public String serviceName;
    /** Outbound only: scheme://host[:port]. */
    public String urlBase;
    public String method = "";
    public byte[] rawPath = new byte[0];
    /** Null = the URL has no "?". */
    public byte[] rawQuery;
    /** Identifier of the 3.4 table (A-FRAMEWORK-ID); required with {@link #frameworkRoute}. */
    public String framework;
    public String frameworkRoute;
    public String traceId;
    /** Outbound only: sampling decision inherited from the inbound exchange; null if none. */
    public Boolean inherited;
    public List<Header> reqHeaders = new ArrayList<>();
    public byte[] reqBody;
    public long reqBodyTotal = ABSENT;
    public boolean reqBodyConsumed = true;
    public boolean reqBodyDecoded = false;
    /** -1 = absent (only with {@link #netError}). */
    public int status = -1;
    public String netError;
    public List<Header> respHeaders = new ArrayList<>();
    public byte[] respBody;
    public long respBodyTotal = ABSENT;
    public boolean respBodyConsumed = true;
    public boolean respBodyDecoded = false;
}
