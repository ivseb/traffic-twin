package io.github.ivseb.traffictwin.capture;

import io.github.ivseb.traffictwin.TrafficTwin;
import io.github.ivseb.traffictwin.sanitizer.Exchange;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLException;

/**
 * One captured outbound call, shared by the client integrations. {@link #begin} returns null when
 * the agent is not capturing or the exchange is not sampled: callers then do nothing at all.
 * The call inherits the decision and the trace of the inbound exchange being served by the
 * calling thread (sanitizer.md 12); outside one (jobs, timers) the trace or random rule applies.
 */
public final class OutboundCapture {
    private final TrafficTwin tt;
    private final Sanitizer san;
    private final Sanitizer.Decision decision;
    private final String method;
    private final String urlBase;
    private final byte[] rawPath;
    private final byte[] rawQuery;
    private final String traceId;
    private final String parentSpanId;
    private final String spanId = ExchangeContext.newSpanId();
    private final long t0 = System.nanoTime();
    private final long tsMs = System.currentTimeMillis();
    private final long setupNs;
    private final boolean inheritedSampled;
    public final BodyTap req;
    public final BodyTap resp;
    private List<Exchange.Header> reqHeaders = new ArrayList<>();
    private final AtomicBoolean done = new AtomicBoolean();

    private OutboundCapture(TrafficTwin tt, Sanitizer san, Sanitizer.Decision d, String method, URI uri, String traceId, String parentSpanId, long setupNs) {
        this.tt = tt;
        this.san = san;
        this.decision = d;
        this.method = method;
        this.urlBase = base(uri);
        this.rawPath = rawPath(uri);
        this.rawQuery = uri.getRawQuery() == null ? null : uri.getRawQuery().getBytes(StandardCharsets.UTF_8);
        this.traceId = traceId;
        this.parentSpanId = parentSpanId;
        this.setupNs = setupNs;
        this.inheritedSampled = d.sampled();
        int limit = san.policy.captureLimit(); // 9.0, 22.5: max(max_body_bytes, bodies.max_large_body_bytes) + 1
        this.req = new BodyTap(limit);
        this.resp = new BodyTap(limit);
    }

    private static String base(URI u) {
        String scheme = u.getScheme() == null ? "" : u.getScheme();
        String host = u.getHost() == null ? (u.getAuthority() == null ? "" : u.getAuthority()) : u.getHost();
        // Spec v1.5 (point 9): the host as the client sees it. IPv6 literals keep their brackets (URI.getHost does),
        // a final dot stays and no IDN conversion is made; the sanitizer decides what is valid.
        return scheme + "://" + host + (u.getPort() >= 0 ? ":" + u.getPort() : "");
    }

    private static byte[] rawPath(URI u) {
        String p = u.getRawPath();
        return (p == null || p.isEmpty() ? "/" : p).getBytes(StandardCharsets.UTF_8);
    }

    /** Starts capturing a call, or returns null (not capturing, not sampled, or any internal problem). Never throws. */
    public static OutboundCapture begin(String method, URI uri) {
        try {
            TrafficTwin tt = TrafficTwin.current();
            Sanitizer san = tt == null ? null : tt.active();
            if (san == null || uri == null) return null;
            long t = System.nanoTime();
            tt.noteSeen();
            ExchangeContext ctx = ExchangeContext.current();
            OtelContext.Ids otel = OtelContext.active();
            Exchange probe = new Exchange();
            probe.inbound = false;
            String traceId;
            String parent = null;
            if (ctx != null) {
                if (!ctx.traceKnown && otel != null) {
                    ctx.traceId = otel.traceId();
                    ctx.traceKnown = true;
                }
                traceId = ctx.traceId;
                parent = ctx.spanId;
                probe.inherited = ctx.sampled;
            } else if (otel != null) {
                traceId = otel.traceId();
                parent = otel.spanId().isEmpty() ? null : otel.spanId();
                probe.traceId = traceId;
            } else {
                traceId = ExchangeContext.newTraceId();
            }
            Sanitizer.Decision d = san.decide(probe);
            if (!d.sampled()) return null;
            tt.noteSampled();
            return new OutboundCapture(tt, san, d, method == null ? "" : method, uri, traceId, parent, System.nanoTime() - t);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** New baggage value with {@code tt.s} for hosts listed in {@code sampling.propagate_to}, or null to leave the request alone. */
    public String baggageFor(String existing) {
        try {
            return tt.mayPropagate(urlBase) ? ExchangeContext.withTtS(existing, inheritedSampled) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    public void requestHeaders(List<Exchange.Header> headers) {
        this.reqHeaders = headers;
    }

    public void addRequestHeader(String name, String value) {
        reqHeaders.add(new Exchange.Header(name, value.getBytes(StandardCharsets.ISO_8859_1)));
    }

    /**
     * Completes the call with a response. {@code reqComplete}/{@code respComplete} say whether every body byte went
     * through the taps (otherwise the body is "not consumed", 9.0).
     */
    public void finish(int status, List<Exchange.Header> respHeaders, boolean reqComplete, boolean respComplete) {
        submit(status, null, respHeaders, reqComplete, respComplete);
    }

    /** Completes the call with a network error. */
    public void fail(Throwable t) {
        submit(-1, netErrorOf(t), List.of(), req.ended() || req.total() == 0, false);
    }

    private void submit(int status, String netError, List<Exchange.Header> respHeaders, boolean reqComplete, boolean respComplete) {
        if (!done.compareAndSet(false, true)) return;
        long t = System.nanoTime();
        try {
            final byte[] reqBody = reqComplete ? req.bytes() : new byte[0];
            final byte[] respBody = respComplete ? resp.bytes() : new byte[0];
            final long reqTotal = reqComplete ? req.total() : 0;
            final long respTotal = respComplete ? resp.total() : 0;
            final List<Exchange.Header> rh = reqHeaders;
            RawExchange raw = new RawExchange();
            raw.sanitizer = san;
            raw.decision = decision;
            raw.inbound = false;
            raw.tsMs = tsMs;
            raw.latencyMs = Math.max(0, (t - t0) / 1_000_000);
            raw.traceId = traceId;
            raw.spanId = spanId;
            raw.parentSpanId = parentSpanId;
            raw.status = status;
            raw.netError = netError;
            raw.heldBytes = reqBody.length + respBody.length;
            raw.build = () -> {
                Exchange ex = new Exchange();
                ex.inbound = false;
                ex.urlBase = urlBase;
                ex.method = method;
                ex.rawPath = rawPath;
                ex.rawQuery = rawQuery;
                ex.inherited = decision.by().equals("inherited") ? Boolean.valueOf(decision.sampled()) : null;
                ex.reqHeaders = rh;
                ex.reqBody = reqBody;
                ex.reqBodyTotal = reqTotal;
                ex.reqBodyConsumed = reqComplete;
                if (netError != null) {
                    ex.netError = netError;
                } else {
                    ex.status = status;
                    ex.respHeaders = respHeaders;
                    ex.respBody = respBody;
                    ex.respBodyTotal = respComplete ? respTotal : Exchange.UNKNOWN;
                    ex.respBodyConsumed = respComplete;
                }
                return ex;
            };
            tt.submit(raw);
            tt.noteOverhead(setupNs + (System.nanoTime() - t));
        } catch (RuntimeException e) {
            tt.noteError("capture_outbound_finish");
        }
    }

    /** Maps a network failure to the event enum (event.md). */
    public static String netErrorOf(Throwable t) {
        Throwable c = t;
        for (int i = 0; i < 8 && c != null; i++) {
            if (c instanceof HttpTimeoutException || c instanceof SocketTimeoutException || c instanceof java.util.concurrent.TimeoutException) return "timeout";
            if (c instanceof ConnectException) return c.getMessage() != null && c.getMessage().toLowerCase(java.util.Locale.ROOT).contains("timed out") ? "timeout" : "refused";
            if (c instanceof UnknownHostException) return "dns";
            if (c instanceof SSLException) return "tls";
            if (c instanceof SocketException) return "reset";
            if (c instanceof java.io.EOFException) return "reset";
            c = c.getCause();
        }
        return "other";
    }
}
