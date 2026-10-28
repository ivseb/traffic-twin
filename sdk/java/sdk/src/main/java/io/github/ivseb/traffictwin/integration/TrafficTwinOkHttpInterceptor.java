package io.github.ivseb.traffictwin.integration;

import io.github.ivseb.traffictwin.capture.OutboundCapture;
import io.github.ivseb.traffictwin.sanitizer.Exchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;
import okio.BufferedSource;
import okio.ForwardingSource;
import okio.Okio;

/**
 * OkHttp application interceptor (optional integration: OkHttp is a compile-only dependency).
 * {@code new OkHttpClient.Builder().addInterceptor(new TrafficTwinOkHttpInterceptor()).build()}.
 *
 * <p>The response body is tee'd as the application reads it: nothing is read ahead, so streaming
 * responses are not delayed. Request bodies are copied only when their length is known and within
 * {@code max(max_body_bytes, bodies.max_large_body_bytes)}; otherwise they are reported as truncated.
 */
public final class TrafficTwinOkHttpInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request req = chain.request();
        OutboundCapture cap = null;
        Request send = req;
        try {
            cap = OutboundCapture.begin(req.method(), req.url().uri());
            if (cap != null) {
                List<Exchange.Header> hs = new ArrayList<>();
                Headers h = req.headers();
                for (int i = 0; i < h.size(); i++) hs.add(new Exchange.Header(h.name(i), h.value(i).getBytes(StandardCharsets.ISO_8859_1)));
                RequestBody rb = req.body();
                if (rb != null) {
                    MediaType ct = rb.contentType();
                    if (ct != null && req.header("Content-Type") == null) hs.add(new Exchange.Header("Content-Type", ct.toString().getBytes(StandardCharsets.ISO_8859_1)));
                    long len = rb.contentLength();
                    long max = (long) cap.req.limit();
                    if (!rb.isOneShot() && !rb.isDuplex() && len >= 0 && len < max) {
                        Buffer buf = new Buffer();
                        rb.writeTo(buf);
                        byte[] bytes = buf.readByteArray();
                        cap.req.add(bytes, 0, bytes.length);
                        cap.req.markEnded();
                    } else if (len >= max) {
                        cap.req.addCount(len); // longer than the limit: only its size matters
                        cap.req.markEnded();
                    } // else unknown length: left "not consumed" (trunc:size)
                } else {
                    cap.req.markEnded();
                }
                cap.requestHeaders(hs);
                String bag = cap.baggageFor(req.header("baggage"));
                if (bag != null) send = req.newBuilder().header("baggage", bag).build();
            }
        } catch (RuntimeException e) {
            cap = null; // capture failed: the call proceeds untouched
            send = req;
        }
        if (cap == null) return chain.proceed(req);
        final OutboundCapture c = cap;
        Response resp;
        try {
            resp = chain.proceed(send);
        } catch (IOException | RuntimeException e) {
            c.fail(e);
            throw e;
        }
        ResponseBody body = resp.body();
        if (body == null) {
            c.resp.markEnded();
            finish(c, resp);
            return resp;
        }
        return resp.newBuilder().body(new TeeBody(body, c, resp)).build();
    }

    private static void finish(OutboundCapture c, Response resp) {
        try {
            List<Exchange.Header> hs = new ArrayList<>();
            Headers h = resp.headers();
            for (int i = 0; i < h.size(); i++) hs.add(new Exchange.Header(h.name(i), h.value(i).getBytes(StandardCharsets.ISO_8859_1)));
            boolean noBody = resp.request().method().equalsIgnoreCase("HEAD") || resp.code() == 204 || resp.code() == 304;
            long cl = -1;
            try {
                String v = resp.header("Content-Length");
                if (v != null) cl = Long.parseLong(v.trim());
            } catch (NumberFormatException e) {
                cl = -1;
            }
            // Readers often stop after Content-Length bytes without asking for the end of the stream.
            boolean allRead = cl > 0 && c.resp.total() >= cl;
            c.finish(resp.code(), hs, c.req.ended(), c.resp.ended() || noBody || allRead || cl == 0);
        } catch (RuntimeException e) {
            // never affect the application
        }
    }

    private static final class TeeBody extends ResponseBody {
        private final ResponseBody inner;
        private final OutboundCapture cap;
        private final Response resp;
        private BufferedSource source;

        TeeBody(ResponseBody inner, OutboundCapture cap, Response resp) {
            this.inner = inner;
            this.cap = cap;
            this.resp = resp;
        }

        @Override
        public MediaType contentType() {
            return inner.contentType();
        }

        @Override
        public long contentLength() {
            return inner.contentLength();
        }

        @Override
        public BufferedSource source() {
            if (source == null) {
                source = Okio.buffer(new ForwardingSource(inner.source()) {
                    @Override
                    public long read(Buffer sink, long byteCount) throws IOException {
                        long before = sink.size();
                        long n = super.read(sink, byteCount);
                        if (n > 0) {
                            Buffer copy = new Buffer();
                            sink.copyTo(copy, before, n);
                            byte[] b = copy.readByteArray();
                            cap.resp.add(b, 0, b.length);
                        } else if (n < 0) {
                            cap.resp.markEnded();
                            finish(cap, resp);
                        }
                        return n;
                    }

                    @Override
                    public void close() throws IOException {
                        super.close();
                        finish(cap, resp); // not read to the end = not consumed (9.0)
                    }
                });
            }
            return source;
        }
    }
}
