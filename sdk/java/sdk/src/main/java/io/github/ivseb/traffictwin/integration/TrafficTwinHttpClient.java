package io.github.ivseb.traffictwin.integration;

import io.github.ivseb.traffictwin.capture.OutboundCapture;
import io.github.ivseb.traffictwin.sanitizer.Exchange;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpResponse.PushPromiseHandler;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * Wrapper around {@link java.net.http.HttpClient} that captures outbound calls. Wrap the client the
 * application already builds: {@code HttpClient c = TrafficTwinHttpClient.wrap(HttpClient.newHttpClient())}.
 *
 * <p>The wrapper tees request and response bodies as they flow (nothing is buffered beyond
 * {@code max(max_body_bytes, bodies.max_large_body_bytes) + 1}), never changes the response the caller receives, and falls back to
 * the plain client if anything about the capture fails. The only request change, opt-in through
 * {@code sampling.propagate_to}, is the {@code tt.s} baggage member toward internal hosts.
 */
public final class TrafficTwinHttpClient extends HttpClient {
    private final HttpClient delegate;

    private TrafficTwinHttpClient(HttpClient delegate) {
        this.delegate = delegate;
    }

    public static HttpClient wrap(HttpClient client) {
        return client instanceof TrafficTwinHttpClient ? client : new TrafficTwinHttpClient(client);
    }

    @Override public Optional<CookieHandler> cookieHandler() { return delegate.cookieHandler(); }
    @Override public Optional<Duration> connectTimeout() { return delegate.connectTimeout(); }
    @Override public Redirect followRedirects() { return delegate.followRedirects(); }
    @Override public Optional<ProxySelector> proxy() { return delegate.proxy(); }
    @Override public SSLContext sslContext() { return delegate.sslContext(); }
    @Override public SSLParameters sslParameters() { return delegate.sslParameters(); }
    @Override public Optional<Authenticator> authenticator() { return delegate.authenticator(); }
    @Override public Version version() { return delegate.version(); }
    @Override public Optional<Executor> executor() { return delegate.executor(); }

    private static final class Prepared<T> {
        final OutboundCapture cap;
        final HttpRequest request;
        final BodyHandler<T> handler;

        Prepared(OutboundCapture cap, HttpRequest request, BodyHandler<T> handler) {
            this.cap = cap;
            this.request = request;
            this.handler = handler;
        }
    }

    private static List<Exchange.Header> headersOf(HttpHeaders h) {
        List<Exchange.Header> out = new ArrayList<>();
        h.map().forEach((n, vs) -> {
            for (String v : vs) out.add(new Exchange.Header(n, v.getBytes(StandardCharsets.ISO_8859_1)));
        });
        return out;
    }

    /** Set while a wrapper delegates to the JDK client, so the java agent hook does not capture the same call twice. */
    private static final ThreadLocal<Boolean> INSIDE = new ThreadLocal<>();

    /**
     * Marks the calling thread as already capturing: another integration (for example the Spring interceptor
     * over a RestClient backed by {@code java.net.http}) wraps the JDK client below it, and the agent hook must
     * not capture the same call a second time. Returns what to pass to {@link #exitScope}.
     */
    public static boolean enterScope() {
        boolean was = INSIDE.get() != null;
        INSIDE.set(Boolean.TRUE);
        return was;
    }

    public static void exitScope(boolean was) {
        if (!was) INSIDE.remove();
    }

    /**
     * Entry point of the {@code -javaagent} hook on {@code jdk.internal.net.http.HttpClientFacade}: returns the
     * {@code {request, bodyHandler}} pair to send instead of the application's (tee'd), or null to send them
     * untouched. Not part of the public API.
     */
    public static Object[] agentPrepare(HttpRequest request, BodyHandler<?> handler) {
        if (INSIDE.get() != null) return null; // an explicit wrapper is already capturing this call
        if (Thread.currentThread().getName().startsWith("tt-")) return null; // the SDK's own Fleet and export calls
        Prepared<?> p = prepare(request, handler);
        return p == null ? null : new Object[] {p.request, p.handler};
    }

    private static <T> Prepared<T> prepare(HttpRequest request, BodyHandler<T> handler) {
        OutboundCapture cap = OutboundCapture.begin(request.method(), request.uri());
        if (cap == null) return null;
        try {
            cap.requestHeaders(headersOf(request.headers()));
            HttpRequest.Builder b = HttpRequest.newBuilder(request, (n, v) -> true);
            Optional<HttpRequest.BodyPublisher> pub = request.bodyPublisher();
            if (pub.isPresent()) b.method(request.method(), new TeePublisher(pub.get(), cap));
            else cap.req.markEnded();
            String bag = cap.baggageFor(request.headers().firstValue("baggage").orElse(null));
            if (bag != null) b.setHeader("baggage", bag);
            return new Prepared<>(cap, b.build(), info -> new TeeSubscriber<>(handler.apply(info), cap, info));
        } catch (RuntimeException e) {
            return null; // capture failed: the call proceeds untouched
        }
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        Prepared<T> p = prepare(request, responseBodyHandler);
        INSIDE.set(Boolean.TRUE);
        try {
            if (p == null) return delegate.send(request, responseBodyHandler);
            try {
                return delegate.send(p.request, p.handler);
            } catch (IOException | InterruptedException | RuntimeException e) {
                p.cap.fail(e);
                throw e;
            }
        } finally {
            INSIDE.remove();
        }
    }

    private static <T> CompletableFuture<HttpResponse<T>> inside(java.util.function.Supplier<CompletableFuture<HttpResponse<T>>> call) {
        INSIDE.set(Boolean.TRUE);
        try {
            return call.get();
        } finally {
            INSIDE.remove();
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> responseBodyHandler) {
        Prepared<T> p = prepare(request, responseBodyHandler);
        if (p == null) return inside(() -> delegate.sendAsync(request, responseBodyHandler));
        CompletableFuture<HttpResponse<T>> f = inside(() -> delegate.sendAsync(p.request, p.handler));
        f.whenComplete((r, t) -> {
            if (t != null) p.cap.fail(t);
        });
        return f;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> responseBodyHandler,
                                                            PushPromiseHandler<T> pushPromiseHandler) {
        Prepared<T> p = prepare(request, responseBodyHandler);
        if (p == null) return inside(() -> delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler));
        CompletableFuture<HttpResponse<T>> f = inside(() -> delegate.sendAsync(p.request, p.handler, pushPromiseHandler));
        f.whenComplete((r, t) -> {
            if (t != null) p.cap.fail(t);
        });
        return f;
    }

    // ---------------------------------------------------------------------------------

    /** Publisher that copies the bytes handed to the HTTP client without changing them. */
    private static final class TeePublisher implements HttpRequest.BodyPublisher {
        private final HttpRequest.BodyPublisher inner;
        private final OutboundCapture cap;

        TeePublisher(HttpRequest.BodyPublisher inner, OutboundCapture cap) {
            this.inner = inner;
            this.cap = cap;
        }

        @Override
        public long contentLength() {
            return inner.contentLength();
        }

        @Override
        public void subscribe(Flow.Subscriber<? super ByteBuffer> s) {
            cap.req.reset(); // published again after a redirect or a retry
            inner.subscribe(new Flow.Subscriber<ByteBuffer>() {
                @Override
                public void onSubscribe(Flow.Subscription sub) {
                    s.onSubscribe(sub);
                }

                @Override
                public void onNext(ByteBuffer item) {
                    cap.req.add(item); // copies without consuming
                    s.onNext(item);
                }

                @Override
                public void onError(Throwable t) {
                    s.onError(t);
                }

                @Override
                public void onComplete() {
                    cap.req.markEnded();
                    s.onComplete();
                }
            });
        }
    }

    /** Body subscriber that copies the bytes it is given and finishes the capture when the body ends. */
    private static final class TeeSubscriber<T> implements BodySubscriber<T> {
        private final BodySubscriber<T> inner;
        private final OutboundCapture cap;
        private final HttpResponse.ResponseInfo info;

        TeeSubscriber(BodySubscriber<T> inner, OutboundCapture cap, HttpResponse.ResponseInfo info) {
            this.inner = inner;
            this.cap = cap;
            this.info = info;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            inner.onSubscribe(subscription);
        }

        @Override
        public void onNext(List<ByteBuffer> item) {
            for (ByteBuffer b : item) cap.resp.add(b);
            inner.onNext(item);
        }

        @Override
        public void onError(Throwable throwable) {
            cap.fail(throwable);
            inner.onError(throwable);
        }

        @Override
        public void onComplete() {
            cap.resp.markEnded();
            try {
                cap.finish(info.statusCode(), headersOf(info.headers()), cap.req.ended() || cap.req.total() == 0, true);
            } catch (RuntimeException e) {
                // never affect the application
            }
            inner.onComplete();
        }

        @Override
        public java.util.concurrent.CompletionStage<T> getBody() {
            return inner.getBody();
        }
    }

    /** Test hook: the wrapped client. */
    public HttpClient delegate() {
        return delegate;
    }
}
