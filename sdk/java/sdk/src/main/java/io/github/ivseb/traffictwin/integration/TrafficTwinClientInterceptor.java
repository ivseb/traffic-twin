package io.github.ivseb.traffictwin.integration;

import io.github.ivseb.traffictwin.capture.OutboundCapture;
import io.github.ivseb.traffictwin.sanitizer.Exchange;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Spring {@code RestTemplate} / {@code RestClient} interceptor (optional integration: Spring is a
 * compile-only dependency, this class is loaded only if the application uses it).
 *
 * <pre>{@code
 * restTemplate.getInterceptors().add(new TrafficTwinClientInterceptor());
 * RestClient.builder().requestInterceptor(new TrafficTwinClientInterceptor()).build();
 * }</pre>
 */
public final class TrafficTwinClientInterceptor implements ClientHttpRequestInterceptor {
    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        OutboundCapture cap = null;
        try {
            cap = OutboundCapture.begin(request.getMethod().name(), request.getURI());
            if (cap != null) {
                cap.requestHeaders(headersOf(request.getHeaders()));
                if (body != null) cap.req.add(body, 0, body.length);
                cap.req.markEnded();
                String bag = cap.baggageFor(request.getHeaders().getFirst("baggage"));
                if (bag != null) request.getHeaders().set("baggage", bag);
            }
        } catch (RuntimeException e) {
            cap = null; // capture failed: the call proceeds untouched
        }
        // The request factory below may be backed by java.net.http: tell the agent hook this call is ours.
        boolean was = TrafficTwinHttpClient.enterScope();
        try {
            if (cap == null) return execution.execute(request, body);
            ClientHttpResponse resp;
            try {
                resp = execution.execute(request, body);
            } catch (IOException | RuntimeException e) {
                cap.fail(e);
                throw e;
            }
            return new TeeResponse(resp, cap, request.getMethod().name());
        } finally {
            TrafficTwinHttpClient.exitScope(was);
        }
    }

    static List<Exchange.Header> headersOf(HttpHeaders h) {
        List<Exchange.Header> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            for (String v : e.getValue()) out.add(new Exchange.Header(e.getKey(), v.getBytes(StandardCharsets.ISO_8859_1)));
        }
        return out;
    }

    /** Response whose body stream is tee'd as the application reads it. */
    private static final class TeeResponse implements ClientHttpResponse {
        private final ClientHttpResponse inner;
        private final OutboundCapture cap;
        private final String method;
        private InputStream stream;

        TeeResponse(ClientHttpResponse inner, OutboundCapture cap, String method) {
            this.inner = inner;
            this.cap = cap;
            this.method = method;
        }

        @Override
        public org.springframework.http.HttpStatusCode getStatusCode() throws IOException {
            return inner.getStatusCode();
        }

        @Override
        @SuppressWarnings("deprecation")
        public int getRawStatusCode() throws IOException {
            return inner.getRawStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return inner.getStatusText();
        }

        @Override
        public HttpHeaders getHeaders() {
            return inner.getHeaders();
        }

        @Override
        public InputStream getBody() throws IOException {
            if (stream == null) {
                InputStream in = inner.getBody();
                stream = new InputStream() {
                    @Override
                    public int read() throws IOException {
                        int b = in.read();
                        if (b >= 0) cap.resp.add(b);
                        else eof();
                        return b;
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        int n = in.read(b, off, len);
                        if (n > 0) cap.resp.add(b, off, n);
                        else if (n < 0) eof();
                        return n;
                    }

                    @Override
                    public int available() throws IOException {
                        return in.available();
                    }

                    @Override
                    public void close() throws IOException {
                        in.close();
                    }
                };
            }
            return stream;
        }

        private void eof() {
            cap.resp.markEnded();
            complete();
        }

        private void complete() {
            try {
                int status = inner.getStatusCode().value();
                long cl = inner.getHeaders().getContentLength();
                boolean noBody = method.equalsIgnoreCase("HEAD") || status == 204 || status == 304 || (status >= 100 && status < 200) || cl == 0;
                // Readers often stop after Content-Length bytes without asking for the end of the stream.
                boolean allRead = cl > 0 && cap.resp.total() >= cl;
                cap.finish(status, headersOf(inner.getHeaders()), cap.req.ended(), cap.resp.ended() || noBody || allRead);
            } catch (IOException | RuntimeException e) {
                cap.fail(e);
            }
        }

        @Override
        public void close() {
            complete(); // body not read to the end = not consumed (9.0)
            inner.close();
        }
    }
}
