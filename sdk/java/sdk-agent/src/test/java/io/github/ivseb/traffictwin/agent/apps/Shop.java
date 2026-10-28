package io.github.ivseb.traffictwin.agent.apps;

import java.util.Set;

/**
 * The code of the test application. It knows nothing about traffic-twin: no import, no filter, no
 * wrapper. POST /orders books a shipment at the carrier with the HTTP clients named in
 * {@code -Dtt.app.outbound=jdk,spring,restclient,okhttp}.
 */
public final class Shop {
    private Shop() {}

    public static final String CARRIER = System.getProperty("tt.app.carrier", "");

    public static String order(byte[] body) throws Exception {
        Set<String> clients = Set.of(System.getProperty("tt.app.outbound", "jdk").split(","));
        if (clients.contains("jdk")) JdkCalls.book(CARRIER);
        if (clients.contains("spring")) SpringCalls.book(CARRIER);
        if (clients.contains("restclient")) SpringCalls.bookWithRestClient(CARRIER);
        if (clients.contains("okhttp")) OkHttpCalls.book(CARRIER);
        return "{\"id\":\"ORD-2026-000184\",\"status\":\"CREATED\",\"echo\":" + body.length + "}";
    }

    /** Reads a JSON object the way a streaming parser does: stops right after the closing brace, without a final read(). */
    public static byte[] readJsonObject(java.io.InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8000];
        int depth = 0;
        boolean started = false;
        while (!started || depth > 0) {
            int n = in.read(buf);
            if (n < 0) break;
            out.write(buf, 0, n);
            for (int i = 0; i < n; i++) {
                if (buf[i] == '{') {
                    depth++;
                    started = true;
                } else if (buf[i] == '}') {
                    depth--;
                }
            }
        }
        return out.toByteArray();
    }

    static final String SHIPMENT = "{\"orderId\":\"ORD-2026-000184\",\"email\":\"giulia.neri@example.com\"}";
}
