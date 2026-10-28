package io.github.ivseb.traffictwin.agent.apps;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

final class OkHttpCalls {
    private OkHttpCalls() {}

    // The bare constructor, on purpose: the hook must not depend on how the client was built.
    private static final OkHttpClient CLIENT = new OkHttpClient();

    static void book(String carrier) throws Exception {
        Request req = new Request.Builder().url(carrier + "/v1/shipments").header("x-client", "okhttp")
            .post(RequestBody.create(Shop.SHIPMENT, MediaType.get("application/json"))).build();
        try (Response r = CLIENT.newCall(req).execute()) {
            String body = r.body().string();
            if (!body.contains("SHP-5521")) throw new IllegalStateException("carrier answer changed: " + body);
        }
    }
}
