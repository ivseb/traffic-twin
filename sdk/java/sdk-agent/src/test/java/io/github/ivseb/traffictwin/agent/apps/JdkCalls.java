package io.github.ivseb.traffictwin.agent.apps;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

final class JdkCalls {
    private JdkCalls() {}

    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    static void book(String carrier) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(carrier + "/v1/shipments"))
            .header("content-type", "application/json").header("authorization", "Bearer carrier-api-key").header("x-client", "jdk")
            .POST(HttpRequest.BodyPublishers.ofString(Shop.SHIPMENT)).build();
        HttpResponse<String> r = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
        if (!r.body().contains("SHP-5521")) throw new IllegalStateException("carrier answer changed: " + r.body());
    }
}
