package io.github.ivseb.traffictwin.agent.apps;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

final class SpringCalls {
    private SpringCalls() {}

    static void book(String carrier) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("x-client", "spring");
        String r = new RestTemplate().postForObject(carrier + "/v1/shipments", new HttpEntity<>(Shop.SHIPMENT, h), String.class);
        if (r == null || !r.contains("SHP-5521")) throw new IllegalStateException("carrier answer changed: " + r);
    }

    static void bookWithRestClient(String carrier) {
        String r = RestClient.builder().build().post().uri(carrier + "/v1/shipments")
            .contentType(MediaType.APPLICATION_JSON).header("x-client", "restclient").body(Shop.SHIPMENT).retrieve().body(String.class);
        if (r == null || !r.contains("SHP-5521")) throw new IllegalStateException("carrier answer changed: " + r);
    }
}
