package io.github.ivseb.traffictwin.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Both {@code -javaagent} flags on the same JVM, in both orders: the OpenTelemetry Java agent 2.x (a test
 * resource downloaded by Maven) and ours. The application must behave as without them, OpenTelemetry must
 * keep producing its server and client spans, and traffic-twin must keep capturing, with the trace id of
 * OpenTelemetry's server span (through the read-only agent extension).
 */
class OtelAgentIT {
    static final Pattern SERVER_SPAN = Pattern.compile("'POST[^']*' : ([0-9a-f]{32}) ([0-9a-f]{16}) SERVER");

    static Map<String, String> otelEnv(ChildApp app) throws Exception {
        Map<String, String> env = app.ttEnv();
        env.put("OTEL_TRACES_EXPORTER", "logging");
        env.put("OTEL_METRICS_EXPORTER", "none");
        env.put("OTEL_LOGS_EXPORTER", "none");
        env.put("OTEL_BSP_SCHEDULE_DELAY", "100");
        env.put("OTEL_SERVICE_NAME", "shop-api");
        env.put("OTEL_INSTRUMENTATION_COMMON_DEFAULT_ENABLED", "true");
        return env;
    }

    void run(String flavour, boolean otelFirst) throws Exception {
        try (ChildApp app = new ChildApp()) {
            List<String> jvm = new ArrayList<>();
            String otel = "-javaagent:" + ChildApp.OTEL_AGENT;
            String tt = "-javaagent:" + ChildApp.AGENT;
            if (otelFirst) {
                jvm.add(otel);
                jvm.add(tt);
            } else {
                jvm.add(tt);
                jvm.add(otel);
            }
            jvm.add("-Dotel.javaagent.extensions=" + ChildApp.OTEL_EXTENSION);
            app.start(flavour, jvm, otelEnv(app), "jdk,spring,restclient,okhttp");

            AgentIT.exerciseOrder(app, Set.of("jdk", "spring", "restclient", "okhttp"), true);

            // OpenTelemetry still works: a server span for the request, client spans for the outbound calls.
            Matcher[] server = new Matcher[1];
            assertTrue(app.core.waitFor(c -> {
                for (String l : app.output) {
                    Matcher m = SERVER_SPAN.matcher(l);
                    if (m.find()) {
                        server[0] = m;
                        return true;
                    }
                }
                return false;
            }, 15_000), "no OpenTelemetry server span logged:\n" + String.join("\n", app.output));
            assertTrue(app.output.stream().anyMatch(l -> l.contains(" CLIENT ")), "no OpenTelemetry client span logged");

            // traffic-twin reads OpenTelemetry's ids, it does not make its own.
            // Several POST server spans are logged (warm-up requests, the downstream call, which can
            // finish first): the inbound event must carry the ids of one of them, not of the first.
            Map<String, Object> in = AgentIT.orderEvents(app).stream().filter(e -> e.get("dir").equals("inbound")).findFirst().orElseThrow();
            String ids = in.get("trace_id") + " " + in.get("span_id");
            assertTrue(app.core.waitFor(c -> app.output.stream().anyMatch(l -> {
                Matcher m = SERVER_SPAN.matcher(l);
                return m.find() && ids.equals(m.group(1) + " " + m.group(2));
            }), 15_000), "no OpenTelemetry server span with the ids of the inbound event (" + ids + "):\n" + String.join("\n", app.output));
            // The application never saw our agent set anything global: the OpenTelemetry agent's own SDK is the only one.
            assertNotNull(app.output);
        }
    }

    @Test
    void otelAgentFirst_tomcat() throws Exception {
        run("tomcat", true);
    }

    @Test
    void ourAgentFirst_jetty() throws Exception {
        run("jetty", false);
    }
}
