package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.ivseb.traffictwin.servlet.TrafficTwinFilter;
import io.github.ivseb.traffictwin.servlet.TrafficTwinInitializer;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.Test;

/** The programmatic registration used by the ServletContainerInitializer. */
class InitializerTest {
    @Test
    void registersTheFilterOnceForAllPaths() throws Exception {
        AtomicReference<jakarta.servlet.FilterRegistration> reg = new AtomicReference<>();
        ServletContextHandler h = new ServletContextHandler() {
            @Override
            protected void startContext() throws Exception {
                TrafficTwinInitializer.register(getServletContext());
                TrafficTwinInitializer.register(getServletContext()); // idempotent
                reg.set(getServletContext().getFilterRegistration("traffic-twin"));
                super.startContext();
            }
        };
        h.setContextPath("/");
        Server server = new Server();
        server.setHandler(h);
        server.start();
        try {
            assertNotNull(reg.get());
            assertEquals(TrafficTwinFilter.class.getName(), reg.get().getClassName());
            assertEquals(List.of("/*"), List.copyOf(reg.get().getUrlPatternMappings()));
        } finally {
            server.stop();
        }
    }
}
