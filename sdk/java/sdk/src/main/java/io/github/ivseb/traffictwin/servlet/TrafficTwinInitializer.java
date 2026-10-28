package io.github.ivseb.traffictwin.servlet;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import java.util.EnumSet;
import java.util.Set;

/**
 * Registers {@link TrafficTwinFilter} automatically (first in the chain, REQUEST and ASYNC) when the
 * web application starts with {@code TT_ENROLL_URL} set and {@code TT_DISABLED} not set. Without the
 * variable it does nothing: dropping the jar into an application never changes it by itself.
 */
public final class TrafficTwinInitializer implements ServletContainerInitializer {
    @Override
    public void onStartup(Set<Class<?>> classes, ServletContext ctx) throws ServletException {
        if (System.getenv("TT_ENROLL_URL") == null || "1".equals(System.getenv("TT_DISABLED"))) return;
        register(ctx);
    }

    /** Registers the filter on a context (also for manual use in code-based configuration). */
    public static void register(ServletContext ctx) {
        if (ctx.getFilterRegistration("traffic-twin") != null) return;
        var reg = ctx.addFilter("traffic-twin", TrafficTwinFilter.class);
        if (reg != null) reg.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC), false, "/*");
    }
}
