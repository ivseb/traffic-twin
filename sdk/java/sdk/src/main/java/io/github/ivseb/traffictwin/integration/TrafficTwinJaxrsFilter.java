package io.github.ivseb.traffictwin.integration;

import io.github.ivseb.traffictwin.capture.ExchangeContext;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;
import java.lang.reflect.Method;

/**
 * JAX-RS (Jersey, RESTEasy, CXF) post-matching filter that tells the servlet capture which template
 * served the request (sanitizer.md 3.4, JAX-RS row). Register it as a provider next to the resources:
 * {@code register(TrafficTwinJaxrsFilter.class)}. It only reads the matched resource class and method
 * ({@code @Path} values and the application base path) and stores the complete route in the
 * exchange context of the request thread; it changes nothing in the request or the response.
 */
@Provider
public final class TrafficTwinJaxrsFilter implements ContainerRequestFilter {
    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            ExchangeContext ec = ExchangeContext.current();
            if (ec == null || !ec.sampled || resourceInfo == null) return;
            Class<?> cls = resourceInfo.getResourceClass();
            Method m = resourceInfo.getResourceMethod();
            if (cls == null || m == null) return;
            String base = ctx.getUriInfo().getBaseUri().getPath();
            ec.frameworkRoute = route(base, cls, m);
            ec.framework = "jaxrs";
        } catch (RuntimeException e) {
            // never affect the application
        }
    }

    /** Complete route: base URI path (context path and application path), class {@code @Path}, method {@code @Path}. */
    static String route(String basePath, Class<?> cls, Method m) {
        StringBuilder sb = new StringBuilder(basePath == null ? "" : basePath.replaceAll("/+$", ""));
        Path cp = cls.getAnnotation(Path.class);
        Path mp = m.getAnnotation(Path.class);
        if (cp != null) append(sb, cp.value());
        if (mp != null) append(sb, mp.value());
        return sb.length() == 0 ? "/" : sb.toString();
    }

    private static void append(StringBuilder sb, String p) {
        String v = p.startsWith("/") ? p : "/" + p;
        sb.append(v.replaceAll("/+$", ""));
    }
}
