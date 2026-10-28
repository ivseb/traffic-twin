package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.github.ivseb.traffictwin.capture.ExchangeContext;
import io.github.ivseb.traffictwin.integration.TrafficTwinJaxrsFilter;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.UriInfo;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import org.junit.jupiter.api.Test;

/** The JAX-RS filter computes the complete route (base path + class @Path + method @Path) and publishes it in the exchange context. */
class JaxrsRouteTest {
    @Path("/orders")
    public static class OrdersResource {
        @GET
        @Path("{ id : [0-9]+ }/shipment")
        public String shipment() {
            return "";
        }

        @GET
        public String list() {
            return "";
        }
    }

    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, java.util.function.BiFunction<Method, Object[], Object> h) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, a) -> h.apply(m, a));
    }

    ContainerRequestContext request(String base) {
        UriInfo ui = proxy(UriInfo.class, (m, a) -> m.getName().equals("getBaseUri") ? URI.create(base) : null);
        return proxy(ContainerRequestContext.class, (m, a) -> m.getName().equals("getUriInfo") ? ui : null);
    }

    TrafficTwinJaxrsFilter filter(Method method) throws Exception {
        TrafficTwinJaxrsFilter f = new TrafficTwinJaxrsFilter();
        ResourceInfo ri = proxy(ResourceInfo.class, (m, a) -> m.getName().equals("getResourceClass") ? OrdersResource.class : method);
        Field fld = TrafficTwinJaxrsFilter.class.getDeclaredField("resourceInfo");
        fld.setAccessible(true);
        fld.set(f, ri);
        return f;
    }

    @Test
    void routeIsBasePathPlusClassPlusMethodPath() throws Exception {
        ExchangeContext ctx = new ExchangeContext(true, ExchangeContext.newTraceId(), true, ExchangeContext.newSpanId());
        ExchangeContext.set(ctx);
        try {
            filter(OrdersResource.class.getMethod("shipment")).filter(request("http://h:8080/shop/api/"));
            assertEquals("/shop/api/orders/{ id : [0-9]+ }/shipment", ctx.frameworkRoute);
            assertEquals("jaxrs", ctx.framework);
            // and it normalizes (sanitizer.md 3.4: JAX-RS row, spaces ignored)
            var segs = io.github.ivseb.traffictwin.sanitizer.Sanitizer.normalizeFrameworkRoute(ctx.frameworkRoute, ctx.framework);
            assertEquals(5, segs.length);
            assertEquals("id", segs[3].param());
            ExchangeContext.set(new ExchangeContext(true, ExchangeContext.newTraceId(), true, ExchangeContext.newSpanId()));
            ExchangeContext c2 = ExchangeContext.current();
            filter(OrdersResource.class.getMethod("list")).filter(request("http://h/"));
            assertEquals("/orders", c2.frameworkRoute);
        } finally {
            ExchangeContext.set(null);
        }
    }

    @Test
    void doesNothingOutsideAnInboundExchange() throws Exception {
        ExchangeContext.set(null);
        filter(OrdersResource.class.getMethod("list")).filter(request("http://h/"));
        assertNull(ExchangeContext.current());
    }
}
