package io.github.ivseb.traffictwin.agent;

import io.github.ivseb.traffictwin.TrafficTwin;
import io.github.ivseb.traffictwin.integration.TrafficTwinHttpClient;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

/**
 * What the patched methods call (see {@link ClassPatcher}). Every hook receives {@code this} and the
 * arguments in an array and returns the array the original method will be called with. A hook never
 * throws: on any problem it returns its input, which leaves the application exactly as it was.
 */
public final class CoreBridgeImpl implements CoreBridge {
    public CoreBridgeImpl() {}

    private static final String FILTER_NAME = "traffic-twin";
    private static final String JAKARTA_FILTER = "io.github.ivseb.traffictwin.servlet.TrafficTwinFilter";
    private static final String JAVAX_FILTER = "io.github.ivseb.traffictwin.servlet.javax.TrafficTwinFilter";
    private static final String OKHTTP_INTERCEPTOR = "io.github.ivseb.traffictwin.integration.TrafficTwinOkHttpInterceptor";
    private static final String SPRING_INTERCEPTOR = "io.github.ivseb.traffictwin.integration.TrafficTwinClientInterceptor";

    private static volatile boolean startTried;

    /** Starts the SDK agent on first use (lazily: a JVM that never serves or calls anything pays nothing). */
    private static boolean started() {
        if (TrafficTwin.current() != null) return true;
        if (startTried || System.getenv("TT_ENROLL_URL") == null) return false;
        synchronized (CoreBridgeImpl.class) {
            if (startTried) return TrafficTwin.current() != null;
            startTried = true;
            try {
                return TrafficTwin.startFromEnvironment() != null;
            } catch (Throwable t) {
                AgentState.log("start failed: " + t);
                return false;
            }
        }
    }

    // --- servlet containers (Tomcat StandardContext, Jetty ServletContextHandler) ----------------

    /** {@code this} has {@code getServletContext()}; the traffic-twin filter is added first in its chain. */
    @Override
    public Object[] servletContainer(Object[] a) {
        try {
            if (started()) registerFilter(a[0]);
        } catch (Throwable t) {
            AgentState.log("servlet filter not registered: " + t);
        }
        return a;
    }

    private static void registerFilter(Object container) throws Exception {
        Object sc = container.getClass().getMethod("getServletContext").invoke(container);
        if (sc == null) return;
        String ns = null;
        Class<?> scApi = null;
        for (Class<?> c = sc.getClass(); c != null && scApi == null; c = c.getSuperclass()) {
            scApi = findInterface(c, "jakarta.servlet.ServletContext");
            if (scApi != null) {
                ns = "jakarta";
            } else if ((scApi = findInterface(c, "javax.servlet.ServletContext")) != null) {
                ns = "javax";
            }
        }
        if (scApi == null) return;
        ClassLoader api = scApi.getClassLoader();
        if (scApi.getMethod("getFilterRegistration", String.class).invoke(sc, FILTER_NAME) != null) return; // already there
        Class<?> filterApi = Class.forName(ns + ".servlet.Filter", false, api);
        Class<?> filterClass = ExtLoader.forApi(api).loadClass(ns.equals("jakarta") ? JAKARTA_FILTER : JAVAX_FILTER);
        Object filter = filterClass.getDeclaredConstructor().newInstance();
        Object reg = scApi.getMethod("addFilter", String.class, filterApi).invoke(sc, FILTER_NAME, filter);
        if (reg == null) return;
        @SuppressWarnings({"rawtypes", "unchecked"})
        EnumSet<?> dispatchers = enumSet((Class) Class.forName(ns + ".servlet.DispatcherType", false, api), "REQUEST", "ASYNC");
        Class<?> regApi = Class.forName(ns + ".servlet.FilterRegistration", false, api);
        regApi.getMethod("addMappingForUrlPatterns", EnumSet.class, boolean.class, String[].class)
            .invoke(reg, dispatchers, false, new String[] {"/*"});
        AgentState.log("servlet filter registered on " + container.getClass().getName());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static EnumSet<?> enumSet(Class type, String... names) {
        EnumSet set = EnumSet.noneOf(type);
        for (String n : names) set.add(Enum.valueOf(type, n));
        return set;
    }

    private static Class<?> findInterface(Class<?> c, String name) {
        for (Class<?> i : c.getInterfaces()) {
            if (i.getName().equals(name)) return i;
            Class<?> r = findInterface(i, name);
            if (r != null) return r;
        }
        return null;
    }

    // --- java.net.http ---------------------------------------------------------------------

    /** {@code HttpClientFacade.send/sendAsync}: {@code {this, request, bodyHandler[, pushHandler]}}. */
    @Override
    public Object[] httpClient(Object[] a) {
        try {
            if (TrafficTwin.current() == null && !started()) return a;
            Object[] p = TrafficTwinHttpClient.agentPrepare((java.net.http.HttpRequest) a[1], (java.net.http.HttpResponse.BodyHandler<?>) a[2]);
            if (p == null) return a;
            Object[] r = a.clone();
            r[1] = p[0];
            r[2] = p[1];
            return r;
        } catch (Throwable t) {
            return a;
        }
    }

    // --- OkHttp and Spring -------------------------------------------------------------------

    /**
     * {@code OkHttpClient.newCall(Request)}: the client's interceptor list is immutable, so the (private,
     * final) field is replaced once per client by a copy with our interceptor first.
     */
    @Override
    public Object[] okhttpClient(Object[] a) {
        try {
            if (!started()) return a;
            Object client = a[0];
            synchronized (client) {
                Field f = findField(client.getClass(), "interceptors");
                f.setAccessible(true);
                @SuppressWarnings("unchecked")
                List<Object> cur = (List<Object>) f.get(client);
                if (!cur.isEmpty() && cur.get(0).getClass().getName().equals(OKHTTP_INTERCEPTOR)) return a;
                Object ours = ExtLoader.forApi(client.getClass().getClassLoader()).loadClass(OKHTTP_INTERCEPTOR).getDeclaredConstructor().newInstance();
                List<Object> next = new ArrayList<>(cur.size() + 1);
                next.add(ours);
                next.addAll(cur);
                f.set(client, java.util.Collections.unmodifiableList(next));
            }
        } catch (Throwable t) {
            AgentState.log("okhttp not hooked: " + t);
        }
        return a;
    }

    /** {@code InterceptingHttpAccessor.getRequestFactory()} (RestTemplate): adds the interceptor to the live list. */
    @Override
    public Object[] springAccessor(Object[] a) {
        try {
            if (started()) addFirst(a[0], "getInterceptors", SPRING_INTERCEPTOR, null);
        } catch (Throwable t) {
            AgentState.log("spring RestTemplate not hooked: " + t);
        }
        return a;
    }

    /** {@code DefaultRestClientBuilder.build()}: adds the interceptor to the builder's list. */
    @Override
    public Object[] restClientBuilder(Object[] a) {
        try {
            if (started()) addFirst(a[0], null, SPRING_INTERCEPTOR, "interceptors");
        } catch (Throwable t) {
            AgentState.log("spring RestClient not hooked: " + t);
        }
        return a;
    }

    /**
     * Puts an interceptor of ours, built next to the application's own API classes, at the head of the
     * list that {@code owner} exposes through the method {@code getter} or the field {@code field}.
     */
    @SuppressWarnings("unchecked")
    private static void addFirst(Object owner, String getter, String interceptorClass, String field) throws Exception {
        List<Object> list;
        Field f = null;
        if (getter != null) {
            Method m = owner.getClass().getMethod(getter);
            list = (List<Object>) m.invoke(owner);
        } else {
            f = findField(owner.getClass(), field);
            f.setAccessible(true);
            list = (List<Object>) f.get(owner);
        }
        if (list != null) {
            for (Object o : list) if (o.getClass().getName().equals(interceptorClass)) return;
        }
        ClassLoader api = owner.getClass().getClassLoader();
        Object interceptor = ExtLoader.forApi(api).loadClass(interceptorClass).getDeclaredConstructor().newInstance();
        if (list == null) {
            list = new ArrayList<>();
            f.set(owner, list);
        }
        list.add(0, interceptor);
    }

    private static Field findField(Class<?> c, String name) throws NoSuchFieldException {
        for (; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                // keep looking in the superclass
            }
        }
        throw new NoSuchFieldException(name);
    }
}
