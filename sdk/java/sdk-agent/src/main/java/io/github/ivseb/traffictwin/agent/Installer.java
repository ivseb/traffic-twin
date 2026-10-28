package io.github.ivseb.traffictwin.agent;

import io.github.ivseb.traffictwin.agent.ClassPatcher.Target;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;

/**
 * Registers the one class-file transformer of the agent (loaded from the bootstrap search path).
 *
 * <p>The transformer only puts hooks in front of a short, fixed list of methods (see {@link #TABLE});
 * it is registered as <em>not</em> retransform-capable, so it coexists with the OpenTelemetry Java
 * agent (which retransforms): the JVM feeds retransformation with the bytes as our transformer left
 * them, so the added methods are part of the baseline and nobody's retransformation changes the
 * class schema.
 */
public final class Installer {
    private Installer() {}


    private static final String SEND = "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;";
    private static final String ASYNC2 = "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;";
    private static final String ASYNC3 = "(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;Ljava/net/http/HttpResponse$PushPromiseHandler;)Ljava/util/concurrent/CompletableFuture;";

    /** Internal class name to the methods that get a hook. */
    static final Map<String, List<Target>> TABLE = new HashMap<>();

    static {
        // Servlet containers: the hook gets the container's context object just before it starts, which is
        // the last moment filters can still be added through the standard ServletContext API.
        Target container = new Target("startInternal", "()V", "servletContainer");
        TABLE.put("org/apache/catalina/core/StandardContext", List.of(container));
        Target jetty = new Target("doStart", "()V", "servletContainer");
        for (String c : new String[] {
            "org/eclipse/jetty/servlet/ServletContextHandler", // Jetty 9.4 - 11
            "org/eclipse/jetty/ee9/servlet/ServletContextHandler", // Jetty 12
            "org/eclipse/jetty/ee10/servlet/ServletContextHandler",
            "org/eclipse/jetty/ee11/servlet/ServletContextHandler"}) {
            TABLE.put(c, List.of(jetty));
        }
        // Outbound clients.
        TABLE.put("jdk/internal/net/http/HttpClientFacade", List.of(
            new Target("send", SEND, "httpClient"),
            new Target("sendAsync", ASYNC2, "httpClient"),
            new Target("sendAsync", ASYNC3, "httpClient")));
        // OkHttp: every call, whatever built the client (the builder, the bare constructor, Retrofit), starts at newCall.
        TABLE.put("okhttp3/OkHttpClient", List.of(new Target("newCall", "(Lokhttp3/Request;)Lokhttp3/Call;", "okhttpClient")));
        TABLE.put("org/springframework/http/client/support/InterceptingHttpAccessor",
            List.of(new Target("getRequestFactory", "()Lorg/springframework/http/client/ClientHttpRequestFactory;", "springAccessor")));
        TABLE.put("org/springframework/web/client/DefaultRestClientBuilder",
            List.of(new Target("build", "()Lorg/springframework/web/client/RestClient;", "restClientBuilder")));
    }

    /** Called by {@link AgentMain} through reflection, from the bootstrap class loader. */
    public static void install(Instrumentation inst, String jarPath) throws Exception {
        AgentState.debug = "1".equals(System.getenv("TT_DEBUG")) || "true".equalsIgnoreCase(System.getenv("TT_DEBUG"));
        AgentState.jar = new JarFile(jarPath);
        // Classes of java.net.http call the hooks, which live in the boot loader's unnamed module.
        Module hooks = Installer.class.getModule();
        ModuleLayer.boot().findModule("java.net.http").ifPresent(m -> {
            if (!m.canRead(hooks)) inst.redefineModule(m, Set.of(hooks), Map.of(), Map.of(), Set.of(), Map.of());
        });
        Set<String> alreadyLoaded = new HashSet<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            String n = c.getName().replace('.', '/');
            if (TABLE.containsKey(n)) alreadyLoaded.add(n);
        }
        if (!alreadyLoaded.isEmpty()) AgentState.log("classes loaded before the agent, not hooked: " + alreadyLoaded);
        inst.addTransformer(new Transformer(), false);
        AgentState.log("installed");
    }


    private static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> redefined, ProtectionDomain pd, byte[] bytes) {
            if (className == null || redefined != null) return null;
            List<Target> targets = TABLE.get(className);
            if (targets == null) return null;
            try {
                byte[] out = ClassPatcher.patch(bytes, targets);
                if (out != bytes) AgentState.log("hooked " + className);
                return out == bytes ? null : out;
            } catch (Throwable t) {
                AgentState.log("could not hook " + className + ": " + t);
                return null;
            }
        }
    }
}
