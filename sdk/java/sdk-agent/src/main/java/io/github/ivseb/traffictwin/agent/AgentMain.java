package io.github.ivseb.traffictwin.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.security.CodeSource;
import java.util.jar.JarFile;

/**
 * {@code -javaagent:traffic-twin-agent.jar}. This is the only class of the jar the application class
 * loader needs: it appends the jar to the bootstrap search path (so the hooks are visible to every
 * class loader, containers' included) and hands over to {@code Installer}, loaded from there.
 *
 * <p>It does nothing unless {@code TT_ENROLL_URL} is set and {@code TT_DISABLED} is not: dropping the
 * agent into a JVM never changes it by itself. It never throws into the JVM start-up and never sets
 * {@code GlobalOpenTelemetry}, a {@code TracerProvider}, a propagator or any other global.
 */
public final class AgentMain {
    private AgentMain() {}

    public static void premain(String args, Instrumentation inst) {
        install(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) {
        install(args, inst);
    }

    private static void install(String args, Instrumentation inst) {
        boolean debug = truthy(System.getenv("TT_DEBUG"));
        try {
            if (truthy(System.getenv("TT_DISABLED")) || System.getenv("TT_ENROLL_URL") == null) return;
            CodeSource cs = AgentMain.class.getProtectionDomain().getCodeSource();
            if (cs == null) throw new IllegalStateException("agent jar location unknown");
            File jar = new File(cs.getLocation().toURI());
            inst.appendToBootstrapClassLoaderSearch(new JarFile(jar));
            Class<?> installer = Class.forName("io.github.ivseb.traffictwin.agent.Installer", true, null);
            installer.getMethod("install", Instrumentation.class, String.class).invoke(null, inst, jar.getPath());
        } catch (Throwable t) {
            // Never affect the application: the JVM starts without the agent.
            if (debug) System.err.println("traffic-twin agent: not installed (" + t.getClass().getSimpleName() + ")");
        }
    }

    private static boolean truthy(String v) {
        return v != null && (v.equals("1") || v.equalsIgnoreCase("true") || v.equalsIgnoreCase("yes") || v.equalsIgnoreCase("debug"));
    }
}
