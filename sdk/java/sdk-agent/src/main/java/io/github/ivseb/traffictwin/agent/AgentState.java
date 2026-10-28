package io.github.ivseb.traffictwin.agent;

import java.util.jar.JarFile;

/** What the boot-path part of the agent shares with the SDK part (JDK types only). */
public final class AgentState {
    private AgentState() {}

    /** The agent jar, opened by the installer. */
    public static volatile JarFile jar;
    /** TT_DEBUG: a few lines about hooks on stderr, never a payload value. */
    public static volatile boolean debug;

    public static void log(String message) {
        if (debug) System.err.println("traffic-twin agent: " + message);
    }
}
