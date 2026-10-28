package io.github.ivseb.traffictwin.agent;

/**
 * What the patched methods call (see {@link ClassPatcher}). Every hook receives {@code this} and the
 * arguments in an array and returns the array the original method will be called with. A hook never
 * throws: on any problem it returns its input, which leaves the application exactly as it was.
 *
 * <p>This class is on the boot path and uses JDK types only; the work is done by the
 * {@link CoreBridge} implementation, loaded on first use from the agent jar by a {@link CoreLoader}.
 */
public final class Hooks {
    private Hooks() {}

    private static final String IMPL = "io.github.ivseb.traffictwin.agent.CoreBridgeImpl";
    private static volatile CoreBridge bridge;
    private static volatile boolean failed;

    private static CoreBridge bridge() {
        CoreBridge b = bridge;
        if (b != null || failed) return b;
        synchronized (Hooks.class) {
            if (bridge == null && !failed) {
                try {
                    bridge = (CoreBridge) new CoreLoader().loadClass(IMPL).getDeclaredConstructor().newInstance();
                } catch (Throwable t) {
                    failed = true;
                    AgentState.log("SDK part not loadable: " + t);
                }
            }
            return bridge;
        }
    }

    public static Object[] servletContainer(Object[] a) {
        try {
            CoreBridge b = bridge();
            return b == null ? a : b.servletContainer(a);
        } catch (Throwable t) {
            return a;
        }
    }

    public static Object[] httpClient(Object[] a) {
        try {
            CoreBridge b = bridge();
            return b == null ? a : b.httpClient(a);
        } catch (Throwable t) {
            return a;
        }
    }

    public static Object[] okhttpClient(Object[] a) {
        try {
            CoreBridge b = bridge();
            return b == null ? a : b.okhttpClient(a);
        } catch (Throwable t) {
            return a;
        }
    }

    public static Object[] springAccessor(Object[] a) {
        try {
            CoreBridge b = bridge();
            return b == null ? a : b.springAccessor(a);
        } catch (Throwable t) {
            return a;
        }
    }

    public static Object[] restClientBuilder(Object[] a) {
        try {
            CoreBridge b = bridge();
            return b == null ? a : b.restClientBuilder(a);
        } catch (Throwable t) {
            return a;
        }
    }
}
