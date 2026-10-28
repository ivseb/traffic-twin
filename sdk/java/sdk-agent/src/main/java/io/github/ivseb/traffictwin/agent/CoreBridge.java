package io.github.ivseb.traffictwin.agent;

/**
 * The hooks, as implemented by the SDK part of the agent. The interface lives on the boot path (JDK
 * types only) so that the patched methods, whatever their class loader, can reach the implementation
 * that lives in an isolated loader ({@code CoreLoader}) that also sees the platform modules
 * ({@code java.net.http}), which the boot loader cannot.
 */
public interface CoreBridge {
    Object[] servletContainer(Object[] args);

    Object[] httpClient(Object[] args);

    Object[] okhttpClient(Object[] args);

    Object[] springAccessor(Object[] args);

    Object[] restClientBuilder(Object[] args);
}
