package io.github.ivseb.traffictwin.agent;

import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Loads the SDK itself from {@code tt/core/**.classdata} in the agent jar. Its parent is the platform
 * class loader: it sees the JDK including {@code java.net.http} (which the boot loader does not), the
 * boot-path classes of the agent ({@code Hooks}, {@code CoreBridge}, {@code AgentState}), and nothing of
 * the application, so the SDK can never pick up an application class or a second copy of itself.
 */
public final class CoreLoader extends ClassLoader {
    private static final String PREFIX = "io.github.ivseb.traffictwin.";

    static {
        ClassLoader.registerAsParallelCapable();
    }

    public CoreLoader() {
        super(ClassLoader.getPlatformClassLoader());
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> c = findLoadedClass(name);
            if (c == null && name.startsWith(PREFIX)) c = define(name);
            if (c == null) return super.loadClass(name, resolve);
            if (resolve) resolveClass(c);
            return c;
        }
    }

    private Class<?> define(String name) {
        JarFile jar = AgentState.jar;
        if (jar == null) return null;
        JarEntry e = jar.getJarEntry("tt/core/" + name.replace('.', '/') + ".classdata");
        if (e == null) return null;
        try (InputStream in = jar.getInputStream(e)) {
            byte[] b = in.readAllBytes();
            return defineClass(name, b, 0, b.length);
        } catch (IOException ex) {
            return null;
        }
    }
}
