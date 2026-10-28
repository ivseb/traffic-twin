package io.github.ivseb.traffictwin.agent;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Loads the SDK classes that are written against a third-party API (the servlet filter, the Spring and
 * OkHttp interceptors) next to that API.
 *
 * <p>Those classes are stored in the agent jar as {@code tt/ext/**.classdata} so nobody can load them by
 * name from the bootstrap path. For each class loader that can see an API (the one that defines
 * {@code jakarta.servlet.ServletContext}, {@code okhttp3.Interceptor}, ...) there is one
 * {@code ExtLoader} whose parent is that loader: the {@code servlet} and {@code integration} packages of
 * the SDK are defined here (child first), the rest of the SDK comes from the one {@link CoreLoader},
 * everything else (the API, the JDK) through the parent. The classes therefore link against exactly the
 * API classes the container or the application uses, whatever its class loader layout, and share one SDK.
 */
final class ExtLoader extends ClassLoader {
    private static final String[] EXT_PACKAGES = {"io.github.ivseb.traffictwin.servlet.", "io.github.ivseb.traffictwin.integration."};
    private static final Map<ClassLoader, WeakReference<ExtLoader>> CACHE = new WeakHashMap<>();

    static {
        ClassLoader.registerAsParallelCapable();
    }

    private final ClassLoader core;

    private ExtLoader(ClassLoader parent, ClassLoader core) {
        super(parent);
        this.core = core;
    }

    /** The loader for classes that see {@code api}'s classes. */
    static ExtLoader forApi(ClassLoader api) {
        synchronized (CACHE) {
            WeakReference<ExtLoader> ref = CACHE.get(api);
            ExtLoader l = ref == null ? null : ref.get();
            if (l == null) {
                l = new ExtLoader(api, ExtLoader.class.getClassLoader());
                CACHE.put(api, new WeakReference<>(l));
            }
            return l;
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> c = findLoadedClass(name);
            if (c == null && isExt(name)) c = define(name);
            if (c == null && name.startsWith("io.github.ivseb.traffictwin.")) c = core.loadClass(name);
            if (c == null) return super.loadClass(name, resolve);
            if (resolve) resolveClass(c);
            return c;
        }
    }

    private static boolean isExt(String name) {
        for (String p : EXT_PACKAGES) if (name.startsWith(p)) return true;
        return false;
    }

    private Class<?> define(String name) {
        JarFile jar = AgentState.jar;
        if (jar == null) return null;
        JarEntry e = jar.getJarEntry("tt/ext/" + name.replace('.', '/') + ".classdata");
        if (e == null) return null;
        try (InputStream in = jar.getInputStream(e)) {
            byte[] b = in.readAllBytes();
            return defineClass(name, b, 0, b.length);
        } catch (IOException ex) {
            return null;
        }
    }
}
