package io.github.ivseb.traffictwin.agent;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.agent.ClassPatcher.Target;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The class-file rewriter, on a class with instance, static, protected, long-returning and void methods. */
class ClassPatcherTest {
    /** Not hooked by anything real: the hook below is the no-op {@code Hooks.servletContainer}. */
    public static class Sample {
        public String greet(String who, Object extra) {
            return "hello " + who + (extra == null ? "" : "+" + extra);
        }

        public static long length(String s, byte[] b) {
            long total = s.length();
            switch (b.length) { // a tableswitch and a branch: the original code must stay valid
                case 0: return total;
                case 1: return total + 1;
                case 2: return total + 2;
                default: return total + b.length;
            }
        }

        protected void touch(StringBuilder sb) {
            sb.append("touched");
        }

        public int notPatched(int a) {
            return a + 1;
        }
    }

    static class Loader extends ClassLoader {
        Loader(byte[] sample) {
            super(ClassPatcherTest.class.getClassLoader());
            this.bytes = sample;
        }

        final byte[] bytes;

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (name.equals(Sample.class.getName())) {
                synchronized (getClassLoadingLock(name)) {
                    Class<?> c = findLoadedClass(name);
                    if (c == null) c = defineClass(name, bytes, 0, bytes.length);
                    return c;
                }
            }
            return super.loadClass(name, resolve);
        }
    }

    static byte[] original() throws Exception {
        try (var in = ClassPatcherTest.class.getResourceAsStream("ClassPatcherTest$Sample.class")) {
            return in.readAllBytes();
        }
    }

    static List<Target> targets() {
        return List.of(
            new Target("greet", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;", "servletContainer"),
            new Target("length", "(Ljava/lang/String;[B)J", "servletContainer"),
            new Target("touch", "(Ljava/lang/StringBuilder;)V", "servletContainer"));
    }

    @Test
    void patchedClassKeepsItsBehaviourAndGainsPrivateRenamedOriginals() throws Exception {
        byte[] patched = ClassPatcher.patch(original(), targets());
        assertTrue(patched.length > original().length);
        Class<?> c = new Loader(patched).loadClass(Sample.class.getName());
        Object o = c.getDeclaredConstructor().newInstance();

        assertEquals("hello ann+x", c.getMethod("greet", String.class, Object.class).invoke(o, "ann", "x"));
        assertEquals("hello ann", c.getMethod("greet", String.class, Object.class).invoke(o, "ann", null));
        assertEquals(5L, c.getMethod("length", String.class, byte[].class).invoke(null, "abc", new byte[2]));
        assertEquals(10L, c.getMethod("length", String.class, byte[].class).invoke(null, "abc", new byte[7]));
        StringBuilder sb = new StringBuilder();
        Method touch = c.getDeclaredMethod("touch", StringBuilder.class);
        touch.setAccessible(true);
        touch.invoke(o, sb);
        assertEquals("touched", sb.toString());
        assertEquals(8, c.getMethod("notPatched", int.class).invoke(o, 7));

        Method renamed = c.getDeclaredMethod("greet" + ClassPatcher.RENAMED_SUFFIX, String.class, Object.class);
        assertTrue(Modifier.isPrivate(renamed.getModifiers()));
        assertTrue(renamed.isSynthetic());
        assertTrue(Modifier.isPublic(c.getMethod("greet", String.class, Object.class).getModifiers()));
        assertTrue(Modifier.isStatic(c.getMethod("length", String.class, byte[].class).getModifiers()));
    }

    @Test
    void classWithoutTargetsIsReturnedAsIs() throws Exception {
        byte[] in = original();
        assertSame(in, ClassPatcher.patch(in, List.of(new Target("nothing", "()V", "servletContainer"))));
    }

    @Test
    void patchingIsDeterministic() throws Exception {
        assertArrayEquals(ClassPatcher.patch(original(), targets()), ClassPatcher.patch(original(), targets()));
    }

    @Test
    void primitiveParametersAreRefused() throws Exception {
        assertThrows(ClassPatcher.PatchException.class,
            () -> ClassPatcher.patch(original(), List.of(new Target("notPatched", "(I)I", "servletContainer"))));
    }

    @Test
    void garbageIsRefusedNotCrashed() {
        assertThrows(ClassPatcher.PatchException.class, () -> ClassPatcher.patch(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, targets()));
        assertThrows(ClassPatcher.PatchException.class, () -> ClassPatcher.patch(new byte[0], targets()));
    }
}
