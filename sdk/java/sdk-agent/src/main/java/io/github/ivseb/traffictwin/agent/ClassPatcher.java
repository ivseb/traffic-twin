package io.github.ivseb.traffictwin.agent;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A tiny class-file rewriter (no ASM, no dependency) that does exactly one thing: put a hook in
 * front of an existing method without touching its bytecode.
 *
 * <p>For each target method {@code m(desc)} it
 * <ol>
 *   <li>renames the original to {@code m$tt} and makes it {@code private synthetic} (its code, its
 *       exception table and its stack map frames are left byte for byte as they were), and
 *   <li>adds a new {@code m(desc)} that packs {@code this} and the arguments into an
 *       {@code Object[]}, calls {@code Hooks.<hook>(Object[])Object[]}, and then calls the original
 *       with the arguments taken back from the returned array (so a hook may replace arguments),
 *       returning whatever the original returns.
 * </ol>
 * The new method is straight-line code (no branches, no handlers), so it needs no StackMapTable.
 * Because nothing inside an existing {@code Code} attribute is moved, there is no offset, frame or
 * switch-padding arithmetic to get wrong. Only reference-typed parameters are supported.
 *
 * <p>Limits: constructors and abstract/native methods cannot be patched; the class file version must
 * be 50 or later (everything the JDK and the containers ship today). Because it adds and renames
 * methods, the transformer that uses it must be registered as not retransform-capable.
 */
final class ClassPatcher {
    private ClassPatcher() {}

    /** A method to put a hook in front of. */
    record Target(String name, String desc, String hook) {}

    static final class PatchException extends Exception {
        private static final long serialVersionUID = 1L;

        PatchException(String m) {
            super(m);
        }
    }

    private static final int ACC_PUBLIC = 0x0001;
    private static final int ACC_PRIVATE = 0x0002;
    private static final int ACC_PROTECTED = 0x0004;
    private static final int ACC_STATIC = 0x0008;
    private static final int ACC_SYNCHRONIZED = 0x0020;
    private static final int ACC_NATIVE = 0x0100;
    private static final int ACC_ABSTRACT = 0x0400;
    private static final int ACC_SYNTHETIC = 0x1000;
    private static final String HOOKS = "io/github/ivseb/traffictwin/agent/Hooks";
    private static final String HOOK_DESC = "([Ljava/lang/Object;)[Ljava/lang/Object;";
    static final String RENAMED_SUFFIX = "$tt";

    private static final class Method {
        int access;
        int nameIdx;
        int descIdx;
        int nameIdxOffset;
        int accessOffset;
        String name;
        String desc;
    }

    /** Returns the patched class file, or the input array itself when no target is present. */
    static byte[] patch(byte[] in, List<Target> targets) throws PatchException {
        try {
            return doPatch(in, targets);
        } catch (RuntimeException e) {
            throw new PatchException("malformed or unsupported class file: " + e);
        }
    }

    private static byte[] doPatch(byte[] in, List<Target> targets) throws PatchException {
        Reader r = new Reader(in);
        if (r.u4() != 0xCAFEBABE) throw new PatchException("not a class file");
        r.u2(); // minor
        int major = r.u2();
        if (major < 50) throw new PatchException("class file version " + major + " too old");
        int cpCount = r.u2();
        Map<Integer, String> utf8 = new HashMap<>();
        Map<Integer, Integer> classNames = new HashMap<>();
        for (int i = 1; i < cpCount; i++) {
            int tag = r.u1();
            switch (tag) {
                case 1 -> {
                    int len = r.u2();
                    utf8.put(i, new String(in, r.pos, len, StandardCharsets.UTF_8)); // only ASCII names matter here
                    r.pos += len;
                }
                case 3, 4 -> r.pos += 4;
                case 5, 6 -> {
                    r.pos += 8;
                    i++;
                }
                case 7 -> classNames.put(i, r.u2());
                case 8, 16, 19, 20 -> r.pos += 2;
                case 9, 10, 11, 12, 17, 18 -> r.pos += 4;
                case 15 -> r.pos += 3;
                default -> throw new PatchException("constant pool tag " + tag);
            }
        }
        int cpEnd = r.pos;
        int access = r.u2();
        if ((access & 0x0200) != 0) throw new PatchException("interfaces are not patched");
        int thisClass = r.u2();
        r.u2(); // super
        int ifaces = r.u2();
        r.pos += 2 * ifaces;
        int fields = r.u2();
        for (int i = 0; i < fields; i++) {
            r.pos += 6;
            skipAttributes(r);
        }
        int methodsCountOffset = r.pos;
        int methodsCount = r.u2();
        List<Method> methods = new ArrayList<>();
        for (int i = 0; i < methodsCount; i++) {
            Method m = new Method();
            m.accessOffset = r.pos;
            m.access = r.u2();
            m.nameIdxOffset = r.pos;
            m.nameIdx = r.u2();
            m.descIdx = r.u2();
            skipAttributes(r);
            m.name = utf8.get(m.nameIdx);
            m.desc = utf8.get(m.descIdx);
            methods.add(m);
        }
        int classAttrsOffset = r.pos;

        // Which methods to patch.
        List<Method> hit = new ArrayList<>();
        List<Target> hitTargets = new ArrayList<>();
        for (Target t : targets) {
            for (Method m : methods) {
                if (t.name().equals(m.name) && t.desc().equals(m.desc)) {
                    if ((m.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) throw new PatchException("abstract or native method " + m.name);
                    hit.add(m);
                    hitTargets.add(t);
                }
            }
        }
        if (hit.isEmpty()) return in;

        String thisName = utf8.get(classNames.get(thisClass));
        Pool pool = new Pool(cpCount, utf8);
        byte[] buf = in.clone();
        ByteArrayOutputStream newMethods = new ByteArrayOutputStream();
        try {
            DataOutputStream out = new DataOutputStream(newMethods);
            for (int i = 0; i < hit.size(); i++) {
                Method m = hit.get(i);
                Target t = hitTargets.get(i);
                boolean isStatic = (m.access & ACC_STATIC) != 0;
                int renamedName = pool.utf8(m.name + RENAMED_SUFFIX);
                // The original: renamed, private, synthetic.
                putU2(buf, m.nameIdxOffset, renamedName);
                putU2(buf, m.accessOffset, (m.access & ~(ACC_PUBLIC | ACC_PROTECTED)) | ACC_PRIVATE | ACC_SYNTHETIC);
                // The wrapper.
                byte[] code = wrapperCode(pool, thisName, m, isStatic, m.name + RENAMED_SUFFIX, t.hook());
                int codeAttr = pool.utf8("Code");
                int total = paramTypes(m.desc).size() + (isStatic ? 0 : 1);
                out.writeShort((m.access & ~ACC_SYNCHRONIZED) & 0xFFFF);
                out.writeShort(m.nameIdx);
                out.writeShort(m.descIdx);
                out.writeShort(1);
                out.writeShort(codeAttr);
                out.writeInt(2 + 2 + 4 + code.length + 2 + 2);
                out.writeShort(Math.max(8, total + 6)); // max_stack
                out.writeShort(total + 1); // max_locals: this + args + the returned array
                out.writeInt(code.length);
                out.write(code);
                out.writeShort(0); // exception table
                out.writeShort(0); // attributes
            }
        } catch (IOException e) {
            throw new PatchException("io: " + e);
        }

        ByteArrayOutputStream res = new ByteArrayOutputStream(in.length + 256);
        try {
            DataOutputStream out = new DataOutputStream(res);
            out.write(buf, 0, 8); // magic, minor, major
            out.writeShort(pool.count());
            out.write(buf, 10, cpEnd - 10);
            pool.writeNew(out);
            out.write(buf, cpEnd, methodsCountOffset - cpEnd);
            out.writeShort(methodsCount + hit.size());
            out.write(buf, methodsCountOffset + 2, classAttrsOffset - (methodsCountOffset + 2));
            out.write(newMethods.toByteArray());
            out.write(buf, classAttrsOffset, buf.length - classAttrsOffset);
        } catch (IOException e) {
            throw new PatchException("io: " + e);
        }
        return res.toByteArray();
    }

    // --- wrapper code ---------------------------------------------------------------------

    private static byte[] wrapperCode(Pool pool, String thisName, Method m, boolean isStatic, String renamed, String hook) throws PatchException {
        List<String> params = paramTypes(m.desc);
        String ret = m.desc.substring(m.desc.indexOf(')') + 1);
        for (String p : params) {
            if (p.charAt(0) != 'L' && p.charAt(0) != '[') throw new PatchException("primitive parameter in " + m.name + m.desc);
        }
        int total = params.size() + (isStatic ? 0 : 1);
        if (total > 100) throw new PatchException("too many parameters");

        int objectCls = pool.cls("java/lang/Object");
        int hookRef = pool.methodRef(pool.cls(HOOKS), hook, HOOK_DESC);
        int origRef = pool.methodRef(pool.cls(thisName), renamed, m.desc);

        Code c = new Code();
        c.pushInt(total);
        c.op(0xBD); // anewarray
        c.u2(objectCls);
        for (int i = 0; i < total; i++) {
            c.op(0x59); // dup
            c.pushInt(i);
            c.aload(i);
            c.op(0x53); // aastore
        }
        c.op(0xB8); // invokestatic Hooks.<hook>
        c.u2(hookRef);
        c.astore(total); // the array the hook returned
        if (!isStatic) c.aload(0);
        for (int j = 0; j < params.size(); j++) {
            c.aload(total);
            c.pushInt(j + (isStatic ? 0 : 1));
            c.op(0x32); // aaload
            String p = params.get(j);
            if (!p.equals("Ljava/lang/Object;")) {
                c.op(0xC0); // checkcast
                c.u2(pool.cls(p.charAt(0) == 'L' ? p.substring(1, p.length() - 1) : p));
            }
        }
        c.op(isStatic ? 0xB8 : 0xB7); // invokestatic / invokespecial (the original is private now)
        c.u2(origRef);
        switch (ret.charAt(0)) {
            case 'V' -> c.op(0xB1);
            case 'J' -> c.op(0xAD);
            case 'F' -> c.op(0xAE);
            case 'D' -> c.op(0xAF);
            case 'L', '[' -> c.op(0xB0);
            default -> c.op(0xAC); // int-like
        }
        return c.bytes();
    }

    private static List<String> paramTypes(String desc) {
        List<String> out = new ArrayList<>();
        int i = 1;
        while (desc.charAt(i) != ')') {
            int s = i;
            while (desc.charAt(i) == '[') i++;
            if (desc.charAt(i) == 'L') i = desc.indexOf(';', i);
            i++;
            out.add(desc.substring(s, i));
        }
        return out;
    }

    private static final class Code {
        private final ByteArrayOutputStream b = new ByteArrayOutputStream();

        void op(int o) {
            b.write(o);
        }

        void u2(int v) {
            b.write(v >> 8);
            b.write(v);
        }

        void pushInt(int v) {
            if (v >= 0 && v <= 5) {
                b.write(0x03 + v); // iconst_N
            } else if (v < 128) {
                b.write(0x10); // bipush
                b.write(v);
            } else {
                b.write(0x11); // sipush
                u2(v);
            }
        }

        void aload(int slot) {
            if (slot <= 3) {
                b.write(0x2A + slot);
            } else {
                b.write(0x19);
                b.write(slot);
            }
        }

        void astore(int slot) {
            if (slot <= 3) {
                b.write(0x4B + slot);
            } else {
                b.write(0x3A);
                b.write(slot);
            }
        }

        byte[] bytes() {
            return b.toByteArray();
        }
    }

    // --- constant pool additions ---------------------------------------------------------------

    private static final class Pool {
        private final int base;
        private final Map<String, Integer> existingByText = new HashMap<>();
        private final List<byte[]> added = new ArrayList<>();
        private final Map<String, Integer> addedKeys = new HashMap<>();

        Pool(int base, Map<Integer, String> existingUtf8) {
            this.base = base;
            existingUtf8.forEach((i, s) -> existingByText.putIfAbsent(s, i));
        }

        int count() {
            return base + added.size();
        }

        int utf8(String s) {
            Integer e = existingByText.get(s);
            if (e != null) return e;
            Integer a = addedKeys.get("U" + s);
            if (a != null) return a;
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            byte[] entry = new byte[3 + bytes.length];
            entry[0] = 1;
            entry[1] = (byte) (bytes.length >> 8);
            entry[2] = (byte) bytes.length;
            System.arraycopy(bytes, 0, entry, 3, bytes.length);
            return add("U" + s, entry);
        }

        int cls(String internalName) {
            int n = utf8(internalName);
            Integer a = addedKeys.get("C" + n);
            if (a != null) return a;
            return add("C" + n, new byte[] {7, (byte) (n >> 8), (byte) n});
        }

        int methodRef(int cls, String name, String desc) {
            int n = utf8(name);
            int d = utf8(desc);
            String ntKey = "N" + n + ":" + d;
            Integer nt = addedKeys.get(ntKey);
            if (nt == null) nt = add(ntKey, new byte[] {12, (byte) (n >> 8), (byte) n, (byte) (d >> 8), (byte) d});
            String key = "M" + cls + ":" + nt;
            Integer a = addedKeys.get(key);
            if (a != null) return a;
            return add(key, new byte[] {10, (byte) (cls >> 8), (byte) cls, (byte) (nt >> 8), (byte) nt.intValue()});
        }

        private int add(String key, byte[] entry) {
            int idx = base + added.size();
            added.add(entry);
            addedKeys.put(key, idx);
            return idx;
        }

        void writeNew(DataOutputStream out) throws IOException {
            for (byte[] e : added) out.write(e);
        }
    }

    // --- parsing helpers -----------------------------------------------------------------------

    private static final class Reader {
        final byte[] b;
        int pos;

        Reader(byte[] b) {
            this.b = b;
        }

        int u1() {
            return b[pos++] & 0xFF;
        }

        int u2() {
            int v = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            return v;
        }

        int u4() {
            int v = ((b[pos] & 0xFF) << 24) | ((b[pos + 1] & 0xFF) << 16) | ((b[pos + 2] & 0xFF) << 8) | (b[pos + 3] & 0xFF);
            pos += 4;
            return v;
        }
    }

    private static void skipAttributes(Reader r) {
        int n = r.u2();
        for (int i = 0; i < n; i++) {
            r.pos += 2;
            int len = r.u4();
            r.pos += len;
        }
    }

    private static void putU2(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }
}
