package io.github.ivseb.traffictwin.sanitizer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict RFC 8259 JSON parser that keeps number lexemes (sanitizer.md 9.2), the tt-cjson
 * canonical writer (10.1) and the canonical number form (10.2).
 *
 * <p>The parser is iterative (no recursion), validates the whole input, rejects a leading BOM,
 * invalid UTF-8 and control characters in strings. Lone surrogates produced by {@code \}u
 * escapes are allowed syntactically and flagged on the string node, as 9.2 requires.
 */
public final class Json {
    private Json() {}

    // ---------------------------------------------------------------------------------
    // Parsed tree

    public sealed interface Node permits Obj, Arr, Str, Num, Bool, Null {}

    /** Object members in document order (duplicates kept; 9.3 resolves them). */
    public static final class Obj implements Node {
        public final List<Str> keys = new ArrayList<>();
        public final List<Node> values = new ArrayList<>();

        public int size() {
            return keys.size();
        }
    }

    public static final class Arr implements Node {
        public final List<Node> items = new ArrayList<>();
    }

    public static final class Str implements Node {
        public final String s;
        /** True when the string holds an unpaired surrogate (9.2). */
        public final boolean bad;

        Str(String s, boolean bad) {
            this.s = s;
            this.bad = bad;
        }
    }

    public static final class Num implements Node {
        public final String lex;

        Num(String lex) {
            this.lex = lex;
        }
    }

    public static final class Bool implements Node {
        public final boolean v;

        private Bool(boolean v) {
            this.v = v;
        }
    }

    public static final class Null implements Node {
        private Null() {}
    }

    private static final Null NULL_NODE = new Null();
    private static final Bool TRUE_NODE = new Bool(true);
    private static final Bool FALSE_NODE = new Bool(false);

    public static final class JsonError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public JsonError(String msg) {
            super(msg, null, false, false);
        }
    }

    private static final class Frame {
        final Node node;
        Str key;

        Frame(Node node, Str key) {
            this.node = node;
            this.key = key;
        }
    }

    /** Parses a complete JSON document. Throws {@link JsonError} on any deviation from RFC 8259. */
    public static Node parse(byte[] input) {
        if (input.length >= 3 && (input[0] & 0xff) == 0xef && (input[1] & 0xff) == 0xbb && (input[2] & 0xff) == 0xbf) {
            throw new JsonError("bom");
        }
        String s = Utf8.decode(input);
        if (s == null) throw new JsonError("invalid utf-8");
        return new Parser(s).run();
    }

    private static final class Parser {
        final String b;
        final int n;
        int i = 0;

        Parser(String s) {
            this.b = s;
            this.n = s.length();
        }

        void ws() {
            while (i < n) {
                char c = b.charAt(i);
                if (c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d) i++;
                else break;
            }
        }

        int at(int k) {
            return k < n ? b.charAt(k) : -1;
        }

        int hex4(int p) {
            int v = 0;
            for (int j = 0; j < 4; j++) {
                int c = at(p + j);
                int d;
                if (c < 0) throw new JsonError("eof in escape");
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else throw new JsonError("bad hex escape");
                v = v * 16 + d;
            }
            return v;
        }

        Str readString() {
            i++; // opening quote
            int start = i;
            StringBuilder out = null;
            for (;;) {
                if (i >= n) throw new JsonError("unterminated string");
                char c = b.charAt(i);
                if (c == '"') {
                    String r;
                    if (out == null) r = b.substring(start, i);
                    else {
                        out.append(b, start, i);
                        r = out.toString();
                    }
                    i++;
                    return new Str(r, !Utf8.isWellFormed(r));
                }
                if (c == '\\') {
                    if (out == null) out = new StringBuilder();
                    out.append(b, start, i);
                    int e = at(i + 1);
                    switch (e) {
                        case '"': out.append('"'); i += 2; break;
                        case '\\': out.append('\\'); i += 2; break;
                        case '/': out.append('/'); i += 2; break;
                        case 'b': out.append('\b'); i += 2; break;
                        case 'f': out.append('\f'); i += 2; break;
                        case 'n': out.append('\n'); i += 2; break;
                        case 'r': out.append('\r'); i += 2; break;
                        case 't': out.append('\t'); i += 2; break;
                        case 'u': out.append((char) hex4(i + 2)); i += 6; break;
                        default: throw new JsonError("bad escape");
                    }
                    start = i;
                    continue;
                }
                if (c < 0x20) throw new JsonError("control character in string");
                i++;
            }
        }

        Num readNumber() {
            int s = i;
            if (at(i) == '-') i++;
            if (at(i) == '0') {
                i++;
            } else if (at(i) >= '1' && at(i) <= '9') {
                while (i < n && at(i) >= '0' && at(i) <= '9') i++;
            } else {
                throw new JsonError("bad number");
            }
            if (at(i) == '.') {
                i++;
                int f = i;
                while (i < n && at(i) >= '0' && at(i) <= '9') i++;
                if (i == f) throw new JsonError("bad fraction");
            }
            if (at(i) == 'e' || at(i) == 'E') {
                i++;
                if (at(i) == '+' || at(i) == '-') i++;
                int f = i;
                while (i < n && at(i) >= '0' && at(i) <= '9') i++;
                if (i == f) throw new JsonError("bad exponent");
            }
            return new Num(b.substring(s, i));
        }

        Node literal(String word, Node node) {
            if (!b.startsWith(word, i)) throw new JsonError("bad literal");
            i += word.length();
            return node;
        }

        Str readKey() {
            if (at(i) != '"') throw new JsonError("expected key");
            Str k = readString();
            ws();
            if (at(i) != ':') throw new JsonError("expected colon");
            i++;
            ws();
            return k;
        }

        Node run() {
            ArrayList<Frame> stack = new ArrayList<>();
            ws();
            for (;;) {
                Node v;
                int c = at(i);
                if (c == '{') {
                    i++;
                    ws();
                    Obj o = new Obj();
                    if (at(i) == '}') {
                        i++;
                        v = o;
                    } else {
                        stack.add(new Frame(o, readKey()));
                        continue;
                    }
                } else if (c == '[') {
                    i++;
                    ws();
                    Arr a = new Arr();
                    if (at(i) == ']') {
                        i++;
                        v = a;
                    } else {
                        stack.add(new Frame(a, null));
                        continue;
                    }
                } else if (c == '"') {
                    v = readString();
                } else if (c == '-' || (c >= '0' && c <= '9')) {
                    v = readNumber();
                } else if (c == 't') {
                    v = literal("true", TRUE_NODE);
                } else if (c == 'f') {
                    v = literal("false", FALSE_NODE);
                } else if (c == 'n') {
                    v = literal("null", NULL_NODE);
                } else {
                    throw new JsonError("unexpected character");
                }
                // Attach v to its parent, closing containers as needed.
                for (;;) {
                    if (stack.isEmpty()) {
                        ws();
                        if (i != n) throw new JsonError("trailing data");
                        return v;
                    }
                    Frame f = stack.get(stack.size() - 1);
                    boolean isObj = f.node instanceof Obj;
                    if (isObj) {
                        Obj o = (Obj) f.node;
                        o.keys.add(f.key);
                        o.values.add(v);
                    } else {
                        ((Arr) f.node).items.add(v);
                    }
                    ws();
                    int d = at(i);
                    if (d == ',') {
                        i++;
                        ws();
                        if (isObj) f.key = readKey();
                        break;
                    }
                    if ((isObj && d == '}') || (!isObj && d == ']')) {
                        i++;
                        stack.remove(stack.size() - 1);
                        v = f.node;
                        continue;
                    }
                    throw new JsonError("expected separator");
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // Canonical numbers (10.2)

    public static boolean isIntLexeme(String lex) {
        int i = 0;
        int n = lex.length();
        if (i < n && lex.charAt(i) == '-') i++;
        if (i >= n) return false;
        if (lex.charAt(i) == '0') return i + 1 == n;
        for (int k = i; k < n; k++) {
            char c = lex.charAt(k);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /** 5.3: lexeme of at most 64 bytes and |written exponent| at most 9999. */
    public static boolean lexemeWithinLimits(String lex) {
        if (lex.length() > 64) return false;
        int e = lex.indexOf('e');
        if (e < 0) e = lex.indexOf('E');
        if (e < 0) return true;
        int p = e + 1;
        if (p < lex.length() && (lex.charAt(p) == '+' || lex.charAt(p) == '-')) p++;
        while (p < lex.length() && lex.charAt(p) == '0') p++;
        return lex.length() - p <= 4;
    }

    /** Canonical form of a valid JSON number lexeme, computed in exact decimal arithmetic. */
    public static String canonicalNumber(String lex) {
        int i = 0;
        boolean neg = false;
        if (lex.charAt(0) == '-') {
            neg = true;
            i = 1;
        }
        int j = i;
        while (j < lex.length() && lex.charAt(j) >= '0' && lex.charAt(j) <= '9') j++;
        String intp = lex.substring(i, j);
        String frac = "";
        if (j < lex.length() && lex.charAt(j) == '.') {
            int k = j + 1;
            while (k < lex.length() && lex.charAt(k) >= '0' && lex.charAt(k) <= '9') k++;
            frac = lex.substring(j + 1, k);
            j = k;
        }
        long exp = 0;
        if (j < lex.length() && (lex.charAt(j) == 'e' || lex.charAt(j) == 'E')) {
            String es = lex.substring(j + 1);
            boolean eneg = false;
            if (es.startsWith("+")) es = es.substring(1);
            else if (es.startsWith("-")) {
                eneg = true;
                es = es.substring(1);
            }
            es = es.replaceFirst("^0+", "");
            long ev = es.length() > 15 ? 1_000_000_000_000_000L : (es.isEmpty() ? 0 : Long.parseLong(es));
            exp = eneg ? -ev : ev;
        }
        String digits = intp + frac;
        exp -= frac.length();
        int s = 0;
        while (s < digits.length() && digits.charAt(s) == '0') s++;
        digits = digits.substring(s);
        int t = digits.length();
        while (t > 0 && digits.charAt(t - 1) == '0') t--;
        exp += digits.length() - t;
        digits = digits.substring(0, t);
        if (digits.isEmpty()) return "0";
        int nd = digits.length();
        long e = exp + nd;
        StringBuilder out = new StringBuilder();
        if (neg) out.append('-');
        if (e > -6 && e <= 21) {
            if (e <= 0) {
                out.append("0.");
                for (long z = 0; z < -e; z++) out.append('0');
                out.append(digits);
            } else if (e >= nd) {
                out.append(digits);
                for (long z = 0; z < e - nd; z++) out.append('0');
            } else {
                out.append(digits, 0, (int) e).append('.').append(digits, (int) e, nd);
            }
        } else {
            long k = e - 1;
            out.append(digits.charAt(0));
            if (nd > 1) out.append('.').append(digits, 1, nd);
            out.append('e').append(k >= 0 ? '+' : '-').append(Math.abs(k));
        }
        return out.toString();
    }

    // ---------------------------------------------------------------------------------
    // Output values and the tt-cjson writer (10.1)

    /** A number already in canonical form. */
    public static final class CNum {
        public final String canon;

        public CNum(String canon) {
            this.canon = canon;
        }
    }

    /** JSON null in output trees and plain documents. */
    public enum NullValue { INSTANCE }

    public static final NullValue NULL = NullValue.INSTANCE;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c < 0x20 || c >= 0x7f) {
                sb.append("\\u").append(HEX[(c >> 12) & 15]).append(HEX[(c >> 8) & 15]).append(HEX[(c >> 4) & 15]).append(HEX[c & 15]);
            } else sb.append(c);
        }
        sb.append('"');
    }

    public static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        writeString(sb, s);
        return sb.toString();
    }

    /** Serializes an output tree (String, Boolean, NULL, CNum, List, Map) in tt-cjson. */
    public static String writeCanonical(Object v) {
        StringBuilder sb = new StringBuilder();
        writeCanonical(sb, v);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static void writeCanonical(StringBuilder sb, Object v) {
        if (v instanceof String s) {
            writeString(sb, s);
        } else if (v == NULL || v == null) {
            sb.append("null");
        } else if (v instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (v instanceof CNum c) {
            sb.append(c.canon);
        } else if (v instanceof Integer || v instanceof Long) {
            sb.append(v);
        } else if (v instanceof List<?> l) {
            sb.append('[');
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(',');
                writeCanonical(sb, l.get(i));
            }
            sb.append(']');
        } else if (v instanceof Map<?, ?> m) {
            List<String> keys = new ArrayList<>(((Map<String, Object>) m).keySet());
            keys.sort(Utf8::cmp);
            sb.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) sb.append(',');
                writeString(sb, keys.get(i));
                sb.append(':');
                writeCanonical(sb, ((Map<String, Object>) m).get(keys.get(i)));
            }
            sb.append('}');
        } else {
            throw new IllegalArgumentException("unsupported output value: " + v.getClass());
        }
    }

    // ---------------------------------------------------------------------------------
    // Plain documents (policies, envelopes, vectors)

    /** A number kept as its lexeme. */
    public static final class Lex {
        public final String lex;

        public Lex(String lex) {
            this.lex = lex;
        }

        public double toDouble() {
            return Double.parseDouble(lex);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Lex l && l.lex.equals(lex);
        }

        @Override
        public int hashCode() {
            return lex.hashCode();
        }
    }

    /**
     * Converts a parsed document to plain Java values: Map (insertion ordered), List, String,
     * Boolean, {@link Lex}, {@link #NULL}. With {@code strict}, duplicate keys and lone
     * surrogates are rejected (policy bodies and envelopes: fail closed); otherwise the last
     * duplicate wins.
     */
    public static Object toPlain(Node node, boolean strict) {
        if (node instanceof Null) return NULL;
        if (node instanceof Bool b) return b.v;
        if (node instanceof Num n) return new Lex(n.lex);
        if (node instanceof Str s) {
            if (strict && s.bad) throw new JsonError("lone surrogate");
            return s.s;
        }
        if (node instanceof Arr a) {
            List<Object> l = new ArrayList<>(a.items.size());
            for (Node x : a.items) l.add(toPlain(x, strict));
            return l;
        }
        Obj o = (Obj) node;
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < o.keys.size(); i++) {
            Str k = o.keys.get(i);
            if (strict && (k.bad || m.containsKey(k.s))) throw new JsonError("duplicate or invalid key");
            m.put(k.s, toPlain(o.values.get(i), strict));
        }
        return m;
    }

    /** Parses bytes into a plain document. */
    public static Object parsePlain(byte[] bytes, boolean strict) {
        return toPlain(parse(bytes), strict);
    }

    /** Converts a plain document back to an output tree with canonical numbers (for hashing/serialization). */
    @SuppressWarnings("unchecked")
    public static Object plainToOut(Object p) {
        if (p instanceof Lex l) return new CNum(canonicalNumber(l.lex));
        if (p instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object x : l) out.add(plainToOut(x));
            return out;
        }
        if (p instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) m).entrySet()) out.put(e.getKey(), plainToOut(e.getValue()));
            return out;
        }
        return p;
    }
}
