package io.github.ivseb.traffictwin.sanitizer;

import java.util.ArrayList;
import java.util.List;

/**
 * Shape of a GraphQL executable document, sanitizer.md 5.7 (spec v1.14): the same tokens with
 * every literal value replaced by a placeholder ({@code ?s ?i ?f ?b ?n ?e}) and every name that
 * fails the name rule replaced by {@code *}.
 *
 * <p>Java strings are UTF-16: the BOM is U+FEFF and any other non-ASCII character outside a
 * string is an error, so lexing on chars gives the same result as lexing on the UTF-8 bytes.
 */
public final class GraphQL {
    private GraphQL() {}

    public static final int MAX_NESTING = 64;
    public static final int MAX_SHAPE_BYTES = 32768;
    public static final int MAX_NAME_BYTES = 64;
    /** Array limit of a response body with the introspection gate open (5.7.2). */
    public static final int INTROSPECTION_MAX_ARRAY = 4096;

    /** Outcome of {@link #shape}: the shape (without "gql:") and the introspection-only flag. */
    public record Result(String shape, boolean introspection) {}

    private static final byte PUNCT = 0, NAME = 1, INT = 2, FLOAT = 3, STR = 4;

    private static final class Tok {
        final byte kind;
        final String text;
        boolean value;

        Tok(byte kind, String text) {
            this.kind = kind;
            this.text = text;
        }
    }

    private static final class Err extends Exception {
        Err() {
            super(null, null, false, false);
        }
    }

    private static final Err ERR = new Err();

    static boolean nameStart(char c) {
        return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    static boolean nameCont(char c) {
        return nameStart(c) || digit(c);
    }

    private static boolean digit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean hexDigit(char c) {
        return digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** Shape of {@code src}, or null when it is not an executable document within the limits. */
    public static Result shape(String src) {
        List<Tok> toks;
        Parser p;
        try {
            toks = lex(src);
            p = new Parser(toks);
            p.document();
        } catch (Err e) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        boolean prevWord = false;
        for (Tok t : toks) {
            String s;
            switch (t.kind) {
                case PUNCT -> s = t.text;
                case NAME -> {
                    if (t.value) s = t.text.equals("true") || t.text.equals("false") ? "?b" : t.text.equals("null") ? "?n" : "?e";
                    else s = nameSafe(t.text) ? t.text : "*";
                }
                case INT -> s = "?i";
                case FLOAT -> s = "?f";
                default -> s = "?s";
            }
            if (prevWord && word(s.charAt(0))) sb.append(' ');
            sb.append(s);
            prevWord = word(s.charAt(s.length() - 1));
            if (sb.length() > MAX_SHAPE_BYTES) return null;
        }
        boolean intro = !p.ops.isEmpty();
        for (List<String> op : p.ops) {
            for (String sel : op) {
                if (!(sel.equals("__schema") || sel.equals("__type") || sel.equals("__typename"))) intro = false;
            }
        }
        return new Result(sb.toString(), intro);
    }

    private static boolean word(char c) {
        return nameCont(c) || c == '?' || c == '*';
    }

    /** The key rule of 9.3 on a GraphQL name (5.7.1). */
    public static boolean nameSafe(String name) {
        int n = name.length();
        if (n == 0 || n > MAX_NAME_BYTES || !isName(name)) return false;
        boolean allHex = n >= 16;
        int run = 0;
        for (int i = 0; i < n; i++) {
            char c = name.charAt(i);
            if (!hexDigit(c)) allHex = false;
            if (digit(c)) {
                if (++run >= 6) return false;
            } else run = 0;
        }
        return !allHex;
    }

    /** True when {@code s} is a GraphQL name (any length). */
    public static boolean isName(String s) {
        if (s.isEmpty() || !nameStart(s.charAt(0))) return false;
        for (int i = 1; i < s.length(); i++) if (!nameCont(s.charAt(i))) return false;
        return true;
    }

    // ---------------------------------------------------------------------------------
    // Lexer

    private static List<Tok> lex(String src) throws Err {
        List<Tok> toks = new ArrayList<>();
        int i = 0, n = src.length(), opened = 0;
        while (i < n) {
            char c = src.charAt(i);
            switch (c) {
                case ' ', '\t', '\n', '\r', ',', '﻿' -> i++;
                case '#' -> {
                    while (i < n && src.charAt(i) != '\n' && src.charAt(i) != '\r') i++;
                }
                case '!', '$', '&', ':', '=', '@', '|' -> {
                    toks.add(new Tok(PUNCT, String.valueOf(c)));
                    i++;
                }
                case '(', '[', '{' -> {
                    if (++opened > MAX_NESTING) throw ERR;
                    toks.add(new Tok(PUNCT, String.valueOf(c)));
                    i++;
                }
                case ')', ']', '}' -> {
                    if (--opened < 0) throw ERR;
                    toks.add(new Tok(PUNCT, String.valueOf(c)));
                    i++;
                }
                case '.' -> {
                    if (!src.startsWith("...", i)) throw ERR;
                    toks.add(new Tok(PUNCT, "..."));
                    i += 3;
                }
                case '"' -> {
                    i = string(src, i);
                    toks.add(new Tok(STR, null));
                }
                default -> {
                    if (nameStart(c)) {
                        int j = i + 1;
                        while (j < n && nameCont(src.charAt(j))) j++;
                        toks.add(new Tok(NAME, src.substring(i, j)));
                        i = j;
                    } else if (c == '-' || digit(c)) {
                        long r = number(src, i);
                        toks.add(new Tok((byte) (r >>> 32), null));
                        i = (int) r;
                    } else {
                        throw ERR;
                    }
                }
            }
        }
        if (opened != 0) throw ERR;
        return toks;
    }

    /** End index in the low 32 bits, token kind (INT or FLOAT) in the high bits. */
    private static long number(String src, int i) throws Err {
        int n = src.length();
        int j = i;
        if (src.charAt(j) == '-') j++;
        if (j >= n || !digit(src.charAt(j))) throw ERR;
        if (src.charAt(j) == '0') {
            j++;
            if (j < n && digit(src.charAt(j))) throw ERR;
        } else {
            while (j < n && digit(src.charAt(j))) j++;
        }
        byte kind = INT;
        if (j < n && src.charAt(j) == '.') {
            j++;
            if (j >= n || !digit(src.charAt(j))) throw ERR;
            while (j < n && digit(src.charAt(j))) j++;
            kind = FLOAT;
        }
        if (j < n && (src.charAt(j) == 'e' || src.charAt(j) == 'E')) {
            j++;
            if (j < n && (src.charAt(j) == '+' || src.charAt(j) == '-')) j++;
            if (j >= n || !digit(src.charAt(j))) throw ERR;
            while (j < n && digit(src.charAt(j))) j++;
            kind = FLOAT;
        }
        if (j < n && (src.charAt(j) == '.' || nameStart(src.charAt(j)))) throw ERR;
        return ((long) kind << 32) | j;
    }

    private static int string(String src, int i) throws Err {
        int n = src.length();
        if (src.startsWith("\"\"\"", i)) {
            int j = i + 3;
            while (j < n) {
                if (src.startsWith("\\\"\"\"", j)) j += 4;
                else if (src.startsWith("\"\"\"", j)) return j + 3;
                else {
                    char c = src.charAt(j);
                    if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') throw ERR;
                    j++;
                }
            }
            throw ERR;
        }
        int j = i + 1;
        while (j < n) {
            char c = src.charAt(j);
            if (c == '"') return j + 1;
            if (c == '\\') {
                if (j + 1 >= n) throw ERR;
                char e = src.charAt(j + 1);
                if ("\"\\/bfnrt".indexOf(e) >= 0) j += 2;
                else if (e == 'u') {
                    if (j + 6 > n) throw ERR;
                    for (int k = j + 2; k < j + 6; k++) if (!hexDigit(src.charAt(k))) throw ERR;
                    j += 6;
                } else throw ERR;
            } else if (c < 0x20 && c != '\t') {
                throw ERR;
            } else j++;
        }
        throw ERR;
    }

    // ---------------------------------------------------------------------------------
    // Parser (grammar of 5.7.1)

    private static final class Parser {
        final List<Tok> t;
        int p;
        /** Per operation, the root selections: the field name, or "" for an alias, a spread or an inline fragment. */
        final List<List<String>> ops = new ArrayList<>();

        Parser(List<Tok> t) {
            this.t = t;
        }

        Tok peek() {
            return p < t.size() ? t.get(p) : null;
        }

        boolean isPunct(String s) {
            Tok k = peek();
            return k != null && k.kind == PUNCT && k.text.equals(s);
        }

        boolean isName() {
            Tok k = peek();
            return k != null && k.kind == NAME;
        }

        boolean isName(String s) {
            return isName() && peek().text.equals(s);
        }

        void expect(String s) throws Err {
            if (!isPunct(s)) throw ERR;
            p++;
        }

        String name() throws Err {
            if (!isName()) throw ERR;
            return t.get(p++).text;
        }

        void document() throws Err {
            if (t.isEmpty()) throw ERR;
            while (p < t.size()) {
                if (isPunct("{")) {
                    ops.add(selectionSet());
                } else if (isName("query") || isName("mutation") || isName("subscription")) {
                    p++;
                    if (isName()) p++;
                    if (isPunct("(")) {
                        p++;
                        if (isPunct(")")) throw ERR;
                        while (!isPunct(")")) varDef();
                        p++;
                    }
                    directives();
                    ops.add(selectionSet());
                } else if (isName("fragment")) {
                    p++;
                    if (name().equals("on")) throw ERR;
                    if (!isName("on")) throw ERR;
                    p++;
                    name();
                    directives();
                    selectionSet();
                } else {
                    throw ERR;
                }
            }
        }

        void varDef() throws Err {
            expect("$");
            name();
            expect(":");
            typeRef();
            if (isPunct("=")) {
                p++;
                value();
            }
            directives();
        }

        void typeRef() throws Err {
            if (isPunct("[")) {
                p++;
                typeRef();
                expect("]");
            } else {
                name();
            }
            if (isPunct("!")) p++;
        }

        List<String> selectionSet() throws Err {
            expect("{");
            List<String> out = new ArrayList<>();
            while (!isPunct("}")) out.add(selection());
            if (out.isEmpty()) throw ERR;
            p++;
            return out;
        }

        String selection() throws Err {
            if (isPunct("...")) {
                p++;
                if (isName() && !isName("on")) {
                    p++;
                    directives();
                    return "";
                }
                if (isName()) { // on
                    p++;
                    name();
                }
                directives();
                selectionSet();
                return "";
            }
            String n = name();
            boolean alias = false;
            if (isPunct(":")) {
                p++;
                n = name();
                alias = true;
            }
            if (isPunct("(")) arguments();
            directives();
            if (isPunct("{")) selectionSet();
            return alias ? "" : n;
        }

        void arguments() throws Err {
            expect("(");
            if (isPunct(")")) throw ERR;
            while (!isPunct(")")) {
                name();
                expect(":");
                value();
            }
            p++;
        }

        void directives() throws Err {
            while (isPunct("@")) {
                p++;
                name();
                if (isPunct("(")) arguments();
            }
        }

        void value() throws Err {
            Tok k = peek();
            if (k == null) throw ERR;
            if (k.kind == PUNCT) {
                switch (k.text) {
                    case "$" -> {
                        p++;
                        name();
                    }
                    case "[" -> {
                        p++;
                        while (!isPunct("]")) value();
                        p++;
                    }
                    case "{" -> {
                        p++;
                        while (!isPunct("}")) {
                            name();
                            expect(":");
                            value();
                        }
                        p++;
                    }
                    default -> throw ERR;
                }
                return;
            }
            if (k.kind == NAME) k.value = true;
            p++;
        }
    }
}
