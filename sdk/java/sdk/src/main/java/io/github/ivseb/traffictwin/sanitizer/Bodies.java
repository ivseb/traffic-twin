package io.github.ivseb.traffictwin.sanitizer;

import io.github.ivseb.traffictwin.sanitizer.Json.Arr;
import io.github.ivseb.traffictwin.sanitizer.Json.Node;
import io.github.ivseb.traffictwin.sanitizer.Json.Obj;
import io.github.ivseb.traffictwin.sanitizer.Json.Str;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Body formats of spec v1.19 (sanitizer.md 22): XML and SOAP (22.2), multipart/form-data (22.3),
 * base64 documents and the document size classes (22.4). Pure functions: they never see the
 * policy. Mirrors conformance/ref/bodies.py.
 *
 * <p>The XML reader is a hand-written strict subset of XML 1.0 + Namespaces: no DTD, no entity
 * other than the five predefined ones and character references, nothing is ever fetched. No JDK
 * XML parser (javax.xml, SAX, StAX) is used.
 */
public final class Bodies {
    private Bodies() {}

    // ---------------------------------------------------------------------------------
    // Documents (22.4)

    private static final long[] DOC_BOUNDS = {1024, 16384, 131072, 1048576, 8388608};
    private static final String[] DOC_NAMES = {"l1k", "l16k", "l128k", "l1m", "l8m"};
    private static final int DOC_MIN_CHARS = 16;

    /** 22.4: document size class of a decoded length. */
    public static String docClass(long n) {
        for (int i = 0; i < DOC_BOUNDS.length; i++) if (n <= DOC_BOUNDS[i]) return DOC_NAMES[i];
        return "lmax";
    }

    private static boolean startsWith(byte[] b, int off, byte[] p) {
        if (b.length - off < p.length) return false;
        for (int i = 0; i < p.length; i++) if (b[off + i] != p[i]) return false;
        return true;
    }

    private static boolean startsWith(byte[] b, byte[] p) {
        return startsWith(b, 0, p);
    }

    /** Index of {@code p} in {@code b} from {@code from}; -1 if absent. */
    static int indexOf(byte[] b, byte[] p, int from) {
        if (p.length == 0) return from <= b.length ? from : -1;
        byte first = p[0];
        int last = b.length - p.length;
        outer:
        for (int i = Math.max(from, 0); i <= last; i++) {
            if (b[i] != first) continue;
            for (int k = 1; k < p.length; k++) if (b[i + k] != p[k]) continue outer;
            return i;
        }
        return -1;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    private static final byte[] M_PDF = ascii("%PDF-");
    private static final byte[] M_PNG = bytes(0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a);
    private static final byte[] M_JPEG = bytes(0xff, 0xd8, 0xff);
    private static final byte[] M_GIF87 = ascii("GIF87a");
    private static final byte[] M_GIF89 = ascii("GIF89a");
    private static final byte[] M_RIFF = ascii("RIFF");
    private static final byte[] M_WEBP = ascii("WEBP");
    private static final byte[] M_OLE = bytes(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1);
    private static final byte[] M_ZIP = bytes('P', 'K', 3, 4);
    private static final byte[] Z_DOCX = ascii("word/document.xml");
    private static final byte[] Z_XLSX = ascii("xl/workbook.xml");
    private static final byte[] Z_PPTX = ascii("ppt/presentation.xml");

    /** 22.4 point 3: kind of a document from its first bytes (and, for zip, the names it holds); null if none. */
    public static String magicKind(byte[] b) {
        if (startsWith(b, M_PDF)) return "pdf";
        if (startsWith(b, M_PNG)) return "png";
        if (startsWith(b, M_JPEG)) return "jpeg";
        if (startsWith(b, M_GIF87) || startsWith(b, M_GIF89)) return "gif";
        if (startsWith(b, M_RIFF) && startsWith(b, 8, M_WEBP)) return "webp";
        if (startsWith(b, M_OLE)) return "ole";
        if (startsWith(b, M_ZIP)) {
            if (indexOf(b, Z_DOCX, 0) >= 0) return "docx";
            if (indexOf(b, Z_XLSX, 0) >= 0) return "xlsx";
            if (indexOf(b, Z_PPTX, 0) >= 0) return "pptx";
            return "zip";
        }
        return null;
    }

    private static int b64Val(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    }

    /**
     * Lenient decoding of {@code s[0, len)}, standard and url alphabets mixed, no padding: the
     * final partial group gives its whole bytes and its padding bits are ignored (22.4 point 2).
     */
    static byte[] b64Decode(String s, int len) {
        byte[] out = new byte[len / 4 * 3 + Math.max(0, len % 4 - 1)];
        int o = 0;
        int acc = 0;
        int bits = 0;
        for (int i = 0; i < len; i++) {
            acc = (acc << 6) | b64Val(s.charAt(i));
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[o++] = (byte) (acc >> bits);
                acc &= (1 << bits) - 1;
            }
        }
        return out;
    }

    /** 22.4: {@code drop:doc:<kind>:<class>} if the (well-formed) string is the base64 of a document, else null. */
    public static String base64Doc(String s) {
        if (s.startsWith("data:")) {
            int i = s.indexOf(',');
            if (i < 0) return null;
            String pre = s.substring(0, i);
            if (pre.length() < 12 || !pre.endsWith(";base64")) return null;
            for (int k = 0; k < pre.length(); k++) {
                char c = pre.charAt(k);
                if (c < 0x21 || c > 0x7e) return null;
            }
            s = s.substring(i + 1);
        }
        int n = s.length();
        if (n < DOC_MIN_CHARS) return null;
        int body = n;
        while (body > 0 && s.charAt(body - 1) == '=') body--;
        if (n - body > 2) return null;
        for (int k = 0; k < body; k++) if (b64Val(s.charAt(k)) < 0) return null;
        if (body != n && n % 4 != 0) return null;
        if (body % 4 == 1) return null;
        byte[] raw = b64Decode(s, body);
        String kind = magicKind(raw);
        if (kind == null) return null;
        return "drop:doc:" + kind + ":" + docClass(raw.length);
    }

    // ---------------------------------------------------------------------------------
    // Media type parameters (22.2 point 11, 22.3 point 1)

    private static String trimSpTab(String s) {
        int a = 0;
        int b = s.length();
        while (a < b && (s.charAt(a) == ' ' || s.charAt(a) == '\t')) a++;
        while (b > a && (s.charAt(b - 1) == ' ' || s.charAt(b - 1) == '\t')) b--;
        return s.substring(a, b);
    }

    /**
     * Parameters of a normalized content-type value: lowercase name to value, first occurrence
     * wins. A quoted value loses its two quotes (no escapes). Not UTF-8 or null: no parameters.
     */
    public static Map<String, String> mediaParams(byte[] value) {
        Map<String, String> out = new HashMap<>();
        if (value == null) return out;
        String s = Utf8.decode(value);
        if (s == null) return out;
        String[] pieces = s.split(";", -1);
        for (int i = 1; i < pieces.length; i++) {
            String piece = trimSpTab(pieces[i]);
            int eq = piece.indexOf('=');
            if (eq < 0) continue;
            String name = Utf8.asciiLower(trimSpTab(piece.substring(0, eq)));
            String v = trimSpTab(piece.substring(eq + 1));
            if (v.startsWith("\"")) {
                if (v.length() < 2 || !v.endsWith("\"")) continue;
                v = v.substring(1, v.length() - 1);
            }
            out.putIfAbsent(name, v);
        }
        return out;
    }

    // ---------------------------------------------------------------------------------
    // multipart/form-data (22.3)

    /** A multipart body that does not follow 22.3 points 1-4. */
    public static final class InvalidMultipart extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidMultipart(String m) {
            super(m, null, false, false);
        }
    }

    /** One part: name, file flag, content bytes, part media type (lowercase, may be null). */
    public record MultipartPart(String name, boolean isFile, byte[] content, String contentType) {}

    private static final Pattern BOUNDARY = Pattern.compile("[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]");
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CRLFCRLF = {'\r', '\n', '\r', '\n'};

    private static boolean tokenChar(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "!#$%&'*+.^_`|~-".indexOf(c) >= 0;
    }

    private static boolean at(byte[] b, int pos, byte[] p) {
        return pos >= 0 && startsWith(b, pos, p);
    }

    private static byte[] trimSpTab(byte[] b) {
        int a = 0;
        int e = b.length;
        while (a < e && (b[a] == ' ' || b[a] == '\t')) a++;
        while (e > a && (b[e - 1] == ' ' || b[e - 1] == '\t')) e--;
        return java.util.Arrays.copyOfRange(b, a, e);
    }

    /** 22.3 point 4: the parameters of a content-disposition value of type form-data. */
    static Map<String, String> disposition(String s) throws InvalidMultipart {
        int i = s.indexOf(';');
        String kind = trimSpTab(i < 0 ? s : s.substring(0, i));
        if (!Utf8.asciiLower(kind).equals("form-data")) throw new InvalidMultipart("disposition");
        Map<String, String> params = new HashMap<>();
        int n = s.length();
        int pos = i < 0 ? n : i;
        while (pos < n) {
            while (pos < n && (s.charAt(pos) == ' ' || s.charAt(pos) == '\t' || s.charAt(pos) == ';')) pos++;
            if (pos >= n) break;
            int start = pos;
            while (pos < n && s.charAt(pos) != '=' && s.charAt(pos) != ';') pos++;
            String name = Utf8.asciiLower(trimSpTab(s.substring(start, pos)));
            if (pos >= n || s.charAt(pos) == ';') {
                params.putIfAbsent(name, "");
                continue;
            }
            pos++; // '='
            while (pos < n && (s.charAt(pos) == ' ' || s.charAt(pos) == '\t')) pos++;
            String val;
            if (pos < n && s.charAt(pos) == '"') {
                pos++;
                StringBuilder buf = new StringBuilder();
                while (true) {
                    if (pos >= n) throw new InvalidMultipart("unterminated quoted string");
                    char c = s.charAt(pos);
                    if (c == '\\' && pos + 1 < n) {
                        buf.append(s.charAt(pos + 1));
                        pos += 2;
                        continue;
                    }
                    if (c == '"') {
                        pos++;
                        break;
                    }
                    buf.append(c);
                    pos++;
                }
                val = buf.toString();
                while (pos < n && (s.charAt(pos) == ' ' || s.charAt(pos) == '\t')) pos++;
                if (pos < n && s.charAt(pos) != ';') throw new InvalidMultipart("garbage after quoted string");
            } else {
                start = pos;
                while (pos < n && s.charAt(pos) != ';') pos++;
                val = trimSpTab(s.substring(start, pos));
            }
            params.putIfAbsent(name, val);
        }
        return params;
    }

    /** 22.3 points 1-5: the parts of a multipart body. {@code boundary} may be null. */
    public static List<MultipartPart> parseMultipart(byte[] data, String boundary) throws InvalidMultipart {
        if (boundary == null || !BOUNDARY.matcher(boundary).matches()) throw new InvalidMultipart("boundary");
        byte[] delim = ascii("--" + boundary);
        byte[] crlfDelim = new byte[delim.length + 2];
        crlfDelim[0] = '\r';
        crlfDelim[1] = '\n';
        System.arraycopy(delim, 0, crlfDelim, 2, delim.length);
        int pos;
        if (startsWith(data, delim)) pos = 0;
        else {
            int i = indexOf(data, crlfDelim, 0);
            if (i < 0) throw new InvalidMultipart("no delimiter");
            pos = i + 2;
        }
        List<byte[]> raw = new ArrayList<>();
        while (true) {
            pos += delim.length;
            if (at(data, pos, new byte[] {'-', '-'})) break;
            while (pos < data.length && (data[pos] == ' ' || data[pos] == '\t')) pos++;
            if (!at(data, pos, CRLF)) throw new InvalidMultipart("delimiter line");
            pos += 2;
            int nxt = indexOf(data, crlfDelim, pos);
            if (nxt < 0) throw new InvalidMultipart("no close delimiter");
            raw.add(java.util.Arrays.copyOfRange(data, pos, nxt));
            pos = nxt + 2;
        }
        List<MultipartPart> out = new ArrayList<>();
        for (byte[] p : raw) {
            byte[] head;
            byte[] content;
            if (startsWith(p, CRLF)) {
                head = new byte[0];
                content = java.util.Arrays.copyOfRange(p, 2, p.length);
            } else {
                int j = indexOf(p, CRLFCRLF, 0);
                if (j < 0) throw new InvalidMultipart("part headers");
                head = java.util.Arrays.copyOfRange(p, 0, j);
                content = java.util.Arrays.copyOfRange(p, j + 4, p.length);
            }
            Map<String, byte[]> headers = new HashMap<>();
            if (head.length > 0) {
                int ls = 0;
                while (true) {
                    int le = indexOf(head, CRLF, ls);
                    int end = le < 0 ? head.length : le;
                    int k = -1;
                    for (int q = ls; q < end; q++) {
                        if (head[q] == ':') {
                            k = q;
                            break;
                        }
                    }
                    if (k <= ls) throw new InvalidMultipart("part header line");
                    for (int q = ls; q < k; q++) if (!tokenChar(head[q] & 0xff)) throw new InvalidMultipart("part header line");
                    String name = Utf8.asciiLower(new String(head, ls, k - ls, StandardCharsets.ISO_8859_1));
                    headers.putIfAbsent(name, trimSpTab(java.util.Arrays.copyOfRange(head, k + 1, end)));
                    if (le < 0) break;
                    ls = le + 2;
                }
            }
            byte[] cd = headers.get("content-disposition");
            if (cd == null) throw new InvalidMultipart("no content-disposition");
            String cds = Utf8.decode(cd);
            if (cds == null) throw new InvalidMultipart("content-disposition not UTF-8");
            Map<String, String> params = disposition(cds);
            if (!params.containsKey("name")) throw new InvalidMultipart("no name");
            boolean isFile = params.containsKey("filename") || params.containsKey("filename*");
            String ct = null;
            byte[] ctb = headers.get("content-type");
            if (ctb != null) {
                String cts = Utf8.decode(ctb);
                if (cts != null) {
                    int semi = cts.indexOf(';');
                    ct = Utf8.asciiLower(trimSpTab(semi < 0 ? cts : cts.substring(0, semi)));
                }
            }
            out.add(new MultipartPart(params.get("name"), isFile, content, ct));
        }
        return out;
    }

    private static final Map<String, String> FILE_TYPES = Map.of(
        "text/plain", "text", "text/csv", "csv", "application/json", "json", "application/xml", "xml", "text/xml", "xml");

    /** 22.3 point 5: {@code drop:file:<kind>:<class>} of a file part. */
    public static String fileToken(byte[] content, String ct) {
        String kind = magicKind(content);
        if (kind == null) kind = FILE_TYPES.getOrDefault(ct == null ? "" : ct, "bin");
        return "drop:file:" + kind + ":" + docClass(content.length);
    }

    // ---------------------------------------------------------------------------------
    // XML (22.2)

    public static final String NS_XML = "http://www.w3.org/XML/1998/namespace";
    public static final String SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
    static final int XML_MAX_NESTING = 256;
    private static final int NS_MAX_BYTES = 512;

    /** An XML body outside the accepted subset (22.2 points 1-6). */
    public static final class InvalidXml extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidXml(String m) {
            super(m, null, false, false);
        }
    }

    /** One element: local name, namespace ("" for none), attributes (local, value) without declarations. */
    public static final class Elem {
        final String local;
        final String ns;
        final List<String[]> attrs;
        final List<Elem> children = new ArrayList<>();
        final StringBuilder text = new StringBuilder();

        Elem(String local, String ns, List<String[]> attrs) {
            this.local = local;
            this.ns = ns;
            this.attrs = attrs;
        }
    }

    private static boolean nameStart(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80;
    }

    private static boolean nameChar(char c) {
        return nameStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':';
    }

    private static boolean xmlChar(int cp) {
        return cp == 0x9 || cp == 0xA || cp == 0xD || (cp >= 0x20 && cp <= 0xD7FF) || (cp >= 0xE000 && cp <= 0xFFFD) || (cp >= 0x10000 && cp <= 0x10FFFF);
    }

    private static boolean isHex(char d) {
        return (d >= '0' && d <= '9') || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F');
    }

    /** 22.2 point 5: character and predefined entity references; attribute values turn tab and newline into spaces. */
    static String refs(String raw, boolean attr) throws InvalidXml {
        if (raw.indexOf('&') < 0 && (!attr || (raw.indexOf('\t') < 0 && raw.indexOf('\n') < 0))) return raw;
        StringBuilder out = new StringBuilder(raw.length());
        int i = 0;
        int n = raw.length();
        while (i < n) {
            char c = raw.charAt(i);
            if (c == '&') {
                int j = raw.indexOf(';', i + 1);
                if (j < 0) throw new InvalidXml("unterminated reference");
                String ent = raw.substring(i + 1, j);
                switch (ent) {
                    case "lt" -> out.append('<');
                    case "gt" -> out.append('>');
                    case "amp" -> out.append('&');
                    case "apos" -> out.append('\'');
                    case "quot" -> out.append('"');
                    default -> {
                        int cp = 0;
                        if (ent.startsWith("#x") && ent.length() > 2) {
                            for (int k = 2; k < ent.length(); k++) {
                                char d = ent.charAt(k);
                                if (!isHex(d)) throw new InvalidXml("unknown entity");
                            }
                            for (int k = 2; k < ent.length(); k++) {
                                cp = cp * 16 + Character.digit(ent.charAt(k), 16);
                                if (cp > 0x10FFFF) throw new InvalidXml("reference out of range");
                            }
                        } else if (ent.startsWith("#") && ent.length() > 1) {
                            for (int k = 1; k < ent.length(); k++) {
                                char d = ent.charAt(k);
                                if (d < '0' || d > '9') throw new InvalidXml("unknown entity");
                            }
                            for (int k = 1; k < ent.length(); k++) {
                                cp = cp * 10 + (ent.charAt(k) - '0');
                                if (cp > 0x10FFFF) throw new InvalidXml("reference out of range");
                            }
                        } else {
                            throw new InvalidXml("unknown entity");
                        }
                        if (!xmlChar(cp)) throw new InvalidXml("reference to a forbidden character");
                        out.appendCodePoint(cp);
                    }
                }
                i = j + 1;
                continue;
            }
            if (attr && (c == '\t' || c == '\n')) out.append(' ');
            else out.append(c);
            i++;
        }
        return out.toString();
    }

    /** {prefix or null, local}. */
    private static String[] splitQname(String q) throws InvalidXml {
        int c = q.indexOf(':');
        if (c < 0) return new String[] {null, q};
        String p = q.substring(0, c);
        String l = q.substring(c + 1);
        if (p.isEmpty() || l.isEmpty() || l.indexOf(':') >= 0) throw new InvalidXml("qualified name");
        return new String[] {p, l};
    }

    private static final class XmlParser {
        final String s;
        final int n;
        int pos;

        XmlParser(String s) {
            this.s = s;
            this.n = s.length();
        }

        int readName(int p) throws InvalidXml {
            if (p >= n || !nameStart(s.charAt(p))) throw new InvalidXml("name");
            int q = p + 1;
            while (q < n && nameChar(s.charAt(q))) q++;
            return q;
        }

        int skipWs(int p) {
            while (p < n) {
                char c = s.charAt(p);
                if (c != ' ' && c != '\t' && c != '\n') break;
                p++;
            }
            return p;
        }

        /** Comment or processing instruction at p: its end, or -1 when none starts there. */
        int misc(int p) throws InvalidXml {
            if (s.startsWith("<!--", p)) {
                int e = s.indexOf("-->", p + 4);
                if (e < 0) throw new InvalidXml("unterminated comment");
                return e + 3;
            }
            if (s.startsWith("<?", p)) {
                int e = s.indexOf("?>", p + 2);
                if (e < 0) throw new InvalidXml("unterminated processing instruction");
                return e + 2;
            }
            return -1;
        }

        /** Result of a start tag. */
        record Start(String qname, Elem el, Map<String, String> nsmap, boolean empty) {}

        Start startTag(Map<String, String> parentNs) throws InvalidXml {
            int p = pos;
            int ne = readName(p + 1);
            String qname = s.substring(p + 1, ne);
            p = ne;
            List<String[]> rawAttrs = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            boolean empty = false;
            while (true) {
                int q = skipWs(p);
                if (s.startsWith("/>", q)) {
                    p = q + 2;
                    empty = true;
                    break;
                }
                if (s.startsWith(">", q)) {
                    p = q + 1;
                    break;
                }
                if (q == p) throw new InvalidXml("attribute without space");
                int ae = readName(q);
                String aname = s.substring(q, ae);
                q = skipWs(ae);
                if (q >= n || s.charAt(q) != '=') throw new InvalidXml("attribute without =");
                q = skipWs(q + 1);
                if (q >= n || (s.charAt(q) != '"' && s.charAt(q) != '\'')) throw new InvalidXml("attribute value");
                int e = s.indexOf(s.charAt(q), q + 1);
                if (e < 0) throw new InvalidXml("unterminated attribute value");
                String raw = s.substring(q + 1, e);
                if (raw.indexOf('<') >= 0) throw new InvalidXml("< in attribute value");
                if (!seen.add(aname)) throw new InvalidXml("duplicate attribute");
                rawAttrs.add(new String[] {aname, refs(raw, true)});
                p = e + 1;
            }
            Map<String, String> nsmap = parentNs;
            for (String[] a : rawAttrs) {
                String aname = a[0];
                if (aname.equals("xmlns") || aname.startsWith("xmlns:")) {
                    if (nsmap == parentNs) nsmap = new HashMap<>(parentNs);
                    if (aname.equals("xmlns")) nsmap.put("", a[1]);
                    else {
                        String pre = aname.substring(6);
                        if (pre.isEmpty() || pre.indexOf(':') >= 0) throw new InvalidXml("namespace declaration");
                        nsmap.put(pre, a[1]);
                    }
                }
            }
            String[] pl = splitQname(qname);
            String ns;
            if (pl[0] == null) ns = nsmap.getOrDefault("", "");
            else if (pl[0].equals("xml")) ns = NS_XML;
            else if (nsmap.containsKey(pl[0])) ns = nsmap.get(pl[0]);
            else throw new InvalidXml("undeclared prefix");
            List<String[]> attrs = new ArrayList<>();
            for (String[] a : rawAttrs) {
                String aname = a[0];
                if (aname.equals("xmlns") || aname.startsWith("xmlns:")) continue;
                String[] apl = splitQname(aname);
                if (apl[0] != null && !apl[0].equals("xml") && !nsmap.containsKey(apl[0])) throw new InvalidXml("undeclared attribute prefix");
                attrs.add(new String[] {apl[1], a[1]});
            }
            pos = p;
            return new Start(qname, new Elem(pl[1], ns, attrs), nsmap, empty);
        }

        Elem run() throws InvalidXml {
            // prolog
            while (true) {
                pos = skipWs(pos);
                if (pos >= n) throw new InvalidXml("no root element");
                int e = misc(pos);
                if (e >= 0) {
                    pos = e;
                    continue;
                }
                if (s.startsWith("<!", pos) || s.charAt(pos) != '<') throw new InvalidXml("prolog");
                break;
            }
            Start st = startTag(Map.of());
            Elem root = st.el();
            List<Start> stack = new ArrayList<>();
            if (!st.empty()) stack.add(st);
            while (!stack.isEmpty()) {
                if (pos >= n) throw new InvalidXml("unclosed element");
                Start top = stack.get(stack.size() - 1);
                Elem cur = top.el();
                if (s.charAt(pos) != '<') {
                    int e = s.indexOf('<', pos);
                    if (e < 0) throw new InvalidXml("unclosed element");
                    cur.text.append(refs(s.substring(pos, e), false));
                    pos = e;
                    continue;
                }
                if (s.startsWith("<![CDATA[", pos)) {
                    int e = s.indexOf("]]>", pos + 9);
                    if (e < 0) throw new InvalidXml("unterminated CDATA");
                    cur.text.append(s, pos + 9, e);
                    pos = e + 3;
                    continue;
                }
                int e = misc(pos);
                if (e >= 0) {
                    pos = e;
                    continue;
                }
                if (s.startsWith("<!", pos)) throw new InvalidXml("declaration in content");
                if (s.startsWith("</", pos)) {
                    int ne = readName(pos + 2);
                    String name = s.substring(pos + 2, ne);
                    int q = skipWs(ne);
                    if (q >= n || s.charAt(q) != '>' || !name.equals(top.qname())) throw new InvalidXml("end tag");
                    stack.remove(stack.size() - 1);
                    pos = q + 1;
                    continue;
                }
                Start child = startTag(top.nsmap());
                cur.children.add(child.el());
                if (!child.empty()) {
                    if (stack.size() >= XML_MAX_NESTING) throw new InvalidXml("nesting");
                    stack.add(child);
                }
            }
            // epilogue
            while (true) {
                pos = skipWs(pos);
                if (pos >= n) break;
                int e = misc(pos);
                if (e < 0) throw new InvalidXml("content after the root element");
                pos = e;
            }
            return root;
        }
    }

    /** 22.2 points 1-6: the root element. {@link InvalidXml} for anything outside the accepted subset. */
    public static Elem parseXml(byte[] data) throws InvalidXml {
        int off = 0;
        if (data.length >= 3 && (data[0] & 0xff) == 0xef && (data[1] & 0xff) == 0xbb && (data[2] & 0xff) == 0xbf) off = 3;
        String s = Utf8.decode(data, off, data.length - off);
        if (s == null) throw new InvalidXml("not UTF-8");
        boolean cr = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0xFFFE || c == 0xFFFF) throw new InvalidXml("forbidden character");
            if (c == '\r') cr = true;
        }
        if (cr) s = s.replace("\r\n", "\n").replace('\r', '\n');
        return new XmlParser(s).run();
    }

    /** 22.2 point 7: element to tree value (string or object). */
    private static Node xmlValue(Elem el) {
        if (el.attrs.isEmpty() && el.children.isEmpty()) return new Str(el.text.toString(), false);
        Obj o = new Obj();
        // Duplicate local attribute names: the last wins, at its own position.
        Map<String, Integer> lastAttr = new HashMap<>();
        for (int i = 0; i < el.attrs.size(); i++) lastAttr.put(el.attrs.get(i)[0], i);
        for (int i = 0; i < el.attrs.size(); i++) {
            String[] a = el.attrs.get(i);
            if (lastAttr.get(a[0]) != i) continue;
            o.keys.add(new Str("@" + a[0], false));
            o.values.add(new Str(a[1], false));
        }
        Map<String, List<Node>> groups = new LinkedHashMap<>();
        for (Elem c : el.children) groups.computeIfAbsent(c.local, k -> new ArrayList<>()).add(xmlValue(c));
        for (Map.Entry<String, List<Node>> g : groups.entrySet()) {
            o.keys.add(new Str(g.getKey(), false));
            if (g.getValue().size() == 1) o.values.add(g.getValue().get(0));
            else {
                Arr arr = new Arr();
                arr.items.addAll(g.getValue());
                o.values.add(arr);
            }
        }
        String text = el.text.toString();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                o.keys.add(new Str("#text", false));
                o.values.add(new Str(text, false));
                break;
            }
        }
        return o;
    }

    private static boolean nsRunChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    }

    private static boolean runHides(String t) {
        if (t.length() > 64) return true;
        int dig = 0;
        int hex = 0;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            dig = c >= '0' && c <= '9' ? dig + 1 : 0;
            hex = isHex(c) ? hex + 1 : 0;
            if (dig >= 6 || hex >= 12) return true;
        }
        return false;
    }

    /** 22.2 point 9: {@code ns:} + pattern of a namespace URI. */
    public static String nsPattern(String uri) {
        if (uri.isEmpty()) return "ns:{none}";
        if (Utf8.length(uri) > NS_MAX_BYTES) return "ns:{*}";
        for (int i = 0; i < uri.length(); i++) {
            char c = uri.charAt(i);
            if (c < '!' || c > '~' || c == '@' || c == '{' || c == '}') return "ns:{*}";
        }
        StringBuilder sb = new StringBuilder("ns:");
        int i = 0;
        while (i < uri.length()) {
            char c = uri.charAt(i);
            if (!nsRunChar(c)) {
                sb.append(c);
                i++;
                continue;
            }
            int j = i;
            while (j < uri.length() && nsRunChar(uri.charAt(j))) j++;
            String t = uri.substring(i, j);
            sb.append(runHides(t) ? "{*}" : t);
            i = j;
        }
        return sb.toString();
    }

    /** Body tree, xmlns entries (path, token) in document order, fmt. */
    public record XmlTree(Obj tree, List<String[]> xmlns, String fmt) {}

    /** 22.2 points 7, 9 and 10. */
    public static XmlTree xmlTree(Elem root, int maxDepth) {
        Obj tree = new Obj();
        tree.keys.add(new Str(root.local, false));
        tree.values.add(xmlValue(root));
        List<String[]> entries = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        visit(root, "$" + step(root.local), "", 1, maxDepth, entries, seen);
        String fmt = "xml";
        if (root.local.equals("Envelope") && root.ns.equals(SOAP11)) fmt = "soap11";
        else if (root.local.equals("Envelope") && root.ns.equals(SOAP12)) fmt = "soap12";
        return new XmlTree(tree, entries, fmt);
    }

    private static String step(String local) {
        return Formats.isLiteralName(local) ? "." + local : ".*";
    }

    private static void visit(Elem el, String path, String parentNs, int depth, int maxDepth, List<String[]> entries, Set<String> seen) {
        if (depth > maxDepth) return;
        if (!el.ns.equals(parentNs) && seen.add(path)) entries.add(new String[] {path, nsPattern(el.ns)});
        Map<String, Integer> counts = new HashMap<>();
        for (Elem c : el.children) counts.merge(c.local, 1, Integer::sum);
        for (Elem c : el.children) {
            String p = path + step(c.local) + (counts.get(c.local) > 1 ? "[*]" : "");
            visit(c, p, el.ns, depth + 1, maxDepth, entries, seen);
        }
    }

    /** 22.2 point 11: the operation name of a SOAPAction value, or null when empty. */
    public static String soapActionName(String raw) {
        String s = trimSpTab(raw);
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) s = s.substring(1, s.length() - 1);
        if (s.isEmpty()) return null;
        int cut = Math.max(s.lastIndexOf('/'), Math.max(s.lastIndexOf('#'), s.lastIndexOf(':')));
        String name = s.substring(cut + 1);
        return Formats.isLiteralName(name) ? name : "{*}";
    }

    /** 22.2 point 8: a key of an XML tree is literal ({@code #text}; {@code @} + a literal name; a literal element name). */
    public static boolean xmlKeyIsLiteral(String k) {
        if (k.equals("#text")) return true;
        if (k.startsWith("@")) return Formats.isLiteralName(k.substring(1));
        return Formats.isLiteralName(k);
    }
}
