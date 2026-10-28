using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace TrafficTwin.Sdk.Sanitizing;

// Body formats of spec v1.19 (sanitizer.md 22): base64 documents (22.4), media type parameters (22.2 point 11),
// multipart/form-data (22.3) and the strict XML subset (22.2). Pure functions: they never see the policy.
// Mirrors conformance/ref/bodies.py. System.Xml is deliberately not used: the spec fixes the accepted subset
// (no DTD, no entities beyond the five predefined ones) so that every source builds the same tree.

/// <summary>Base64 documents and document size classes (sanitizer.md 22.4).</summary>
internal static class Docs
{
    private const int MinChars = 16;

    /// <summary>Document class on the decoded length.</summary>
    public static string DocClass(long n)
    {
        if (n <= 1024) return "l1k";
        if (n <= 16384) return "l16k";
        if (n <= 131072) return "l128k";
        if (n <= 1048576) return "l1m";
        if (n <= 8388608) return "l8m";
        return "lmax";
    }

    private static bool StartsWith(ReadOnlySpan<byte> b, ReadOnlySpan<byte> p) => b.Length >= p.Length && b.Slice(0, p.Length).SequenceEqual(p);

    /// <summary>Kind of a document from its first bytes (and, for zip, the names it holds); null if none.</summary>
    public static string? MagicKind(ReadOnlySpan<byte> b)
    {
        if (StartsWith(b, "%PDF-"u8)) return "pdf";
        if (StartsWith(b, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) return "png";
        if (StartsWith(b, new byte[] { 0xFF, 0xD8, 0xFF })) return "jpeg";
        if (StartsWith(b, "GIF87a"u8) || StartsWith(b, "GIF89a"u8)) return "gif";
        if (StartsWith(b, "RIFF"u8) && b.Length >= 12 && b.Slice(8, 4).SequenceEqual("WEBP"u8)) return "webp";
        if (StartsWith(b, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return "ole";
        if (StartsWith(b, new byte[] { 0x50, 0x4B, 0x03, 0x04 }))
        {
            if (b.IndexOf("word/document.xml"u8) >= 0) return "docx";
            if (b.IndexOf("xl/workbook.xml"u8) >= 0) return "xlsx";
            if (b.IndexOf("ppt/presentation.xml"u8) >= 0) return "pptx";
            return "zip";
        }
        return null;
    }

    private static int B64Value(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    }

    /// <summary>
    /// Decodes <paramref name="n"/> characters of the standard or url alphabet (mixed) starting at <paramref name="start"/>,
    /// without padding; the final padding bits are ignored. The characters must already be validated.
    /// Convert.FromBase64String is not used: it rejects the url alphabet and unpadded input.
    /// </summary>
    private static byte[] Decode(string s, int start, int n)
    {
        var outp = new byte[(int)((long)n * 3 / 4)];
        int o = 0;
        int acc = 0, bits = 0;
        for (int i = 0; i < n; i++)
        {
            acc = (acc << 6) | B64Value(s[start + i]);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                if (o < outp.Length) outp[o++] = (byte)(acc >> bits);
                acc &= (1 << bits) - 1;
            }
        }
        return outp;
    }

    /// <summary>22.4: <c>drop:doc:&lt;kind&gt;:&lt;class&gt;</c> if the string is the base64 of a document, else null.</summary>
    public static string? Base64Doc(string s)
    {
        int start = 0;
        if (s.StartsWith("data:", StringComparison.Ordinal))
        {
            int i = s.IndexOf(',');
            if (i < 0) return null;
            // "data:" + printable ASCII without ',' + ";base64"
            if (i < 12 || string.CompareOrdinal(s, i - 7, ";base64", 0, 7) != 0) return null;
            for (int k = 0; k < i; k++)
            {
                if (s[k] < 0x21 || s[k] > 0x7e) return null;
            }
            start = i + 1;
        }
        int len = s.Length - start;
        if (len < MinChars) return null;
        int pad = 0;
        while (pad < 2 && s[s.Length - 1 - pad] == '=') pad++;
        int body = len - pad;
        for (int k = start; k < start + body; k++)
        {
            if (B64Value(s[k]) < 0) return null;
        }
        if (pad > 0 && len % 4 != 0) return null;
        if (body % 4 == 1) return null;
        long decodedLen = (long)body * 3 / 4;
        // The kind needs only the first bytes, except a zip (it looks for the names inside).
        int head = Math.Min(body, 16);
        byte[] first = Decode(s, start, head);
        string? kind = MagicKind(first);
        if (kind == null) return null;
        if (kind == "zip") kind = MagicKind(Decode(s, start, body));
        return "drop:doc:" + kind + ":" + DocClass(decodedLen);
    }
}

/// <summary>Parameters of a content-type value (sanitizer.md 22.2 point 11, 22.3 point 1).</summary>
internal static class MediaParams
{
    private static string TrimSpTab(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
        while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
        return s.Substring(a, b - a);
    }

    internal static string Trim(string s) => TrimSpTab(s);

    /// <summary>Lowercase name to value, first occurrence wins; empty for an absent or non-UTF-8 value.</summary>
    public static Dictionary<string, string> Parse(byte[]? value)
    {
        var res = new Dictionary<string, string>(StringComparer.Ordinal);
        if (value == null) return res;
        string? s = Utf8Util.Decode(value);
        if (s == null) return res;
        string[] pieces = s.Split(';');
        for (int i = 1; i < pieces.Length; i++)
        {
            string piece = TrimSpTab(pieces[i]);
            int eq = piece.IndexOf('=');
            if (eq < 0) continue;
            string name = Utf8Util.AsciiLower(TrimSpTab(piece.Substring(0, eq)));
            string v = TrimSpTab(piece.Substring(eq + 1));
            if (v.StartsWith('"'))
            {
                if (v.Length < 2 || !v.EndsWith('"')) continue;
                v = v.Substring(1, v.Length - 2);
            }
            res.TryAdd(name, v);
        }
        return res;
    }
}

internal sealed class InvalidBodyException : Exception
{
    public InvalidBodyException(string why) : base(why) { }
}

/// <summary>One part of a multipart/form-data body: name, file or field, content bytes, lowercase media type of the part (or null).</summary>
internal readonly record struct MultipartPart(string Name, bool IsFile, byte[] Content, string? Ct);

/// <summary>multipart/form-data (sanitizer.md 22.3).</summary>
internal static class Multipart
{
    private static readonly Regex BoundaryRe = Re.Full("[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]");

    private static InvalidBodyException Bad(string why) => new(why);

    private static bool IsTokenByte(byte c) =>
        (c >= (byte)'A' && c <= (byte)'Z') || (c >= (byte)'a' && c <= (byte)'z') || (c >= (byte)'0' && c <= (byte)'9') ||
        "!#$%&'*+.^_`|~-".IndexOf((char)c) >= 0;

    private static byte[] TrimSpTab(ReadOnlySpan<byte> b)
    {
        int a = 0, e = b.Length;
        while (a < e && (b[a] == ' ' || b[a] == '\t')) a++;
        while (e > a && (b[e - 1] == ' ' || b[e - 1] == '\t')) e--;
        return b.Slice(a, e - a).ToArray();
    }

    /// <summary>content-disposition of a part: parameters (first wins). Throws if the type is not form-data.</summary>
    internal static Dictionary<string, string> Disposition(string s)
    {
        int i = s.IndexOf(';');
        string kind = MediaParams.Trim(i < 0 ? s : s.Substring(0, i));
        if (Utf8Util.AsciiLower(kind) != "form-data") throw Bad("disposition");
        var ps = new Dictionary<string, string>(StringComparer.Ordinal);
        int n = s.Length;
        int pos = i < 0 ? n : i;
        while (pos < n)
        {
            while (pos < n && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == ';')) pos++;
            if (pos >= n) break;
            int start = pos;
            while (pos < n && s[pos] != '=' && s[pos] != ';') pos++;
            string name = Utf8Util.AsciiLower(MediaParams.Trim(s.Substring(start, pos - start)));
            if (pos >= n || s[pos] == ';')
            {
                ps.TryAdd(name, "");
                continue;
            }
            pos++; // '='
            while (pos < n && (s[pos] == ' ' || s[pos] == '\t')) pos++;
            string val;
            if (pos < n && s[pos] == '"')
            {
                pos++;
                var buf = new StringBuilder();
                while (true)
                {
                    if (pos >= n) throw Bad("unterminated quoted string");
                    char c = s[pos];
                    if (c == '\\' && pos + 1 < n)
                    {
                        buf.Append(s[pos + 1]);
                        pos += 2;
                        continue;
                    }
                    if (c == '"')
                    {
                        pos++;
                        break;
                    }
                    buf.Append(c);
                    pos++;
                }
                val = buf.ToString();
                while (pos < n && (s[pos] == ' ' || s[pos] == '\t')) pos++;
                if (pos < n && s[pos] != ';') throw Bad("garbage after quoted string");
            }
            else
            {
                start = pos;
                while (pos < n && s[pos] != ';') pos++;
                val = MediaParams.Trim(s.Substring(start, pos - start));
            }
            ps.TryAdd(name, val);
        }
        return ps;
    }

    /// <summary>Parses a body. Throws <see cref="InvalidBodyException"/> for anything outside 22.3 points 1-4.</summary>
    public static List<MultipartPart> Parse(byte[] data, string? boundary)
    {
        if (boundary == null || !BoundaryRe.IsMatch(boundary)) throw Bad("boundary");
        byte[] delim = Encoding.ASCII.GetBytes("--" + boundary);
        var crlfDelim = new byte[delim.Length + 2];
        crlfDelim[0] = (byte)'\r';
        crlfDelim[1] = (byte)'\n';
        delim.CopyTo(crlfDelim, 2);
        ReadOnlySpan<byte> d = data;
        int n = d.Length;
        int pos;
        if (d.StartsWith(delim)) pos = 0;
        else
        {
            int i = d.IndexOf(crlfDelim);
            if (i < 0) throw Bad("no delimiter");
            pos = i + 2;
        }
        var raw = new List<(int Start, int End)>();
        while (true)
        {
            pos += delim.Length;
            if (pos + 2 <= n && d[pos] == '-' && d[pos + 1] == '-') break;
            while (pos < n && (d[pos] == ' ' || d[pos] == '\t')) pos++;
            if (!(pos + 2 <= n && d[pos] == '\r' && d[pos + 1] == '\n')) throw Bad("delimiter line");
            pos += 2;
            int rel = d.Slice(pos).IndexOf(crlfDelim);
            if (rel < 0) throw Bad("no close delimiter");
            int nxt = pos + rel;
            raw.Add((pos, nxt));
            pos = nxt + 2;
        }
        var outp = new List<MultipartPart>(raw.Count);
        foreach (var (start, end) in raw)
        {
            ReadOnlySpan<byte> p = d.Slice(start, end - start);
            ReadOnlySpan<byte> head;
            ReadOnlySpan<byte> content;
            if (p.StartsWith("\r\n"u8))
            {
                head = ReadOnlySpan<byte>.Empty;
                content = p.Slice(2);
            }
            else
            {
                int j = p.IndexOf("\r\n\r\n"u8);
                if (j < 0) throw Bad("part headers");
                head = p.Slice(0, j);
                content = p.Slice(j + 4);
            }
            var headers = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            while (head.Length > 0)
            {
                int eol = head.IndexOf("\r\n"u8);
                ReadOnlySpan<byte> line = eol < 0 ? head : head.Slice(0, eol);
                head = eol < 0 ? ReadOnlySpan<byte>.Empty : head.Slice(eol + 2);
                int k = line.IndexOf((byte)':');
                if (k <= 0) throw Bad("part header line");
                for (int q = 0; q < k; q++)
                {
                    if (!IsTokenByte(line[q])) throw Bad("part header name");
                }
                string name = Utf8Util.AsciiLower(Utf8Util.Latin1(line.Slice(0, k)));
                headers.TryAdd(name, TrimSpTab(line.Slice(k + 1)));
                if (eol >= 0 && head.Length == 0)
                {
                    // a trailing empty line: split() would give an empty last line, which has no ':'
                    throw Bad("part header line");
                }
            }
            if (!headers.TryGetValue("content-disposition", out byte[]? cd)) throw Bad("no content-disposition");
            string cds = Utf8Util.Decode(cd) ?? throw Bad("content-disposition not UTF-8");
            var ps = Disposition(cds);
            if (!ps.TryGetValue("name", out string? partName)) throw Bad("no name");
            bool isFile = ps.ContainsKey("filename") || ps.ContainsKey("filename*");
            string? ct = null;
            if (headers.TryGetValue("content-type", out byte[]? ctb))
            {
                string? cts = Utf8Util.Decode(ctb);
                if (cts != null)
                {
                    int semi = cts.IndexOf(';');
                    ct = Utf8Util.AsciiLower(MediaParams.Trim(semi < 0 ? cts : cts.Substring(0, semi)));
                }
            }
            outp.Add(new MultipartPart(partName, isFile, content.ToArray(), ct));
        }
        return outp;
    }

    /// <summary>22.3: <c>drop:file:&lt;kind&gt;:&lt;class&gt;</c> of a file part.</summary>
    public static string FileToken(byte[] content, string? ct)
    {
        string? kind = Docs.MagicKind(content);
        if (kind == null)
        {
            kind = ct switch
            {
                "text/plain" => "text",
                "text/csv" => "csv",
                "application/json" => "json",
                "application/xml" or "text/xml" => "xml",
                _ => "bin",
            };
        }
        return "drop:file:" + kind + ":" + Docs.DocClass(content.Length);
    }
}

/// <summary>One XML element: local name, namespace URI ("" = none), attributes without namespace declarations, children, direct text.</summary>
internal sealed class XElem
{
    public readonly string Local;
    public readonly string Ns;
    public readonly List<(string Local, string Value)> Attrs;
    public readonly List<XElem> Children = new();
    public readonly StringBuilder Text = new();

    public XElem(string local, string ns, List<(string, string)> attrs)
    {
        Local = local;
        Ns = ns;
        Attrs = attrs;
    }
}

/// <summary>Strict XML subset (sanitizer.md 22.2 points 1-6) and its tree (points 7-10).</summary>
internal static class Xml
{
    public const string NsXml = "http://www.w3.org/XML/1998/namespace";
    public const string Soap11 = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string Soap12 = "http://www.w3.org/2003/05/soap-envelope";
    public const int MaxNesting = 256;
    private const int NsMaxBytes = 512;

    private static InvalidBodyException Bad(string why) => new(why);

    private static bool NameStart(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80;

    private static bool NameChar(char c) => NameStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':';

    private static bool IsXmlChar(int cp) =>
        cp == 0x9 || cp == 0xA || cp == 0xD || (cp >= 0x20 && cp <= 0xD7FF) || (cp >= 0xE000 && cp <= 0xFFFD) || (cp >= 0x10000 && cp <= 0x10FFFF);

    private static bool IsWs(char c) => c == ' ' || c == '\t' || c == '\n';

    private static int HexDigit(char d)
    {
        if (d >= '0' && d <= '9') return d - '0';
        if (d >= 'a' && d <= 'f') return d - 'a' + 10;
        if (d >= 'A' && d <= 'F') return d - 'A' + 10;
        return -1;
    }

    /// <summary>Character and predefined entity references; attribute values turn literal tab and newline into spaces.</summary>
    private static string Refs(string s, int from, int to, bool attr)
    {
        StringBuilder? sb = null;
        int i = from;
        int plain = from; // start of the pending run copied as is
        while (i < to)
        {
            char c = s[i];
            if (c == '&')
            {
                sb ??= new StringBuilder(to - from);
                sb.Append(s, plain, i - plain);
                int j = s.IndexOf(';', i + 1, to - i - 1);
                if (j < 0) throw Bad("unterminated reference");
                string ent = s.Substring(i + 1, j - i - 1);
                switch (ent)
                {
                    case "lt": sb.Append('<'); break;
                    case "gt": sb.Append('>'); break;
                    case "amp": sb.Append('&'); break;
                    case "apos": sb.Append('\''); break;
                    case "quot": sb.Append('"'); break;
                    default:
                        {
                            int cp = 0;
                            if (ent.Length > 2 && ent[0] == '#' && ent[1] == 'x' && AllHex(ent, 2))
                            {
                                for (int k = 2; k < ent.Length; k++)
                                {
                                    cp = cp * 16 + HexDigit(ent[k]);
                                    if (cp > 0x10FFFF) throw Bad("reference out of range");
                                }
                            }
                            else if (ent.Length > 1 && ent[0] == '#' && AllDec(ent, 1))
                            {
                                for (int k = 1; k < ent.Length; k++)
                                {
                                    cp = cp * 10 + (ent[k] - '0');
                                    if (cp > 0x10FFFF) throw Bad("reference out of range");
                                }
                            }
                            else throw Bad("unknown entity");
                            if (!IsXmlChar(cp)) throw Bad("reference to a forbidden character");
                            sb.Append(char.ConvertFromUtf32(cp));
                            break;
                        }
                }
                i = j + 1;
                plain = i;
                continue;
            }
            if (attr && (c == '\t' || c == '\n'))
            {
                sb ??= new StringBuilder(to - from);
                sb.Append(s, plain, i - plain);
                sb.Append(' ');
                i++;
                plain = i;
                continue;
            }
            i++;
        }
        if (sb == null) return s.Substring(from, to - from);
        sb.Append(s, plain, to - plain);
        return sb.ToString();
    }

    private static bool AllHex(string s, int from)
    {
        for (int k = from; k < s.Length; k++)
        {
            if (HexDigit(s[k]) < 0) return false;
        }
        return true;
    }

    private static bool AllDec(string s, int from)
    {
        for (int k = from; k < s.Length; k++)
        {
            if (s[k] < '0' || s[k] > '9') return false;
        }
        return true;
    }

    private static (string? Prefix, string Local) SplitQName(string q)
    {
        int c = q.IndexOf(':');
        if (c < 0) return (null, q);
        string p = q.Substring(0, c);
        string l = q.Substring(c + 1);
        if (p.Length == 0 || l.Length == 0 || l.IndexOf(':') >= 0) throw Bad("qualified name");
        return (p, l);
    }

    private sealed class Parser
    {
        private readonly string s;
        private readonly int n;

        public Parser(string s)
        {
            this.s = s;
            n = s.Length;
        }

        private bool At(int p, string lit) => p + lit.Length <= n && string.CompareOrdinal(s, p, lit, 0, lit.Length) == 0;

        private (string Name, int End) ReadName(int p)
        {
            if (p >= n || !NameStart(s[p])) throw Bad("name");
            int q = p + 1;
            while (q < n && NameChar(s[q])) q++;
            return (s.Substring(p, q - p), q);
        }

        private int SkipWs(int p)
        {
            while (p < n && IsWs(s[p])) p++;
            return p;
        }

        /// <summary>Comment or processing instruction at p: its end, or -1 if none starts there.</summary>
        private int Misc(int p)
        {
            if (At(p, "<!--"))
            {
                int e = s.IndexOf("-->", p + 4, StringComparison.Ordinal);
                if (e < 0) throw Bad("unterminated comment");
                return e + 3;
            }
            if (At(p, "<?"))
            {
                int e = s.IndexOf("?>", p + 2, StringComparison.Ordinal);
                if (e < 0) throw Bad("unterminated processing instruction");
                return e + 2;
            }
            return -1;
        }

        private (string QName, XElem El, Dictionary<string, string> NsMap, bool Empty, int End) StartTag(int p, Dictionary<string, string> parentNs)
        {
            (string qname, p) = ReadName(p + 1);
            var rawAttrs = new List<(string Name, string Value)>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            bool empty = false;
            while (true)
            {
                int q = SkipWs(p);
                if (At(q, "/>"))
                {
                    p = q + 2;
                    empty = true;
                    break;
                }
                if (At(q, ">"))
                {
                    p = q + 1;
                    break;
                }
                if (q == p) throw Bad("attribute without space");
                (string aname, q) = ReadName(q);
                q = SkipWs(q);
                if (q >= n || s[q] != '=') throw Bad("attribute without =");
                q = SkipWs(q + 1);
                if (q >= n || (s[q] != '"' && s[q] != '\'')) throw Bad("attribute value");
                int e = s.IndexOf(s[q], q + 1);
                if (e < 0) throw Bad("unterminated attribute value");
                if (s.IndexOf('<', q + 1, e - q - 1) >= 0) throw Bad("< in attribute value");
                if (!seen.Add(aname)) throw Bad("duplicate attribute");
                rawAttrs.Add((aname, Refs(s, q + 1, e, true)));
                p = e + 1;
            }
            var nsmap = parentNs;
            foreach (var (aname, v) in rawAttrs)
            {
                string? pre = null;
                if (aname == "xmlns") pre = "";
                else if (aname.StartsWith("xmlns:", StringComparison.Ordinal))
                {
                    pre = aname.Substring(6);
                    if (pre.Length == 0 || pre.IndexOf(':') >= 0) throw Bad("namespace declaration");
                }
                if (pre == null) continue;
                if (ReferenceEquals(nsmap, parentNs)) nsmap = new Dictionary<string, string>(parentNs, StringComparer.Ordinal);
                nsmap[pre] = v;
            }
            var (prefix, local) = SplitQName(qname);
            string ns;
            if (prefix == null) ns = nsmap.TryGetValue("", out string? dns) ? dns : "";
            else if (prefix == "xml") ns = NsXml;
            else if (!nsmap.TryGetValue(prefix, out ns!)) throw Bad("undeclared prefix");
            var attrs = new List<(string, string)>();
            foreach (var (aname, v) in rawAttrs)
            {
                if (aname == "xmlns" || aname.StartsWith("xmlns:", StringComparison.Ordinal)) continue;
                var (ap, al) = SplitQName(aname);
                if (ap != null && ap != "xml" && !nsmap.ContainsKey(ap)) throw Bad("undeclared attribute prefix");
                attrs.Add((al, v));
            }
            return (qname, new XElem(local, ns, attrs), nsmap, empty, p);
        }

        public XElem Parse()
        {
            int pos = 0;
            // prolog
            while (true)
            {
                pos = SkipWs(pos);
                if (pos >= n) throw Bad("no root element");
                int e = Misc(pos);
                if (e >= 0)
                {
                    pos = e;
                    continue;
                }
                if (At(pos, "<!") || s[pos] != '<') throw Bad("prolog");
                break;
            }
            var stack = new List<(string QName, XElem El, Dictionary<string, string> NsMap)>();
            var (qname0, root, nsmap0, empty0, p0) = StartTag(pos, new Dictionary<string, string>(StringComparer.Ordinal));
            pos = p0;
            if (!empty0) stack.Add((qname0, root, nsmap0));
            while (stack.Count > 0)
            {
                if (pos >= n) throw Bad("unclosed element");
                var (qn, cur, curNs) = stack[stack.Count - 1];
                if (s[pos] != '<')
                {
                    int e = s.IndexOf('<', pos);
                    if (e < 0) throw Bad("unclosed element");
                    cur.Text.Append(Refs(s, pos, e, false));
                    pos = e;
                    continue;
                }
                if (At(pos, "<![CDATA["))
                {
                    int e = s.IndexOf("]]>", pos + 9, StringComparison.Ordinal);
                    if (e < 0) throw Bad("unterminated CDATA");
                    cur.Text.Append(s, pos + 9, e - pos - 9);
                    pos = e + 3;
                    continue;
                }
                int m = Misc(pos);
                if (m >= 0)
                {
                    pos = m;
                    continue;
                }
                if (At(pos, "<!")) throw Bad("declaration in content");
                if (At(pos, "</"))
                {
                    var (name, q) = ReadName(pos + 2);
                    q = SkipWs(q);
                    if (q >= n || s[q] != '>' || name != qn) throw Bad("end tag");
                    stack.RemoveAt(stack.Count - 1);
                    pos = q + 1;
                    continue;
                }
                var (qname, el, nsmap, empty, p) = StartTag(pos, curNs);
                pos = p;
                cur.Children.Add(el);
                if (!empty)
                {
                    if (stack.Count >= MaxNesting) throw Bad("nesting");
                    stack.Add((qname, el, nsmap));
                }
            }
            // epilogue
            while (true)
            {
                pos = SkipWs(pos);
                if (pos >= n) break;
                int e = Misc(pos);
                if (e < 0) throw Bad("content after the root element");
                pos = e;
            }
            return root;
        }
    }

    /// <summary>22.2 points 1-6: the root element. Throws <see cref="InvalidBodyException"/> outside the accepted subset.</summary>
    public static XElem Parse(byte[] data)
    {
        ReadOnlySpan<byte> b = data;
        if (b.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) b = b.Slice(3);
        string s = Utf8Util.Decode(b) ?? throw Bad("not UTF-8");
        bool hasCr = false;
        foreach (char c in s)
        {
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == '￾' || c == '￿') throw Bad("forbidden character");
            if (c == '\r') hasCr = true;
        }
        if (hasCr) s = s.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        return new Parser(s).Parse();
    }

    private static bool HasNonSpace(StringBuilder t)
    {
        for (int i = 0; i < t.Length; i++)
        {
            char c = t[i];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return true;
        }
        return false;
    }

    /// <summary>22.2 point 7: element to tree value (a string, or an object).</summary>
    private static JNode Value(XElem el)
    {
        if (el.Attrs.Count == 0 && el.Children.Count == 0) return new JStr(el.Text.ToString(), false);
        var members = new List<KeyValuePair<JStr, JNode>?>();
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (local, v) in el.Attrs)
        {
            // duplicates (same local name): the last wins, at its own position
            string k = "@" + local;
            if (index.TryGetValue(k, out int prev)) members[prev] = null;
            index[k] = members.Count;
            members.Add(new KeyValuePair<JStr, JNode>(new JStr(k, false), new JStr(v, false)));
        }
        var obj = new JObj();
        foreach (var m in members)
        {
            if (m != null) obj.Members.Add(m.Value);
        }
        var groups = new Dictionary<string, List<JNode>>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (XElem c in el.Children)
        {
            if (!groups.TryGetValue(c.Local, out List<JNode>? g))
            {
                g = new List<JNode>();
                groups[c.Local] = g;
                order.Add(c.Local);
            }
            g.Add(Value(c));
        }
        foreach (string k in order)
        {
            var vs = groups[k];
            JNode v;
            if (vs.Count == 1) v = vs[0];
            else
            {
                var arr = new JArr();
                arr.Items.AddRange(vs);
                v = arr;
            }
            obj.Members.Add(new KeyValuePair<JStr, JNode>(new JStr(k, false), v));
        }
        if (HasNonSpace(el.Text)) obj.Members.Add(new KeyValuePair<JStr, JNode>(new JStr("#text", false), new JStr(el.Text.ToString(), false)));
        return obj;
    }

    private static bool KeepsRun(string uri, int a, int b)
    {
        int len = b - a;
        if (len > 64) return false;
        int digits = 0, hex = 0;
        for (int i = a; i < b; i++)
        {
            char c = uri[i];
            digits = c >= '0' && c <= '9' ? digits + 1 : 0;
            hex = HexDigit(c) >= 0 ? hex + 1 : 0;
            if (digits >= 6 || hex >= 12) return false;
        }
        return true;
    }

    private static bool RunChar(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';

    /// <summary>22.2 point 9: <c>ns:</c> + pattern of a namespace URI.</summary>
    public static string NsPattern(string uri)
    {
        if (uri.Length == 0) return "ns:{none}";
        if (Utf8Util.Utf8Length(uri) > NsMaxBytes) return "ns:{*}";
        foreach (char c in uri)
        {
            if (c < '!' || c > '~' || c == '@' || c == '{' || c == '}') return "ns:{*}";
        }
        var sb = new StringBuilder("ns:", uri.Length + 3);
        int i = 0;
        while (i < uri.Length)
        {
            if (!RunChar(uri[i]))
            {
                sb.Append(uri[i]);
                i++;
                continue;
            }
            int j = i;
            while (j < uri.Length && RunChar(uri[j])) j++;
            if (KeepsRun(uri, i, j)) sb.Append(uri, i, j - i);
            else sb.Append("{*}");
            i = j;
        }
        return sb.ToString();
    }

    /// <summary>The body tree, the xmlns entries (path, token) in document order, and fmt (22.2 points 7, 9, 10).</summary>
    public static (JObj Tree, List<(string Path, string Token)> Entries, string Fmt) Tree(XElem root, int maxDepth)
    {
        var tree = new JObj();
        tree.Members.Add(new KeyValuePair<JStr, JNode>(new JStr(root.Local, false), Value(root)));
        var entries = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Visit(XElem el, string path, string parentNs, int depth)
        {
            if (depth > maxDepth) return;
            if (el.Ns != parentNs && seen.Add(path)) entries.Add((path, NsPattern(el.Ns)));
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (XElem c in el.Children) counts[c.Local] = counts.GetValueOrDefault(c.Local) + 1;
            foreach (XElem c in el.Children)
            {
                string p = path + (Formats.IsLiteralName(c.Local) ? "." + c.Local : ".*") + (counts[c.Local] > 1 ? "[*]" : "");
                Visit(c, p, el.Ns, depth + 1);
            }
        }

        Visit(root, "$" + (Formats.IsLiteralName(root.Local) ? "." + root.Local : ".*"), "", 1);
        string fmt = "xml";
        if (root.Local == "Envelope" && root.Ns == Soap11) fmt = "soap11";
        else if (root.Local == "Envelope" && root.Ns == Soap12) fmt = "soap12";
        return (tree, entries, fmt);
    }

    /// <summary>22.2 point 8: keys of an XML tree (<c>#text</c>, <c>@</c> + attribute name, element name).</summary>
    public static bool KeyIsLiteral(string k)
    {
        if (k == "#text") return true;
        if (k.Length > 0 && k[0] == '@') return Formats.IsLiteralName(k.Substring(1));
        return Formats.IsLiteralName(k);
    }

    /// <summary>22.2 point 11: the operation name of a SOAPAction value, or null when empty.</summary>
    public static string? SoapActionName(string raw)
    {
        string s = MediaParams.Trim(raw);
        if (s.Length >= 2 && s[0] == '"' && s[s.Length - 1] == '"') s = s.Substring(1, s.Length - 2);
        if (s.Length == 0) return null;
        int cut = Math.Max(s.LastIndexOf('/'), Math.Max(s.LastIndexOf('#'), s.LastIndexOf(':')));
        string name = s.Substring(cut + 1);
        return Formats.IsLiteralName(name) ? name : "{*}";
    }
}
