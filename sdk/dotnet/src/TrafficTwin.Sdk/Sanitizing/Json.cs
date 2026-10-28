using System;
using System.Collections.Generic;
using System.Text;

namespace TrafficTwin.Sdk.Sanitizing;

// Strict RFC 8259 JSON parser that keeps number lexemes (sanitizer.md 9.2), the tt-cjson
// canonical writer (10.1) and the canonical number form (10.2).
//
// The parser is iterative (no recursion), validates the whole input, rejects a leading BOM,
// invalid UTF-8, control characters in strings, and anything outside RFC 8259. Lone
// surrogates produced by \u escapes are allowed syntactically and flagged on the string node.
// System.Text.Json is deliberately not used: it does not report lone-surrogate escapes
// uniformly and its numbers would have to be re-read from ValueSpan; a 300-line parser is
// simpler to audit against 9.2 than a wrapper.

internal enum JKind { Obj, Arr, Str, Num, Bool, Null }

internal abstract class JNode
{
    public abstract JKind Kind { get; }
}

internal sealed class JObj : JNode
{
    public override JKind Kind => JKind.Obj;
    public readonly List<KeyValuePair<JStr, JNode>> Members = new();
}

internal sealed class JArr : JNode
{
    public override JKind Kind => JKind.Arr;
    public readonly List<JNode> Items = new();
}

internal sealed class JStr : JNode
{
    public override JKind Kind => JKind.Str;
    public readonly string S;
    /// <summary>The string holds a lone surrogate (an unpaired \uD800-\uDFFF escape).</summary>
    public readonly bool Bad;
    public JStr(string s, bool bad) { S = s; Bad = bad; }
}

internal sealed class JNum : JNode
{
    public override JKind Kind => JKind.Num;
    public readonly string Lex;
    public JNum(string lex) { Lex = lex; }
}

internal sealed class JBool : JNode
{
    public override JKind Kind => JKind.Bool;
    public readonly bool V;
    public JBool(bool v) { V = v; }
}

internal sealed class JNull : JNode
{
    public override JKind Kind => JKind.Null;
}

internal sealed class JsonException2 : Exception
{
    public JsonException2(string msg) : base(msg) { }
}

internal static class JsonParser
{
    private static readonly JNull NullNode = new();
    private static readonly JBool TrueNode = new(true);
    private static readonly JBool FalseNode = new(false);

    private sealed class Frame
    {
        public JNode Node = null!;
        public JStr? Key;
    }

    private static bool IsWs(byte c) => c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d;

    /// <summary>Parses a complete JSON document. Throws <see cref="JsonException2"/> on any deviation from RFC 8259.</summary>
    public static JNode Parse(byte[] buf)
    {
        return new Reader(buf).ParseDocument();
    }

    private sealed class Reader
    {
        private readonly byte[] b;
        private readonly int n;
        private int i;

        public Reader(byte[] buf) { b = buf; n = buf.Length; }

        private int At(int k) => k < n ? b[k] : -1;

        private void Ws()
        {
            while (i < n && IsWs(b[i])) i++;
        }

        private int Hex4(int p)
        {
            int v = 0;
            for (int j = 0; j < 4; j++)
            {
                int c = At(p + j);
                int d;
                if (c < 0) throw new JsonException2("eof in escape");
                if (c >= 0x30 && c <= 0x39) d = c - 0x30;
                else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
                else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
                else throw new JsonException2("bad hex escape");
                v = v * 16 + d;
            }
            return v;
        }

        private JStr ReadString()
        {
            i++; // opening quote
            StringBuilder? sb = null;
            int start = i;
            bool nonAscii = false;

            void Flush(int end)
            {
                if (end > start)
                {
                    string piece;
                    if (nonAscii)
                    {
                        string? d = Utf8Util.Decode(b.AsSpan(start, end - start));
                        if (d == null) throw new JsonException2("invalid utf-8");
                        piece = d;
                    }
                    else
                    {
                        piece = Encoding.Latin1.GetString(b, start, end - start);
                    }
                    (sb ??= new StringBuilder()).Append(piece);
                }
                nonAscii = false;
            }

            for (;;)
            {
                if (i >= n) throw new JsonException2("unterminated string");
                byte c = b[i];
                if (c == 0x22)
                {
                    string result;
                    if (sb == null)
                    {
                        // Fast path: no escapes.
                        if (i > start)
                        {
                            string? d = nonAscii ? Utf8Util.Decode(b.AsSpan(start, i - start)) : Encoding.Latin1.GetString(b, start, i - start);
                            if (d == null) throw new JsonException2("invalid utf-8");
                            result = d;
                        }
                        else result = "";
                    }
                    else
                    {
                        Flush(i);
                        result = sb.ToString();
                    }
                    i++;
                    return new JStr(result, !Utf8Util.IsWellFormed(result));
                }
                if (c == 0x5c)
                {
                    Flush(i);
                    int e = At(i + 1);
                    sb ??= new StringBuilder();
                    switch (e)
                    {
                        case 0x22: sb.Append('"'); i += 2; break;
                        case 0x5c: sb.Append('\\'); i += 2; break;
                        case 0x2f: sb.Append('/'); i += 2; break;
                        case 0x62: sb.Append('\b'); i += 2; break;
                        case 0x66: sb.Append('\f'); i += 2; break;
                        case 0x6e: sb.Append('\n'); i += 2; break;
                        case 0x72: sb.Append('\r'); i += 2; break;
                        case 0x74: sb.Append('\t'); i += 2; break;
                        case 0x75: sb.Append((char)Hex4(i + 2)); i += 6; break;
                        default: throw new JsonException2("bad escape");
                    }
                    start = i;
                    continue;
                }
                if (c < 0x20) throw new JsonException2("control character in string");
                if (c >= 0x80) nonAscii = true;
                i++;
            }
        }

        private JNum ReadNumber()
        {
            int s = i;
            if (At(i) == 0x2d) i++;
            if (At(i) == 0x30) i++;
            else if (At(i) >= 0x31 && At(i) <= 0x39)
            {
                while (i < n && b[i] >= 0x30 && b[i] <= 0x39) i++;
            }
            else throw new JsonException2("bad number");
            if (At(i) == 0x2e)
            {
                i++;
                int f = i;
                while (i < n && b[i] >= 0x30 && b[i] <= 0x39) i++;
                if (i == f) throw new JsonException2("bad fraction");
            }
            if (At(i) == 0x65 || At(i) == 0x45)
            {
                i++;
                if (At(i) == 0x2b || At(i) == 0x2d) i++;
                int f = i;
                while (i < n && b[i] >= 0x30 && b[i] <= 0x39) i++;
                if (i == f) throw new JsonException2("bad exponent");
            }
            return new JNum(Encoding.Latin1.GetString(b, s, i - s));
        }

        private JNode Literal(string word, JNode node)
        {
            for (int j = 0; j < word.Length; j++)
            {
                if (At(i + j) != word[j]) throw new JsonException2("bad literal");
            }
            i += word.Length;
            return node;
        }

        private JStr ReadKey()
        {
            if (At(i) != 0x22) throw new JsonException2("expected key");
            JStr k = ReadString();
            Ws();
            if (At(i) != 0x3a) throw new JsonException2("expected colon");
            i++;
            Ws();
            return k;
        }

        public JNode ParseDocument()
        {
            if (n >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf) throw new JsonException2("bom");
            var stack = new List<Frame>();
            Ws();
            for (;;)
            {
                JNode v;
                int c = At(i);
                if (c == 0x7b)
                {
                    i++;
                    Ws();
                    var o = new JObj();
                    if (At(i) == 0x7d) { i++; v = o; }
                    else
                    {
                        stack.Add(new Frame { Node = o, Key = ReadKey() });
                        continue;
                    }
                }
                else if (c == 0x5b)
                {
                    i++;
                    Ws();
                    var a = new JArr();
                    if (At(i) == 0x5d) { i++; v = a; }
                    else
                    {
                        stack.Add(new Frame { Node = a, Key = null });
                        continue;
                    }
                }
                else if (c == 0x22) v = ReadString();
                else if (c == 0x2d || (c >= 0x30 && c <= 0x39)) v = ReadNumber();
                else if (c == 0x74) v = Literal("true", TrueNode);
                else if (c == 0x66) v = Literal("false", FalseNode);
                else if (c == 0x6e) v = Literal("null", NullNode);
                else throw new JsonException2("unexpected character");

                // Attach v to its parent, closing containers as needed.
                for (;;)
                {
                    if (stack.Count == 0)
                    {
                        Ws();
                        if (i != n) throw new JsonException2("trailing data");
                        return v;
                    }
                    Frame f = stack[stack.Count - 1];
                    if (f.Node is JObj fo) fo.Members.Add(new KeyValuePair<JStr, JNode>(f.Key!, v));
                    else ((JArr)f.Node).Items.Add(v);
                    Ws();
                    int d = At(i);
                    if (d == 0x2c)
                    {
                        i++;
                        Ws();
                        if (f.Node is JObj) f.Key = ReadKey();
                        break;
                    }
                    if ((f.Node is JObj && d == 0x7d) || (f.Node is JArr && d == 0x5d))
                    {
                        i++;
                        stack.RemoveAt(stack.Count - 1);
                        v = f.Node;
                        continue;
                    }
                    throw new JsonException2("expected separator");
                }
            }
        }
    }
}

/// <summary>A JSON number kept as its lexeme (policy bodies, vectors).</summary>
internal sealed class Lex
{
    public readonly string Text;
    public Lex(string text) { Text = text; }
    public double ToDouble() => double.Parse(Text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture);
}

internal static class JsonNumbers
{
    public static bool IsIntLexeme(string lex)
    {
        int i = 0;
        if (lex.Length > 0 && lex[0] == '-') i = 1;
        if (i >= lex.Length) return false;
        if (lex[i] == '0') return i + 1 == lex.Length;
        if (lex[i] < '1' || lex[i] > '9') return false;
        for (int j = i + 1; j < lex.Length; j++)
        {
            if (lex[j] < '0' || lex[j] > '9') return false;
        }
        return true;
    }

    /// <summary>5.3: lexeme of at most 64 bytes and |written exponent| &lt;= 9999.</summary>
    public static bool WithinLimits(string lex)
    {
        if (lex.Length > 64) return false;
        int e = lex.IndexOf('e');
        if (e < 0) e = lex.IndexOf('E');
        if (e < 0) return true;
        int p = e + 1;
        if (p < lex.Length && (lex[p] == '+' || lex[p] == '-')) p++;
        while (p < lex.Length && lex[p] == '0') p++;
        return lex.Length - p <= 4;
    }

    /// <summary>Canonical form of a valid JSON number lexeme, computed in exact decimal arithmetic (10.2).</summary>
    public static string Canonical(string lex)
    {
        int i = 0;
        bool neg = false;
        if (lex.Length > 0 && lex[0] == '-') { neg = true; i = 1; }
        int j = i;
        while (j < lex.Length && lex[j] >= '0' && lex[j] <= '9') j++;
        string intp = lex.Substring(i, j - i);
        string frac = "";
        if (j < lex.Length && lex[j] == '.')
        {
            int k = j + 1;
            while (k < lex.Length && lex[k] >= '0' && lex[k] <= '9') k++;
            frac = lex.Substring(j + 1, k - j - 1);
            j = k;
        }
        long exp = 0;
        if (j < lex.Length && (lex[j] == 'e' || lex[j] == 'E'))
        {
            int p = j + 1;
            bool eneg = false;
            if (p < lex.Length && (lex[p] == '+' || lex[p] == '-')) { eneg = lex[p] == '-'; p++; }
            for (; p < lex.Length; p++)
            {
                exp = exp * 10 + (lex[p] - '0');
                if (exp > 1_000_000_000L) exp = 1_000_000_000L; // clamp, callers bound the exponent
            }
            if (eneg) exp = -exp;
        }
        string digits = intp + frac;
        exp -= frac.Length;
        int s = 0;
        while (s < digits.Length && digits[s] == '0') s++;
        digits = digits.Substring(s);
        int t = digits.Length;
        while (t > 0 && digits[t - 1] == '0') t--;
        exp += digits.Length - t;
        digits = digits.Substring(0, t);
        if (digits.Length == 0) return "0";
        int nd = digits.Length;
        long e = exp + nd;
        string outp;
        if (e > -6 && e <= 21)
        {
            if (e <= 0) outp = "0." + new string('0', (int)-e) + digits;
            else if (e >= nd) outp = digits + new string('0', (int)(e - nd));
            else outp = digits.Substring(0, (int)e) + "." + digits.Substring((int)e);
        }
        else
        {
            long k = e - 1;
            outp = digits[0] + (nd > 1 ? "." + digits.Substring(1) : "") + "e" + (k >= 0 ? "+" : "-") + Math.Abs(k).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        return (neg ? "-" : "") + outp;
    }
}

/// <summary>A number already in canonical form (output tree).</summary>
internal sealed class CNum
{
    public readonly string Canon;
    public CNum(string canon) { Canon = canon; }
}

/// <summary>
/// The tt-cjson writer (10.1). Values of the output tree: string, bool, null, <see cref="CNum"/>,
/// <c>List&lt;object?&gt;</c> and <c>Dictionary&lt;string, object?&gt;</c> (a map; keys are sorted by bytes on output).
/// </summary>
internal static class Canonical
{
    public static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char ch in s)
        {
            if (ch == '"') sb.Append("\\\"");
            else if (ch == '\\') sb.Append("\\\\");
            else if (ch < 0x20 || ch >= 0x7f)
            {
                sb.Append("\\u");
                sb.Append(((int)ch).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
            }
            else sb.Append(ch);
        }
        sb.Append('"');
    }

    public static string WriteString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        WriteString(sb, s);
        return sb.ToString();
    }

    public static string Write(object? v)
    {
        var sb = new StringBuilder();
        Write(sb, v);
        return sb.ToString();
    }

    public static void Write(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); return;
            case string s: WriteString(sb, s); return;
            case bool b: sb.Append(b ? "true" : "false"); return;
            case CNum n: sb.Append(n.Canon); return;
            case List<object?> list:
                sb.Append('[');
                for (int i = 0; i < list.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Write(sb, list[i]);
                }
                sb.Append(']');
                return;
            case Dictionary<string, object?> map:
                {
                    var keys = new List<string>(map.Keys);
                    keys.Sort(Utf8Util.CmpUtf8);
                    sb.Append('{');
                    for (int i = 0; i < keys.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        WriteString(sb, keys[i]);
                        sb.Append(':');
                        Write(sb, map[keys[i]]);
                    }
                    sb.Append('}');
                    return;
                }
            default:
                throw new InvalidOperationException("unsupported output value");
        }
    }

    /// <summary>tt-cjson object from already serialized members (keys sorted by bytes).</summary>
    public static string Compose(Dictionary<string, string> parts)
    {
        var keys = new List<string>(parts.Keys);
        keys.Sort(Utf8Util.CmpUtf8);
        var sb = new StringBuilder();
        sb.Append('{');
        for (int i = 0; i < keys.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteString(sb, keys[i]);
            sb.Append(':');
            sb.Append(parts[keys[i]]);
        }
        sb.Append('}');
        return sb.ToString();
    }
}

/// <summary>Plain trees of parsed documents (policy bodies, vectors): string, bool, null, <see cref="Lex"/>, <c>List&lt;object?&gt;</c>, <c>Dictionary&lt;string, object?&gt;</c>.</summary>
internal static class Plain
{
    /// <summary>Converts a parsed document to plain values; with <paramref name="strict"/> rejects duplicate keys and lone surrogates (fail closed).</summary>
    public static object? From(JNode node, bool strict)
    {
        switch (node)
        {
            case JNull: return null;
            case JBool b: return b.V;
            case JNum n: return new Lex(n.Lex);
            case JStr s:
                if (strict && s.Bad) throw new JsonException2("lone surrogate");
                return s.S;
            case JArr a:
                {
                    var l = new List<object?>(a.Items.Count);
                    foreach (var x in a.Items) l.Add(From(x, strict));
                    return l;
                }
            case JObj o:
                {
                    var d = new Dictionary<string, object?>(StringComparer.Ordinal);
                    foreach (var kv in o.Members)
                    {
                        if (strict && (kv.Key.Bad || d.ContainsKey(kv.Key.S))) throw new JsonException2("duplicate or invalid key");
                        d[kv.Key.S] = From(kv.Value, strict);
                    }
                    return d;
                }
            default:
                throw new InvalidOperationException();
        }
    }

    public static Dictionary<string, object?>? Obj(object? v) => v as Dictionary<string, object?>;
    public static List<object?> Arr(object? v) => v as List<object?> ?? new List<object?>();
    public static string Str(object? v, string d) => v is string s ? s : d;
    public static double Num(object? v, double d)
    {
        if (v is Lex l)
        {
            double n = l.ToDouble();
            return double.IsFinite(n) ? n : d;
        }
        return d;
    }
}
