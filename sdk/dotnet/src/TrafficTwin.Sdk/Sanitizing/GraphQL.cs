using System.Collections.Generic;
using System.Text;

namespace TrafficTwin.Sdk.Sanitizing;

/// <summary>
/// Shape of a GraphQL executable document (sanitizer.md 5.7, spec v1.14), a step-by-step port of the reference
/// (internal/graphql: lex.go, parse.go, shape.go). Names are kept, every literal value becomes a placeholder, so no value
/// written inline in a query ever leaves the source. The input is a .NET string (UTF-16): every byte the reference
/// accepts outside strings and comments is ASCII, the BOM is U+FEFF, and the shape is ASCII (its length in chars is
/// its length in bytes).
/// </summary>
internal static class GraphQL
{
    /// <summary>Largest number of open brackets (<c>{</c>, <c>(</c> and <c>[</c> together).</summary>
    public const int MaxNesting = 64;
    /// <summary>Largest shape; a longer one is not emitted.</summary>
    public const int MaxShapeBytes = 32768;
    /// <summary>Longest name emitted as written.</summary>
    public const int MaxNameBytes = 64;
    /// <summary>Array limit of a response body when the introspection gate is open (5.7.2).</summary>
    public const int IntrospectionMaxArray = 4096;

    private enum TokKind { Punct, Name, Int, Float, String }

    private sealed class Token
    {
        public TokKind Kind;
        public string S = "";
        /// <summary>A name in value position (enum, true, false, null): the shape writes a placeholder.</summary>
        public bool Value;
    }

    /// <summary>Kind, alias and name of a root selection (all the introspection gate needs).</summary>
    private readonly record struct RootSel(bool Field, bool Aliased, string Name);

    /// <summary>Not an executable document (unwinds the recursive descent; caught in <see cref="Shape"/>).</summary>
    private sealed class SyntaxError : System.Exception
    {
    }

    private static bool IsNameStart(char c) => c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    private static bool IsNameCont(char c) => IsNameStart(c) || (c >= '0' && c <= '9');
    private static bool IsDigit(char c) => c >= '0' && c <= '9';
    private static bool IsHexDigit(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    private static bool IsWordChar(char c) => IsNameCont(c) || c == '?' || c == '*';

    /// <summary>
    /// The shape of <paramref name="src"/> (without the <c>gql:</c> prefix) and whether every operation selects only
    /// <c>__schema</c>, <c>__type</c> and <c>__typename</c> at its root without aliases; null when src is not an
    /// executable document within the limits (the caller emits the drop form).
    /// </summary>
    public static (string Shape, bool Introspection)? Shape(string src)
    {
        List<Token>? toks = Lex(src);
        if (toks == null) return null;
        bool intro;
        try { intro = new Parser(toks).Document(); }
        catch (SyntaxError) { return null; }
        var sb = new StringBuilder();
        bool prevWord = false;
        foreach (Token t in toks)
        {
            string o = t.Kind switch
            {
                TokKind.Punct => t.S,
                TokKind.Name when t.Value => t.S switch { "true" or "false" => "?b", "null" => "?n", _ => "?e" },
                TokKind.Name => SafeName(t.S),
                TokKind.Int => "?i",
                TokKind.Float => "?f",
                _ => "?s",
            };
            if (prevWord && IsWordChar(o[0])) sb.Append(' ');
            sb.Append(o);
            prevWord = IsWordChar(o[o.Length - 1]);
            if (sb.Length > MaxShapeBytes) return null;
        }
        return (sb.ToString(), intro);
    }

    /// <summary>The name when it may leave a source as written, <c>*</c> otherwise.</summary>
    public static string SafeName(string name) => NameSafe(name) ? name : "*";

    /// <summary>Name rule of 5.7.1: at most 64 bytes, not 16 or more hexadecimal digits only, no six consecutive digits.</summary>
    public static bool NameSafe(string name)
    {
        if (name.Length == 0 || name.Length > MaxNameBytes || !IsNameStart(name[0])) return false;
        bool allHex = name.Length >= 16;
        int run = 0;
        foreach (char c in name)
        {
            if (!IsNameCont(c)) return false;
            if (!IsHexDigit(c)) allHex = false;
            if (IsDigit(c))
            {
                if (++run >= 6) return false;
            }
            else run = 0;
        }
        return !allHex;
    }

    /// <summary>True when s is a GraphQL name (any length).</summary>
    public static bool IsName(string s)
    {
        if (s.Length == 0 || !IsNameStart(s[0])) return false;
        for (int i = 1; i < s.Length; i++)
        {
            if (!IsNameCont(s[i])) return false;
        }
        return true;
    }

    // --- lexing ---

    private static List<Token>? Lex(string src)
    {
        var toks = new List<Token>();
        int open = 0, i = 0, n = src.Length;
        while (i < n)
        {
            char c = src[i];
            switch (c)
            {
                case ' ' or '\t' or '\n' or '\r' or ',' or '﻿':
                    i++;
                    continue;
                case '#':
                    while (i < n && src[i] != '\n' && src[i] != '\r') i++;
                    continue;
                case '!' or '$' or '&' or ':' or '=' or '@' or '|':
                    toks.Add(new Token { Kind = TokKind.Punct, S = c.ToString() });
                    i++;
                    continue;
                case '(' or '[' or '{':
                    if (++open > MaxNesting) return null;
                    toks.Add(new Token { Kind = TokKind.Punct, S = c.ToString() });
                    i++;
                    continue;
                case ')' or ']' or '}':
                    if (--open < 0) return null;
                    toks.Add(new Token { Kind = TokKind.Punct, S = c.ToString() });
                    i++;
                    continue;
                case '.':
                    if (i + 2 < n && src[i + 1] == '.' && src[i + 2] == '.')
                    {
                        toks.Add(new Token { Kind = TokKind.Punct, S = "..." });
                        i += 3;
                        continue;
                    }
                    return null;
                case '"':
                    {
                        int j = LexString(src, i);
                        if (j < 0) return null;
                        toks.Add(new Token { Kind = TokKind.String });
                        i = j;
                        continue;
                    }
            }
            if (IsNameStart(c))
            {
                int j = i + 1;
                while (j < n && IsNameCont(src[j])) j++;
                toks.Add(new Token { Kind = TokKind.Name, S = src.Substring(i, j - i) });
                i = j;
                continue;
            }
            if (c == '-' || IsDigit(c))
            {
                int j = LexNumber(src, i, out bool isFloat);
                if (j < 0) return null;
                toks.Add(new Token { Kind = isFloat ? TokKind.Float : TokKind.Int });
                i = j;
                continue;
            }
            return null;
        }
        return open == 0 ? toks : null;
    }

    /// <summary>An IntValue or FloatValue starting at i: the index after it, or -1.</summary>
    private static int LexNumber(string src, int i, out bool isFloat)
    {
        isFloat = false;
        int n = src.Length, j = i;
        if (src[j] == '-') j++;
        if (j >= n || !IsDigit(src[j])) return -1;
        if (src[j] == '0')
        {
            j++;
            if (j < n && IsDigit(src[j])) return -1; // leading zero
        }
        else
        {
            while (j < n && IsDigit(src[j])) j++;
        }
        if (j < n && src[j] == '.')
        {
            j++;
            if (j >= n || !IsDigit(src[j])) return -1;
            while (j < n && IsDigit(src[j])) j++;
            isFloat = true;
        }
        if (j < n && (src[j] == 'e' || src[j] == 'E'))
        {
            j++;
            if (j < n && (src[j] == '+' || src[j] == '-')) j++;
            if (j >= n || !IsDigit(src[j])) return -1;
            while (j < n && IsDigit(src[j])) j++;
            isFloat = true;
        }
        // A number is not followed by '.' or a NameStart (digits were consumed above).
        if (j < n && (src[j] == '.' || IsNameStart(src[j]))) return -1;
        return j;
    }

    /// <summary>A string or block string starting at the quote at i: the index after its end, or -1.</summary>
    private static int LexString(string src, int i)
    {
        int n = src.Length, j;
        if (i + 2 < n && src[i + 1] == '"' && src[i + 2] == '"')
        {
            // Block string: ends at the first """ not escaped as \""".
            j = i + 3;
            while (j < n)
            {
                char c = src[j];
                if (c == '\\' && j + 3 < n && src[j + 1] == '"' && src[j + 2] == '"' && src[j + 3] == '"') j += 4;
                else if (c == '"' && j + 2 < n && src[j + 1] == '"' && src[j + 2] == '"') return j + 3;
                else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return -1;
                else j++;
            }
            return -1;
        }
        j = i + 1;
        while (j < n)
        {
            char c = src[j];
            if (c == '"') return j + 1;
            if (c == '\\')
            {
                if (j + 1 >= n) return -1;
                switch (src[j + 1])
                {
                    case '"' or '\\' or '/' or 'b' or 'f' or 'n' or 'r' or 't':
                        j += 2;
                        break;
                    case 'u':
                        if (j + 5 >= n || !IsHexDigit(src[j + 2]) || !IsHexDigit(src[j + 3]) || !IsHexDigit(src[j + 4]) || !IsHexDigit(src[j + 5])) return -1;
                        j += 6;
                        break;
                    default:
                        return -1;
                }
                continue;
            }
            if (c < 0x20 && c != '\t') return -1; // line terminators and control characters
            j++;
        }
        return -1;
    }

    // --- parsing (only what the shape and the gate need: names in value position, root selections) ---

    private sealed class Parser
    {
        private readonly List<Token> toks;
        private int pos;

        public Parser(List<Token> toks) => this.toks = toks;

        private Token? Peek() => pos < toks.Count ? toks[pos] : null;

        private bool IsPunct(string s)
        {
            Token? t = Peek();
            return t != null && t.Kind == TokKind.Punct && t.S == s;
        }

        private bool IsName() => Peek() is { Kind: TokKind.Name };

        private void Expect(string s)
        {
            if (!IsPunct(s)) throw new SyntaxError();
            pos++;
        }

        private string Name()
        {
            if (!IsName()) throw new SyntaxError();
            return toks[pos++].S;
        }

        /// <summary>Parses the document; returns the introspection condition of 5.7.2.</summary>
        public bool Document()
        {
            if (toks.Count == 0) throw new SyntaxError();
            bool intro = true;
            int ops = 0;
            while (pos < toks.Count)
            {
                Token t = toks[pos];
                List<RootSel> root;
                if (t.Kind == TokKind.Punct && t.S == "{") root = SelectionSet();
                else if (t.Kind == TokKind.Name && t.S is "query" or "mutation" or "subscription") root = Operation();
                else if (t.Kind == TokKind.Name && t.S == "fragment")
                {
                    Fragment();
                    continue;
                }
                else throw new SyntaxError();
                ops++;
                foreach (RootSel s in root)
                {
                    if (!s.Field || s.Aliased || s.Name is not ("__schema" or "__type" or "__typename")) intro = false;
                }
            }
            return intro && ops > 0;
        }

        private List<RootSel> Operation()
        {
            pos++; // operation type
            if (IsName()) pos++;
            if (IsPunct("("))
            {
                pos++;
                int vars = 0;
                while (true)
                {
                    if (IsPunct(")"))
                    {
                        if (vars == 0) throw new SyntaxError();
                        pos++;
                        break;
                    }
                    VarDef();
                    vars++;
                }
            }
            Directives();
            return SelectionSet();
        }

        private void VarDef()
        {
            Expect("$");
            Name();
            Expect(":");
            TypeRef();
            if (IsPunct("="))
            {
                pos++;
                Value();
            }
            Directives(); // accepted and ignored
        }

        private void TypeRef()
        {
            if (IsPunct("["))
            {
                pos++;
                TypeRef();
                Expect("]");
            }
            else Name();
            if (IsPunct("!")) pos++;
        }

        private void Fragment()
        {
            pos++; // fragment
            if (Name() == "on") throw new SyntaxError();
            if (!IsName() || toks[pos].S != "on") throw new SyntaxError();
            pos++;
            Name();
            Directives();
            SelectionSet();
        }

        private List<RootSel> SelectionSet()
        {
            Expect("{");
            var res = new List<RootSel>();
            while (true)
            {
                if (IsPunct("}"))
                {
                    if (res.Count == 0) throw new SyntaxError();
                    pos++;
                    return res;
                }
                res.Add(Selection());
            }
        }

        private RootSel Selection()
        {
            if (IsPunct("..."))
            {
                pos++;
                if (IsName() && toks[pos].S != "on")
                {
                    string spread = toks[pos++].S;
                    Directives();
                    return new RootSel(false, false, spread);
                }
                if (IsName()) // "on"
                {
                    pos++;
                    Name();
                }
                Directives();
                SelectionSet();
                return new RootSel(false, false, "");
            }
            string name = Name();
            bool aliased = false;
            if (IsPunct(":"))
            {
                pos++;
                aliased = true;
                name = Name();
            }
            if (IsPunct("(")) Arguments();
            Directives();
            if (IsPunct("{")) SelectionSet();
            return new RootSel(true, aliased, name);
        }

        private void Arguments()
        {
            Expect("(");
            int count = 0;
            while (true)
            {
                if (IsPunct(")"))
                {
                    if (count == 0) throw new SyntaxError();
                    pos++;
                    return;
                }
                Name();
                Expect(":");
                Value();
                count++;
            }
        }

        private void Directives()
        {
            while (IsPunct("@"))
            {
                pos++;
                Name();
                if (IsPunct("(")) Arguments();
            }
        }

        private void Value()
        {
            Token t = Peek() ?? throw new SyntaxError();
            switch (t.Kind)
            {
                case TokKind.Punct:
                    switch (t.S)
                    {
                        case "$":
                            pos++;
                            Name();
                            return;
                        case "[":
                            pos++;
                            while (!IsPunct("]")) Value();
                            pos++;
                            return;
                        case "{":
                            pos++;
                            while (!IsPunct("}"))
                            {
                                Name();
                                Expect(":");
                                Value();
                            }
                            pos++;
                            return;
                    }
                    throw new SyntaxError();
                case TokKind.Name:
                    t.Value = true;
                    pos++;
                    return;
                default:
                    pos++;
                    return;
            }
        }
    }
}
