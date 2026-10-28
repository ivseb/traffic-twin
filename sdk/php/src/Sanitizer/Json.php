<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Strict RFC 8259 JSON parser that keeps number lexemes (sanitizer.md 9.2), the tt-cjson
 * canonical writer (10.1) and the canonical number form (10.2).
 *
 * json_decode() cannot be used: it loses lexemes (1.50, 1E3, 15e-1), turns big integers into
 * floats and drops duplicate keys. The parser is iterative (no recursion), validates the
 * whole input, rejects a leading BOM, invalid UTF-8 and control characters in strings.
 * Lone surrogates produced by \u escapes are allowed syntactically and flagged on the string
 * node (`bad`), as 9.2 requires.
 */
final class Json
{
    private const STR_STOP = "\"\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    /**
     * @param int $maxDepth containers nested deeper than this are validated but not built (JDeep)
     * @throws JsonError on any deviation from RFC 8259
     */
    public static function parse(string $buf, int $maxDepth = PHP_INT_MAX): object
    {
        $n = strlen($buf);
        if ($n >= 3 && $buf[0] === "\xEF" && $buf[1] === "\xBB" && $buf[2] === "\xBF") {
            throw new JsonError('bom');
        }
        if (!Utf8::valid($buf)) {
            throw new JsonError('invalid utf-8');
        }
        $i = 0;
        /** @var list<JObj|JArr|JDeep> $nodes */
        $nodes = [];
        /** @var list<bool> $isObj */
        $isObj = [];
        /** @var list<?JStr> $keys */
        $keys = [];
        $i += strspn($buf, " \t\n\r", $i);
        for (;;) {
            $c = $buf[$i] ?? '';
            if ($c === '{') {
                $i++;
                $i += strspn($buf, " \t\n\r", $i);
                $o = count($nodes) >= $maxDepth ? JDeep::get() : new JObj();
                if (($buf[$i] ?? '') === '}') {
                    $i++;
                    $v = $o;
                } else {
                    $nodes[] = $o;
                    $isObj[] = true;
                    $keys[] = self::readKey($buf, $i);
                    continue;
                }
            } elseif ($c === '[') {
                $i++;
                $i += strspn($buf, " \t\n\r", $i);
                $a = count($nodes) >= $maxDepth ? JDeep::get() : new JArr();
                if (($buf[$i] ?? '') === ']') {
                    $i++;
                    $v = $a;
                } else {
                    $nodes[] = $a;
                    $isObj[] = false;
                    $keys[] = null;
                    continue;
                }
            } elseif ($c === '"') {
                $v = self::readString($buf, $i, $n);
            } elseif ($c === '-' || ($c >= '0' && $c <= '9' && $c !== '')) {
                $v = self::readNumber($buf, $i);
            } elseif ($c === 't') {
                $v = self::literal($buf, $i, 'true', JBool::of(true));
            } elseif ($c === 'f') {
                $v = self::literal($buf, $i, 'false', JBool::of(false));
            } elseif ($c === 'n') {
                $v = self::literal($buf, $i, 'null', JNull::get());
            } else {
                throw new JsonError('unexpected character');
            }
            // Attach $v to its parent, closing containers as needed.
            for (;;) {
                $top = count($nodes) - 1;
                if ($top < 0) {
                    $i += strspn($buf, " \t\n\r", $i);
                    if ($i !== $n) {
                        throw new JsonError('trailing data');
                    }
                    return $v;
                }
                $f = $nodes[$top];
                if ($f instanceof JObj) {
                    $f->m[] = [$keys[$top], $v];
                } elseif ($f instanceof JArr) {
                    $f->a[] = $v;
                }
                $i += strspn($buf, " \t\n\r", $i);
                $d = $buf[$i] ?? '';
                if ($d === ',') {
                    $i++;
                    $i += strspn($buf, " \t\n\r", $i);
                    if ($isObj[$top]) {
                        $keys[$top] = self::readKey($buf, $i);
                    }
                    break;
                }
                if (($isObj[$top] && $d === '}') || (!$isObj[$top] && $d === ']')) {
                    $i++;
                    array_pop($nodes);
                    array_pop($isObj);
                    array_pop($keys);
                    $v = $f;
                    continue;
                }
                throw new JsonError('expected separator');
            }
        }
    }

    private static function readKey(string $buf, int &$i): JStr
    {
        if (($buf[$i] ?? '') !== '"') {
            throw new JsonError('expected key');
        }
        $k = self::readString($buf, $i, strlen($buf));
        $i += strspn($buf, " \t\n\r", $i);
        if (($buf[$i] ?? '') !== ':') {
            throw new JsonError('expected colon');
        }
        $i++;
        $i += strspn($buf, " \t\n\r", $i);
        return $k;
    }

    private static function hex4(string $buf, int $i): int
    {
        $h = substr($buf, $i, 4);
        if (strlen($h) !== 4 || strspn($h, '0123456789abcdefABCDEF') !== 4) {
            throw new JsonError('bad hex escape');
        }
        return (int) hexdec($h);
    }

    private static function readString(string $buf, int &$i, int $n): JStr
    {
        $i++; // opening quote
        $out = '';
        $bad = false;
        for (;;) {
            $j = $i + strcspn($buf, self::STR_STOP, $i);
            if ($j >= $n) {
                throw new JsonError('unterminated string');
            }
            $c = $buf[$j];
            if ($j > $i) {
                $out .= substr($buf, $i, $j - $i);
            }
            if ($c === '"') {
                $i = $j + 1;
                return new JStr($out, $bad);
            }
            if ($c !== '\\') {
                throw new JsonError('control character in string');
            }
            $e = $buf[$j + 1] ?? '';
            switch ($e) {
                case '"': $out .= '"'; $i = $j + 2; break;
                case '\\': $out .= '\\'; $i = $j + 2; break;
                case '/': $out .= '/'; $i = $j + 2; break;
                case 'b': $out .= "\x08"; $i = $j + 2; break;
                case 'f': $out .= "\x0c"; $i = $j + 2; break;
                case 'n': $out .= "\n"; $i = $j + 2; break;
                case 'r': $out .= "\r"; $i = $j + 2; break;
                case 't': $out .= "\t"; $i = $j + 2; break;
                case 'u':
                    $cp = self::hex4($buf, $j + 2);
                    $i = $j + 6;
                    if ($cp >= 0xD800 && $cp <= 0xDBFF && ($buf[$i] ?? '') === '\\' && ($buf[$i + 1] ?? '') === 'u') {
                        $lo = self::hex4($buf, $i + 2);
                        if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                            $cp = 0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00);
                            $i += 6;
                        }
                    }
                    if ($cp >= 0xD800 && $cp <= 0xDFFF) {
                        $bad = true;
                    }
                    $out .= Utf8::fromCodePoint($cp);
                    break;
                default:
                    throw new JsonError('bad escape');
            }
        }
    }

    private static function readNumber(string $buf, int &$i): JNum
    {
        $s = $i;
        if (($buf[$i] ?? '') === '-') {
            $i++;
        }
        $c = $buf[$i] ?? '';
        if ($c === '0') {
            $i++;
        } elseif ($c >= '1' && $c <= '9' && $c !== '') {
            $i += strspn($buf, '0123456789', $i);
        } else {
            throw new JsonError('bad number');
        }
        if (($buf[$i] ?? '') === '.') {
            $i++;
            $f = strspn($buf, '0123456789', $i);
            if ($f === 0) {
                throw new JsonError('bad fraction');
            }
            $i += $f;
        }
        $c = $buf[$i] ?? '';
        if ($c === 'e' || $c === 'E') {
            $i++;
            $c = $buf[$i] ?? '';
            if ($c === '+' || $c === '-') {
                $i++;
            }
            $f = strspn($buf, '0123456789', $i);
            if ($f === 0) {
                throw new JsonError('bad exponent');
            }
            $i += $f;
        }
        return new JNum(substr($buf, $s, $i - $s));
    }

    private static function literal(string $buf, int &$i, string $word, object $node): object
    {
        if (substr($buf, $i, strlen($word)) !== $word) {
            throw new JsonError('bad literal');
        }
        $i += strlen($word);
        return $node;
    }

    // -----------------------------------------------------------------------------
    // Canonical numbers (10.2)

    public static function isIntLexeme(string $lex): bool
    {
        return preg_match('/^-?(0|[1-9][0-9]*)$/D', $lex) === 1;
    }

    /** 5.3: lexeme of at most 64 bytes and |written exponent| <= 9999. */
    public static function lexemeWithinLimits(string $lex): bool
    {
        if (strlen($lex) > 64) {
            return false;
        }
        $e = strpos($lex, 'e');
        if ($e === false) {
            $e = strpos($lex, 'E');
        }
        if ($e === false) {
            return true;
        }
        $d = substr($lex, $e + 1);
        if ($d !== '' && ($d[0] === '+' || $d[0] === '-')) {
            $d = substr($d, 1);
        }
        return strlen(ltrim($d, '0')) <= 4;
    }

    /** Canonical form of a valid JSON number lexeme, computed in exact decimal arithmetic. */
    public static function canonicalNumber(string $lex): string
    {
        $neg = $lex !== '' && $lex[0] === '-';
        $i = $neg ? 1 : 0;
        $j = $i + strspn($lex, '0123456789', $i);
        $intp = substr($lex, $i, $j - $i);
        $frac = '';
        if (($lex[$j] ?? '') === '.') {
            $k = $j + 1 + strspn($lex, '0123456789', $j + 1);
            $frac = substr($lex, $j + 1, $k - $j - 1);
            $j = $k;
        }
        $exp = 0;
        $c = $lex[$j] ?? '';
        if ($c === 'e' || $c === 'E') {
            $exp = (int) substr($lex, $j + 1);
        }
        $digits = $intp . $frac;
        $exp -= strlen($frac);
        $digits = ltrim($digits, '0');
        $t = rtrim($digits, '0');
        $exp += strlen($digits) - strlen($t);
        $digits = $t;
        if ($digits === '') {
            return '0';
        }
        $nd = strlen($digits);
        $e = $exp + $nd;
        if ($e > -6 && $e <= 21) {
            if ($e <= 0) {
                $out = '0.' . str_repeat('0', -$e) . $digits;
            } elseif ($e >= $nd) {
                $out = $digits . str_repeat('0', $e - $nd);
            } else {
                $out = substr($digits, 0, $e) . '.' . substr($digits, $e);
            }
        } else {
            $k = $e - 1;
            $out = $digits[0] . ($nd > 1 ? '.' . substr($digits, 1) : '') . 'e' . ($k >= 0 ? '+' : '-') . abs($k);
        }
        return ($neg ? '-' : '') . $out;
    }

    // -----------------------------------------------------------------------------
    // tt-cjson writer (10.1)

    /**
     * @param string|bool|null|CNum|Obj|list<mixed> $v
     */
    public static function write(mixed $v): string
    {
        if (is_string($v)) {
            return self::writeString($v);
        }
        if ($v === null) {
            return 'null';
        }
        if ($v === true) {
            return 'true';
        }
        if ($v === false) {
            return 'false';
        }
        if ($v instanceof CNum) {
            return $v->canon;
        }
        if (is_array($v)) {
            $out = '[';
            $first = true;
            foreach ($v as $x) {
                $out .= ($first ? '' : ',') . self::write($x);
                $first = false;
            }
            return $out . ']';
        }
        if ($v instanceof Obj) {
            $m = $v->m;
            ksort($m, SORT_STRING);
            $out = '{';
            $first = true;
            foreach ($m as $k => $x) {
                $out .= ($first ? '' : ',') . self::writeString((string) $k) . ':' . self::write($x);
                $first = false;
            }
            return $out . '}';
        }
        throw new \LogicException('unwritable value');
    }

    public static function writeString(string $s): string
    {
        if (preg_match('/[\x00-\x1f"\\\\\x7f-\xff]/', $s) !== 1) {
            return '"' . $s . '"';
        }
        $out = '"';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = ord($s[$i]);
            if ($c === 0x22) {
                $out .= '\\"';
            } elseif ($c === 0x5C) {
                $out .= '\\\\';
            } elseif ($c < 0x20 || $c === 0x7F) {
                $out .= sprintf('\\u%04x', $c);
            } elseif ($c < 0x80) {
                $out .= $s[$i];
            } else {
                if ($c >= 0xF0) {
                    $cp = (($c & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3F) << 12) | ((ord($s[$i + 2]) & 0x3F) << 6) | (ord($s[$i + 3]) & 0x3F);
                    $i += 3;
                } elseif ($c >= 0xE0) {
                    $cp = (($c & 0x0F) << 12) | ((ord($s[$i + 1]) & 0x3F) << 6) | (ord($s[$i + 2]) & 0x3F);
                    $i += 2;
                } else {
                    $cp = (($c & 0x1F) << 6) | (ord($s[$i + 1]) & 0x3F);
                    $i += 1;
                }
                if ($cp > 0xFFFF) {
                    $cp -= 0x10000;
                    $out .= sprintf('\\u%04x\\u%04x', 0xD800 + ($cp >> 10), 0xDC00 + ($cp & 0x3FF));
                } else {
                    $out .= sprintf('\\u%04x', $cp);
                }
            }
        }
        return $out . '"';
    }

    /**
     * Converts a parsed document to an output tree (numbers canonicalized, objects as Obj). Used to
     * build canonical documents such as policy bodies in tests and tooling.
     */
    public static function toOut(object $node): mixed
    {
        if ($node instanceof JNull) {
            return null;
        }
        if ($node instanceof JBool) {
            return $node->v;
        }
        if ($node instanceof JNum) {
            return new CNum(self::canonicalNumber($node->lex));
        }
        if ($node instanceof JStr) {
            return $node->s;
        }
        if ($node instanceof JArr) {
            return array_map(static fn (object $x): mixed => self::toOut($x), $node->a);
        }
        if ($node instanceof JObj) {
            $o = [];
            foreach ($node->m as [$k, $v]) {
                $o[$k->s] = self::toOut($v);
            }
            return new Obj($o);
        }
        throw new JsonError('too deep');
    }

    /**
     * Converts a parsed document to plain values: PObj for objects, lists, Lex for numbers.
     * With $strict, duplicate keys and lone surrogates are rejected (policy bodies and
     * envelopes: fail closed).
     */
    public static function toPlain(object $node, bool $strict): mixed
    {
        // Iterative would be nicer; policy documents are shallow and validated by size.
        if ($node instanceof JNull) {
            return null;
        }
        if ($node instanceof JBool) {
            return $node->v;
        }
        if ($node instanceof JNum) {
            return new Lex($node->lex);
        }
        if ($node instanceof JStr) {
            if ($strict && $node->bad) {
                throw new JsonError('lone surrogate');
            }
            return $node->s;
        }
        if ($node instanceof JArr) {
            $r = [];
            foreach ($node->a as $x) {
                $r[] = self::toPlain($x, $strict);
            }
            return $r;
        }
        if ($node instanceof JObj) {
            $o = [];
            foreach ($node->m as [$k, $v]) {
                if ($strict && ($k->bad || array_key_exists($k->s, $o))) {
                    throw new JsonError('duplicate or invalid key');
                }
                $o[$k->s] = self::toPlain($v, $strict);
            }
            return new PObj($o);
        }
        throw new JsonError('too deep');
    }
}
