<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * The strict XML subset of sanitizer.md 22.2 points 1-6 (spec v1.19), written by hand on the
 * body bytes: no generic XML parser (ext-xml, SimpleXML, DOM, XMLReader) is ever used, so no
 * DTD, external entity or entity expansion can be read (hardening.md 3). Mirrors
 * conformance/ref/bodies.py parse_xml().
 *
 * Works on bytes: after the UTF-8 check every delimiter is ASCII, and every byte of a non-ASCII
 * character is >= 0x80, which is a name character (point 3).
 *
 * @internal
 */
final class XmlParser
{
    public const NS_XML = 'http://www.w3.org/XML/1998/namespace';
    public const MAX_NESTING = 256;
    private const WS = " \t\n";
    private const ENTITIES = ['lt' => '<', 'gt' => '>', 'amp' => '&', 'apos' => "'", 'quot' => '"'];

    private static ?string $nameChars = null;

    private string $s;
    private int $n;

    private function __construct(string $s)
    {
        $this->s = $s;
        $this->n = strlen($s);
    }

    /** @throws BodyError for anything outside the accepted subset */
    public static function parse(string $data): XmlElem
    {
        if (str_starts_with($data, "\xEF\xBB\xBF")) {
            $data = substr($data, 3);
        }
        if (!Utf8::valid($data)) {
            throw new BodyError('not UTF-8');
        }
        // Controls other than tab, LF and CR; U+FFFE and U+FFFF (surrogates are not valid UTF-8).
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]|\xEF\xBF[\xBE\xBF]/', $data) === 1) {
            throw new BodyError('forbidden character');
        }
        return (new self(str_replace(["\r\n", "\r"], "\n", $data)))->document();
    }

    private static function nameChars(): string
    {
        if (self::$nameChars === null) {
            $c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-:';
            for ($b = 0x80; $b <= 0xFF; $b++) {
                $c .= chr($b);
            }
            self::$nameChars = $c;
        }
        return self::$nameChars;
    }

    private static function nameStart(string $c): bool
    {
        return ($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z') || $c === '_' || ord($c) >= 0x80;
    }

    private function at(int $p, string $t): bool
    {
        return substr($this->s, $p, strlen($t)) === $t;
    }

    /** @return array{0: string, 1: int} */
    private function readName(int $p): array
    {
        if ($p >= $this->n || !self::nameStart($this->s[$p])) {
            throw new BodyError('name');
        }
        $q = $p + 1 + strspn($this->s, self::nameChars(), $p + 1);
        return [substr($this->s, $p, $q - $p), $q];
    }

    private function skipWs(int $p): int
    {
        return $p >= $this->n ? $p : $p + strspn($this->s, self::WS, $p);
    }

    /** Comment or processing instruction at $p: its end, or null if none starts there. */
    private function misc(int $p): ?int
    {
        if ($this->at($p, '<!--')) {
            $e = strpos($this->s, '-->', $p + 4);
            if ($e === false) {
                throw new BodyError('unterminated comment');
            }
            return $e + 3;
        }
        if ($this->at($p, '<?')) {
            $e = strpos($this->s, '?>', $p + 2);
            if ($e === false) {
                throw new BodyError('unterminated processing instruction');
            }
            return $e + 2;
        }
        return null;
    }

    private static function xmlChar(int $cp): bool
    {
        return $cp === 0x9 || $cp === 0xA || $cp === 0xD || ($cp >= 0x20 && $cp <= 0xD7FF) || ($cp >= 0xE000 && $cp <= 0xFFFD) || ($cp >= 0x10000 && $cp <= 0x10FFFF);
    }

    /** Point 5: predefined and character references; attribute values turn literal tab and LF into spaces. */
    private static function refs(string $raw, bool $attr): string
    {
        if ($attr) {
            // A tab or LF inside a reference name makes the reference unknown either way.
            $raw = strtr($raw, "\t\n", '  ');
        }
        if (!str_contains($raw, '&')) {
            return $raw;
        }
        $out = '';
        $i = 0;
        while (($a = strpos($raw, '&', $i)) !== false) {
            $out .= substr($raw, $i, $a - $i);
            $j = strpos($raw, ';', $a + 1);
            if ($j === false) {
                throw new BodyError('unterminated reference');
            }
            $ent = substr($raw, $a + 1, $j - $a - 1);
            if (isset(self::ENTITIES[$ent])) {
                $out .= self::ENTITIES[$ent];
            } elseif (preg_match('/^#x([0-9A-Fa-f]+)$/D', $ent, $m) === 1) {
                $out .= Utf8::fromCodePoint(self::codePoint($m[1], 16));
            } elseif (preg_match('/^#([0-9]+)$/D', $ent, $m) === 1) {
                $out .= Utf8::fromCodePoint(self::codePoint($m[1], 10));
            } else {
                throw new BodyError('unknown entity');
            }
            $i = $j + 1;
        }
        return $out . substr($raw, $i);
    }

    private static function codePoint(string $digits, int $base): int
    {
        $cp = 0;
        $len = strlen($digits);
        for ($k = 0; $k < $len; $k++) {
            $cp = $cp * $base + (int) hexdec($digits[$k]);
            if ($cp > 0x10FFFF) {
                throw new BodyError('reference out of range');
            }
        }
        if (!self::xmlChar($cp)) {
            throw new BodyError('reference to a forbidden character');
        }
        return $cp;
    }

    /** @return array{0: ?string, 1: string} */
    private static function splitQname(string $q): array
    {
        $c = strpos($q, ':');
        if ($c === false) {
            return [null, $q];
        }
        $p = substr($q, 0, $c);
        $l = substr($q, $c + 1);
        if ($p === '' || $l === '' || str_contains($l, ':')) {
            throw new BodyError('qualified name');
        }
        return [$p, $l];
    }

    /**
     * Start tag at $p ("<" included).
     *
     * @param array<string, string> $parentNs
     * @return array{0: string, 1: XmlElem, 2: array<string, string>, 3: bool, 4: int}
     */
    private function startTag(int $p, array $parentNs): array
    {
        $s = $this->s;
        $n = $this->n;
        [$qname, $p] = $this->readName($p + 1);
        $rawAttrs = [];
        $seen = [];
        $empty = false;
        while (true) {
            $q = $this->skipWs($p);
            if ($this->at($q, '/>')) {
                $p = $q + 2;
                $empty = true;
                break;
            }
            if ($this->at($q, '>')) {
                $p = $q + 1;
                break;
            }
            if ($q === $p) {
                throw new BodyError('attribute without space');
            }
            [$aname, $q] = $this->readName($q);
            $q = $this->skipWs($q);
            if ($q >= $n || $s[$q] !== '=') {
                throw new BodyError('attribute without =');
            }
            $q = $this->skipWs($q + 1);
            if ($q >= $n || ($s[$q] !== '"' && $s[$q] !== "'")) {
                throw new BodyError('attribute value');
            }
            $e = strpos($s, $s[$q], $q + 1);
            if ($e === false) {
                throw new BodyError('unterminated attribute value');
            }
            $raw = substr($s, $q + 1, $e - $q - 1);
            if (str_contains($raw, '<')) {
                throw new BodyError('< in attribute value');
            }
            if (isset($seen[$aname])) {
                throw new BodyError('duplicate attribute');
            }
            $seen[$aname] = true;
            $rawAttrs[] = [$aname, self::refs($raw, true)];
            $p = $e + 1;
        }
        $nsmap = $parentNs;
        foreach ($rawAttrs as [$aname, $v]) {
            if ($aname === 'xmlns') {
                $nsmap[''] = $v;
            } elseif (str_starts_with($aname, 'xmlns:')) {
                $pre = substr($aname, 6);
                if ($pre === '' || str_contains($pre, ':')) {
                    throw new BodyError('namespace declaration');
                }
                $nsmap[$pre] = $v;
            }
        }
        [$prefix, $local] = self::splitQname($qname);
        if ($prefix === null) {
            $ns = $nsmap[''] ?? '';
        } elseif ($prefix === 'xml') {
            $ns = self::NS_XML;
        } elseif (array_key_exists($prefix, $nsmap)) {
            $ns = $nsmap[$prefix];
        } else {
            throw new BodyError('undeclared prefix');
        }
        $attrs = [];
        foreach ($rawAttrs as [$aname, $v]) {
            if ($aname === 'xmlns' || str_starts_with($aname, 'xmlns:')) {
                continue;
            }
            [$ap, $al] = self::splitQname($aname);
            if ($ap !== null && $ap !== 'xml' && !array_key_exists($ap, $nsmap)) {
                throw new BodyError('undeclared attribute prefix');
            }
            $attrs[] = [$al, $v];
        }
        return [$qname, new XmlElem($local, $ns, $attrs), $nsmap, $empty, $p];
    }

    private function document(): XmlElem
    {
        $s = $this->s;
        $n = $this->n;
        $pos = 0;
        // prolog
        while (true) {
            $pos = $this->skipWs($pos);
            if ($pos >= $n) {
                throw new BodyError('no root element');
            }
            $e = $this->misc($pos);
            if ($e !== null) {
                $pos = $e;
                continue;
            }
            if ($this->at($pos, '<!') || $s[$pos] !== '<') {
                throw new BodyError('prolog');
            }
            break;
        }
        [$qname, $root, $nsmap, $empty, $pos] = $this->startTag($pos, []);
        /** @var list<array{0: string, 1: XmlElem, 2: array<string, string>}> $stack */
        $stack = [];
        if (!$empty) {
            $stack[] = [$qname, $root, $nsmap];
        }
        while ($stack !== []) {
            if ($pos >= $n) {
                throw new BodyError('unclosed element');
            }
            [$qn, $cur, $curNs] = $stack[count($stack) - 1];
            if ($s[$pos] !== '<') {
                $e = strpos($s, '<', $pos);
                if ($e === false) {
                    throw new BodyError('unclosed element');
                }
                $cur->text .= self::refs(substr($s, $pos, $e - $pos), false);
                $pos = $e;
                continue;
            }
            if ($this->at($pos, '<![CDATA[')) {
                $e = strpos($s, ']]>', $pos + 9);
                if ($e === false) {
                    throw new BodyError('unterminated CDATA');
                }
                $cur->text .= substr($s, $pos + 9, $e - $pos - 9);
                $pos = $e + 3;
                continue;
            }
            $e = $this->misc($pos);
            if ($e !== null) {
                $pos = $e;
                continue;
            }
            if ($this->at($pos, '<!')) {
                throw new BodyError('declaration in content');
            }
            if ($this->at($pos, '</')) {
                [$name, $q] = $this->readName($pos + 2);
                $q = $this->skipWs($q);
                if ($q >= $n || $s[$q] !== '>' || $name !== $qn) {
                    throw new BodyError('end tag');
                }
                array_pop($stack);
                $pos = $q + 1;
                continue;
            }
            [$qname, $el, $nsmap, $empty, $pos] = $this->startTag($pos, $curNs);
            $cur->children[] = $el;
            if (!$empty) {
                if (count($stack) >= self::MAX_NESTING) {
                    throw new BodyError('nesting');
                }
                $stack[] = [$qname, $el, $nsmap];
            }
        }
        // epilogue
        while (true) {
            $pos = $this->skipWs($pos);
            if ($pos >= $n) {
                break;
            }
            $e = $this->misc($pos);
            if ($e === null) {
                throw new BodyError('content after the root element');
            }
            $pos = $e;
        }
        return $root;
    }
}
