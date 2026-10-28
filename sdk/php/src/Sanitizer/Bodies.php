<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Body formats of spec v1.19 (sanitizer.md 22): base64 documents (22.4), media type parameters
 * (22.2 point 11, 22.3 point 1), multipart/form-data (22.3), the XML tree, namespaces and
 * SOAPAction (22.2). Pure functions on bytes; they never see the policy. Mirrors
 * conformance/ref/bodies.py.
 *
 * @internal
 */
final class Bodies
{
    public const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    public const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const DOC_MIN_CHARS = 16;
    private const NS_MAX_BYTES = 512;
    private const BOUNDARY_RE = "/^[0-9A-Za-z'()+_,.\\/:=? -]{0,69}[0-9A-Za-z'()+_,.\\/:=?-]$/D";
    private const PART_HEADER_NAME_RE = "/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/D";
    private const FILE_TYPES = ['text/plain' => 'text', 'text/csv' => 'csv', 'application/json' => 'json', 'application/xml' => 'xml', 'text/xml' => 'xml'];

    // --- documents (22.4) ----------------------------------------------------------------

    /** 22.4: document class of a decoded length. */
    public static function docClass(int $n): string
    {
        if ($n <= 1024) {
            return 'l1k';
        }
        if ($n <= 16384) {
            return 'l16k';
        }
        if ($n <= 131072) {
            return 'l128k';
        }
        if ($n <= 1048576) {
            return 'l1m';
        }
        return $n <= 8388608 ? 'l8m' : 'lmax';
    }

    /** 22.4 point 3: kind of a document from its first bytes (and, for zip, the names it holds). */
    public static function magicKind(string $b): ?string
    {
        if (str_starts_with($b, '%PDF-')) {
            return 'pdf';
        }
        if (str_starts_with($b, "\x89PNG\r\n\x1a\n")) {
            return 'png';
        }
        if (str_starts_with($b, "\xff\xd8\xff")) {
            return 'jpeg';
        }
        if (str_starts_with($b, 'GIF87a') || str_starts_with($b, 'GIF89a')) {
            return 'gif';
        }
        if (str_starts_with($b, 'RIFF') && substr($b, 8, 4) === 'WEBP') {
            return 'webp';
        }
        if (str_starts_with($b, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) {
            return 'ole';
        }
        if (str_starts_with($b, "PK\x03\x04")) {
            if (str_contains($b, 'word/document.xml')) {
                return 'docx';
            }
            if (str_contains($b, 'xl/workbook.xml')) {
                return 'xlsx';
            }
            if (str_contains($b, 'ppt/presentation.xml')) {
                return 'pptx';
            }
            return 'zip';
        }
        return null;
    }

    /** 22.4: 'drop:doc:<kind>:<class>' if the (valid UTF-8) string is the base64 of a document, else null. */
    public static function base64Doc(string $s): ?string
    {
        if (str_starts_with($s, 'data:')) {
            $i = strpos($s, ',');
            // printable ASCII without ',' (the first ',' ends the prefix), ending with ";base64"
            if ($i === false || preg_match('/^data:[\x21-\x2b\x2d-\x7e]*;base64$/D', substr($s, 0, $i)) !== 1) {
                return null;
            }
            $s = substr($s, $i + 1);
        }
        if (strlen($s) < self::DOC_MIN_CHARS || preg_match('/^[A-Za-z0-9+\/_-]*={0,2}$/D', $s) !== 1) {
            return null;
        }
        $body = rtrim($s, '=');
        if (strlen($body) !== strlen($s) && strlen($s) % 4 !== 0) {
            return null;
        }
        if (strlen($body) % 4 === 1) {
            return null;
        }
        // Non-strict decoding of an unpadded, already checked alphabet: the final padding bits are ignored.
        $raw = base64_decode(strtr($body, '-_', '+/'), false);
        if ($raw === false) {
            return null;
        }
        $kind = self::magicKind($raw);
        return $kind === null ? null : 'drop:doc:' . $kind . ':' . self::docClass(strlen($raw));
    }

    // --- media type parameters (22.2 point 11, 22.3 point 1) -------------------------------------

    /**
     * Parameters of a normalized content-type value: lowercase name => value, first occurrence wins.
     *
     * @return array<string, string>
     */
    public static function mediaParams(?string $value): array
    {
        $out = [];
        if ($value === null || !Utf8::valid($value)) {
            return $out;
        }
        $pieces = explode(';', $value);
        array_shift($pieces);
        foreach ($pieces as $piece) {
            $piece = trim($piece, " \t");
            $eq = strpos($piece, '=');
            if ($eq === false) {
                continue;
            }
            $name = Utf8::lower(trim(substr($piece, 0, $eq), " \t"));
            $v = trim(substr($piece, $eq + 1), " \t");
            if (str_starts_with($v, '"')) {
                if (strlen($v) < 2 || !str_ends_with($v, '"')) {
                    continue;
                }
                $v = substr($v, 1, -1);
            }
            if (!array_key_exists($name, $out)) {
                $out[$name] = $v;
            }
        }
        return $out;
    }

    // --- multipart (22.3) ----------------------------------------------------------------

    /**
     * 22.3 point 4: parameters of a content-disposition value (valid UTF-8).
     *
     * @return array<string, string>
     */
    private static function disposition(string $s): array
    {
        $i = strpos($s, ';');
        $kind = trim($i === false ? $s : substr($s, 0, $i), " \t");
        if (Utf8::lower($kind) !== 'form-data') {
            throw new BodyError('disposition');
        }
        $params = [];
        $n = strlen($s);
        $pos = $i === false ? $n : $i;
        while ($pos < $n) {
            $pos += strspn($s, " \t;", $pos);
            if ($pos >= $n) {
                break;
            }
            $start = $pos;
            $pos += strcspn($s, '=;', $pos);
            $name = Utf8::lower(trim(substr($s, $start, $pos - $start), " \t"));
            if ($pos >= $n || $s[$pos] === ';') {
                if (!array_key_exists($name, $params)) {
                    $params[$name] = '';
                }
                continue;
            }
            $pos++; // '='
            $pos += $pos < $n ? strspn($s, " \t", $pos) : 0;
            if ($pos < $n && $s[$pos] === '"') {
                $pos++;
                $buf = '';
                while (true) {
                    if ($pos >= $n) {
                        throw new BodyError('unterminated quoted string');
                    }
                    $c = $s[$pos];
                    if ($c === '\\' && $pos + 1 < $n) {
                        $buf .= $s[$pos + 1];
                        $pos += 2;
                        continue;
                    }
                    if ($c === '"') {
                        $pos++;
                        break;
                    }
                    $buf .= $c;
                    $pos++;
                }
                $val = $buf;
                $pos += $pos < $n ? strspn($s, " \t", $pos) : 0;
                if ($pos < $n && $s[$pos] !== ';') {
                    throw new BodyError('garbage after quoted string');
                }
            } else {
                $start = $pos;
                $pos += $pos < $n ? strcspn($s, ';', $pos) : 0;
                $val = trim(substr($s, $start, $pos - $start), " \t");
            }
            if (!array_key_exists($name, $params)) {
                $params[$name] = $val;
            }
        }
        return $params;
    }

    /**
     * 22.3 on the raw body bytes (never PHP's own multipart parsing).
     *
     * @return list<array{name: string, file: bool, content: string, ct: ?string}>
     * @throws BodyError
     */
    public static function parseMultipart(string $data, ?string $boundary): array
    {
        if ($boundary === null || preg_match(self::BOUNDARY_RE, $boundary) !== 1) {
            throw new BodyError('boundary');
        }
        $delim = '--' . $boundary;
        $crDelim = "\r\n" . $delim;
        $len = strlen($data);
        if (str_starts_with($data, $delim)) {
            $pos = 0;
        } else {
            $i = strpos($data, $crDelim);
            if ($i === false) {
                throw new BodyError('no delimiter');
            }
            $pos = $i + 2;
        }
        $parts = [];
        while (true) {
            $pos += strlen($delim);
            if (substr($data, $pos, 2) === '--') {
                break;
            }
            $pos += $pos < $len ? strspn($data, " \t", $pos) : 0;
            if (substr($data, $pos, 2) !== "\r\n") {
                throw new BodyError('delimiter line');
            }
            $pos += 2;
            $nxt = strpos($data, $crDelim, $pos);
            if ($nxt === false) {
                throw new BodyError('no close delimiter');
            }
            $parts[] = substr($data, $pos, $nxt - $pos);
            $pos = $nxt + 2;
        }
        $out = [];
        foreach ($parts as $p) {
            if (str_starts_with($p, "\r\n")) {
                $head = '';
                $content = substr($p, 2);
            } else {
                $j = strpos($p, "\r\n\r\n");
                if ($j === false) {
                    throw new BodyError('part headers');
                }
                $head = substr($p, 0, $j);
                $content = substr($p, $j + 4);
            }
            $headers = [];
            foreach ($head === '' ? [] : explode("\r\n", $head) as $line) {
                $k = strpos($line, ':');
                if ($k === false || $k === 0 || preg_match(self::PART_HEADER_NAME_RE, substr($line, 0, $k)) !== 1) {
                    throw new BodyError('part header line');
                }
                $name = Utf8::lower(substr($line, 0, $k));
                if (!array_key_exists($name, $headers)) {
                    $headers[$name] = trim(substr($line, $k + 1), " \t");
                }
            }
            $cd = $headers['content-disposition'] ?? null;
            if ($cd === null) {
                throw new BodyError('no content-disposition');
            }
            if (!Utf8::valid($cd)) {
                throw new BodyError('content-disposition not UTF-8');
            }
            $params = self::disposition($cd);
            if (!array_key_exists('name', $params)) {
                throw new BodyError('no name');
            }
            $ct = null;
            if (isset($headers['content-type']) && Utf8::valid($headers['content-type'])) {
                $ct = Utf8::lower(trim(explode(';', $headers['content-type'], 2)[0], " \t"));
            }
            $out[] = [
                'name' => (string) $params['name'],
                'file' => array_key_exists('filename', $params) || array_key_exists('filename*', $params),
                'content' => $content,
                'ct' => $ct,
            ];
        }
        return $out;
    }

    /** 22.3 point 5: drop:file:<kind>:<class> of a file part. */
    public static function fileToken(string $content, ?string $ct): string
    {
        $kind = self::magicKind($content) ?? self::FILE_TYPES[$ct ?? ''] ?? 'bin';
        return 'drop:file:' . $kind . ':' . self::docClass(strlen($content));
    }

    // --- XML (22.2) ----------------------------------------------------------------------

    /** 22.2 point 7: element -> tree value (JStr or JObj). */
    private static function xmlValue(XmlElem $el): object
    {
        if ($el->attrs === [] && $el->children === []) {
            return new JStr($el->text);
        }
        $members = [];
        $index = [];
        foreach ($el->attrs as [$local, $v]) { // same local name twice: the last wins, at its own position
            $k = '@' . $local;
            if (isset($index[$k])) {
                $members[$index[$k]] = null;
            }
            $index[$k] = count($members);
            $members[] = [new JStr($k), new JStr($v)];
        }
        $members = array_values(array_filter($members, static fn (?array $m): bool => $m !== null));
        $groups = [];
        foreach ($el->children as $c) {
            $groups[$c->local][] = self::xmlValue($c);
        }
        foreach ($groups as $k => $vs) {
            if (count($vs) === 1) {
                $members[] = [new JStr((string) $k), $vs[0]];
            } else {
                $arr = new JArr();
                $arr->a = $vs;
                $members[] = [new JStr((string) $k), $arr];
            }
        }
        if (trim($el->text, " \t\n\r") !== '') {
            $members[] = [new JStr('#text'), new JStr($el->text)];
        }
        $o = new JObj();
        $o->m = $members;
        return $o;
    }

    /** 22.2 point 9: 'ns:' + pattern of a namespace URI. */
    public static function nsPattern(string $uri): string
    {
        if ($uri === '') {
            return 'ns:{none}';
        }
        if (strlen($uri) > self::NS_MAX_BYTES || preg_match('/[^\x21-\x7e]|[@{}]/', $uri) === 1) {
            return 'ns:{*}';
        }
        return 'ns:' . preg_replace_callback('/[A-Za-z0-9_-]+/', static function (array $m): string {
            $t = $m[0];
            if (strlen($t) > 64 || preg_match('/[0-9]{6}/', $t) === 1 || preg_match('/[0-9A-Fa-f]{12}/', $t) === 1) {
                return '{*}';
            }
            return $t;
        }, $uri);
    }

    /**
     * 22.2 points 7, 9 and 10: body tree, xmlns entries (path => token, document order) and fmt.
     *
     * @return array{0: JObj, 1: array<string, string>, 2: string}
     */
    public static function xmlTree(XmlElem $root, int $maxDepth): array
    {
        $tree = new JObj();
        $tree->m = [[new JStr($root->local), self::xmlValue($root)]];
        $entries = [];
        self::visitNs($root, '$' . (Formats::isLiteralName($root->local) ? '.' . $root->local : '.*'), '', 1, $maxDepth, $entries);
        $fmt = 'xml';
        if ($root->local === 'Envelope' && $root->ns === self::SOAP11) {
            $fmt = 'soap11';
        } elseif ($root->local === 'Envelope' && $root->ns === self::SOAP12) {
            $fmt = 'soap12';
        }
        return [$tree, $entries, $fmt];
    }

    /** @param array<string, string> $entries */
    private static function visitNs(XmlElem $el, string $path, string $parentNs, int $depth, int $maxDepth, array &$entries): void
    {
        if ($depth > $maxDepth) {
            return;
        }
        if ($el->ns !== $parentNs && !isset($entries[$path])) {
            $entries[$path] = self::nsPattern($el->ns);
        }
        $counts = [];
        foreach ($el->children as $c) {
            $counts[$c->local] = ($counts[$c->local] ?? 0) + 1;
        }
        foreach ($el->children as $c) {
            $p = $path . (Formats::isLiteralName($c->local) ? '.' . $c->local : '.*') . ($counts[$c->local] > 1 ? '[*]' : '');
            self::visitNs($c, $p, $el->ns, $depth + 1, $maxDepth, $entries);
        }
    }

    /** 22.2 point 11: operation name of a SOAPAction value (valid UTF-8), or null when empty. */
    public static function soapActionName(string $raw): ?string
    {
        $s = trim($raw, " \t");
        if (strlen($s) >= 2 && str_starts_with($s, '"') && str_ends_with($s, '"')) {
            $s = substr($s, 1, -1);
        }
        if ($s === '') {
            return null;
        }
        // The part after the last '/', '#' or ':' (the whole value when none occurs).
        $cut = 0;
        foreach (['/', '#', ':'] as $sep) {
            $r = strrpos($s, $sep);
            if ($r !== false && $r + 1 > $cut) {
                $cut = $r + 1;
            }
        }
        $name = substr($s, $cut);
        return Formats::isLiteralName($name) ? $name : '{*}';
    }
}
