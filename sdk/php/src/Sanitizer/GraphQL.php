<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Shape of a GraphQL executable document (sanitizer.md 5.7, spec v1.14): the same tokens with every literal value
 * replaced by a placeholder (?s ?i ?f ?b ?n ?e) and every name that fails the name rule replaced by "*". Works on
 * bytes, step by step like the Go reference (internal/graphql): lexing, a recursive-descent parse of the executable
 * subset, emission. Recursion is bounded by the 64 open brackets the lexer allows.
 *
 * @internal used by Run
 */
final class GraphQL
{
    public const MAX_NESTING = 64;
    public const MAX_SHAPE_BYTES = 32768;
    public const MAX_NAME_BYTES = 64;
    /** Array limit of a response body with the introspection gate open (5.7.2). */
    public const INTROSPECTION_MAX_ARRAY = 4096;

    private const PUNCT = 0;
    private const NAME = 1;
    private const INT = 2;
    private const FLOAT = 3;
    private const STR = 4;

    private const NAME_CONT = '_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    private const DIGITS = '0123456789';
    private const HEX = '0123456789ABCDEFabcdef';
    private const ROOT_INTROSPECTION = ['__schema' => true, '__type' => true, '__typename' => true];

    /** @var list<int> */
    private array $kind = [];
    /** @var list<string> punctuator or name text ('' for literals) */
    private array $text = [];
    /** @var array<int, true> names in value position */
    private array $value = [];
    private int $pos = 0;
    private int $count = 0;
    private int $ops = 0;
    private bool $intro = true;

    private function __construct()
    {
    }

    /**
     * Shape of $src without the "gql:" prefix and whether the document is introspection-only (every operation, at
     * least one, selects only __schema, __type or __typename at its root, without aliases or fragments). null when
     * $src is not an executable document within the limits: the caller emits the drop form.
     *
     * @return array{0: string, 1: bool}|null
     */
    public static function shape(string $src): ?array
    {
        $g = new self();
        if (!$g->lex($src) || !$g->document()) {
            return null;
        }
        $out = '';
        $prevWord = false;
        for ($i = 0; $i < $g->count; $i++) {
            switch ($g->kind[$i]) {
                case self::PUNCT:
                    $t = $g->text[$i];
                    break;
                case self::NAME:
                    $t = $g->text[$i];
                    if (isset($g->value[$i])) {
                        $t = $t === 'true' || $t === 'false' ? '?b' : ($t === 'null' ? '?n' : '?e');
                    } elseif (!self::nameSafe($t)) {
                        $t = '*';
                    }
                    break;
                case self::INT:
                    $t = '?i';
                    break;
                case self::FLOAT:
                    $t = '?f';
                    break;
                default:
                    $t = '?s';
            }
            if ($prevWord && self::isWordByte($t[0])) {
                $out .= ' ';
            }
            $out .= $t;
            $prevWord = self::isWordByte($t[strlen($t) - 1]);
            if (strlen($out) > self::MAX_SHAPE_BYTES) {
                return null;
            }
        }
        return [$out, $g->ops > 0 && $g->intro];
    }

    /** A GraphQL name (any length): [_A-Za-z][_0-9A-Za-z]*. */
    public static function isName(string $s): bool
    {
        return $s !== '' && self::isNameStart($s[0]) && strspn($s, self::NAME_CONT) === strlen($s);
    }

    /**
     * Name rule of 5.7.1: a name leaves as written if it has at most 64 bytes, is not 16 or more hexadecimal digits
     * only and has no six consecutive digits.
     */
    public static function nameSafe(string $s): bool
    {
        $n = strlen($s);
        if ($n === 0 || $n > self::MAX_NAME_BYTES || !self::isName($s)) {
            return false;
        }
        if ($n >= 16 && strspn($s, self::HEX) === $n) {
            return false;
        }
        return preg_match('/[0-9]{6}/', $s) !== 1;
    }

    private static function isNameStart(string $c): bool
    {
        return $c === '_' || ($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z');
    }

    private static function isDigit(string $c): bool
    {
        return $c >= '0' && $c <= '9';
    }

    private static function isHexDigit(string $c): bool
    {
        return ($c >= '0' && $c <= '9') || ($c >= 'a' && $c <= 'f') || ($c >= 'A' && $c <= 'F');
    }

    private static function isWordByte(string $c): bool
    {
        return $c === '?' || $c === '*' || $c === '_' || ($c >= '0' && $c <= '9') || ($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z');
    }

    // --- 1. lexing -------------------------------------------------------------------------------

    private function push(int $kind, string $text): void
    {
        $this->kind[] = $kind;
        $this->text[] = $text;
        $this->count++;
    }

    private function lex(string $src): bool
    {
        $n = strlen($src);
        $open = 0;
        $i = 0;
        while ($i < $n) {
            $c = $src[$i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" || $c === ',') {
                $i++;
            } elseif ($c === "\xEF" && $i + 2 < $n && $src[$i + 1] === "\xBB" && $src[$i + 2] === "\xBF") {
                $i += 3; // U+FEFF
            } elseif ($c === '#') {
                $i += strcspn($src, "\n\r", $i);
            } elseif ($c === '!' || $c === '$' || $c === '&' || $c === ':' || $c === '=' || $c === '@' || $c === '|') {
                $this->push(self::PUNCT, $c);
                $i++;
            } elseif ($c === '(' || $c === '[' || $c === '{') {
                if (++$open > self::MAX_NESTING) {
                    return false;
                }
                $this->push(self::PUNCT, $c);
                $i++;
            } elseif ($c === ')' || $c === ']' || $c === '}') {
                if (--$open < 0) {
                    return false;
                }
                $this->push(self::PUNCT, $c);
                $i++;
            } elseif ($c === '.') {
                if ($i + 2 < $n && $src[$i + 1] === '.' && $src[$i + 2] === '.') {
                    $this->push(self::PUNCT, '...');
                    $i += 3;
                } else {
                    return false;
                }
            } elseif (self::isNameStart($c)) {
                $j = $i + 1 + strspn($src, self::NAME_CONT, $i + 1);
                $this->push(self::NAME, substr($src, $i, $j - $i));
                $i = $j;
            } elseif ($c === '-' || self::isDigit($c)) {
                $kind = self::INT;
                $i = self::lexNumber($src, $i, $kind);
                if ($i < 0) {
                    return false;
                }
                $this->push($kind, '');
            } elseif ($c === '"') {
                $i = self::lexString($src, $i);
                if ($i < 0) {
                    return false;
                }
                $this->push(self::STR, '');
            } else {
                return false;
            }
        }
        return $open === 0;
    }

    /** IntValue or FloatValue at $i: index after it, or -1. */
    private static function lexNumber(string $src, int $i, int &$kind): int
    {
        $n = strlen($src);
        $j = $i;
        if ($src[$j] === '-') {
            $j++;
        }
        if ($j >= $n || !self::isDigit($src[$j])) {
            return -1;
        }
        if ($src[$j] === '0') {
            $j++;
            if ($j < $n && self::isDigit($src[$j])) {
                return -1; // leading zero
            }
        } else {
            $j += strspn($src, self::DIGITS, $j);
        }
        $kind = self::INT;
        if ($j < $n && $src[$j] === '.') {
            $j++;
            if ($j >= $n || !self::isDigit($src[$j])) {
                return -1;
            }
            $j += strspn($src, self::DIGITS, $j);
            $kind = self::FLOAT;
        }
        if ($j < $n && ($src[$j] === 'e' || $src[$j] === 'E')) {
            $j++;
            if ($j < $n && ($src[$j] === '+' || $src[$j] === '-')) {
                $j++;
            }
            if ($j >= $n || !self::isDigit($src[$j])) {
                return -1;
            }
            $j += strspn($src, self::DIGITS, $j);
            $kind = self::FLOAT;
        }
        // A number is not followed by '.' or a NameStart.
        if ($j < $n && ($src[$j] === '.' || self::isNameStart($src[$j]))) {
            return -1;
        }
        return $j;
    }

    /** String or block string starting at the quote at $i: index after its end, or -1. */
    private static function lexString(string $src, int $i): int
    {
        $n = strlen($src);
        if ($i + 2 < $n && $src[$i + 1] === '"' && $src[$i + 2] === '"') {
            // Block string: ends at the first """ not escaped as \""".
            $j = $i + 3;
            while ($j < $n) {
                $c = $src[$j];
                if ($c === '\\' && $j + 3 < $n && $src[$j + 1] === '"' && $src[$j + 2] === '"' && $src[$j + 3] === '"') {
                    $j += 4;
                } elseif ($c === '"' && $j + 2 < $n && $src[$j + 1] === '"' && $src[$j + 2] === '"') {
                    return $j + 3;
                } elseif ($c < "\x20" && $c !== "\t" && $c !== "\n" && $c !== "\r") {
                    return -1;
                } else {
                    $j++;
                }
            }
            return -1;
        }
        $j = $i + 1;
        while ($j < $n) {
            $c = $src[$j];
            if ($c === '"') {
                return $j + 1;
            }
            if ($c === '\\') {
                if ($j + 1 >= $n) {
                    return -1;
                }
                $e = $src[$j + 1];
                if ($e === '"' || $e === '\\' || $e === '/' || $e === 'b' || $e === 'f' || $e === 'n' || $e === 'r' || $e === 't') {
                    $j += 2;
                } elseif ($e === 'u') {
                    if ($j + 5 >= $n || !self::isHexDigit($src[$j + 2]) || !self::isHexDigit($src[$j + 3]) || !self::isHexDigit($src[$j + 4]) || !self::isHexDigit($src[$j + 5])) {
                        return -1;
                    }
                    $j += 6;
                } else {
                    return -1;
                }
            } elseif ($c < "\x20" && $c !== "\t") {
                return -1; // line terminators and control characters
            } else {
                $j++;
            }
        }
        return -1;
    }

    // --- 2. parsing ------------------------------------------------------------------------------

    private function isPunct(string $s): bool
    {
        return $this->pos < $this->count && $this->kind[$this->pos] === self::PUNCT && $this->text[$this->pos] === $s;
    }

    private function atName(): bool
    {
        return $this->pos < $this->count && $this->kind[$this->pos] === self::NAME;
    }

    private function expect(string $s): bool
    {
        if (!$this->isPunct($s)) {
            return false;
        }
        $this->pos++;
        return true;
    }

    /** Consumes a name; null when the next token is not one. */
    private function name(): ?string
    {
        if (!$this->atName()) {
            return null;
        }
        return $this->text[$this->pos++];
    }

    private function document(): bool
    {
        if ($this->count === 0) {
            return false;
        }
        while ($this->pos < $this->count) {
            $k = $this->kind[$this->pos];
            $t = $this->text[$this->pos];
            if ($k === self::PUNCT && $t === '{') {
                $this->ops++;
                if (!$this->selectionSet(true)) {
                    return false;
                }
            } elseif ($k === self::NAME && ($t === 'query' || $t === 'mutation' || $t === 'subscription')) {
                $this->ops++;
                if (!$this->operation()) {
                    return false;
                }
            } elseif ($k === self::NAME && $t === 'fragment') {
                if (!$this->fragment()) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }

    private function operation(): bool
    {
        $this->pos++; // query | mutation | subscription
        if ($this->atName()) {
            $this->pos++;
        }
        if ($this->isPunct('(')) {
            $this->pos++;
            $vars = 0;
            while (true) {
                if ($this->isPunct(')')) {
                    if ($vars === 0) {
                        return false;
                    }
                    $this->pos++;
                    break;
                }
                if (!$this->varDef()) {
                    return false;
                }
                $vars++;
            }
        }
        return $this->directives() && $this->selectionSet(true);
    }

    private function varDef(): bool
    {
        if (!$this->expect('$') || $this->name() === null || !$this->expect(':') || !$this->typeRef()) {
            return false;
        }
        if ($this->isPunct('=')) {
            $this->pos++;
            if (!$this->value()) {
                return false;
            }
        }
        return $this->directives();
    }

    private function typeRef(): bool
    {
        if ($this->isPunct('[')) {
            $this->pos++;
            if (!$this->typeRef() || !$this->expect(']')) {
                return false;
            }
        } elseif ($this->name() === null) {
            return false;
        }
        if ($this->isPunct('!')) {
            $this->pos++;
        }
        return true;
    }

    private function fragment(): bool
    {
        $this->pos++; // fragment
        $name = $this->name();
        if ($name === null || $name === 'on') {
            return false;
        }
        if (!$this->atName() || $this->text[$this->pos] !== 'on') {
            return false;
        }
        $this->pos++;
        return $this->name() !== null && $this->directives() && $this->selectionSet(false);
    }

    /** $root: the selection set of an operation, checked for the introspection gate. */
    private function selectionSet(bool $root): bool
    {
        if (!$this->expect('{')) {
            return false;
        }
        $n = 0;
        while (true) {
            if ($this->isPunct('}')) {
                if ($n === 0) {
                    return false;
                }
                $this->pos++;
                return true;
            }
            if (!$this->selection($root)) {
                return false;
            }
            $n++;
        }
    }

    private function selection(bool $root): bool
    {
        if ($this->isPunct('...')) {
            $this->pos++;
            if ($root) {
                $this->intro = false; // fragments at the root
            }
            if ($this->atName() && $this->text[$this->pos] !== 'on') {
                $this->pos++;
                return $this->directives();
            }
            if ($this->atName()) { // "on"
                $this->pos++;
                if ($this->name() === null) {
                    return false;
                }
            }
            return $this->directives() && $this->selectionSet(false);
        }
        $name = $this->name();
        if ($name === null) {
            return false;
        }
        if ($this->isPunct(':')) {
            $this->pos++;
            if ($root) {
                $this->intro = false; // alias at the root
            }
            $name = $this->name();
            if ($name === null) {
                return false;
            }
        }
        if ($root && !isset(self::ROOT_INTROSPECTION[$name])) {
            $this->intro = false;
        }
        if ($this->isPunct('(') && !$this->arguments()) {
            return false;
        }
        if (!$this->directives()) {
            return false;
        }
        if ($this->isPunct('{')) {
            return $this->selectionSet(false);
        }
        return true;
    }

    private function arguments(): bool
    {
        if (!$this->expect('(')) {
            return false;
        }
        $n = 0;
        while (true) {
            if ($this->isPunct(')')) {
                if ($n === 0) {
                    return false;
                }
                $this->pos++;
                return true;
            }
            if ($this->name() === null || !$this->expect(':') || !$this->value()) {
                return false;
            }
            $n++;
        }
    }

    private function directives(): bool
    {
        while ($this->isPunct('@')) {
            $this->pos++;
            if ($this->name() === null) {
                return false;
            }
            if ($this->isPunct('(') && !$this->arguments()) {
                return false;
            }
        }
        return true;
    }

    private function value(): bool
    {
        if ($this->pos >= $this->count) {
            return false;
        }
        $k = $this->kind[$this->pos];
        if ($k === self::PUNCT) {
            $t = $this->text[$this->pos];
            if ($t === '$') {
                $this->pos++;
                return $this->name() !== null;
            }
            if ($t === '[') {
                $this->pos++;
                while (!$this->isPunct(']')) {
                    if (!$this->value()) {
                        return false;
                    }
                }
                $this->pos++;
                return true;
            }
            if ($t === '{') {
                $this->pos++;
                while (!$this->isPunct('}')) {
                    if ($this->name() === null || !$this->expect(':') || !$this->value()) {
                        return false;
                    }
                }
                $this->pos++;
                return true;
            }
            return false;
        }
        if ($k === self::NAME) {
            $this->value[$this->pos] = true; // enum, true, false, null
        }
        $this->pos++;
        return true;
    }
}
