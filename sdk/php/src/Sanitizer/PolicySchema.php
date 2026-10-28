<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Validation of a `tt.policy.body/v1` document against schemas/policy-compiled.v1.schema.json
 * (`#/$defs/body`) plus the cross-field checks of the policy spec that a source repeats
 * (reserved HMAC domains, bounds strictly increasing as doubles). A source never trusts the
 * validation done by tt-core (policy.md 4, condition 1).
 */
final class PolicySchema
{
    public const RESERVED_DOMAINS = ['subject' => true, 'sample' => true, 'sample-trace' => true, 'discovery' => true];
    public const BODY_FORMAT = 'tt.policy.body/v1';

    private const RE_POLICY_ID = '/^[a-z0-9][a-z0-9-]{0,62}$/D';
    private const RE_DOMAIN = '/^[a-z][a-z0-9_-]{0,31}$/D';
    private const RE_KID = '/^[a-z0-9]{1,8}$/D';
    private const RE_HOSTPORT = '/^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$/D';
    private const RE_KEYNAME = '/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/D';
    private const RE_HEADERNAME = '/^[a-z0-9!#$%&\'*+.^_`|~-]{1,64}$/D';
    private const RE_PARAMNAME = '/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D';
    /** Spec v1.19: also the XML steps ".@name" and ".#text" (sanitizer.md 5.0). */
    private const RE_TTPATH = '/^\$(\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\]){0,64}$/D';
    private const RE_OPKEY = '/^[A-Z]{1,16} \/([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})?(\/([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})){0,31}$/D';
    private const RE_BASE = '/^https?:\/\/[a-z0-9.-]{1,253}(:[0-9]{1,5})?(\/[A-Za-z0-9._~-]{1,64})*$/D';

    /** @throws Refused policy_rejected */
    public static function validate(mixed $plain): PObj
    {
        try {
            self::body($plain, '$');
        } catch (\InvalidArgumentException $e) {
            throw new Refused('policy_rejected', 'schema ' . $e->getMessage());
        }
        /** @var PObj $plain */
        self::checkUnsafe($plain);
        return $plain;
    }

    private const CREDENTIAL_HEADERS = ['authorization' => true, 'cookie' => true, 'set-cookie' => true, 'proxy-authorization' => true];

    /**
     * Source-side safety subset (hardening.md 2.1, v1.3), applied to every signed body:
     * H1 keep, code (v1.11, any shape: code(alnum) of v1.19 too) or hmac on authorization, cookie, set-cookie, proxy-authorization (header rules of request,
     * response and errors; global, services and operations); H2 keep, code or hmac on a tt-path with any wildcard step
     * (".*" or "[*]") in the global body rules; H3 discovery or auto_words expiring later than created_at + 7 days.
     * Properties of the body: neither the clock nor the group matter.
     *
     * @throws Refused policy_rejected with the detail prefix Refused::UNSAFE
     */
    public static function checkUnsafe(PObj $b): void
    {
        $unsafe = static fn (string $why): Refused => new Refused('policy_rejected', Refused::UNSAFE . ': ' . $why);
        $parts = [];
        $collect = static function (mixed $scope, array $keys) use (&$parts): void {
            if (!$scope instanceof PObj) {
                return;
            }
            foreach ($keys as $k) {
                if (($scope->m[$k] ?? null) instanceof PObj) {
                    $parts[] = $scope->m[$k];
                }
            }
        };
        $global = $b->m['global'] ?? null;
        $collect($global, ['request', 'response', 'errors']);
        foreach (is_array($b->m['services'] ?? null) ? $b->m['services'] : [] as $svc) {
            $collect($svc, ['request', 'response', 'errors']);
            if ($svc instanceof PObj && is_array($svc->m['ops'] ?? null)) {
                foreach ($svc->m['ops'] as $op) {
                    $collect($op, ['request', 'response']);
                }
            }
        }
        foreach ($parts as $p) {
            $headers = $p->m['headers'] ?? null;
            if (!$headers instanceof PObj) {
                continue;
            }
            foreach ($headers->m as $name => $a) {
                $act = $a instanceof PObj ? ($a->m['action'] ?? null) : null;
                if (isset(self::CREDENTIAL_HEADERS[(string) $name]) && ($act === 'keep' || $act === 'code' || $act === 'hmac')) {
                    throw $unsafe($act . ' on header ' . $name);
                }
            }
        }
        if ($global instanceof PObj) {
            foreach (['request', 'response', 'errors'] as $k) {
                $part = $global->m[$k] ?? null;
                $rules = $part instanceof PObj && is_array($part->m['body'] ?? null) ? $part->m['body'] : [];
                foreach ($rules as $r) {
                    if (!$r instanceof PObj) {
                        continue;
                    }
                    $a = $r->m['action'] ?? null;
                    $act = $a instanceof PObj ? ($a->m['action'] ?? null) : null;
                    $path = $r->m['path'] ?? null;
                    if (($act === 'keep' || $act === 'code' || $act === 'hmac') && is_string($path) && (str_contains($path, '.*') || str_contains($path, '[*]'))) {
                        throw $unsafe($act . ' on ' . $path . ' in a global rule');
                    }
                }
            }
        }
        $created = Time::parse($b->m['created_at'] ?? null);
        if ($created === null) {
            return;
        }
        $limit = $created + 7 * Time::DAY_MS;
        $seg = $b->m['segments'] ?? null;
        if ($seg instanceof PObj && ($seg->m['auto_words'] ?? null) === true) {
            $t = Time::parse($seg->m['auto_words_expires_at'] ?? null);
            if ($t !== null && $t > $limit) {
                throw $unsafe('auto_words expires beyond created_at + 7 days');
            }
        }
        $d = $b->m['discovery'] ?? null;
        if ($d instanceof PObj && ($d->m['enabled'] ?? null) === true) {
            $t = Time::parse($d->m['expires_at'] ?? null);
            if ($t !== null && $t > $limit) {
                throw $unsafe('discovery expires beyond created_at + 7 days');
            }
        }
    }

    private static function fail(string $at, string $why): never
    {
        throw new \InvalidArgumentException($at . ': ' . $why);
    }

    private static function str(mixed $v, string $re, string $at): void
    {
        if (!is_string($v) || preg_match($re, $v) !== 1) {
            self::fail($at, 'string');
        }
    }

    private static function int(mixed $v, int $min, int $max, string $at): void
    {
        if (!$v instanceof Lex || !$v->isInt()) {
            self::fail($at, 'integer');
        }
        $n = (float) $v->lex;
        if ($n < $min || $n > $max) {
            self::fail($at, 'range');
        }
    }

    private static function bool(mixed $v, string $at): void
    {
        if (!is_bool($v)) {
            self::fail($at, 'boolean');
        }
    }

    private static function time(mixed $v, string $at): void
    {
        if (Time::parse($v) === null) {
            self::fail($at, 'date-time');
        }
    }

    /**
     * @param callable(mixed, string): void $item
     */
    private static function arr(mixed $v, callable $item, int $max, bool $unique, int $min, string $at): void
    {
        if (!is_array($v) || !array_is_list($v) || count($v) > $max || count($v) < $min) {
            self::fail($at, 'array');
        }
        $seen = [];
        foreach ($v as $i => $x) {
            $item($x, $at . '[' . $i . ']');
            if ($unique) {
                $k = $x instanceof Lex ? 'n' . $x->lex : 's' . (is_string($x) ? $x : '');
                if (isset($seen[$k])) {
                    self::fail($at, 'unique');
                }
                $seen[$k] = true;
            }
        }
    }

    /**
     * @param array<string, callable(mixed, string): void> $props
     * @param list<string> $required
     */
    private static function object(mixed $v, array $props, array $required, string $at): void
    {
        if (!$v instanceof PObj) {
            self::fail($at, 'object');
        }
        foreach ($v->m as $k => $x) {
            $k = (string) $k;
            if (!isset($props[$k])) {
                self::fail($at . '.' . $k, 'unexpected');
            }
            $props[$k]($x, $at . '.' . $k);
        }
        foreach ($required as $r) {
            if (!array_key_exists($r, $v->m)) {
                self::fail($at . '.' . $r, 'required');
            }
        }
    }

    /**
     * @param callable(mixed, string): void $val
     */
    private static function map(mixed $v, string $nameRe, callable $val, int $max, string $at): void
    {
        if (!$v instanceof PObj) {
            self::fail($at, 'object');
        }
        if (count($v->m) > $max) {
            self::fail($at, 'maxProperties');
        }
        foreach ($v->m as $k => $x) {
            $k = (string) $k;
            if (preg_match($nameRe, $k) !== 1) {
                self::fail($at . '.' . $k, 'name');
            }
            $val($x, $at . '.' . $k);
        }
    }

    private static function any(): \Closure
    {
        return static function (): void {
        };
    }

    private static function action(mixed $v, string $at): void
    {
        if (!$v instanceof PObj) {
            self::fail($at, 'action');
        }
        $a = $v->m['action'] ?? null;
        $any = self::any();
        if ($a === 'drop' || $a === 'keep' || $a === 'graphql') {
            self::object($v, ['action' => $any], ['action'], $at);
            return;
        }
        if ($a === 'code') {
            // v1.11 code, or v1.19 code with the only shape "alnum" (sanitizer.md 5.6)
            self::object($v, [
                'action' => $any,
                'shape' => static function ($x, $p): void {
                    if ($x !== 'alnum') {
                        self::fail($p, 'const');
                    }
                },
            ], ['action'], $at);
            return;
        }
        if ($a === 'hmac') {
            self::object($v, ['action' => $any, 'domain' => static fn ($x, $p) => self::str($x, self::RE_DOMAIN, $p)], ['action', 'domain'], $at);
            if (isset(self::RESERVED_DOMAINS[(string) $v->m['domain']])) {
                self::fail($at, 'reserved domain');
            }
            return;
        }
        $kind = $v->m['kind'] ?? null;
        if ($a === 'bucket' && $kind === 'num') {
            self::object($v, [
                'action' => $any,
                'kind' => $any,
                'bounds' => static fn ($x, $p) => self::arr($x, static function ($b, $p2): void {
                    if (!$b instanceof Lex) {
                        self::fail($p2, 'number');
                    }
                    if (strlen($b->lex) > 64) {
                        self::fail($p2, 'lexeme');
                    }
                }, 32, false, 1, $p),
            ], ['action', 'kind', 'bounds'], $at);
            /** @var list<Lex> $bounds */
            $bounds = $v->m['bounds'];
            for ($i = 1; $i < count($bounds); $i++) {
                if (!((float) $bounds[$i - 1]->lex < (float) $bounds[$i]->lex)) {
                    self::fail($at, 'bounds not increasing');
                }
            }
            return;
        }
        if ($a === 'bucket' && $kind === 'time') {
            self::object($v, [
                'action' => $any,
                'kind' => $any,
                'unit' => static fn ($x, $p) => self::str($x, '/^(year|month|day|hour)$/D', $p),
            ], ['action', 'kind', 'unit'], $at);
            return;
        }
        self::fail($at, 'action');
    }

    private static function bodyRules(mixed $v, string $at): void
    {
        self::arr($v, static fn ($r, $p) => self::object($r, [
            'path' => static fn ($x, $p2) => self::str($x, self::RE_TTPATH, $p2),
            'action' => static fn ($x, $p2) => self::action($x, $p2),
        ], ['path', 'action'], $p), 1024, false, 0, $at);
    }

    private static function actionMap(string $nameRe, int $max): \Closure
    {
        return static fn ($v, $at) => self::map($v, $nameRe, static fn ($x, $p) => self::action($x, $p), $max, $at);
    }

    /** @return array<string, callable(mixed, string): void> */
    private static function partProps(bool $withPath): array
    {
        $p = [
            'query' => self::actionMap(self::RE_KEYNAME, 256),
            'headers' => self::actionMap(self::RE_HEADERNAME, 256),
            'cookies' => self::actionMap(self::RE_KEYNAME, 256),
            'body' => static fn ($v, $at) => self::bodyRules($v, $at),
        ];
        if ($withPath) {
            $p['path'] = self::actionMap(self::RE_PARAMNAME, 32);
        }
        return $p;
    }

    private static function part(mixed $v, string $at): void
    {
        self::object($v, self::partProps(false), [], $at);
    }

    private static function opPart(mixed $v, string $at): void
    {
        self::object($v, self::partProps(true), [], $at);
    }

    private static function scope(mixed $v, string $at): void
    {
        $p = static fn ($x, $a) => self::part($x, $a);
        self::object($v, ['request' => $p, 'response' => $p, 'errors' => $p], [], $at);
    }

    private static function matchSpec(mixed $v, string $at): void
    {
        if (!$v instanceof PObj) {
            self::fail($at, 'match');
        }
        if (array_key_exists('base', $v->m)) {
            self::object($v, ['base' => static fn ($x, $p) => self::str($x, self::RE_BASE, $p)], ['base'], $at);
            return;
        }
        self::object($v, [
            'inbound' => static function ($x, $p): void {
                if ($x !== true) {
                    self::fail($p, 'const');
                }
            },
            'internal' => static fn ($x, $p) => self::bool($x, $p),
        ], ['inbound', 'internal'], $at);
    }

    private static function service(mixed $v, string $at): void
    {
        self::object($v, [
            'name' => static fn ($x, $p) => self::str($x, '/^[a-z0-9][a-z0-9._-]{0,62}$/D', $p),
            'match' => static fn ($x, $p) => self::matchSpec($x, $p),
            'request' => static fn ($x, $p) => self::part($x, $p),
            'response' => static fn ($x, $p) => self::part($x, $p),
            'errors' => static fn ($x, $p) => self::part($x, $p),
            'ops' => static fn ($x, $p) => self::arr($x, static fn ($o, $p2) => self::object($o, [
                'op' => static fn ($y, $p3) => self::str($y, self::RE_OPKEY, $p3),
                'request' => static fn ($y, $p3) => self::opPart($y, $p3),
                'response' => static fn ($y, $p3) => self::opPart($y, $p3),
            ], ['op'], $p2), 4096, false, 0, $p),
        ], ['name', 'match', 'ops'], $at);
    }

    private static function body(mixed $v, string $at): void
    {
        $hostPort = static fn ($x, $p) => self::str($x, self::RE_HOSTPORT, $p);
        self::object($v, [
            'format' => static function ($x, $p): void {
                if ($x !== self::BODY_FORMAT) {
                    self::fail($p, 'const');
                }
            },
            'policy_id' => static fn ($x, $p) => self::str($x, self::RE_POLICY_ID, $p),
            'version' => static fn ($x, $p) => self::int($x, 1, PHP_INT_MAX, $p),
            'issued_seq' => static fn ($x, $p) => self::int($x, 1, PHP_INT_MAX, $p),
            'created_at' => static fn ($x, $p) => self::time($x, $p),
            'not_after' => static fn ($x, $p) => self::time($x, $p),
            'targets' => static fn ($x, $p) => self::object($x, [
                'groups' => static fn ($g, $p2) => self::arr($g, static fn ($y, $p3) => self::str($y, self::RE_POLICY_ID, $p3), 256, true, 1, $p2),
            ], ['groups'], $p),
            'hmac' => static fn ($x, $p) => self::object($x, [
                'kid' => static fn ($y, $p2) => self::str($y, self::RE_KID, $p2),
                'accept_kids' => static fn ($y, $p2) => self::arr($y, static fn ($k, $p3) => self::str($k, self::RE_KID, $p3), 4, true, 0, $p2),
                'epoch' => static fn ($y, $p2) => self::str($y, '/^[A-Za-z0-9._-]{1,32}$/D', $p2),
            ], ['kid', 'epoch', 'accept_kids'], $p),
            'identity' => static fn ($x, $p) => self::object($x, [
                'subject' => static function ($s, $p2): void {
                    self::object($s, [
                        'from' => static fn ($y, $p3) => self::str($y, '/^(header|cookie)$/D', $p3),
                        'name' => static fn ($y, $p3) => self::str($y, '/^[A-Za-z0-9!#$%&\'*+.^_`|~-]{1,64}$/D', $p3),
                        'jwt_claim' => static fn ($y, $p3) => self::str($y, self::RE_KEYNAME, $p3),
                        'json_path' => static fn ($y, $p3) => self::str($y, '/^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,7}$/D', $p3),
                    ], ['from', 'name'], $p2);
                    // Spec v1.18: json_path reads a header only and excludes jwt_claim.
                    if ($s instanceof PObj && array_key_exists('json_path', $s->m)
                        && (array_key_exists('jwt_claim', $s->m) || ($s->m['from'] ?? null) !== 'header')) {
                        self::fail($p2 . '.json_path', 'header only, excludes jwt_claim');
                    }
                },
            ], [], $p),
            'sampling' => static fn ($x, $p) => self::object($x, [
                'rate_bp' => static fn ($y, $p2) => self::int($y, 0, 10000, $p2),
                'trust_baggage' => static fn ($y, $p2) => self::bool($y, $p2),
                'propagate_to' => static fn ($y, $p2) => self::arr($y, $hostPort, 256, true, 0, $p2),
            ], ['rate_bp', 'trust_baggage', 'propagate_to'], $p),
            'segments' => static function ($x, $p) use ($hostPort): void {
                self::object($x, [
                    'auto_words' => static fn ($y, $p2) => self::bool($y, $p2),
                    'auto_words_expires_at' => static fn ($y, $p2) => self::time($y, $p2),
                    'allow' => static fn ($y, $p2) => self::arr($y, static fn ($s, $p3) => self::str($s, Formats::PATH_TOKEN, $p3), 1024, true, 0, $p2),
                    'hosts_allow' => static fn ($y, $p2) => self::arr($y, $hostPort, 1024, true, 0, $p2),
                ], ['auto_words', 'allow', 'hosts_allow'], $p);
                if ($x instanceof PObj && ($x->m['auto_words'] ?? null) === true && !array_key_exists('auto_words_expires_at', $x->m)) {
                    self::fail($p, 'auto_words_expires_at required');
                }
            },
            'limits' => static fn ($x, $p) => self::object($x, [
                'max_body_bytes' => static fn ($y, $p2) => self::int($y, 0, 16777216, $p2),
                'max_depth' => static fn ($y, $p2) => self::int($y, 1, 128, $p2),
                'max_array' => static fn ($y, $p2) => self::int($y, 0, 1024, $p2),
                'max_keys' => static fn ($y, $p2) => self::int($y, 1, 4096, $p2),
                'keep_max_bytes' => static fn ($y, $p2) => self::int($y, 0, 1024, $p2),
            ], ['max_body_bytes', 'max_depth', 'max_array', 'max_keys', 'keep_max_bytes'], $p),
            // Spec v1.19 (sanitizer.md 22.1): every field required, absent object = all off.
            'bodies' => static fn ($x, $p) => self::object($x, [
                'xml' => static fn ($y, $p2) => self::bool($y, $p2),
                'multipart' => static fn ($y, $p2) => self::bool($y, $p2),
                'docs' => static fn ($y, $p2) => self::bool($y, $p2),
                'max_large_body_bytes' => static fn ($y, $p2) => self::int($y, 0, 67108864, $p2),
                'large_array' => static fn ($y, $p2) => self::int($y, 0, 1024, $p2),
                'large_nested_array' => static fn ($y, $p2) => self::int($y, 0, 1024, $p2),
            ], ['xml', 'multipart', 'docs', 'max_large_body_bytes', 'large_array', 'large_nested_array'], $p),
            'discovery' => static fn ($x, $p) => self::object($x, [
                'enabled' => static fn ($y, $p2) => self::bool($y, $p2),
                'expires_at' => static fn ($y, $p2) => self::time($y, $p2),
            ], ['enabled', 'expires_at'], $p),
            'hosts' => static fn ($x, $p) => self::object($x, [
                'discovery' => static fn ($y, $p2) => self::str($y, '/^(auto|off)$/D', $p2),
            ], ['discovery'], $p),
            'global' => static fn ($x, $p) => self::scope($x, $p),
            'services' => static fn ($x, $p) => self::arr($x, static fn ($s, $p2) => self::service($s, $p2), 1024, false, 0, $p),
        ], ['format', 'policy_id', 'version', 'issued_seq', 'created_at', 'not_after', 'targets', 'hmac', 'sampling', 'segments', 'limits', 'global', 'services'], $at);
    }
}
