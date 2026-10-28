<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Ready-to-use compiled policy (policy.md 2): a verified `tt.policy.body/v1` document turned
 * into lookup structures. The body must already have passed PolicySchema::validate().
 */
final class Policy
{
    public const DEFAULT_LIMITS = ['max_body_bytes' => 1048576, 'max_depth' => 32, 'max_array' => 32, 'max_keys' => 256, 'keep_max_bytes' => 64];

    public string $policyId;
    public int $version;
    public int $issuedSeq;
    public ?int $createdAt;
    public ?int $notAfter;
    /** @var list<string> */
    public array $groups = [];
    public string $kid;
    /** @var list<string> */
    public array $acceptKids = [];
    public string $epoch;
    /** @var array{from: string, name: string, jwt_claim: ?string, json_path: ?string}|null */
    public ?array $subject = null;
    public int $rateBp;
    public bool $trustBaggage;
    /** @var array<string, true> */
    public array $propagateTo = [];
    public bool $autoWords;
    public ?int $autoWordsExpiresAt;
    /** @var array<string, true> */
    public array $allow = [];
    /** @var array<string, true> */
    public array $hostsAllow = [];
    /** Spec v1.5: `hosts.discovery` is `auto` (default, also when absent) rather than `off`. */
    public bool $hostsAuto = true;
    public int $maxBodyBytes;
    public int $maxDepth;
    public int $maxArray;
    public int $maxKeys;
    public int $keepMaxBytes;
    /** Spec v1.19 (sanitizer.md 22): `bodies` switches and limits; absent = every switch off. */
    public bool $xml = false;
    public bool $multipart = false;
    public bool $docs = false;
    public int $maxLargeBodyBytes = 0;
    public int $largeArray = 0;
    public int $largeNestedArray = 0;
    public bool $discoveryEnabled;
    public ?int $discoveryExpiresAt;
    public ?Part $globalRequest;
    public ?Part $globalResponse;
    public ?Part $globalErrors;
    /** @var list<Service> */
    public array $services = [];
    /** @var array<string, Service> */
    public array $inbound = [];
    /** @var array<string, true> */
    public array $baseHosts = [];
    /** sha256:<hex> of the body bytes, when known. */
    public string $hash = '';

    public function __construct(PObj $body)
    {
        $b = $body->m;
        $this->policyId = self::str($b['policy_id'] ?? null);
        $this->version = self::int($b['version'] ?? null, 0);
        $this->issuedSeq = self::int($b['issued_seq'] ?? null, 0);
        $this->createdAt = Time::parse($b['created_at'] ?? null);
        $this->notAfter = Time::parse($b['not_after'] ?? null);
        foreach (self::arr(self::obj($b['targets'] ?? null)['groups'] ?? null) as $g) {
            $this->groups[] = self::str($g);
        }
        $hmac = self::obj($b['hmac'] ?? null);
        $this->kid = self::str($hmac['kid'] ?? null);
        foreach (self::arr($hmac['accept_kids'] ?? null) as $k) {
            $this->acceptKids[] = self::str($k);
        }
        $this->epoch = self::str($hmac['epoch'] ?? null);
        $subj = self::obj(self::obj($b['identity'] ?? null)['subject'] ?? null);
        if ($subj !== []) {
            $jc = $subj['jwt_claim'] ?? null;
            $jp = $subj['json_path'] ?? null;
            $this->subject = [
                'from' => self::str($subj['from'] ?? null, 'header'),
                'name' => self::str($subj['name'] ?? null),
                'jwt_claim' => is_string($jc) ? $jc : null,
                // Spec v1.18: dotted path of members inside a header whose value is a JSON object (or base64 of one).
                'json_path' => is_string($jp) ? $jp : null,
            ];
        }
        $sampling = self::obj($b['sampling'] ?? null);
        $this->rateBp = self::int($sampling['rate_bp'] ?? null, 0);
        $this->trustBaggage = ($sampling['trust_baggage'] ?? null) === true;
        foreach (self::arr($sampling['propagate_to'] ?? null) as $h) {
            $this->propagateTo[self::str($h)] = true;
        }
        $seg = self::obj($b['segments'] ?? null);
        $this->autoWords = ($seg['auto_words'] ?? null) === true;
        $this->autoWordsExpiresAt = Time::parse($seg['auto_words_expires_at'] ?? null);
        foreach (self::arr($seg['allow'] ?? null) as $x) {
            $this->allow[self::str($x)] = true;
        }
        foreach (self::arr($seg['hosts_allow'] ?? null) as $x) {
            $this->hostsAllow[self::str($x)] = true;
        }
        $this->hostsAuto = (self::obj($b['hosts'] ?? null)['discovery'] ?? 'auto') !== 'off';
        $lim = self::obj($b['limits'] ?? null);
        $d = self::DEFAULT_LIMITS;
        $this->maxBodyBytes = self::int($lim['max_body_bytes'] ?? null, $d['max_body_bytes']);
        $this->maxDepth = self::int($lim['max_depth'] ?? null, $d['max_depth']);
        $this->maxArray = self::int($lim['max_array'] ?? null, $d['max_array']);
        $this->maxKeys = self::int($lim['max_keys'] ?? null, $d['max_keys']);
        $this->keepMaxBytes = self::int($lim['keep_max_bytes'] ?? null, $d['keep_max_bytes']);
        $bodies = self::obj($b['bodies'] ?? null);
        if ($bodies !== []) {
            $this->xml = ($bodies['xml'] ?? null) === true;
            $this->multipart = ($bodies['multipart'] ?? null) === true;
            $this->docs = ($bodies['docs'] ?? null) === true;
            $this->maxLargeBodyBytes = self::int($bodies['max_large_body_bytes'] ?? null, 0);
            $this->largeArray = self::int($bodies['large_array'] ?? null, 0);
            $this->largeNestedArray = self::int($bodies['large_nested_array'] ?? null, 0);
        }
        $disc = self::obj($b['discovery'] ?? null);
        $this->discoveryEnabled = ($disc['enabled'] ?? null) === true;
        $this->discoveryExpiresAt = Time::parse($disc['expires_at'] ?? null);
        $g = self::obj($b['global'] ?? null);
        $this->globalRequest = self::part($g['request'] ?? null);
        $this->globalResponse = self::part($g['response'] ?? null);
        $this->globalErrors = self::part($g['errors'] ?? null);
        foreach (self::arr($b['services'] ?? null) as $s) {
            if (!$s instanceof PObj) {
                continue;
            }
            $so = $s->m;
            $m = self::obj($so['match'] ?? null);
            $svc = new Service(self::str($so['name'] ?? null), ($m['inbound'] ?? null) === true, ($m['internal'] ?? null) === true);
            $svc->request = self::part($so['request'] ?? null);
            $svc->response = self::part($so['response'] ?? null);
            $svc->errors = self::part($so['errors'] ?? null);
            if (isset($m['base']) && is_string($m['base'])) {
                $svc->base = self::splitBase($m['base']);
                $auth = preg_replace('/^[a-z]+:\/\//', '', $svc->base[0]) ?? '';
                $this->baseHosts[$auth] = true;
                $this->baseHosts[preg_replace('/:[0-9]+$/', '', $auth) ?? $auth] = true;
            }
            foreach (self::arr($so['ops'] ?? null) as $o) {
                $oo = self::obj($o);
                $parsed = self::parseOpKey(self::str($oo['op'] ?? null));
                if ($parsed === null) {
                    continue;
                }
                $svc->ops[] = new Op($parsed['key'], $parsed['method'], $parsed['segs'], $parsed['literals'], self::part($oo['request'] ?? null), self::part($oo['response'] ?? null));
            }
            $this->services[] = $svc;
            if ($svc->inbound && !isset($this->inbound[$svc->name])) {
                $this->inbound[$svc->name] = $svc;
            }
        }
    }

    /**
     * Body bytes a capture keeps (9.0, 22.5): max(max_body_bytes, bodies.max_large_body_bytes) + 1.
     * The rest of the body is only counted.
     */
    public function bodyCaptureLimit(): int
    {
        return max($this->maxBodyBytes, $this->maxLargeBodyBytes) + 1;
    }

    /** 4.3: auto words active at $now (ms). */
    public function autoWordsActive(?int $now): bool
    {
        return $this->autoWords && $now !== null && $this->autoWordsExpiresAt !== null && $this->createdAt !== null
            && $now < $this->autoWordsExpiresAt && $now < $this->createdAt + 7 * Time::DAY_MS;
    }

    /** 15: discovery active at $now (ms). */
    public function discoveryActive(?int $now): bool
    {
        return $this->discoveryEnabled && $now !== null && $this->discoveryExpiresAt !== null && $this->createdAt !== null
            && $now < $this->discoveryExpiresAt && $now < $this->createdAt + 7 * Time::DAY_MS;
    }

    // ------------------------------------------------------------------------------

    /** @return array<string, mixed> */
    private static function obj(mixed $v): array
    {
        return $v instanceof PObj ? $v->m : [];
    }

    /** @return list<mixed> */
    private static function arr(mixed $v): array
    {
        return is_array($v) ? array_values($v) : [];
    }

    private static function str(mixed $v, string $d = ''): string
    {
        return is_string($v) ? $v : $d;
    }

    private static function int(mixed $v, int $d): int
    {
        return $v instanceof Lex && $v->isInt() ? $v->int() : $d;
    }

    private static function action(mixed $v): ?Action
    {
        if (!$v instanceof PObj) {
            return null;
        }
        $o = $v->m;
        $a = $o['action'] ?? null;
        if ($a === 'drop' || $a === 'keep' || $a === 'graphql') {
            return new Action($a);
        }
        if ($a === 'code') {
            // 5.6: shape alnum (v1.19) or the v1.11 code shape
            return new Action('code', null, null, null, null, ($o['shape'] ?? null) === 'alnum' ? 'alnum' : null);
        }
        if ($a === 'hmac') {
            return new Action('hmac', self::str($o['domain'] ?? null, 'id'));
        }
        if ($a === 'bucket' && ($o['kind'] ?? null) === 'num') {
            $bounds = [];
            foreach (self::arr($o['bounds'] ?? null) as $x) {
                $lex = $x instanceof Lex ? $x->lex : '0';
                $bounds[] = ['canon' => Json::canonicalNumber($lex), 'd' => (float) $lex];
            }
            return new Action('bucket', null, 'num', $bounds);
        }
        if ($a === 'bucket' && ($o['kind'] ?? null) === 'time') {
            return new Action('bucket', null, 'time', null, self::str($o['unit'] ?? null, 'day'));
        }
        return new Action('drop');
    }

    /** @return array<string, Action> */
    private static function nameMap(mixed $v): array
    {
        $m = [];
        foreach (self::obj($v) as $k => $x) {
            $a = self::action($x);
            if ($a !== null) {
                $m[(string) $k] = $a;
            }
        }
        return $m;
    }

    /** Parses a tt-path; null if it does not follow the grammar. @return list<array{0: int, 1: string}>|null */
    public static function parseTtPath(string $p): ?array
    {
        if ($p === '' || $p[0] !== '$') {
            return null;
        }
        $steps = [];
        $i = 1;
        $n = strlen($p);
        while ($i < $n) {
            if (substr($p, $i, 2) === '.*') {
                $steps[] = [BodyRule::ANY, ''];
                $i += 2;
            } elseif (substr($p, $i, 3) === '[*]') {
                $steps[] = [BodyRule::IDX, ''];
                $i += 3;
            } elseif (substr($p, $i, 6) === '.#text') {
                // v1.19: mixed text of an XML element (a JSON key "#text" otherwise)
                $steps[] = [BodyRule::NAME, '#text'];
                $i += 6;
            } elseif ($p[$i] === '.') {
                // v1.19: ".@name" selects an XML attribute (a JSON key "@name" otherwise)
                if (preg_match('/^@?[A-Za-z_][A-Za-z0-9_-]{0,63}/', substr($p, $i + 1), $m) !== 1) {
                    return null;
                }
                $steps[] = [BodyRule::NAME, $m[0]];
                $i += 1 + strlen($m[0]);
            } else {
                return null;
            }
        }
        return $steps;
    }

    private static function part(mixed $v): ?Part
    {
        if (!$v instanceof PObj) {
            return null;
        }
        $o = $v->m;
        $body = [];
        foreach (self::arr($o['body'] ?? null) as $r) {
            $ro = self::obj($r);
            $path = self::str($ro['path'] ?? null);
            $steps = self::parseTtPath($path);
            $action = self::action($ro['action'] ?? null);
            if ($steps === null || $action === null) {
                continue;
            }
            $names = 0;
            foreach ($steps as $st) {
                if ($st[0] === BodyRule::NAME) {
                    $names++;
                }
            }
            $body[] = new BodyRule($path, $steps, $names, $action);
        }
        return new Part(self::nameMap($o['query'] ?? null), self::nameMap($o['headers'] ?? null), self::nameMap($o['cookies'] ?? null), self::nameMap($o['path'] ?? null), $body);
    }

    /** @return array{key: string, method: string, segs: list<array{0: ?string, 1: ?string}>, literals: int}|null */
    public static function parseOpKey(string $key): ?array
    {
        $sp = strpos($key, ' ');
        if ($sp === false || $sp === 0) {
            return null;
        }
        $method = substr($key, 0, $sp);
        $tmpl = substr($key, $sp + 1);
        if ($tmpl === '' || $tmpl[0] !== '/') {
            return null;
        }
        $segs = [];
        $literals = 0;
        foreach (explode('/', $tmpl) as $s) {
            if ($s === '') {
                continue;
            }
            if ($s[0] === '{' && $s[strlen($s) - 1] === '}') {
                $segs[] = [null, substr($s, 1, -1)];
            } else {
                $segs[] = [$s, null];
                $literals++;
            }
        }
        return ['key' => $key, 'method' => $method, 'segs' => $segs, 'literals' => $literals];
    }

    /** Splits a normalized `match.base` into origin and path segments. @return array{0: string, 1: list<string>} */
    public static function splitBase(string $base): array
    {
        if (preg_match('/^([a-z][a-z0-9+.-]*:\/\/[^\/]*)(\/.*)?$/Ds', $base, $m) !== 1) {
            return [$base, []];
        }
        $segs = [];
        foreach (explode('/', $m[2] ?? '') as $s) {
            if ($s !== '') {
                $segs[] = $s;
            }
        }
        return [$m[1], $segs];
    }
}
