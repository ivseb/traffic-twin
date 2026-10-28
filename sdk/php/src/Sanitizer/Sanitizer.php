<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * The sanitizer, docs/spec/sanitizer.md v1.1.1. Input: one normalized exchange (section 1), a
 * verified compiled policy, the local HMAC key and the clock. Output: the canonical object of
 * section 2, or "not sampled".
 *
 * Guiding rule: in doubt, drop. Any exception escaping from here must be treated by the
 * caller as an internal error (no event, `sanitizer_errors` + 1).
 */
final class Sanitizer
{
    public const MAX_EVENT_BYTES = 524288;
    private const SUBJECT_MAX = 8192;

    /** @var callable(): int|null */
    private $rand;

    /**
     * @param array{kid: string, key: string} $key
     * @param (callable(): int)|null $rand returns an integer in 0..9999 (tests); default random_int
     */
    public function __construct(
        public readonly Policy $policy,
        public readonly array $key,
        public readonly ?int $rateOverrideBp = null,
        ?callable $rand = null,
    ) {
        $this->rand = $rand;
    }

    public function mac(string $domain, string $value): string
    {
        return hash_hmac('sha256', $this->policy->epoch . "\0" . $domain . "\0" . $value, $this->key['key'], true);
    }

    public function token(string $domain, string $value): string
    {
        return 'tk1:' . $this->key['kid'] . ':' . Utf8::b64url(substr($this->mac($domain, $value), 0, 16));
    }

    public function rateBp(): int
    {
        return $this->rateOverrideBp !== null ? min($this->rateOverrideBp, $this->policy->rateBp) : $this->policy->rateBp;
    }

    // --- headers (8.0) ---------------------------------------------------------------

    /**
     * Joined value of one exact lowercase header name (subject, baggage).
     *
     * @param list<array{0: string, 1: string}> $list
     */
    public static function headerValue(array $list, string $lower): ?string
    {
        $vals = [];
        foreach ($list as [$n, $v]) {
            if ($n !== '' && $n[0] === ':') {
                continue;
            }
            if (Utf8::lower($n) === $lower) {
                $vals[] = trim($v, " \t");
            }
        }
        if ($vals === []) {
            return null;
        }
        return implode($lower === 'cookie' ? '; ' : ', ', $vals);
    }

    // --- subject (11) ----------------------------------------------------------------

    /** @param list<array{0: string, 1: string}> $reqHeaders */
    public function subjectValue(array $reqHeaders): ?string
    {
        $spec = $this->policy->subject;
        if ($spec === null) {
            return null;
        }
        $raw = null;
        if ($spec['from'] === 'header') {
            $raw = self::headerValue($reqHeaders, Utf8::lower($spec['name']));
        } else {
            $cookie = self::headerValue($reqHeaders, 'cookie');
            if ($cookie !== null) {
                foreach (explode(';', $cookie) as $p) {
                    $piece = trim($p, " \t");
                    $eq = strpos($piece, '=');
                    if ($eq === false) {
                        continue;
                    }
                    if (substr($piece, 0, $eq) === $spec['name'] && Utf8::valid(substr($piece, 0, $eq))) {
                        $raw = substr($piece, $eq + 1);
                        break;
                    }
                }
            }
        }
        if ($raw === null || $raw === '' || strlen($raw) > self::SUBJECT_MAX) {
            return null;
        }
        $s = Utf8::decode($raw);
        if ($s === null || $s === '') {
            return null;
        }
        if ($spec['from'] === 'header' && $spec['json_path'] !== null) {
            return self::jsonMember($s, $spec['json_path']);
        }
        if ($spec['from'] === 'header' && preg_match('/^bearer[ \t]+/i', $s, $m) === 1) {
            $s = substr($s, strlen($m[0]));
            if ($s === '') {
                return null;
            }
        }
        if ($spec['jwt_claim'] === null) {
            return $s;
        }
        $parts = explode('.', $s);
        if (count($parts) !== 3) {
            return null;
        }
        $payload = preg_replace('/={1,2}$/D', '', $parts[1]) ?? '';
        $bytes = Utf8::b64urlDecode($payload);
        if ($bytes === null) {
            return null;
        }
        try {
            $doc = Json::parse($bytes, 64);
        } catch (JsonError) {
            return null;
        }
        if (!$doc instanceof JObj) {
            return null;
        }
        $v = null;
        foreach ($doc->m as [$k, $val]) {
            if (!$k->bad && $k->s === $spec['jwt_claim']) {
                $v = $val;
            }
        }
        if ($v === null) {
            return null;
        }
        if ($v instanceof JStr) {
            return $v->s !== '' && !$v->bad ? $v->s : null;
        }
        if ($v instanceof JNum) {
            return Json::lexemeWithinLimits($v->lex) ? Json::canonicalNumber($v->lex) : null;
        }
        return null;
    }

    /**
     * Standard or URL-safe base64 (never mixed), with or without padding (at most two '=' at the end, then a length
     * that is a multiple of 4). Null on any other character or an impossible length.
     */
    private static function b64Any(string $s): ?string
    {
        $body = rtrim($s, '=');
        $pad = strlen($s) - strlen($body);
        $n = strlen($body);
        if ($n === 0 || $pad > 2 || ($pad > 0 && strlen($s) % 4 !== 0) || $n % 4 === 1) {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_+\/-]+$/D', $body) !== 1) {
            return null;
        }
        $std = strpbrk($body, '+/') !== false;
        if ($std && strpbrk($body, '-_') !== false) {
            return null;
        }
        if (!$std) {
            $body = strtr($body, '-_', '+/');
        }
        $out = base64_decode($body . str_repeat('=', (4 - $n % 4) % 4), true);
        return $out === false ? null : $out;
    }

    /**
     * Spec v1.18 (sanitizer.md 11, step 4 bis): the subject is a member of a header whose value is a JSON object, or
     * base64/base64url of one. No bearer prefix is stripped; the dot always separates members.
     */
    private static function jsonMember(string $s, string $path): ?string
    {
        $t = trim($s, " \t");
        if ($t === '') {
            return null;
        }
        $bytes = $t[0] === '{' ? $t : self::b64Any($t);
        if ($bytes === null) {
            return null;
        }
        try {
            $v = Json::parse($bytes, 64);
        } catch (JsonError) {
            return null;
        }
        foreach (explode('.', $path) as $name) {
            if (!$v instanceof JObj) {
                return null;
            }
            $found = null;
            foreach ($v->m as [$k, $val]) {
                if (!$k->bad && $k->s === $name) {
                    $found = $val;
                }
            }
            if ($found === null) {
                return null;
            }
            $v = $found;
        }
        if ($v instanceof JStr) {
            return $v->s !== '' && !$v->bad ? $v->s : null;
        }
        if ($v instanceof JNum) {
            return Json::lexemeWithinLimits($v->lex) ? Json::canonicalNumber($v->lex) : null;
        }
        return null;
    }

    // --- sampling (12) ---------------------------------------------------------------

    private function hashSample(string $domain, string $value): bool
    {
        $u = unpack('N', substr($this->mac($domain, $value), 0, 4));
        return $u[1] % 10000 < $this->rateBp();
    }

    private function randomSample(): bool
    {
        $rate = $this->rateBp();
        if ($rate <= 0) {
            return false;
        }
        if ($rate >= 10000) {
            return true;
        }
        return ($this->rand !== null ? ($this->rand)() : random_int(0, 9999)) < $rate;
    }

    /** Sampling decision for an exchange (needs only the request line and the request headers). */
    public function decide(Exchange $ex): Decision
    {
        return $this->decideWith($ex, $this->subjectValue($ex->reqHeaders));
    }

    public function decideWith(Exchange $ex, ?string $subject): Decision
    {
        if ($ex->dir === 'inbound') {
            $svc = $ex->serviceName !== null ? ($this->policy->inbound[$ex->serviceName] ?? null) : null;
            if ($this->policy->trustBaggage && $svc !== null && $svc->internal) {
                $bag = self::headerValue($ex->reqHeaders, 'baggage');
                $s = $bag !== null ? Utf8::decode($bag) : null;
                if ($s !== null) {
                    foreach (explode(',', $s) as $member) {
                        $kv = trim(explode(';', $member, 2)[0], " \t");
                        $eq = strpos($kv, '=');
                        if ($eq === false) {
                            continue;
                        }
                        $k = trim(substr($kv, 0, $eq), " \t");
                        $v = trim(substr($kv, $eq + 1), " \t");
                        if ($k === 'tt.s' && ($v === '0' || $v === '1')) {
                            return new Decision($v === '1', 'baggage');
                        }
                    }
                }
            }
            if ($subject !== null && $subject !== '') {
                return new Decision($this->hashSample('sample', $subject), 'subject');
            }
        } elseif ($ex->inherited !== null) {
            return new Decision($ex->inherited, 'inherited');
        }
        if ($ex->traceId !== null && $ex->traceId !== '') {
            return new Decision($this->hashSample('sample-trace', Utf8::lower($ex->traceId)), 'trace');
        }
        return new Decision($this->randomSample(), 'random');
    }

    // --- whole exchange --------------------------------------------------------------

    /** Sanitizes one exchange. $now is the source clock in milliseconds. */
    public function run(Exchange $ex, ?int $now, ?Decision $decision = null): Result
    {
        // A-SUBJECT-OUTBOUND: the subject token is also emitted for outbound exchanges, but only
        // inbound sampling uses it.
        $subject = $this->subjectValue($ex->reqHeaders);
        $d = $decision ?? $this->decideWith($ex, $subject);
        if (!$d->sampled) {
            return new Result('not_sampled', $d->by);
        }
        $out = (new Run($this, $ex, $now))->build($d->by, $subject);
        $parts = [];
        foreach ($out->m as $k => $v) {
            $parts[(string) $k] = Json::write($v);
        }
        $canonical = self::compose($parts);
        // 10.3, measured on the sanitizer output (A-EVENT-SIZE-BASE). Canonical output is ASCII.
        if (strlen($canonical) > self::MAX_EVENT_BYTES) {
            foreach (['req', 'resp', 'disc'] as $k) {
                $changed = false;
                if ($k === 'disc') {
                    if (isset($out->m['disc'])) {
                        unset($out->m['disc'], $parts['disc']);
                        $changed = true;
                    }
                } elseif (($out->m[$k] ?? null) instanceof Obj && array_key_exists('body', $out->m[$k]->m)) {
                    $out->m[$k]->m['body'] = 'trunc:size';
                    $parts[$k] = Json::write($out->m[$k]);
                    $changed = true;
                }
                if (!$changed) {
                    continue;
                }
                $canonical = self::compose($parts);
                if (strlen($canonical) <= self::MAX_EVENT_BYTES) {
                    break;
                }
            }
            if (strlen($canonical) > self::MAX_EVENT_BYTES) {
                return new Result('too_large', $d->by);
            }
        }
        return new Result('event', $d->by, $canonical, $parts);
    }

    /**
     * tt-cjson object from already serialized members (keys sorted by bytes).
     *
     * @param array<string, string> $parts
     */
    public static function compose(array $parts): string
    {
        ksort($parts, SORT_STRING);
        $s = '{';
        $first = true;
        foreach ($parts as $k => $v) {
            $s .= ($first ? '' : ',') . Json::writeString((string) $k) . ':' . $v;
            $first = false;
        }
        return $s . '}';
    }
}
