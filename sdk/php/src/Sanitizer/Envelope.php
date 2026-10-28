<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Signed envelope verification (policy.md 3, conditions 1-2 of 4) and the acceptance checks
 * of conditions 3-5. Ed25519 comes from ext-sodium; without it nothing can be verified and
 * the source refuses to capture (fail closed).
 */
final class Envelope
{
    public const FORMAT = 'tt.policy.compiled/v1';
    public const SIGNATURE_PREFIX = "tt.policy.body/v1\0";

    public static function sodiumAvailable(): bool
    {
        return function_exists('sodium_crypto_sign_verify_detached');
    }

    /** Raw 32-byte Ed25519 public key from its base64url form; null if malformed. */
    public static function publicKey(string $b64url): ?string
    {
        $raw = Utf8::b64urlDecode($b64url);
        return $raw !== null && strlen($raw) === 32 ? $raw : null;
    }

    /**
     * @param array<string, string> $keys pinned, non-revoked signature kid => raw public key
     * @return array{bodyBytes: string, body: PObj, hash: string}
     * @throws Refused policy_rejected
     */
    public static function verify(mixed $env, array $keys, bool $strict): array
    {
        $reject = static function (string $why): never {
            throw new Refused('policy_rejected', $why);
        };
        if (!self::sodiumAvailable()) {
            $reject('ext-sodium missing');
        }
        if (!$env instanceof PObj) {
            $reject('envelope');
        }
        $e = $env->m;
        if ($strict) {
            foreach (array_keys($e) as $k) {
                if (!in_array((string) $k, ['format', 'policy_id', 'version', 'issued_seq', 'hash', 'body_b64', 'signature'], true)) {
                    $reject('envelope field');
                }
            }
        }
        if (($e['format'] ?? null) !== self::FORMAT) {
            $reject('envelope format');
        }
        $sig = $e['signature'] ?? null;
        if (!$sig instanceof PObj || ($sig->m['alg'] ?? null) !== 'Ed25519' || !is_string($sig->m['kid'] ?? null) || !is_string($sig->m['sig'] ?? null)) {
            $reject('signature');
        }
        $pub = $keys[$sig->m['kid']] ?? null;
        if ($pub === null) {
            $reject('unknown kid');
        }
        $b64 = $e['body_b64'] ?? null;
        if (!is_string($b64)) {
            $reject('body_b64');
        }
        $bodyBytes = Utf8::b64urlDecode($b64);
        if ($bodyBytes === null || $bodyBytes === '') {
            $reject('body_b64');
        }
        $hash = 'sha256:' . hash('sha256', $bodyBytes);
        if (($e['hash'] ?? null) !== $hash) {
            $reject('hash');
        }
        $sigBytes = Utf8::b64urlDecode($sig->m['sig']);
        if ($sigBytes === null || strlen($sigBytes) !== 64) {
            $reject('signature encoding');
        }
        try {
            $ok = sodium_crypto_sign_verify_detached($sigBytes, self::SIGNATURE_PREFIX . $bodyBytes, $pub);
        } catch (\Throwable) {
            $ok = false;
        }
        if (!$ok) {
            $reject('signature');
        }
        try {
            $plain = Json::toPlain(Json::parse($bodyBytes, 64), true);
        } catch (JsonError) {
            $reject('body json');
        }
        $body = $strict ? PolicySchema::validate($plain) : self::checkBodyMinimal($plain);
        $same = static fn (mixed $a, mixed $b): bool => $a instanceof Lex && $b instanceof Lex ? $a->lex === $b->lex : $a === $b;
        if (!$same($e['policy_id'] ?? null, $body->m['policy_id'] ?? null)) {
            $reject('policy_id mismatch');
        }
        if (!$same($e['version'] ?? null, $body->m['version'] ?? null)) {
            $reject('version mismatch');
        }
        if (($strict || isset($e['issued_seq']) || isset($body->m['issued_seq'])) && !$same($e['issued_seq'] ?? null, $body->m['issued_seq'] ?? null)) {
            $reject('issued_seq mismatch');
        }
        if ($strict && ($body->m['format'] ?? null) !== PolicySchema::BODY_FORMAT) {
            $reject('body format');
        }
        self::checkBodyMinimal($body);
        return ['bodyBytes' => $bodyBytes, 'body' => $body, 'hash' => $hash];
    }

    /** Minimal body checks of the conformance runner (format.md, step 1): format, reserved domains, v1.3 safety subset. */
    public static function checkBodyMinimal(mixed $body): PObj
    {
        if (!$body instanceof PObj || ($body->m['format'] ?? null) !== PolicySchema::BODY_FORMAT) {
            throw new Refused('policy_rejected', 'body format');
        }
        foreach (self::actions($body->m) as $a) {
            if (($a->m['action'] ?? null) === 'hmac' && is_string($a->m['domain'] ?? null) && isset(PolicySchema::RESERVED_DOMAINS[$a->m['domain']])) {
                throw new Refused('policy_rejected', 'reserved domain');
            }
        }
        PolicySchema::checkUnsafe($body);
        return $body;
    }

    /** @param array<string, mixed> $body @return \Generator<PObj> */
    private static function actions(array $body): \Generator
    {
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
        $collect($body['global'] ?? null, ['request', 'response', 'errors']);
        foreach (is_array($body['services'] ?? null) ? $body['services'] : [] as $svc) {
            $collect($svc, ['request', 'response', 'errors']);
            if ($svc instanceof PObj && is_array($svc->m['ops'] ?? null)) {
                foreach ($svc->m['ops'] as $op) {
                    $collect($op, ['request', 'response']);
                }
            }
        }
        foreach ($parts as $p) {
            foreach (['query', 'headers', 'cookies', 'path'] as $sec) {
                $m = $p->m[$sec] ?? null;
                if ($m instanceof PObj) {
                    foreach ($m->m as $a) {
                        if ($a instanceof PObj) {
                            yield $a;
                        }
                    }
                }
            }
            if (is_array($p->m['body'] ?? null)) {
                foreach ($p->m['body'] as $r) {
                    if ($r instanceof PObj && ($r->m['action'] ?? null) instanceof PObj) {
                        yield $r->m['action'];
                    }
                }
            }
        }
    }

    /**
     * policy.md 4, conditions 3-5: group, expiry, issued_seq ordering. $allowEqualSeq lets a
     * source re-verify the very policy it already accepted (cache at start-up).
     *
     * @throws Refused
     */
    public static function checkAcceptance(Policy $p, string $group, int $now, int $lastIssuedSeq, int $minIssuedSeq, bool $allowEqualSeq = false): void
    {
        if (!in_array($group, $p->groups, true)) {
            throw new Refused('policy_rejected', 'group');
        }
        if ($p->notAfter === null || !($now < $p->notAfter)) {
            throw new Refused('expired_policy');
        }
        $fresh = $allowEqualSeq ? $p->issuedSeq >= $lastIssuedSeq : $p->issuedSeq > $lastIssuedSeq;
        if (!$fresh) {
            throw new Refused('policy_rejected', 'issued_seq replay');
        }
        if ($p->issuedSeq < $minIssuedSeq) {
            throw new Refused('policy_rejected', 'issued_seq below minimum');
        }
    }
}
