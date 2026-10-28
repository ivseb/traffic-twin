<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Executes one conformance vector (conformance/format.md, "Executing a vector"). This is the
 * test function every source must expose (sanitizer.md 16). Needs ext-sodium for vectors with
 * a signed envelope.
 */
final class VectorRunner
{
    /** Parses a vector file (bytes) with the lexeme-preserving parser. */
    public static function parse(string $bytes): PObj
    {
        $v = Json::toPlain(Json::parse($bytes), false);
        if (!$v instanceof PObj) {
            throw new \RuntimeException('vector is not an object');
        }
        return $v;
    }

    private static function bytes(mixed $v): string
    {
        if ($v === null) {
            return '';
        }
        if (is_string($v)) {
            return $v;
        }
        if ($v instanceof PObj && is_string($v->m['b64'] ?? null)) {
            $r = base64_decode($v->m['b64'], true);
            if ($r === false) {
                throw new \RuntimeException('bad b64');
            }
            return $r;
        }
        throw new \RuntimeException('bad bytes value');
    }

    private static function num(mixed $v): ?int
    {
        return $v instanceof Lex ? (int) $v->lex : null;
    }

    /** @return int|string|null */
    private static function total(mixed $v): int|string|null
    {
        return $v === 'unknown' ? 'unknown' : self::num($v);
    }

    private static function bool(mixed $v): ?bool
    {
        return is_bool($v) ? $v : null;
    }

    /** @return list<array{0: string, 1: string}> */
    private static function headers(mixed $v): array
    {
        $out = [];
        if (is_array($v)) {
            foreach ($v as $pair) {
                $out[] = [(string) $pair[0], self::bytes($pair[1])];
            }
        }
        return $out;
    }

    /** Converts the `input` object of a vector into a sanitizer exchange. */
    public static function exchange(PObj $input): Exchange
    {
        $i = $input->m;
        $ex = new Exchange();
        $ex->dir = (string) ($i['dir'] ?? 'inbound');
        $ex->method = (string) ($i['method'] ?? '');
        $ex->rawPath = self::bytes($i['raw_path'] ?? null);
        $ex->rawQuery = array_key_exists('raw_query', $i) ? self::bytes($i['raw_query']) : null;
        $ex->reqHeaders = self::headers($i['req_headers'] ?? null);
        $ex->reqBody = self::bytes($i['req_body'] ?? null);
        $ex->reqBodyTotal = self::total($i['req_body_total'] ?? null);
        $ex->reqBodyConsumed = self::bool($i['req_body_consumed'] ?? null);
        $ex->reqBodyDecoded = self::bool($i['req_body_decoded'] ?? null);
        $ex->respHeaders = self::headers($i['resp_headers'] ?? null);
        $ex->respBody = self::bytes($i['resp_body'] ?? null);
        $ex->respBodyTotal = self::total($i['resp_body_total'] ?? null);
        $ex->respBodyConsumed = self::bool($i['resp_body_consumed'] ?? null);
        $ex->respBodyDecoded = self::bool($i['resp_body_decoded'] ?? null);
        $ex->serviceName = is_string($i['service_name'] ?? null) ? $i['service_name'] : null;
        $ex->urlBase = is_string($i['url_base'] ?? null) ? $i['url_base'] : null;
        $ex->frameworkRoute = is_string($i['framework_route'] ?? null) ? $i['framework_route'] : null;
        $ex->framework = is_string($i['framework'] ?? null) ? $i['framework'] : null;
        $ex->traceId = is_string($i['trace_id'] ?? null) ? $i['trace_id'] : null;
        $ex->inherited = is_bool($i['inherited'] ?? null) ? $i['inherited'] : null;
        $ex->status = self::num($i['status'] ?? null);
        $ex->netError = is_string($i['net_error'] ?? null) ? $i['net_error'] : null;
        return $ex;
    }

    /**
     * Runs one parsed vector. $root is the conformance/ directory (for policy_ref).
     *
     * @return array{outcome: string, canonical?: string, sampled_by?: string, code?: string}
     */
    public static function run(PObj $vec, string $root): array
    {
        $v = $vec->m;
        $now = is_string($v['now'] ?? null) ? Time::parse($v['now']) : null;
        try {
            if (isset($v['policy_envelope'])) {
                $keys = [];
                $fk = $v['fleet_keys'] ?? null;
                if ($fk instanceof PObj) {
                    foreach ($fk->m as $kid => $pub) {
                        $raw = is_string($pub) ? Envelope::publicKey($pub) : null;
                        if ($raw !== null) {
                            $keys[(string) $kid] = $raw;
                        }
                    }
                }
                $body = Envelope::verify($v['policy_envelope'], $keys, true)['body'];
            } elseif (isset($v['policy_ref']) && is_string($v['policy_ref'])) {
                $bytes = file_get_contents($root . '/' . $v['policy_ref']);
                if ($bytes === false) {
                    throw new \RuntimeException('policy_ref unreadable');
                }
                $body = PolicySchema::validate(Json::toPlain(Json::parse($bytes), true));
            } elseif (isset($v['policy'])) {
                $body = PolicySchema::validate($v['policy']);
            } else {
                throw new Refused('no_policy');
            }
            $policy = new Policy($body);
            Envelope::checkAcceptance(
                $policy,
                is_string($v['source_group'] ?? null) ? $v['source_group'] : '',
                $now ?? PHP_INT_MIN,
                self::num($v['last_issued_seq'] ?? null) ?? 0,
                self::num($v['min_issued_seq'] ?? null) ?? 0,
            );
            $ring = KeyRing::parse(is_string($v['hmac_key'] ?? null) ? $v['hmac_key'] : null);
            $sanitizer = new Sanitizer($policy, $ring->select($policy));
        } catch (Refused $e) {
            return ['outcome' => 'refused', 'code' => $e->reason];
        }
        $input = $v['input'] ?? null;
        if (!$input instanceof PObj) {
            throw new \RuntimeException('vector without input');
        }
        $r = $sanitizer->run(self::exchange($input), $now);
        if ($r->outcome === 'not_sampled') {
            return ['outcome' => 'not_sampled', 'sampled_by' => $r->sampledBy];
        }
        if ($r->outcome === 'too_large') {
            return ['outcome' => 'refused', 'code' => 'event_too_large'];
        }
        return ['outcome' => 'event', 'canonical' => $r->canonical];
    }
}
