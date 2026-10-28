<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** The local HMAC key material (sanitizer.md 7.1): one or more `<kid>:<base64url>` lines. */
final class KeyRing
{
    /**
     * @param array<string, string> $keys kid => key bytes
     * @param list<string> $order kids in file order
     */
    private function __construct(public readonly array $keys, public readonly array $order)
    {
    }

    /** Parses the content of TT_HMAC_KEY / TT_HMAC_KEY_FILE. @throws Refused key_missing */
    public static function parse(?string $text): self
    {
        if ($text === null) {
            throw new Refused('key_missing', 'absent');
        }
        $keys = [];
        $order = [];
        foreach (explode("\n", $text) as $line) {
            if (str_ends_with($line, "\r")) {
                $line = substr($line, 0, -1);
            }
            if ($line === '') {
                continue;
            }
            $c = strpos($line, ':');
            if ($c === false) {
                throw new Refused('key_missing', 'malformed');
            }
            $kid = substr($line, 0, $c);
            if (preg_match('/^[a-z0-9]{1,8}$/D', $kid) !== 1) {
                throw new Refused('key_missing', 'kid');
            }
            $raw = Utf8::b64urlDecode(substr($line, $c + 1));
            if ($raw === null || strlen($raw) < 32) {
                throw new Refused('key_missing', 'key bytes');
            }
            if (!isset($keys[$kid])) {
                $keys[$kid] = $raw;
                $order[] = $kid;
            }
        }
        if ($keys === []) {
            throw new Refused('key_missing', 'empty');
        }
        return new self($keys, $order);
    }

    /** 7.1: picks the key for a policy (hmac.kid, then accept_kids in order). @return array{kid: string, key: string} @throws Refused key_mismatch */
    public function select(Policy $policy): array
    {
        if (isset($this->keys[$policy->kid])) {
            return ['kid' => $policy->kid, 'key' => $this->keys[$policy->kid]];
        }
        foreach ($policy->acceptKids as $kid) {
            if (isset($this->keys[$kid])) {
                return ['kid' => $kid, 'key' => $this->keys[$kid]];
            }
        }
        throw new Refused('key_mismatch');
    }
}
