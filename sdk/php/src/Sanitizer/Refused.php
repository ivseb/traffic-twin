<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** The source must not capture: no_policy, policy_rejected, expired_policy, key_missing, key_mismatch. */
final class Refused extends \RuntimeException
{
    /** Detail prefix of a refusal raised by the v1.3 safety subset (hardening.md 2); reported as policy_unsafe. */
    public const UNSAFE = 'unsafe';

    public function __construct(public readonly string $reason, public readonly string $detail = '')
    {
        parent::__construct($reason . ($detail !== '' ? ': ' . $detail : ''));
    }

    /** True when the policy was refused by the safety subset H1 to H3 (hardening.md 2.1). */
    public function isUnsafe(): bool
    {
        return str_starts_with($this->detail, self::UNSAFE);
    }
}
