<?php

declare(strict_types=1);

namespace TrafficTwin\Shipper;

/** A Fleet failure: the code is a short identifier, never a payload value. */
final class FleetError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly ?int $httpStatus = null)
    {
        parent::__construct($errorCode);
    }
}
