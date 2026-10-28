<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** An XML or multipart body outside the accepted subset (sanitizer.md 22.2, 22.3). */
final class BodyError extends \Exception
{
}
