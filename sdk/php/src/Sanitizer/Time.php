<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** Calendar arithmetic without the process time zone or locale. */
final class Time
{
    public const DAY_MS = 86_400_000;

    public static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** @return array{0: int, 1: int, 2: int} */
    public static function civilFromDays(int $z): array
    {
        $z += 719468;
        $era = intdiv($z >= 0 ? $z : $z - 146096, 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp + ($mp < 10 ? 3 : -9);
        return [$m <= 2 ? $y + 1 : $y, $m, $d];
    }

    /** RFC 3339 timestamp to epoch milliseconds; null when absent or malformed. */
    public static function parse(mixed $v): ?int
    {
        if (!is_string($v)) {
            return null;
        }
        if (preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))$/D', $v, $m) !== 1) {
            return null;
        }
        [$y, $mo, $d, $h, $mi, $s] = [(int) $m[1], (int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], (int) $m[6]];
        if ($mo < 1 || $mo > 12 || $d < 1 || $d > 31 || $h > 23 || $mi > 59 || $s > 60) {
            return null;
        }
        $ms = (self::daysFromCivil($y, $mo, $d) * 86400 + $h * 3600 + $mi * 60 + $s) * 1000;
        if (($m[7] ?? '') !== '') {
            $ms += (int) floor((float) ('0' . $m[7]) * 1000);
        }
        if (($m[9] ?? '') !== '') {
            $off = ((int) $m[10] * 60 + (int) $m[11]) * 60_000;
            $ms += $m[9] === '+' ? -$off : $off;
        }
        return $ms;
    }

    /** RFC 3339 UTC with milliseconds (event.md ts). */
    public static function iso(int $ms): string
    {
        return gmdate('Y-m-d\TH:i:s', intdiv($ms, 1000)) . sprintf('.%03dZ', $ms % 1000);
    }
}
