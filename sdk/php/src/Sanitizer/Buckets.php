<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** bucket(num) and bucket(time) of sanitizer.md 5.5. */
final class Buckets
{
    public static function num(string $lex, Action $a): string
    {
        /** @var list<array{canon: string, d: float}> $b */
        $b = $a->bounds;
        $v = (float) $lex; // correctly rounded; overflow gives INF, underflow gives +-0
        if ($v < $b[0]['d']) {
            return 'num:<' . $b[0]['canon'];
        }
        $n = count($b);
        for ($i = 0; $i + 1 < $n; $i++) {
            if ($v >= $b[$i]['d'] && $v < $b[$i + 1]['d']) {
                return 'num:' . $b[$i]['canon'] . '-' . $b[$i + 1]['canon'];
            }
        }
        return 'num:>=' . $b[$n - 1]['canon'];
    }

    public static function time(string $s, string $unit): ?string
    {
        if (!Formats::isPrintableAscii($s) || (preg_match(Formats::RE_DATETIME, $s) !== 1 && preg_match(Formats::RE_DATE, $s) !== 1)) {
            return null;
        }
        if (preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?$/D', $s, $m) !== 1) {
            return null;
        }
        $y = (int) $m[1];
        $mo = (int) $m[2];
        $d = (int) $m[3];
        $h = (int) ($m[4] ?? 0);
        $mi = (int) ($m[5] ?? 0);
        $se = (int) ($m[6] ?? 0);
        if ($y < 1 || $y > 9999 || $mo < 1 || $mo > 12 || $d < 1) {
            return null;
        }
        $leap = ($y % 4 === 0 && $y % 100 !== 0) || $y % 400 === 0;
        $dim = [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][$mo - 1];
        if ($d > $dim || $h > 23 || $mi > 59 || $se > 59) {
            return null;
        }
        $off = 0;
        if (($m[7] ?? '') !== '') {
            $oh = (int) $m[8];
            $om = (int) $m[9];
            if ($oh > 23 || $om > 59) {
                return null;
            }
            $off = ($oh * 60 + $om) * ($m[7] === '+' ? 1 : -1);
        }
        $total = Time::daysFromCivil($y, $mo, $d) * 1440 + $h * 60 + $mi - $off;
        $days = intdiv($total >= 0 ? $total : $total - 1439, 1440);
        $hour = intdiv($total - $days * 1440, 60);
        [$uy, $um, $ud] = Time::civilFromDays($days);
        if ($uy < 1 || $uy > 9999) {
            return null;
        }
        $ys = sprintf('%04d', $uy);
        return match ($unit) {
            'year' => 'time:' . $ys,
            'month' => sprintf('time:%s-%02d', $ys, $um),
            'day' => sprintf('time:%s-%02d-%02d', $ys, $um, $ud),
            'hour' => sprintf('time:%s-%02d-%02dT%02d', $ys, $um, $ud, $hour),
            default => null,
        };
    }
}
