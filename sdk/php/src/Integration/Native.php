<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

use TrafficTwin\Capture\Headers;
use TrafficTwin\Capture\Inbound;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Exchange;

/**
 * Inbound capture for plain PHP scripts and legacy frameworks without PSR-7 (WordPress-style
 * front controllers): one call at the very top of the entry point.
 *
 *     \TrafficTwin\Integration\Native::install();   // public/index.php, before anything is sent
 *
 * It reads the request from the SAPI (`getallheaders()` or `$_SERVER`, `php://input`) and the
 * response through an output buffer that passes every byte through unchanged in 8 KiB chunks
 * (so streaming and large downloads keep working; flush() still flushes), plus `headers_list()`
 * and `http_response_code()` at shutdown. There is no `framework_route`: templates come from the
 * policy. Header names are the ones PHP exposes (see Headers).
 */
final class Native
{
    private const CHUNK = 8192;

    private static ?Inbound $in = null;
    private static int $level = 0;
    private static string $prefix = '';
    private static int $total = 0;
    private static int $limit = 0;

    public static function install(?Runtime $rt = null): void
    {
        if (self::$in !== null || !isset($_SERVER['REQUEST_METHOD'])) {
            return;
        }
        $rt ??= Runtime::get();
        try {
            if ($rt->sanitizer() === null) {
                return;
            }
            $in = Inbound::begin($rt, Headers::fromGlobals());
        } catch (\Throwable) {
            return;
        }
        if ($in === null) {
            return;
        }
        self::$in = $in;
        self::$prefix = '';
        self::$total = 0;
        self::$limit = $in->bodyLimit();
        if ($in->sampled()) {
            ob_start([self::class, 'tap'], self::CHUNK);
            self::$level = ob_get_level();
        }
        register_shutdown_function([self::class, 'finish']);
    }

    /** Output-buffer callback: keeps the first bytes and counts the rest, sends everything on untouched. */
    public static function tap(string $chunk, int $phase): string|false
    {
        $n = strlen($chunk);
        if ($n > 0) {
            $room = self::$limit - strlen(self::$prefix);
            if ($room > 0) {
                self::$prefix .= substr($chunk, 0, $room);
            }
            self::$total += $n;
        }
        return false; // false: the original chunk is sent as is
    }

    public static function finish(): void
    {
        $in = self::$in;
        self::$in = null;
        if ($in === null) {
            return;
        }
        try {
            if ($in->sampled()) {
                // Push the last bytes through our buffer (and any buffer opened above it).
                while (ob_get_level() >= self::$level && self::$level > 0) {
                    if (!@ob_end_flush()) {
                        break;
                    }
                }
                $t = hrtime(true);
                self::capture($in);
                $in->addOverhead(hrtime(true) - $t);
            }
        } catch (\Throwable) {
            $in->rt->counters->error('capture_inbound_finish');
        } finally {
            $in->end();
        }
    }

    private static function capture(Inbound $in): void
    {
        $limit = $in->bodyLimit();
        $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $reqHeaders = Headers::fromGlobals();
        $cl = $_SERVER['CONTENT_LENGTH'] ?? null;
        $contentLength = is_string($cl) && ctype_digit($cl) ? (int) $cl : null;
        $reqPrefix = '';
        $fh = @fopen('php://input', 'rb');
        if ($fh !== false) {
            $reqPrefix = (string) stream_get_contents($fh, $limit);
            fclose($fh);
        }
        $reqTotal = $contentLength ?? strlen($reqPrefix);
        // PHP consumed the body itself (multipart, or a form parsed into $_POST without php://input):
        // the app has it, we do not. Report "not consumed" rather than an empty body.
        $reqConsumed = !($reqPrefix === '' && $reqTotal > 0);
        $status = http_response_code();
        $status = is_int($status) ? $status : 200;
        $noBody = $method === 'HEAD' || $status === 204 || $status === 304 || ($status >= 100 && $status < 200);
        $respHeaders = [];
        foreach (headers_list() as $line) {
            $c = strpos($line, ':');
            if ($c > 0) {
                $respHeaders[] = [substr($line, 0, $c), trim(substr($line, $c + 1))];
            }
        }
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        if (preg_match('#^[a-z][a-z0-9+.-]*://[^/]*#i', $uri, $m) === 1) {
            $uri = substr($uri, strlen($m[0])) ?: '/';
        }
        $q = strpos($uri, '?');
        $rawPath = $q === false ? $uri : substr($uri, 0, $q);
        $rawQuery = $q === false ? null : substr($uri, $q + 1);
        $respPrefix = $noBody ? '' : self::$prefix;
        $respTotal = $noBody ? 0 : self::$total;
        $service = $in->rt->serviceName();
        $traceId = $in->ctx->traceKnown ? $in->ctx->traceId : null;
        $in->submit(static function () use ($service, $method, $rawPath, $rawQuery, $traceId, $reqHeaders, $reqPrefix, $reqTotal, $reqConsumed, $status, $respHeaders, $respPrefix, $respTotal): Exchange {
            $ex = new Exchange();
            $ex->dir = 'inbound';
            $ex->serviceName = $service;
            $ex->method = $method;
            $ex->rawPath = $rawPath;
            $ex->rawQuery = $rawQuery === '' ? null : $rawQuery;
            $ex->traceId = $traceId;
            $ex->reqHeaders = $reqHeaders;
            $ex->reqBody = $reqPrefix;
            $ex->reqBodyTotal = $reqTotal;
            $ex->reqBodyConsumed = $reqConsumed;
            $ex->status = $status;
            $ex->respHeaders = $respHeaders;
            $ex->respBody = $respPrefix;
            $ex->respBodyTotal = $respTotal;
            return $ex;
        }, $status, strlen($reqPrefix) + strlen($respPrefix));
    }
}
