<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

use Closure;
use TrafficTwin\Capture\Headers;
use TrafficTwin\Capture\Inbound;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Exchange;

/**
 * Inbound capture for Laravel (global or group middleware; Laravel has no PSR-15 pipeline).
 * Duck-typed on `Illuminate\Http\Request` / `Symfony\Component\HttpFoundation\Response`:
 * the SDK does not depend on Laravel. The route template is `$request->route()->uri()`, which
 * includes group prefixes (sanitizer.md 3.4, Laravel row).
 *
 *     // bootstrap/app.php (Laravel 11) or app/Http/Kernel.php
 *     $middleware->prepend(\TrafficTwin\Integration\LaravelMiddleware::class);
 *
 * The response is sent by Laravel first; sanitization runs in a shutdown function afterwards
 * (after fastcgi_finish_request() under PHP-FPM).
 */
final class LaravelMiddleware
{
    public function __construct(private ?Runtime $runtime = null)
    {
    }

    public function handle(object $request, Closure $next): mixed
    {
        $rt = $this->runtime ?? Runtime::get();
        $in = null;
        try {
            if ($rt->sanitizer() !== null) {
                $in = Inbound::begin($rt, Headers::fromRequestBag($request->headers->all()));
            }
        } catch (\Throwable) {
            $in = null;
        }
        if ($in === null) {
            return $next($request);
        }
        try {
            $response = $next($request);
        } catch (\Throwable $e) {
            $in->end();
            throw $e;
        }
        try {
            if ($in->sampled()) {
                $t = hrtime(true);
                $this->capture($in, $request, $response);
                $in->addOverhead(hrtime(true) - $t);
            }
        } catch (\Throwable) {
            $rt->counters->error('capture_inbound_finish');
        } finally {
            $in->end();
        }
        return $response;
    }

    private function capture(Inbound $in, object $request, object $response): void
    {
        $limit = $in->bodyLimit();
        $status = (int) $response->getStatusCode();
        $method = (string) $request->getMethod();
        $noBody = $method === 'HEAD' || $status === 204 || $status === 304 || ($status >= 100 && $status < 200);

        $reqBody = '';
        $reqConsumed = true;
        try {
            $reqBody = (string) $request->getContent();
        } catch (\Throwable) {
            $reqConsumed = false;
        }
        $reqTotal = strlen($reqBody);
        $cl = $request->headers->get('content-length');
        if ($reqTotal === 0 && is_string($cl) && ctype_digit($cl) && (int) $cl > 0) {
            // The SAPI consumed the body itself (multipart/form-data parsed into $_POST/$_FILES): "not consumed".
            $reqConsumed = false;
        }
        $reqPrefix = substr($reqBody, 0, $limit);
        unset($reqBody);

        $respPrefix = '';
        $respTotal = 0;
        if (!$noBody) {
            $content = $response->getContent();
            if (is_string($content)) {
                $respTotal = strlen($content);
                $respPrefix = substr($content, 0, $limit);
            } else {
                $respTotal = 'unknown'; // streamed / file responses
            }
        }
        $reqHeaders = Headers::fromRequestBag($request->headers->all());
        $respHeaders = $this->responseHeaders($response);
        $route = null;
        $fw = null;
        try {
            $r = Routes::laravel(method_exists($request, 'route') ? $request->route() : null);
            if ($r !== null) {
                [$fw, $route] = $r;
            }
        } catch (\Throwable) {
            $route = null;
        }
        $service = $in->rt->serviceName();
        $traceId = $in->ctx->traceKnown ? $in->ctx->traceId : null;
        $rawPath = $this->rawPath($request);
        $rawQuery = (string) $request->server->get('QUERY_STRING', '');
        $build = static function () use ($service, $method, $rawPath, $rawQuery, $fw, $route, $traceId, $reqHeaders, $reqPrefix, $reqTotal, $reqConsumed, $status, $respHeaders, $respPrefix, $respTotal): Exchange {
            $ex = new Exchange();
            $ex->dir = 'inbound';
            $ex->serviceName = $service;
            $ex->method = $method;
            $ex->rawPath = $rawPath;
            $ex->rawQuery = $rawQuery === '' ? null : $rawQuery;
            if ($route !== null) {
                $ex->framework = $fw;
                $ex->frameworkRoute = $route;
            }
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
        };
        $in->submit($build, $status, strlen($reqPrefix) + strlen($respPrefix));
    }

    /** The request path as sent (not decoded), without the query. */
    private function rawPath(object $request): string
    {
        $uri = (string) $request->server->get('REQUEST_URI', '');
        if ($uri === '') {
            return (string) $request->getPathInfo();
        }
        $q = strpos($uri, '?');
        $path = $q === false ? $uri : substr($uri, 0, $q);
        if (preg_match('#^[a-z][a-z0-9+.-]*://[^/]*#i', $path, $m) === 1) {
            $path = substr($path, strlen($m[0])) ?: '/';
        }
        return $path;
    }

    /** @return list<array{0: string, 1: string}> */
    private function responseHeaders(object $response): array
    {
        // Symfony keeps Set-Cookie as Cookie objects; the bag lists each of them once.
        return Headers::fromResponseBag($response->headers);
    }
}
