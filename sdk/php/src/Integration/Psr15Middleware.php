<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TrafficTwin\Capture\Headers;
use TrafficTwin\Capture\Inbound;
use TrafficTwin\Capture\TeeStream;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Exchange;

/**
 * Inbound capture as a PSR-15 middleware.
 *
 * Put it as far out in the pipeline as you can (after your error handler if you want 500
 * responses captured; an exception that escapes the pipeline produces no response, so no event).
 * It never changes the request, the response or their timing apart from replacing a
 * non-seekable body with a decorator that passes every byte through unchanged.
 *
 * `framework_route` (sanitizer.md 3.3, 3.4) comes from the optional route resolver, a callable
 * `fn(ServerRequestInterface $request): ?array` returning `[framework, route]`, for example
 * `['laravel', '/api/orders/{id}']`. The resolver runs after the handler returns, with the
 * request as this middleware received it: attributes added downstream by a router are not
 * visible through PSR-7 immutability, so resolve through the framework's own objects (see
 * {@see Routes}) or place this middleware after a routing middleware that sets an attribute.
 * The route must include every mount prefix; if you cannot provide it, return null.
 */
final class Psr15Middleware implements MiddlewareInterface
{
    /** @param (\Closure(ServerRequestInterface): ?array{0: string, 1: string})|null $routeResolver */
    public function __construct(private ?Runtime $runtime = null, private ?\Closure $routeResolver = null)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $rt = $this->runtime ?? Runtime::get();
        $headers = null;
        $in = null;
        try {
            if ($rt->sanitizer() !== null) {
                $headers = Headers::fromMap($request->getHeaders());
                $in = Inbound::begin($rt, $headers);
            }
        } catch (\Throwable) {
            $in = null;
        }
        if ($in === null) {
            return $handler->handle($request);
        }
        if (!$in->sampled()) {
            try {
                return $handler->handle($request);
            } finally {
                $in->end();
            }
        }

        $limit = $in->bodyLimit();
        $entry = $request;
        $reqTee = null;
        try {
            $body = $request->getBody();
            if ($body->getSize() !== 0) {
                $reqTee = new TeeStream($body, $limit);
                $request = $request->withBody($reqTee);
            }
        } catch (\Throwable) {
            $reqTee = null;
            $request = $entry;
        }

        try {
            $response = $handler->handle($request);
        } catch (\Throwable $e) {
            $in->end();
            throw $e;
        }

        try {
            $t = hrtime(true);
            $response = $this->finish($in, $entry, $headers ?? [], $reqTee, $response, $limit);
            $in->addOverhead(hrtime(true) - $t);
        } catch (\Throwable) {
            $rt->counters->error('capture_inbound_finish');
        } finally {
            $in->end();
        }
        return $response;
    }

    /** @param list<array{0: string, 1: string}> $reqHeaders */
    private function finish(Inbound $in, ServerRequestInterface $entry, array $reqHeaders, ?TeeStream $reqTee, ResponseInterface $response, int $limit): ResponseInterface
    {
        $status = $response->getStatusCode();
        $method = $entry->getMethod();
        $noBody = $method === 'HEAD' || $status === 204 || $status === 304 || ($status >= 100 && $status < 200);

        // Response body: seekable streams are read now (an emitter may close them afterwards);
        // others are decorated and read when the sanitizer runs.
        $respPrefix = '';
        $respTotal = 0;
        $respTee = null;
        if (!$noBody) {
            $rb = $response->getBody();
            [$respPrefix, $respTotal, $respTee] = self::peek($rb, $limit, $in->rt->deferMode !== 'now');
            if ($respTee !== null) {
                $response = $response->withBody($respTee);
            }
        }

        $uri = $entry->getUri();
        $rawPath = $uri->getPath();
        $q = $uri->getQuery();
        $rawQuery = $q === '' ? null : $q;
        $framework = null;
        $route = null;
        if ($this->routeResolver !== null) {
            try {
                $r = ($this->routeResolver)($entry);
                if (is_array($r) && isset($r[0], $r[1]) && is_string($r[0]) && is_string($r[1])) {
                    [$framework, $route] = $r;
                }
            } catch (\Throwable) {
                $framework = $route = null;
            }
        }
        $respHeaders = Headers::fromMap($response->getHeaders());
        $clHeader = Headers::first($reqHeaders, 'content-length');
        $contentLength = $clHeader !== null && ctype_digit($clHeader) ? (int) $clHeader : null;
        $service = $in->rt->serviceName();
        $traceId = $in->ctx->traceKnown ? $in->ctx->traceId : null;
        $held = strlen($respPrefix) + ($reqTee !== null ? min($limit, $contentLength ?? 0) : 0);

        $build = static function () use (
            $service, $method, $rawPath, $rawQuery, $framework, $route, $traceId, $reqHeaders, $reqTee,
            $contentLength, $status, $respHeaders, $respPrefix, $respTotal, $respTee, $noBody
        ): Exchange {
            $ex = new Exchange();
            $ex->dir = 'inbound';
            $ex->serviceName = $service;
            $ex->method = $method;
            $ex->rawPath = $rawPath;
            $ex->rawQuery = $rawQuery;
            if ($route !== null) {
                $ex->framework = $framework;
                $ex->frameworkRoute = $route;
            }
            $ex->traceId = $traceId;
            $ex->reqHeaders = $reqHeaders;
            if ($reqTee === null) {
                $ex->reqBody = '';
                $ex->reqBodyTotal = 0;
                // An empty stream with a declared length: the SAPI consumed the body itself (multipart/form-data
                // parsed into $_POST/$_FILES). Report "not consumed" (trunc:size), never an empty body.
                $ex->reqBodyConsumed = !($contentLength !== null && $contentLength > 0);
            } else {
                $total = $reqTee->total();
                $ex->reqBody = $reqTee->prefix();
                $ex->reqBodyTotal = $total ?? 'unknown';
                $ex->reqBodyConsumed = $total !== null && $reqTee->consumed();
                if ($total === 0 && $contentLength === 0) {
                    $ex->reqBodyConsumed = true;
                }
            }
            $ex->status = $status;
            $ex->respHeaders = $respHeaders;
            if ($respTee !== null) {
                $total = $respTee->total();
                $ex->respBody = $respTee->prefix();
                $ex->respBodyTotal = $total ?? 'unknown';
                $ex->respBodyConsumed = $total !== null && $respTee->consumed();
            } else {
                $ex->respBody = $respPrefix;
                $ex->respBodyTotal = $respTotal;
                $ex->respBodyConsumed = true;
            }
            return $ex;
        };
        $in->submit($build, $status, $held);
        return $response;
    }

    /**
     * Reads the first $limit bytes of a seekable body without moving its position, or wraps a
     * non-seekable one (only when $tee: the wrapper is read later, so it needs deferred
     * sanitization). Returns [prefix, total or 'unknown', tee or null].
     *
     * @return array{0: string, 1: int|string, 2: ?TeeStream}
     */
    public static function peek(StreamInterface $body, int $limit, bool $tee = true): array
    {
        $size = $body->getSize();
        if ($size === 0) {
            return ['', 0, null];
        }
        if ($body->isSeekable() && $body->isReadable()) {
            $pos = $body->tell();
            $body->rewind();
            $prefix = '';
            while (strlen($prefix) < $limit && !$body->eof()) {
                $chunk = $body->read($limit - strlen($prefix));
                if ($chunk === '') {
                    break;
                }
                $prefix .= $chunk;
            }
            $body->seek($pos);
            if ($size !== null) {
                return [$prefix, $size, null];
            }
            return [$prefix, strlen($prefix) < $limit ? strlen($prefix) : 'unknown', null];
        }
        return ['', 'unknown', $tee ? new TeeStream($body, $limit) : null];
    }
}
