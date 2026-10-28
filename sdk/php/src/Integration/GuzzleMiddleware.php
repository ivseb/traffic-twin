<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TrafficTwin\Capture\Context;
use TrafficTwin\Capture\Headers;
use TrafficTwin\Capture\NetError;
use TrafficTwin\Capture\Pending;
use TrafficTwin\Capture\TeeStream;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Decision;
use TrafficTwin\Sanitizer\Exchange;

/**
 * Outbound capture as a Guzzle handler middleware:
 *
 *     $stack = HandlerStack::create();
 *     $stack->push(\TrafficTwin\Integration\GuzzleMiddleware::create());
 *     $client = new Client(['handler' => $stack]);
 *
 * Guzzle is only a development and suggested dependency of the SDK: the middleware is plain
 * callables and PSR-7. Pushed last (the default for `push()`), it sits closest to the transport,
 * so it sees every redirect hop and every HTTP status as a response; only transport failures
 * reach it as rejections (`net_error`). The data is seen before TLS encryption.
 *
 * The call inherits the sampling decision and the trace id of the inbound exchange being served
 * (`inherited`); outside a request (queue workers, cron) the decision is taken with the trace
 * of the active OpenTelemetry span if there is one, else at random. Nothing is added to the
 * request except, when the policy lists the host in `sampling.propagate_to` (and it is not an
 * external service of the policy), the baggage member `tt.s=0|1`.
 */
final class GuzzleMiddleware
{
    /** @return callable(callable): callable */
    public static function create(?Runtime $runtime = null): callable
    {
        return static function (callable $handler) use ($runtime): callable {
            return static function (RequestInterface $request, array $options) use ($handler, $runtime) {
                $rt = $runtime ?? Runtime::get();
                try {
                    $cap = self::begin($rt, $request);
                } catch (\Throwable) {
                    $cap = null;
                }
                if ($cap === null) {
                    return $handler($request, $options);
                }
                [$request, $state] = $cap;
                $promise = $handler($request, $options);
                if ($state === null) {
                    return $promise;
                }
                return $promise->then(
                    static function ($response) use ($rt, $state) {
                        try {
                            return self::settle($rt, $state, $response, null);
                        } catch (\Throwable) {
                            $rt->counters->error('capture_outbound_finish');
                            return $response;
                        }
                    },
                    static function ($reason) use ($rt, $state) {
                        try {
                            self::settle($rt, $state, null, $reason);
                        } catch (\Throwable) {
                            $rt->counters->error('capture_outbound_finish');
                        }
                        if (class_exists('GuzzleHttp\\Promise\\Create')) {
                            return \GuzzleHttp\Promise\Create::rejectionFor($reason);
                        }
                        throw $reason instanceof \Throwable ? $reason : new \RuntimeException('request rejected');
                    },
                );
            };
        };
    }

    /**
     * @return array{0: RequestInterface, 1: ?array<string, mixed>}|null null = not capturing at all
     */
    private static function begin(Runtime $rt, RequestInterface $request): ?array
    {
        $san = $rt->sanitizer();
        if ($san === null) {
            return null;
        }
        $t0 = hrtime(true);
        $rt->counters->seen();
        $uri = $request->getUri();
        $port = $uri->getPort();
        $urlBase = $uri->getScheme() . '://' . $uri->getHost() . ($port !== null ? ':' . $port : '');
        $ctx = Context::current();
        $otel = $ctx === null ? Context::otelActive() : null;
        $reqHeaders = Headers::fromMap($request->getHeaders());
        if ($ctx !== null) {
            $decision = new Decision($ctx->sampled, 'inherited');
        } else {
            $ex = new Exchange();
            $ex->dir = 'outbound';
            $ex->reqHeaders = [];
            $ex->traceId = $otel['traceId'] ?? null;
            $decision = $san->decide($ex);
        }
        // Propagation of the sampling decision (D-M8): only toward listed internal hosts.
        if ($rt->mayPropagate($urlBase)) {
            $existing = $request->getHeader('baggage');
            $request = $request->withHeader('baggage', Context::withTtS($existing === [] ? null : implode(',', $existing), $decision->sampled));
        }
        if (!$decision->sampled) {
            $rt->counters->overhead(intdiv(hrtime(true) - $t0, 1000));
            return [$request, null];
        }
        $rt->counters->sampled();
        $limit = $san->policy->bodyCaptureLimit(); // 9.0, 22.5
        $body = $request->getBody();
        $tee = null;
        [$prefix, $total, $tee] = Psr15Middleware::peek($body, $limit, $rt->deferMode !== 'now');
        if ($tee !== null) {
            $request = $request->withBody($tee);
        }
        return [$request, [
            'san' => $san,
            'decision' => $decision,
            'urlBase' => $urlBase,
            'method' => $request->getMethod(),
            'path' => $uri->getPath(),
            'query' => $uri->getQuery() === '' ? null : $uri->getQuery(),
            'reqHeaders' => Headers::fromMap($request->getHeaders()),
            'reqPrefix' => $prefix,
            'reqTotal' => $total,
            'reqTee' => $tee,
            't0' => $t0,
            'start' => hrtime(true),
            'tsMs' => (int) (microtime(true) * 1000),
            'limit' => $limit,
            'traceId' => $ctx?->traceId ?? $otel['traceId'] ?? Context::newTraceId(),
            'parent' => $ctx?->spanId ?? ($otel['spanId'] ?? '') ?: null,
            'span' => Context::newSpanId(),
            'overhead' => hrtime(true) - $t0,
        ]];
    }

    /**
     * @param array<string, mixed> $s
     * @return mixed the response (possibly decorated) for the promise chain
     */
    private static function settle(Runtime $rt, array $s, mixed $response, mixed $reason): mixed
    {
        $t = hrtime(true);
        $latencyMs = intdiv($t - $s['start'], 1_000_000);
        $netError = null;
        $status = null;
        $respHeaders = [];
        $respPrefix = '';
        $respTotal = 0;
        $respTee = null;
        $decoded = null;
        if ($response === null && is_object($reason) && method_exists($reason, 'getResponse') && $reason->getResponse() instanceof ResponseInterface) {
            // A rejection that carries a response (HTTP error raised by an inner layer): it is a normal exchange.
            $response = $reason->getResponse();
            $reason = null;
        }
        $out = $response;
        if ($response instanceof ResponseInterface) {
            $status = $response->getStatusCode();
            $noBody = $s['method'] === 'HEAD' || $status === 204 || $status === 304 || ($status >= 100 && $status < 200);
            if (!$noBody) {
                [$respPrefix, $respTotal, $respTee] = Psr15Middleware::peek($response->getBody(), $s['limit'], $rt->deferMode !== 'now');
                if ($respTee !== null) {
                    $out = $response->withBody($respTee);
                }
            }
            $respHeaders = Headers::fromMap($response->getHeaders());
            // Guzzle's decode_content removes Content-Encoding and keeps the original in
            // x-encoded-content-encoding: give the sanitizer the on-the-wire view.
            $enc = null;
            $clean = [];
            foreach ($respHeaders as $h) {
                $ln = strtolower($h[0]);
                if ($ln === 'x-encoded-content-encoding') {
                    $enc = $h[1];
                } elseif ($ln !== 'x-encoded-content-length') {
                    $clean[] = $h;
                }
            }
            if ($enc !== null) {
                $clean[] = ['content-encoding', $enc];
                $decoded = true;
            }
            $respHeaders = $clean;
        } else {
            $netError = $reason instanceof \Throwable ? NetError::fromThrowable($reason) : 'other';
        }

        $build = static function () use ($s, $status, $netError, $respHeaders, $respPrefix, $respTotal, $respTee, $decoded): Exchange {
            $ex = new Exchange();
            $ex->dir = 'outbound';
            $ex->urlBase = $s['urlBase'];
            $ex->method = $s['method'];
            $ex->rawPath = $s['path'];
            $ex->rawQuery = $s['query'];
            $ex->traceId = $s['traceId'];
            $ex->reqHeaders = $s['reqHeaders'];
            if ($s['reqTee'] !== null) {
                $total = $s['reqTee']->total();
                $ex->reqBody = $s['reqTee']->prefix();
                $ex->reqBodyTotal = $total ?? 'unknown';
                $ex->reqBodyConsumed = $total !== null && $s['reqTee']->consumed();
            } else {
                $ex->reqBody = $s['reqPrefix'];
                $ex->reqBodyTotal = $s['reqTotal'];
            }
            if ($netError !== null) {
                $ex->netError = $netError;
                return $ex;
            }
            $ex->status = $status;
            $ex->respHeaders = $respHeaders;
            $ex->respBodyDecoded = $decoded;
            if ($respTee !== null) {
                $total = $respTee->total();
                $ex->respBody = $respTee->prefix();
                $ex->respBodyTotal = $total ?? 'unknown';
                $ex->respBodyConsumed = $total !== null && $respTee->consumed();
            } else {
                $ex->respBody = $respPrefix;
                $ex->respBodyTotal = $respTotal;
            }
            return $ex;
        };
        $rt->enqueue(new Pending(
            $s['san'],
            $s['decision'],
            $build,
            'outbound',
            $s['tsMs'],
            $latencyMs,
            $s['traceId'],
            $s['span'],
            $s['parent'],
            $status,
            $netError,
            strlen($s['reqPrefix']) + strlen($respPrefix),
        ));
        $rt->counters->overhead(intdiv($s['overhead'] + (hrtime(true) - $t), 1000));
        return $out;
    }
}
