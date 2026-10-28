<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Decision;
use TrafficTwin\Sanitizer\Exchange;
use TrafficTwin\Sanitizer\Sanitizer;

/**
 * Framework-neutral half of the inbound capture: the sampling decision and the context at the
 * start of the request, and the hand-off of the finished exchange. The PSR-15, Laravel and
 * Symfony integrations only translate their request and response objects.
 */
final class Inbound
{
    private int $overheadNs;

    private function __construct(
        public readonly Runtime $rt,
        public readonly Sanitizer $san,
        public readonly Decision $decision,
        public readonly ExchangeCtx $ctx,
        public readonly ?string $parentSpanId,
        public readonly int $t0,
        public readonly int $tsMs,
        int $overheadNs,
    ) {
        $this->overheadNs = $overheadNs;
    }

    /**
     * Starts an inbound exchange. Returns null when capture is not allowed (the fast path:
     * no policy, kill switch, no key, no heartbeat...). Never throws.
     *
     * @param list<array{0: string, 1: string}> $headers request headers, any order, duplicates kept
     */
    public static function begin(Runtime $rt, array $headers): ?self
    {
        try {
            $san = $rt->sanitizer();
            if ($san === null) {
                return null;
            }
            $t0 = hrtime(true);
            $rt->counters->seen();
            $names = $rt->decisionHeaders() + ['traceparent' => true];
            $pairs = Headers::only($headers, $names);
            $tp = Context::parseTraceparent(Headers::first($pairs, 'traceparent'));
            $otel = $tp === null ? Context::otelActive() : null;
            $known = $tp['traceId'] ?? $otel['traceId'] ?? null;
            $ex = new Exchange();
            $ex->dir = 'inbound';
            $ex->serviceName = $rt->serviceName();
            $ex->reqHeaders = $pairs;
            $ex->traceId = $known;
            $decision = $san->decide($ex);
            $ctx = new ExchangeCtx($decision->sampled, $known ?? Context::newTraceId(), $known !== null, Context::newSpanId());
            Context::enter($ctx);
            if ($decision->sampled) {
                $rt->counters->sampled();
            }
            return new self($rt, $san, $decision, $ctx, $tp['spanId'] ?? null, $t0, (int) (microtime(true) * 1000), hrtime(true) - $t0);
        } catch (\Throwable) {
            $rt->counters->error('capture_inbound_start');
            return null;
        }
    }

    public function sampled(): bool
    {
        return $this->decision->sampled;
    }

    /** Body bytes the capture may keep: max(max_body_bytes, bodies.max_large_body_bytes) + 1 (9.0, 22.5). */
    public function bodyLimit(): int
    {
        return $this->san->policy->bodyCaptureLimit();
    }

    /**
     * Queues the finished exchange. $build is evaluated later (after the response, where the
     * SAPI allows) and returns the sanitizer input. Never throws.
     *
     * @param \Closure(): Exchange $build
     */
    public function submit(\Closure $build, int $status, int $heldBytes): void
    {
        try {
            $t = hrtime(true);
            $latencyMs = intdiv($t - $this->t0, 1_000_000);
            $this->rt->enqueue(new Pending(
                $this->san,
                $this->decision,
                $build,
                'inbound',
                $this->tsMs,
                $latencyMs,
                $this->ctx->traceId,
                $this->ctx->spanId,
                $this->parentSpanId,
                $status,
                null,
                $heldBytes,
            ));
            $this->overheadNs += hrtime(true) - $t;
        } catch (\Throwable) {
            $this->rt->counters->error('capture_inbound_finish');
        }
    }

    /** Ends the exchange: clears the context and records the time spent in the capture. */
    public function end(): void
    {
        Context::leave();
        $this->rt->counters->overhead(intdiv($this->overheadNs, 1000));
    }

    /** Adds time spent by the integration between begin() and end(), in nanoseconds. */
    public function addOverhead(int $ns): void
    {
        $this->overheadNs += $ns;
    }
}
