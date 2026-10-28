<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use TrafficTwin\Capture\Headers;
use TrafficTwin\Capture\Inbound;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Exchange;

/**
 * Inbound capture for Symfony (HttpKernel events). Register as a service with the tag
 * `kernel.event_subscriber`, passing the router (`@router`) so the full path pattern of the
 * matched route can be looked up from the `_route` request attribute
 * (`RouteCollection::get($name)->getPath()`, imported prefixes included; sanitizer.md 3.4,
 * Symfony row).
 *
 * Request events run first (priority 512) and response events last, so the exchange covers the
 * whole kernel; sanitization happens in a shutdown function after the response was sent.
 */
final class SymfonySubscriber implements EventSubscriberInterface
{
    private const ATTR = '_tt_inbound';

    public function __construct(private mixed $router = null, private ?Runtime $runtime = null)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            'kernel.request' => ['onRequest', 512],
            'kernel.response' => ['onResponse', -512],
        ];
    }

    private static function isMain(object $event): bool
    {
        return method_exists($event, 'isMainRequest') ? $event->isMainRequest() : $event->isMasterRequest();
    }

    public function onRequest(object $event): void
    {
        if (!self::isMain($event)) {
            return;
        }
        $rt = $this->runtime ?? Runtime::get();
        $request = $event->getRequest();
        $in = null;
        try {
            if ($rt->sanitizer() !== null) {
                $in = Inbound::begin($rt, Headers::fromRequestBag($request->headers->all()));
            }
        } catch (\Throwable) {
            $in = null;
        }
        if ($in !== null) {
            $request->attributes->set(self::ATTR, $in);
        }
    }

    public function onResponse(object $event): void
    {
        if (!self::isMain($event)) {
            return;
        }
        $request = $event->getRequest();
        $in = $request->attributes->get(self::ATTR);
        if (!$in instanceof Inbound) {
            return;
        }
        $request->attributes->remove(self::ATTR);
        try {
            if ($in->sampled()) {
                $t = hrtime(true);
                $this->capture($in, $request, $event->getResponse());
                $in->addOverhead(hrtime(true) - $t);
            }
        } catch (\Throwable) {
            $in->rt->counters->error('capture_inbound_finish');
        } finally {
            $in->end();
        }
    }

    private function capture(Inbound $in, object $request, object $response): void
    {
        $limit = $in->bodyLimit();
        $status = (int) $response->getStatusCode();
        $method = (string) $request->getMethod();
        $noBody = $method === 'HEAD' || $status === 204 || $status === 304 || ($status >= 100 && $status < 200);
        $reqConsumed = true;
        $reqBody = '';
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
                $respTotal = 'unknown';
            }
        }
        $reqHeaders = Headers::fromRequestBag($request->headers->all());
        $respHeaders = Headers::fromResponseBag($response->headers);
        $name = $request->attributes->get('_route');
        $r = Routes::symfonyByName($this->router, is_string($name) ? $name : null);
        $fw = $r[0] ?? null;
        $route = $r[1] ?? null;
        $service = $in->rt->serviceName();
        $traceId = $in->ctx->traceKnown ? $in->ctx->traceId : null;
        $uri = (string) $request->server->get('REQUEST_URI', '');
        $q = strpos($uri, '?');
        $rawPath = $uri === '' ? (string) $request->getPathInfo() : ($q === false ? $uri : substr($uri, 0, $q));
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
}
