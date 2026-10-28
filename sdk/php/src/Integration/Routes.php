<?php

declare(strict_types=1);

namespace TrafficTwin\Integration;

/**
 * Route templates for `framework_route` (sanitizer.md 3.3, 3.4). Each helper returns
 * `[framework, route]` or null. The route MUST include every mount prefix (route groups,
 * imported collections); if the framework object cannot give the complete template, return
 * null and the sanitizer falls back to the policy templates (3.3 point 2).
 */
final class Routes
{
    /**
     * Laravel `Illuminate\Routing\Route`: uri() is the full template including group prefixes,
     * e.g. `api/orders/{id}`. Optional parameters (`{id?}`) are not normalizable and make the
     * sanitizer fall back, as the spec requires.
     *
     * @return array{0: string, 1: string}|null
     */
    public static function laravel(mixed $route): ?array
    {
        if (is_object($route) && method_exists($route, 'uri')) {
            $uri = $route->uri();
            if (is_string($uri)) {
                return ['laravel', '/' . ltrim($uri, '/')];
            }
        }
        return null;
    }

    /**
     * Symfony `Symfony\Component\Routing\Route`: getPath() is the full path pattern, imported
     * prefixes included, e.g. `/api/orders/{id}`.
     *
     * @return array{0: string, 1: string}|null
     */
    public static function symfony(mixed $route): ?array
    {
        if (is_object($route) && method_exists($route, 'getPath')) {
            $p = $route->getPath();
            if (is_string($p)) {
                return ['symfony', '/' . ltrim($p, '/')];
            }
        }
        return null;
    }

    /**
     * Symfony route by name through the router (`_route` request attribute).
     *
     * @return array{0: string, 1: string}|null
     */
    public static function symfonyByName(mixed $router, ?string $name): ?array
    {
        if ($name === null || $name === '' || !is_object($router) || !method_exists($router, 'getRouteCollection')) {
            return null;
        }
        try {
            return self::symfony($router->getRouteCollection()->get($name));
        } catch (\Throwable) {
            return null;
        }
    }
}
