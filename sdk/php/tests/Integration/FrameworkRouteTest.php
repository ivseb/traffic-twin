<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Integration;

use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher as LaravelEvents;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request as LaravelRequest;
use Illuminate\Routing\CallableDispatcher;
use Illuminate\Routing\ControllerDispatcher;
use Illuminate\Routing\Contracts\CallableDispatcher as CallableDispatcherContract;
use Illuminate\Routing\Contracts\ControllerDispatcher as ControllerDispatcherContract;
use Illuminate\Routing\Router as LaravelRouter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse as SfJsonResponse;
use Symfony\Component\HttpFoundation\Request as SfRequest;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver;
use Symfony\Component\HttpKernel\Controller\ControllerResolver;
use Symfony\Component\HttpKernel\EventListener\RouterListener;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use TrafficTwin\Capture\Context;
use TrafficTwin\Integration\LaravelMiddleware;
use TrafficTwin\Integration\Routes;
use TrafficTwin\Integration\SymfonySubscriber;
use TrafficTwin\Runtime;
use TrafficTwin\Tests\Support\Fixture;

/** framework_route from real routers (sanitizer.md 3.4): complete templates, mount prefixes included. */
final class FrameworkRouteTest extends TestCase
{
    private Fixture $f;
    private Runtime $rt;

    protected function setUp(): void
    {
        $order = ['request' => ['path' => ['orderId' => ['action' => 'hmac', 'domain' => 'order']]]];
        $this->f = (new Fixture())->write(Fixture::policy(['services' => [[
            'name' => 'shop-api',
            'match' => ['inbound' => true, 'internal' => false],
            'ops' => [
                ['op' => 'GET /api/v1/orders/{orderId}'] + $order,
                ['op' => 'GET /api/v1/items/{orderId}'] + $order,
                ['op' => 'POST /api/v1/orders', 'response' => ['body' => [['path' => '$.status', 'action' => ['action' => 'keep']]]]],
            ],
        ]]]));
        $this->rt = $this->f->runtime();
    }

    protected function tearDown(): void
    {
        Context::leave();
        Container::setInstance(null);
    }

    private function laravel(): LaravelRouter
    {
        $container = new Container();
        Container::setInstance($container);
        $container->instance(LaravelMiddleware::class, new LaravelMiddleware($this->rt));
        $container->singleton(CallableDispatcherContract::class, static fn ($app) => new CallableDispatcher($app));
        $container->singleton(ControllerDispatcherContract::class, static fn ($app) => new ControllerDispatcher($app));
        $router = new LaravelRouter(new LaravelEvents($container), $container);
        $router->group(['prefix' => 'api', 'middleware' => [LaravelMiddleware::class]], function () use ($router): void {
            $router->group(['prefix' => 'v1'], function () use ($router): void {
                $router->get('orders/{id}', static fn (string $id) => new JsonResponse(['id' => $id, 'status' => 'OK']));
                $router->get('items/{id?}', static fn (?string $id = null) => new JsonResponse(['id' => $id]));
                $router->post('orders', static fn () => new JsonResponse(['status' => 'CREATED'], 201));
            });
        });
        return $router;
    }

    public function testLaravelRouteIncludingGroupPrefixes(): void
    {
        $router = $this->laravel();
        $resp = $router->dispatch(LaravelRequest::create('/api/v1/orders/ORD-2026-000184?x=1', 'GET', [], [], [], ['HTTP_ACCEPT' => 'application/json']));
        $this->rt->processPending();
        self::assertSame(200, $resp->getStatusCode());
        self::assertSame('{"id":"ORD-2026-000184","status":"OK"}', $resp->getContent(), 'the response is untouched');
        $e = $this->f->events();
        self::assertCount(1, $e);
        self::assertSame('framework', $e[0]['route_source']);
        self::assertSame('GET /api/v1/orders/{orderId}', $e[0]['op']);
        self::assertMatchesRegularExpression('#^/api/v1/orders/\{tk1:k1:#', $e[0]['req']['path']);
        self::assertStringNotContainsString('ORD-2026', $this->f->spoolText());
        self::assertSame(['drop:str:digits'], $e[0]['req']['query']['x']);
    }

    public function testLaravelOptionalParameterFallsBackToThePolicy(): void
    {
        $router = $this->laravel();
        $router->dispatch(LaravelRequest::create('/api/v1/items/42', 'GET'));
        $this->rt->processPending();
        $e = $this->f->events();
        self::assertSame('policy', $e[0]['route_source'], '{id?} is not normalizable (3.4): the policy template decides');
        self::assertSame('GET /api/v1/items/{orderId}', $e[0]['op']);
    }

    public function testLaravelPostBodyAndResponse(): void
    {
        $router = $this->laravel();
        $router->dispatch(LaravelRequest::create('/api/v1/orders', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"items":[{"sku":"TSHIRT-RED-M"}]}'));
        $this->rt->processPending();
        $e = $this->f->events();
        self::assertSame('POST /api/v1/orders', $e[0]['op']);
        self::assertSame('framework', $e[0]['route_source']);
        self::assertSame('keep:CREATED', $e[0]['resp']['body']['status']);
        self::assertSame('drop:str:l32', $e[0]['req']['body']['items'][0]['sku']);
    }

    public function testLaravelRoutesHelperIsDuckTyped(): void
    {
        $route = new class () {
            public function uri(): string
            {
                return 'api/v1/orders/{id}';
            }
        };
        self::assertSame(['laravel', '/api/v1/orders/{id}'], Routes::laravel($route));
        self::assertNull(Routes::laravel(null));
        self::assertNull(Routes::laravel(new \stdClass()));
    }

    /** @return array{0: HttpKernel, 1: RouteCollection} */
    private function symfony(): array
    {
        $routes = new RouteCollection();
        $api = new RouteCollection();
        $api->add('order_show', new Route('/orders/{id}', ['_controller' => static fn (SfRequest $r) => new SfJsonResponse(['id' => $r->attributes->get('id'), 'status' => 'OK'])], ['id' => '[A-Z0-9-]+'], [], '', [], ['GET']));
        $api->add('item_show', new Route('/items/{id}', ['id' => null, '_controller' => static fn () => new SfJsonResponse(['ok' => true])], [], [], '', [], ['GET']));
        $api->add('order_create', new Route('/orders', ['_controller' => static fn () => new SfJsonResponse(['status' => 'CREATED'], 201)], [], [], '', [], ['POST']));
        $api->add('cookies', new Route('/cookies', ['_controller' => static function () {
            $r = new SfJsonResponse(['ok' => true]);
            $r->headers->setCookie(Cookie::create('a', '1'));
            $r->headers->setCookie(Cookie::create('b', '2'));
            $r->headers->setCookie(Cookie::create('a', '3', 0, '/other'));
            return $r;
        }], [], [], '', [], ['GET']));
        $api->addPrefix('/api/v1');
        $routes->addCollection($api);
        $stack = new RequestStack();
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new RouterListener(new UrlMatcher($routes, new RequestContext()), $stack));
        $router = new class ($routes) {
            public function __construct(private RouteCollection $c)
            {
            }

            public function getRouteCollection(): RouteCollection
            {
                return $this->c;
            }
        };
        $dispatcher->addSubscriber(new SymfonySubscriber($router, $this->rt));
        return [new HttpKernel($dispatcher, new ControllerResolver(), $stack, new ArgumentResolver()), $routes];
    }

    public function testSymfonyRouteIncludingImportedPrefix(): void
    {
        [$kernel] = $this->symfony();
        $resp = $kernel->handle(SfRequest::create('/api/v1/orders/ORD-2026-000184', 'GET'));
        $this->rt->processPending();
        self::assertSame('{"id":"ORD-2026-000184","status":"OK"}', $resp->getContent());
        $e = $this->f->events();
        self::assertCount(1, $e);
        self::assertSame('framework', $e[0]['route_source']);
        self::assertSame('GET /api/v1/orders/{orderId}', $e[0]['op']);
        self::assertStringNotContainsString('ORD-2026', $this->f->spoolText());
    }

    public function testSymfonyRouteWithADefaultKeepsTheCompiledPathPattern(): void
    {
        [$kernel] = $this->symfony();
        // Symfony stores the optional parameter as {id} plus a default: getPath() is the policy template.
        $kernel->handle(SfRequest::create('/api/v1/items/42', 'GET'));
        $this->rt->processPending();
        $e = $this->f->events();
        self::assertSame('framework', $e[0]['route_source']);
        self::assertSame('GET /api/v1/items/{orderId}', $e[0]['op']);
        self::assertSame(['symfony', '/api/v1/items/{id}'], Routes::symfony(new Route('/api/v1/items/{id?}')));
        self::assertSame(['symfony', '/api/{x}'], Routes::symfony(new Route('/api/{x<\\d+>}')));
    }

    public function testSymfonyPostAndNotFound(): void
    {
        [$kernel] = $this->symfony();
        $kernel->handle(SfRequest::create('/api/v1/orders', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"items":[]}'));
        try {
            $kernel->handle(SfRequest::create('/nowhere/1', 'GET'), 1, false);
        } catch (\Throwable) {
        }
        $this->rt->processPending();
        $e = $this->f->events();
        self::assertSame('POST /api/v1/orders', $e[0]['op']);
        self::assertSame('keep:CREATED', $e[0]['resp']['body']['status']);
    }

    /** RT3-FW-2 and RT3-FW-3: the event carries what was on the wire, not what the framework added to its bags. */
    public function testSymfonyCookiesAreRecordedOnceAndFrameworkRequestHeadersAreNotCaptured(): void
    {
        $this->f = (new Fixture())->write(Fixture::policy(['services' => [[
            'name' => 'shop-api',
            'match' => ['inbound' => true, 'internal' => false],
            'ops' => [['op' => 'GET /api/v1/cookies']],
        ]]]));
        $this->rt = $this->f->runtime();
        [$kernel] = $this->symfony();
        $kernel->handle(SfRequest::create('/api/v1/cookies', 'GET', [], [], [], ['HTTP_X_CLIENT' => 'yes']));
        $this->rt->processPending();
        $e = $this->f->events();
        self::assertCount(1, $e);
        // Three distinct cookies (a, b and a on another path), each once and in order.
        self::assertCount(2, $e[0]['resp']['cookies']['a']);
        self::assertCount(1, $e[0]['resp']['cookies']['b']);
        self::assertArrayNotHasKey('x-php-ob-level', $e[0]['req']['headers'] ?? []);
        self::assertArrayHasKey('x-client', $e[0]['req']['headers']);
    }
}
