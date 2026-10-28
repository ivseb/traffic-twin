<?php

declare(strict_types=1);

namespace App;

use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use TrafficTwin\Integration\SymfonySubscriber;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Red team round 3: Symfony micro kernel. traffic-twin is registered exactly as the SDK
 * README says (SymfonySubscriber, '@router', kernel.event_subscriber). The app never logs
 * request data itself.
 */
final class Kernel extends BaseKernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
    }

    protected function configureContainer(ContainerConfigurator $c): void
    {
        $c->extension('framework', [
            'secret' => 'rt3fw-not-a-secret',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
        ]);
        $c->services()
            ->set(SymfonySubscriber::class)
            ->args([service('router')])
            ->tag('kernel.event_subscriber');
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(__FILE__, 'attribute');
    }

    public function getCacheDir(): string
    {
        return '/app/var/cache/' . $this->environment;
    }

    public function getLogDir(): string
    {
        return '/app/var/log';
    }

    #[Route('/health', methods: ['GET'])]
    public function health(): Response
    {
        return new Response('ok', 200, ['content-type' => 'text/plain']);
    }

    #[Route('/orders/{id}', methods: ['POST'])]
    public function order(string $id, Request $request): Response
    {
        $b = json_decode($request->getContent(), true) ?: [];
        $r = new JsonResponse(['id' => $id, 'status' => 'created', 'echo' => $b['secret'] ?? null,
            'email' => $b['nested']['email'] ?? null], 201);
        $r->headers->set('x-echo', (string) $request->headers->get('x-secret', ''));
        $r->headers->setCookie(Cookie::create('sess', (string) ($b['secret'] ?? '')));
        return $r;
    }

    /** Unhandled: Symfony answers 500 and logs the exception (the app's own log). */
    #[Route('/boom/{v}', methods: ['GET'])]
    public function boom(string $v): Response
    {
        throw new \RuntimeException("boom $v");
    }

    #[Route('/fail/{v}', methods: ['GET'])]
    public function fail(string $v): Response
    {
        return new JsonResponse(['error' => ['code' => 'E_FAIL', 'message' => "order $v failed"]], 500);
    }
}
