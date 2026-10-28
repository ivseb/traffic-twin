<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CallbackHandler implements RequestHandlerInterface
{
    public function __construct(private \Closure $fn)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return ($this->fn)($request);
    }
}
