<?php

namespace Yasno\Logging\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yasno\Logging\RequestId;

/**
 * Id source order: server param REQUEST_ID (set by nginx fastcgi_param) -> X-Request-Id header -> generated.
 * Untrusted values are validated by RequestId::normalize(), so a forged header cannot inject junk into the logs.
 */
final class RequestIdMiddleware implements MiddlewareInterface
{
    public const HEADER = 'X-Request-Id';
    public const ATTRIBUTE = 'request_id';

    public function __construct(private readonly RequestId $requestId)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $serverParam = $request->getServerParams()['REQUEST_ID'] ?? null;
        $id = RequestId::resolve(is_string($serverParam) ? $serverParam : null, $request->getHeaderLine(self::HEADER));
        $this->requestId->set($id);
        try {
            return $handler->handle($request->withAttribute(self::ATTRIBUTE, $id))->withHeader(self::HEADER, $id);
        } finally {
            $this->requestId->reset();
        }
    }
}
