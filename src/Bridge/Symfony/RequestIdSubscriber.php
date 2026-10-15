<?php

namespace Yasno\Logging\Bridge\Symfony;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Yasno\Logging\Http\RequestIdMiddleware;
use Yasno\Logging\RequestId;

/**
 * Symfony counterpart of RequestIdMiddleware. Requires symfony/http-kernel. The RequestId service is expected to be
 * tagged kernel.reset (see config/symfony/yasno_logging.yaml); kernel.terminate resets it as well. Pass
 * $trustClientHeader = false when no trusted proxy sets REQUEST_ID: the X-Request-Id header is then ignored.
 */
final class RequestIdSubscriber implements EventSubscriberInterface
{
    /** Below every default priority, so that the other kernel.terminate listeners still see the id. */
    public const TERMINATE_PRIORITY = -1024;

    public function __construct(private readonly RequestId $requestId, private readonly bool $trustClientHeader = true)
    {
    }

    /**
     * @return array<string, array{string, int}|string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onRequest', 512],
            KernelEvents::RESPONSE => 'onResponse',
            KernelEvents::TERMINATE => ['onTerminate', self::TERMINATE_PRIORITY],
        ];
    }

    public function onRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        $serverParam = $request->server->get('REQUEST_ID');
        $header = $this->trustClientHeader ? $request->headers->get(RequestIdMiddleware::HEADER) : null;
        $id = RequestId::resolve(is_string($serverParam) ? $serverParam : null, $header);
        $this->requestId->set($id);
        $request->attributes->set(RequestIdMiddleware::ATTRIBUTE, $id);
    }

    /** Last in line: other kernel.terminate listeners still log with the id; long-lived workers get a clean slate. */
    public function onTerminate(TerminateEvent $event): void
    {
        $this->requestId->reset();
    }

    public function onResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $id = $event->getRequest()->attributes->get(RequestIdMiddleware::ATTRIBUTE);
        if (is_string($id)) {
            $event->getResponse()->headers->set(RequestIdMiddleware::HEADER, $id);
        }
    }
}
