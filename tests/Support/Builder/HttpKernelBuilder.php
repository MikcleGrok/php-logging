<?php

namespace Yasno\Logging\Tests\Support\Builder;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Controller\ArgumentResolver;
use Symfony\Component\HttpKernel\Controller\ControllerResolver;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\HttpKernel\KernelEvents;

/** A real HttpKernel on a real EventDispatcher; every request is served by a controller returning an empty page. */
final class HttpKernelBuilder
{
    private function __construct(private readonly EventDispatcher $dispatcher)
    {
    }

    public static function create(): self
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(KernelEvents::REQUEST, static function (RequestEvent $event): void {
            $event->getRequest()->attributes->set('_controller', static fn (): Response => new Response());
        }, 256);

        return new self($dispatcher);
    }

    public function withSubscriber(EventSubscriberInterface $subscriber): self
    {
        $this->dispatcher->addSubscriber($subscriber);

        return $this;
    }

    public function withListener(string $event, callable $listener, int $priority = 0): self
    {
        $this->dispatcher->addListener($event, $listener, $priority);

        return $this;
    }

    public function build(): HttpKernel
    {
        return new HttpKernel($this->dispatcher, new ControllerResolver(), new RequestStack(), new ArgumentResolver());
    }
}
