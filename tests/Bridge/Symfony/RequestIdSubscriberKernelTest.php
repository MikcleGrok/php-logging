<?php

namespace Yasno\Logging\Tests\Bridge\Symfony;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\KernelEvents;
use Yasno\Logging\Bridge\Symfony\RequestIdSubscriber;
use Yasno\Logging\RequestId;
use Yasno\Logging\Tests\Support\Act\KernelAct;
use Yasno\Logging\Tests\Support\Builder\HttpKernelBuilder;

final class RequestIdSubscriberKernelTest extends TestCase
{
    public function testAnotherTerminateListenerStillSeesTheIdAndTheKernelLeavesNoneBehind(): void
    {
        $requestId = new RequestId();
        $seenOnTerminate = null;
        $kernel = HttpKernelBuilder::create()
            ->withSubscriber(new RequestIdSubscriber($requestId))
            ->withListener(KernelEvents::TERMINATE, static function () use ($requestId, &$seenOnTerminate): void {
                $seenOnTerminate = $requestId->get();
            })
            ->build();

        $response = KernelAct::serve($kernel);

        self::assertSame($response->headers->get('X-Request-Id'), $seenOnTerminate);
        self::assertNull($requestId->get());
    }

    public function testARequestOfALongLivedWorkerStartsWithoutTheIdOfThePreviousOne(): void
    {
        $requestId = new RequestId();
        $seenBeforeTheSubscriber = [];
        $kernel = HttpKernelBuilder::create()
            ->withListener(KernelEvents::REQUEST, static function () use ($requestId, &$seenBeforeTheSubscriber): void {
                $seenBeforeTheSubscriber[] = $requestId->get();
            }, 1024)
            ->withSubscriber(new RequestIdSubscriber($requestId))
            ->build();

        $first = KernelAct::serve($kernel);
        KernelAct::serve($kernel);

        self::assertNotNull($first->headers->get('X-Request-Id'));
        self::assertSame([null, null], $seenBeforeTheSubscriber);
    }
}
