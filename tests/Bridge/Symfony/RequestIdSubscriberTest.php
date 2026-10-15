<?php

namespace Yasno\Logging\Tests\Bridge\Symfony;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Yasno\Logging\Bridge\Symfony\RequestIdSubscriber;
use Yasno\Logging\RequestId;
use Yasno\Logging\Tests\Support\Assert\RequestIdAssert;

final class RequestIdSubscriberTest extends TestCase
{
    private RequestId $requestId;
    private RequestIdSubscriber $subscriber;
    private HttpKernelInterface $kernel;

    protected function setUp(): void
    {
        $this->requestId = new RequestId();
        $this->subscriber = new RequestIdSubscriber($this->requestId);
        $this->kernel = $this->createMock(HttpKernelInterface::class);
    }

    private function handle(Request $request, int $type = HttpKernelInterface::MAIN_REQUEST): Response
    {
        $this->subscriber->onRequest(new RequestEvent($this->kernel, $request, $type));
        $response = new Response();
        $this->subscriber->onResponse(new ResponseEvent($this->kernel, $request, $type, $response));

        return $response;
    }

    public function testItSubscribesToRequestWithHighPriorityAndResponse(): void
    {
        $events = RequestIdSubscriber::getSubscribedEvents();

        self::assertSame(['onRequest', 512], $events[KernelEvents::REQUEST]);
        self::assertSame('onResponse', $events[KernelEvents::RESPONSE]);
    }

    public function testItSubscribesToTerminateAfterOtherListeners(): void
    {
        $events = RequestIdSubscriber::getSubscribedEvents();

        self::assertSame(['onTerminate', RequestIdSubscriber::TERMINATE_PRIORITY], $events[KernelEvents::TERMINATE]);
    }

    public function testTheIdIsResetWhenTheKernelTerminates(): void
    {
        $request = Request::create('/');
        $response = $this->handle($request);

        $this->subscriber->onTerminate(new TerminateEvent($this->kernel, $request, $response));

        self::assertNull($this->requestId->get());
    }

    public function testItTakesTheIdFromServerParams(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REQUEST_ID' => '0123456789abcdef']);

        $response = $this->handle($request);

        self::assertSame('0123456789abcdef', $this->requestId->get());
        self::assertSame('0123456789abcdef', $request->attributes->get('request_id'));
        self::assertSame('0123456789abcdef', $response->headers->get('X-Request-Id'));
    }

    public function testItFallsBackToAValidHeader(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['HTTP_X_REQUEST_ID' => 'headerheader1234']);

        $response = $this->handle($request);

        self::assertSame('headerheader1234', $response->headers->get('X-Request-Id'));
    }

    public function testTheHeaderIsIgnoredWhenClientHeadersAreNotTrusted(): void
    {
        $clientId = RequestId::generate();
        $this->subscriber = new RequestIdSubscriber($this->requestId, false);
        $request = Request::create('/', 'GET', [], [], [], ['HTTP_X_REQUEST_ID' => $clientId]);

        $response = $this->handle($request);

        self::assertNotSame($clientId, $this->requestId->get());
        RequestIdAssert::seeGenerated((string) $this->requestId->get());
        self::assertSame($this->requestId->get(), $response->headers->get('X-Request-Id'));
    }

    public function testTheServerParamStillWinsWhenClientHeadersAreNotTrusted(): void
    {
        $serverId = RequestId::generate();
        $this->subscriber = new RequestIdSubscriber($this->requestId, false);
        $request = Request::create('/', 'GET', [], [], [], ['REQUEST_ID' => $serverId, 'HTTP_X_REQUEST_ID' => RequestId::generate()]);

        $this->handle($request);

        self::assertSame($serverId, $this->requestId->get());
    }

    public function testAnInvalidHeaderIsReplacedByAGeneratedId(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['HTTP_X_REQUEST_ID' => 'bad value']);

        $response = $this->handle($request);

        RequestIdAssert::seeGenerated((string) $response->headers->get('X-Request-Id'));
        self::assertSame($response->headers->get('X-Request-Id'), $this->requestId->get());
    }

    public function testSubRequestsDoNotOverrideTheMainId(): void
    {
        $main = Request::create('/', 'GET', [], [], [], ['REQUEST_ID' => '0123456789abcdef']);
        $this->subscriber->onRequest(new RequestEvent($this->kernel, $main, HttpKernelInterface::MAIN_REQUEST));

        $sub = Request::create('/sub');
        $this->subscriber->onRequest(new RequestEvent($this->kernel, $sub, HttpKernelInterface::SUB_REQUEST));
        $response = new Response();
        $this->subscriber->onResponse(new ResponseEvent($this->kernel, $sub, HttpKernelInterface::SUB_REQUEST, $response));

        self::assertSame('0123456789abcdef', $this->requestId->get());
        self::assertFalse($response->headers->has('X-Request-Id'));
    }

    public function testResetClearsTheId(): void
    {
        $this->handle(Request::create('/'));
        self::assertNotNull($this->requestId->get());

        $this->requestId->reset();

        self::assertNull($this->requestId->get());
    }
}
