<?php

namespace Yasno\Logging\Tests\Http;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use Yasno\Logging\Http\RequestIdMiddleware;
use Yasno\Logging\RequestId;

final class RequestIdMiddlewareTest extends TestCase
{
    private RequestId $requestId;
    private RequestIdMiddleware $middleware;
    private ?string $idSeenByHandler = null;
    private mixed $attributeSeenByHandler = null;

    protected function setUp(): void
    {
        $this->requestId = new RequestId();
        $this->middleware = new RequestIdMiddleware($this->requestId);
    }

    private function handler(): RequestHandlerInterface
    {
        return new class ($this) implements RequestHandlerInterface {
            public function __construct(private readonly RequestIdMiddlewareTest $test)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->test->record($request);
                return new Response(200);
            }
        };
    }

    public function record(ServerRequestInterface $request): void
    {
        $this->idSeenByHandler = $this->requestId->get();
        $this->attributeSeenByHandler = $request->getAttribute('request_id');
    }

    public function testItTakesTheIdFromServerParams(): void
    {
        $request = new ServerRequest('GET', '/', [], null, '1.1', ['REQUEST_ID' => '0123456789abcdef']);

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame('0123456789abcdef', $this->idSeenByHandler);
        self::assertSame('0123456789abcdef', $this->attributeSeenByHandler);
        self::assertSame('0123456789abcdef', $response->getHeaderLine('X-Request-Id'));
    }

    public function testServerParamsWinOverTheHeader(): void
    {
        $request = new ServerRequest('GET', '/', ['X-Request-Id' => 'headerheader1234'], null, '1.1', ['REQUEST_ID' => '0123456789abcdef']);

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame('0123456789abcdef', $response->getHeaderLine('X-Request-Id'));
    }

    public function testItFallsBackToAValidHeader(): void
    {
        $request = new ServerRequest('GET', '/', ['X-Request-Id' => 'headerheader1234']);

        $response = $this->middleware->process($request, $this->handler());

        self::assertSame('headerheader1234', $this->idSeenByHandler);
        self::assertSame('headerheader1234', $response->getHeaderLine('X-Request-Id'));
    }

    public function testAnInvalidHeaderIsReplacedByAGeneratedId(): void
    {
        $request = new ServerRequest('GET', '/', ['X-Request-Id' => "bad value\t" . str_repeat('x', 10240)]);

        $response = $this->middleware->process($request, $this->handler());

        self::assertMatchesRegularExpression('~^[0-9a-f]{32}$~', $this->idSeenByHandler ?? '');
        self::assertSame($this->idSeenByHandler, $response->getHeaderLine('X-Request-Id'));
    }

    public function testAnInvalidServerParamFallsThroughToTheHeader(): void
    {
        $request = new ServerRequest('GET', '/', ['X-Request-Id' => 'headerheader1234'], null, '1.1', ['REQUEST_ID' => "x\r\ny"]);

        $this->middleware->process($request, $this->handler());

        self::assertSame('headerheader1234', $this->idSeenByHandler);
    }

    public function testWithoutAnyIdOneIsGenerated(): void
    {
        $response = $this->middleware->process(new ServerRequest('GET', '/'), $this->handler());

        self::assertMatchesRegularExpression('~^[0-9a-f]{32}$~', $response->getHeaderLine('X-Request-Id'));
    }

    public function testTheIdIsResetAfterTheRequest(): void
    {
        $this->middleware->process(new ServerRequest('GET', '/'), $this->handler());

        self::assertNull($this->requestId->get());
    }

    public function testTheIdIsResetWhenTheHandlerThrows(): void
    {
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new RuntimeException('boom');
            }
        };

        try {
            $this->middleware->process(new ServerRequest('GET', '/'), $handler);
            self::fail('The exception must propagate');
        } catch (RuntimeException) {
        }

        self::assertNull($this->requestId->get());
    }
}
