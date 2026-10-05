<?php

namespace Yasno\Logging\Tests;

use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yasno\Logging\Formatter\JsonLineFormatter;
use Yasno\Logging\LoggerFactory;
use Yasno\Logging\RequestId;

final class LoggerFactoryTest extends TestCase
{
    private string|false $previousLevel = false;

    protected function setUp(): void
    {
        $this->previousLevel = getenv('LOG_LEVEL');
        putenv('LOG_LEVEL');
    }

    protected function tearDown(): void
    {
        if ($this->previousLevel === false) {
            putenv('LOG_LEVEL');
        } else {
            putenv('LOG_LEVEL=' . $this->previousLevel);
        }
    }

    /**
     * @return array{Logger, resource}
     */
    private function logger(string $channel = 'app', ?RequestId $id = null, ?string $level = null): array
    {
        $stream = fopen('php://memory', 'w+');
        self::assertIsResource($stream);

        return [LoggerFactory::create($channel, $id, $level, $stream), $stream];
    }

    /**
     * @param resource $stream
     */
    private function written($stream): string
    {
        rewind($stream);

        return (string) stream_get_contents($stream);
    }

    public function testInfoWritesExactlyOneJsonLineWithTheContractKeys(): void
    {
        $id = new RequestId();
        $id->set('0123456789abcdef');
        [$logger, $stream] = $this->logger('app', $id);

        $logger->info('hi', ['a' => 1]);

        $output = $this->written($stream);
        self::assertSame(1, substr_count($output, "\n"));
        self::assertStringEndsWith("\n", $output);
        $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['message', 'context', 'level', 'level_name', 'channel', 'datetime', 'request_id'], array_keys($data));
        self::assertSame('hi', $data['message']);
        self::assertSame(['a' => 1], $data['context']);
        self::assertSame(200, $data['level']);
        self::assertSame('INFO', $data['level_name']);
        self::assertSame('app', $data['channel']);
        self::assertSame('0123456789abcdef', $data['request_id']);
    }

    public function testWithoutRequestIdTheKeyIsAbsent(): void
    {
        [$logger, $stream] = $this->logger();

        $logger->info('hi');

        $data = json_decode($this->written($stream), true, 512, JSON_THROW_ON_ERROR);
        self::assertArrayNotHasKey('request_id', $data);
        self::assertArrayNotHasKey('extra', $data);
    }

    public function testChannelIsTaken(): void
    {
        [$logger, $stream] = $this->logger('mail');

        $logger->info('hi');

        $data = json_decode($this->written($stream), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('mail', $data['channel']);
    }

    public function testHugeMessageIsTruncatedToTheLineLimitAndStaysValidJson(): void
    {
        [$logger, $stream] = $this->logger();

        $logger->info(str_repeat('x', 20000), ['payload' => str_repeat('y', 20000)]);

        $output = $this->written($stream);
        self::assertLessThanOrEqual(8192, strlen($output));
        self::assertSame(1, substr_count($output, "\n"));
        $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        self::assertNotSame('', $data['message']);
        self::assertSame(['truncated' => true], $data['context']);
    }

    public function testHugeMessageOfEscapedCharactersStillFitsTheLimit(): void
    {
        [$logger, $stream] = $this->logger();

        $logger->info(str_repeat("\x01", 20000));

        $output = $this->written($stream);
        self::assertLessThanOrEqual(8192, strlen($output));
        json_decode($output, true, 512, JSON_THROW_ON_ERROR);
    }

    public function testRequestIdSurvivesTruncation(): void
    {
        $id = new RequestId();
        $id->set('0123456789abcdef');
        [$logger, $stream] = $this->logger('app', $id);

        $logger->info(str_repeat('x', 20000));

        $data = json_decode($this->written($stream), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('0123456789abcdef', $data['request_id']);
    }

    public function testExceptionInContextHasNoTrace(): void
    {
        [$logger, $stream] = $this->logger();

        $logger->error('boom', ['exception' => new RuntimeException('bad')]);

        $output = $this->written($stream);
        self::assertStringNotContainsString('"trace"', $output);
        $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(RuntimeException::class, $data['context']['exception']['class']);
    }

    public function testExplicitLevelFiltersLowerRecords(): void
    {
        [$logger, $stream] = $this->logger('app', null, 'warning');

        $logger->info('skipped');
        $logger->warning('kept');

        $output = $this->written($stream);
        self::assertSame(1, substr_count($output, "\n"));
        self::assertStringContainsString('kept', $output);
    }

    public function testLogLevelEnvironmentVariableIsUsed(): void
    {
        putenv('LOG_LEVEL=warning');
        [$logger, $stream] = $this->logger();

        $logger->info('skipped');
        $logger->error('kept');

        $output = $this->written($stream);
        self::assertStringNotContainsString('skipped', $output);
        self::assertStringContainsString('kept', $output);
    }

    public function testDefaultLevelIsInfo(): void
    {
        [$logger, $stream] = $this->logger();

        $logger->debug('skipped');
        $logger->info('kept');

        $output = $this->written($stream);
        self::assertStringNotContainsString('skipped', $output);
        self::assertStringContainsString('kept', $output);
    }

    public function testUnknownLevelFallsBackToInfo(): void
    {
        [$logger, $stream] = $this->logger('app', null, 'verbose');

        $logger->debug('skipped');
        $logger->info('kept');

        $output = $this->written($stream);
        self::assertStringNotContainsString('skipped', $output);
        self::assertStringContainsString('kept', $output);
    }

    public function testDefaultHandlerWritesToStderrWithTheJsonLineFormatter(): void
    {
        $logger = LoggerFactory::create();

        $handlers = $logger->getHandlers();
        self::assertCount(1, $handlers);
        $handler = $handlers[0];
        self::assertInstanceOf(StreamHandler::class, $handler);
        self::assertSame('php://stderr', $handler->getUrl());
        self::assertSame(Level::Info, $handler->getLevel());
        self::assertInstanceOf(JsonLineFormatter::class, $handler->getFormatter());
    }
}
