<?php

namespace Yasno\Logging\Tests;

use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yasno\Logging\Formatter\JsonLineFormatter;
use Yasno\Logging\LoggerFactory;
use Yasno\Logging\RequestId;
use Yasno\Logging\Tests\Support\Assert\StreamHandlerAssert;

final class LoggerFactoryTest extends TestCase
{
    private string|false $previousLevel = false;
    /** @var list<string> files, links and directories created by the test, removed in reverse order */
    private array $createdPaths = [];
    private ?int $originalUmask = null;

    protected function setUp(): void
    {
        $this->previousLevel = getenv('LOG_LEVEL');
        putenv('LOG_LEVEL');
    }

    protected function tearDown(): void
    {
        if ($this->originalUmask !== null) {
            umask($this->originalUmask);
        }
        foreach (array_reverse($this->createdPaths) as $path) {
            if (is_link($path) || is_file($path)) {
                unlink($path);
            } elseif (is_dir($path)) {
                rmdir($path);
            }
        }
        if ($this->previousLevel === false) {
            putenv('LOG_LEVEL');
        } else {
            putenv('LOG_LEVEL=' . $this->previousLevel);
        }
    }

    /** The mode a new file gets from the system is part of the arrangement, not of the machine the test runs on. */
    private function arrangeUmask(int $mask): void
    {
        $this->originalUmask ??= umask($mask);
        umask($mask);
    }

    private function tempPath(string $suffix = ''): string
    {
        $path = sys_get_temp_dir() . '/logging-' . bin2hex(random_bytes(8)) . $suffix;
        $this->createdPaths[] = $path;

        return $path;
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

    #[DataProvider('umasks')]
    public function testALogFileCreatedFromAPathGetsTheRequestedModeWhateverTheUmask(int $umask): void
    {
        $this->arrangeUmask($umask);
        $logFile = $this->tempPath('.log');
        $logger = LoggerFactory::create('app', null, null, $logFile);

        $logger->info('hi');

        clearstatcache(true, $logFile);
        self::assertSame(LoggerFactory::LOG_FILE_PERMISSION, fileperms($logFile) & 0777);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function umasks(): iterable
    {
        yield 'open' => [0000];
        yield 'usual' => [0022];
        yield 'strict' => [0077];
    }

    public function testALogFileInADirectoryCreatedOnTheFlyGetsTheRequestedMode(): void
    {
        $this->arrangeUmask(0022);
        $directory = $this->tempPath();
        $nested = "$directory/nested";
        $logFile = "$nested/app.log";
        $this->createdPaths = [...$this->createdPaths, $nested, $logFile];
        $logger = LoggerFactory::create('app', null, null, $logFile);

        $logger->info('hi');

        clearstatcache(true, $logFile);
        self::assertSame(LoggerFactory::LOG_FILE_PERMISSION, fileperms($logFile) & 0777);
    }

    public function testAnExistingRegularFileIsTightenedToo(): void
    {
        $this->arrangeUmask(0022);
        $logFile = $this->tempPath('.log');
        touch($logFile);
        chmod($logFile, 0644);
        $logger = LoggerFactory::create('app', null, null, $logFile);

        $logger->info('hi');

        clearstatcache(true, $logFile);
        self::assertSame(LoggerFactory::LOG_FILE_PERMISSION, fileperms($logFile) & 0777);
    }

    public function testAnExistingFileKeepsItsModeWhenNoModeIsAskedFor(): void
    {
        $this->arrangeUmask(0022);
        $logFile = $this->tempPath('.log');
        touch($logFile);
        chmod($logFile, 0644);
        $logger = LoggerFactory::create('app', null, null, $logFile, [], null);

        $logger->info('hi');

        clearstatcache(true, $logFile);
        self::assertSame(0644, fileperms($logFile) & 0777);
    }

    public function testALogPathThatIsASymlinkIsWrittenThroughButItsTargetKeepsItsMode(): void
    {
        $this->arrangeUmask(0022);
        $target = $this->tempPath('.log');
        touch($target);
        chmod($target, 0644);
        $link = $this->tempPath('.link');
        symlink($target, $link);
        $logger = LoggerFactory::create('app', null, null, $link);
        $message = bin2hex(random_bytes(8));

        $logger->info($message);

        clearstatcache(true, $target);
        self::assertSame(0644, fileperms($target) & 0777);
        self::assertStringContainsString($message, (string) file_get_contents($target));
    }

    #[DataProvider('streamsThatMustNeverBeChmodded')]
    public function testNoModeIsRequestedForDevicesAndStreamWrappers(string $stream): void
    {
        $logger = LoggerFactory::create('app', null, null, $stream);

        StreamHandlerAssert::seeFilePermission(null, $logger);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function streamsThatMustNeverBeChmodded(): iterable
    {
        yield 'null device' => ['/dev/null'];
        yield 'stderr device' => ['/dev/stderr'];
        yield 'stdout device' => ['/dev/stdout'];
        yield 'php stderr' => ['php://stderr'];
        yield 'php stdout' => ['php://stdout'];
        yield 'php memory' => ['php://memory'];
        yield 'file wrapper' => ['file:///tmp/app.log'];
    }

    public function testNoModeIsRequestedForAResource(): void
    {
        $stream = fopen('php://memory', 'w+');
        self::assertIsResource($stream);

        $logger = LoggerFactory::create('app', null, null, $stream);

        StreamHandlerAssert::seeFilePermission(null, $logger);
    }

    public function testNoModeIsRequestedForADirectoryPath(): void
    {
        $logger = LoggerFactory::create('app', null, null, sys_get_temp_dir());

        StreamHandlerAssert::seeFilePermission(null, $logger);
    }

    public function testNoModeIsRequestedForAPathUnderARegularFile(): void
    {
        $file = $this->tempPath('.file');
        touch($file);

        $logger = LoggerFactory::create('app', null, null, "$file/app.log");

        StreamHandlerAssert::seeFilePermission(null, $logger);
    }

    public function testTheDefaultModeIsRequestedForAnOrdinaryPath(): void
    {
        $logger = LoggerFactory::create('app', null, null, $this->tempPath('.log'));

        StreamHandlerAssert::seeFilePermission(LoggerFactory::LOG_FILE_PERMISSION, $logger);
    }

    public function testAGivenModeIsRequestedForAnOrdinaryPath(): void
    {
        $logger = LoggerFactory::create('app', null, null, $this->tempPath('.log'), [], 0600);

        StreamHandlerAssert::seeFilePermission(0600, $logger);
    }

    public function testNoModeIsRequestedForAnOrdinaryPathWhenTheCallerAsksForNone(): void
    {
        $logger = LoggerFactory::create('app', null, null, $this->tempPath('.log'), [], null);

        StreamHandlerAssert::seeFilePermission(null, $logger);
    }
}
