<?php

namespace Yasno\Logging;

use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use UnhandledMatchError;
use Yasno\Logging\Formatter\JsonLineFormatter;
use Yasno\Logging\Processor\RequestIdProcessor;

final class LoggerFactory
{
    /**
     * @param resource|string $stream php://stderr in production; a resource or another URL for tests
     */
    public static function create(
        string $channel = 'app',
        ?RequestId $id = null,
        ?string $level = null,
        mixed $stream = 'php://stderr',
    ): Logger {
        $handler = new StreamHandler($stream, self::resolveLevel($level));
        $handler->setFormatter(new JsonLineFormatter());
        $logger = new Logger($channel, [$handler]);
        if ($id !== null) {
            $logger->pushProcessor(new RequestIdProcessor($id));
        }
        return $logger;
    }

    /** An unknown level name falls back to info: a typo in LOG_LEVEL must not take the site down. */
    private static function resolveLevel(?string $level): Level
    {
        $name = $level ?? (getenv('LOG_LEVEL') ?: 'info');
        try {
            return Level::fromName(ucfirst(strtolower($name)));
        } catch (UnhandledMatchError) {
            return Level::Info;
        }
    }
}
