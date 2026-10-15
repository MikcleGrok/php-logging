<?php

namespace Yasno\Logging;

use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use Yasno\Logging\Formatter\JsonLineFormatter;
use Yasno\Logging\Processor\RequestIdProcessor;

final class LoggerFactory
{
    /** A log file created from a path is readable by the owner and group only, whatever the umask is. */
    public const LOG_FILE_PERMISSION = 0640;

    /**
     * @param resource|string $stream php://stderr in production; a resource or another URL for tests
     * @param list<string> $sensitiveKeys additional context/extra keys to redact, matched by words (see JsonLineFormatter)
     * @param int|null $filePermission the mode of a log file given as a path (0640 by default); null never touches the
     *                                 mode of the file, whatever it is, and a stream wrapper, a device, a symlink or a
     *                                 resource is never touched either
     */
    public static function create(
        string $channel = 'app',
        ?RequestId $id = null,
        ?string $level = null,
        mixed $stream = 'php://stderr',
        array $sensitiveKeys = [],
        ?int $filePermission = self::LOG_FILE_PERMISSION,
    ): Logger {
        $permission = $filePermission === null ? null : self::filePermission($stream, $filePermission);
        $handler = new StreamHandler($stream, self::resolveLevel($level), true, $permission);
        $handler->setFormatter(new JsonLineFormatter($sensitiveKeys));
        $logger = new Logger($channel, [$handler]);
        if ($id !== null) {
            $logger->pushProcessor(new RequestIdProcessor($id));
        }
        return $logger;
    }

    /**
     * Monolog runs chmod on the path every time it opens it, so the mode is requested only for an ordinary log file:
     * a string path without a stream wrapper (php://stderr), not a symlink, not a device or a FIFO (/dev/null,
     * /dev/stderr), and either an existing regular file or a path that does not exist yet.
     */
    private static function filePermission(mixed $stream, int $mode): ?int
    {
        if (!is_string($stream) || str_contains($stream, '://')) {
            return null;
        }
        if (is_link($stream)) {
            return null;
        }
        if (file_exists($stream)) {
            return is_file($stream) ? $mode : null;
        }
        $parent = dirname($stream);
        return !file_exists($parent) || is_dir($parent) ? $mode : null;
    }

    /** An unknown level name falls back to info: a typo in LOG_LEVEL must not take the site down. */
    private static function resolveLevel(?string $level): Level
    {
        $name = $level ?? (getenv('LOG_LEVEL') ?: 'info');
        foreach (Level::cases() as $case) {
            if (strcasecmp($case->name, $name) === 0) {
                return $case;
            }
        }
        return Level::Info;
    }
}
