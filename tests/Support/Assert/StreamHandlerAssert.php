<?php

namespace Yasno\Logging\Tests\Support\Assert;

use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use PHPUnit\Framework\Assert;
use ReflectionProperty;

final class StreamHandlerAssert
{
    /**
     * The mode the logger's only handler would chmod its file to on every open; null when it never chmods.
     * Read from the handler so that nothing is opened, and no system path is touched, to find out.
     */
    public static function seeFilePermission(?int $expected, Logger $logger): void
    {
        $handlers = $logger->getHandlers();
        Assert::assertCount(1, $handlers);
        $handler = $handlers[0];
        Assert::assertInstanceOf(StreamHandler::class, $handler);

        $property = new ReflectionProperty(StreamHandler::class, 'filePermission');
        Assert::assertSame($expected, $property->getValue($handler));
    }
}
