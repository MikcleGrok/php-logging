<?php

namespace Yasno\Logging\Tests;

use DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;
use Yasno\Logging\Processor\RequestIdProcessor;
use Yasno\Logging\RequestId;

final class RequestIdProcessorTest extends TestCase
{
    private function record(): LogRecord
    {
        return new LogRecord(new DateTimeImmutable(), 'app', Level::Info, 'hi');
    }

    public function testItWritesTheRequestIdIntoExtra(): void
    {
        $id = new RequestId();
        $id->set('0123456789abcdef');

        $record = (new RequestIdProcessor($id))($this->record());

        self::assertSame('0123456789abcdef', $record->extra['request_id']);
    }

    public function testItLeavesTheRecordAloneWithoutAnId(): void
    {
        $record = (new RequestIdProcessor(new RequestId()))($this->record());

        self::assertArrayNotHasKey('request_id', $record->extra);
    }
}
