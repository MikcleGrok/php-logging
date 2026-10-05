<?php

namespace Yasno\Logging\Processor;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;
use Yasno\Logging\RequestId;

final class RequestIdProcessor implements ProcessorInterface
{
    public function __construct(private readonly RequestId $requestId)
    {
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        $id = $this->requestId->get();
        if ($id === null) {
            return $record;
        }
        $record->extra['request_id'] = $id;
        return $record;
    }
}
