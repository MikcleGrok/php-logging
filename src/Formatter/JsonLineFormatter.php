<?php

namespace Yasno\Logging\Formatter;

use Monolog\Formatter\JsonFormatter;
use Monolog\LogRecord;

/**
 * One JSON object per line, no stack traces, extra.request_id lifted to the top level, line (with the trailing
 * newline) never longer than 8 KiB so that docker/php-fpm do not split it.
 */
final class JsonLineFormatter extends JsonFormatter
{
    private const MAX_LINE = 8192;
    private const TRUNCATED_MESSAGE_LENGTH = 2048;

    public function __construct()
    {
        parent::__construct(self::BATCH_MODE_NEWLINES, true, true, false);
    }

    public function format(LogRecord $record): string
    {
        $data = $this->normalizeRecord($record);
        if (isset($data['extra']['request_id'])) {
            $data['request_id'] = $data['extra']['request_id'];
            unset($data['extra']['request_id']);
            if ($data['extra'] === []) {
                unset($data['extra']);
            }
        }
        $line = $this->toJson($data, true);
        if (strlen($line) + 1 <= self::MAX_LINE) {
            return $line . "\n";
        }
        $data['context'] = ['truncated' => true];
        unset($data['extra']);
        $length = self::TRUNCATED_MESSAGE_LENGTH;
        $message = (string) ($data['message'] ?? '');
        do {
            $data['message'] = mb_strcut($message, 0, $length);
            $line = $this->toJson($data, true);
            $length = intdiv($length, 2);
        } while (strlen($line) + 1 > self::MAX_LINE && $length > 0);
        return $line . "\n";
    }
}
