<?php

namespace Yasno\Logging\Tests\Support\Builder;

use DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;

final class LogRecordBuilder
{
    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed> $extra
     */
    private function __construct(
        private DateTimeImmutable $datetime,
        private string $channel,
        private Level $level,
        private string $message,
        private array $context,
        private array $extra,
    ) {
    }

    public static function create(): self
    {
        return new self(
            new DateTimeImmutable(),
            'app',
            Level::Info,
            'message ' . bin2hex(random_bytes(4)),
            ['order' => bin2hex(random_bytes(4))],
            [],
        );
    }

    public function withMessage(string $message): self
    {
        $this->message = $message;

        return $this;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function withContext(array $context): self
    {
        $this->context = $context;

        return $this;
    }

    /**
     * @param array<string, mixed> $extra
     */
    public function withExtra(array $extra): self
    {
        $this->extra = $extra;

        return $this;
    }

    public function build(): LogRecord
    {
        return new LogRecord($this->datetime, $this->channel, $this->level, $this->message, $this->context, $this->extra);
    }
}
