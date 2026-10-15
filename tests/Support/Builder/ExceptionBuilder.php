<?php

namespace Yasno\Logging\Tests\Support\Builder;

use RuntimeException;
use Throwable;

final class ExceptionBuilder
{
    private function __construct(
        private string $message,
        private ?Throwable $previous,
    ) {
    }

    public static function create(): self
    {
        return new self('failure ' . bin2hex(random_bytes(4)), null);
    }

    public function withMessage(string $message): self
    {
        $this->message = $message;

        return $this;
    }

    public function withPrevious(Throwable $previous): self
    {
        $this->previous = $previous;

        return $this;
    }

    public function build(): RuntimeException
    {
        return new RuntimeException($this->message, 0, $this->previous);
    }
}
