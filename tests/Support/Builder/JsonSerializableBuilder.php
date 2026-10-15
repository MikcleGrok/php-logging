<?php

namespace Yasno\Logging\Tests\Support\Builder;

use JsonSerializable;

final class JsonSerializableBuilder
{
    /**
     * @param array<string, mixed> $data
     */
    private function __construct(private array $data)
    {
    }

    public static function create(): self
    {
        return new self(['id' => bin2hex(random_bytes(4))]);
    }

    /**
     * @param array<string, mixed> $data
     */
    public function withData(array $data): self
    {
        $this->data = $data;

        return $this;
    }

    public function build(): JsonSerializable
    {
        return new class ($this->data) implements JsonSerializable {
            /**
             * @param array<string, mixed> $data
             */
            public function __construct(private readonly array $data)
            {
            }

            /**
             * @return array<string, mixed>
             */
            public function jsonSerialize(): array
            {
                return $this->data;
            }
        };
    }
}
