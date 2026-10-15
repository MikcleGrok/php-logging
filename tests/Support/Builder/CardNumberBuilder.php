<?php

namespace Yasno\Logging\Tests\Support\Builder;

final class CardNumberBuilder
{
    private function __construct(
        private string $prefix,
        private int $length,
        private bool $validCheckDigit,
    ) {
    }

    /** A random Visa-like number of 16 digits with a valid Luhn check digit. */
    public static function create(): self
    {
        return new self('4', 16, true);
    }

    public function withPrefix(string $prefix): self
    {
        $this->prefix = $prefix;

        return $this;
    }

    public function withLength(int $length): self
    {
        $this->length = $length;

        return $this;
    }

    public function withBrokenCheckDigit(): self
    {
        $this->validCheckDigit = false;

        return $this;
    }

    public function build(): string
    {
        $body = $this->prefix;
        while (strlen($body) < $this->length - 1) {
            $body .= (string) random_int(0, 9);
        }
        $check = self::luhnCheckDigit($body);

        return $body . ($this->validCheckDigit ? $check : ($check + 1) % 10);
    }

    private static function luhnCheckDigit(string $body): int
    {
        $sum = 0;
        foreach (array_reverse(str_split($body)) as $position => $digit) {
            $value = (int) $digit * ($position % 2 === 0 ? 2 : 1);
            $sum += $value > 9 ? $value - 9 : $value;
        }

        return (10 - $sum % 10) % 10;
    }
}
