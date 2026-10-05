<?php

namespace Yasno\Logging;

/**
 * Holds the id of the request being handled so that processors and middleware share it. Not thread-safe by design:
 * php-fpm handles one request per process; reset() must be called when the request ends.
 */
final class RequestId
{
    private const PATTERN = '~^[A-Za-z0-9-]{8,64}$~D';

    private ?string $id = null;

    public function set(string $id): void
    {
        $this->id = $id;
    }

    public function get(): ?string
    {
        return $this->id;
    }

    public function reset(): void
    {
        $this->id = null;
    }

    /** Returns the candidate when it is a safe id (8-64 chars of [A-Za-z0-9-]), otherwise null. */
    public static function normalize(?string $candidate): ?string
    {
        if ($candidate === null || preg_match(self::PATTERN, $candidate) !== 1) {
            return null;
        }
        return $candidate;
    }

    public static function generate(): string
    {
        return bin2hex(random_bytes(16));
    }
}
