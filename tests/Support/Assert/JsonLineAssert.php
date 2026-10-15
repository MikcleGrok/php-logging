<?php

namespace Yasno\Logging\Tests\Support\Assert;

use PHPUnit\Framework\Assert;

final class JsonLineAssert
{
    /**
     * The output is exactly one valid UTF-8 JSON object terminated by a single newline; returns it decoded.
     *
     * @return array<string, mixed>
     */
    public static function seeSingleJsonLine(string $output): array
    {
        Assert::assertStringEndsWith("\n", $output);
        Assert::assertSame(1, substr_count($output, "\n"), 'the line must not contain other newlines');
        Assert::assertTrue(mb_check_encoding($output, 'UTF-8'), 'the line must be valid UTF-8');
        $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($data);

        return $data;
    }
}
