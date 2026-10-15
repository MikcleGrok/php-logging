<?php

namespace Yasno\Logging\Tests\Support\Assert;

use PHPUnit\Framework\Assert;

final class RequestIdAssert
{
    /** An id made by RequestId::generate(): 32 lowercase hex characters. */
    public static function seeGenerated(string $id): void
    {
        Assert::assertMatchesRegularExpression('~^[0-9a-f]{32}$~', $id);
    }
}
