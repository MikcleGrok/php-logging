<?php

namespace Yasno\Logging\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Yasno\Logging\RequestId;

final class RequestIdTest extends TestCase
{
    #[DataProvider('invalidCandidates')]
    public function testNormalizeRejectsInvalidCandidates(?string $candidate): void
    {
        self::assertNull(RequestId::normalize($candidate));
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function invalidCandidates(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
        yield 'too short' => ['abc'];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'crlf injection' => ["abcdefgh\r\nX: y"];
        yield 'trailing newline' => ["0123456789abcdef\n"];
        yield 'spaces' => ['0123 4567 89ab'];
        yield 'quotes' => ['"0123456789abcdef"'];
        yield 'garbage 10 KB' => [str_repeat('x', 10240)];
    }

    #[DataProvider('validCandidates')]
    public function testNormalizeAcceptsValidCandidates(string $candidate): void
    {
        self::assertSame($candidate, RequestId::normalize($candidate));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validCandidates(): iterable
    {
        yield 'hex' => ['0123456789abcdef'];
        yield 'uuid' => ['3f2504e0-4f89-11d3-9a0c-0305e82c3301'];
        yield 'min length' => ['abcdefgh'];
        yield 'max length' => [str_repeat('A', 64)];
    }

    public function testGenerateReturnsThirtyTwoHexCharactersThatNormalizeAccepts(): void
    {
        $id = RequestId::generate();

        self::assertMatchesRegularExpression('~^[0-9a-f]{32}$~', $id);
        self::assertSame($id, RequestId::normalize($id));
        self::assertNotSame($id, RequestId::generate());
    }

    public function testSetGetReset(): void
    {
        $requestId = new RequestId();
        self::assertNull($requestId->get());

        $requestId->set('0123456789abcdef');
        self::assertSame('0123456789abcdef', $requestId->get());

        $requestId->reset();
        self::assertNull($requestId->get());
    }
}
