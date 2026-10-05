<?php

namespace Yasno\Logging\Tests;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yasno\Logging\ThrowableContext;

final class ThrowableContextTest extends TestCase
{
    public function testItReportsClassesAndMessagesOfTheThrowableAndItsPrevious(): void
    {
        $context = ThrowableContext::of(new RuntimeException('outer', 0, new LogicException('inner')));

        self::assertSame(RuntimeException::class, $context['exception']);
        self::assertSame('outer', $context['message']);
        self::assertSame(LogicException::class, $context['previous']);
        self::assertSame('inner', $context['previous_message']);
    }

    public function testWithoutAPreviousTheKeysAreNull(): void
    {
        $context = ThrowableContext::of(new RuntimeException('alone'));

        self::assertNull($context['previous']);
        self::assertNull($context['previous_message']);
    }

    #[DataProvider('secretCases')]
    public function testSecretsAreMasked(string $input, string $forbidden): void
    {
        self::assertStringNotContainsString($forbidden, ThrowableContext::scrub($input));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function secretCases(): iterable
    {
        yield 'dsn credentials' => ['Unable to connect to smtp://user:hunter2@smtp.example.net:587', 'hunter2'];
        yield 'dsn user only' => ['smtp://apikey@host', 'apikey'];
        yield 'token query' => ['GET /email/confirm?t=abc.def-ghi failed', 'abc.def-ghi'];
        yield 'token in the middle' => ['/password/reset?x=1&t=SECRETTOKEN&y=2', 'SECRETTOKEN'];
        yield 'password pair' => ['bad password=hunter2 given', 'hunter2'];
        yield 'email address' => ['Email "alice@example.com" does not comply', 'alice@example.com'];
    }

    public function testExplicitSecretsAreMaskedEvenWhenUrlEncoded(): void
    {
        $text = ThrowableContext::scrub('auth failed with p@ss w0rd: p%40ss%20w0rd', ['p@ss w0rd']);

        self::assertStringNotContainsString('w0rd', $text);
    }

    public function testDsnPasswordIsExtractedAndDecoded(): void
    {
        self::assertSame('p@ss', ThrowableContext::dsnPassword('smtp://user:p%40ss@host:25'));
        self::assertSame('', ThrowableContext::dsnPassword('null://null'));
        self::assertSame('', ThrowableContext::dsnPassword(null));
    }

    public function testMessagesAreTruncatedAndControlCharactersReplaced(): void
    {
        $text = ThrowableContext::scrub("line\r\nforged " . str_repeat('x', 1000));

        self::assertSame(300, mb_strlen($text));
        self::assertStringNotContainsString("\n", $text);
        self::assertStringNotContainsString("\r", $text);
    }
}
