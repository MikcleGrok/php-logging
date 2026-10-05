<?php

namespace Yasno\Logging;

use Throwable;

/**
 * Builds a log context for a Throwable that is safe to ship to the log aggregator: class names plus messages with
 * secrets (URL credentials, DSN passwords, token query parameters) and email addresses masked. The trace is never
 * included; the raw exception is deliberately not put into the context either.
 */
final class ThrowableContext
{
    private const MAX_MESSAGE_LENGTH = 300;

    /**
     * @param list<string> $secrets exact secret strings (e.g. a DSN password) that must never appear in the output
     * @return array{exception: class-string<Throwable>, message: string, previous: ?class-string<Throwable>, previous_message: ?string}
     */
    public static function of(Throwable $throwable, array $secrets = []): array
    {
        $previous = $throwable->getPrevious();
        return [
            'exception' => $throwable::class,
            'message' => self::scrub($throwable->getMessage(), $secrets),
            'previous' => $previous === null ? null : $previous::class,
            'previous_message' => $previous === null ? null : self::scrub($previous->getMessage(), $secrets),
        ];
    }

    /** @param list<string> $secrets */
    public static function scrub(string $text, array $secrets = []): string
    {
        foreach ($secrets as $secret) {
            if ($secret !== '') {
                $text = str_replace([$secret, rawurlencode($secret), urlencode($secret)], '***', $text);
            }
        }
        $text = (string) preg_replace('~(\b[a-z][a-z0-9+.-]*://)[^\s/@]+@~i', '$1***@', $text);
        $text = (string) preg_replace('~(?<![A-Za-z0-9_])(t|token|password|pass|secret|key)=[^\s&"\']+~i', '$1=***', $text);
        $text = (string) preg_replace('~[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}~', '***@***', $text);
        $text = (string) preg_replace('~[^\x20-\x7E\x{0080}-\x{FFFF}]~u', '?', $text);
        return mb_substr($text, 0, self::MAX_MESSAGE_LENGTH);
    }

    /** The password part of a DSN-like URL, for use as a scrub secret; empty when there is none. */
    public static function dsnPassword(?string $dsn): string
    {
        $password = parse_url((string) $dsn, PHP_URL_PASS);
        return is_string($password) ? urldecode($password) : '';
    }
}
