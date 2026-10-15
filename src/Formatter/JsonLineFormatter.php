<?php

namespace Yasno\Logging\Formatter;

use ArrayIterator;
use ArrayObject;
use DateTimeInterface;
use JsonSerializable;
use Monolog\Formatter\JsonFormatter;
use Monolog\LogRecord;
use SplObjectStorage;
use UnitEnum;
use Yasno\Logging\SensitiveKey;
use Yasno\Logging\ThrowableContext;

/**
 * One JSON object per line, no stack traces, extra.request_id lifted to the top level, line (with the trailing
 * newline) never longer than 8 KiB so that docker/php-fpm do not split it. Values under sensitive keys (see
 * SensitiveKey, plus the words given to the constructor) are replaced with "***" at any depth of context/extra; key
 * names are masked too, and credentials inside every string (including normalized exception messages) are masked
 * with ThrowableContext::mask().
 */
final class JsonLineFormatter extends JsonFormatter
{
    public const MAX_LINE = 8192;
    private const TRUNCATED_MESSAGE_LENGTH = 2048;
    private const MASK = '***';
    private const MAX_DEPTH = 10;

    /** The words that make a key sensitive by default (see SensitiveKey). */
    public const DEFAULT_SENSITIVE_KEYS = SensitiveKey::WORDS;

    private const MEMO_LIMIT = 4096;

    /** @var list<list<string>> the words of every additional key, e.g. [['passport'], ['iban', 'code']] */
    private readonly array $sensitiveWords;
    /** @var array<string, bool> */
    private array $sensitiveMemo = [];
    /** @var array<string, string> */
    private array $maskedKeys = [];

    /**
     * @param list<string> $sensitiveKeys additional keys, matched by words exactly like the built-in ones: "passport"
     *                                    redacts passport, passport_number and userPassport but not passports or
     *                                    mypassport, and "iban_code" redacts IBAN-Code (case, "-", "_", ".", camelCase
     *                                    and a trailing number are not told apart)
     */
    public function __construct(array $sensitiveKeys = [])
    {
        parent::__construct(self::BATCH_MODE_NEWLINES, true, true, false);
        $words = array_map(SensitiveKey::words(...), $sensitiveKeys);
        $this->sensitiveWords = array_values(array_filter($words));
    }

    public function format(LogRecord $record): string
    {
        $data = (array) $this->normalizeRecord($record);
        $extra = $data['extra'] ?? null;
        if (is_array($extra) && isset($extra['request_id'])) {
            $data['request_id'] = $extra['request_id'];
            unset($extra['request_id']);
            $data['extra'] = $extra;
            if ($extra === []) {
                unset($data['extra']);
            }
        }
        $data = $this->redact($data);
        $line = $this->toJson($data, true);
        if (strlen($line) + 1 <= self::MAX_LINE) {
            return $line . "\n";
        }
        $data['context'] = ['truncated' => true];
        unset($data['extra']);
        $length = self::TRUNCATED_MESSAGE_LENGTH;
        $message = (string) ($data['message'] ?? '');
        do {
            $data['message'] = mb_strcut($message, 0, $length);
            $line = $this->toJson($data, true);
            $length = intdiv($length, 2);
        } while (strlen($line) + 1 > self::MAX_LINE && $length > 0);
        return $line . "\n";
    }

    /**
     * @param array<mixed> $data a normalized record
     * @return array<mixed>
     */
    private function redact(array $data): array
    {
        if (isset($data['message']) && is_string($data['message'])) {
            $data['message'] = ThrowableContext::mask($data['message']);
        }
        foreach (['context', 'extra'] as $section) {
            if (isset($data[$section]) && is_array($data[$section])) {
                $data[$section] = $this->redactTree($data[$section], 0, new SplObjectStorage());
            }
        }
        return $data;
    }

    /**
     * @param array<mixed> $tree
     * @param SplObjectStorage<object, null> $path objects being visited right now, to cut cycles
     * @return array<mixed>
     */
    private function redactTree(array $tree, int $depth, SplObjectStorage $path): array
    {
        $result = [];
        foreach ($tree as $key => $value) {
            if (!is_string($key)) {
                $result[$key] = $this->redactValue($value, $depth + 1, $path);
                continue;
            }
            $masksValue = $value !== null && $this->isSensitive($key) && !SensitiveKey::isMetadata($key, $value);
            $newValue = $masksValue ? self::MASK : $this->redactValue($value, $depth + 1, $path);
            $result[self::freeKey($result, $this->maskedKey($key))] = $newValue;
        }
        return $result;
    }

    /** Keys repeat from record to record, so the (deterministic) masked form is remembered. */
    private function maskedKey(string $key): string
    {
        if (!isset($this->maskedKeys[$key])) {
            if (count($this->maskedKeys) >= self::MEMO_LIMIT) {
                $this->maskedKeys = [];
            }
            $this->maskedKeys[$key] = ThrowableContext::mask($key);
        }
        return $this->maskedKeys[$key];
    }

    /**
     * Two keys that differ only in a masked secret (password=a, password=b) must not merge into one entry.
     *
     * @param array<mixed> $result
     */
    private static function freeKey(array $result, string $key): string
    {
        $free = $key;
        for ($number = 2; array_key_exists($free, $result); $number++) {
            $free = $key . '#' . $number;
        }
        return $free;
    }

    /**
     * Objects are walked the way json_encode() would see them (JsonSerializable output, a date as its formatted string,
     * the elements of an ArrayObject/ArrayIterator, otherwise public properties), because the line is encoded after
     * this step and would otherwise print them unredacted.
     *
     * @param SplObjectStorage<object, null> $path
     */
    private function redactValue(mixed $value, int $depth, SplObjectStorage $path): mixed
    {
        if (is_string($value)) {
            return ThrowableContext::mask($value);
        }
        if (!is_array($value) && !is_object($value) || $value instanceof UnitEnum) {
            return $value;
        }
        if ($depth > self::MAX_DEPTH) {
            return '[max depth]';
        }
        if (is_array($value)) {
            return $this->redactTree($value, $depth, $path);
        }
        if ($value instanceof DateTimeInterface) {
            return $this->formatDate($value);
        }
        if (isset($path[$value])) {
            return '[circular]';
        }
        $path[$value] = null;
        try {
            if ($value instanceof JsonSerializable) {
                return $this->redactValue($value->jsonSerialize(), $depth + 1, $path);
            }
            $properties = $value instanceof ArrayObject || $value instanceof ArrayIterator
                ? $value->getArrayCopy()
                : get_object_vars($value);
            return (object) $this->redactTree($properties, $depth, $path);
        } finally {
            unset($path[$value]);
        }
    }

    private function isSensitive(string $key): bool
    {
        if (SensitiveKey::isSensitive($key)) {
            return true;
        }
        if ($this->sensitiveWords === []) {
            return false;
        }
        if (!isset($this->sensitiveMemo[$key])) {
            if (count($this->sensitiveMemo) >= self::MEMO_LIMIT) {
                $this->sensitiveMemo = [];
            }
            $this->sensitiveMemo[$key] = $this->hasAdditionalWords(SensitiveKey::words($key));
        }
        return $this->sensitiveMemo[$key];
    }

    /**
     * @param list<string> $keyWords
     */
    private function hasAdditionalWords(array $keyWords): bool
    {
        $withoutNumbers = array_map(static fn (string $word): string => rtrim($word, '0123456789'), $keyWords);
        foreach ($this->sensitiveWords as $words) {
            if (self::containsSequence($keyWords, $words) || self::containsSequence($withoutNumbers, $words)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param list<string> $haystack
     * @param list<string> $needle
     */
    private static function containsSequence(array $haystack, array $needle): bool
    {
        $length = count($needle);
        for ($offset = 0; $offset + $length <= count($haystack); $offset++) {
            if (array_slice($haystack, $offset, $length) === $needle) {
                return true;
            }
        }
        return false;
    }
}
