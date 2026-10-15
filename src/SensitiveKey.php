<?php

namespace Yasno\Logging;

/**
 * Decides whether a key name (an array key, a JSON key, the name left of "=" or ":" in a text) denotes a secret.
 * The name is split into words (snake_case, kebab-case, camelCase, dots), so accessToken, access_token and X-Api-Key
 * match while monkey, bypass, secretary and tokenizer do not. Metadata about a secret is not a secret: booleans,
 * counters and sizes (password_length, tokens_count, max_tokens) and timestamps (password_changed_at) pass through.
 */
final class SensitiveKey
{
    /** Words that make a key sensitive. */
    public const WORDS = [
        'password',
        'passwd',
        'pwd',
        'pass',
        'passphrase',
        'passcode',
        'secret',
        'secrets',
        'token',
        'tokens',
        'jwt',
        'auth',
        'authorization',
        'cookie',
        'cookies',
        'session',
        'sessionid',
        'sid',
        'signature',
        'bearer',
        'otp',
        'credential',
        'credentials',
        'apikey',
        'privatekey',
        'secretkey',
        'accesskey',
        'signingkey',
        'sessid',
        'phpsessid',
        'jsessionid',
        'creds',
        'csrf',
        'xsrf',
        'pin',
        'cvv',
        'cvc',
        'cvv2',
        'cvc2',
        'iban',
        'ssn',
        'dsn',
        'totp',
        'hmac',
        'sig',
        'license',
        'cardnumber',
        'pw',
    ];

    /** "key" alone is too common (cache_key, sort_key); it is sensitive after one of these words. */
    private const KEY_PREFIXES = [
        'api',
        'private',
        'access',
        'secret',
        'signing',
        'encryption',
        'master',
        'client',
        'app',
        'account',
        'subscription',
        'deploy',
        'service',
        'routing',
        'ssh',
        'functions',
        'shared',
        'webhook',
        'integration',
        'consumer',
        'bot',
        'stripe',
        'sendgrid',
        'twilio',
        'openai',
        'github',
        'gitlab',
        'slack',
        'mailgun',
        'aws',
        'google',
        'firebase',
        'sentry',
    ];
    /** Two-word names that are secrets although neither word is on its own. */
    private const PAIRS = [
        ['card', 'number'],
        ['card', 'num'],
        ['card', 'no'],
        ['cc', 'number'],
        ['cc', 'num'],
        ['credit', 'card'],
        ['security', 'code'],
        ['verification', 'code'],
        ['reset', 'code'],
        ['sms', 'code'],
        ['mfa', 'code'],
        ['connection', 'string'],
        ['webhook', 'url'],
    ];
    /** Run-on forms such as accesstoken, clientsecret, dbpassword, newpwd. */
    private const WORD_SUFFIXES = ['password', 'passwd', 'pwd', 'secret', 'token', 'apikey'];
    /** "pass" and "pw" end ordinary words (bypass, compass), so they count as a suffix only after one of these: dbpass. */
    private const SHORT_SUFFIXES = ['pass', 'pw'];
    private const SHORT_SUFFIX_PREFIXES = [
        'db',
        'user',
        'admin',
        'root',
        'mail',
        'smtp',
        'ftp',
        'sftp',
        'ssh',
        'sql',
        'mysql',
        'pg',
        'redis',
        'login',
        'wifi',
        'master',
        'app',
        'api',
        'sys',
        'proxy',
        'ldap',
        'imap',
        'pop',
        'auth',
        'account',
        'new',
        'old',
        'temp',
        'tmp',
        'default',
    ];
    private const MEMO_LIMIT = 4096;
    /** Measurement words; a number under a sensitive name is metadata only when the name ENDS with one of them. */
    private const MEASURE_SUFFIXES = [
        'count',
        'limit',
        'total',
        'ttl',
        'length',
        'len',
        'size',
        'duration',
        'age',
        'timeout',
        'lifetime',
        'retries',
        'retry',
        'attempts',
        'failed',
        'failures',
        'ms',
        'sec',
        'secs',
        'seconds',
        'minutes',
        'hours',
        'days',
        'bytes',
        'ts',
        'timestamp',
        'epoch',
    ];
    /** Token usage (tokens_used, prompt_tokens, input_tokens) counts as a measurement only in names with "token(s)". */
    private const USAGE_SUFFIXES = ['used', 'remaining'];
    private const USAGE_PREFIXES = ['prompt', 'completion', 'input', 'output'];
    private const TOKEN_WORDS = ['token', 'tokens'];
    private const SIZE_PREFIXES = ['max', 'min', 'num', 'total'];
    private const TIME_WORDS = ['at', 'date', 'time', 'changed', 'updated', 'created', 'expires', 'expiry', 'expired'];
    /** "expires_in", "valid_until"-style names: the unit word follows the expiry word. */
    private const EXPIRY_WORDS = ['expires', 'expiry', 'expired', 'valid'];
    private const DATE_VALUE = '~^\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]{1,16}(?:Z|[+-]\d{2}:?\d{2})?)?$~D';

    /** @var array<string, bool> */
    private static array $memo = [];
    /** @var array<string, list<string>> */
    private static array $wordsMemo = [];
    /** @var array<string, true>|null */
    private static ?array $wordSet = null;
    /** @var array<string, true>|null */
    private static ?array $pairSet = null;

    /**
     * @param bool $bare also treat a lone "key" and "t" as sensitive (the left side of key=value in free text)
     */
    public static function isSensitive(string $key, bool $bare = false): bool
    {
        $memoKey = ($bare ? 'b' : 'n') . $key;
        if (isset(self::$memo[$memoKey])) {
            return self::$memo[$memoKey];
        }
        if (count(self::$memo) >= self::MEMO_LIMIT) {
            self::$memo = [];
        }

        return self::$memo[$memoKey] = self::compute($key, $bare);
    }

    private static function compute(string $key, bool $bare): bool
    {
        $words = self::words($key);
        if ($bare && ($words === ['key'] || $words === ['t'])) {
            return true;
        }
        foreach ($words as $index => $word) {
            $previous = $words[$index - 1] ?? null;
            $base = rtrim($word, '0123456789');
            $hasDigitTail = $base !== '' && $base !== $word;
            if (self::matchesWord($word, $previous) || ($hasDigitTail && self::matchesWord($base, $previous))) {
                return true;
            }
        }
        return false;
    }

    private static function matchesWord(string $word, ?string $previous): bool
    {
        self::$wordSet ??= array_fill_keys(self::WORDS, true);
        self::$pairSet ??= array_fill_keys(array_map(static fn (array $pair): string => implode(' ', $pair), self::PAIRS), true);
        if (isset(self::$wordSet[$word])) {
            return true;
        }
        if ($previous === null) {
            return self::hasSuffix($word);
        }
        if ($word === 'key' && in_array($previous, self::KEY_PREFIXES, true)) {
            return true;
        }
        return isset(self::$pairSet[$previous . ' ' . $word]) || self::hasSuffix($word);
    }

    /** A run-on form: accesstoken, clientsecret, dbpassword, newpwd, and dbpass / userpw after a known prefix. */
    private static function hasSuffix(string $word): bool
    {
        foreach (self::WORD_SUFFIXES as $suffix) {
            if (strlen($word) > strlen($suffix) && str_ends_with($word, $suffix)) {
                return true;
            }
        }
        foreach (self::SHORT_SUFFIXES as $suffix) {
            $prefix = substr($word, 0, -strlen($suffix));
            if (strlen($word) > strlen($suffix) && str_ends_with($word, $suffix)
                && in_array($prefix, self::SHORT_SUFFIX_PREFIXES, true)) {
                return true;
            }
        }
        return false;
    }

    /** True when the key is sensitive and the value can actually carry a secret. */
    public static function shouldMask(string $key, mixed $value, bool $bare = false): bool
    {
        return self::isSensitive($key, $bare) && !self::isMetadata($key, $value);
    }

    /**
     * A flag, a counter/size or a timestamp stored under a sensitive-looking key. A measurement word counts only as
     * the LAST word of the name (password_length, otp_ttl, token_expires_in); anywhere else it is just a word of the
     * name, so one_time_password, pin_input and cvv_used with a number are still secrets.
     */
    public static function isMetadata(string $key, mixed $value): bool
    {
        if (is_bool($value)) {
            return true;
        }
        $words = self::words($key);
        $isNumber = is_int($value) || is_float($value);
        if ($isNumber && self::isMeasure($words)) {
            return true;
        }
        if (self::isTimeName($words)) {
            return $isNumber || (is_string($value) && preg_match(self::DATE_VALUE, $value) === 1);
        }
        return false;
    }

    /**
     * @param list<string> $words
     */
    private static function isMeasure(array $words): bool
    {
        $first = $words[0] ?? '';
        $last = $words === [] ? '' : end($words);
        if (in_array($first, self::SIZE_PREFIXES, true)) {
            return true;
        }
        if (in_array($last, self::MEASURE_SUFFIXES, true) || self::isTimeName($words)) {
            return true;
        }
        $isUsage = in_array($last, self::USAGE_SUFFIXES, true) || in_array($first, self::USAGE_PREFIXES, true);
        return $isUsage && array_intersect($words, self::TOKEN_WORDS) !== [];
    }

    /**
     * @param list<string> $words
     */
    private static function isTimeName(array $words): bool
    {
        $last = $words === [] ? '' : end($words);
        if (in_array($last, self::TIME_WORDS, true)) {
            return true;
        }
        return $last === 'in' && count($words) > 1 && in_array($words[count($words) - 2], self::EXPIRY_WORDS, true);
    }

    /**
     * The lowercase words of a key: snake_case, kebab-case, dotted and camelCase (XApiKey is x, api, key).
     *
     * @return list<string>
     */
    public static function words(string $key): array
    {
        if (isset(self::$wordsMemo[$key])) {
            return self::$wordsMemo[$key];
        }
        if (count(self::$wordsMemo) >= self::MEMO_LIMIT) {
            self::$wordsMemo = [];
        }
        $spaced = (string) preg_replace(['~([a-z0-9])([A-Z])~', '~([A-Z]+)([A-Z][a-z])~'], '$1_$2', $key);
        $words = preg_split('~[^a-z0-9]+~', strtolower($spaced), -1, PREG_SPLIT_NO_EMPTY);

        return self::$wordsMemo[$key] = $words === false ? [] : $words;
    }
}
