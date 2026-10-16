<?php

namespace Yasno\Logging;

use Throwable;

/**
 * Builds a log context for a Throwable that is safe to ship to the log aggregator: class names plus messages with
 * secrets (URL credentials, DSN passwords, token query parameters, Authorization headers, Bearer/Basic credentials,
 * JWT and GitHub/GitLab/Slack/AWS/Stripe/Google/SendGrid/npm/Telegram tokens, PEM private keys, payment card numbers,
 * JSON and Python-repr (scalars, arrays and objects) and key=value pairs of password-like names, quoted, escaped or
 * percent-encoded) and email addresses masked. The trace is never included; the raw exception is deliberately not
 * put into the context either.
 */
final class ThrowableContext
{
    public const MAX_MESSAGE_LENGTH = 300;
    public const MAX_MASK_INPUT_BYTES = 65536;
    /** Only the first MAX_MESSAGE_LENGTH characters survive scrub(); the e-mail/control regexes need not see more. */
    private const SCRUB_REGEX_INPUT_LENGTH = 1024;
    private const UNMASKABLE = '[unmaskable]';
    private const IDENT = '[A-Za-z][A-Za-z0-9_.-]{0,64}';
    /** A name with PHP array subscripts: user[password], password[0]. */
    private const SUBSCRIPTED_IDENT = '[A-Za-z][A-Za-z0-9_.-]{0,64}(?:\[[^\]\s]{0,32}\]){0,4}';
    private const AUTH_SCHEME = '(?:(?:Basic|Bearer|Digest|Negotiate|NTLM|Token)[ \t]+)?';
    private const EQ_VALUE = '(?:"[^"]*+"?|\'[^\']*+\'?|' . self::AUTH_SCHEME . '[^\s&"\']+)';
    /** Words that follow "token:" / "password:" in an error text and are a state, not a value. */
    private const STATE_WORDS = '(?i:expired|invalid|missing|required|revoked|denied|rejected|forbidden|unauthorized'
        . '|empty|unknown|undefined|null)';
    private const COLON_VALUE = '(?!' . self::STATE_WORDS . '\b)'
        . '(?:"[^"]*+"?|\'[^\']*+\'?|' . self::AUTH_SCHEME . '[^\s,;&"\']+)';
    private const JSON_VALUE = '(?:"(?:[^"\\\\]++|\\\\.)*+"?|[0-9][0-9.eE+-]*+)';
    private const PYTHON_VALUE = '(?:\'(?:[^\'\\\\]++|\\\\.)*+\'?|"(?:[^"\\\\]++|\\\\.)*+"?|[0-9][0-9.eE+-]*+)';
    private const PLAIN = 1;
    private const ESCAPED = 2;
    private const PYTHON = 3;
    /** A JSON array/object under a sensitive key is masked up to its closing bracket; a longer one is unmaskable. */
    private const MAX_CONTAINER_BYTES = 4096;
    /** A userinfo is "user:password@" (the password may hold @ / ? # :) or "user@", also without a scheme. */
    private const URL_USERINFO = '~(\b[a-z][a-z0-9+.-]{0,32}://|(?<![A-Za-z0-9_:/.@-])//)'
        . '(?:[^\s/?#:]{0,2048}:(?!\d{1,5}[/?#])[^\s]{0,4096}|[^\s/?#@]{1,2048})@~i';
    private const GO_DSN_HOST = '(?:tcp|udp|unix|cloudsql|pipe|memory)\\(';
    /** The Go MySQL driver form: user:password@tcp(host:3306)/db. */
    private const GO_DSN_USERINFO = '~(?<![A-Za-z0-9_.:-])[A-Za-z0-9_.-]{1,64}+:(?!//)'
        . '[^\s@]{0,128}+(?:@(?!' . self::GO_DSN_HOST . ')[^\s@]{0,128}+){0,3}+'
        . '@(?=' . self::GO_DSN_HOST . ')~';
    /** "Basic <base64>" outside an Authorization header; plain words after "Basic" are left alone. */
    private const BASIC_CREDENTIALS = '~((?i:\bBasic)[ \t]+)(?=[A-Za-z0-9+/]*(?:[0-9+/]|[a-z][A-Z]))'
        . '[A-Za-z0-9+/]{8,}+={0,2}~';
    /**
     * Bare tokens with a recognisable shape: JWT, GitHub, GitLab, Slack, AWS access key id, Stripe, Google API key,
     * SendGrid, npm and a Telegram bot token (bot<id>:<token>).
     */
    private const KNOWN_TOKENS = '~(?<![A-Za-z0-9])(?:'
        . 'eyJ[A-Za-z0-9_-]{8,}+\.eyJ[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]*+'
        . '|gh[pousr]_[A-Za-z0-9]{30,}+|github_pat_[A-Za-z0-9_]{20,}+|xox[baprs]-[A-Za-z0-9-]{10,}+'
        . '|glpat-[A-Za-z0-9_-]{20,}+|npm_[A-Za-z0-9]{36,}+'
        . '|(?:[sr]k_(?:live|test)|whsec)_[A-Za-z0-9]{16,}+|AIza[0-9A-Za-z_-]{35,}+'
        . '|SG\.[A-Za-z0-9_-]{16,}+\.[A-Za-z0-9_-]{16,}+|bot[0-9]{6,}+:[A-Za-z0-9_-]{30,}+'
        . '|(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9]))~';
    /** The secret part of a Slack incoming webhook URL. */
    private const SLACK_WEBHOOK = '~(?<=hooks\.slack\.com/services/)[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+~';
    /** A PEM private key (also OpenSSH, encrypted, PGP): masked up to its END line, or to the end of a cut text. */
    private const PEM_PRIVATE_KEY = '~(-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----)'
        . '(?:[^-]++|-(?!----END ))*+(?:-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----)?~';
    /**
     * 13-19 digits, or 4-4-4-1..7 / Amex 4-6-5 groups with one separator; Luhn and the issuer prefix decide. The
     * number must not be glued to a letter, "_" or "." (hash, identifier, decimal fraction) unless the glue is a
     * card word (card4111..., cc_4111..., pan-4111...).
     */
    private const CARD_NUMBER = '~(?:(?<![0-9A-Za-z_.])|(?<=(?i:card))|(?<=(?i:card[_-]))|(?<=(?i:pan[_-]))'
        . '|(?<=(?i:cc[_-])))(?:[0-9]{13,19}'
        . '|[0-9]{4}([ -])[0-9]{4}\\1[0-9]{4}\\1[0-9]{1,7}|[0-9]{4}([ -])[0-9]{6}\\2[0-9]{5})(?![0-9A-Za-z])~';
    private const CARD_ISSUER_PREFIX = '~^(?:4|5[0-8]|6[0-9]|3[0-9]|2[2-7])~';
    private const ESCAPED_JSON_VALUE = '(?:\\\\"[^"\\\\]*+(?:\\\\")?|[0-9][0-9.eE+-]*+)';

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
        $text = mb_substr(self::mask($text, $secrets), 0, self::SCRUB_REGEX_INPUT_LENGTH);
        $text = (string) preg_replace('~[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}~', '***@***', $text);
        $text = (string) preg_replace('~[^\x20-\x7E\x{0080}-\x{FFFF}]~u', '?', $text);
        return mb_substr($text, 0, self::MAX_MESSAGE_LENGTH);
    }

    /**
     * Masks credentials only (explicit secrets, URL/DSN credentials, Authorization headers, Bearer tokens, JSON and
     * key=value / key: value pairs of password-like names); does not touch e-mails, control characters or length.
     * Invalid UTF-8 bytes are replaced with "?" first so that the regexes never fail on them.
     *
     * @param list<string> $secrets
     */
    public static function mask(string $text, array $secrets = []): string
    {
        $text = mb_strcut(mb_scrub($text, 'UTF-8'), 0, self::MAX_MASK_INPUT_BYTES);
        foreach ($secrets as $secret) {
            if ($secret !== '') {
                $text = str_replace([$secret, rawurlencode($secret), urlencode($secret)], '***', $text);
            }
        }
        if (preg_match(self::trigger(), $text) === 0) {
            return $text;
        }
        $found = [];
        foreach (self::steps() as [$needles, $caseless, $step]) {
            $applies = false;
            foreach ($needles as $needle) {
                $found[$needle] ??= self::contains($text, $needle, $caseless);
                if ($found[$needle]) {
                    $applies = true;
                    break;
                }
            }
            if (!$applies) {
                continue;
            }
            $masked = $step($text);
            if ($masked === null) {
                return self::UNMASKABLE;
            }
            if ($masked !== $text) {
                $text = $masked;
                $found = [];
            }
        }
        return $text;
    }

    /**
     * One regex of every step's needles: a text without any of them cannot be changed by any step and is returned
     * as is. Derived from the steps, so that a new step can never be skipped by a stale list.
     */
    private static function trigger(): string
    {
        static $trigger = null;
        if ($trigger === null) {
            $parts = [];
            foreach (self::steps() as [$needles]) {
                foreach ($needles as $needle) {
                    $parts[] = $needle[0] === '~' ? substr($needle, 1) : preg_quote($needle, '~');
                }
            }
            $trigger = '~' . implode('|', array_unique($parts)) . '~i';
        }
        return $trigger;
    }

    /** @param string $needle a literal, or a regex fragment when it starts with "~" */
    private static function contains(string $text, string $needle, bool $caseless): bool
    {
        if ($needle[0] === '~') {
            return preg_match('~' . substr($needle, 1) . '~i', $text) !== 0;
        }
        return ($caseless ? stripos($text, $needle) : strpos($text, $needle)) !== false;
    }

    /**
     * The masking steps in the order they run. A step carries the needles of which at least one must be in the text
     * for the step to be able to match at all (a literal, or a regex fragment after "~"), so that the common harmless
     * string skips most regexes; the list is built once because the regex strings are the same for every call.
     *
     * @return list<array{list<string>, bool, callable(string): ?string}>
     */
    private static function steps(): array
    {
        static $steps = null;
        return $steps ??= [
            [['-----'], false, static fn (string $t): ?string => preg_replace(self::PEM_PRIVATE_KEY, '$1***', $t)],
            [['@'], false, static fn (string $t): ?string => preg_replace(self::URL_USERINFO, '$1***@', $t)],
            [['@'], false, static fn (string $t): ?string => preg_replace(self::GO_DSN_USERINFO, '***@', $t)],
            [[':'], false, static fn (string $t): ?string => preg_replace(
                '~\b(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)'
                    . '(\s{0,2}:[ \t]{0,16})[^\r\n]+~i',
                '$1$2***',
                $t,
            )],
            [[':'], false, static fn (string $t): ?string => preg_replace(
                '~(?<![A-Za-z0-9-])((?:-u|--user|--proxy-user)[ \t]{1,8}[^\s:"\']{1,256}:)[^\s"\']+~',
                '$1***',
                $t,
            )],
            [['--'], false, self::pairs(
                '(?<![A-Za-z0-9-])((--(' . self::IDENT . '))[ \t]{1,8})',
                '(?!-)' . self::EQ_VALUE,
                '***',
                false,
                3,
            )],
            [['bearer'], true, static fn (string $t): ?string => preg_replace(
                '~(\bBearer[ \t]+)[A-Za-z0-9._\~+/=-]{8,}~i',
                '$1***',
                $t,
            )],
            [['basic'], true, static fn (string $t): ?string => preg_replace(self::BASIC_CREDENTIALS, '$1***', $t)],
            [['~eyJ|gh[pousr]_|github_pat_|xox|glpat-|npm_|[sr]k_|whsec_|AIza|SG\.|bot[0-9]|AKIA|ASIA'], false, static fn (string $t): ?string => preg_replace(self::KNOWN_TOKENS, '***', $t)],
            [['hooks.slack.com'], false, static fn (string $t): ?string => preg_replace(self::SLACK_WEBHOOK, '***', $t)],
            [['~[0-9]{4}'], false, static fn (string $t): ?string => preg_replace_callback(
                self::CARD_NUMBER,
                static fn (array $m): string => self::isCardNumber($m[0]) ? '***' : $m[0],
                $t,
            )],
            [['=>'], false, self::pairs(
                '(\[(' . self::IDENT . ')((?::[^\]\s]{1,128}){0,2})\]\s{0,4}=>\s{0,4})',
                '[^\r\n]*+',
                '***',
            )],
            [[']=>'], false, self::pairs(
                '(\["(' . self::IDENT . ')"(?::(?:"[^"\r\n]{1,128}"|[a-z]{1,16})){0,2}\]=>[ \t]*\r?\n[ \t]*)',
                '[^\r\n]*+',
                '***',
            )],
            [['<'], false, self::pairs(
                '(<(?:[A-Za-z_][A-Za-z0-9_.-]{0,32}:)?(' . self::IDENT . ')(?:\s[^<>]{0,256})?(?<!/)>\s{0,16}(?:<!\[CDATA\[)?)',
                '(?:(?!\]\]>)[^<])*+',
                '***',
            )],
            [['~s:[0-9]'], false, self::pairs(
                '(s:[0-9]{1,6}:"(?:\x00[^\x00"]{0,64}\x00)?(' . self::IDENT . ')";)',
                '(?:s:[0-9]{1,6}:"(?:[^"]|"(?![;}]))*+"?|i:[0-9]{1,18})',
                's:3:"***"',
            )],
            [['\\"'], false, self::pairs(
                '(\\\\"(' . self::IDENT . ')\\\\"\s{0,16}:\s{0,16})',
                self::ESCAPED_JSON_VALUE,
                '\\"***\\"',
                false,
                2,
                self::ESCAPED,
            )],
            [['"'], false, self::pairs(
                '("(' . self::IDENT . ')"\s{0,16}:\s{0,16})',
                self::JSON_VALUE,
                '"***"',
                false,
                2,
                self::PLAIN,
            )],
            [['=', '%3d'], true, self::pairs(
                '(?:(?<![A-Za-z0-9])|(?<=%26))((' . self::SUBSCRIPTED_IDENT . ')(?:\s{0,8}=\s{0,8}|%3[Dd]))',
                '(?!>)' . self::EQ_VALUE,
                '***',
                true,
            )],
            [[':'], false, self::pairs(
                '(?<![A-Za-z0-9\[])((' . self::SUBSCRIPTED_IDENT . ')\s{0,16}:\s{0,16}(?!//))',
                self::COLON_VALUE,
                '***',
            )],
            [['=>'], false, self::pairs(
                '(?<![A-Za-z0-9_.-])(([\'"]?)(' . self::IDENT . ')\2\s{0,4}=>\s{0,4})',
                '\'(?:[^\'\\\\]|\\\\.)*+\'?|"(?:[^"\\\\]|\\\\.)*+"?|[^\s,)]+',
                '***',
                false,
                3,
            )],
            [["'"], false, self::pairs(
                '(\'(' . self::IDENT . ')\'\s{0,16}:\s{0,16})',
                self::PYTHON_VALUE,
                "'***'",
                false,
                2,
                self::PYTHON,
            )],
        ];
    }

    /**
     * A step that masks the value of every "key <separator> value" match whose key is sensitive (see maskPairs()).
     *
     * @return callable(string): ?string
     */
    private static function pairs(
        string $prefix,
        string $value,
        string $replacement,
        bool $bare = false,
        int $keyGroup = 2,
        ?int $json = null,
    ): callable {
        $prefixRegex = '~' . $prefix . '~';
        $valueRegex = '~\G(?:' . $value . ')~';

        return static fn (string $text): ?string => self::maskPairs(
            $text,
            $prefixRegex,
            $valueRegex,
            $replacement,
            $bare,
            $keyGroup,
            $json,
        );
    }

    /**
     * Replaces the value of every "key <separator> value" match whose key is sensitive. $prefixRegex matches the key
     * and the separator ($keyGroup is the key), $valueRegex the value that follows, anchored with \G. Only the
     * prefixes are scanned first, so the value of a harmless pair is never swallowed ("a=1;password=x" still reaches
     * "password=x"). With $json set a [...] or {...} value is masked up to its balanced closing bracket.
     */
    private static function maskPairs(
        string $text,
        string $prefixRegex,
        string $valueRegex,
        string $replacement,
        bool $bare,
        int $keyGroup,
        ?int $json,
    ): ?string {
        if (preg_match_all($prefixRegex, $text, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE) === false) {
            return null;
        }
        $result = '';
        $position = 0;
        $sensitive = [];
        foreach ($matches as $match) {
            $start = $match[0][1];
            $valueStart = $start + strlen($match[0][0]);
            $name = $match[$keyGroup][0];
            $sensitive[$name] ??= SensitiveKey::isSensitive($name, $bare);
            if ($start < $position || !$sensitive[$name]) {
                continue;
            }
            $length = self::valueLength($text, $valueStart, $valueRegex, $json);
            if ($length === false) {
                return null;
            }
            $raw = (string) substr($text, $valueStart, (int) $length);
            $typed = is_numeric($raw) ? $raw + 0 : $raw;
            if ($length === null || SensitiveKey::isMetadata($name, $typed)) {
                continue;
            }
            $result .= substr($text, $position, $valueStart - $position) . $replacement;
            $position = $valueStart + $length;
        }
        return $result . substr($text, $position);
    }

    /**
     * @return int|false|null the byte length of the value at $offset; null when there is none, false when the value
     *                        cannot be delimited safely (the caller then gives up on the whole text)
     */
    private static function valueLength(string $text, int $offset, string $valueRegex, ?int $json): int|false|null
    {
        $char = $text[$offset] ?? '';
        if ($json !== null && ($char === '[' || $char === '{')) {
            return self::balancedLength($text, $offset, $json);
        }
        $found = preg_match($valueRegex, $text, $m, 0, $offset);
        return $found === false ? false : ($found === 1 ? strlen($m[0]) : null);
    }

    /**
     * Length of the JSON array/object starting at $start, up to its balanced closing bracket. A text that ends first
     * (a truncated message) is masked to its end; a container longer than MAX_CONTAINER_BYTES is not delimited.
     * $mode is ESCAPED for a document inside a JSON string (\"...\"), PYTHON when both ' and " quote a string.
     *
     * @return int|false
     */
    private static function balancedLength(string $text, int $start, int $mode): int|false
    {
        $length = strlen($text);
        $end = min($length, $start + self::MAX_CONTAINER_BYTES);
        $quotes = $mode === self::PYTHON ? '\'"' : '"';
        $quote = '';
        $depth = 0;
        for ($i = $start; $i < $end; $i++) {
            $char = $text[$i];
            $next = $text[$i + 1] ?? '';
            if ($char === '\\') {
                $quote = $mode === self::ESCAPED && $next === '"' ? ($quote === '' ? '"' : '') : $quote;
                $i++;
            } elseif ($mode !== self::ESCAPED && str_contains($quotes, $char) && ($quote === '' || $quote === $char)) {
                $quote = $quote === '' ? $char : '';
            } elseif ($quote === '' && ($char === '[' || $char === '{')) {
                $depth++;
            } elseif ($quote === '' && ($char === ']' || $char === '}') && --$depth === 0) {
                return $i + 1 - $start;
            }
        }
        return $end === $length ? $length - $start : false;
    }

    private static function isCardNumber(string $candidate): bool
    {
        $digits = (string) preg_replace('~[^0-9]~', '', $candidate);
        if (preg_match(self::CARD_ISSUER_PREFIX, $digits) !== 1) {
            return false;
        }
        $sum = 0;
        foreach (array_reverse(str_split($digits)) as $position => $digit) {
            $value = (int) $digit * ($position % 2 === 1 ? 2 : 1);
            $sum += $value > 9 ? $value - 9 : $value;
        }
        return $sum % 10 === 0;
    }

    /** The password part of a DSN-like URL, for use as a scrub secret; empty when there is none. */
    public static function dsnPassword(?string $dsn): string
    {
        $password = parse_url((string) $dsn, PHP_URL_PASS);
        return is_string($password) ? urldecode($password) : '';
    }
}
