<?php

namespace Yasno\Logging\Tests;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yasno\Logging\Tests\Support\Builder\CardNumberBuilder;
use Yasno\Logging\Tests\Support\Builder\ExceptionBuilder;
use Yasno\Logging\ThrowableContext;

final class ThrowableContextTest extends TestCase
{
    /** A harmless neighbour of a secret in a text ("user":"..."): it must survive masking untouched. */
    private string $user;

    protected function setUp(): void
    {
        $this->user = 'user-' . bin2hex(random_bytes(4));
    }

    /** Fills {user} of a provider template. */
    private function fill(string $text): string
    {
        return str_replace('{user}', $this->user, $text);
    }

    public function testItReportsClassesAndMessagesOfTheThrowableAndItsPrevious(): void
    {
        $previous = new LogicException(bin2hex(random_bytes(4)));
        $throwable = ExceptionBuilder::create()->withPrevious($previous)->build();

        $context = ThrowableContext::of($throwable);

        self::assertSame(RuntimeException::class, $context['exception']);
        self::assertSame($throwable->getMessage(), $context['message']);
        self::assertSame(LogicException::class, $context['previous']);
        self::assertSame($previous->getMessage(), $context['previous_message']);
    }

    public function testWithoutAPreviousTheKeysAreNull(): void
    {
        $context = ThrowableContext::of(ExceptionBuilder::create()->build());

        self::assertNull($context['previous']);
        self::assertNull($context['previous_message']);
    }

    public function testSecretsInTheMessageAndInThePreviousMessageAreMasked(): void
    {
        $outerSecret = bin2hex(random_bytes(8));
        $innerSecret = bin2hex(random_bytes(8));
        $outerNote = 'outer-' . bin2hex(random_bytes(4));
        $innerNote = 'inner-' . bin2hex(random_bytes(4));
        $inner = ExceptionBuilder::create()->withMessage("$innerNote token=$innerSecret for $innerSecret@example.com")->build();
        $outer = ExceptionBuilder::create()->withMessage("$outerNote password=$outerSecret")->withPrevious($inner)->build();

        $context = ThrowableContext::of($outer);

        self::assertSame("$outerNote password=***", $context['message']);
        self::assertSame("$innerNote token=*** for ***@***", $context['previous_message']);
    }

    public function testOnlyTheNearestPreviousIsReported(): void
    {
        $secret = bin2hex(random_bytes(8));
        $grandparent = ExceptionBuilder::create()->withMessage("deep $secret")->build();
        $parent = ExceptionBuilder::create()->withPrevious($grandparent)->build();
        $outer = ExceptionBuilder::create()->withPrevious($parent)->build();

        $context = ThrowableContext::of($outer);

        self::assertSame($parent->getMessage(), $context['previous_message']);
        self::assertStringNotContainsString($secret, (string) json_encode($context));
    }

    #[DataProvider('maskedCases')]
    public function testSecretsAreMaskedAndTheRestOfTheTextIsKept(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $text = ThrowableContext::scrub($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $text);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function maskedCases(): iterable
    {
        yield 'dsn credentials' => [
            'Unable to connect to smtp://user:%s@smtp.example.net:587',
            'Unable to connect to smtp://***@smtp.example.net:587',
        ];
        yield 'dsn user only' => ['smtp://%s@host', 'smtp://***@host'];
        yield 'token query' => ['GET /email/confirm?t=%s failed', 'GET /email/confirm?t=*** failed'];
        yield 'token in the middle' => ['/password/reset?x=1&t=%s&y=2', '/password/reset?x=1&t=***&y=2'];
        yield 'password pair' => ['bad password=%s given', 'bad password=*** given'];
        yield 'pass pair' => ['bad pass=%s given', 'bad pass=*** given'];
        yield 'token pair' => ['bad token=%s given', 'bad token=*** given'];
        yield 'secret pair' => ['bad secret=%s given', 'bad secret=*** given'];
        yield 'key pair' => ['bad key=%s given', 'bad key=*** given'];
        yield 'api_key pair' => ['bad api_key=%s given', 'bad api_key=*** given'];
        yield 'access_token pair' => ['bad access_token=%s given', 'bad access_token=*** given'];
        yield 'client_secret pair' => ['bad client_secret=%s given', 'bad client_secret=*** given'];
        yield 'api-key pair' => ['bad api-key=%s given', 'bad api-key=*** given'];
        yield 'bearer token' => ['Request failed with Bearer %s', 'Request failed with Bearer ***'];
        yield 'lowercase bearer token' => ['sent bearer %s today', 'sent bearer *** today'];
        yield 'authorization with bearer' => ['Authorization: Bearer %s', 'Authorization: ***'];
        yield 'authorization with basic' => ['Authorization: Basic %s', 'Authorization: ***'];
        yield 'authorization inside a header dump' => [
            "Host: a\r\nAuthorization: Bearer %s\r\nAccept: */*",
            'Host: a??Authorization: ***??Accept: */*',
        ];
        yield 'json password' => ['{"password":"%s","user":"{user}"}', '{"password":"***","user":"{user}"}'];
        yield 'json access_token with spaces' => ['{"access_token" : "%s"}', '{"access_token" : "***"}'];
        yield 'json value with an escaped quote' => ['{"client_secret":"a\\"%s"}', '{"client_secret":"***"}'];
        yield 'colon password' => ['login failed, password: %s given', 'login failed, password: *** given'];
        yield 'colon api_key' => ['rejected api_key: %s', 'rejected api_key: ***'];
        yield 'refresh_token pair' => ['bad refresh_token=%s given', 'bad refresh_token=*** given'];
        yield 'passwd pair' => ['bad passwd=%s given', 'bad passwd=*** given'];
        yield 'double-quoted value with a space' => ['bad password="%s x" given', 'bad password=*** given'];
        yield 'single-quoted value with a space' => ["bad password='%s x' given", 'bad password=*** given'];
        yield 'json escaped inside a string' => ['{\\"password\\":\\"%s\\",\\"user\\":\\"{user}\\"}', '{\\"password\\":\\"***\\",\\"user\\":\\"{user}\\"}'];
        yield 'cookie header' => ['Cookie: sid=%s; theme=dark', 'Cookie: ***'];
        yield 'set-cookie header' => ['Set-Cookie: sid=%s; HttpOnly', 'Set-Cookie: ***'];
        yield 'x-api-key header' => ['X-Api-Key: %s', 'X-Api-Key: ***'];
        yield 'uppercase name' => ['bad PASSWORD=%s given', 'bad PASSWORD=*** given'];
        yield 'email address' => ['Email "%s@example.com" does not comply', 'Email "***@***" does not comply'];
        yield 'pair after a harmless pair' => ['a=1;password=%s', 'a=1;password=***'];
        yield 'pair inside a quoted value of a harmless pair' => ['note="see password=%s" ok', 'note="see password=***" ok'];
        yield 'account key of a connection string' => [
            'DefaultEndpointsProtocol=https;AccountName=x;AccountKey=%s',
            'DefaultEndpointsProtocol=https;AccountName=x;AccountKey=***',
        ];
        yield 'subscription key header' => ['Ocp-Apim-Subscription-Key: %s', 'Ocp-Apim-Subscription-Key: ***'];
        yield 'bare jwt' => ['saw eyJ%1$s.eyJ%1$s.%1$s here', 'saw *** here'];
        yield 'jwt without a signature' => ['saw eyJ%1$s.eyJ%1$s. here', 'saw *** here'];
        yield 'github personal token' => ['used ghp_%1$s%1$s now', 'used *** now'];
        yield 'github oauth token' => ['used gho_%1$s%1$s now', 'used *** now'];
        yield 'github fine-grained token' => ['used github_pat_%1$s%1$s now', 'used *** now'];
        yield 'slack token' => ['used xoxb-%s now', 'used *** now'];
        yield 'gitlab token' => ['used glpat-%1$s%1$s now', 'used *** now'];
        yield 'npm token' => ['used npm_%1$s%1$s%1$s now', 'used *** now'];
        yield 'stripe live key' => ['used sk_live_%1$s now', 'used *** now'];
        yield 'stripe test key' => ['used sk_test_%1$s now', 'used *** now'];
        yield 'stripe restricted key' => ['used rk_live_%1$s now', 'used *** now'];
        yield 'stripe webhook secret' => ['used whsec_%1$s now', 'used *** now'];
        yield 'google api key' => ['used AIza%1$s%1$s%1$s now', 'used *** now'];
        yield 'sendgrid key' => ['used SG.%1$s.%1$s now', 'used *** now'];
        yield 'telegram bot token in a url' => [
            'GET https://api.telegram.org/bot123456789:%1$s%1$s/sendMessage failed',
            'GET https://api.telegram.org/***/sendMessage failed',
        ];
        yield 'slack webhook url' => [
            'POST https://hooks.slack.com/services/T0%1$s/B0%1$s/%1$s failed',
            'POST https://hooks.slack.com/services/*** failed',
        ];
        yield 'percent-encoded equals sign' => ['a%%3D1&password%%3D%s&b%%3D2', 'a%3D1&password%3D***&b%3D2'];
        yield 'lowercase percent-encoded equals sign' => ['bad token%%3d%s given', 'bad token%3d*** given'];
        yield 'percent-encoded pair after a percent-encoded ampersand' => [
            'x%%3D1%%26password%%3D%s',
            'x%3D1%26password%3D***',
        ];
        yield 'python repr string' => ["{'password': '%s', 'user': '{user}'}", "{'password': '***', 'user': '{user}'}"];
        yield 'python repr double-quoted string' => ['{\'token\': "it\'s %s"}', "{'token': '***'}"];
        yield 'python repr escaped quote' => ["{'password': 'it\\'s %s', 'user': '{user}'}", "{'password': '***', 'user': '{user}'}"];
        yield 'value that merely starts with a state word' => ['bad token: expired%s given', 'bad token: *** given'];
    }

    #[DataProvider('awsKeyIdPrefixes')]
    public function testAnAwsAccessKeyIdIsMasked(string $prefix): void
    {
        $keyId = $prefix . strtoupper(bin2hex(random_bytes(8)));

        $masked = ThrowableContext::mask("used $keyId now");

        self::assertSame('used *** now', $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function awsKeyIdPrefixes(): iterable
    {
        yield 'long-term key' => ['AKIA'];
        yield 'temporary key' => ['ASIA'];
    }

    public function testBasicCredentialsOutsideAnAuthorizationHeaderAreMasked(): void
    {
        $credentials = base64_encode('user:a1' . bin2hex(random_bytes(8)));

        $masked = ThrowableContext::mask("sent Basic $credentials here");

        self::assertSame('sent Basic *** here', $masked);
    }

    #[DataProvider('jsonContainers')]
    public function testAJsonArrayOrObjectUnderASensitiveKeyIsMaskedWhole(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function jsonContainers(): iterable
    {
        yield 'api key header values' => ['{"X-Api-Key":["%s"]}', '{"X-Api-Key":"***"}'];
        yield 'basic authorization header values' => ['{"Authorization":["Basic %s"]}', '{"Authorization":"***"}'];
        yield 'several values' => ['{"token":["%s","b"],"user":"{user}"}', '{"token":"***","user":"{user}"}'];
        yield 'nested object' => [
            '{"secret":{"value":"%s","list":[1,{"a":2}]},"user":"{user}"}',
            '{"secret":"***","user":"{user}"}',
        ];
        yield 'brackets inside a string' => ['{"token":["%s]}","b"],"user":"{user}"}', '{"token":"***","user":"{user}"}'];
        yield 'escaped quote inside a string' => ['{"token":["a\\"%s]","b"],"user":"{user}"}', '{"token":"***","user":"{user}"}'];
        yield 'escaped document' => [
            '{\\"token\\":[\\"%s]\\",\\"b\\"],\\"user\\":\\"{user}\\"}',
            '{\\"token\\":\\"***\\",\\"user\\":\\"{user}\\"}',
        ];
        yield 'opening bracket inside a string' => ['{"token":["[%s","b"],"user":"{user}"}', '{"token":"***","user":"{user}"}'];
        yield 'raw quote inside an escaped document' => [
            '{\\"token\\":[\\"a"%s\\",\\"b\\"],\\"user\\":\\"{user}\\"}',
            '{\\"token\\":\\"***\\",\\"user\\":\\"{user}\\"}',
        ];
        yield 'truncated message' => ['{"token":["%s","b', '{"token":"***"'];
        yield 'sensitive key inside a harmless object' => [
            '{"user":{"password":["%s"]}}',
            '{"user":{"password":"***"}}',
        ];
    }

    public function testAJsonContainerLongerThanTheScanBoundMakesTheWholeTextUnmaskable(): void
    {
        $secret = str_repeat(bin2hex(random_bytes(8)), 700);

        $masked = ThrowableContext::mask($this->fill('{"token":["' . $secret . '"],"user":"{user}"}'));

        self::assertSame('[unmaskable]', $masked);
    }

    #[DataProvider('credentialUrls')]
    public function testOtherCredentialUrlShapesAreMasked(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function credentialUrls(): iterable
    {
        yield 'hash in the password' => ['postgres://user:p#ss%s@db/x', 'postgres://***@db/x'];
        yield 'question mark in the password' => ['postgres://user:p?ss%s@db/x', 'postgres://***@db/x'];
        yield 'without a scheme' => ['connect //user:%s@db.example/x failed', 'connect //***@db.example/x failed'];
        yield 'go sql driver form' => ['dsn user:%s@tcp(db:3306)/app failed', 'dsn ***@tcp(db:3306)/app failed'];
        yield 'go sql driver form with an at sign' => [
            'dsn user:p@%s@tcp(db:3306)/app failed',
            'dsn ***@tcp(db:3306)/app failed',
        ];
    }

    public function testAUsernameLongerThanTwoHundredAndFiftySixCharactersIsMasked(): void
    {
        $user = str_repeat('u', 1500);
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask("connect https://$user:$secret@db.example/x failed");

        self::assertSame('connect https://***@db.example/x failed', $masked);
    }

    #[DataProvider('intactCases')]
    public function testTextWithoutSecretsIsKeptAsIs(string $text): void
    {
        $text = $this->fill($text);

        self::assertSame($text, ThrowableContext::scrub($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function intactCases(): iterable
    {
        yield 'plain ascii' => ['Connection refused while sending message #42'];
        yield 'cyrillic' => ['Не удалось подключиться к серверу'];
        yield 'name ending with key' => ['monkey=banana'];
        yield 'name ending with pass' => ['bypass=1 compass=north'];
        yield 'numbered names ending with pass' => ['bypass2=1 compass1=north'];
        yield 'name starting with pw' => ['pwa=1 keyboard=qwerty'];
        yield 'word bearer in prose' => ['The bearer of bad news'];
        yield 'authorization without a value' => ['Authorization failed for the current user'];
        yield 'unrelated pairs' => ['user_id=42 status=failed'];
        yield 'harmless subscripts' => ['items[0]=abc given'];
        yield 'harmless flag' => ['run --count 5'];
        yield 'flag followed by another flag' => ['run --token --verbose'];
        yield 'json without sensitive names' => ['{"user":"{user}","status":"failed"}'];
        yield 'quoted value of a non-sensitive name' => ['name="x y" city=\'z\''];
        yield 'cookie in prose' => ['cookie banner was shown'];
        yield 'colon after a non-sensitive word' => ['status: failed, passport: valid'];
        yield 'json containers of harmless names' => ['{"tags":["a","b"],"user":{"name":"{user}"}}'];
        yield 'basic as a plain word' => ['Basic information about the setup'];
        yield 'short github-like prefix' => ['ghp_abc is not a token'];
        yield 'jwt-like prefix without the payload' => ['eyJhbGciOiJIUzI1NiJ9 alone'];
        yield 'harmless pairs separated by semicolons' => ['a=1;b=2;c=3'];
        yield 'public certificate' => ['-----BEGIN CERTIFICATE----- MIIBkTCB -----END CERTIFICATE-----'];
        yield 'public key' => ['-----BEGIN PUBLIC KEY----- MFkwEwYH -----END PUBLIC KEY-----'];
        yield 'python repr of harmless names' => ["{'user': '{user}', 'status': 'failed', 'tags': ['a', 'b']}"];
        yield 'python repr of metadata' => ["{'tokens_count': 5, 'password_length': 12}"];
        yield 'bot word with a short number' => ['bot12345:abc is not a token'];
        yield 'short stripe-like prefix' => ['sk_live_abc is not a key'];
        yield 'slack host without a webhook path' => ['https://hooks.slack.com/services/'];
    }

    #[DataProvider('pemLabels')]
    public function testAPemPrivateKeyIsMaskedWholeWhateverItsLabel(string $label): void
    {
        $body = base64_encode(random_bytes(48));

        $masked = ThrowableContext::mask("key -----BEGIN $label-----\n$body\n$body\n-----END $label----- after");

        self::assertSame("key -----BEGIN $label-----*** after", $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function pemLabels(): iterable
    {
        yield 'pkcs8' => ['PRIVATE KEY'];
        yield 'rsa' => ['RSA PRIVATE KEY'];
        yield 'ec' => ['EC PRIVATE KEY'];
        yield 'openssh' => ['OPENSSH PRIVATE KEY'];
        yield 'encrypted pkcs8' => ['ENCRYPTED PRIVATE KEY'];
        yield 'pgp block' => ['PGP PRIVATE KEY BLOCK'];
    }

    #[DataProvider('pemDocuments')]
    public function testPemPrivateKeysInOtherShapesAreMasked(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function pemDocuments(): iterable
    {
        yield 'legacy encrypted headers' => [
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,%1\$s\n\n%1\$s\n-----END RSA PRIVATE KEY-----",
            '-----BEGIN RSA PRIVATE KEY-----***',
        ];
        yield 'cut before the end line' => ["-----BEGIN PRIVATE KEY-----\n%s", '-----BEGIN PRIVATE KEY-----***'];
        yield 'text after the end line survives' => [
            "a -----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\nb",
            "a -----BEGIN PRIVATE KEY-----***\nb",
        ];
        yield 'two keys' => [
            "-----BEGIN PRIVATE KEY-----\n%1\$s\n-----END PRIVATE KEY-----\nmid\n-----BEGIN PRIVATE KEY-----\n%1\$s\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----***\nmid\n-----BEGIN PRIVATE KEY-----***",
        ];
        yield 'inside a json string' => [
            '{"cert":"-----BEGIN PRIVATE KEY-----\\n%s\\n-----END PRIVATE KEY-----\\n","user":"{user}"}',
            '{"cert":"-----BEGIN PRIVATE KEY-----***\\n","user":"{user}"}',
        ];
    }

    #[DataProvider('pythonContainers')]
    public function testAPythonListOrDictUnderASensitiveKeyIsMaskedWhole(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function pythonContainers(): iterable
    {
        yield 'list' => ["{'api_key': ['%s', 'b'], 'user': '{user}'}", "{'api_key': '***', 'user': '{user}'}"];
        yield 'nested dict' => [
            "{'secret': {'value': '%s', 'list': [1, {'a': 2}]}, 'user': '{user}'}",
            "{'secret': '***', 'user': '{user}'}",
        ];
        yield 'brackets inside both quote styles' => [
            "{'token': ['a]%s', \"it's ]\"], 'user': '{user}'}",
            "{'token': '***', 'user': '{user}'}",
        ];
        yield 'opening bracket inside a string' => [
            "{'token': ['[%s', 'b'], 'user': '{user}'}",
            "{'token': '***', 'user': '{user}'}",
        ];
        yield 'truncated message' => ["{'token': ['%s', 'b", "{'token': '***'"];
    }

    public function testANumberUnderAPythonSensitiveKeyIsMasked(): void
    {
        $number = (string) random_int(10_000_000, 99_999_999);

        $masked = ThrowableContext::mask($this->fill("{'pin': $number, 'user': '{user}'}"));

        self::assertSame($this->fill("{'pin': '***', 'user': '{user}'}"), $masked);
    }

    #[DataProvider('cardShapes')]
    public function testACardNumberIsMaskedWhateverItsIssuerAndLength(string $prefix, int $length): void
    {
        $pan = CardNumberBuilder::create()->withPrefix($prefix)->withLength($length)->build();

        $masked = ThrowableContext::mask("card $pan declined");

        self::assertSame('card *** declined', $masked);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function cardShapes(): iterable
    {
        yield 'visa 16' => ['4', 16];
        yield 'visa 13' => ['4', 13];
        yield 'visa 19' => ['4', 19];
        yield 'mastercard' => ['51', 16];
        yield 'mastercard 2-series' => ['2221', 16];
        yield 'amex' => ['34', 15];
        yield 'discover' => ['6011', 16];
        yield 'diners' => ['36', 14];
        yield 'jcb' => ['3528', 16];
        yield 'mir' => ['2200', 16];
        yield 'unionpay' => ['62', 19];
    }

    #[DataProvider('cardSeparators')]
    public function testAGroupedCardNumberIsMasked(string $separator): void
    {
        $pan = CardNumberBuilder::create()->build();
        $amex = CardNumberBuilder::create()->withPrefix('37')->withLength(15)->build();
        $grouped = implode($separator, str_split($pan, 4));
        $amexGrouped = substr($amex, 0, 4) . $separator . substr($amex, 4, 6) . $separator . substr($amex, 10);

        $masked = ThrowableContext::mask("cards $grouped and $amexGrouped.");

        self::assertSame('cards *** and ***.', $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function cardSeparators(): iterable
    {
        yield 'spaces' => [' '];
        yield 'hyphens' => ['-'];
    }

    #[DataProvider('notCardNumbers')]
    public function testDigitsThatAreNotACardNumberAreKept(string $text): void
    {
        self::assertSame("id $text ok", ThrowableContext::mask("id $text ok"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notCardNumbers(): iterable
    {
        yield 'broken luhn check digit' => [CardNumberBuilder::create()->withBrokenCheckDigit()->build()];
        yield 'unknown issuer prefix' => [CardNumberBuilder::create()->withPrefix('1')->build()];
        yield 'twelve digits' => [CardNumberBuilder::create()->withLength(12)->build()];
        yield 'twenty digits' => [CardNumberBuilder::create()->withLength(20)->build()];
        yield 'glued to a letter before' => ['x' . CardNumberBuilder::create()->build()];
        yield 'glued to a letter after' => [CardNumberBuilder::create()->build() . 'x'];
        yield 'decimal fraction' => ['0.' . CardNumberBuilder::create()->build()];
        yield 'glued to an identifier word' => ['order_' . CardNumberBuilder::create()->build()];
        yield 'mixed separators' => ['4111 1111-1111 1111'];
    }

    #[DataProvider('cardWords')]
    public function testACardNumberGluedToACardWordIsMasked(string $word): void
    {
        $pan = CardNumberBuilder::create()->build();

        $masked = ThrowableContext::mask("id $word$pan ok");

        self::assertSame("id $word*** ok", $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function cardWords(): iterable
    {
        yield 'card' => ['card'];
        yield 'capitalized card' => ['Card'];
        yield 'card and underscore' => ['card_'];
        yield 'card and hyphen' => ['card-'];
        yield 'pan and underscore' => ['pan_'];
        yield 'cc and underscore' => ['cc_'];
    }

    #[DataProvider('authorizationHeaders')]
    public function testAnAuthorizationHeaderWithParametersIsMaskedWhole(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function authorizationHeaders(): iterable
    {
        yield 'aws signature v4' => [
            'Authorization: AWS4-HMAC-SHA256 Credential=%1$s/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=%1$s',
            'Authorization: ***',
        ];
        yield 'hawk' => [
            'Authorization: Hawk id="%1$s", ts="1353832234", nonce="j4h3g2", mac="%1$s"',
            'Authorization: ***',
        ];
        yield 'digest' => [
            'Authorization: Digest username="{user}", realm="r", nonce="%1$s", uri="/x", response="%1$s"',
            'Authorization: ***',
        ];
        yield 'proxy digest' => [
            'Proxy-Authorization: Digest username="{user}", realm="r", nonce="n", response="%s"',
            'Proxy-Authorization: ***',
        ];
        yield 'proxy negotiate' => ['Proxy-Authorization: Negotiate %s', 'Proxy-Authorization: ***'];
        yield 'auth token header with a value of several words' => [
            'X-Auth-Token: %s issued for a session',
            'X-Auth-Token: ***',
        ];
        yield 'header dump' => [
            "Host: a\r\nAuthorization: Hawk id=\"x\", mac=\"%s\"\r\nAccept: */*",
            "Host: a\r\nAuthorization: ***\r\nAccept: */*",
        ];
    }

    #[DataProvider('stateWords')]
    public function testAStateWordAfterTheColonIsNotTakenForASecret(string $word): void
    {
        self::assertSame("login failed, token: $word, retry", ThrowableContext::scrub("login failed, token: $word, retry"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function stateWords(): iterable
    {
        foreach (['expired', 'invalid', 'missing', 'required', 'revoked', 'denied', 'rejected'] as $word) {
            yield $word => [$word];
        }
        foreach (['forbidden', 'unauthorized', 'empty', 'unknown', 'undefined', 'null'] as $word) {
            yield $word => [$word];
        }
        yield 'capitals' => ['EXPIRED'];
        yield 'mixed case' => ['Invalid'];
    }

    public function testExplicitSecretsAreMaskedInPlainRawurlencodedAndUrlencodedForm(): void
    {
        $secret = 'p@ss ' . bin2hex(random_bytes(8));
        $text = sprintf('plain %s raw %s url %s', $secret, rawurlencode($secret), urlencode($secret));

        $scrubbed = ThrowableContext::scrub($text, [$secret]);

        self::assertSame('plain *** raw *** url ***', $scrubbed);
    }

    #[DataProvider('sensitiveNames')]
    public function testPairsAreMaskedWhateverTheNamingStyleOfTheKey(string $name): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask("failed $name=$secret given");

        self::assertSame("failed $name=*** given", $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sensitiveNames(): iterable
    {
        yield 'camelCase token' => ['accessToken'];
        yield 'camelCase secret' => ['clientSecret'];
        yield 'camelCase api key' => ['apiKey'];
        yield 'camelCase auth token' => ['authToken'];
        yield 'camelCase word in the middle' => ['userAuthHeader'];
        yield 'run-on api key' => ['apikey'];
        yield 'pwd' => ['pwd'];
        yield 'passphrase' => ['passphrase'];
        yield 'session id' => ['sessionid'];
        yield 'signature' => ['signature'];
        yield 'jwt' => ['jwt'];
        yield 'auth' => ['auth'];
        yield 'cookie' => ['cookie'];
        yield 'authorization' => ['authorization'];
        yield 'php session cookie' => ['PHPSESSID'];
        yield 'sessid' => ['sessid'];
        yield 'java session cookie' => ['JSESSIONID'];
        yield 'subscripted' => ['user[password]'];
        yield 'account key' => ['AccountKey'];
        yield 'subscription key header' => ['Ocp-Apim-Subscription-Key'];
        yield 'deploy key' => ['deploy_key'];
        yield 'functions key header' => ['x-functions-key'];
        yield 'routing key' => ['routing_key'];
        yield 'ssh key' => ['ssh_key'];
        yield 'shared key' => ['shared_key'];
        yield 'webhook key' => ['webhook_key'];
        yield 'service key' => ['service_key'];
        yield 'numbered password' => ['password1'];
        yield 'short password' => ['pw'];
        yield 'run-on user password' => ['userpass'];
        yield 'camelCase header with a prefix letter' => ['XApiKey'];
        yield 'vendor key' => ['stripeKey'];
    }

    public function testBareCodeIsNotTreatedAsASecret(): void
    {
        self::assertSame('exit code=1 status code: 500', ThrowableContext::mask('exit code=1 status code: 500'));
    }

    #[DataProvider('passwordShapes')]
    public function testUserinfoIsMaskedUpToTheLastAtSignBeforeTheHost(string $passwordTemplate): void
    {
        $secret = bin2hex(random_bytes(8));
        $password = sprintf($passwordTemplate, $secret);

        $masked = ThrowableContext::mask("connect https://user:$password@db.example:8443/path?x=1 failed");

        self::assertSame('connect https://***@db.example:8443/path?x=1 failed', $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function passwordShapes(): iterable
    {
        yield 'plain' => ['%s'];
        yield 'digits only' => ['12345'];
        yield 'with an at sign' => ['p@ss%s'];
        yield 'with a slash' => ['p/ss%s'];
        yield 'with a colon' => ['p:ss%s'];
        yield 'with a hash' => ['p#ss%s'];
        yield 'with a question mark' => ['p?ss%s'];
        yield 'longer than a thousand characters' => [str_repeat('%1$s', 70)];
    }

    #[DataProvider('urlsWithoutUserinfo')]
    public function testUrlsWithoutUserinfoAreKept(string $url): void
    {
        self::assertSame("GET $url failed", ThrowableContext::mask("GET $url failed"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function urlsWithoutUserinfo(): iterable
    {
        yield 'plain' => ['https://api.example.net/v1/items'];
        yield 'at sign in the query' => ['https://api.example.net/v1?email=a@b.example'];
        yield 'at sign in the fragment' => ['https://api.example.net/v1#@top'];
        yield 'profile path' => ['https://medium.com/@user/post'];
        yield 'port and an at sign in the path' => ['https://host.example:8080/a/@b'];
        yield 'port and an at sign in the query' => ['http://localhost:8080?x=a@b'];
        yield 'protocol-relative address' => ['//cdn.example.net/@user/x'];
        yield 'comment slashes before a sentence' => ['// note: mail a@b.example'];
        yield 'double slash inside a path' => ['https://api.example.net/v1//ref:abc@def'];
    }

    public function testAQuotedValueIsMaskedToItsClosingQuoteHoweverLongItIs(): void
    {
        $secret = str_repeat(bin2hex(random_bytes(8)), 200);

        $masked = ThrowableContext::mask("login password=\"$secret\" retry");

        self::assertSame('login password=*** retry', $masked);
    }

    public function testALongNumericJsonValueIsMaskedWhole(): void
    {
        $number = str_repeat('7', 60);

        $masked = ThrowableContext::mask($this->fill('{"token":' . $number . ',"user":"{user}"}'));

        self::assertSame($this->fill('{"token":"***","user":"{user}"}'), $masked);
    }

    public function testALongEscapedJsonValueIsMaskedWhole(): void
    {
        $secret = str_repeat(bin2hex(random_bytes(8)), 400);

        $masked = ThrowableContext::mask($this->fill('{\"password\":\"' . $secret . '\",\"user\":\"{user}\"}'));

        self::assertSame($this->fill('{\"password\":\"***\",\"user\":\"{user}\"}'), $masked);
    }

    #[DataProvider('otherPairFormats')]
    public function testOtherPairFormatsAreMasked(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function otherPairFormats(): iterable
    {
        yield 'spaces around the equals sign' => ['password = %s ok', 'password = *** ok'];
        yield 'pass with a colon' => ['pass: %s ok', 'pass: *** ok'];
        yield 'quoted yaml value' => ['password: "%s x" ok', 'password: *** ok'];
        yield 'print_r' => ["[password] => %s\n[user] => {user}", "[password] => ***\n[user] => {user}"];
        yield 'var_export' => ["'password' => '%s',", "'password' => ***,"];
        yield 'bare name and arrow' => ['password => %s ok', 'password => *** ok'];
        yield 'bare name and arrow without spaces' => ['password=>%s ok', 'password=>*** ok'];
    }

    #[DataProvider('printRProperties')]
    public function testPrintROfAnObjectWithNonPublicPropertiesIsMasked(string $property): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask("[$property] => $secret\n[user] => $this->user");

        self::assertSame("[$property] => ***\n[user] => $this->user", $masked);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function printRProperties(): iterable
    {
        yield 'public' => ['password'];
        yield 'protected' => ['password:protected'];
        yield 'private' => ['password:private'];
        yield 'private of a class' => ['apiToken:App\\User:private'];
    }

    public function testMetadataUnderASensitiveNameIsKept(): void
    {
        $text = 'tokens_count=5 max_tokens=1000 password_length: 12';

        self::assertSame($text, ThrowableContext::mask($text));
    }

    #[DataProvider('subscriptedPairs')]
    public function testPhpArraySubscriptsInTheNameAreRecognised(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function subscriptedPairs(): iterable
    {
        yield 'key inside the subscript' => ['user[password]=%s given', 'user[password]=*** given'];
        yield 'index after the name' => ['password[0]=%s given', 'password[0]=*** given'];
        yield 'two subscripts' => ['a[b][secret]=%s given', 'a[b][secret]=*** given'];
        yield 'colon form' => ['data[token]: %s given', 'data[token]: *** given'];
    }

    public function testAKeyNameLongerThanThirtyTwoCharactersIsStillRecognised(): void
    {
        $secret = bin2hex(random_bytes(8));
        $name = 'password_' . str_repeat('a', 45);

        self::assertSame("failed $name=*** given", ThrowableContext::mask("failed $name=$secret given"));
    }

    public function testAJsonKeyLongerThanThirtyTwoCharactersIsStillRecognised(): void
    {
        $secret = bin2hex(random_bytes(8));
        $name = 'password_' . str_repeat('a', 45);

        self::assertSame("{\"$name\":\"***\"}", ThrowableContext::mask("{\"$name\":\"$secret\"}"));
    }

    #[DataProvider('schemeValues')]
    public function testASchemeBeforeTheValueIsMaskedTogetherWithIt(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function schemeValues(): iterable
    {
        yield 'basic after authorization=' => ['authorization=Basic %s ok', 'authorization=*** ok'];
        yield 'bearer after token=' => ['token=Bearer %s ok', 'token=*** ok'];
        yield 'digest after auth:' => ['auth: Digest %s ok', 'auth: *** ok'];
    }

    #[DataProvider('commandLines')]
    public function testCommandLineSecretsAreMasked(string $template, string $expected): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask($this->fill(sprintf($template, $secret)));

        self::assertSame($this->fill($expected), $masked);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function commandLines(): iterable
    {
        yield 'flag then value' => ['run --password %s --verbose', 'run --password *** --verbose'];
        yield 'token flag' => ['run --token %s', 'run --token ***'];
        yield 'quoted value' => ['run --secret "%s x" --verbose', 'run --secret *** --verbose'];
        yield 'curl user' => ['curl -u admin:%s https://api.example.net', 'curl -u admin:*** https://api.example.net'];
        yield 'long user flag' => ['curl --user admin:%s https://api.example.net', 'curl --user admin:*** https://api.example.net'];
        yield 'proxy user flag' => [
            'curl --proxy-user admin:%s https://api.example.net',
            'curl --proxy-user admin:*** https://api.example.net',
        ];
    }

    // a separate process: pcre.jit only affects patterns compiled after the switch, and an earlier test compiles them
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testScrubNeedsFewRegexStepsOnAnAdversarialEmailLikeInputWithoutJit(): void
    {
        $text = str_repeat('a.', 20_000) . '@' . str_repeat('b-', 10_000);

        [$scrubbed, $error] = self::runWithoutJitUnderTheStepLimit(static fn (): string => ThrowableContext::scrub($text));

        self::assertSame(PREG_NO_ERROR, $error);
        self::assertSame(substr($text, 0, ThrowableContext::MAX_MESSAGE_LENGTH), $scrubbed);
    }

    // a separate process for the same reason: patterns are compiled without JIT only after the switch
    #[DataProvider('adversarialPrefixes')]
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testMaskNeedsFewRegexStepsOnAdversarialInputWithoutJitAndStillHidesTheSecretAtTheEnd(string $prefix): void
    {
        $secret = bin2hex(random_bytes(8));
        $text = "$prefix password=$secret";

        [$masked, $error] = self::runWithoutJitUnderTheStepLimit(static fn (): string => ThrowableContext::mask($text));

        self::assertLessThan(ThrowableContext::MAX_MASK_INPUT_BYTES, strlen($text), 'the secret must not be cut off');
        self::assertSame(PREG_NO_ERROR, $error);
        self::assertNotSame('[unmaskable]', $masked, 'the engine must not give up');
        self::assertStringNotContainsString($secret, $masked);
    }

    // a separate process for the same reason as above
    #[DataProvider('openContainerPrefixes')]
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAnOpenContainerUnderASensitiveKeyMakesTheWholeTextUnmaskableWithoutRunawayBacktracking(string $prefix): void
    {
        $secret = bin2hex(random_bytes(8));
        $text = "$prefix password=$secret";

        [$masked, $error] = self::runWithoutJitUnderTheStepLimit(static fn (): string => ThrowableContext::mask($text));

        self::assertLessThan(ThrowableContext::MAX_MASK_INPUT_BYTES, strlen($text), 'the secret must not be cut off');
        self::assertSame(PREG_NO_ERROR, $error);
        self::assertSame('[unmaskable]', $masked);
    }

    /**
     * Runs $work with JIT off and a PCRE backtrack limit that every adversarial case below stays well under (the
     * heaviest needs about a third of it): runaway backtracking surfaces as a PCRE error, not as a slow test.
     *
     * @return array{string, int} the result of $work and preg_last_error() right after it
     */
    private static function runWithoutJitUnderTheStepLimit(callable $work): array
    {
        $previousJit = ini_set('pcre.jit', '0');
        $previousLimit = ini_set('pcre.backtrack_limit', '250000');

        try {
            $result = $work();
            $error = preg_last_error();
        } finally {
            ini_set('pcre.jit', (string) $previousJit);
            ini_set('pcre.backtrack_limit', (string) $previousLimit);
        }

        return [$result, $error];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function openContainerPrefixes(): iterable
    {
        yield 'open arrays' => ['"token":' . str_repeat('[', 50_000)];
        yield 'repeated sensitive keys with arrays' => [str_repeat('"token":[', 6_000)];
        yield 'open python arrays' => ["'token': " . str_repeat('[', 50_000)];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function adversarialPrefixes(): iterable
    {
        yield 'repeated scheme separators' => [str_repeat('a://', 15_000)];
        yield 'repeated schemes with colons' => [str_repeat('a://:', 12_000)];
        yield 'repeated protocol-relative userinfo' => [str_repeat('//a:', 15_000)];
        yield 'colons' => [str_repeat('a:', 30_000)];
        yield 'colons and semicolons' => [str_repeat('a:;', 20_000)];
        yield 'repeated basic' => [str_repeat('Basic ', 10_000)];
        yield 'long base64 run' => ['Basic ' . str_repeat('aA', 28_000)];
        yield 'jwt prefixes' => [str_repeat('eyJaaaaaaaa.', 5_000)];
        yield 'token prefixes' => [str_repeat('ghp_', 15_000)];
        yield 'harmless pairs' => [str_repeat('a=', 30_000)];
        yield 'repeated sensitive names' => [str_repeat('password=', 6_000)];
        yield 'repeated pem headers' => [str_repeat('-----BEGIN PRIVATE KEY-----', 2_400)];
        yield 'long digit run' => [str_repeat('1', 60_000)];
        yield 'long digit run glued to a letter' => [str_repeat('1', 60_000) . 'x'];
        yield 'grouped digits' => [str_repeat('4111 ', 12_000)];
        yield 'repeated python keys' => [str_repeat("'a': ", 12_000)];
        yield 'repeated percent-encoded pairs' => [str_repeat('a%3D', 15_000)];
        yield 'repeated state words' => [str_repeat('token: expired ', 4_000)];
        yield 'repeated bot prefixes' => [str_repeat('bot123456:', 6_000)];
        yield 'repeated sendgrid prefixes' => [str_repeat('SG.aaaaaaaaaaaaaaaa.', 3_000)];
    }

    public function testMaskHidesCredentialsButKeepsEmailsControlCharactersAndLength(): void
    {
        $secret = bin2hex(random_bytes(8));
        $text = "user@example.com\tpassword=$secret " . str_repeat('x', 500);

        $masked = ThrowableContext::mask($text);

        self::assertSame("user@example.com\tpassword=*** " . str_repeat('x', 500), $masked);
    }

    public function testMaskSurvivesAHugeJsonValue(): void
    {
        $secret = str_repeat(bin2hex(random_bytes(8)), 3000);

        $masked = ThrowableContext::mask($this->fill('{"password":"' . $secret . '","user":"{user}"}'));

        self::assertSame($this->fill('{"password":"***","user":"{user}"}'), $masked);
    }

    public function testNumericJsonValueUnderASensitiveKeyIsMasked(): void
    {
        $number = (string) random_int(10_000_000, 99_999_999);

        $masked = ThrowableContext::mask($this->fill('{"token":' . $number . ',"user":"{user}"}'));

        self::assertSame($this->fill('{"token":"***","user":"{user}"}'), $masked);
    }

    // a separate process for the same reason as above
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAHugeRunOfRepeatedKeywordsNeedsFewRegexStepsAndKeepsItsText(): void
    {
        $text = '"' . str_repeat('password', 100_000);

        [$masked, $error] = self::runWithoutJitUnderTheStepLimit(static fn (): string => ThrowableContext::mask($text));

        self::assertSame(PREG_NO_ERROR, $error);
        self::assertSame(substr($text, 0, ThrowableContext::MAX_MASK_INPUT_BYTES), $masked);
    }

    public function testAKeyLongerThanTheScanBoundIsNotTreatedAsASensitiveKey(): void
    {
        $text = '{"' . str_repeat('a', 100) . 'password":"value"}';

        self::assertSame($text, ThrowableContext::mask($text));
    }

    public function testInputIsCutToTheMaskLimitBeforeMasking(): void
    {
        $masked = ThrowableContext::mask(str_repeat('a', ThrowableContext::MAX_MASK_INPUT_BYTES * 3));

        self::assertSame(ThrowableContext::MAX_MASK_INPUT_BYTES, strlen($masked));
    }

    public function testAnEngineErrorYieldsAMarkerNeitherEmptyNorTheRawSecret(): void
    {
        $secret = bin2hex(random_bytes(8));
        $previousJit = ini_set('pcre.jit', '0');
        $previousLimit = ini_set('pcre.backtrack_limit', '1');

        try {
            $masked = ThrowableContext::mask("login password=$secret Bearer $secret and more text");
        } finally {
            ini_set('pcre.jit', (string) $previousJit);
            ini_set('pcre.backtrack_limit', (string) $previousLimit);
        }

        self::assertSame('[unmaskable]', $masked);
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

        self::assertSame(ThrowableContext::MAX_MESSAGE_LENGTH, mb_strlen($text));
        self::assertStringNotContainsString("\n", $text);
        self::assertStringNotContainsString("\r", $text);
    }

    #[DataProvider('invalidBytes')]
    public function testInvalidUtf8BytesAreSubstitutedAndTheSurroundingTextSurvives(string $bytes, string $substitute): void
    {
        $secret = bin2hex(random_bytes(8));

        $text = ThrowableContext::scrub("before {$bytes} after password=$secret");

        self::assertSame("before {$substitute} after password=***", $text);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidBytes(): iterable
    {
        yield 'byte never valid in utf-8' => ["\xFF", '?'];
        yield 'lone continuation byte' => ["\x80", '?'];
    }

    #[DataProvider('invalidBytes')]
    public function testMaskSubstitutesInvalidUtf8BytesAndStillMasks(string $bytes, string $substitute): void
    {
        $secret = bin2hex(random_bytes(8));

        $masked = ThrowableContext::mask("before {$bytes} after password=$secret");

        self::assertSame("before {$substitute} after password=***", $masked);
        self::assertTrue(mb_check_encoding($masked, 'UTF-8'));
    }

    #[DataProvider('brokenSequences')]
    public function testBrokenMultibyteSequencesNeverEmptyTheMessageAndStayValidUtf8(string $bytes): void
    {
        $text = ThrowableContext::scrub("before {$bytes} after");

        self::assertTrue(mb_check_encoding($text, 'UTF-8'));
        self::assertStringStartsWith('before ', $text);
        self::assertStringEndsWith(' after', $text);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function brokenSequences(): iterable
    {
        yield 'euro sign cut after two bytes' => ["\xE2\x82"];
        yield 'overlong slash' => ["\xC0\xAF"];
        yield 'utf-16 surrogate' => ["\xED\xA0\x80"];
    }

    public function testThrowableWithInvalidUtf8InTheMessageKeepsItsMessage(): void
    {
        $throwable = ExceptionBuilder::create()->withMessage("read failed: \xFF\xFE")->build();

        $context = ThrowableContext::of($throwable);

        self::assertSame('read failed: ??', $context['message']);
    }
}
