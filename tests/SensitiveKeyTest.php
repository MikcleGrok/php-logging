<?php

namespace Yasno\Logging\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Yasno\Logging\SensitiveKey;

final class SensitiveKeyTest extends TestCase
{
    #[DataProvider('sensitiveNames')]
    public function testNamesInAnyStyleAreSensitive(string $name): void
    {
        self::assertTrue(SensitiveKey::isSensitive($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sensitiveNames(): iterable
    {
        yield 'snake' => ['access_token'];
        yield 'kebab header' => ['X-Api-Key'];
        yield 'camel' => ['clientSecret'];
        yield 'camel word in the middle' => ['userAuthHeader'];
        yield 'dotted' => ['db.password'];
        yield 'run-on' => ['refreshtoken'];
        yield 'upper' => ['PASSWORD'];
        yield 'oauth code' => ['authorization_code'];
        yield 'credential' => ['credential'];
        yield 'client key' => ['client_key'];
        yield 'app key' => ['app_key'];
        yield 'encryption key' => ['encryption_key'];
        yield 'master key' => ['master_key'];
        yield 'subscripted' => ['user[password]'];
        yield 'php session id' => ['PHPSESSID'];
        yield 'java session id' => ['JSESSIONID'];
        yield 'sessid' => ['sessid'];
        yield 'creds' => ['creds'];
        yield 'csrf' => ['csrf'];
        yield 'pin' => ['pin'];
        yield 'cvv' => ['cvv'];
        yield 'ssn' => ['ssn'];
        yield 'dsn' => ['dsn'];
        yield 'totp' => ['totp'];
        yield 'hmac' => ['hmac'];
        yield 'sig' => ['sig'];
        yield 'license' => ['license'];
        yield 'card number' => ['card_number'];
        yield 'account key' => ['AccountKey'];
        yield 'subscription key header' => ['Ocp-Apim-Subscription-Key'];
        yield 'deploy key' => ['deploy_key'];
        yield 'service key' => ['service_key'];
        yield 'routing key' => ['routing_key'];
        yield 'ssh key' => ['ssh_key'];
        yield 'functions key header' => ['x-functions-key'];
        yield 'shared key' => ['shared_key'];
        yield 'webhook key' => ['webhook_key'];
        yield 'integration key' => ['integration_key'];
        yield 'consumer key' => ['consumer_key'];
        yield 'bot key' => ['bot_key'];
        yield 'access key' => ['access_key'];
        yield 'signing key' => ['signing_key'];
        yield 'passcode' => ['passcode'];
        yield 'secrets' => ['secrets'];
        yield 'cookies' => ['cookies'];
        yield 'xsrf' => ['xsrf'];
        yield 'cvc' => ['cvc'];
        yield 'run-on private key' => ['privatekey'];
        yield 'run-on secret key' => ['secretkey'];
        yield 'run-on access key' => ['accesskey'];
        yield 'run-on signing key' => ['signingkey'];
        yield 'run-on card number' => ['cardnumber'];
        yield 'password' => ['password'];
        yield 'passwd' => ['passwd'];
        yield 'pass' => ['pass'];
        yield 'token' => ['token'];
        yield 'tokens' => ['tokens'];
        yield 'secret' => ['secret'];
        yield 'session' => ['session'];
        yield 'sessionid' => ['sessionid'];
        yield 'sid' => ['sid'];
        yield 'bearer' => ['bearer'];
        yield 'otp' => ['otp'];
        yield 'credentials' => ['credentials'];
        yield 'authorization' => ['authorization'];
        yield 'phpsessid lowercase' => ['phpsessid'];
        yield 'jsessionid lowercase' => ['jsessionid'];
        yield 'private key' => ['private_key'];
        yield 'secret key' => ['secret_key'];
        yield 'api key' => ['api_key'];
        yield 'card num' => ['card_num'];
        yield 'credit card' => ['credit_card'];
        yield 'cvv2' => ['cvv2'];
        yield 'cvc2' => ['cvc2'];
        yield 'iban' => ['IBAN'];
        yield 'card no' => ['card_no'];
        yield 'cc number' => ['cc_number'];
        yield 'cc num' => ['ccNum'];
        yield 'security code' => ['security_code'];
        yield 'verification code' => ['verification_code'];
        yield 'reset code' => ['resetCode'];
        yield 'sms code' => ['sms_code'];
        yield 'mfa code' => ['mfa_code'];
        yield 'connection string' => ['connectionString'];
        yield 'webhook url' => ['webhook_url'];
        yield 'numbered password' => ['password1'];
        yield 'numbered pass' => ['pass2'];
        yield 'numbered camelCase secret' => ['clientSecret3'];
        yield 'numbered key after a prefix' => ['api_key2'];
        yield 'short password' => ['pw'];
        yield 'numbered short password' => ['pw3'];
        yield 'run-on user password' => ['userpass'];
        yield 'run-on db password' => ['dbpass'];
        yield 'run-on short password' => ['dbpw'];
        yield 'run-on pwd' => ['newpwd'];
        yield 'camelCase header with a prefix letter' => ['XApiKey'];
        yield 'all-caps acronym before a word' => ['APIKey'];
        yield 'vendor key' => ['stripeKey'];
    }

    #[DataProvider('plainNames')]
    public function testNamesThatOnlyResembleSecretsAreNot(string $name): void
    {
        self::assertFalse(SensitiveKey::isSensitive($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function plainNames(): iterable
    {
        yield 'monkey' => ['monkey'];
        yield 'bypass' => ['bypass'];
        yield 'compass' => ['compass'];
        yield 'numbered bypass' => ['bypass2'];
        yield 'run-on pass after an unknown prefix' => ['underpass'];
        yield 'starts with pw' => ['pwa'];
        yield 'keyboard' => ['keyboard'];
        yield 'hash name' => ['sha256'];
        yield 'numbered vendor name' => ['stripe2'];
        yield 'secretary' => ['secretary'];
        yield 'tokenizer' => ['tokenizer'];
        yield 'author' => ['author'];
        yield 'bare key' => ['key'];
        yield 'cache key' => ['cache_key'];
        yield 'sort key' => ['sort_key'];
        yield 'primary key' => ['primary_key'];
        yield 'foreign key' => ['foreign_key'];
        yield 'partition key' => ['partition_key'];
        yield 'idempotency key' => ['idempotency_key'];
        yield 'public key' => ['public_key'];
        yield 'code' => ['code'];
        yield 'pinned' => ['pinned'];
        yield 'card alone' => ['card'];
        yield 'signal' => ['signal'];
        yield 'webhook alone' => ['webhook'];
        yield 'connection alone' => ['connection'];
        yield 'security level' => ['security_level'];
        yield 'card type' => ['card_type'];
        yield 'bare cc' => ['cc'];
        yield 'bare reset' => ['reset'];
        yield 'status code' => ['status_code'];
        yield 'url alone' => ['url'];
        yield 'empty' => [''];
    }

    public function testBareKeyAndTAreSensitiveOnlyInFreeText(): void
    {
        self::assertTrue(SensitiveKey::isSensitive('key', true));
        self::assertTrue(SensitiveKey::isSensitive('t', true));
        self::assertFalse(SensitiveKey::isSensitive('t'));
    }

    #[DataProvider('measureNamesAtTheEnd')]
    public function testANumberUnderANameEndingWithAMeasurementWordIsMetadata(string $name): void
    {
        $number = random_int(100_000, 999_999);

        self::assertTrue(SensitiveKey::isMetadata($name, $number));
    }

    #[DataProvider('measureNamesAtTheEnd')]
    public function testANameEndingWithAMeasurementWordIsStillASensitiveName(string $name): void
    {
        self::assertTrue(SensitiveKey::isSensitive($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function measureNamesAtTheEnd(): iterable
    {
        yield 'length' => ['password_length'];
        yield 'count' => ['tokens_count'];
        yield 'max prefix' => ['max_tokens'];
        yield 'ttl' => ['otp_ttl'];
        yield 'ttl in seconds' => ['token_ttl_seconds'];
        yield 'changed at' => ['password_changed_at'];
        yield 'expires' => ['token_expires'];
        yield 'expires in' => ['access_token_expires_in'];
        yield 'tokens used' => ['tokens_used'];
        yield 'tokens remaining' => ['tokens_remaining'];
        yield 'input tokens' => ['input_tokens'];
        yield 'completion tokens' => ['completion_tokens'];
        yield 'attempts' => ['password_attempts'];
        yield 'camelCase' => ['otpTtl'];
        yield 'seconds' => ['token_ttl_secs'];
        yield 'verification code ttl' => ['verification_code_ttl'];
    }

    #[DataProvider('measureNamesInTheMiddle')]
    public function testANumberUnderANameWithAMeasurementWordNotAtTheEndIsNotMetadata(string $name): void
    {
        $number = random_int(100_000, 999_999);

        self::assertFalse(SensitiveKey::isMetadata($name, $number));
    }

    #[DataProvider('measureNamesInTheMiddle')]
    public function testANameWithAMeasurementWordNotAtTheEndIsASensitiveName(string $name): void
    {
        self::assertTrue(SensitiveKey::isSensitive($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function measureNamesInTheMiddle(): iterable
    {
        yield 'time in the middle' => ['one_time_password'];
        yield 'time in camelCase' => ['oneTimePassword'];
        yield 'input after the secret' => ['pin_input'];
        yield 'input after otp' => ['otp_input'];
        yield 'used without tokens' => ['cvv_used'];
        yield 'size before the secret' => ['size_secret'];
        yield 'date before the secret' => ['date_password'];
    }

    public function testShouldMaskNeedsASensitiveNameAndAValueThatCanCarryASecret(): void
    {
        $number = random_int(100_000, 999_999);
        $secret = bin2hex(random_bytes(8));

        self::assertFalse(SensitiveKey::shouldMask('password_length', $number));
        self::assertTrue(SensitiveKey::shouldMask('one_time_password', $number));
        self::assertFalse(SensitiveKey::shouldMask('order_id', $secret));
        self::assertTrue(SensitiveKey::shouldMask('password', $secret));
    }

    /**
     * @param list<string> $words
     */
    #[DataProvider('splitNames')]
    public function testWordsSplitsSnakeKebabDottedAndCamelCaseNames(string $name, array $words): void
    {
        self::assertSame($words, SensitiveKey::words($name));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function splitNames(): iterable
    {
        yield 'snake' => ['access_token', ['access', 'token']];
        yield 'kebab' => ['X-Api-Key', ['x', 'api', 'key']];
        yield 'camel' => ['clientSecret', ['client', 'secret']];
        yield 'camel with a leading capital letter' => ['XApiKey', ['x', 'api', 'key']];
        yield 'acronym before a word' => ['APIKey', ['api', 'key']];
        yield 'all caps' => ['PHPSESSID', ['phpsessid']];
        yield 'dotted' => ['db.password', ['db', 'password']];
        yield 'number kept in the word' => ['password1', ['password1']];
        yield 'empty' => ['', []];
    }

    public function testATextValueUnderAMeasurementNameIsStillASecret(): void
    {
        $secret = bin2hex(random_bytes(8));

        self::assertFalse(SensitiveKey::isMetadata('password_length', $secret));
    }

    public function testADateUnderATimeNameIsMetadataAndADateUnderAnotherNameIsNot(): void
    {
        $date = '2026-10-15T10:00:00+00:00';

        self::assertTrue(SensitiveKey::isMetadata('token_expires_in', $date));
        self::assertFalse(SensitiveKey::isMetadata('one_time_password', $date));
    }
}
