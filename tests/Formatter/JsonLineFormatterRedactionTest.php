<?php

namespace Yasno\Logging\Tests\Formatter;

use ArrayIterator;
use ArrayObject;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;
use Yasno\Logging\Formatter\JsonLineFormatter;
use Yasno\Logging\LoggerFactory;
use Yasno\Logging\RequestId;
use Yasno\Logging\Tests\Support\Assert\JsonLineAssert;
use Yasno\Logging\Tests\Support\Builder\CardNumberBuilder;
use Yasno\Logging\Tests\Support\Builder\ExceptionBuilder;
use Yasno\Logging\Tests\Support\Builder\JsonSerializableBuilder;
use Yasno\Logging\Tests\Support\Enum\DeliveryChannel;
use Yasno\Logging\Tests\Support\Builder\LogRecordBuilder;

final class JsonLineFormatterRedactionTest extends TestCase
{
    private JsonLineFormatter $formatter;

    protected function setUp(): void
    {
        $this->formatter = new JsonLineFormatter();
    }

    #[DataProvider('sensitiveKeys')]
    public function testValuesUnderSensitiveContextKeysAreRedacted(string $key): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext([$key => $secret])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame([$key => '***'], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    /**
     * What SensitiveKeyTest checks name by name is represented here by one name per way a key is written.
     *
     * @return iterable<string, array{string}>
     */
    public static function sensitiveKeys(): iterable
    {
        yield 'capitalized' => ['Password'];
        yield 'dashed header name' => ['X-Api-Key'];
        yield 'numbered' => ['password1'];
        yield 'camelCase with a prefix letter' => ['XApiKey'];
    }

    public function testSensitiveKeysAreRedactedAtAnyDepthAndInExtra(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()
            ->withContext(['user' => ['credentials' => ['password' => $secret]], 'items' => [['token' => $secret]]])
            ->withExtra(['secret' => $secret])
            ->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['user' => ['credentials' => '***'], 'items' => [['token' => '***']]], $data['context']);
        self::assertSame(['secret' => '***'], $data['extra']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testNonStringSensitiveValuesAreRedactedAndNullStaysNull(): void
    {
        $record = LogRecordBuilder::create()->withContext(['token' => ['a' => 1], 'password' => 42, 'secret' => null])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['token' => '***', 'password' => '***', 'secret' => null], $data['context']);
    }

    public function testOrdinaryContextIsLeftUntouched(): void
    {
        $record = LogRecordBuilder::create()->withContext(['order' => ['id' => 42, 'note' => 'ship tomorrow'], 'count' => 3])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame($record->context, $data['context']);
    }

    public function testRequestIdLiftedFromExtraIsNotRedacted(): void
    {
        $requestId = RequestId::generate();
        $record = LogRecordBuilder::create()->withExtra(['request_id' => $requestId])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame($requestId, $data['request_id']);
    }

    public function testCredentialsInsideContextStringsAndTheMessageAreMasked(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()
            ->withMessage("call failed: Authorization: Bearer $secret")
            ->withContext(['url' => "https://user:$secret@api.example.net/v1?token=$secret"])
            ->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame('call failed: Authorization: ***', $data['message']);
        self::assertSame(['url' => 'https://***@api.example.net/v1?token=***'], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testCardNumbersAndPrivateKeysInStringsAreMasked(): void
    {
        $pan = CardNumberBuilder::create()->build();
        $body = base64_encode(random_bytes(48));
        $record = LogRecordBuilder::create()
            ->withMessage("payment declined for card $pan")
            ->withContext(['note' => "key -----BEGIN PRIVATE KEY-----\n$body\n-----END PRIVATE KEY-----"])
            ->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame('payment declined for card ***', $data['message']);
        self::assertSame(['note' => 'key -----BEGIN PRIVATE KEY-----***'], $data['context']);
        self::assertStringNotContainsString($pan, $output);
        self::assertStringNotContainsString($body, $output);
    }

    public function testRawExceptionInContextHasItsMessageMasked(): void
    {
        $secret = bin2hex(random_bytes(8));
        $exception = ExceptionBuilder::create()->withMessage("connect failed password=$secret")->build();
        $record = LogRecordBuilder::create()->withContext(['exception' => $exception])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame('connect failed password=***', $data['context']['exception']['message']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testAdditionalSensitiveKeysCanBeGiven(): void
    {
        $value = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(['passport_number' => $value])->build();

        $defaultOutput = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter())->format($record));
        $extendedOutput = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter(['Passport']))->format($record));

        self::assertSame(['passport_number' => $value], $defaultOutput['context']);
        self::assertSame(['passport_number' => '***'], $extendedOutput['context']);
    }

    public function testLoggerFromTheFactoryRedactsByDefaultAndAcceptsExtraKeys(): void
    {
        $secret = bin2hex(random_bytes(8));
        $user = 'user-' . bin2hex(random_bytes(4));
        $stream = fopen('php://memory', 'w+');
        self::assertIsResource($stream);
        $logger = LoggerFactory::create('app', null, null, $stream, ['passport']);

        $logger->info('login', ['password' => $secret, 'passport' => $secret, 'user' => $user]);

        rewind($stream);
        $output = (string) stream_get_contents($stream);
        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['password' => '***', 'passport' => '***', 'user' => $user], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testPublicPropertiesOfAnObjectInContextAreRedacted(): void
    {
        $secret = bin2hex(random_bytes(8));
        $name = 'name-' . bin2hex(random_bytes(4));
        $record = LogRecordBuilder::create()->withContext(['user' => (object) ['name' => $name, 'password' => $secret]])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['user' => ['name' => $name, 'password' => '***']], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testJsonSerializableOutputIsRedacted(): void
    {
        $secret = bin2hex(random_bytes(8));
        $payload = JsonSerializableBuilder::create()->withData(['api_key' => $secret, 'note' => "Bearer $secret"])->build();
        $record = LogRecordBuilder::create()->withContext(['request' => $payload])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['request' => ['api_key' => '***', 'note' => 'Bearer ***']], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testAnObjectNestedInAnArrayIsRedacted(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(['batch' => [['user' => (object) ['token' => $secret]]]])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['batch' => [['user' => ['token' => '***']]]], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testAnEmptyObjectStaysAnObject(): void
    {
        $record = LogRecordBuilder::create()->withContext(['payload' => new stdClass()])->build();

        $output = $this->formatter->format($record);

        self::assertStringContainsString('"payload":{}', $output);
    }

    public function testACyclicObjectGraphTerminatesAndDoesNotLeak(): void
    {
        $secret = bin2hex(random_bytes(8));
        $node = new stdClass();
        $node->password = $secret;
        $node->note = "password=$secret";
        $node->self = $node;
        $record = LogRecordBuilder::create()->withContext(['node' => $node])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['password' => '***', 'note' => 'password=***', 'self' => '[circular]'], $data['context']['node']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testAnObjectChainDeeperThanTheLimitIsCutOff(): void
    {
        $secret = bin2hex(random_bytes(8));
        $chain = (object) ['password' => $secret];
        for ($level = 0; $level < 15; $level++) {
            $chain = (object) ['next' => $chain];
        }
        $record = LogRecordBuilder::create()->withContext(['chain' => $chain])->build();

        $output = $this->formatter->format($record);

        JsonLineAssert::seeSingleJsonLine($output);
        self::assertStringContainsString('[max depth]', $output);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testNumericMetricsUnderTokenLikeKeysAreKept(): void
    {
        $record = LogRecordBuilder::create()
            ->withContext(['tokens_count' => 5, 'max_tokens' => 1000, 'token_limit' => 3, 'token_total' => 7, 'password_ttl' => 60.5])
            ->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame($record->context, $data['context']);
    }

    public function testStringValuesUnderMetricLikeKeysAreStillRedacted(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(['tokens_count' => $secret, 'max_tokens' => $secret])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['tokens_count' => '***', 'max_tokens' => '***'], $data['context']);
    }

    #[DataProvider('harmlessKeys')]
    public function testKeysThatMerelyResembleSensitiveOnesAreKept(string $key): void
    {
        $value = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext([$key => $value])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame([$key => $value], $data['context']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function harmlessKeys(): iterable
    {
        yield 'bare key' => ['cache_key'];
        yield 'ends with a secret word' => ['bypass'];
        yield 'starts with a secret word' => ['tokenizer'];
    }

    #[DataProvider('metadataEntries')]
    public function testFlagsCountersAndTimestampsUnderSensitiveKeysAreKept(string $key, mixed $value): void
    {
        $record = LogRecordBuilder::create()->withContext([$key => $value])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame([$key => $value], $data['context']);
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function metadataEntries(): iterable
    {
        yield 'flag' => ['is_password_set', true];
        yield 'length' => ['password_length', 12];
        yield 'iso timestamp' => ['password_changed_at', '2026-10-15T10:00:00+00:00'];
    }

    public function testATextValueUnderAMetadataLikeKeyIsStillRedacted(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(['password_changed_at' => $secret])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['password_changed_at' => '***'], $data['context']);
    }

    public function testASecretInsideAKeyNameIsMasked(): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(["https://user:$secret@db.example" => 1, 'order' => 2])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['https://***@db.example' => 1, 'order' => 2], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    #[DataProvider('measureKeys')]
    public function testATextValueUnderAMeasurementLikeKeyIsStillRedacted(string $key): void
    {
        $secret = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext([$key => $secret])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame([$key => '***'], $data['context']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function measureKeys(): iterable
    {
        yield 'usage' => ['prompt_tokens'];
        yield 'timeout' => ['session_timeout'];
    }

    public function testAnIntegerSecretWithoutAMeasurementWordIsRedacted(): void
    {
        $record = LogRecordBuilder::create()->withContext(['pin' => 482913, 'cvv' => 123])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['pin' => '***', 'cvv' => '***'], $data['context']);
    }

    #[DataProvider('integerSecretKeys')]
    public function testAnIntegerUnderAKeyWithAMeasurementWordInTheMiddleIsRedacted(string $key): void
    {
        $record = LogRecordBuilder::create()->withContext([$key => random_int(100_000, 999_999)])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame([$key => '***'], $data['context']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function integerSecretKeys(): iterable
    {
        yield 'measurement word before the secret' => ['one_time_password'];
        yield 'measurement word after the secret' => ['pin_input'];
    }

    public function testAdditionalKeyFragmentsMatchDashedAndUnderscoredKeysAlike(): void
    {
        $value = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(['IBAN-Code' => $value])->build();

        $data = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter(['iban_code']))->format($record));

        self::assertSame(['IBAN-Code' => '***'], $data['context']);
    }

    #[DataProvider('additionalKeyMatches')]
    public function testAnAdditionalKeyMatchesWholeWordsOfAKey(string $key): void
    {
        $value = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext([$key => $value])->build();

        $data = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter(['passport']))->format($record));

        self::assertSame([$key => '***'], $data['context']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function additionalKeyMatches(): iterable
    {
        yield 'the word itself' => ['passport'];
        yield 'followed by a word' => ['passport_number'];
        yield 'camelCase' => ['userPassport'];
        yield 'dashed and capitalized' => ['Passport-No'];
        yield 'numbered' => ['passport2'];
    }

    #[DataProvider('additionalKeyMisses')]
    public function testAnAdditionalKeyIsNotFoundInsideAnotherWord(string $key): void
    {
        $value = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext([$key => $value])->build();

        $data = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter(['passport']))->format($record));

        self::assertSame([$key => $value], $data['context']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function additionalKeyMisses(): iterable
    {
        yield 'plural' => ['passports'];
        yield 'glued prefix' => ['mypassport'];
        yield 'glued suffix' => ['passporter'];
    }

    public function testAnEmptyAdditionalKeyDoesNotRedactEverything(): void
    {
        $record = LogRecordBuilder::create()->build();

        $data = JsonLineAssert::seeSingleJsonLine((new JsonLineFormatter(['']))->format($record));

        self::assertSame($record->context, $data['context']);
    }

    public function testKeysThatDifferOnlyInAMaskedSecretStayApart(): void
    {
        $first = bin2hex(random_bytes(8));
        $second = bin2hex(random_bytes(8));
        $record = LogRecordBuilder::create()->withContext(["https://user:$first@db.example" => 1, "https://user:$second@db.example" => 2])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['https://***@db.example' => 1, 'https://***@db.example#2' => 2], $data['context']);
        self::assertStringNotContainsString($first, $output);
        self::assertStringNotContainsString($second, $output);
    }

    #[DataProvider('arrayLikeObjects')]
    public function testTheElementsOfAnArrayLikeObjectAreWalkedAndRedacted(string $class): void
    {
        $secret = bin2hex(random_bytes(8));
        $name = 'name-' . bin2hex(random_bytes(4));
        $record = LogRecordBuilder::create()->withContext(['bag' => new $class(['name' => $name, 'password' => $secret])])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertSame(['bag' => ['name' => $name, 'password' => '***']], $data['context']);
        self::assertStringNotContainsString($secret, $output);
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function arrayLikeObjects(): iterable
    {
        yield 'array object' => [ArrayObject::class];
        yield 'array iterator' => [ArrayIterator::class];
    }

    public function testADateInsideJsonSerializableOutputIsFormattedLikeAnyOtherDate(): void
    {
        $date = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $payload = JsonSerializableBuilder::create()->withData(['at' => $date])->build();
        $record = LogRecordBuilder::create()->withContext(['request' => $payload])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['request' => ['at' => $date->format(DATE_ATOM)]], $data['context']);
    }

    public function testASecretInAMessageThatGetsTruncatedStaysMasked(): void
    {
        $secret = bin2hex(random_bytes(8));
        $filler = str_repeat('x', JsonLineFormatter::MAX_LINE);
        $record = LogRecordBuilder::create()->withMessage("password=$secret $filler")->withContext(['payload' => $filler])->build();

        $output = $this->formatter->format($record);

        $data = JsonLineAssert::seeSingleJsonLine($output);
        self::assertLessThanOrEqual(JsonLineFormatter::MAX_LINE, strlen($output));
        self::assertSame(['truncated' => true], $data['context']);
        self::assertStringStartsWith('password=*** ', $data['message']);
        self::assertStringNotContainsString($secret, $output);
    }

    public function testAnEnumInContextKeepsItsJsonValue(): void
    {
        $record = LogRecordBuilder::create()->withContext(['channel' => DeliveryChannel::Sms])->build();

        $data = JsonLineAssert::seeSingleJsonLine($this->formatter->format($record));

        self::assertSame(['channel' => DeliveryChannel::Sms->value], $data['context']);
    }
}
