# php-framework/logging

Структурированное JSON-логирование для PHP-проектов Yasno. Приложение пишет одну JSON-строку на запись в stderr, дальше её забирает docker `json-file` и Fluent Bit.

## Состав

| Класс | Назначение |
|---|---|
| `LoggerFactory::create($channel, $id, $level, $stream, $sensitiveKeys)` | Monolog `Logger`: `StreamHandler('php://stderr')` + `JsonLineFormatter` |
| `Formatter\JsonLineFormatter` | одна строка JSON, без stack trace, `extra.request_id` поднимается в `request_id`, строка ≤ 8 KiB, значения чувствительных ключей и секреты в строках маскируются |
| `RequestId` | ID текущего запроса; `normalize()` принимает `^[A-Za-z0-9-]{8,64}$`, остальное отбрасывает |
| `Processor\RequestIdProcessor` | кладёт ID в `extra.request_id` |
| `Http\RequestIdMiddleware` | PSR-15 (Slim и др.) |
| `Bridge\Symfony\RequestIdSubscriber` | `kernel.request` (приоритет 512) / `kernel.response` |
| `ThrowableContext` | контекст исключения без trace, секреты и e-mail замаскированы |

## Маскирование секретов

`JsonLineFormatter` включает его по умолчанию, отключить нельзя:

- значение под ключом `context`/`extra` (на любой глубине) заменяется на `***`, если имя ключа содержит слово из списка (`SensitiveKey::WORDS`): `password`, `passwd`, `pwd`, `pass`, `passphrase`, `secret`, `token`, `jwt`, `auth`, `authorization`, `cookie`, `session`, `sessionid`, `sid`, `signature`, `bearer`, `otp`, `credential(s)`, `apikey`, `sessid`/`phpsessid`/`jsessionid`, `creds`, `csrf`, `xsrf`, `pin`, `cvv`, `cvc`, `ssn`, `dsn`, `totp`, `hmac`, `sig`, `license`, `pw`, `card_number`, `card_no`/`cc_number`, `cvv2`/`cvc2`, `iban`, `security_code`/`verification_code`/`reset_code`/`sms_code`/`mfa_code`, `connection_string`, `webhook_url`, а также `key` после `api`/`private`/`access`/`secret`/`signing`/`encryption`/`master`/`client`/`app`/`account`/`subscription`/`deploy`/`service`/`routing`/`ssh`/`functions`/`shared`/`webhook`/`integration`/`consumer`/`bot` и вендор (`stripe`/`sendgrid`/`twilio`/`openai`/`github`/`gitlab`/`slack`/`mailgun`/`aws`/`google`/`firebase`/`sentry`) (`AccountKey`, `stripeKey`, `Ocp-Apim-Subscription-Key`, `x-functions-key`, `deploy_key`, `routing_key`...). Имя делится на слова по `_`, `-`, `.` и camelCase (`XApiKey` = `x`+`api`+`key`), цифровой хвост слова отбрасывается (`password1`, `pass2`, `api_key2`), слитные формы `...password`/`...passwd`/`...pwd`/`...secret`/`...token`/`...apikey` совпадают (`dbpassword`), а `...pass`/`...pw` — только после `db`/`user`/`admin`/`root`/`mail`/`smtp`/`ftp`/`ssh`/`sql`/`redis`/`login`/`master`/`app`/`api`/`proxy`/`new`/`old` и т. п. (`dbpass`, `userpass`, `dbpw`; `bypass`, `compass`, `underpass` — нет), поэтому `accessToken`, `access_token`, `X-Api-Key` совпадают, а `monkey`, `bypass`, `secretary`, `tokenizer`, `author`, `cache_key` — нет. Имена с PHP-индексами (`user[password]=...`, `password[0]=...`) разбираются по всем частям. Одиночный `key` в ключах массива не считается секретом (слишком частое слово), в тексте `key=...` маскируется. Выбран список префиксов, а не инверсия («`key` секретен, кроме denylist»): инверсия маскировала бы `primary_key`, `sort_key`, `partition_key`, `idempotency_key`, `public_key` в каждой второй записи; цена выбора — незнакомое `<вендор>_key` не ловится, такие имена добавляйте через `sensitiveKeys`;
- в любой строке (`message`, строковые значения, текст исключений, в том числе сырой `'exception' => $e`) маскируются учётные данные в URL/DSN (до последнего `@` перед хостом, пароль может содержать `@`, `/`, `:`, `?`, `#`; имя до 2048 символов; форма без схемы `//user:pw@host` и Go-DSN `user:pw@tcp(host:3306)/db`), голые JWT (`eyJ….eyJ….sig`), токены GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`), Slack (`xox[baprs]-`) и AWS access key id (`AKIA…`/`ASIA…`), GitLab (`glpat-`), npm (`npm_`), Stripe (`sk_live_`/`sk_test_`/`rk_live_`/`whsec_`), ключи Google API (`AIza…`), SendGrid (`SG.….…`), токен Telegram-бота (`bot<id>:<token>`), секретная часть Slack webhook (`hooks.slack.com/services/T…/B…/…`), PEM-блок приватного ключа (`-----BEGIN … PRIVATE KEY-----` до `-----END …` или до конца обрезанного текста, строка заголовка остаётся), номера банковских карт (13–19 цифр слитно или группами `4-4-4-N` / Amex `4-6-5` через пробел либо дефис; нужны префикс эмитента и контрольная сумма Луна; номер, приклеенный к слову `card`/`card_`/`pan_`/`cc_`, тоже), `Basic <base64>` вне заголовка, `Authorization:`, `Cookie:`, `Set-Cookie:`, `X-Api-Key:`, `Bearer ...`, пары `name=value`, `name = value`, `name: value` (значения в кавычках — целиком; схема `Basic`/`Bearer`/`Digest`/... перед значением маскируется вместе с ним), аргументы командной строки `--password S`, `--token S`, `curl -u user:S` / `--user user:S`, JSON `"name":"value"` / `"name":123` (в том числе экранированный `\"name\":\"value\"`), `name%3Dvalue` в URL-кодировке (в том числе сразу после `%26`), Python-repr `{'password': 'x'}` (значения-контейнеры маскируются так же, как JSON); значение-массив или -объект (`"X-Api-Key":["abc"]`, `"secret":{"value":"x"}`) маскируется до парной скобки целиком, лишь бы оно было не длиннее 4096 байт, иначе вся строка заменяется на `[unmaskable]`; оборванный на середине JSON маскируется до конца строки; также вывод `print_r` (`[password] => x`, в том числе `[password:protected] => x`, `[token:App\User:private] => x`) и `var_export` (`'password' => 'x'`), голое `password => x` — `ThrowableContext::mask()`;
- имена ключей `context`/`extra` тоже проходят через `mask()` (секрет в имени ключа); два ключа, совпавшие после маскирования (`https://u:a@h`, `https://u:b@h`), не сливаются: второй получает суффикс `#2`, третий — `#3`;
- свои ключи добавляются списком: `new JsonLineFormatter(['passport'])` или `LoggerFactory::create(sensitiveKeys: ['passport'])`; в Symfony — аргумент сервиса `JsonLineFormatter`. Они сопоставляются так же, как встроенные: по целым словам ключа, без учёта регистра, `-`/`_`/`.`, camelCase и цифрового хвоста — `passport` ловит `passport`, `passport_number`, `userPassport`, `Passport-No`, `passport2`, но не `passports` и не `mypassport`; многословный ключ задаётся как есть (`iban_code` ловит `IBAN-Code`);
- объекты в `context`/`extra` обходятся так, как их увидит `json_encode`: `JsonSerializable` — по результату `jsonSerialize()`, даты — строкой в формате форматтера, `ArrayObject`/`ArrayIterator` — по элементам, остальные — по публичным свойствам (непубличные в JSON не попадают); циклы заменяются на `[circular]`, глубже 10 уровней — `[max depth]`;
- метаданные не маскируются: булевы значения под любым ключом (`is_password_set`, `cookie_consent`); числа под ключами, которые ЗАКАНЧИВАЮТСЯ словом-мерой (`*_count`, `*_limit`, `*_total`, `*_ttl`, `*_length`, `*_size`, `*_timeout`, `*_attempts`, `*_ms`, `*_seconds`, ...) или начинаются с `max_`/`min_`/`num_`/`total_` (`password_length`, `tokens_count`, `max_tokens`, `otp_ttl`); даты/числа под ключами, заканчивающимися словом-временем (`password_changed_at`, `token_expires`, `token_expires_in`); счётчики использования токенов (`tokens_used`, `tokens_remaining`, `prompt_tokens`, `input_tokens`) — только в именах со словом `token`. Слово-мера в середине имени метаданными не делает ключ: `one_time_password`, `pin_input`, `otp_input`, `cvv_used` с числом маскируются. Строка под таким ключом, не похожая на дату, маскируется.

Принятые ограничения (эвристики):
- ложные срабатывания: слова `auth`, `session`, `pass`, `sid` в имени ключа (`auth_method`, `pass_through`), правила `token: ...`, `password: ...`, `key=...` по свободному тексту (`pass: 3 of 5` станет `pass: *** of 5`, `sid=42` — `sid=***`). Слово-состояние сразу после двоеточия не маскируется (`token: expired`, `password: invalid`, `secret: missing`; список: `expired`, `invalid`, `missing`, `required`, `revoked`, `denied`, `rejected`, `forbidden`, `unauthorized`, `empty`, `unknown`, `undefined`, `null`, без учёта регистра и только целым словом: `token: expired123` маскируется) — это исключение действует лишь для формы `name: value`, `name=expired` маскируется; `routing_key` (RabbitMQ) считается секретом из-за префикса `routing` — если он нужен в логе, это известное ложное срабатывание; голое `code=...` не маскируется (код возврата), OAuth-код ловится как `authorization_code`/`auth_code`;
- пропуски: секрет без признаков (голая строка в сообщении) не находится — для него `ThrowableContext::scrub($text, [$secret])`; строка под ключом, похожим на флаг (`cookie_consent => 'granted'`), маскируется — метаданными считаются только bool, числа под ключом-мерой и даты; значения вложенного массива после `[password] => Array` в `print_r` не маскируются; пароль в URL длиннее 4096 символов; текст длиннее 64 KiB перед маскированием обрезается; если движок PCRE вернул ошибку, строка заменяется на `[unmaskable]`;
- номер карты узнаётся по длине, префиксу эмитента и сумме Луна: случайное 13–19-значное число (идентификатор заказа, телефон), которое начинается с `2`–`6` и проходит Луна (около 10% таких чисел), будет замаскировано; число с пробелами и дефисами вперемешку (`4111 1111-1111 1111`), число из `int` в `context` под несекретным ключом (`pan`) и карта, вплотную приклеенная к другим буквам, `_` или `.` (`id_4111…`, `x4111…`, `0.4111…`), не ловятся: слово `card`/`card_`/`pan_`/`cc_` перед числом — единственное исключение, остальное — хэши, идентификаторы и десятичные дроби, и расширение правила маскировало бы часть случайных hex-хэшей;
- слова `pin`, `sig`, `license`, `dsn` добавлены ради редких секретов и могут срабатывать на безобидные поля (`license: MIT` будет `***`); `card` без `number` секретом не считается;
- URL: пользовательская часть — это `user:пароль@` (пароль может содержать `@`, `/`, `:`, `?`, `#`) или `user@` без `/`. Путь вида `https://medium.com/@user/post` и `https://host:8080/a/@b` сохраняют хост (после двоеточия идёт порт и `/`); цена — пароль из 1–5 цифр, за которым сразу идёт `/`, `?` или `#` (`user:123/x@host`), не маскируется, а `https://user:S@host/p/@x` маскируется до последнего `@` (хост теряется, секрет — нет);
- значение пары `name=value` продолжается до пробела или `&` (значение в кавычках — до закрывающей кавычки), а в `name: value` — ещё и до `,` и `;`: в строке подключения `AccountKey=x;EndpointSuffix=y` хвост после ключа тоже станет `***` (безопасная сторона); значение пары не «проглатывает» следующие пары: `a=1;password=x` маскирует `x`;
- Go-DSN и форма без схемы ловятся эвристиками с ограниченными квантификаторами (защита от ReDoS): пароль Go-DSN длиннее 128 символов (с `@` — до 4×128), имя пользователя или пароль в URL длиннее 2048/4096 символов, а также `user:pw@host` без схемы и без `tcp(`/`unix(` — не маскируются; `//host:8080/a@b` и `http://host:8080?x=a@b` остаются как есть;
- голый `Basic <base64>` ловится эвристикой (от 8 символов base64 с цифрой, `+`, `/` или сменой регистра); короткие или «словесные» значения не ловятся, а имя с такой формой (`Basic ProductName`) даст ложное срабатывание; из токенов распознаются только перечисленные формы;
- JSON-массив/объект длиннее 4096 байт под чувствительным ключом делает всю строку `[unmaskable]`; JSON, экранированный дважды (`\\\"password\\\":\\\"x\\\"`), не маскируется — распознаётся только один уровень экранирования (`\"password\":\"x\"`);
- URL-кодировка распознаётся только в `name%3Dvalue`; `name%3Avalue`, URL-кодированный JSON (`%22password%22%3A%22x%22`) и OAuth-код в адресе (`callback?code=…`) не маскируются; из токенов поставщиков распознаются только перечисленные формы, Python-repr — только с ключом в одинарных кавычках;
- пары «имя/значение» (`{"name":"password","value":"x"}`) не распознаются: чувствительность определяется только по ключу, а не по соседнему полю; ключи не из латиницы (`пароль`, `密码`) не распознаются ни в тексте (`пароль=x`, `{"пароль":"x"}` остаются как есть), ни в `ThrowableContext`; для ключей `context`/`extra` их можно добавить через `sensitiveKeys`, в тексте сообщения — только через `$secrets`;
- `scrub()` и `ThrowableContext::of()` оставляют первые 300 символов сообщения (после маскирования): любой длинный префикс (стек, дамп, повторяющийся фрагмент) вытесняет полезный хвост — это усечение, не утечка;
- командная строка: форма `-p S` (краткий флаг пароля) не распознаётся, так как `-p` слишком неоднозначен;

Маскирование — страховка, а не замена дисциплины: не кладите в контекст тело запроса целиком.

## Каналы и уровень

- Канал по умолчанию — `app`. Доменные каналы — одно слово в нижнем регистре: `mail`, `security`, `import`.
- Канал `access` зарезервирован за nginx; в приложениях не использовать.
- Уровень — переменная окружения `LOG_LEVEL` (`debug`, `info`, `notice`, `warning`, `error`, `critical`, `alert`, `emergency`). По умолчанию `info`; неизвестное значение = `info`. Явный аргумент `$level` приоритетнее env.

## Подключение

В `composer.json` проекта (пакет в публичном GitHub-репозитории, без Packagist):

```json
"repositories": [{ "type": "vcs", "url": "https://github.com/MikcleGrok/php-logging.git" }]
```

```
composer require php-framework/logging:^0.1
```

`composer update php-framework/logging --with-dependencies`, `composer.lock` коммитится.

### Slim 4

```php
use Yasno\Logging\Http\RequestIdMiddleware;
use Yasno\Logging\LoggerFactory;
use Yasno\Logging\RequestId;

$requestId = new RequestId();
$logger = LoggerFactory::create('app', $requestId);

// Slim: LIFO, последний add() = внешний слой. RequestIdMiddleware добавлять последним.
$app->add(new RequestIdMiddleware($requestId));
$app->addErrorMiddleware(false, true, false, $logger);
```

Исключение логируется так: `$logger->error('unhandled', ThrowableContext::of($e))`. Кастомные `ErrorHandler` (наследники `Slim\Handlers\ErrorHandler`) получают `$logger` в конструктор и переопределяют `logError()`, иначе Slim пишет plain-текст через `error_log` и в логе будут дубли.

### Symfony (без бандла)

1. Скопировать `config/symfony/yasno_logging.yaml` в `config/` проекта и подключить из `config/services.yaml`: `imports: [{ resource: yasno_logging.yaml }]`.
2. В `config/packages/monolog.yaml` для prod-хендлеров (`type: stream`, `path: php://stderr`) указать `formatter: Yasno\Logging\Formatter\JsonLineFormatter`.
3. Нужен `symfony/http-kernel` (в Symfony-проекте уже есть).

## Request ID

Источник ID по приоритету: `$_SERVER['REQUEST_ID']` (nginx `fastcgi_param REQUEST_ID $req_id;`) → заголовок `X-Request-Id` → сгенерированный (32 hex). Невалидное значение (мусор, CRLF, длиннее 64 символов) молча заменяется. Заголовок `X-Request-Id` подконтролен клиенту (формат проверяется, но значение можно подставить); без доверенного прокси, выставляющего `REQUEST_ID`, передайте `trustClientHeader: false` — `new RequestIdMiddleware($requestId, false)` / вторым аргументом `RequestIdSubscriber` — и заголовок будет игнорироваться (по умолчанию `true`, поведение прежнее). ID возвращается в заголовке ответа `X-Request-Id`. После запроса `RequestId` сбрасывается (middleware — в `finally`, Symfony — сервис с тегом `kernel.reset` и подписчик на `kernel.terminate` с приоритетом -1024).

## Контракт полей

| Поле VictoriaLogs | Источник | Тип |
|---|---|---|
| `_time` | docker `time` (через Fluent Bit `date`) | stream-независимое |
| `_stream` = `{project, service, stream}` | `attrs.com.docker.compose.project`, `attrs.com.docker.compose.service`, docker `stream` | stream fields, низкая кардинальность |
| `_msg` | `message` (Monolog, nginx), иначе `log` (plain-строка) | `_msg_field=message,log` |
| `level_name`, `level`, `channel` | `JsonLineFormatter` | строка / int / строка |
| `context.*`, `extra.*` | Monolog; VictoriaLogs сам расплющивает вложенные объекты | поля |
| `request_id` | nginx `$req_id`; Monolog — поднимается из `extra` на верхний уровень форматтером пакета | строка, общая для access и app |
| `method`, `uri`, `status`, `bytes`, `request_time`, `referer`, `user_agent`, `remote_addr` | nginx `log_format app_json` | поля |
| `container_id`, `file` | путь файла (`path_key`) | поле, не stream |

Ограничения: одна строка ≤ 8 KiB (при превышении `context` заменяется на `{"truncated": true}`, `message` обрезается); stack trace не пишется; query string в логи не попадает.

## Разработка

```
composer install
vendor/bin/phpunit
composer validate --strict
```

Нет локального PHP — `docker run --rm -v "$PWD":/app -w /app composer:2 sh -c 'composer install && vendor/bin/phpunit'`.

## Версии

Теги semver (`v0.1.0`, ...). Проекты пинят версию через `composer.lock`.
