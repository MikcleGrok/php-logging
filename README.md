# yasno/logging

Структурированное JSON-логирование для PHP-проектов Yasno. Приложение пишет одну JSON-строку на запись в stderr, дальше её забирает docker `json-file` и Fluent Bit (см. `.task/centralized-logging/plan.md`).

## Состав

| Класс | Назначение |
|---|---|
| `LoggerFactory::create($channel, $id, $level)` | Monolog `Logger`: `StreamHandler('php://stderr')` + `JsonLineFormatter` |
| `Formatter\JsonLineFormatter` | одна строка JSON, без stack trace, `extra.request_id` поднимается в `request_id`, строка ≤ 8 KiB |
| `RequestId` | ID текущего запроса; `normalize()` принимает `^[A-Za-z0-9-]{8,64}$`, остальное отбрасывает |
| `Processor\RequestIdProcessor` | кладёт ID в `extra.request_id` |
| `Http\RequestIdMiddleware` | PSR-15 (Slim и др.) |
| `Bridge\Symfony\RequestIdSubscriber` | `kernel.request` (приоритет 512) / `kernel.response` |
| `ThrowableContext` | контекст исключения без trace, секреты и e-mail замаскированы |

## Каналы и уровень

- Канал по умолчанию — `app`. Доменные каналы — одно слово в нижнем регистре: `mail`, `security`, `import`.
- Канал `access` зарезервирован за nginx; в приложениях не использовать.
- Уровень — переменная окружения `LOG_LEVEL` (`debug`, `info`, `notice`, `warning`, `error`, `critical`, `alert`, `emergency`). По умолчанию `info`; неизвестное значение = `info`. Явный аргумент `$level` приоритетнее env.

## Подключение

В `composer.json` проекта (пакет в публичном GitHub-репозитории, без Packagist):

```json
"repositories": [{ "type": "vcs", "url": "https://github.com/MikcleGrok/yasno-logging" }],
"require": { "yasno/logging": "^0.1" }
```

`composer update yasno/logging --with-dependencies`, `composer.lock` коммитится.

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

Источник ID по приоритету: `$_SERVER['REQUEST_ID']` (nginx `fastcgi_param REQUEST_ID $req_id;`) → заголовок `X-Request-Id` → сгенерированный (32 hex). Невалидное значение (мусор, CRLF, длиннее 64 символов) молча заменяется. ID возвращается в заголовке ответа `X-Request-Id`. После запроса `RequestId` сбрасывается (middleware — в `finally`, Symfony — сервис с тегом `kernel.reset`).

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
