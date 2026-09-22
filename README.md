# DetoxProxy — модуль безопасности персональных данных

Сервис находит в русском тексте 17 типов персональных данных, заменяет их обратимыми токенами (`<<FIO_1>>`, `<<INN_1>>` …) перед отправкой во внешнюю LLM и восстанавливает исходные значения в ответе. Один статический бинарник на Rust (axum + tokio), без базы данных: таблица соответствий живёт только в памяти процесса и удаляется по TTL.

Код написан coding-агентом DeepSeek-V4-Flash-0731 через AlfaGen (OpenCode, настройки — `opencode.json`) по спецификации и задачам команды.

## Быстрый старт

```bash
cargo build --release
./target/release/detox-proxy --config config.yaml      # слушает 0.0.0.0:8080
```

Проверка:

```bash
curl -s localhost:8080/healthz
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент Иванов Иван Иванович, ИНН 500100732259","payload_id":"demo-1"}'
# {"result":"Клиент <<FIO_1>>, ИНН <<INN_1>>"}
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент <<FIO_1>>, ИНН <<INN_1>>","payload_id":"demo-1"}'
# {"result":"Клиент Иванов Иван Иванович, ИНН 500100732259"}
```

Сборка под Linux из Windows/macOS (glibc, результат — `target/linux/release/detox-proxy`):

```bash
docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm cargo build --release --target-dir target/linux
```

Рабочий стенд: `http://93.183.93.44:8080` (systemd-сервис под отдельным пользователем, порт 8080; HTTPS с самоподписанным сертификатом на 443).

## API

| Метод | Назначение |
|---|---|
| `POST /process` | контракт автопроверки: `{"payload", "payload_id"}` → `{"result"}` |
| `POST /v1/mask` | `{"text", "session_id"?}` → `{"text", "session_id", "entities", "mappings"}` |
| `POST /v1/unmask` | `{"text", "session_id"}` → `{"text"}` |
| `POST /v1/detect` | `{"text"}` → `{"entities": [{"type","start","end","confidence"}]}`, смещения в байтах UTF-8 |
| `GET /healthz`, `/readyz` | живость и готовность |
| `POST /v1/chat/completions` | OpenAI-совместимый прокси к LLM: маскирует `messages`, отправляет в upstream, восстанавливает ответ (обычный и `stream: true`); без upstream — демо-режим |
| `POST /admin/reload` | перечитать конфиг, типы ПД, allowlist и словари без рестарта (заголовок `X-Admin-Token` = переменная `DETOX_ADMIN_TOKEN`; без переменной эндпоинт выключен). То же по `SIGHUP` |
| `GET /metrics` | Prometheus |

Заголовок `X-System-Id` выбирает систему-потребителя из `config.yaml` (без заголовка — `default_system`). Неизвестная система → 403, битый JSON или нет `payload_id` → 400, перегрузка → 429 с `Retry-After`, не уложились в `request_deadline_ms` → 503 с `Retry-After`.

Соответствия хранятся отдельно для каждой системы: маска системы A, присланная системой B с тем же `payload_id`, не раскрывается.

### Как `/process` понимает, маскировать или восстанавливать

- новый `payload_id` → маскирование, соответствия сохраняются под этим id;
- тот же `payload_id` и текст с нашими токенами → восстановление;
- тот же `payload_id` и снова исходный текст (повтор запроса) → та же маска, что в первый раз, без нового маскирования.

Токены распознаются без учёта регистра и с пробелами внутри (`<< inn_1 >>`), если LLM их слегка исказила. Чужой `payload_id` не раскрывает данные другого запроса.

## Что маскируется

| Тип | Токен | Тип | Токен |
|---|---|---|---|
| ФИО | `FIO` | Водительское удостоверение | `DRIVLIC` |
| Дата рождения | `BDATE` | Адрес | `ADDR` |
| Место рождения | `BPLACE` | Email | `EMAIL` |
| Паспорт (серия, номер) | `PASSPORT` | Телефон | `PHONE` |
| Гражданство | `CITIZEN` | ИНН | `INN` |
| Кем выдан паспорт | `PASSISS` | Номер карты | `CARD` |
| Код подразделения | `SUBDIV` | CVV/CVC | `CVV` |
| Дата выдачи паспорта | `ISSDATE` | PIN | `PIN` |
| СНИЛС (дополнительно) | `SNILS` | Держатель карты | `CARDHLD` |

Детектор — правила, а не модель: регулярные выражения, валидаторы (Luhn, контрольные суммы ИНН и СНИЛС, календарные даты), словари имён, фамилий, отчеств и городов, контекстные маркеры. Каждая находка получает confidence; ниже порога системы — не маскируется.

Ловушки, которые обрабатываются отдельно: общеизвестные люди и биографические даты («поэт Пушкин родился в 1799»), топонимы-омонимы фамилий («г. Пушкин», «ул. Пушкина»), адреса отделений и офисов, названия полей без значений («укажите ФИО и ИНН»), похожие числа без контекста (номер заказа, версия сборки), PIN/CVV без карты (правило комбинаций, включается на систему).

## Настройка

Всё поведение задаётся данными, без пересборки:

- `config.yaml` — сервер и системы-потребители;
- `data/pii_types.yaml` — типы ПД: шаблоны, валидаторы, маркеры контекста, метки токенов, режим маскирования по умолчанию;
- `data/allowlist.yaml` — общеизвестные персоны и организации;
- `data/dict/*.txt` — словари имён, фамилий, отчеств, городов, стран.

Поля системы в `config.yaml`:

| Поле | Значения | Смысл |
|---|---|---|
| `mask_mode` | `token` / `pseudonym` / `stars` / `synthetic` / `remove` / `off` | как заменять найденное; `pseudonym` — правдоподобные подстановки вместо токенов (см. `docs/MASKS.md`) |
| `overrides` | `{тип: режим}` | режим для отдельного типа |
| `types` | `all` или список | какие типы искать |
| `unmask_enabled` | bool | разрешено ли восстановление |
| `min_confidence` | 0…1 | порог уверенности |
| `trap_policy` | `prefer_mask` / `prefer_skip` | что делать в спорных случаях |
| `combination_rule` | bool | PIN/CVV маскировать только рядом с картой |
| `allow_substrings` | список строк | никогда не маскировать |
| `token_numbering` | `sequential` / `hash` | `<<INN_1>>` или `<<INN_f5c0b7>>` (стабильно между запросами — не ломает кеш промптов LLM) |
| `hash_salt` | строка | соль для `hash` |
| `session_mode` | `stateless` / `stateful` | время жизни соответствий |

Сервер: `mapping_ttl_sec` (TTL соответствий, по умолчанию 900 с), `mapping_max_entries`, `max_inflight` (дальше — 429), `max_body_bytes`, `request_deadline_ms`, `historical_date_years` (старше — «историческая» дата).

В поставке три системы: `autotest` (по умолчанию), `chatbot` (хеш-токены, без восстановления), `strict` (правило комбинаций, `prefer_skip`).

### Прокси к LLM

```yaml
llm:
  upstream_url: "https://llm.example/v1/chat/completions"   # не задан — демо-режим
  api_key_env: "DETOX_LLM_API_KEY"                          # имя переменной окружения с ключом
  timeout_ms: 60000
```

Все сообщения одного запроса маскируются одной таблицей: одно значение — один токен во всех сообщениях. В upstream уходит только текст с токенами; ключ берётся из окружения и нигде не логируется; ошибка upstream отдаётся клиенту как 502 без подробностей. Заголовок ответа `X-Detox-Masked-Entities` — сколько значений было скрыто.

## Логи и метрики

Логи — JSON в stdout, одна строка на запрос без значений ПД: `request_id`, система, направление (mask/unmask), `payload_id` (длинный — хешем), число сущностей по типам, задержка, статус. Метрики Prometheus: `pii_requests_total` и `pii_latency_seconds` (по системе, направлению, статусу), `pii_entities_total` (по типам), `pii_rejected_total` (429 и 503), `pii_inflight`, `pii_mappings_stored`; для разбора прогонов — `pii_payload_bytes` (размер текстов), `pii_entities_per_request`, `pii_requests_without_entities_total`, `pii_process_retry_total` (повторы с тем же `payload_id`), `pii_unmask_unresolved_tokens_total` (токены без соответствия), `pii_config_reloads_total`. Значения ПД не попадают ни в логи, ни в метрики, ни в тексты ошибок — это проверяется тестами.

## Проверка

```bash
cargo test                                             # модульные и HTTP-тесты
python tools/check_process.py --bin target/release/detox-proxy --config config.yaml   # контракт /process
bash tools/manual_accept.sh                            # 25 ручных кейсов с ловушками
python tools/check_modes.py --bin target/release/detox-proxy   # все режимы маскирования: утечки и восстановление
python tools/eval_dataset.py --url http://127.0.0.1:8080   # точность на размеченных наборах (tests/data)
```

Что читать дальше:

- `docs/JURY.md` — сценарии проверки за 10 минут, готовые команды;
- `docs/ARCHITECTURE.md` — как устроен детектор и почему так;
- `docs/MASKS.md` — режимы маскирования, нумерация токенов, падежи;
- `docs/QUALITY.md` — точность на размеченных и отложенных наборах;
- `docs/LOAD.md` — нагрузочные прогоны;
- `docs/LIMITATIONS.md` — что не умеем и почему;
- `docs/LICENSES.md` — сторонние данные и лицензии.
