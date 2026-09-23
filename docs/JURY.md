# DetoxProxy — инструкция для жюри

Всё ниже проверено на чистой Ubuntu 26.04 и в контейнере `rust:1-bookworm`. Нужен только Rust (стабильный) и, по желанию, Python 3 для инструментов проверки. Ни базы данных, ни интернета, ни GPU.

## 1. Запуск за одну минуту

```bash
cargo build --release
./target/release/detox-proxy --config config.yaml     # слушает 0.0.0.0:8080
```

Без Rust — в Docker (сборка 3–5 минут, образ запускается от непривилегированного пользователя):

```bash
docker build -t detoxproxy .
docker run --rm -p 8080:8080 detoxproxy
```

Проверка, что живой:

```bash
curl -s localhost:8080/healthz          # ok
```

Рабочий стенд, если не хочется собирать: **http://93.183.93.44:8080**

## 2. Главный сценарий: маскирование и восстановление

```bash
curl -s localhost:8080/process -H 'Content-Type: application/json' -d '{
  "payload": "Клиент Иванов Иван Иванович, паспорт 4509 123456, ИНН 500100732259, тел. +7 912 345-67-89",
  "payload_id": "demo-1"}'
```
```json
{"result":"Клиент <<FIO_1>>, паспорт <<PASSPORT_1>>, ИНН <<INN_1>>, тел. <<PHONE_1>>"}
```

Теперь отправьте полученный текст обратно с тем же `payload_id` — вернётся оригинал:

```bash
curl -s localhost:8080/process -H 'Content-Type: application/json' -d '{
  "payload": "Клиент <<FIO_1>>, паспорт <<PASSPORT_1>>, ИНН <<INN_1>>, тел. <<PHONE_1>>",
  "payload_id": "demo-1"}'
```

Повторная отправка исходного текста с тем же `payload_id` вернёт ту же маску (идемпотентность, не путается с демаскированием).

## 3. Ловушки: что мы не маскируем

```bash
for t in \
  "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве." \
  "Адрес отделения банка: г. Казань, ул. Баумана, д. 3." \
  "Заполните форму: ФИО, дата рождения, ИНН, PIN и CVV." \
  "Версия сборки 8.900.123.45.67 опубликована вчера." \
  "Номер заказа 500100732258 передан в доставку."; do
  curl -s localhost:8080/process -H 'Content-Type: application/json' \
    -d "{\"payload\": \"$t\", \"payload_id\": \"$RANDOM\"}"; echo; done
```

Все пять текстов возвращаются без изменений. Для сравнения — те же формы, но с настоящими данными клиента, маскируются:

```bash
curl -s localhost:8080/process -H 'Content-Type: application/json' -d '{
  "payload": "Наш клиент ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ, 06.06.1988 г.р., проживает: Москва, ул. Лесная, дом 17, квартира 42",
  "payload_id": "demo-2"}'
```

Вариации написания, которые тоже маскируются: строчными с телефона («иванов иван иванович, тел 89123456789»), с латинской «o» внутри фамилии («Иванoв»), латиницей с отчеством («Ivanov Ivan Ivanovich»), «Королев» при словаре с «Королёв», дата прописью («двенадцатого марта 1985 г.»), «серия 4509, номер 123456».

## 4. Настройка под систему-потребителя

Заголовок `X-System-Id` выбирает политику из `config.yaml`. В поставке четыре системы: `autotest` (по умолчанию), `chatbot`, `strict` и `pseudo` (правдоподобные подстановки, см. вкладку «Псевдонимизация» на `/demo`). Примеры:

```bash
# chatbot: хеш-токены (стабильны между запросами — не ломают кеш промптов LLM), без восстановления
curl -s localhost:8080/process -H 'X-System-Id: chatbot' -H 'Content-Type: application/json' \
  -d '{"payload":"ИНН 500100732259","payload_id":"demo-3"}'
# -> {"result":"ИНН <<INN_f5c0b7>>"}

# strict: PIN и CVV маскируются только при номере карты в том же предложении, спорные случаи не маскируются
curl -s localhost:8080/process -H 'X-System-Id: strict' -H 'Content-Type: application/json' \
  -d '{"payload":"пин-код 4821","payload_id":"demo-4"}'
```

Системе можно назначить ключ доступа: в `config.yaml` у `strict` указано `api_key_env: DETOX_KEY_STRICT`. Если переменная задана, запрос к `strict` без заголовка `X-Api-Key` или с неверным ключом получает 401, ключ сравнивается за постоянное время и не попадает ни в журнал, ни в метрики:

```bash
DETOX_KEY_STRICT=s3cret ./target/release/detox-proxy --config config.yaml &
curl -s localhost:8080/process -H 'X-System-Id: strict' -H 'Content-Type: application/json'   -d '{"payload":"ИНН 500100732259","payload_id":"demo-5"}'                      # 401
curl -s localhost:8080/process -H 'X-System-Id: strict' -H 'X-Api-Key: s3cret' -H 'Content-Type: application/json'   -d '{"payload":"ИНН 500100732259","payload_id":"demo-5"}'                      # 200
```

Неизвестная система — 403, отключённая (`enabled: false`) — тоже 403, запрет восстановления для системы — `unmask_enabled: false`. Значения в хранилище соответствий зашифрованы ключом процесса (`server.encrypt_mappings`).

Режим замены задаётся на систему и на тип: `token`, `pseudonym` (правдоподобная подстановка: «Сидорову Петру Ивановичу» → «Чернякову Ираклию Ильичу», ИНН и карта с верной контрольной суммой), `stars` (`4276 **** **** 3347`, ФИО → `С. П. И.`), `synthetic`, `remove`, `off`. Все режимы на одном тексте — `docs/MASKS.md`, проверка — `python3 tools/check_modes.py --bin target/release/detox-proxy`.

## 5. Добавление нового типа ПД без пересборки

Все правила — данные. Допишите в `data/pii_types.yaml`:

```yaml
  - id: vehicle_plate
    name: Vehicle registration plate
    token_label: PLATE
    context_required: true
    context_words: [госномер, гос. номер, номер автомобиля, автомобиль, машина, транспортное средство, регистрационный знак]
    patterns:
      - '(?iu)\b[АВЕКМНОРСТУХ]\d{3}[АВЕКМНОРСТУХ]{2}\d{2,3}\b'
```

и примените без рестарта:

```bash
DETOX_ADMIN_TOKEN=secret ./target/release/detox-proxy --config config.yaml &   # токен включает эндпоинт
curl -s -X POST localhost:8080/admin/reload -H 'X-Admin-Token: secret'          # {"version":1}
curl -s localhost:8080/process -H 'Content-Type: application/json' \
  -d '{"payload":"Госномер А123ВС777 в протоколе","payload_id":"demo-5"}'
# -> {"result":"Госномер <<PLATE_1>> в протоколе"}
```

То же самое делает `SIGHUP`. В поставке этот тип выключен: в задании 17 типов, а лишние маски штрафуются.

## 6. Сквозной сценарий с LLM

`POST /v1/chat/completions` — OpenAI-совместимый прокси: маскирует сообщения, отправляет в LLM, восстанавливает ответ. Без настроенного upstream работает демо-режим:

```bash
curl -s localhost:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model":"demo","messages":[{"role":"user","content":"Напиши письмо с отказом Иванову Ивану Ивановичу, ИНН 500100732259"}]}'
```

Модель видит только метки: `<<FIO_1:дат>>` (падеж исходного слова) и `<<INN_1>>`. Первым сообщением прокси добавляет системный промпт из `config.yaml` (`llm.case_hints_prompt`): как обращаться с метками и как запросить падеж. Модель может написать `<<FIO_1:им>>`, и клиент получит «Уважаемый Иванов Иван Иванович», а не «Уважаемый Иванову Ивану Ивановичу». Заголовок `X-Detox-Masked-Entities` показывает, сколько значений скрыто; с заголовком `X-Detox-Debug: 1` в ответе есть поле `detox`: ровно то, что ушло в модель, и режим (`demo` или `upstream`).

LLM на стенде не подключена, поэтому ответ модели не изображается: в демо-режиме прокси возвращает таблицу склонений каждой найденной метки (ФИО, место рождения, гражданство), восстановленную из меток вида `<<FIO_1:род>>`.

Свой upstream подключается в `config.yaml` (`llm.upstream_url`, ключ — через переменную окружения).

## 6а. Страница демо и метрики

`http://93.183.93.44:8080/demo` (или `localhost:8080/demo`): три вкладки — «Токенизация» (маскирование с подсветкой найденного и восстановление ответа LLM, с примерами «все падежи» и «искажённые метки»), «Псевдонимизация» (тот же текст с правдоподобными подстановками и их восстановление), «Через LLM (падежи)» (системный промпт, что ушло в модель, таблица склонений). В каждом блоке — кнопки готовых примеров, текст можно вводить вручную. Вверху страницы — живая панель из `GET /stats`: RPS, TPS, p50/p99 и ошибки за последнюю минуту. Полные метрики Prometheus — `/metrics`.

## 7. Проверки, которые можно запустить

```bash
cargo test                                                   # модульные и HTTP-тесты
python3 tools/check_process.py --bin target/release/detox-proxy --config config.yaml
                                                             # контракт /process: 54 проверки
bash tools/manual_accept.sh                                  # 25 ручных кейсов с ловушками
python3 tools/big_text_check.py --bin target/release/detox-proxy
                                                             # текст ~100 000 токенов: маска и точное восстановление
python3 tools/jury_check.py --bin target/release/detox-proxy
                                                             # текст ~100 000 токенов: маска и точное восстановление
```

Наборы данных в архив не входят (по требованиям организаторов), поэтому оценка точности `tools/eval_dataset.py` запускается на своих размеченных данных в формате `{"text", "entities":[{"type","start","end"}]}`. Наши измерения — `docs/QUALITY.md`, нагрузка — `docs/LOAD.md`.

## 8. Что смотреть в коде

| Вопрос | Файл |
|---|---|
| Как устроен детектор и слои проверки | `src/detect/mod.rs`, обзор — `docs/ARCHITECTURE.md` |
| Правила по типам ПД (данные, не код) | `data/pii_types.yaml` |
| Политики систем-потребителей | `config.yaml`, `src/config/mod.rs` |
| Маскирование, восстановление, падежи | `src/mask/mod.rs`, `src/morph/mod.rs` |
| Хранилище соответствий (TTL, вытеснение) | `src/store/mod.rs` |
| HTTP, лимиты, метрики, перезагрузка | `src/server/mod.rs` |
| Прокси к LLM | `src/llm/mod.rs` |

Логи — JSON без значений ПД, метрики Prometheus на `/metrics`.
