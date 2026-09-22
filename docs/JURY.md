# DetoxProxy — инструкция для жюри

Всё ниже проверено на чистой Ubuntu 26.04 и в контейнере `rust:1-bookworm`. Нужен только Rust (стабильный) и, по желанию, Python 3 для инструментов проверки. Ни базы данных, ни интернета, ни GPU.

## 1. Запуск за одну минуту

```bash
cargo build --release
./target/release/detox-proxy --config config.yaml     # слушает 0.0.0.0:8080
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

## 4. Настройка под систему-потребителя

Заголовок `X-System-Id` выбирает политику из `config.yaml`. В поставке три системы:

```bash
# chatbot: хеш-токены (стабильны между запросами — не ломают кеш промптов LLM), без восстановления
curl -s localhost:8080/process -H 'X-System-Id: chatbot' -H 'Content-Type: application/json' \
  -d '{"payload":"ИНН 500100732259","payload_id":"demo-3"}'
# -> {"result":"ИНН <<INN_3fa91c>>"}

# strict: PIN и CVV маскируются только рядом с картой, спорные случаи не маскируются
curl -s localhost:8080/process -H 'X-System-Id: strict' -H 'Content-Type: application/json' \
  -d '{"payload":"пин-код 4821","payload_id":"demo-4"}'
```

Режим замены задаётся на систему и на тип: `token`, `stars` (`4276 **** **** 5679`, ФИО → `И. И. И.`), `synthetic` (правдоподобная подстановка), `remove`, `off`.

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

Модель видит только `<<FIO_1>>` и `<<INN_1>>`. В ответе значения восстановлены, причём **в нужном падеже**: модель может попросить `<<FIO_1:им>>`, и клиент получит «Уважаемый Иванов Иван Иванович», а не «Уважаемый Иванову Ивану Ивановичу». Заголовок ответа `X-Detox-Masked-Entities` показывает, сколько значений было скрыто.

Свой upstream подключается в `config.yaml` (`llm.upstream_url`, ключ — через переменную окружения).

## 7. Проверки, которые можно запустить

```bash
cargo test                                                   # 188 тестов
python3 tools/check_process.py --bin target/release/detox-proxy --config config.yaml
                                                             # контракт /process: 54 проверки
bash tools/manual_accept.sh                                  # 25 ручных кейсов с ловушками
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
