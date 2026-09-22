# TASKS — очередь задач для DeepSeek V4 Flash

Стек: прокси на Rust (решение от 22.09), инструменты стенда (mock, генератор нагрузки) на Go. **Полные ТЗ блока 1 с проверенными компилятором сигнатурами — `tasks/BLOCK1.rust.md`**, порядок выдачи: T01 → T05 → T03 → T04 → T06 → T07 → T08, затем T02, T09, T10. Таблицы ниже — обзор всей очереди.

Правила выдачи: одна задача — одна сессия агента. Контекст задачи: `AGENTS.md`, нужный раздел `SPEC.md`, перечисленные файлы. После зелёной проверки — коммит. После 2–3 неудачных попыток — новая сессия с уточнённой постановкой.

Шаблон промпта:

```xml
<task id="T03">
  <goal>Что должно появиться, одним-двумя предложениями.</goal>
  <context>SPEC.md §N; файлы, которые нужно прочитать.</context>
  <files_allowed>Список файлов, которые можно создавать и менять.</files_allowed>
  <requirements>Нумерованный список проверяемых требований.</requirements>
  <acceptance>Точная команда и ожидаемый результат.</acceptance>
  <out_of_scope>Что не делать.</out_of_scope>
</task>
```

## Блок 1 — скелет и измеримость (0–4 ч)

| ID | Задача | Приёмка |
|---|---|---|
| T01 | Каркас Rust-проекта: `Cargo.toml` из `Cargo.deps.toml`, модули из `tasks/skeleton.rs` с телами `todo!()`, `.gitignore` | `cargo clippy -- -D warnings` и `cargo build` проходят |
| T02 | `tools/mockllm` (Go): OpenAI-совместимый SSE-сервер с параметрами из SPEC §9 (ttft_ms, tps, output_tokens, error_rate, stall, echo), корректный `usage` | тест: стрим из N токенов приходит с заданным TTFT ±10%, заканчивается `[DONE]` |
| T03 | `src/upstream/sse.rs`: инкрементальный SSE-парсер поверх `Bytes` (`data:` с пробелом и без, многострочные data, комментарии, события > 64 KB, любая нарезка входа, `raw` побайтово равен входу) | табличные тесты и тест нарезки: целиком, побайтово, кусками по 2/3/7/4096 байт — результат идентичен |
| T04 | `llm-proxy`: `POST /v1/chat/completions` — сквозная пересылка stream и non-stream на один upstream; flush на каждое событие; отмена upstream при отключении клиента; заголовки SSE | `check.py --only nonstream_passthrough,stream_incremental,client_cancel,metrics` зелёная |
| T05 | `src/config`: схема из SPEC §4 (server, providers, routes, timeouts, retry), валидация, снимок в `ArcSwap`, `ConfigStore::replace` с сохранением прежней версии при ошибке | тесты валидации: битый конфиг отклоняется, старый остаётся |
| T06 | Таймауты connect / TTFT / idle / total; TTFT считается по первому content-чанку | тесты с mock: `slow_headers`, `stall_after_n_tokens` дают ожидаемые ошибки и коды |
| T07 | Цикл попыток `run_attempts`: retry (full jitter, классы ошибок, `Retry-After`) и fallback-цепочка; только до первого байта клиенту; заголовки `X-Served-By`, `X-Fallback-Reason` | тест: upstream A отдаёт 503 → ответ от B, клиент ошибок не видит; после начала стрима — in-band error; полная `check.py` — 10/10 |
| T08 | `src/obs`: метрики из SPEC §7 (requests, ttft, itl, e2e, overhead, inflight, retries, fallback), `/metrics`, `X-Request-Id` | тест: после запроса счётчики и гистограммы изменились |
| T09 | `tools/loadgen` (Go): open-loop генератор, чтение SSE, TTFT/ITL/e2e/goodput, p50/p95/p99, JSON-отчёт, режим сравнения direct/proxy | запуск на mock 500 RPS × 30 s даёт отчёт; coordinated omission отсутствует (расписание запросов не зависит от ответов) |
| T10 | `deploy/docker-compose.yml`: proxy, 3 mock (fast/slow/flaky), Redis, Prometheus, Grafana с provisioned-дашбордом (6 панелей из playbook §8) | `docker compose up` → дашборд открывается, метрики идут |

Контрольная точка: первая цифра overhead p50/p99 записана в `docs/loadtest/baseline.md`.

## Блок 2 — устойчивость и high-load (4–12 ч)

| ID | Задача | Приёмка |
|---|---|---|
| T11 | Circuit breaker на (provider, model): состояния, TTFT-timeout как отказ, отдельный cooldown для 429, panic mode; метрика `proxy_breaker_state` | тест на состояния с фейковыми часами |
| T12 | Балансировка: weighted и P2C + peak-EWMA по TTFT (decay 10 s), учёт in-flight; active health check; passive outlier detection | тест: при замедлении одного из двух upstream его доля трафика падает < 20% за 10 s |
| T13 | Auth (ключ → tenant) и rate limit RPM + TPM: GCRA в Redis (Lua), reserve → settle по `usage`, локальная аренда квоты, fail-open на локальные лимиты; заголовки `X-RateLimit-*`, `Retry-After` | тесты: превышение → 429; Redis выключен → прокси отвечает; погрешность лимита при 3 репликах < 10% |
| T14 | Admission: ограниченная очередь с приоритетами, дедлайн ожидания, shedding sheddable-класса; adaptive concurrency AIMD по TTFT на upstream; bulkhead на провайдера | нагрузочный тест ×3: critical в SLO, sheddable получает 429, процесс не падает |
| T15 | Exact-cache: канонический ключ, L1 LRU + L2 Redis, replay в SSE, `X-Cache`; singleflight с broadcast для стримов | тест: 100 одинаковых одновременных запросов → 1 вызов upstream, все 100 получили полный стрим |
| T15a | Прозрачный режим: любой `POST/GET /v1/*`, для которого нет специального обработчика, проксируется с той же маршрутизацией, лимитами, retry и метриками, тело не разбирается | тест: `/v1/embeddings` на mock проходит через прокси, метрики и лимиты учитываются |
| T15b | Флаги особенностей провайдера: `force_stream` (обычный запрос клиента уходит в upstream как стрим, ответ собирается в JSON `chat.completion` с `usage`); SSE-парсер принимает `data:` с пробелом и без | тест с mock в режиме «только stream» (на non-stream отвечает 400 с пустым телом): клиент получает корректный JSON |
| T16 | Hot reload: крейт `notify` + `PUT /admin/config` (dry-run, версия, история, rollback) + Redis pub/sub; canary-веса | тест: смена весов под нагрузкой — 0 оборванных стримов, распределение меняется < 1 s |
| T17 | Graceful shutdown: readiness 503, drain, in-band `server_shutdown`; LB в compose (leastconn, без буферизации), 3 реплики | сценарий: rolling restart под нагрузкой → 0 оборванных стримов в отчёте loadgen |
| T18 | Второй адаптер с потоковой трансляцией формата (Anthropic либо GigaChat/YandexGPT) → OpenAI chunk; маппинг `finish_reason`, usage, tool-call дельт | golden-тесты на записанных потоках |
| T19 | Toxiproxy в compose + `scripts/chaos.sh`: таймлайн latency / reset_peer / timeout / slicer во время нагрузки | скрипт отрабатывает, на дашборде видны breaker и fallback |

## Блок 3 — отличия (12–24 ч)

| ID | Задача | Приёмка |
|---|---|---|
| T20 | PII-детекторы: карта (Luhn), ИНН, СНИЛС, счёт + БИК, телефон, email, паспорт; нормализация | табличные тесты с валидными и невалидными контрольными суммами; ложных срабатываний на случайных числах < 1% |
| T21 | PII на входе: плейсхолдеры, карта соответствий в контексте запроса; policy-routing по тегу `on_prem`; метрика и аудит без значений | тест с mock в режиме echo: до upstream дошли только плейсхолдеры |
| T22 | PII на выходе: rehydrate с hold-back; плейсхолдер, разорванный между чанками | property-тест: результат при любой нарезке на чанки совпадает с обработкой целой строки; добавленная задержка < 2 ms |
| T23 | Hedged requests: адаптивный порог p95 TTFT, лимит доли, отмена проигравшего; метрика `proxy_hedges_total{won}` | тест: при 5% медленных ответов p99 TTFT падает, доля дублей ≤ 10% |
| T24 | Prefix-sticky routing: rendezvous hash первых блоков промпта + bounded load; симуляция prefix-cache в mock | тест: повторные префиксы попадают на тот же upstream, средний TTFT ниже |
| T25 | Учёт стоимости: таблица цен в конфиге, аккумуляторы по tenant, async sink с отбрасыванием при переполнении | тест: sink заблокирован → запросы не замедляются, растёт `proxy_log_dropped_total` |
| T26 | OTel-трейсы: `traceparent`, спаны attempts / hedge / fallback, событие first_token | трейс виден в Tempo или Jaeger из compose |
| T27 | k8s-манифесты: Deployment (3 реплики, PDB, preStop, topology spread), HPA/KEDA по `proxy_inflight`, readiness/liveness | `kubectl apply --dry-run=server` проходит; демо автоскейла на локальном кластере |

## Блок 4 — доказательства и презентация (последние 10–12 ч)

| ID | Задача | Результат |
|---|---|---|
| T28 | Прогоны нагрузки ×1 / ×3 / ×10, direct против proxy, soak 30 мин | `docs/loadtest/report.md` с таблицами и графиками |
| T29 | Профилирование (`cargo flamegraph` или `samply` в Docker под Linux, `tokio-console` для задач) и устранение 2–3 главных горячих точек | до/после в отчёте |
| T30 | README: архитектурная схема, соответствие требованиям задачи, SLO и результаты, запуск одной командой, план роста ×10 и узкие места | — |
| T31 | ADR на ключевые решения: стек, локальная аренда квоты, retry только до первого байта, hold-back для PII | `docs/adr/` |
| T32 | Презентация и запись демо по сценарию из `00-PREP.md` §4 | — |
