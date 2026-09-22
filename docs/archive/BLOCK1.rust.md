# Блок 1 под Rust — полные ТЗ

Порядок выдачи: T01 → T05 → T03 → T04 → T06 → T07 → T08, затем инструменты T02, T09, T10 (Go и compose — по таблице в `TASKS.md`).
Одна задача — одна сессия агента. Извлечь ТЗ по идентификатору: `python docs/agent-kit/tasks/task.py T04`.

Общее для всех задач:
- Правила — `AGENTS.md` в корне (вариант Rust). Сигнатуры — `docs/agent-kit/tasks/skeleton.rs`: публичные имена, поля и сигнатуры копируются дословно, менять их нельзя. Образцы вызовов API — `docs/agent-kit/rust-api-cheatsheet.rs`.
- Бинарник называется `llm-proxy`, запускается как `llm-proxy --config <путь к YAML>`.
- Приёмка чёрным ящиком — `tools/check.py` (изменять запрещено; при старте скопировать из `docs/agent-kit/tasks/check.py`, запускалку — из `bakeoff/agent.sh` в `tools/agent.sh`). Она сама генерирует `check-config.yaml` и поднимает два фейковых upstream.
- Полная проверка в каждой задаче: `cargo clippy --all-targets -- -D warnings && cargo test`.

<task id="T01">
  <goal>Создать каркас Rust-проекта: все модули блока 1 с проверенными сигнатурами и телами todo!(), проект собирается.</goal>
  <context>docs/agent-kit/tasks/skeleton.rs, docs/agent-kit/Cargo.deps.toml, раздел layout в AGENTS.md.</context>
  <files_allowed>Cargo.toml, .gitignore, src/main.rs, src/error.rs, src/state.rs, src/config/mod.rs, src/upstream/mod.rs, src/upstream/sse.rs, src/server/mod.rs, src/obs/mod.rs</files_allowed>
  <requirements>
    1. Cargo.toml: package name llm-proxy, edition 2021; блоки [dependencies] и [profile.release] скопированы из Cargo.deps.toml дословно.
    2. Каждый mod из skeleton.rs разнесён в свой файл по таблице в шапке skeleton.rs. Сигнатуры, имена полей, derive и serde-атрибуты — дословно. Тела остаются todo!().
    3. В src/main.rs: объявления модулей, глобальный аллокатор mimalloc, функция main с #[tokio::main], которая пока только разбирает аргумент --config (без внешних крейтов, через std::env::args) и завершается с ошибкой, если он не задан.
    4. Временно допустим #![allow(dead_code, unused_variables)] в main.rs; остальные предупреждения clippy запрещены.
    5. .gitignore: target/, *.exe, *.log, check-config.yaml, check-result.json, __pycache__/.
  </requirements>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo build</acceptance>
  <out_of_scope>Любая реализация логики. Новые зависимости. Изменение сигнатур.</out_of_scope>
</task>

<task id="T05">
  <goal>Реализовать модуль конфигурации: разбор YAML, валидация, атомарный снимок с безопасной заменой.</goal>
  <context>src/config/mod.rs (сигнатуры уже на месте), SPEC.md §4.</context>
  <files_allowed>src/config/mod.rs, tests/config.rs, config.example.yaml</files_allowed>
  <requirements>
    1. Config::from_yaml разбирает текст и сразу вызывает validate; ошибка разбора — ConfigError::Yaml, ошибка правил — ConfigError::Invalid с понятным сообщением на английском.
    2. validate отклоняет: пустой список providers или routes; повторяющиеся имена провайдеров; base_url без схемы http:// или https://; target, ссылающийся на несуществующего провайдера; маршрут без targets; нулевые ttft_ms, idle_ms, total_ms, connect_ms; weight равный 0; пустой listen.
    3. route_for: сначала точное совпадение model, затем маршрут с model "*"; иначе None.
    4. ConfigStore::new валидирует начальный конфиг. ConfigStore::replace валидирует новый конфиг и подменяет снимок только при успехе; при ошибке прежний снимок остаётся. load не блокируется.
    5. config.example.yaml: рабочий пример с двумя провайдерами и маршрутом "*", все поля с комментариями на английском.
  </requirements>
  <tests>
    tests/config.rs: пример из config.example.yaml разбирается; каждое правило из пункта 2 имеет свой тест на отклонение; неизвестное поле отклоняется; replace с невалидным конфигом возвращает ошибку и load отдаёт прежнюю версию; значения по умолчанию Timeouts и RetryConfig совпадают со skeleton.rs.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test --test config</acceptance>
  <out_of_scope>Слежение за файлом и Admin API (это T16). Поля, которых нет в skeleton.rs.</out_of_scope>
</task>

<task id="T03">
  <goal>Реализовать инкрементальный SSE-парсер, устойчивый к любой нарезке входа.</goal>
  <context>src/upstream/sse.rs (сигнатуры на месте).</context>
  <files_allowed>src/upstream/sse.rs, tests/sse.rs</files_allowed>
  <requirements>
    1. Событие заканчивается пустой строкой. Поддерживаются переводы строк \n и \r\n, в том числе вперемешку.
    2. Поле data: принимается и с пробелом после двоеточия, и без него ("data: {" и "data:{") — оба варианта встречаются у реального upstream. Срезается не более одного ведущего пробела.
    3. Несколько строк data: в одном событии склеиваются через '\n'. Поле event: сохраняется. Строки-комментарии (начинаются с ':') и неизвестные поля в data не попадают.
    4. raw содержит точные байты события вместе с завершающей пустой строкой — без нормализации, чтобы сквозная пересылка была побайтовой.
    5. Блок только из комментариев даёт событие с пустым data; is_comment возвращает true. is_done возвращает true для data равного "[DONE]".
    6. push принимает вход, разрезанный в любом месте, включая середину "\r\n" и середину многобайтового символа UTF-8. Недочитанный хвост хранится в buf.
    7. Если незавершённое событие превысило max_event_bytes — SseError::EventTooLarge. finish возвращает незавершённый хвост как событие, если в нём есть данные.
    8. Без аллокации String на событие: data и raw — это Bytes. Без unsafe.
  </requirements>
  <tests>
    tests/sse.rs: табличные случаи на каждый пункт 1–7; обязательный тест нарезки — один и тот же поток из минимум 6 разных событий (включая кириллицу в JSON, \r\n, комментарий, многострочный data, событие больше 64 KB) подаётся целиком, побайтово и кусками по 2, 3, 7, 4096 байт, результат во всех случаях идентичен; конкатенация raw всех событий равна исходному входу.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test --test sse</acceptance>
  <out_of_scope>Разбор JSON внутри data. Поле retry: и id:.</out_of_scope>
</task>

<task id="T04">
  <goal>Сквозной прокси POST /v1/chat/completions на первый target маршрута: stream и non-stream, без буферизации, с отменой upstream при отключении клиента.</goal>
  <context>src/error.rs, src/state.rs, src/server/mod.rs, src/upstream/mod.rs, src/obs/mod.rs, src/main.rs; docs/agent-kit/rust-api-cheatsheet.rs; разделы streaming_rules и ownership_rules в AGENTS.md.</context>
  <files_allowed>src/main.rs, src/error.rs, src/state.rs, src/server/mod.rs, src/upstream/mod.rs, src/obs/mod.rs</files_allowed>
  <requirements>
    1. main: читает YAML по --config, строит ConfigStore, общий reqwest::Client (build_http_client: pool_max_idle_per_host 512, pool_idle_timeout 90 s, tcp_nodelay, connect_timeout 2 s), устанавливает метрики, слушает server.listen с TCP_NODELAY через tap_io (образец в шпаргалке).
    2. chat_completions: тело ограничено server.max_body_bytes (413 при превышении); из тела извлекается только ChatRequestView; невалидный JSON — ProxyError::BadRequest; маршрут ищется через route_for, при отсутствии — NoRoute (404).
    3. upstream::attempt для первого target маршрута: запрос на base_url + path; заголовки клиента пробрасываются, кроме host, content-length, transfer-encoding, connection; тело — исходные Bytes без пересериализации. Если задан api_key_env — Authorization берётся из этой переменной окружения, иначе пробрасывается клиентский.
    4. Ответ: статус и заголовки upstream (кроме content-length, transfer-encoding, connection) передаются клиенту; добавляется X-Served-By с именем провайдера. Для стрима добавляются cache-control: no-cache и x-accel-buffering: no.
    5. Стрим пересылается чанк за чанком через Body::from_stream; стрим ответа напрямую владеет upstream-стримом — промежуточных задач и каналов нет, поэтому отключение клиента закрывает соединение с upstream.
    6. ProxyError::into_response: JSON {"error": {"message", "type"}} и статус из status(). classify_status: 429 → RateLimit; 401 и 403 → Auth; 408 и все 5xx → Retryable; остальные 4xx → Fatal.
    7. GET /healthz → 200 "ok". GET /metrics → текст Prometheus; счётчик proxy_requests_total увеличивается на каждый POST.
    8. run_attempts и with_stream_timeouts в этой задаче не реализуются (остаются todo!()), attempt вызывается напрямую.
  </requirements>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo build --release && python tools/check.py --yaml --cmd "target/release/llm-proxy.exe" --base-port 18100 --only nonstream_passthrough,stream_incremental,client_cancel,metrics</acceptance>
  <out_of_scope>Retry, fallback, таймауты TTFT и idle (T06, T07). Разбор SSE на этом пути: чанки пересылаются как есть.</out_of_scope>
</task>

<task id="T06">
  <goal>Раздельные таймауты upstream: connect, TTFT (по первому чанку тела, а не по заголовкам), idle между чанками, total.</goal>
  <context>src/upstream/mod.rs, src/server/mod.rs, config::Timeouts.</context>
  <files_allowed>src/upstream/mod.rs, src/server/mod.rs, tests/common/mod.rs, tests/timeouts.rs</files_allowed>
  <requirements>
    1. В attempt для стрима: после получения заголовков ждать первый чанк тела не дольше ttft_ms (tokio::time::timeout вокруг stream.next()). Upstream может прислать 200 и заголовки сразу, а первый чанк задержать — это тоже TTFT-таймаут. При таймауте ответ upstream уничтожается (соединение закрывается), возвращается ProxyError::Upstream с class Retryable и message "ttft timeout".
    2. Для non-stream весь ответ ограничен total_ms.
    3. with_stream_timeouts: если следующий чанк не пришёл за idle — поток выдаёт Err(ProxyError::Upstream {.. message: "idle timeout"}) и завершается; то же при исчерпании total. Реализация — без отдельной задачи tokio::spawn: обёртка над потоком (tokio_stream::StreamExt::timeout или futures_util::stream::unfold).
    4. into_client_response оборачивает rest в with_stream_timeouts. Ошибка после первого байта превращается в завершающее SSE-событие data: {"error": {"message", "type"}} и закрытие стрима; клиент не зависает.
    5. connect_ms применяется на уровне запроса, если отличается от значения клиента по умолчанию.
  </requirements>
  <tests>
    tests/common/mod.rs: вспомогательный фейковый upstream на axum (порт 0), режимы: ok, stall_first (заголовки сразу, первый чанк через N ms), stall_mid (зависает после K чанков), счётчик активных соединений для проверки отмены. tests/timeouts.rs: TTFT-таймаут срабатывает за ttft_ms ±200 ms и соединение с фейком закрывается; idle-таймаут даёт завершающее событие error после K чанков; total ограничивает non-stream.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test --test timeouts && cargo build --release && python tools/check.py --yaml --cmd "target/release/llm-proxy.exe" --base-port 18100 --only nonstream_passthrough,stream_incremental,client_cancel,midstream_abort_no_retry</acceptance>
  <out_of_scope>Повтор на другом upstream (T07).</out_of_scope>
</task>

<task id="T07">
  <goal>Цикл попыток: retry с full jitter и fallback по цепочке targets — строго до первого байта клиенту.</goal>
  <context>src/upstream/mod.rs, src/server/mod.rs, config::RetryConfig, error::ErrClass.</context>
  <files_allowed>src/upstream/mod.rs, src/server/mod.rs, tests/attempts.rs</files_allowed>
  <requirements>
    1. run_attempts перебирает targets маршрута по порядку. На каждом target — до retry.max_attempts попыток. Повтор и переход к следующему target делаются только для ErrClass::Retryable и RateLimit; Auth, Fatal, ContextLength, Policy возвращаются клиенту сразу.
    2. backoff_delay: равномерно в [0, min(cap, base * 2^attempt)], без переполнения при больших attempt. Если upstream прислал Retry-After (секунды) — ждать его, но не дольше cap.
    3. Каждая неуспешная попытка полностью отменяется до начала следующей (ответ upstream уничтожен).
    4. При успехе не на первом target в UpstreamResponse.fallback_reason записывается причина последней неудачи; клиенту уходит заголовок X-Fallback-Reason.
    5. Все targets исчерпаны → ProxyError::AllUpstreamsFailed, статус 503, JSON-ошибка.
    6. После того как первый чанк принят и ответ отдан клиенту, никакие повторы невозможны по построению: run_attempts возвращает управление до начала пересылки.
    7. chat_completions переключается с прямого вызова attempt на run_attempts. Метрики: proxy_retries_total{reason}, proxy_fallback_total{from,to}.
  </requirements>
  <tests>
    tests/attempts.rs: backoff_delay в границах для attempt 0..40; 503 на первом target → ответ от второго; 401 не повторяется; Retry-After учитывается; все недоступны → 503 с JSON.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check.py --yaml --cmd "target/release/llm-proxy.exe" --base-port 18100</acceptance>
  <expected>ИТОГ: 10/10</expected>
  <out_of_scope>Circuit breaker, балансировка по весам, hedging (блок 2).</out_of_scope>
</task>

<task id="T08">
  <goal>Метрики задержек и идентификатор запроса.</goal>
  <context>src/obs/mod.rs, src/server/mod.rs, SPEC.md §7.</context>
  <files_allowed>src/obs/mod.rs, src/server/mod.rs, tests/metrics.rs</files_allowed>
  <requirements>
    1. Гистограммы (секунды, бакеты от 0.0005 до 60): proxy_ttft_seconds, proxy_itl_seconds, proxy_e2e_seconds, proxy_overhead_seconds{phase="pre"|"first_byte"}. phase=pre — от приёма запроса до отправки в upstream; first_byte — от первого чанка upstream до передачи его клиенту.
    2. proxy_requests_total{route,provider,status,stream}; gauge proxy_inflight{provider}, уменьшается в том числе при отключении клиента (через Drop-guard, живущий внутри стрима ответа).
    3. Измерение ITL не добавляет аллокаций на чанк: обёртка над потоком хранит Instant предыдущего чанка.
    4. Каждому запросу присваивается X-Request-Id (принимается от клиента либо генерируется); он возвращается в ответе и попадает в tracing-span.
    5. Значения лейблов — из конфига (имена маршрутов и провайдеров), не из пользовательского ввода: кардинальность ограничена.
  </requirements>
  <tests>tests/metrics.rs: после стрим-запроса к фейковому upstream в /metrics есть все гистограммы с ненулевым count; proxy_inflight возвращается к 0 после обрыва клиента.</tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check.py --yaml --cmd "target/release/llm-proxy.exe" --base-port 18100</acceptance>
  <out_of_scope>OpenTelemetry-трейсы (T26). Учёт токенов и стоимости (T25).</out_of_scope>
</task>
