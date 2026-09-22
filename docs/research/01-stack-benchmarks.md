# Стек для high-load LLM-gateway (данные на сентябрь 2026)

Максимум производительности даёт Rust (axum + hyper + reqwest). Для хакатона на 24–48 часов, где код пишет DeepSeek V4 Flash, я бы всё же взял Go 1.27 на stdlib `net/http`. Разница в накладных расходах между ними меньше 1–4 ms при TTFT провайдера от 100 ms до нескольких секунд, а риск не успеть сделать фичи с Rust заметно выше.

Пометки в тексте:
- **[V]** — прочитано на странице-источнике через WebFetch. Страницу пересказывает малая модель, поэтому перед питчем сверьте цифры по URL.
- **[S]** — цифра только из сниппета поисковой выдачи.
- **[I]** — мой вывод или экспертное знание, источником не подтверждено.

## 1. Open-source LLM-gateways: опубликованные цифры

| Gateway | Язык / фреймворк | Overhead | RPS и память | Источник |
|---|---|---|---|---|
| LiteLLM (Python) | FastAPI/Uvicorn | p99 257.7 ms под нагрузкой. В бенчмарке TensorZero: 100 QPS — p99 5.87 ms, 500 QPS — p99 39.69 ms, 1000 QPS — отказ. | 242 RPS, 1352 MB (c7i.large) | [V] |
| LiteLLM Rust (beta, июнь–июль 2026) | axum + hyper, Python-плагины в sidecar | p99 0.7 ms; в анонсе ~0.05 ms на запрос против 7.5 ms у Python | ~2814 RPS на 4 vCPU, пик 21.8 MB | [V] цифры, [S] про axum/hyper |
| Bifrost (Maxim) | Go, fasthttp, плагины | Заявлено 11 µs (t3.xlarge) и 59 µs (t3.medium) при 5k RPS. У конкурентов: p99 4.5 ms; p50 4.30 / p99 20.5 ms. | 1984 RPS, 298.9 MB (c7i.large); 199 MB в тесте LiteLLM | [V] |
| TensorZero | Rust | Mean 0.37 / p50 0.35 / p99 0.94 ms при 10k QPS (c7i.xlarge, свой тест от 30.07.2025) | 4498 RPS, 105 MB. У ENTERPILOT p50 49.97 ms при c=10 — авторы объясняют это эффектом Nagle. | [V] |
| Helicone AI Gateway | Rust, Tower | «<1 ms»; p95 89 ms при mock-upstream 60 ms | 3000 RPS, <100 MB, CPU ~80% (Fly performance-2x) | [V] |
| agentgateway 1.3 | Rust, xDS, CEL | p50 0.83 / p90 1.53 / p99 1.97 ms | 36 933 QPS, 22 MB. LiteLLM там же: 3198 QPS, 11.8 GB. Условия: 32 соединения, payload 1 KB, 3 секунды. | [V] |
| GoModel 0.1.94 | Go | p50 2.34 / p99 7.19 ms | 4215 RPS, 91.8 MB, cold start 1.03 s | [V] |
| Portkey OSS | TypeScript, Hono | p99 2.3 ms (тест LiteLLM); 9.87 / 32.14 ms (ENTERPILOT). Заявлено «<1 ms, 122 kB»; с guardrails 20–40 ms. | 907 RPS, 124 MB | [V], заявления [S] |
| Envoy AI Gateway | Envoy (C++) + Go ext_proc | ~2 ms. Broadcom: 3 часа, streaming, 190 пользователей, реальные H100, TTFT 0.103 s. | — | [V] |
| Kong AI Gateway | Lua / OpenResty | 29 005 RPS, p95 24.07 / p99 30.35 ms (12 CPU, 400 VU, WireMock). «+228% к Portkey, +859% к LiteLLM». | — | [V] через deepinspect, [S] |
| vLLM Router | Rust | Consistent hashing, power-of-two, PD-дезагрегация, circuit breaker. Throughput +25% к llm-d и +100% к K8s LB; TTFT на 1200–2000 ms быстрее. | — | [V] |
| SGLang Model Gateway | Rust | Cache-aware routing: 1.9× throughput, 3.8× cache hit. Token-bucket, очередь запросов, retry, per-worker circuit breaker. | — | [S] |
| llm-d | Go EPP + Envoy (ext_proc) | Pipeline filter → score → pick. Цифр overhead не нашёл. | — | [S] |
| OpenRouter | TypeScript, Cloudflare Workers | ~15 ms по их документации; ~55 ms по оценке Requesty | — | [S] / [V] |
| Cloudflare AI Gateway | Workers | 10–50 ms | — | [S] |
| Requesty | Go, Gin | ~16 ms в production | — | [V] |

Источники:
- LiteLLM Rust: https://docs.litellm.ai/blog/rust-ai-gateway-benchmarks и https://docs.litellm.ai/blog/litellm-rust-launch
- Bifrost: https://www.getmaxim.ai/bifrost/resources/benchmarks и https://github.com/maximhq/bifrost
- TensorZero: https://raw.githubusercontent.com/tensorzero/tensorzero/main/docs/gateway/benchmarks.mdx
- Helicone: https://github.com/Helicone/ai-gateway/blob/main/benchmarks/README.md
- agentgateway: https://agentgateway.dev/blog/2026-06-26-benchmarking-agentgateway-vs-litellm/
- ENTERPILOT, независимый тест, прогон 18.09.2026: https://github.com/ENTERPILOT/ai-gateway-reproducible-benchmark
- Разбор методологий: https://www.deepinspect.ai/blog/ai-gateway-latency-benchmarks
- Envoy AI Gateway: https://tetrate.io/learn/ai/ai-gateway-benchmarks
- Kong: https://konghq.com/blog/engineering/ai-gateway-benchmark-kong-ai-gateway-portkey-litellm
- vLLM Router: https://vllm.ai/blog/2025-12-13-vllm-router-release
- Аудит языков gateways: https://www.requesty.ai/blog/why-ai-gateways-should-be-built-in-go
- OpenRouter: https://openrouter.ai/docs/guides/best-practices/latency-and-performance

Что из этого следует [I]:
- Почти все цифры вендорские, сняты на mock-upstream и без streaming. Bifrost у себя показывает 11 µs, у конкурента 4.5 ms p99.
- Качество реализации важнее языка. В ENTERPILOT Go-шлюз GoModel обошёл Rust-шлюз TensorZero: авторы бенчмарка объясняют это эффектом Nagle на соединениях TensorZero [V], то есть, по-видимому, не выставлен `TCP_NODELAY` [I].
- Разумная цель для хакатона: overhead p99 < 1–2 ms, меньше 100 MB памяти и 5–10k RPS на 4 vCPU. Это достижимо и на Rust, и на Go.
- Python и Node в этой задаче не рассматриваю: они отстают на порядки.

## 2. Общие бенчмарки HTTP и proxy

**TechEmpower закрыт.** Репозиторий заархивирован 24.03.2026 [V]. Последний раунд — Round 23 (февраль 2025): Rust на верхних местах, Go-фреймворки дают примерно 50–70% от лучшего Rust-результата [V, через статью]. Преемник — HttpArena (alpha, 95 участников). По сниппетам [S] в HTTP/1.1 composite лидируют genhttp-ioxide (C#) 7056, actix 6847, fiber-tuned (Go) 6433, bun 6040, vertx 5295.
- https://dev.to/kaliumhexacyanoferrat/techempower-framework-benchmarks-are-now-archived-whats-next-3l0a
- https://www.http-arena.com/leaderboard/

**Память на 1 млн параллельных задач** (Kołaczkowski, 2023) [V]:

| Runtime | Память |
|---|---|
| Rust tokio | ~350 MB |
| Python asyncio | ~900 MB |
| C# | ~1.2 GB |
| Node.js | ~1.4 GB |
| Java virtual threads | ~1.8 GB |
| Go | ~4.5 GB (в 12 раз больше tokio) |

На 100k задач: tokio ~40 MB, Go ~500 MB. Источник: https://pkolaczk.github.io/memory-consumption-of-async/

Моя оценка на один проксируемый SSE-стрим [I]:
- Go `net/http`: 20–35 KB. Это серверная goroutine, два bufio-буфера по 4 KB, две goroutine Transport на upstream-соединение и буфер копирования.
- Rust: 5–15 KB.
- На 10k стримов получается ~300 MB против ~100 MB. Оба варианта приемлемы.

**Pingora против nginx у Cloudflare** [S]:
- CPU меньше на 70%, памяти на 67%.
- Connection reuse вырос с 87.1% до 99.92%, то есть новых соединений к origin стало в 160 раз меньше.
- Медианный TTFB уменьшился на 5 ms, p95 на 80 ms.
- Причина — общий пул соединений между потоками.
- Источник: https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/

**Reverse-proxy на M1 Max, hello-world** [V]:

| Proxy | RPS | Память | CPU |
|---|---|---|---|
| Nginx | 54.8k | 12 MB | — |
| Envoy | 37.6k | 43 MB | 383% |
| Pingora | 31k | 19.6 MB | 77% |
| Traefik (Go) | 8.6k | 61 MB | — |

Источник: https://dev.to/kanywst/go-vs-rust-vs-c-deep-dive-into-reverse-proxy-performance-on-mac-pingoraenvoytraefiknginx-g40

**GC и хвост латентности:**
- Go 1.26 (февраль 2026): Green Tea GC включён по умолчанию, накладные расходы GC ниже на 10–40%, ещё до 10% на Zen4 и Ice Lake [V].
- Go 1.27 (август 2026): `encoding/json` работает на движке v2, Unmarshal существенно быстрее; аллокации меньше 80 байт быстрее до 30% [V].
- Оценка «Go даёт колебания p99 на 2–5 ms при 5k RPS со streaming, у Rust хвост ровный» ничем в источнике не подкреплена [V как цитата].
- Discord и Linkerd ушли на Rust из-за хвостовой латентности [S].
- Java с ZGC держит паузы около 50 µs, но JVM прожорлива по памяти [S].
- Источники: https://go.dev/doc/go1.26, https://go.dev/doc/go1.27, https://dev.to/gabrielanhaia/rust-vs-go-for-ai-infrastructure-in-2026-heres-what-the-benchmarks-actually-say-4j28

**io_uring и monoio.** По собственным тестам monoio он вдвое быстрее tokio на 4 ядрах и втрое на 16 [S]. Но крейт monoio 0.2.4 не обновлялся с августа 2024, tokio-uring 0.5.0 — с мая 2024 [V, crates.io]. Экосистемы hyper, reqwest и TLS под них нет, для хакатона не подходит [I].

**.NET YARP.** Заявлено больше 100k RPS на 4 ядрах, а также +21% QPS к nginx ценой +65% CPU [S]. Это рабочий третий вариант.

## 3. Подводные камни SSE-проксирования

Источник большинства [V]-пунктов: https://dev.to/gauravdagde/streaming-sse-proxying-for-llm-apis-the-hard-parts-4d60

**Буферизация:**
- В Go `io.Copy` пишет в ResponseWriter с буфером 4 KB. Нужен `Flush()` после каждого события [V]. Прецедент: https://github.com/ArsalanDotMe/switchboard-go/pull/6
- `httputil.ReverseProxy` сам ставит FlushInterval = -1 для `text/event-stream` [S].
- Перед gateway на nginx: `proxy_buffering off` или заголовок `X-Accel-Buffering: no`, и gzip выключен для SSE [S].
- На upstream-клиенте отключить автоматическую декомпрессию: `DisableCompression: true` в Go [I].
- `Server.WriteTimeout = 0`; дедлайн ставить на каждый чанк через `http.ResponseController` [I].

**Nagle и TCP_NODELAY.** Без NODELAY мелкие записи задерживаются до 40 ms [S]; случай TensorZero в ENTERPILOT это подтверждает [V]. В axum нужно явно вызвать `axum::serve(...).tcp_nodelay(true)`. В reqwest и Go NODELAY включён по умолчанию [I].

**Границы чанков.** TCP режет SSE-события посередине. Если стрим только пересылается, передавайте сырые байты и не разбирайте их [V].

**Отключение клиента.** Если не отменить upstream, генерация продолжается, а токены оплачиваются или GPU-слот остаётся занят. Базовая доля отключений — около 5% [V].
- Баг LiteLLM: https://github.com/BerriAI/litellm/issues/30244
- Расхождение в счетах до ~14%: https://tianpan.co/blog/2026/06/03/the-streaming-abort-signal-your-frontend-sent-that-your-provider-billed-for-the-unsent-tokens-anyway
- В Go: `http.NewRequestWithContext(r.Context(), ...)`.
- В Rust upstream-стрим должен принадлежать телу ответа. Когда hyper сбрасывает тело, соединение закрывается (HTTP/1.1) или уходит RST_STREAM (HTTP/2). Если есть промежуточная задача с каналом, нужно обрабатывать ошибку отправки [I].
- fasthttp не отменяет контекст при отключении клиента; это видно только по ошибке записи [S]: https://github.com/valyala/fasthttp/issues/771

**Backpressure:**
- Ограниченный канал на ~64 события и таймаут записи 5 s, медленного клиента рвать [V].
- При 10k стримов по 50 чанков в секунду выходит 500k write-syscalls в секунду, и это основной расход CPU. Под нагрузкой склеивайте чанки окном 5–10 ms [I].

**Ошибки после ответа 200:**
- Отправлять in-band событие `data: {"error":...}` [V].
- Retry и failover возможны только до первого байта.
- Нужны три отдельных таймаута: connect, TTFT и простой между чанками [I].
- Heartbeat-комментарий каждые 15–30 s, потому что load balancer рвёт простаивающие соединения через 60–120 s [S].

**HTTP/2 против HTTP/1.1 к upstream** [I]:
- HTTP/2 экономит TLS-handshakes и эфемерные порты. Пул на 10k+ HTTP/1.1-соединений к одному IP:port упирается в `ip_local_port_range`.
- Минусы HTTP/2: лимит MAX_CONCURRENT_STREAMS (часто 100), head-of-line blocking на уровне TCP при потере пакетов, общее окно flow-control.
- Для внешних провайдеров брать HTTP/2 с несколькими соединениями. В Go 1.26 для этого появился `HTTP2Config.StrictMaxConcurrentRequests` [V].
- Для локального vLLM или mock подойдёт keep-alive пул HTTP/1.1.
- В Go `MaxIdleConnsPerHost` по умолчанию равен 2, его обязательно поднять до сотен или тысяч.

**TLS.** Handshake стоит 1–2 RTT плюс ~1–5 ms CPU [I]. Держите соединения тёплыми, делайте preconnect при старте, используйте общий пул (пример Pingora выше).

**Zero-copy.** Через TLS `splice` не работает. В Rust можно без копирования передать `Bytes` из `reqwest::bytes_stream()` в `Body::from_stream`. В Go — буфер 32 KB из `sync.Pool`. При чанках около 200 байт копирование несущественно; считать надо syscalls и аллокации [I].

**JSON:**
- Go: sonic до 5 раз быстрее старого stdlib на Unmarshal, json/v2 — вдвое [S].
- Rust: sonic-rs в 1.5–2 раза быстрее simd-json и в 3–4 раза быстрее serde_json [S, данные README].
- Лучше вообще не делать полный разбор. Из запроса нужны только `model` и `stream`: в Go это `gjson` или `sonic.Get`, в Rust — serde-структура с нужными полями и `&RawValue` для остального. В стриме искать подстроку `"usage"` только в последних чанках [I].

**Подсчёт токенов.** Добавлять в запрос `stream_options: {"include_usage": true}` и читать финальный usage-чанк перед `[DONE]` [V]. Tiktoken использовать только как запасной вариант вне горячего пути [I]. Лимиты по TPM сверять по факту после ответа, а не резервировать заранее [I].

## 4. Rust или Go для хакатона с DeepSeek V4 Flash

**Модель.** DeepSeek V4 Flash: заявлено 79.0% SWE-bench Verified [S]. По языкам (Aider polyglot для Rust и Go отдельно) данных не нашёл. Есть статья arXiv 2604.27001: всего 23.3% компилируемого Rust-кода от LLM в один проход. Это узкий криптографический домен без агентного цикла, и 94% ошибок там связаны с типами [S]. Там же: Go компилируется в 10–60 раз быстрее. Источник по срокам: «Go first cut ~1 day; Rust 2–3 days» [V].

**Ранжирование по ожидаемому результату, а не по пиковой скорости** [I]:

1. **Go 1.27 на stdlib `net/http`.**
   - Даёт примерно 90–95% производительности Rust: GoModel показал p99 7 ms на 2 vCPU при 4.2k RPS, а после Green Tea GC паузы меньше миллисекунды.
   - Отмена upstream при отключении клиента делается через `r.Context()` в одну строку.
   - Сборка занимает секунды, кросс-компиляция с вашего Windows тривиальна, агент почти не застревает.
   - Типичные ошибки агента: гонки данных, утечки goroutine, забытые `Flush` и `resp.Body.Close`. Лечится `go test -race`, `go vet` и профилем `goroutineleak` из Go 1.27.
2. **Rust: axum + hyper + reqwest.**
   - Лучший p99, в 3–10 раз меньше памяти; это стек LiteLLM Rust и TensorZero.
   - Брать, если оценка идёт по замерам overhead на mock и есть человек, который разблокирует агента.
   - Риски:
     - Ограничения `Send + 'static` и типы Body в tower и hyper 1.x.
     - Дрейф API относительно обучающих данных модели: в axum 0.8 пути пишутся как `/{id}`, reqwest уже 0.13.
     - Release-сборка с LTO занимает минуты.
     - На Windows/MSVC jemalloc не собирается, нужен mimalloc или сборка в Docker.
   - Правила для агента:
     - `middleware::from_fn` вместо собственных Layer.
     - `Arc<AppState>` и `.clone()`, никаких lifetimes в структурах.
     - `anyhow`.
     - `cargo check` после каждого шага.
     - Зафиксировать версии в Cargo.toml.
3. **Rust на Pingora 0.9.0.**
   - Это самый производительный фундамент именно для proxy.
   - Модели знают его API хуже, он меняется до версии 1.0, нативно под Windows не собирается.
   - Для агента рискованно.
4. **Go на fasthttp** (путь Bifrost).
   - Нет HTTP/2, отключение клиента ловится костылями, API несовместим с `net/http`.
   - Выигрыш виден только в микробенчмарках.
5. **Остальные:**
   - .NET 10 Kestrel + YARP — достойный вариант.
   - Java Netty с ZGC — тоже.
   - Envoy с ext_proc — про конфигурацию, не про код.
   - Bun, Node, Python — не брать.

**Как выбрать, не гадая.** Попросите агента за 2 часа собрать Rust-скелет: passthrough SSE, отмена upstream и `/metrics`. Если агент за 2 часа не получил работающую сборку, переходите на Go.

**Версии библиотек** [V — crates.io API и proxy.golang.org, 21.09.2026]:

| Роль | Rust | Go (1.27.1) |
|---|---|---|
| HTTP server | axum 0.8.9, hyper 1.11.1, tokio 1.53.1, tower-http 0.7.1. Альтернатива: pingora 0.9.0. | stdlib `net/http` + chi v5.3.2. Альтернатива: fasthttp v1.74.0. |
| HTTP client | reqwest 0.13.5 (rustls 0.23.45) либо hyper-util 0.1.20 legacy client | `http.Transport` с тюнингом, x/net v0.59.0 |
| JSON | serde_json 1.0.151 + `RawValue`; для горячего пути sonic-rs 0.5.10 или simd-json 0.18.1 | bytedance/sonic v1.15.4, tidwall/gjson v1.19.0, stdlib json (v2-движок) |
| Metrics | metrics 0.24.6 + metrics-exporter-prometheus 0.18.3, tracing 0.1.44 | prometheus/client_golang v1.24.1 или VictoriaMetrics/metrics v1.44.0 |
| Config hot-reload | arc-swap 1.9.2 + notify 8.2.0 + config 0.15.26 | `atomic.Pointer[Config]` + fsnotify v1.10.1 + koanf v2.3.6 |
| Rate limit | governor 0.10.4 (локально) + Lua-скрипт в Redis | x/time/rate v0.16.0 (локально) + redis_rate v10.0.1 или mennanov/limiters v1.13.11 |
| Redis | redis 1.7.0 + deadpool-redis 0.23.1. fred 10.1.0 не обновлялся с февраля 2025. | redis/rueidis v1.0.78 (auto-pipelining) или go-redis v9.22.0 |
| Circuit breaker | Самописный на atomics (около 80 строк). failsafe 1.3.0 не обновлялся с 2024. | sony/gobreaker v2.4.0 или failsafe-go v0.9.7 (retry, hedge, circuit breaker) |
| Прочее | mimalloc 0.1.52 или tikv-jemallocator 0.7.0, bytes 1.12.1, moka 0.12.16, dashmap 6.2.1, tiktoken-rs 0.12.0 | puzpuzpuz/xsync v4.5.0, tiktoken-go/tokenizer v0.8.1, `GOMEMLIMIT`, `sync.Pool` |

**Общие рекомендации для обоих стеков** [I]:
- Экземпляры без состояния, глобальные лимиты и кеш вынести в Redis.
- Локальный token bucket с периодической синхронизацией вместо обращения к Redis на каждый запрос.
- `SO_REUSEPORT`, поднятый `ulimit -n`.
- Прогрев соединений к upstream при старте.
- Health-checks и пассивное выявление сбойных upstream (outlier detection).
- Нагрузочный тест: mock-upstream со streaming (k6 или oha). Мерить TTFT и интервалы между чанками. Non-streaming RPS в этой задаче мало что показывает.

Не удалось прочитать страницу SGLang gateway docs (404) и таблицу HttpArena: leaderboard рендерится на JavaScript, цифры по нему взяты только из сниппетов.
