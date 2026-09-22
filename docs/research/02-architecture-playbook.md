# Playbook: High-load LLM-прокси (хакатон, вероятно Альфа-Банк)

Это исследование по открытым источникам. Сам я ничего не запускал и не мерил. Пометка «(реком.)» означает моё инженерное предложение. Остальные числа взяты из источников, список URL дан после каждого раздела. Цифры производительности gateway-ев (Bifrost, LiteLLM и др.) публикуют сами вендоры, в основном на mock-апстриме.

---

## 0. Эталонная архитектура

```
Client (OpenAI-compatible API, SSE)
  → [Ingress/L4 LB]
  → Proxy (stateless, N реплик; Go или Rust)
       pipeline: auth → admission/priority → rate-limit (local+Redis) → cache lookup (exact → semantic)
                 → input guardrails (PII mask) → router (model→pool→endpoint; breaker, P2C/prefix-aware)
                 → upstream adapter (OpenAI/Anthropic/Gemini/GigaChat/YandexGPT/vLLM/Ollama)
                 → stream transformer (SSE parse → normalize → guardrail/rehydrate → token count → re-emit)
                 → async sink (usage/cost/log → NATS/Kafka → ClickHouse)
  ↔ Redis/Dragonfly (rate limits, cache, breaker gossip, config pub/sub)
  ↔ Prometheus + OTel Collector → Grafana/Tempo
```

Правило для security-gateway из разбора DeepInspect: «enforce inline, commit evidence asynchronously». На горячем пути остаются только решения (лимит, маршрут, маска). Логи, биллинг и аудит пишутся асинхронно.

Язык (реком.): Go или Rust. Go даёт быстрый старт: `net/http`, `httputil`, `x/sync/singleflight`. По вендорским бенчмаркам Bifrost (Go) добавляет около 11 µs на 5k RPS, LiteLLM (Python) около 600 µs. В одном из опубликованных прогонов LiteLLM падал по памяти на 1k RPS. Envoy AI Gateway показывает около 2 ms на реальном H100 со стримингом. Судьям стоит показывать именно overhead прокси, потому что он составляет доли процента от времени инференса.

Источники: https://www.deepinspect.ai/blog/ai-gateway-latency-benchmarks · https://github.com/maximhq/bifrost · https://www.getmaxim.ai/bifrost/resources/benchmarks

---

## 1. Reliability-паттерны

### 1.1 Таймауты

У SSE заголовок 200 OK приходит раньше первого токена. Поэтому латентность нужно мерить по первому байту тела, иначе hedging и таймауты не сработают. Дефолты (реком.):

| Таймаут | Значение | Действие |
|---|---|---|
| connect | 1–2 s для внешнего провайдера, 250 ms внутри ДЦ | retry на другой endpoint |
| TLS handshake | 3 s | retry |
| TTFT (до первого content-чанка) | 5–10 s для чата, 30–60 s для reasoning, настраивается per-model | fallback; безопасен, пока клиенту не ушло ни байта |
| inter-token idle | 10–15 s | оборвать и отдать SSE-событие `error`; retry после начала стрима нельзя |
| total | 120–300 s или deadline клиента | cancel upstream |
| queue wait | до 30 s, потом 408 (у SGLang gateway: queue 128, timeout 30 s) | shed |

У SGLang Model Gateway connect timeout 10 s, pool idle 50 s, max idle per host 500, TCP keepalive 30 s. Для пула соединений стоит взять похожие значения. Частая ошибка — маленький `MaxIdleConnsPerHost` в Go.

### 1.2 Deadline propagation и отмена

- Deadline берётся из заголовка клиента (`X-Request-Timeout` или `grpc-timeout`-стиль) либо из SLA тенанта. Из него создаётся `context.WithDeadline`.
- Каждый retry или fallback получает остаток бюджета. Если остаток меньше минимально полезного (например, меньше p50 TTFT модели), прокси сразу отдаёт fail-fast или деградированный ответ.
- Отмена двунаправленная. Если клиент закрыл соединение, прокси отменяет upstream-запрос, чтобы не платить за токены, которые никто не прочтёт.

### 1.3 Retry: backoff, jitter, budget

- Формула Full Jitter (дефолт AWS SDK): `sleep = rand(0, min(cap, base * 2^attempt))`. Реком.: base 100 ms, cap 2–5 s, максимум 2 retry. У SGLang gateway: 5 попыток, 50 ms → 5 s, множитель ×2, jitter 0.1.
- Retry делается на 408, 429 (с учётом `Retry-After`), 500, 502, 503, 504, 529, connect/reset и TTFT-timeout. Не делается на 400, 401, 403, 404, 422, content-policy и context-length. Для двух последних используется специализированный fallback: у LiteLLM это `context_window_fallbacks` и `content_policy_fallbacks`.
- Retry допустим только до отправки первого байта клиенту. После начала стрима остаётся SSE `error`. Продолжение через prefill уже выданного текста на другой модели возможно, но рискованно.
- Retry лучше отправлять на другой endpoint или провайдера, а не на тот же.
- Retry budget защищает от retry storm:
  - Envoy: `retry_budget.budget_percent` = 20% от активных запросов, `min_retry_concurrency` = 3.
  - gRPC: token bucket. Неудача стоит 1 токен, успех возвращает `tokenRatio` (0.1). Retry разрешён, пока tokens > maxTokens/2.
  - По разбору tianpan.co: глобальный cap 5–15% от базового трафика, отдельные бюджеты по классам ошибок (overload, network, timeout). При исчерпании бюджета новые retry отклоняются сразу, без очереди.

### 1.4 Fallback chains

Цепочка выглядит так: `primary(model A @ provider X) → same model @ provider Y → smaller/cheaper model → cached/semantic-cached answer → статический деградированный ответ (503 + Retry-After)`. У Portkey это вложенные стратегии `fallback`/`loadbalance` с `on_status_codes: [429, 500…]`. У LiteLLM — `fallbacks` и специализированные варианты. В ответе нужен заголовок `x-served-by-model` или `x-fallback-reason`, чтобы деградация была видна клиенту и на дашборде.

### 1.5 Circuit breaker (на endpoint и на пару provider, model)

- Состояния: Closed → Open → Half-Open.
- SGLang gateway: 5 последовательных отказов открывают breaker, окно 60 s, breaker открыт 30 s, 2 успеха в half-open закрывают.
- LiteLLM: `allowed_fails` = 3 в минуту, `cooldown_time` = 5 s. 429 даёт немедленный cooldown. Cooldown также включается при доле отказов больше 50% за минуту.
- Реком.: breaker открывается при выполнении любого из двух условий — 5 отказов подряд или error-rate ≥ 50% при минимум 20 запросах в скользящем окне 10–30 s. Open длится 10–30 s с экспоненциальным ростом: у Envoy base_ejection_time 30 s умножается на число эжекций. В half-open пропускается 1–3 пробных запроса.
- Для LLM «отказом» нужно считать и превышение TTFT, не только 5xx. 429 учитывается отдельно: это rate-limit cooldown по `Retry-After`, а не поломка.
- Состояние breaker хранится локально в каждой реплике. Опционально реплики обмениваются событием «open» через Redis pub/sub. Без этого они просто сходятся немного медленнее, что приемлемо.

### 1.6 Hedged requests

Алгоритм: если первый байт тела не пришёл за p90–p95 TTFT для этой модели (порог адаптивный, по скользящей гистограмме), прокси отправляет дубль на другой endpoint. Побеждает тот, кто первым прислал content-чанк, проигравший отменяется. Долю hedge ограничивает token bucket на 5–10% трафика, иначе при реальной аварии нагрузка удвоится. По опубликованным результатам worst-case TTFT упал с 4.2 s до 1.2 s, p99 снизился на 74% при примерно 9% лишних запросов. Hedging стоит включать только для интерактивного класса и дешёвых или self-hosted моделей, потому что каждый дубль стоит денег.

### 1.7 Защита от перегрузки

- **Adaptive concurrency limit** вместо фиксированного RPS.
  - AIMD: при успехе `limit += 1` за RTT-раунд, при таймауте или 429/503 `limit *= 0.5…0.9`.
  - Gradient (Envoy): `gradient = (minRTT + B) / sampleRTT`, `limit_new = gradient × limit_old + √limit`. Параметры: sampleRTT = p90 окна, minRTT пересчитывается каждые 60 s, окно 50 запросов, jitter 10%.
  - В Netflix concurrency-limits есть Vegas, Gradient2 и AIMD.
  - Для LLM в качестве RTT нужно брать TTFT. Полная длительность не годится, потому что зависит от длины ответа. Лимит ведётся на каждый upstream.
- **Bulkheads**: отдельные семафоры или пулы на тенанта, провайдера и класс приоритета. Один зависший провайдер не должен занять все горутины и соединения.
- **Admission control и priority queues**: классы `critical / standard / sheddable` по образцу criticality в Gateway API Inference Extension, где sheddable-запросы сбрасываются при заполнении KV-cache или очереди. Очередь ограничена (128). Приоритеты обслуживаются через weighted fair queueing. При перегрузке применяется LIFO или сброс самых старых: запрос с почти истёкшим дедлайном выгоднее сбросить, чем обслужить. Ответ — 429 или 503 с `Retry-After`.
- **Load shedding по сигналам**: in-flight выше лимита, время в очереди выше порога (CoDel-подобно, 100–500 ms для интерактива), давление CPU или памяти самого прокси.
- **Backpressure**: каналы между upstream-reader и client-writer ограничены. Если клиент медленный, прокси перестаёт читать upstream и TCP-backpressure дойдёт до провайдера. Буфер на стрим ограничен, например 64–256 KB. Для «зависшего» клиента ставится write deadline на каждый flush, 10–30 s.
- **Graceful degradation**: меньшая модель, урезанный `max_tokens`, отключение дорогих guardrails (NER остаётся, LLM-judge выключается), ответ из semantic cache с ослабленным порогом и пометкой в заголовке.

Источники:
- https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
- https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/circuit_breaker.proto
- https://gateway-api.sigs.k8s.io/geps/gep-3388/
- https://docs.litellm.ai/docs/routing
- https://docs.litellm.ai/docs/proxy/reliability
- https://docs.sglang.io/advanced_features/sgl_model_gateway.html
- https://tianpan.co/blog/2026-05-02-tail-tolerant-retry-policy-llm-gateway-latency-cliff
- https://engineering.myhoai.com/posts/a-simple-fix-for-llm-tail-latency/
- https://github.com/bhope/hedge
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter
- https://github.com/Netflix/concurrency-limits (обзор: https://deepwiki.com/Netflix/concurrency-limits)
- https://kubernetes.io/blog/2025/06/05/introducing-gateway-api-inference-extension/
- https://portkey.ai/docs/api-reference/inference-api/config-object

---

## 2. Load balancing по LLM-бэкендам

| Алгоритм | Когда использовать | Замечание |
|---|---|---|
| Round robin / random | бэкенды однородные, запросы короткие | для LLM подходит плохо: стоимость запросов различается в десятки раз |
| Weighted (simple-shuffle по rpm/tpm/weight) | внешние провайдеры с квотами | дефолт LiteLLM, минимальный overhead |
| Least-connections / least-busy | базовый минимум для LLM | учитывает in-flight, но не длину запроса |
| Least-pending-tokens | self-hosted vLLM | score = Σ(prompt_tokens + ожидаемые output) по активным запросам. Лучший дешёвый прокси GPU-нагрузки |
| Peak-EWMA + P2C | разнородные провайдеры, цель — tail latency | cost = EWMA(latency) × (in_flight + 1). Peak: при всплеске значение подскакивает сразу и затухает экспоненциально, τ ≈ 10 s. P2C: берутся 2 случайных endpoint, выбирается с меньшим cost. Сложность O(1), нет herd-эффекта. Для LLM в EWMA подставляется TTFT (реком.) |
| Prefix/KV-cache-aware | self-hosted с prefix caching | подробности ниже |
| Consistent hashing / session affinity | многоходовые диалоги, provider-side prompt cache | ключ: `session_id`, `user`, hash(system prompt). Нужен bounded-load (c = 1.25), иначе появятся hot spots |

Реализации KV/prefix-aware:
- **SGLang router (cache_aware, дефолт)**: приближённое radix-дерево префиксов на каждый worker. Если доля совпадения ≥ `cache-threshold` (0.3), запрос идёт на worker с лучшим совпадением. Иначе на worker с наибольшей свободной ёмкостью. При дисбалансе (`balance-abs-threshold` 64 и `balance-rel-threshold` 1.5) роутер переходит на shortest-queue. Eviction каждые 120 s. Заявлено до 1.9× по throughput и 3.8× по hit rate.
- **NVIDIA Dynamo KV router**: `cost = kv_overlap_score_weight × potential_prefill_blocks + potential_active_blocks`, вес по умолчанию 1.0. Выбирается минимум или softmax-sampling.
- **llm-d и Gateway API Inference Extension (EPP)**: scorer-ы prefix-cache, kv-cache-utilization и queue с весами. Есть приоритеты и flow control. На повторных префиксах TTFT падает примерно до 1.5 s после заполнения кеша.
- **vLLM production-stack router**: режимы `roundrobin | session | prefixaware | kvaware | disaggregated_prefill`. В `session` используется consistent hashing. В `prefixaware` задаётся минимальная длина совпадения, при меньшем совпадении роутер откатывается к QPS.
- Дешёвая версия для хакатона (реком.): хешируются первые N блоков промпта по 256–1024 символов (system prompt и начало истории), дальше rendezvous hashing по списку endpoint с bounded-load. Это около 30 строк кода, а эффект можно показать на mock-сервере с симуляцией prefix cache.

Health checks и outlier detection:
- Active: `GET /health` или `/v1/models` каждые 5–30 s, timeout 2–10 s. Порог: 3 провала переводят в unhealthy, 2 успеха возвращают в healthy (дефолты SGLang: 30 s / 10 s / 3 / 2). Для платных провайдеров active-проверки стоят денег, поэтому там только passive.
- Passive (outlier detection, дефолты Envoy): `consecutive_5xx` = 5, `interval` = 10 s, `base_ejection_time` = 30 s, умножается на число эжекций, `max_ejection_percent` = 10%. Для 2–3 провайдеров последний параметр стоит поднять до 50–66%. Добавляются latency-outlier по TTFT-EWMA и правило panic mode: если исключены почти все endpoint, трафик идёт на всех.
- Pre-call checks из LiteLLM: endpoint отфильтровываются по context window, региону и остатку TPM/RPM.
- В Linkerd 2.20 (июнь 2026) появился rate-limit-aware LB. Идея: 429 используется как сигнал для весов балансировки.

Источники:
- https://linkerd.io/2016/03/16/beyond-round-robin-load-balancing-for-latency/
- https://linkerd.io/2026/06/23/announcing-linkerd-2.20/
- https://arxiv.org/pdf/2312.10172 (Prequal: «Load is not what you should balance»)
- https://www.lmsys.org/blog/2024-12-04-sglang-v0-4/
- https://docs.sglang.io/advanced_features/sgl_model_gateway.html
- https://docs.nvidia.com/dynamo/latest/router/README.html
- https://github.com/llm-d/llm-d-router
- https://developers.redhat.com/articles/2025/10/07/master-kv-cache-aware-routing-llm-d-efficient-ai-inference
- https://github.com/kubernetes-sigs/gateway-api-inference-extension
- https://gateway-api-inference-extension.sigs.k8s.io/
- https://vllm.ai/blog/2025-12-13-vllm-router-release
- https://github.com/vllm-project/production-stack
- https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier
- https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/outlier_detection.proto

---

## 3. Rate limiting и квоты

- Два измерения: **RPM** защищает от шквала запросов, **TPM** защищает бюджет и GPU. Ключи лимитов: `api_key`, `tenant`, `user`, `model` и их комбинации. Лимиты иерархические: org → team → key.
- Проблема TPM в том, что число токенов ответа заранее неизвестно. Решение — схема reserve → settle. До запроса резервируется `prompt_tokens (оценка) + max_tokens` (или p95 исторического output). После ответа учёт корректируется по фактическому `usage`, излишек возвращается. Так работает Envoy AI Gateway: `llmRequestCosts` извлекает usage из ответа. Стоимость можно задать CEL-выражением, например `input_tokens * 0.25 + output_tokens * 1.0`. Проверка лимита идёт на следующем запросе, при превышении отдаётся 429.
- Алгоритмы поверх Redis, атомарно через Lua/`EVALSHA`:
  - **GCRA**: один ключ хранит TAT (theoretical arrival time). `emission = period/limit`, `new_tat = max(tat, now) + cost × emission`. Если `new_tat − now ≤ burst × emission`, запрос разрешён. Один ключ, O(1), TTL ставится автоматически, стоимость можно задавать в токенах. Готовая реализация — `go-redis/redis_rate`. Это лучший вариант для TPM.
  - **Token bucket** (Lua: `tokens`, `ts`): самый понятный, естественно допускает burst.
  - **Sliding window counter**: два соседних fixed-window счётчика с весом `prev × (1 − elapsed/window) + curr`. Дёшево и достаточно точно. Вариант на ZSET точнее, но расходует O(N) памяти.
- Как не ходить в Redis на каждый запрос (реком.):
  1. **Локальный token bucket с арендой квоты.** Реплика раз в 50–200 ms берёт у Redis пачку токенов (`DECRBY` на 5–10% лимита) и расходует её локально. Погрешность не превышает размер пачки, умноженный на число реплик.
  2. **Асинхронный sync.** Решение принимается по локальному счётчику плюс последней известной глобальной сумме. Дельты отправляются батчем через pipeline каждые 100 ms.
  3. При недоступности Redis: fail-open с локальным лимитом `limit / N_replicas`. Для банка допустим fail-closed на дорогих моделях.
- В ответ добавляются `x-ratelimit-limit/remaining/reset-requests|tokens` и `Retry-After`.
- Бюджеты: стоимость считается как `in_tok × price_in + out_tok × price_out + cached_tok × price_cached` по таблице цен из конфига. В Redis ведутся аккумуляторы по ключу, дню и месяцу. Soft limit (80%) отправляет алерт и webhook. Hard limit отдаёт 402 или 429 либо переводит на дешёвую модель.

Источники:
- https://redis.io/tutorials/howtos/ratelimiting/
- https://redis.io/docs/latest/develop/use-cases/rate-limiter/
- https://blog.callr.tech/rate-limiting-for-distributed-systems-with-redis-and-lua/
- https://github.com/go-redis/redis_rate
- https://aigateway.envoyproxy.io/docs/0.1/capabilities/usage-based-ratelimiting/
- https://github.com/envoyproxy/ai-gateway/blob/main/examples/token_ratelimit/token_ratelimit.yaml
- https://agentgateway.dev/docs/kubernetes/latest/llm/rate-limit/

---

## 4. Кеширование

1. **Exact-match.** Ключ: `SHA-256(canonical JSON: model, messages, temperature, top_p, max_tokens, tools, response_format, seed) + tenant scope`. При нормализации ключи сортируются, пробелы обрезаются, `stream`, `user` и metadata отбрасываются. Кешируется только при `temperature = 0` или при явном opt-in (`x-cache: on`, `x-cache-ttl`). Два уровня: L1 — in-process LRU (ristretto или otter), L2 — Redis. TTL от 1 до 24 часов. Tool-calls с побочными эффектами не кешируются.
2. **Кеш стриминговых ответов.** При промахе чанки копируются в буфер. После `[DONE]` в кеш записывается либо список дельт, либо итоговый текст. При попадании ответ отдаётся как SSE. Есть два режима: быстрый (всё сразу крупными чанками) и реалистичный (pacing 0–5 ms). В ответе ставится `x-cache: HIT`, а `usage` обнуляется или помечается cached. Для `stream=false` из того же кеша собирается обычный JSON.
3. **Singleflight (request coalescing).** `x/sync/singleflight` по ключу кеша. Обычный singleflight ждёт полный ответ. Для стриминга нужен broadcast: лидер читает upstream и пишет в ring-buffer с replay, а последователи подписываются, получают накопленный префикс и дальше читают live. Пример такой реализации — PR cradle #58. Ожидание последователей должно иметь timeout (`DoChan`). Если лидер упал, первый последователь становится новым лидером.
4. **Semantic cache.** Embedding последнего user-сообщения плюс hash контекста → vector search (Redis Vector/RediSearch HNSW, Qdrant, GPTCache). При cosine ≥ порога считается попаданием.
   - Порог 0.97: hit rate 5–10%, ложных срабатываний меньше 0.5%. Порог 0.85–0.90: много попаданий, но риск неверного ответа 1–15%. Реком.: для банка старт с 0.95–0.97 и обязательное разделение по тенанту, system prompt и модели.
   - Качество embedding-модели влияет сильнее, чем подбор порога.
   - Embedding добавляет 5–30 ms, если модель локальная. Поэтому сначала проверяется exact-cache, затем semantic. Semantic можно считать параллельно с отправкой в upstream и при попадании отменять upstream-запрос (реком.).
   - Не подходит для персонализированных ответов с данными клиента, для tool-calls и для длинных многоходовых диалогов.
5. **Provider-side prompt caching — как прокси повышает hit rate:**
   - Anthropic: явные `cache_control` breakpoints, запись стоит ×1.25, чтение ×0.1, TTL 5 минут с опцией на 1 час. Прокси может сам ставить breakpoint после system и tools и на последнем стабильном сообщении.
   - OpenAI: кеширование автоматическое, по самому длинному префиксу. `prompt_cache_key` влияет на маршрутизацию к бэкенду. Рекомендация — около 15 RPM на ключ, более горячий трафик делить детерминированно. В поисковой выдаче утверждается, что на новейших моделях ключ уже не нужен. Перед использованием это нужно проверить по документации OpenAI.
   - Что делает прокси. (а) Стабилизирует префикс: детерминированный порядок tools и JSON-ключей, динамика (дата, request-id, RAG) вставляется в конец, а не в system. (б) Держит sticky routing: один `hash(prefix)` всегда идёт на тот же провайдер, аккаунт, регион или vLLM-реплику (так поступает OpenRouter). (в) Не меняет провайдера без необходимости, потому что fallback сбрасывает кеш. (г) Собирает метрику `cached_tokens / prompt_tokens` по маршруту.
   - Для self-hosted: `--enable-prefix-caching` в vLLM плюс prefix-aware routing из раздела 2.

Источники:
- https://github.com/zilliztech/GPTCache
- https://redis.io/blog/10-techniques-for-semantic-cache-optimization/
- https://www.spheron.network/blog/semantic-cache-llm-inference-gpu-cloud/
- https://arxiv.org/pdf/2403.02694 (MeanCache)
- https://arxiv.org/pdf/2603.03301
- https://github.com/519lab/cradle/pull/58
- https://rednafi.com/go/request-coalescing/
- https://ai-tldr.dev/learn/production-llmops/cost-latency-optimization/request-coalescing-llm/
- https://developers.openai.com/api/docs/guides/prompt-caching
- https://openrouter.ai/docs/guides/best-practices/prompt-caching
- https://www.truefoundry.com/blog/provider-agnostic-prompt-caching-llm-gateway

---

## 5. SLA-метрики и автоскейлинг

- **TTFT** — от получения запроса прокси до первого content-чанка клиенту. Ориентир для чата меньше 500 ms.
- **ITL/TPOT** — интервал между токенами. Больше 100 ms уже выглядит как «заикание».
- **E2E** = TTFT + (N − 1) × TPOT. Также считается **TPS** на стрим и суммарно.
- **Goodput** — число запросов в секунду, уложившихся в SLO одновременно по TTFT и TPOT (определение DistServe). Это основная метрика, в отличие от throughput.
- Перцентили p50/p95/p99 строятся по гистограммам. Средние значения не показательны.
- **Proxy overhead.** Измеряются три отрезка: `t_recv → t_upstream_sent` (pre-processing), `t_upstream_first_byte → t_client_first_byte` (stream overhead) и задержка пересылки каждого чанка. Метрика: `proxy_overhead_seconds{phase}`. Внешняя проверка: нагрузка на mock напрямую и через прокси при одинаковой concurrency, разница p50/p99 по TTFT. Ориентиры индустрии: единицы миллисекунд для «голого» пути и 20–40 ms с guardrails (Portkey). Ошибки методологии: сравнение non-streaming со streaming, замер только p50, замер без прогрева.
- Пример SLO (реком.): `p95 TTFT_overhead < 10 ms`, `p99 < 25 ms`, `availability 99.9%` с учётом fallback, `goodput ≥ 99% при 1× нагрузке и ≥ 95% при 3×`. Нужны error budget и burn-rate алерты.
- **Автоскейлинг прокси.** CPU у прокси низкий (I/O-bound), поэтому HPA по CPU вводит в заблуждение. Масштабировать нужно по in-flight стримам на pod (цель — около 50–70% от проверенного нагрузкой максимума), по глубине очереди и по p95 overhead. Инструмент — KEDA Prometheus scaler или HPA с custom metrics. Настройки: scale-up без stabilization, scale-down с окном 300 s и с учётом drain длинных стримов.
- **Автоскейлинг GPU-бэкендов.** Метрики `vllm:num_requests_waiting` (обычно порог 5–10 на pod) и KV-cache utilization. Составной сигнал: `max(queue/queueThr, kv/kvThr)`. Холодный старт GPU занимает минуты, поэтому прокси должен смягчать пики очередью, шеддингом и fallback на внешнего провайдера.

Источники:
- https://haoailab.com/blogs/distserve/
- https://arxiv.org/pdf/2401.09670
- https://bentoml.com/llm/inference-optimization/llm-inference-metrics
- https://docs.anyscale.com/llm/serving/benchmarking/metrics
- https://arxiv.org/pdf/2507.09019
- https://docs.aws.amazon.com/eks/latest/userguide/ml-inference-autoscaling-hpa-keda.html
- https://github.com/llm-d/llm-d/blob/main/guides/workload-autoscaling/README.md
- https://github.com/kornsour/keda-inference-scaler
- https://developers.redhat.com/articles/2025/09/23/how-set-kserve-autoscaling-vllm-keda

---

## 6. Гибкость и адаптация к изменениям

- **Единый вход** — OpenAI-compatible `/v1/chat/completions`, `/v1/embeddings`, `/v1/models`. Опционально `/v1/messages` (Anthropic) как второй диалект. Envoy AI Gateway 1.0 транслирует Anthropic ↔ OpenAI ↔ Bedrock, включая стриминг, tools и thinking, для 16 провайдеров.
- **Внутренняя каноническая модель (IR)**: `Request{model, messages[], tools, params, stream}` и `StreamEvent{type: delta|tool_call_delta|usage|error|done}`. Адаптер описывается интерфейсом:
  ```go
  type Provider interface {
    BuildRequest(ctx, ir) (*http.Request, error)
    ParseStream(io.Reader) <-chan StreamEvent   // инкрементально
    ParseResponse([]byte) (irResp, error)
    MapError(status, body) ErrClass              // retryable / rate_limit / context_length / policy / auth
    Capabilities() Caps                          // tools, json_schema, vision, max_ctx
  }
  ```
  Всего N адаптеров плюс один IR вместо N² транслятор-пар. Для российского контекста важно: у GigaChat есть OpenAI-совместимые адаптеры (`ai-forever/gpt2giga`, `gigachat-adapter`), для YandexGPT существует `YandexGPT_to_OpenAI`. Адаптер GigaChat или YandexGPT хорошо зайдёт у жюри банка. Локальные vLLM и Ollama уже OpenAI-compatible.
- **Middleware-pipeline**: упорядоченный список плагинов с хуками `OnRequest`, `OnUpstreamSelect`, `OnStreamChunk`, `OnResponseEnd`. Включение и параметры задаются конфигом на route или тенанта. В Portkey так устроены guardrails/hooks, в LiteLLM — callbacks и `pre_call/during_call/post_call`.
- **Dynamic config / hot reload**: конфиг хранится как immutable snapshot в `atomic.Pointer[Config]`. Запрос захватывает snapshot в начале и дорабатывает на нём, поэтому «полуприменённого» конфига не бывает. Источники конфига: файл (fsnotify/SIGHUP), Admin API (`PUT /admin/config` с валидацией и dry-run), Redis/etcd (watch/pubsub доставляет его на все реплики). Версионирование: `version`, `checksum`, история и `POST /admin/rollback`. При ошибке валидации остаётся старый конфиг. Метрика `config_version{replica}` показывает, что версии сошлись. В Envoy-мире то же самое делает xDS.
- **Декларативные правила маршрутизации**, по образцу Portkey config:
  ```yaml
  routes:
    - match: {model: "chat-default", tenant: "*", header: {x-tier: premium}}
      strategy: fallback
      targets:
        - strategy: loadbalance
          targets: [{provider: openai, model: gpt-x, weight: 0.9},
                    {provider: vllm-local, model: qwen, weight: 0.1}]   # canary 10%
        - {provider: gigachat, model: GigaChat-Max}
      retry: {attempts: 2, on_status: [429,500,502,503,504]}
      timeouts: {ttft: 8s, idle: 15s, total: 120s}
  ```
  **Virtual model aliases** (`chat-default` → реальная модель) дают возможность менять модель без правки клиентов. Это и есть прямой ответ на «адаптацию к изменениям».
- **Canary и A/B**: взвешенный сплит плюс sticky по `hash(user_id)`, чтобы пользователь не переключался между моделями. Метка `variant` пишется в метрики и логи для сравнения TTFT, стоимости и error-rate. Авто-rollback canary срабатывает по error-rate или p95. Shadow traffic (mirror без ответа клиенту) используется для оценки новой модели.
- **Feature flags** на тенанта и route: cache, semantic cache, hedging, PII, moderation. Переключаются через Admin API без рестарта.

Источники:
- https://aigateway.envoyproxy.io/blog/v1.0-release-announcement/
- https://aigateway.envoyproxy.io/release-notes/v1.0/
- https://agentgateway.dev/models/
- https://portkey.ai/docs/api-reference/inference-api/config-object
- https://github.com/Portkey-AI/gateway
- https://github.com/Portkey-AI/portkey-cookbook/blob/main/product/101-portkey-gateway-configs.md
- https://github.com/ai-forever/gpt2giga
- https://github.com/antonko/gigachat-adapter
- https://github.com/sazonovanton/YandexGPT_to_OpenAI
- https://docs.litellm.ai/docs/routing

---

## 7. Обработка «на лету, без шаблонов»: потоковые трансформации

Интерпретация условия (реком.): прокси не буферизует ответ целиком и не держит жёстких per-provider шаблонов. Он работает как потоковый конвейер над IR-событиями и использует контекст запроса (тенант, история, политика) для решений в реальном времени. Стоит формулировать это именно так.

- **SSE-парсинг и re-emit.** Нужен инкрементальный парсер: строки `data:`, `event:`, пустая строка как разделитель, многострочные data, комментарии `:` (keep-alive), `[DONE]`. `bufio.Scanner` с дефолтным буфером 64 KB читать нельзя, потому что большие tool-call чанки его переполнят. Лимит нужно увеличить или использовать `Reader.ReadBytes`. После каждого события вызывается `Flush()`. Буферизация отключается (`X-Accel-Buffering: no`, без gzip на SSE). Каждые 15 s отправляется heartbeat-комментарий, иначе промежуточные LB закроют соединение по idle.
- **Потоковая трансляция форматов.** События Anthropic (`message_start`, `content_block_delta`, `message_delta(usage)`, `message_stop`) и чанки Gemini преобразуются в IR, а из IR собирается OpenAI `chat.completion.chunk`. Нужен конечный автомат на стрим: индексы tool-call, накопление `arguments`, маппинг `finish_reason`, usage в последнем чанке (`stream_options.include_usage`).
- **Подсчёт токенов на лету.** Вход считается tiktoken-совместимым токенайзером либо грубо `chars/4` (для русского ближе к `chars/2.5–3`). Это нужно для резерва TPM до запроса. Выход считается по дельтам и затем сверяется с `usage` провайдера. При обрыве стрима биллинг идёт по собственному счётчику.
- **Потоковые guardrails и PII.** По бенчмаркам TrueFoundry:
  - regex + checksum/entropy: меньше 2 ms (p99 около 3 ms). Ставится inline всегда.
  - NER-трансформер: около 35 ms (p99 около 70 ms). Inline только там, где важны имена.
  - внешний PII API: около 180 ms (p99 400+ ms). Только для high-compliance.
  - Маскирование входа нельзя распараллелить с вызовом модели, потому что модель должна получить уже очищенный текст. Валидацию (только детект и блокировка) распараллелить можно.
  - Часть gateway-ев, включая TrueFoundry, вообще отключает output-guardrails при `stream: true`. Если сделать это правильно, получится заметное отличие от них.
- **Алгоритмы для выходного потока:**
  1. **Settlement point / hold-back** (`llm-stream-guardrails`): прокси держит «сырой» хвост и выпускает текст только до позиции, после которой ни одно совпадение паттерна уже не может вырасти: «a match touching the end of the buffer is never final». На обычном тексте удерживается несколько символов, максимум 8192. Результат байт-в-байт совпадает с фильтрацией целой строки. Перед детектом текст канонизируется: NBSP, unicode-цифры, гомоглифы.
  2. **Sliding window с overlap** (NeMo Guardrails): `chunk_size` = 200 токенов, `context_size` = 50. При `stream_first: true` текст отдаётся сразу и проверяется после, при нарушении стрим обрывается JSON-ошибкой. При `false` проверка идёт до отдачи, и TTFT растёт на время работы rail. Для банка для PII нужен `false`, а для «мягкой» модерации подойдёт `true`.
  3. **Mask → LLM → rehydrate** (LLM-Shield-Proxy; у Kong AI Sanitizer есть «restoration»). На входе PII заменяется детерминированными плейсхолдерами: `<PERSON_1>` или криптотокенами, генерируемыми по ключу оператора. Это делается stateless, без хранения маппинга между репликами. В выходном стриме плейсхолдеры возвращаются обратно с буферизацией, если плейсхолдер разорван между чанками. Во внешний LLM персональные данные вообще не попадают — это главный аргумент для банка (152-ФЗ, банковская тайна). В замере time-to-first-safe-data составил 0.11 s при длине стрима 2.56 s.
  - Российские сущности: номер карты (Luhn), счёт 20 цифр + БИК (контрольный ключ), ИНН (10 и 12 цифр с контрольными разрядами), СНИЛС (checksum), паспорт РФ, телефон +7, email, ОГРН. Готовый пакет `presidio-ru-recognizers` покрывает ИНН, СНИЛС, ОГРН, паспорт, телефон и расчётный счёт. Для ФИО есть Natasha/Slovnet или spaCy `ru_core_news`, их можно вынести в sidecar. Regex с checksum реализуется нативно в Go/Rust.
  - Реком.: режим задаётся в конфиге на каждую сущность: `mask | block | tokenize+rehydrate | allow`. Метрика `pii_detected_total{entity,direction}` и audit-log без самих значений.
- **Потоковая валидация structured output.** Инкрементальный JSON-парсер (state machine по глубине и строкам) отслеживает корректность на лету. По `[DONE]` проверяется JSON Schema. При невалидном результате делается авто-repair или retry с `response_format`. Поскольку retry после стрима невозможен, в режиме `strict` прокси копит весь ответ и отдаёт его только после проверки. Trade-off задаётся флагом. Оборванный JSON ловится по `finish_reason = length`.
- **Модерация на стриме.** Дешёвые классификаторы или словарь работают по sliding window. «Тяжёлый» LLM-judge запускается асинхронно с правом оборвать стрим (`stream_first`-семантика).
- **Обогащение контекста на лету.** Инъекция system-policy тенанта, даты, RAG-сниппетов. Сжатие и обрезка истории под context window (pre-call check). Авто-выбор модели по длине и сложности запроса. Вставки делаются в конец промпта, чтобы не сбрасывать prompt-cache (раздел 4).

Источники:
- https://www.truefoundry.com/blog/pii-redaction-llm-gateway-vs-application
- https://github.com/roshcompanylabs/llm-stream-guardrails
- https://github.com/ninadphalak/LLM-Shield-Proxy
- https://github.com/BerriAI/litellm/pull/39621
- https://docs.nvidia.com/nemo/guardrails/configure-guardrails/yaml-schema/streaming/output-rail-streaming
- https://developer.nvidia.com/blog/stream-smarter-and-safer-learn-how-nvidia-nemo-guardrails-enhance-llm-output-streaming/
- https://developer.konghq.com/plugins/ai-sanitizer/
- https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2
- https://microsoft.github.io/presidio/supported_entities/
- https://www.piwheels.org/project/presidio-ru-recognizers/
- https://api7.ai/blog/ai-gateway-pii-redaction
- https://qaskills.sh/blog/testing-pii-redaction-in-streaming-llm-output
- https://arxiv.org/pdf/2604.03962

---

## 8. Observability

- **OTel GenAI semconv** (все метрики в статусе Development):
  - метрики: `gen_ai.client.token.usage` (histogram, `{token}`, атрибут `gen_ai.token.type = input|output`), `gen_ai.client.operation.duration`, `gen_ai.client.operation.time_to_first_chunk`, `gen_ai.client.operation.time_per_output_chunk`. Bucket-ы: 0.01, 0.02, 0.04 … 81.92 s.
  - серверные: `gen_ai.server.time_to_first_token`, `gen_ai.server.time_per_output_token`, `gen_ai.server.request.duration`.
  - span-атрибуты: `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens/output_tokens`, `gen_ai.response.finish_reasons`.
  - Контент промптов включается только по opt-in. Для банка он выключен или замаскирован.
- **Собственные Prometheus-метрики прокси** (реком.):
  - `proxy_requests_total{tenant,route,provider,model,status,cache,fallback}`
  - `proxy_ttft_seconds`, `proxy_itl_seconds`, `proxy_e2e_seconds`, `proxy_overhead_seconds{phase}`
  - `proxy_inflight{provider}`, `proxy_queue_depth{priority}`, `proxy_queue_wait_seconds`, `proxy_shed_total{reason}`
  - `proxy_retries_total{reason}`, `proxy_hedges_total{won}`, `proxy_fallback_total{from,to,reason}`
  - `proxy_breaker_state{upstream}` (0/1/2), `proxy_concurrency_limit{upstream}`
  - `proxy_ratelimit_rejected_total{dimension}`, `proxy_cache_hits_total{layer=exact|semantic|coalesced}`, `proxy_provider_cached_tokens_total`
  - `proxy_tokens_total{direction}`, `proxy_cost_usd_total{tenant,model}`, `proxy_pii_detected_total{entity,direction}`, `proxy_config_version`
  - Следить за кардинальностью: `user_id` в лейблы не класть. Тенантов держать до нескольких сотен, остальное уходит в логи.
- **Трейсинг.** W3C `traceparent` принимается и пробрасывается в upstream. Спаны: `gateway.request` → `ratelimit` → `cache.lookup` → `guardrail.input` → `upstream.attempt[n]` (retry, hedge и fallback видны как братские спаны) → `stream`. Событие `first_token` записывается как span event. Sampling: tail-based, сохраняются все ошибки, все медленные запросы и 1–5% остальных.
- **Логи.** Структурированный JSON, одна запись на запрос в конце: `request_id`, tenant, route, цепочка attempts, токены, стоимость, тайминги, статус кеша, PII-счётчики. Без текстов. Запись асинхронная: lock-free ring или ограниченный channel → батч → NATS JetStream/Kafka → ClickHouse (аналитика стоимости и использования) либо Loki. При переполнении буфера логи отбрасываются, запрос не блокируется. Отброшенные записи считает `proxy_log_dropped_total`.
- **Учёт стоимости по запросам.** Таблица цен лежит в конфиге и обновляется hot reload. Стоимость пишется в лог-событие и в Redis-аккумуляторы бюджета. В ClickHouse строится materialized view по тенанту, модели и дню.
- **Дашборд Grafana для демо из 6 панелей:**
  1. RPS и goodput.
  2. TTFT p50/p95/p99, прокси против upstream.
  3. Proxy overhead.
  4. Состояние breaker, fallback-и, retry.
  5. Cache hit rate и сэкономленные доллары.
  6. Токены и стоимость по тенантам плюс 429 и shed.

Источники:
- https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-metrics.md
- https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
- https://opentelemetry.io/blog/2026/genai-observability/
- https://openobserve.ai/blog/opentelemetry-genai-semantic-conventions/
- https://greptime.com/blogs/2026-05-09-opentelemetry-genai-semantic-conventions
- https://www.deepinspect.ai/blog/ai-gateway-latency-benchmarks

---

## 9. Stateless-масштабирование

Что общее, а что локальное:

| Состояние | Где хранится | Консистентность |
|---|---|---|
| Rate limits и бюджеты | Redis (Lua/GCRA) плюс локальная аренда квоты | приближённая, ошибка ≤ batch × N |
| Exact и semantic cache | L1 локально, L2 Redis (+vector) | eventual |
| Config и routing rules | etcd/Redis/файл → snapshot в памяти, pub/sub | версионируется, сходится за секунды |
| Состояние breaker, EWMA-латентности, concurrency-limit | локально на реплику, опционально gossip «open» через pub/sub | независимая. LiteLLM хранит cooldown, latency и tpm/rpm в Redis, но это лишний hop на горячем пути |
| Session affinity / prefix → endpoint | детерминированный хеш (rendezvous), хранить не нужно | одинаковый список endpoint на всех репликах |
| In-flight стримы | локально | не переносятся, поэтому нужен drain |

- **Redis, Dragonfly или KeyDB.** Dragonfly многопоточный и совместим по протоколу. Он полезен, если Redis упирается в одно ядро на Lua. Перед выбором нужно проверить совместимость Lua-скриптов и RediSearch/vector. Для демо достаточно одного Redis. В проде нужен Redis Cluster или Sentinel и отдельные инстансы под лимиты и под кеш, потому что у них разные eviction-политики: `noeviction` и `allkeys-lru`. Все вызовы Redis идут с timeout 5–20 ms и собственным breaker-ом. Если Redis недоступен, прокси продолжает работать на локальных лимитах и L1-кеше.
- **Kubernetes:**
  - Deployment минимум из 3 реплик, `topologySpreadConstraints` по зонам, PDB `maxUnavailable: 1`.
  - readiness: «конфиг загружен и доступен хотя бы один upstream». liveness: только event loop. Liveness не должен зависеть от Redis или upstream.
  - Нужны requests/limits по CPU, потому что throttling портит p99. `GOMAXPROCS` выставляется по limits.
  - HTTP/2 к upstream или большой keep-alive пул, тюнинг `ulimit -n` и conntrack. Один стрим — одно долгоживущее соединение, поэтому планирование идёт по concurrent streams, а не по RPS.
  - L4/L7 LB перед прокси: least-connections. Round robin не подходит, потому что стримы долгие. Idle timeout больше 60 s и heartbeat-ы.
- **Graceful shutdown для долгих стримов:**
  1. `preStop: sleep 5–15 s`, чтобы дождаться распространения удаления из endpoints.
  2. По SIGTERM readiness переключается в fail, новые запросы не принимаются (`Connection: close`, HTTP/2 GOAWAY).
  3. Активные стримы дорабатывают до `drain_timeout` (60–120 s).
  4. Оставшимся отправляется SSE `event: error {"type":"server_shutdown","retryable":true}` и соединение закрывается.
  5. `terminationGracePeriodSeconds = preStop + drain + 10 s`. Для длинных соединений рекомендуют 90–120 s и более.
  - Использовать `http.Server.Shutdown`, а не `Close`. Контексты handler-ов наследуются от root-context.
  - Rolling update: `maxSurge: 25%`, `maxUnavailable: 0`.
- **Multi-region.** Geo-DNS или anycast ведёт на региональный кластер прокси. Rate limits региональные с долей глобальной квоты либо с асинхронной репликацией счётчиков. Кеш региональный. Конфиг глобальный (etcd или git → CD). Fallback-цепочка сначала перебирает провайдеров своего региона, потом кросс-региональных. Для банка РФ действует требование резидентности данных. Поэтому политика маршрутизации должна разделять, какие классы данных можно отправлять во внешний LLM, а какие только on-prem (vLLM, GigaChat, YandexGPT). Решение принимается на лету по результату PII-детекта. Это убедительный сценарий для демо.

Источники:
- https://docs.litellm.ai/docs/routing
- https://learnkube.com/graceful-shutdown
- https://www.cncf.io/blog/2024/12/19/decoding-the-pod-termination-lifecycle-in-kubernetes-a-comprehensive-guide/
- https://www.server-sent-events.com/backend-stream-generation-connection-management/go-streaming-patterns/graceful-shutdown-for-go-sse-servers/
- https://linkerd.io/2.18/tasks/graceful-shutdown/
- https://www.dragonflydb.io/

---

## 10. Нагрузочное тестирование, mock и chaos

- **Инструменты:**
  - **k6 + xk6-sse** (`phymbert/xk6-sse`): обычный k6 буферизует стрим целиком, TTFT без расширения не измерить. **xk6-llm** (`msradam/xk6-llm`) даёт из коробки TTFT, ITL, TPOT, goodput и стоимость с выгрузкой в Prometheus/Grafana. Это лучший выбор для демо. Нужны сценарии `constant-arrival-rate` и `ramping-arrival-rate`: open-loop модель, без coordinated omission.
  - **vegeta**, **oha**, **wrk2** (constant throughput, корректные перцентили): подходят для non-streaming пути, кеш-хитов, 429 и предельного RPS прокси. SSE они не понимают.
  - **Locust**: гибкий (Python), но сам генератор становится узким местом. Нужны FastHttpUser и несколько воркеров.
  - **GuideLLM** (vLLM project): rate sweep, режимы synchronous/concurrent/poisson, отчёты по TTFT, ITL и throughput. **AIPerf** (NVIDIA, преемник genai-perf): arrival-паттерны constant/poisson/gamma, ramping, trace replay, перцентили. **llm-load-test** (OpenShift PSAP), **LLMPerf** (Ray), **llmapibenchmark** (Go).
  - Методология: реалистичное распределение длин промптов и ответов, отдельные прогоны warm/cold/mixed cache, мелкий шаг concurrency около точки насыщения, soak-тест на утечки.
- **Mock LLM upstream.**
  - Готовый вариант — **`llm-d-inference-sim`** (Go, эмулирует vLLM, OpenAI-compatible). Флаги: `--time-to-first-token`, `--inter-token-latency`, `--std-dev` (jitter). Латентность растёт с concurrency, есть `--max-num-seqs`, `--failure-injection-rate`, `--failure-types` (rate_limit, model_not_found, …), `--mode echo|random`. Симулирует KV-cache и P/D-disaggregation. Образ: `ghcr.io/llm-d/llm-d-inference-sim`. Несколько инстансов с разными профилями дают fast, slow и flaky «провайдеров».
  - Свой mock на 100–150 строк Go (реком.). Параметры через query, headers или admin API:
    - `ttft_ms` — lognormal-распределение (μ, σ);
    - `tps`, `output_tokens`;
    - `error_rate` и `error_code`;
    - `stall_after_n_tokens` — зависание посреди стрима;
    - `slow_headers`;
    - `reset_prob`;
    - `429_with_retry_after`;
    - `max_concurrency` — при превышении очередь, рост TTFT или 503;
    - `prefix_cache_sim` — если prefix-hash уже встречался, TTFT делится на 5.
    
    Mock должен отдавать корректный `usage`. Режим echo нужен для проверки PII-маскирования: можно убедиться, что до «провайдера» дошли плейсхолдеры, а не исходные данные. Mock должен быть быстрее прокси: без аллокаций на токен, тайминги через timer wheel или `time.Ticker`. Иначе измеряется mock, а не прокси.
- **Chaos.** **Toxiproxy** (Shopify) ставится между прокси и mock/Redis. Toxics: `latency` (+jitter), `bandwidth`, `timeout` (blackhole), `reset_peer`, `slow_close`, `slicer` (режет пакеты и хорошо проверяет SSE-парсер и PII на границах чанков), `limit_data`. Управляется по HTTP API на порту 8474, поэтому сценарии можно запускать скриптом по таймлайну во время нагрузки. Дополнительно: остановить pod прокси во время стримов (проверка drain), остановить Redis (fail-open), подать невалидный конфиг (остаётся старый).
- **Сценарий демо для судей, 5–7 минут под постоянной нагрузкой k6 с открытой Grafana:**
  1. Базовая линия: X RPS, overhead p99 меньше N ms. Сравнение напрямую и через прокси.
  2. Остановить провайдера A. Breaker открывается за секунды, включается fallback на B, goodput почти не меняется, ошибок у клиента нет.
  3. Провайдер замедляется (toxiproxy latency). Hedging и Peak-EWMA уводят трафик, p99 TTFT остаётся в SLO.
  4. Нагрузка ×3–×5. Adaptive concurrency и shedding сбрасывают sheddable-класс с 429, critical держит SLO. KEDA/HPA добавляет реплики, 429 исчезают.
  5. Hot reload: по API меняется вес canary с 10% до 50% и алиас модели, без рестарта и обрыва стримов. Затем rollback.
  6. PII: запрос с номером карты, ИНН и ФИО. В логе mock-провайдера видны плейсхолдеры, у клиента восстановленный ответ, стрим не задержан. Метрика `pii_detected` растёт.
  7. Кеш и singleflight: 100 одинаковых одновременных запросов дают один upstream-вызов. Показать экономию в долларах.
  8. Rolling restart под нагрузкой: ни одного оборванного стрима.
  9. Rate limit: тенант исчерпал TPM и получает 429 с `Retry-After`, соседний тенант не затронут.

Источники:
- https://github.com/phymbert/xk6-sse
- https://github.com/msradam/xk6-llm
- https://tianpan.co/blog/2026-03-19-load-testing-llm-applications
- https://gatling.io/blog/load-testing-an-llm-api
- https://github.com/vllm-project/guidellm
- https://developer.nvidia.com/blog/benchmarking-llm-inference-at-scale-with-aiperf/
- https://docs.nvidia.com/aiperf/getting-started/ai-perf-comprehensive-llm-benchmarking
- https://github.com/ray-project/llmperf
- https://github.com/Yoosu-L/llmapibenchmark
- https://github.com/llm-d/llm-d-inference-sim
- https://github.com/Shopify/toxiproxy
- https://www.server-sent-events.com/backend-stream-generation-connection-management/testing-and-load-testing-sse-endpoints/chaos-testing-sse-through-proxies/
- https://blog.premai.io/load-testing-llms-tools-metrics-realistic-traffic-simulation-2026/

---

## 11. Шпаргалка дефолтов

```yaml
timeouts:        {connect: 2s, ttft: 8s, idle_between_tokens: 15s, total: 120s, queue_wait: 5s (interactive) / 30s (batch)}
retry:           {max_attempts: 2, backoff: full_jitter, base: 100ms, cap: 2s, on: [408,429,500,502,503,504,529,conn,ttft_timeout],
                  only_before_first_byte: true, budget: 20% of active (min 3), respect_retry_after: true}
hedging:         {enabled_for: [interactive], delay: p95_ttft(model), max_rate: 5-10%, cancel_loser: true}
circuit_breaker: {consecutive_failures: 5, or_error_rate: 50% over 20+ req / 30s window, open: 30s (x2 backoff, max 5m),
                  half_open_probes: 3, close_after_successes: 2, count_ttft_timeouts: true, 429: separate cooldown}
outlier:         {interval: 10s, base_ejection: 30s, max_ejection_percent: 50 (при малом числе upstream), panic_threshold: да}
health_check:    {interval: 10-30s, timeout: 2-10s, unhealthy: 3, healthy: 2}
concurrency:     {algo: gradient|aimd, signal: ttft, min: 10, initial: 100, aimd_backoff: 0.9, per_upstream: true}
queue:           {size: 128-1024, priorities: [critical, standard, sheddable], shed: oldest-first / deadline-aware}
lb:              {external: weighted + p2c_peak_ewma(ttft, decay 10s), self_hosted: prefix_hash + bounded_load(1.25) → least_pending_tokens}
rate_limit:      {algo: gcra, dims: [rpm, tpm], reserve: prompt+max_tokens, settle: on usage, local_lease: 5-10% / 100ms, redis_timeout: 10ms, on_redis_fail: local limit/N}
cache:           {exact: {l1: 10k entries, l2_ttl: 1h, only_if: temperature==0 || opt-in}, semantic: {threshold: 0.95-0.97, scope: tenant+system_prompt+model}, singleflight: on}
stream:          {heartbeat: 15s, per_stream_buffer: 256KB, write_deadline: 30s, pii_holdback: adaptive (settlement point, ≤8KB)}
shutdown:        {preStop: 10s, drain: 90s, terminationGracePeriod: 110s}
```

---

## 12. Приоритизированный MVP

**Первые 4 часа: работающий скелет и измеримость.**
1. Прокси на Go или Rust: `/v1/chat/completions` (stream и non-stream), SSE pass-through с flush, отмена upstream при отключении клиента.
2. Адаптер OpenAI-compatible (покрывает vLLM, Ollama и mock) и YAML-конфиг с алиасами моделей.
3. Mock-upstream с настраиваемыми TTFT, TPS и error-rate (или `llm-d-inference-sim`), всё в docker-compose.
4. Таймауты connect/TTFT/idle/total, retry с full jitter (только до первого байта), простая fallback-цепочка.
5. Prometheus-метрики (TTFT, ITL, e2e, overhead, in-flight, счётчики ошибок) и готовый Grafana-дашборд в compose.
6. Скрипт k6 (xk6-sse или xk6-llm) с constant-arrival-rate, чтобы базовая цифра overhead появилась как можно раньше.

**К 12 часам: устойчивость и high-load, главные критерии условия.**
7. Circuit breaker на upstream и passive outlier detection, балансировка P2C + Peak-EWMA/least-inflight, active health checks.
8. Rate limiting RPM + TPM (GCRA в Redis Lua, reserve/settle), локальная аренда квоты, заголовки `x-ratelimit-*` и `Retry-After`.
9. Admission control: ограниченная очередь с приоритетами, load shedding, adaptive concurrency (AIMD проще, Gradient эффектнее), bulkhead на провайдера.
10. Exact-cache (L1 + Redis) с replay в SSE и singleflight.
11. Hot reload конфига (fsnotify + Admin API, atomic snapshot, версия, rollback), weighted/canary routing.
12. Graceful shutdown с drain стримов. Запуск в 2–3 реплики за nginx, HAProxy или в k8s.
13. Второй адаптер с реальной трансляцией формата: Anthropic или GigaChat/YandexGPT. Это доказывает работу IR и стриминговой трансляции.
14. Сценарии Toxiproxy и скрипт демо-таймлайна.

**К 24 часам: отличия от других команд и подготовка демо.**
15. Потоковое PII-маскирование: regex + checksum для карты, ИНН, СНИЛС, счёта, телефона, email; mask → rehydrate с hold-back на границах чанков; policy-routing «есть PII → только on-prem модель». Для банковского жюри это главная фича. Если команда сильная, её стоит поднять в блок 12 часов.
16. Hedged requests с лимитом 5–10%. Деградация на меньшую модель с заголовком-индикатором.
17. Prefix-aware/sticky routing: consistent hash префикса и симуляция prefix-cache в mock. Авто-расстановка `cache_control` для Anthropic. Метрика cached tokens.
18. Semantic cache на Redis vector или Qdrant с локальной embedding-моделью. Флаг включения на route, порог 0.95+.
19. OTel-трейсы с GenAI-атрибутами (attempts, hedge и fallback как спаны). Асинхронный пайплайн usage/cost → NATS/Kafka → ClickHouse, панель стоимости по тенантам, бюджеты.
20. k8s-манифесты: HPA/KEDA по in-flight и глубине очереди, PDB, preStop. Демо автоскейла при нагрузке ×5.
21. Потоковая валидация JSON/structured output (strict-режим).
22. README с архитектурной схемой, таблицей SLO и результатами нагрузочных тестов: графики goodput против RPS, overhead p50/p99, поведение при отказах, план роста ×10 (что и как масштабируется, где узкие места: Redis, соединения, генератор нагрузки).

**Чем жертвовать при нехватке времени:** сначала semantic cache, ClickHouse и multi-region — их достаточно описать в README, потом JSON-валидацией. Пункты 1–12 и 15 с хорошим дашбордом и chaos-демо закрывают все четыре критерия условия (SLA, отказоустойчивость, гибкость, масштаб).
