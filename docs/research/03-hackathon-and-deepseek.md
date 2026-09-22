# Отчёт: хакатон Альфа-Банка по LLM-прокси и DeepSeek V4 Flash как coding-агент

Хакатон найден точно. Это «АЛЬФА ВААА{АИ}ЙЙЙБ ХАКАТОН» Альфа-Банка на платформе AlfaGen. Он стартует завтра: с 22.09.2026 9:00 мск до 23.09.2026 23:59 мск.

Формулировка задачи на официальной странице дословно совпадает с вашей. Критерии оценки, стек и обязательность DeepSeek V4 Flash публично не раскрыты. Их обещают дать на брифинге 22 сентября.

## ЧАСТЬ A. Хакатон

### A1. Проверенные факты

Официальная страница: https://alfabank.ru/alfadigital/vibecoding-hackathon/. WebFetch получает 403, поэтому я читал её через браузер.

- **Название:** АЛЬФА ВААА{АИ}ЙЙЙБ ХАКАТОН.
- **Регистрация:** закрыта, шла с 17.08 по 15.09. Остальные даты — в расписании ниже.
- **Формат:** кейс решается онлайн, команда может собираться офлайн.
- **Аудитория:** «разработчики, продакты, дизайнеры и все, кто интересуется вайб-кодингом». В прессе событие описано как хакатон для разработчиков и техлидов бигтеха, то есть внешних участников.
- **Команда:** от 1 до 4 человек.
- **Задача:** одна, без треков — «Высоконагруженный прокси для LLM». Текст на странице совпадает с вашим дословно: данные «на лету, без шаблонов, с полным погружением в контекст»; архитектура (SLA по времени отклика, отказоустойчивость, масштабируемость); гибкость; масштаб (кратный рост нагрузки).
- **Призы:** 1 000 000, 800 000 и 500 000 ₽, общий фонд 2,3 млн ₽.
- **Результат:** «рабочий прототип на вайб-кодинг платформе AlfaGen» и презентация. Дословно: «Жюри проверит проекты и оценит презентации участников».
- **Жюри:** «победители хакатонов, участники команд разработки с вайб-кодингом, эксперты в вайб-кодинге из бигтеха».
- **Инфраструктура:** «настроенная вайб-кодинг среда». Специально к хакатону в AlfaGen сделали «витрину ИИ-продуктов для внешних пользователей».
- **Поддержка:** Telegram-чат хакатона и Q&A-сессия с экспертами по промптам и AlfaGen перед стартом.

Расписание:

| Дата | Событие |
|---|---|
| 22.09 | Брифинг: «знакомим с подробностями кейса» |
| 22–23.09 | Решение кейса |
| 24–28.09 | Проверка проектов и презентаций жюри |
| 30.09, 18:00 мск | Награждение на АЛЬФА ВААА{АИ}ЙЙЙБ МИТАПЕ, Москва, «Альфа Кристалл», ул. Самокатная, 4, стр. 11, с онлайн-трансляцией |

Источники:
- https://bankinform.ru/news/142813
- https://news.rambler.ru/tech/56943229-alfa-bank-provedet-hakaton-po-vayb-kodingu-dlya-razrabotchikov-i-tehlidov/
- https://habr.com/ru/companies/alfa/news/1076724/
- https://habr.com/ru/companies/alfa/posts/1076726/

### A2. Что подтвердить не удалось

- **Обязательность DeepSeek V4 Flash.** Публичного подтверждения, что код должен писать именно этот агент, нет. Известно только, что AlfaGen даёт «доступ к топовым моделям» в закрытом контуре банка. В Хабр-статье Альфы упомянуты тесты DeepSeek V3, Qwen, GLM-5 и MiniMax, а V4 Flash не назван.
- **Чекпойнт модели.** Неизвестно, какой именно развёрнут (0423-preview, 0731 или V4.1), какой харнесс или плагин используется и включён ли thinking. Это критично, разница между чекпойнтами описана в части B. Стоит спросить на брифинге.
- **Критерии оценки, стек, нагрузочный тест.** Формальные критерии и разрешённый стек не опубликованы. Неизвестно, будут ли нагрузочный тест и автопроверка, какие целевые RPS и p99, как сдавать решение (репозиторий или деплой) и какой upstream: реальная модель или mock.
- **Проверка авторства.** Неясно, проверяют ли логи агента, чтобы убедиться, что код написан ИИ. Косвенный признак есть: на внутреннем апрельском хакатоне считали запросы к платформе, то есть телеметрия у AlfaGen имеется.

### A3. Прошлые хакатоны Альфы по вайб-кодингу

**AI-хакатон ДРБС & AlfaGen (апрель 2026, внутренний)**

- Участвовали 280 человек в 81 команде, длительность 24 часа.
- Задача — автоматизация пакетной обработки финансовых операций: разнородные данные, валидация, корректировка, передача в банковские системы.
- Первый этап оценки был автоматическим: решения проверяли LLM-инструменты во внутреннем контуре по единым критериям.
- Метрики платформы: 96 тыс. запросов (около 340 на человека), пик 20 тыс. токенов в секунду, сгенерировано 1,6 млн строк кода.
- Источники: https://www.vedomosti.ru/press_releases/2026/04/29/alfa-bank-provyol-ai-hakaton-po-vaibkodingu-na-baze-platformi-alfagen и https://habr.com/ru/companies/alfa/articles/1039050/

**Hackathon Vibecoding (23–24 июня 2026, внутренний)**

- Сайт: https://alfa-vibecoding.ru/
- Три трека: B2B Spotlight AI-сценарии, B2C on-device LLM, MCP-совместимый API над Альфа-Инвестициями.
- Критерии жюри: «продуктовая логика, дизайн, возможность интеграции с банковскими системами, ИИ-сценарии».
- Фонд 1,25 млн ₽. Разборов решений победителей в открытом доступе нет.

**Хакатон «Альфа-Будущее» (ноябрь 2025, студенческий)**

- Задачи: RAG по базе знаний и copilot для малого бизнеса. К вашему кейсу это не относится.
- Источник: https://habr.com/ru/companies/alfa/news/962402/

**Культура EVC (Enterprise Vibe Coding) в Альфе, по Хабр-статье**

- До первой строчки кода пишется структурированное ТЗ.
- Принята семантическая XML-разметка промптов. Дословно: «если контекст > 4000 токенов — всегда XML». В статье заявлены экономия токенов больше 50% и рост точности на 60–70%.
- Есть cookbook и маркетплейс плагинов.
- Вывод: жюри, скорее всего, оценит видимый spec-driven процесс (спеки, AGENTS.md, промпты в репозитории), а не только код.

### A4. Аналогичные задачи у других компаний

Публичных хакатонных кейсов «LLM proxy / LLM gateway» с критериями оценки я не нашёл ни у одной из названных компаний (Сбер, Т-Банк, Яндекс, МТС, VK, Авито). Это отрицательный результат поиска, а не доказательство, что таких кейсов не было.

Ближайшие референсы по содержанию — отраслевые описания LLM-gateway:
- LiteLLM-proxy поверх vLLM, роутинг, квоты, DLP: https://itglobal.com/ru-ru/company/blog/kak-vnedrit-trehurovnevuyu-arhitekturu-llm-inferensa-shlyuz-routing-i-infrastruktura-chast-2/
- AI Gateway для микросервисов: https://habr.com/ru/companies/otus/articles/1031276/
- Динамическая анонимизация перед внешними LLM (Just AI): https://habr.com/ru/companies/just_ai/articles/946392/
- Шлюз маскировки персональных данных (pii-mask): https://github.com/dewil/pii-mask
- GigaChat-proxy с лимитами RPS и потоков: https://llmstudio.ru/blog/llm-proxy-with-control-rps-and-threads

### A5. Моя интерпретация задачи (предположения, не факты)

Фраза «данные обрабатывались на лету — без шаблонов, с полным погружением в контекст» допускает три прочтения:
- Потоковая обработка SSE-ответов и запросов (трансформация, маскирование, guardrails) без regex-шаблонов, контекстно-зависимо. Например, маскирование PII и банковских данных с помощью NER или LLM, а не регулярками.
- Семантический роутинг и обогащение запросов вместо prompt-шаблонов.
- Оба варианта сразу.

Банковский контекст делает DLP и маскирование вероятным: закрытый контур, система Agent Risk Management и модули контроля контента описаны в https://www.kommersant.ru/doc/8689448.

Ожидаемый каркас решения:
- OpenAI-совместимый streaming-прокси;
- пул upstream-ов, балансировка, retries, hedging, circuit breaker, таймауты и дедлайны;
- rate-limit и квоты, очереди и backpressure;
- кеш (точный и семантический);
- метрики Prometheus и Grafana, трассировка;
- горизонтальное масштабирование (stateless-узлы плюс Redis), конфигурация с hot-reload для пункта «гибкость»;
- k8s и HPA;
- нагрузочный тест (k6, vegeta) с отчётом по p50, p95 и p99;
- демонстрация отказа upstream-а (chaos-демо).

### A6. Стек Альфа-Банка

Подтверждено:
- Основной backend — Java и Kotlin, Spring Boot, WebFlux и Reactor, Kafka.
- Базы и поиск: PostgreSQL, MongoDB, Elastic.
- Инфраструктура и мониторинг: Docker, Kubernetes, Micrometer, Prometheus, Grafana.
- Остальное: Node.js и TypeScript на фронте и в BFF, Python для ML.
- Go используется в облачной и инфраструктурной разработке: есть вакансии «Старший Golang-разработчик» с REST/gRPC, контейнеризацией и CI/CD.
- Rust в вакансиях и статьях не встретился.

Источники:
- https://vc.ru/alfabank/134703-6-mifov-o-razrabotke-v-bankah-i-pochemu-v-alfe-vse-po-drugomu
- https://hh.ru/article/31696
- https://digital.alfabank.ru/vacancies/starshii-golang-razrabotchik--200693
- https://digital.alfabank.ru/vacancies/baza-am--168187
- Статья Альфы про нагрузочное тестирование: https://habr.com/ru/companies/alfa/articles/1018996/

Вывод (предположение): Go — компромисс для сетевого прокси.
- Он знаком жюри и подходит для highload.
- Agent-бенчмарки SWE-bench Multilingual и SWE-bench Pro включают Go.
- Kotlin с WebFlux ближе всего к жюри, но тяжелее по latency и сложнее для агента.
- Rust рискован с двух сторон: незнаком жюри и тяжелее для слабой модели.

## ЧАСТЬ B. DeepSeek V4 Flash как coding-агент

### B1. Релизы

| Дата | Событие | Источник |
|---|---|---|
| 24.04.2026 | V4 Preview: V4-Pro (1.6T параметров, 49B активных) и V4-Flash (284B, 13B активных, MoE). Контекст 1M, лицензия MIT, open weights. Эксперты MoE в FP4, остальное в FP8 | https://api-docs.deepseek.com/news/news260424/, https://huggingface.co/deepseek-ai/DeepSeek-V4-Flash |
| 31.07.2026 | V4-Flash-0731, официальный релиз. Архитектура та же, post-training переработан под агентность, встроен DSpark (speculative decoding). Веса открыты под MIT, 167 ГБ | https://huggingface.co/deepseek-ai/DeepSeek-V4-Flash-0731, https://recipes.vllm.ai/deepseek-ai/DeepSeek-V4-Flash |
| 13.08.2026 | V4-Pro-0813 (GA) | — |
| 16.08.2026 | Введён peak/off-peak прайсинг | — |
| 10.09.2026 | V4.1-Flash: 552B параметров, vision, open weights. Новый API id `deepseek-flash`. Старые `deepseek-v4-flash` принимаются временно, но обслуживаются и тарифицируются как V4.1 | https://www.aipricing.guru/news/deepseek-v4-1-flash-api-pricing-september-2026/, https://www.deepseek.com/en/news/deepseek-v4-1-flash/ |

Цифры активных параметров V4.1 взяты из вторичного источника, на странице DeepSeek я их не проверял.

Важно: «V4 Flash» в контуре AlfaGen — это self-hosted веса, и версия может быть любой из трёх. Через публичный API сегодня фактически отвечает V4.1.

### B2. API

Источники:
- https://api-docs.deepseek.com/quick_start/pricing/
- https://api-docs.deepseek.com/guides/thinking_mode
- https://api-docs.deepseek.com/guides/anthropic_api

Параметры:
- **Endpoints:** OpenAI-совместимый `https://api.deepseek.com`, Anthropic-совместимый `https://api.deepseek.com/anthropic`. Заявлена поддержка Responses API.
- **Контекст:** 1M токенов, максимальный вывод 384K.
- **Возможности:** JSON output, tool calls (включая strict), chat prefix. FIM работает только в non-thinking.
- **Concurrency:** Flash 2500, Pro 500.
- **Текущие цены `deepseek-flash`** (off-peak, peak вдвое дороже): cache-hit $0.003, cache-miss $0.15, output $0.60 за 1M токенов. Peak действует 01–04 и 06–10 UTC по будням.
- **Цены V4-Flash до V4.1:** разные источники дают $0.14/$0.28 и $0.22/$0.66. Значение зависит от даты, так что это расхождение, а не ошибка.
- **Thinking:** включён по умолчанию, effort по умолчанию `high`.
  - В OpenAI-формате: `extra_body={"thinking":{"type":"enabled|disabled"}}` плюс `reasoning_effort` со значениями `low|high|max`.
  - В Anthropic-формате `budget_tokens` игнорируется, thinking отключается значением `effort: none`.
  - В thinking-режиме игнорируются `temperature`, `presence_penalty` и `frequency_penalty`, а `top_p` не может быть ниже 0.95.
  - Для self-host рекомендованы temperature=1.0 и top_p=1.0, а для Think Max — окно не меньше 384K.
- **Ключевая ловушка:** при запросах с `tools` поле `reasoning_content` нужно возвращать API во всех последующих ходах, иначе приходит HTTP 400. По данным codersera, это ломает многие клиенты.

### B3. Бенчмарки

Модельная карта V4-Flash (preview), режимы Non-think / High / Max:

| Бенчмарк | Non-think | High | Max |
|---|---|---|---|
| SWE-bench Verified | 73.7 | 78.6 | 79.0 |
| SWE-bench Pro | 49.1 | 52.3 | 52.6 |
| SWE Multilingual | 69.7 | 70.2 | 73.3 |
| Terminal-Bench 2.0 | 49.1 | 56.6 | 56.9 |
| LiveCodeBench | 55.2 | 88.4 | 91.6 |
| Codeforces | — | 2816 | 3052 |
| MRCR 1M | 37.5 | 76.9 | 78.7 |

- Non-think резко проседает на длинном контексте и на LiveCodeBench, поэтому для агентной работы нужен thinking.
- У Pro-Max SWE-bench Verified 80.6, LiveCodeBench 93.5, Terminal-Bench 2.0 — 67.9.

Агентные бенчмарки: Flash-0731 против Flash-preview и Pro-preview:

| Бенчмарк | Flash-0731 | Flash-preview | Pro-preview |
|---|---|---|---|
| Terminal-Bench 2.1 | 82.7 | 61.8 | 72.1 |
| DeepSWE | 54.4 | 7.3 | 12.8 |
| NL2Repo | 54.2 | 39.4 | 38.5 |
| Toolathlon | 70.3 | 49.7 | 55.9 |
| DSBench-FullStack | 68.7 | 37.0 | — |

- По источнику, среднее по девяти агентным бенчмаркам: 55.2 у 0731 против 29.6 у preview. Если в AlfaGen развёрнут 0423-preview, агентное качество будет заметно ниже.
- Эти цифры взяты из вторичного источника: https://www.cometapi.com/deepseek-v4-flash-0731-deepseek-harness-guide-to-the-agentic-coding-breakthrough-2026/.
- На benchlm.ai для Terminal-Bench 2.1 указано 67.0, цифры между агрегаторами расходятся.

V4.1-Flash: DeepSWE 74.2, Terminal-Bench 2.1 — 90.6 (https://www.mindstudio.ai/blog/deepseek-v4-1-flash-benchmarks).

Artificial Analysis для 0731: около 238 токенов в секунду, TTFT 1.13 с, модель «very verbose» (240M токенов на индекс при медиане 140M). Значение самого индекса в источниках расходится: 34 и 50 (https://artificialanalysis.ai/models/deepseek-v4-flash).

Не найдены:
- Aider polyglot для V4 Flash.
- Разбивка качества по языкам для Flash. Ближайшее — SWE Multilingual 73.3 против Verified 79.0, то есть не-Python-языки проседают примерно на 6 п.п.
- По общим данным Multi-SWE-bench порядок такой: Python, затем Java, затем Go и Rust, затем TS и JS. Go и Rust описаны как «нестабильные от модели к модели» (https://arxiv.org/pdf/2504.02605).
- Поисковая выдача приписывает V4 Pro провал на TypeScript (36.1%) и техотчёту V4 — внутренние Rust/C++ нагрузки. Источники этих утверждений я не открывал и не проверял.
- Отзывов сообщества именно про Go- и Rust-сетевые сервисы на V4 Flash я не нашёл.

### B4. Харнессы и настройка

**Claude Code** (официальный гайд: https://api-docs.deepseek.com/quick_start/agent_integrations/claude_code/). Блок ниже — под Windows (PowerShell); на Linux/Mac те же переменные задаются через `export`.

```
$env:ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"
$env:ANTHROPIC_AUTH_TOKEN="<key>"
$env:ANTHROPIC_MODEL="deepseek-flash[1m]"
$env:ANTHROPIC_DEFAULT_OPUS_MODEL="deepseek-flash[1m]"
$env:ANTHROPIC_DEFAULT_SONNET_MODEL="deepseek-flash[1m]"
$env:ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash"
$env:CLAUDE_CODE_SUBAGENT_MODEL="deepseek-flash"
$env:CLAUDE_CODE_EFFORT_LEVEL="max"
$env:CLAUDE_CODE_AUTO_COMPACT_WINDOW="786432"
```

- `ANTHROPIC_API_KEY` нужно снять, чтобы не конфликтовал. Ключ указывается без префикса `Bearer`.
- Маппинг имён: `claude-opus*` уходит в v4-pro, всё остальное — в flash.
- Команда `/cost` показывает неверные суммы.

**OpenCode** версии не ниже v1.18.30: команда `/connect deepseek` и выбор DeepSeek-V4-Flash. В `opencode.jsonc` задаётся `"reasoningEffort":"max"`.
- https://api-docs.deepseek.com/quick_start/agent_integrations/opencode/
- https://www.orcarouter.ai/blog/deepseek-v4-1-flash-opencode

**Остальные агенты** (https://devtk.ai/en/blog/deepseek-v4-agent-setup-2026/):
- Codex CLI: `~/.codex/config.toml`, OpenAI-endpoint, `wire_api="chat"`.
- Cline, Kilo, Roo: OpenAI-compatible provider, контекст 1048576, изображения отключить.
- Copilot CLI: лучше режим `COPILOT_PROVIDER_TYPE=anthropic` из-за thinking.
- Официально DeepSeek упоминает Claude Code, OpenClaw и OpenCode. Собственный «DeepSeek Harness» анонсирован, полный релиз на август ожидался.

**Сравнение харнессов на V4 Flash** (Хабр, Koda, 261 задача, включая SWE Multilingual с Java, Go и TS):

| Харнесс | Max | Medium |
|---|---|---|
| Koda | 52.2% | 46.3% |
| KiloCode | 49.5% | 44.9% |
| Claude Code | 48.2% | 46.9% |
| OpenCode | 47.6% | 43.4% |

- Источник: https://habr.com/ru/companies/koda/articles/1083546/. Автор исследования — вендор Koda, возможна предвзятость.
- Разброс между харнессами 3–5 п.п. Выигрыш от effort Max составляет от 1 до 6 п.п. в зависимости от харнесса.
- Другой автор на Хабре предпочитает лёгкий Pi-harness: около 3K токенов оверхеда на запрос против 18K у Codex и 30K у Claude Code. По его данным, V4.1-Flash даёт около 300 токенов в секунду (https://habr.com/ru/articles/1083368/).
- Aider, Crush, Qwen Code: проверенных данных по работе с V4 Flash я не нашёл.

### B5. Известные слабости

- **Деградация tool calling на большом контексте.** При контексте около 50K токенов и 48 инструментах Flash выдал HTML-текст, имитирующий виджет вызова, вместо `tool_calls`. Pro на том же запросе справился. Лечится сокращением набора инструментов (в том числе лишних MCP) и `tool_choice: required`. Источник: https://github.com/xzxiong/ai-coding/issues/1.
- **Проблемы self-host: DSML-формат tool-calls.** Это первый кандидат, если агент в AlfaGen «теряет» вызовы. Источники: https://www.aifreeapi.com/en/posts/deepseek-v4-tool-calling-local-agent-troubleshooting и форум NVIDIA про NIM: https://forums.developer.nvidia.com/t/368085.
  - Теги `<｜DSML｜tool_calls>` при неверном парсере vLLM или SGLang утекают в `content`.
  - Чаще всего это случается при сочетании `auto` и stream (vLLM #40801).
  - Квантизация влияет на корректность выдачи разделителей.
- **Потеря `reasoning_content` клиентом** даёт HTTP 400 (см. B2).
- **Длинные цепочки действий.** По вторичным источникам, Agents' Last Exam — 25.2 против 50.4 у лидера, с кем именно сравнивают, не уточнено. Рекомендация: при 10 и более связанных tool-calls эскалировать на Pro. Flash «жертвует соблюдением ограничений ради прогресса»: ослабляет пошаговый контроль, формат и границы, правит несвязанные файлы, зацикливается на одном падающем тесте. Формула из обзора: «Flash executes. It doesn't plan». Источники: https://www.siliconflow.com/blog/deepseek-v4-flash-coding-agent-routing и https://avinashsangle.com/blog/deepseek-v4-flash-agentic-coding-guide.
- **Галлюцинации фактов.** По AA-Omniscience доля галлюцинаций около 96%: модель почти всегда отвечает, даже когда не знает. Для кода это означает выдуманные API библиотек и версий. Цифра из вторичного источника.
- **Многословность** и высокий расход токенов. Non-think резко слабее на длинном контексте (MRCR 37.5 против 78.7).
- **Rust и borrow checker.** Конкретных отчётов по V4 Flash я не нашёл. Общий вывод из Multi-SWE-bench: системные языки даются моделям хуже и нестабильнее.

### B6. Практики работы с моделью

Это синтез источников и EVC-подхода Альфы. Частично это мои выводы.

1. **Спека до кода.** Репозиторий начинается с `SPEC.md` или `ARCHITECTURE.md` и `AGENTS.md` (или `CLAUDE.md`). В них: команды build, test и lint, структура каталогов, запреты вроде «не трогать X» и «не добавлять зависимости без запроса». Для длинных промптов подойдёт XML-разметка — жюри Альфы это ценит.
2. **Планирование отдельно от исполнения.** План и декомпозицию делает человек, либо модель на effort Max или Pro (если доступен) в отдельной сессии. Flash получает мелкие задачи по 1–3 файла с явным критерием приёмки, например «`go test ./proxy/...` зелёный».
3. **Test-first и короткая петля.** Порядок: inspect → patch → `go vet`, `golangci-lint`, `go test -race` → review. Попытки ремонта ограничить: после двух-трёх неудач сбрасывать контекст или переформулировать задачу.
4. **Защита от выдуманных API.**
   - Закрепить версии в `go.mod`.
   - Положить в `docs/` выдержки API нужных библиотек.
   - Предпочитать stdlib: `net/http`, `httputil.ReverseProxy`, `context`, `x/time/rate`, `errgroup`.
   - Поверх stdlib — минимум популярных библиотек: `prometheus/client_golang`, `go-redis`, `sony/gobreaker`.
   - Правило в AGENTS.md: «перед использованием API открой исходник в module cache или `go doc`».
5. **Короткий контекст.** Нужны частые новые сессии, небольшой набор инструментов и MCP, стабильный префикс промпта (это повышает cache-hit). Thinking включён, effort не ниже high.
6. **Страховка от over-editing.** Коммит после каждого зелёного шага, `git diff --stat` для ревью и указание «меняй только файлы X и Y».
7. **Артефакты процесса в репозитории.** Спеки, промпты, лог сессий, отчёт нагрузочного теста, ADR. Это показывает жюри сам процесс вайб-кодинга.

### B7. Flash против Pro и конкурентов

- Flash-0731 опережает Pro-preview на агентных бенчмарках с коротким горизонтом.
- Flash уступает Pro-0813 на знаниях, сложном reasoning и длинных цепочках. Он в три и более раз дешевле и быстрее.
- На Хабре Flash сравнивают с GLM 5.3 Flash и Qwen 3.8 27B. В тесте Koda GLM 5.3 Flash Max набрал 49.2% — примерно как Flash с большинством харнессов.
- Источники: https://habr.com/ru/companies/koda/articles/1083546/, https://habr.com/ru/articles/1080316/, https://www.orcarouter.ai/blog/deepseek-v4-flash-vs-kimi-k3.
- Треды Reddit и HN напрямую не открывал.

## Сводка непроверенного

1. Обязательность DeepSeek V4 Flash, версия чекпойнта и харнесс в AlfaGen.
2. Критерии оценки, разрешённый стек, наличие нагрузочной автопроверки, формат сдачи.
3. Смысл фразы «без шаблонов» в задаче (моя интерпретация — в A5).
4. Aider polyglot и разбивка по языкам для V4 Flash; отзывы сообщества про Go- и Rust-сервисы.
5. Хакатонные кейсы «LLM gateway» у других компаний не найдены.
6. Часть цифр (0731, V4.1, AA-индекс, Omniscience, цены) взята из вторичных агрегаторов и расходится между источниками. Первичны только api-docs.deepseek.com, карточки HuggingFace и страница Альфа-Банка.
