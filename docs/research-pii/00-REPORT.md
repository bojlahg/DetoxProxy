# DetoxProxy Research Report

## 1. Executive summary

Базовая связка — **специализированный RMR ruBERT (`rubert-base-pii-ner`) + deterministic rules с контрольными суммами** (архитектура официального `redmadrobot-rnd/pii-guard`, Apache-2.0, разобрана по коду — см. `docs/pii_guard_analysis.md`). Официальные метрики на `pii_benchmark` (exact, 14 категорий): модель одна P81.9/R85.5/**F1 83.6**, пайплайн правила+модель P90.4/R87.5/**F1 88.9**; на протоколе leaderboard (PERSON+LOCATION, overlap) модель **94.7**, пайплайн **95.0**. Generic Slovnet/GLiNER теперь вторичны: zero-shot GLiNER ~70 F1 не покрывает русские документ-типы, а Slovnet — лёгкая CPU-альтернатива без измеренного качества на PII-документах. Latency ≤0.5s при 1000–2000 RPS для BERT-связки не доказана — нужны реальные замеры (CPU 10–100ms/запрос по данным upstream против LLM 2–5s); пока они не проведены, держим Slovnet как fallback и правила как обязательное ядро.

## 2. Самые полезные внешние проекты

- `redmadrobot-rnd/pii-guard` (Apache-2.0, клон в `references/pii_guard/upstream/`) — двухветочная схема правила (16 типов) + ruBERT, дистанционные бюджеты контекста, pairwise-конфликты, mask/tag/pseudonymize с падежами.
- `redmadrobot-rnd/rubert-base-pii-ner` (Apache-2.0) — официальная модель (см. `docs/rubert_pii_ner.md`): 178M, 21 тип/43 BIO, обучена на `pii_train` 17,137/39,687.
- `redmadrobot-rnd/pii_benchmark` (MIT, 2841) + `pii_train` (MIT, 17137, 12.7MB) — единственные русские PII-датасеты с документными ID; скачаны целиком.
- `microsoft/presidio` (Apache 2.0) — формула `pattern+validation+context`, registry, anonymizer справа-налево.
- `brikkoAI/presidio-ru-recognizers` (MIT) — независимая сверка весов КС ФНС/ПФР.
- `natasha/slovnet` (MIT) — лёгкий CPU-fallback (~27MB), пока без PII-метрик.

## 3. Датасеты

- Benchmark: `datasets/redmadrobot/pii_benchmark/test.csv` (2841, MIT) → `corpus/external_rmr/rmr_benchmark_alfa.jsonl` (2841: 2470 pos / 371 neg, errors=0). Маппинг сохраняет `rmr_label`; сверка с gold из карточки модели: PASSPORT 494, INN 263, SNILS 223, OMS 170, CARD 203, DRIVER 371, MILITARY 278, BIRTH_CERT 341, EMAIL 221 — совпадают.
- Train: `datasets/redmadrobot/pii_train/train.csv` (17137, 12.7MB, MIT) — скачан целиком, в корпус не разворачивался (обучение вне scope); распределение B-меток: FIRST 3876, LAST 3361, CITY 2669, PASSPORT 2540, MIDDLE 2344, STREET 2190, URL 2090, COUNTRY 1999, HOUSE 1906, EMAIL 1755, DISTRICT 1696, DRIVER 1688, BIRTH_CERT 1590, MILITARY 1442, INN 1163, CREDIT 989, IP 939, SNILS 924, OMS 742.
- Сырые CSV в Git не входят; в Git — только `corpus/**/*.jsonl`.

## 4. Coverage категорий Alfa

RMR покрывает: ФИО, паспорт, телефон, ИНН, СНИЛС, карта, ОМС, ВУ, военник, свид-во о рождении, email, URL/IP, адрес (композитом). Частично: даты (есть тексты, нет роли), гражданство/место (нет роли). Нет: дата выдачи, орган выдачи, код подразделения, CVV, PIN, держатель карты — закрыты `synthetic_missing` 9×~240.

## 5. Recommended deterministic detectors

Из кода pii-guard: ИНН (КС, 0.90–0.95, prio 40), СНИЛС (0.95, prio 30), паспорт/ВУ (0.75–0.80 + resolver, prio 60/70), свид-во о рождении/военник (0.80–0.95, prio 10/20), карта/ОМС (Luhn + дистанция 100/220, prio 50/51), счёт+БИК (0.90–0.97, окно 120/40, prio 45/50), индекс (0.92 + veto, prio 60), даты (8 regex 0.75–0.85), email/IP. Бюджет контекста — измеренные дистанции, не бинарное наличие.

## 6. Где потребуется context

Всё короткое/двусмысленное + паспорт-vs-ВУ resolver (80/160/200), CARD-vs-OMS (100/220), счёт-vs-БИК (120/40), индекс negatives. Окно базовое 80 (предложение), широкое 260. CVV/PIN/код — только с keyword.

## 7. Где потребуется ML (обновлено)

Основной кандидат — **RMR ruBERT + deterministic rules** (83.6 exact / 94.7 overlap моделью, 88.9/95.0 пайплайном). Slovnet — fallback до latency-тестов. BERT в hot path под 1000–2000 RPS/0.5s — отдельным tier/батчингом/квантованием; решение только по замерам. Слабые места модели (IP 36.0, INN 68.3) закрываются regex-правилами.

## 8. Hard negatives + conflicts

`hard_negatives` 219 уникальных (famous, org-address, historic-date, bad-checksum с битым КС, format-talk, fiction, meta-numbers) — дедуплицировано, массовых повторов нет. `conflicts/overlap_conflicts` 105 кейсов с `candidates`+`expected`: INN-vs-PASSPORT (КС решает), PASSPORT-vs-DL (контекст), CARD-vs-OMS (дистанция), ADDRESS-merge-vs-single/suppressor, EMAIL-vs-URL (pairwise), IP_PORT-vs-IP (pairwise против score), FIO-merge, CVV/DIVISION-gate.

## 9. Rust libraries

`regex+regex-automata` (предкомпиляция, Send+Sync, byte offsets), `aho-corasick` (keywords за проход), `luhn` (inline), `serde`, `tokio+axum`. Порт точной логики pii-guard: greedy `(-score,-len,start)`, pairwise-таблица, дистанционные окна, data-only спаны, замены справа-налево.

## 10. Security / 152-ФЗ observations

Без изменений: DetoxProxy — техническая мера, не «соответствие 152-ФЗ». pii-guard stateless (таблица у вызывающего), offsets по нормализованному тексту — для подсветки исходника нужен ремап. State — request-scoped, TTL, zeroize.

## 11. Лицензии

pii-guard Apache-2.0, rubert-base-pii-ner Apache-2.0, RMR datasets MIT, Presidio Apache 2.0, ru-recognizers MIT, Natasha MIT, regex/axum/tokio MIT/Apache, aho-corasick MIT/Unlicense. GPL-исключение upstream (gender-guesser) — opt-in only, не тянем. КС-формулы — математика регуляторов.

## 12. Главные риски

1. Паспорт vs ИНН-10 vs ВУ — закрыто КС-приоритетом + resolver (код есть).
2. Адрес физлица vs адрес банка — suppressors + longest-merge.
3. CVV/PIN без контекста — строгий gate.
4. 100k tokens × N recognizers — один проход + чанкинг (BERT stride 128 — тот же приём).
5. BERT-latency под 2000 RPS — главный неизмеренный риск; mitigations: rules-first, NER только на окнах, квантование, реплики (upstream: semaphore 503, scale by replicas).
6. Offsets по нормализованному тексту — ремап для исходника.

## 13. Что рекомендуем передать архитектору

- Взять за основу pipeline pii-guard: `normalize → base64/translit-guard → rules + ruBERT → ML-vs-rules (правила побеждают) → pairwise → score-greedy → mask/tag/pseudonymize`.
- ML-компонент: RMR ruBERT (конфиг 512/stride-128/порог) как primary, Slovnet как fallback до замеров.
- Typed tokens per-request, deanonymize с падежами — по образцу `pseudonymize.py`.
- Benchmark: strict exact + type-overlap из `tests/quality/` (gate micro_f1, require_same_dataset); regression на `corpus/external_rmr` + `conflicts`.

## 14. Что НЕ удалось выяснить

- Латентность ruBERT на целевом железе под 100k tokens / 2000 RPS — нужны замеры.
- Полный БИК-справочник ЦБ — out of scope.
- Актуальные приказы РКН по ГИС-обезличиванию — следить.

## Architectural findings

- Конфликты закрыты кодом upstream (pairwise + greedy), а не эвристикой — портировать таблицу.
- Base64/транслит-препроцессинг с бюджетами (32 блоба/20000 символов, foreign 0.90) — обязателен для adversarial-устойчивости.
- Normal facilement: offsets — нормализованный текст; для DetoxProxy спроектировать SpanMap сразу.

## Статистика corpus (фактический вывод corpus_stats.py)

```
external_rmr/rmr_benchmark_alfa.jsonl: total=2841 positive=2470 negative=371 multi=1217 avg=203.1 max=2574 dups=0
synthetic/synthetic_alfa.jsonl: total=302 positive=302 avg=31.7 max=65 dups=0
synthetic/synthetic_missing_categories.jsonl: total=2156 positive=~1076 negative=~1080 avg=45.6 dups=0
synthetic/multi_entity.jsonl: total=80 positive=80 multi=80 avg=109.8 max=292 dups=0
hard_negatives/hard_negatives.jsonl: total=219 negative=219 avg=48.4 dups=0
conflicts/overlap_conflicts.jsonl: total=105 (104 pos / 1 suppressed) avg=41.8 dups=0
```
