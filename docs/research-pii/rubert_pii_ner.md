# rubert-base-pii-ner: официальная модель redmadrobot-rnd

Карточка: https://huggingface.co/redmadrobot-rnd/rubert-base-pii-ner (Apache-2.0, pipeline `token-classification`, safetensors).
Код пайплайна: github.com/redmadrobot-rnd/pii-guard (`src/pii_guard/ner/`, `models/README.md`).
Дата фиксации: 2026-09-22. Веса в Git не лежат (одноразовый `huggingface-cli download`, дальше офлайн).

## 1. Что это

Fine-tune `ai-forever/ruBert-base` (BERT-base, 178M параметров, словарь 120k, `model.safetensors` ~678–700MB, F32 177,749,803 параметров) под русский PII NER.
Голова: 21 тип / 43 BIO-метки (21×B/I + O), `config.json id2label`, `tokenizer model_max_length=512`.

- Обучение: `redmadrobot-rnd/pii_train` — 17,137 предложений, 39,687 спанов (проверенные production-логи с засинтетизированными ПД + synthetic по типам документов + hard negatives). Дубли benchmark удалены.
- Оценка: `redmadrobot-rnd/pii_benchmark` — 2,841 held-out предложений, дизъюнктно.
- Гиперпараметры (из карточки): 10 эпох, lr 3e-5 linear decay без warmup, batch 16, AdamW wd 0.01, fp32, max_len 512, seed 42.
- Рантайм в pii-guard: `TransformerNERConfig(model, revision=None, max_length=512, stride=128, min_confidence=0.70)` в движке; в карточке для прямого вызова — `stride=128`, порог `0.3` + обязательный merge соседних фрагментов одного типа (иначе `elena@pochta.ru` рвётся на `B-` посередине). Склейка пунктуации `.,;:!?`, для имён/локаций отключена. Оversize-токены → `O`. Скор фиксированно 0.70 на выходе движка.
- Ревизия модели не пинится (`revision=None` → warning; env `PII_GUARD_NER_MODEL` / `PII_GUARD_NER_REVISION`); устройство `auto→cuda else cpu` (mps только явно).

## 2. Типы (совпадают с train/benchmark)

PERSON: `FIRST_NAME/LAST_NAME/MIDDLE_NAME`; LOCATION: `COUNTRY/REGION/DISTRICT/CITY/STREET/HOUSE`; контакты: `EMAIL/PHONE/URL/IP_ADDRESS`; документы: `PASSPORT/INN/SNILS/OMS/CREDIT_CARD/DRIVER_LICENSE/MILITARY_ID/BIRTH_CERTIFICATE`. Маппинг движка (`engine.py:59-81`): первые две группы → `PERSON/LOCATION`, остальные — как есть; неизвестные метки игнорируются. `DATE_TIME/BANK_ACCOUNT/BIK/TELEGRAM` у модели нет головы — их закрывают только правила.

## 3. Benchmark-метрики (официальные, self-reported, exact span-level, greedy 1:1)

Протокол строгий exact (без нормализации спанов). 14 общих категорий:

| Система | P | R | F1 |
|---|---|---|---|
| Модель одна | 81.9 | 85.5 | **83.6** |
| Пайплайн pii-guard (правила + модель) | 90.4 | 87.5 | **88.9** |

Протокол leaderboard (`PERSON+LOCATION`, overlap): модель **94.7**, пайплайн **95.0**.

Per-entity F1 модели (exact, gold counts из карточки):

| Entity | gold | F1 | Entity | gold | F1 |
|---|---|---|---|---|---|
| FIRST_NAME | 499 | 89.8 | IP_ADDRESS | 155 | 36.0 |
| LAST_NAME | 457 | 84.5 | PASSPORT | 494 | 81.3 |
| MIDDLE_NAME | 308 | 91.5 | INN | 263 | 68.3 |
| COUNTRY | 242 | 86.1 | SNILS | 223 | 78.5 |
| REGION | 176 | 80.3 | OMS | 170 | 90.1 |
| CITY | 339 | 82.5 | CREDIT_CARD | 203 | 87.9 |
| DISTRICT | 161 | 78.3 | DRIVER_LICENSE | 371 | 81.8 |
| STREET | 171 | 87.3 | MILITARY_ID | 278 | 78.3 |
| HOUSE | 163 | 92.7 | BIRTH_CERTIFICATE | 341 | 83.7 |
| EMAIL | 221 | 97.6 | PHONE | 173 | 86.9 |
| URL | 206 | 89.7 | — | — | — |

Слабые места модели: `IP_ADDRESS` 36.0 (рвётся на точках — в пайплайне это regex), `INN` 68.3 (без КС). Сильные: EMAIL 97.6, HOUSE 92.7, MIDDLE 91.5.

Дополнительные замеры из `docs/quality.md` + `tests/quality/`: на пересечении с внешними наборами пайплайн 88.6/93.7–90.3/95.0 против guardrails/GLiNER-omni ниже; rules-only ~49, model-only ~44–67 — по отдельности недостаточно. Regression-gate в репо: `micro_f1 0.974513` на закрытом `test.xlsx` 3857 кейсов (не в git), пороги `MICRO 0.95 / CAT 0.85 / DROP 0.02`.

## 4. Вывод для DetoxProxy

Самый интересный кандидат — **специализированный RMR ruBERT + deterministic rules** (а не generic Slovnet/GLiNER): только он даёт 83.6 exact / 94.7 overlap на русских документах и 88.9 в связке с правилами. Slovnet остаётся лёгкой CPU-альтернативой, но по качеству на PII-документах проигрывает до latency-тестов. BERT в hot path под 1000–2000 RPS / 0.5s — только отдельным tier/батчингом/квантованием; это должно доказать измерение, а не предположение.
